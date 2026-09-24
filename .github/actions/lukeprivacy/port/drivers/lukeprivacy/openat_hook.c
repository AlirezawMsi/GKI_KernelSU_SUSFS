/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy - openat() fd→path tracking (built-in kernel port)
 *
 * Ported from KernelPatch KPM. The runtime syscall inline-hook is gone;
 * this logic is now invoked directly:
 *   void lp_openat_hook(int dfd, const char __user *filename,
 *                       int flags, long ret_fd);   -- from fs/open.c
 *                                                     do_sys_openat2(), POST
 *                                                     (ret_fd = returned fd)
 *   void lp_close_hook(int fd);                    -- from the close path
 *
 * NOTE ON "PRE / redirect / deny": the current logic does NOT redirect or
 * deny any open — it only tags the RETURNED fd with a type so read_hook can
 * rewrite the buffer later. That inherently needs the fd, so this is a POST
 * call-site, not a PRE one. (See FLAGS in the port report.)
 *
 * This file OWNS the shared fd→type table (tracked_fds[]) plus the dedicated
 * boot_id / mounts / keva tables; read_hook.c consumes them via extern.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/sched.h>

#include "profile.h"
#include "uaccess.h"
#include "lp_log.h"

#define MAX_TRACKED_FDS 64
#define MAX_PATH_LEN 128

/* getuid()/getpid() equivalents for the choke-point (real UID + TGID). */
static inline int lp_cur_uid(void)
{
    return (int)from_kuid(&init_user_ns, current_uid());
}

enum fd_type {
    FD_TYPE_NONE = 0,
    FD_TYPE_WIFI_MAC,
    FD_TYPE_BT_MAC,
    FD_TYPE_SHAREDPREFS,
    /* TikTok keva binary key-value store. Tracked so keva_hook.c can
     * intercept write() calls on these fds and substitute sdi/ecneuq/
     * openudid/semithc/msmodel values before they hit the disk.
     * Path pattern: /data/data/com.zhiliaoapp.musically[.go|trill]/files/keva/<hexhash> */
    FD_TYPE_KEVA,
    /* SUSFS v2.0.0 GKI add_open_redirect has uid<=2000 limit — apps (uid>=10000)
     * like TikTok don't get /proc/<x> redirected. Port-side replacement covers
     * the gap via fd-tracking on openat + buffer rewrite on read. */
    FD_TYPE_PROC_VERSION,    /* /proc/version — kernel build string (drop "Wild" leak) */
    FD_TYPE_PROC_CPUINFO,    /* /proc/cpuinfo — sanitized (no Hardware/Serial lines) */
    FD_TYPE_PROC_INET6,      /* /proc/net/if_inet6 + per-pid variant — drop dummy0 EUI-64 */
    FD_TYPE_PROC_BOOT_ID,    /* /proc/sys/kernel/random/boot_id — per-boot UUID; spoof per-seed */
    /* Per-component hardware serials in sysfs. These survive factory reset
     * (battery fuel-gauge serial is fused at pack manufacture, display
     * serial is OLED panel-level). TikTok openudid derives from these +
     * cdt_hwid + hw.soc.id → without spoofing them, openudid stays stable
     * across pm clear + reinstall. */
    FD_TYPE_BATTERY_SERIAL,  /* /sys/.../maxfg/serial_number + /sys/...battery/serial_number */
    FD_TYPE_DISPLAY_SERIAL,  /* /sys/...drmdsim/.../serial_number — OLED panel serial */
    FD_TYPE_UFS_SERIAL,      /* /sys/...ufs/string_descriptors/serial_number — storage chip */
    FD_TYPE_SOC0_MACHINE,    /* /sys/devices/soc0/machine — may leak "Oriole DVT" engineering suffix */
    FD_TYPE_SOC0_FAMILY,     /* /sys/devices/soc0/family — Tensor codename */
    FD_TYPE_SOC0_SOCID,      /* /sys/devices/soc0/soc_id — SoC model ID */
    FD_TYPE_SOC0_REVISION,   /* /sys/devices/soc0/revision — chip rev integer */
    FD_TYPE_SOC0_SERIAL,     /* /sys/devices/soc0/serial_number — per-chip unique (future-proof) */
    /* /proc/mounts + /proc/self/mountinfo + /proc/<pid>/mountinfo. The KSU
     * overlay mount label leaks our module dir name into mountinfo;
     * read_hook strips the tell-tale lines. */
    FD_TYPE_PROC_MOUNTS,
};

struct tracked_fd {
    int fd;
    int pid;
    enum fd_type type;
};

static struct tracked_fd tracked_fds[MAX_TRACKED_FDS];

/* Find a slot to use. Prefers a slot already keyed by the same (fd, pid);
 * falls back to the first empty slot, then round-robin eviction. */
static int g_evict_cursor = 0;
static int find_free_slot_for(int pid, int fd)
{
    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        if (tracked_fds[i].fd == fd && tracked_fds[i].pid == pid) return i;
    }
    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        if (tracked_fds[i].fd == 0) return i;
    }
    int slot = g_evict_cursor;
    g_evict_cursor = (g_evict_cursor + 1) % MAX_TRACKED_FDS;
    return slot;
}

enum fd_type get_fd_type(int fd, int pid)
{
    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        if (tracked_fds[i].fd == fd && tracked_fds[i].pid == pid) {
            return tracked_fds[i].type;
        }
    }
    return FD_TYPE_NONE;
}

void clear_fd_tracking(int fd, int pid)
{
    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        if (tracked_fds[i].fd == fd && tracked_fds[i].pid == pid) {
            tracked_fds[i].fd = 0;
            tracked_fds[i].pid = 0;
            tracked_fds[i].type = FD_TYPE_NONE;
        }
    }
}

/* Dedicated, eviction-proof tracking for /proc/sys/kernel/random/boot_id fds.
 * The shared 64-slot table is churned hard by an app's own file activity, so a
 * Java new FileInputStream(boot_id) can lose its slot before the delayed read;
 * boot_id opens are rare, so a small dedicated table never evicts. */
#define MAX_BOOTID_FDS 256
static struct { int fd; int pid; } bootid_fds[MAX_BOOTID_FDS];
static int g_bootid_evict = 0;

void bootid_fd_track(int fd, int pid)
{
    for (int i = 0; i < MAX_BOOTID_FDS; i++)
        if (bootid_fds[i].fd == fd && bootid_fds[i].pid == pid) return;
    for (int i = 0; i < MAX_BOOTID_FDS; i++)
        if (bootid_fds[i].fd == 0) { bootid_fds[i].fd = fd; bootid_fds[i].pid = pid; return; }
    int s = g_bootid_evict;
    g_bootid_evict = (g_bootid_evict + 1) % MAX_BOOTID_FDS;
    bootid_fds[s].fd = fd; bootid_fds[s].pid = pid;
}

int is_bootid_fd(int fd, int pid)
{
    for (int i = 0; i < MAX_BOOTID_FDS; i++)
        if (bootid_fds[i].fd == fd && bootid_fds[i].pid == pid) return 1;
    return 0;
}

void bootid_fd_clear(int fd, int pid)
{
    for (int i = 0; i < MAX_BOOTID_FDS; i++)
        if (bootid_fds[i].fd == fd && bootid_fds[i].pid == pid) { bootid_fds[i].fd = 0; bootid_fds[i].pid = 0; }
}

/* Dedicated, eviction-proof tracking for /proc mounts + mountinfo fds, same
 * rationale as boot_id: Ferrite / dd do open -> [churn] -> one big read(), so a
 * delayed reader can lose its shared-table slot. Mounts opens are rare. */
#define MAX_MOUNTS_FDS 256
static struct { int fd; int pid; } mounts_fds[MAX_MOUNTS_FDS];
static int g_mounts_evict = 0;

void mounts_fd_track(int fd, int pid)
{
    for (int i = 0; i < MAX_MOUNTS_FDS; i++)
        if (mounts_fds[i].fd == fd && mounts_fds[i].pid == pid) return;
    for (int i = 0; i < MAX_MOUNTS_FDS; i++)
        if (mounts_fds[i].fd == 0) { mounts_fds[i].fd = fd; mounts_fds[i].pid = pid; return; }
    int s = g_mounts_evict;
    g_mounts_evict = (g_mounts_evict + 1) % MAX_MOUNTS_FDS;
    mounts_fds[s].fd = fd; mounts_fds[s].pid = pid;
}

int is_mounts_fd(int fd, int pid)
{
    for (int i = 0; i < MAX_MOUNTS_FDS; i++)
        if (mounts_fds[i].fd == fd && mounts_fds[i].pid == pid) return 1;
    return 0;
}

void mounts_fd_clear(int fd, int pid)
{
    for (int i = 0; i < MAX_MOUNTS_FDS; i++)
        if (mounts_fds[i].fd == fd && mounts_fds[i].pid == pid) { mounts_fds[i].fd = 0; mounts_fds[i].pid = 0; }
}

/* Keva fd bitmap — 2048 slots using fd % 2048 as index. Not truly per-pid,
 * but keva fds are short-lived so aliasing across PIDs is negligible. */
#define LP_KEVA_MAP_SIZE 2048
static unsigned long g_keva_fd_map[LP_KEVA_MAP_SIZE / (8 * sizeof(unsigned long))];

void lp_fd_mark_keva(int fd)
{
    if (fd < 0 || fd >= LP_KEVA_MAP_SIZE) return;
    g_keva_fd_map[fd / (8 * sizeof(unsigned long))] |=
        (1UL << (fd % (8 * sizeof(unsigned long))));
}

bool lp_fd_is_keva(int fd)
{
    if (fd < 0 || fd >= LP_KEVA_MAP_SIZE) return false;
    return !!(g_keva_fd_map[fd / (8 * sizeof(unsigned long))] &
              (1UL << (fd % (8 * sizeof(unsigned long)))));
}

void lp_fd_unmark_keva(int fd)
{
    if (fd < 0 || fd >= LP_KEVA_MAP_SIZE) return;
    g_keva_fd_map[fd / (8 * sizeof(unsigned long))] &=
        ~(1UL << (fd % (8 * sizeof(unsigned long))));
}

/* Check if path belongs to a TikTok keva store directory.
 * Covers: musically (global), musically.go (TikTok Lite), trill (regional). */
static bool is_tiktok_keva_path(const char *path)
{
    if (!path) return false;
    return strstr(path, "/com.zhiliaoapp.musically/files/keva/") != NULL
        || strstr(path, "/com.zhiliaoapp.musically.go/files/keva/") != NULL
        || strstr(path, "/com.ss.android.ugc.trill/files/keva/") != NULL;
}

static bool str_contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static bool str_ends_with(const char *str, const char *suffix)
{
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len) return false;
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

/* True for `/proc/...` paths. Used to scope generic suffix matches (e.g.
 * "/mounts") to procfs only — avoids hitting an app's own /data/.../mounts. */
static bool starts_with_proc(const char *path)
{
    return path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
           path[3] == 'o' && path[4] == 'c' && path[5] == '/';
}

/* Counter for /proc/config.gz denials (visible via dmesg on first hit). */
unsigned int g_config_gz_denied = 0;

/*
 * lp_openat_deny — decide whether an open() must be failed with -ENOENT.
 *
 * Called from fs/open.c do_sys_openat2() right after the fd is assigned but
 * before returning. Used to hide /proc/config.gz from ordinary app UIDs
 * (>= 10000, incl. GMS/DroidGuard uid 10167) so they cannot read
 * CONFIG_KSU / CONFIG_KSU_SUSFS / CONFIG_LUKEPRIVACY out of the kernel config
 * — the last remaining root tell. System UIDs (< 10000: init, system_server,
 * the VINTF kernel-config verifier at boot) are left untouched so
 * /proc/config.gz stays readable for them and the device boots normally.
 * Returns 1 to deny (caller closes the fd + returns -ENOENT), 0 otherwise.
 */
/*
 * U14 (2026-09-24 genuine-device audit): true when the CURRENT caller must see /proc/config.gz as ABSENT.
 * Applies to ALL app uids (>= 10000), not just the runtime-configured GMS/DroidGuard uid: a genuine Pixel
 * exposes no app-readable kernel config carrying CONFIG_KSU / CONFIG_KSU_SUSFS / CONFIG_LUKEPRIVACY markers,
 * so any app that greps config.gz for root (IG does) must see it gone. System uids (< 10000: init,
 * system_server, the VINTF kernel-config verifier at boot) still read the REAL config.gz so the device
 * boots normally. The explicit set_configgz_uids list is still honored (harmless superset for any < 10000
 * entry). Shared by the open/stat/access denies so an app's view is CONSISTENT (open + stat + access all
 * return -ENOENT), exactly matching a stock IKCONFIG_PROC=n device — no open/stat inconsistency to detect.
 */
static int lp_configgz_hidden(const char __user *filename)
{
    char path[MAX_PATH_LEN];
    long len;
    int uid;

    if (!g_hooks_enabled) return 0;
    if (!filename) return 0;
    uid = lp_cur_uid();
    if (uid < 10000 && !lp_uid_hides_configgz(uid)) return 0;

    len = lp_copy_from_user(path, filename, sizeof(path) - 1);
    if (len <= 0) return 0;
    path[len] = '\0';
    return !strcmp(path, "/proc/config.gz");
}

int lp_openat_deny(const char __user *filename)
{
    if (!lp_configgz_hidden(filename)) return 0;
    if (!g_config_gz_denied)
        pr_info("lukeprivacy: hiding /proc/config.gz from app uid=%d (open)\n", lp_cur_uid());
    g_config_gz_denied++;
    return 1;
}

/* kernel #4 (2026-09-24 genuine-device audit): /proc/luke path-probe hide. The LukePrivacy control node
 * is readdir-hidden + open-denied for apps, but stat()/access() by path still succeeded (mode 0666),
 * giving a probe of the literal path "/proc/luke" a positive existence hit + an open-vs-stat
 * inconsistency (a recognizable hiding-framework tell). Deny stat/access for app uids (>=10000) too so
 * existence probing by path fails, matching the readdir/open behavior. Root/system (<10000, incl
 * kpm_apply's writer) is exempt so the control channel still works. */
static int lp_luke_hidden(const char __user *filename)
{
    char path[MAX_PATH_LEN];
    long len;

    if (!g_hooks_enabled) return 0;
    if (!filename) return 0;
    if (lp_cur_uid() < 10000) return 0;
    len = lp_copy_from_user(path, filename, sizeof(path) - 1);
    if (len <= 0) return 0;
    path[len] = '\0';
    return !strcmp(path, "/proc/luke");
}

/* U14: stat()/statx() deny — return -ENOENT for config.gz so stat agrees with open (no "present via stat,
 * absent via open" inconsistency). Called from the fs/stat.c call-sites. Also covers /proc/luke (kernel #4). */
int lp_stat_deny(const char __user *filename)
{
    return lp_configgz_hidden(filename) || lp_luke_hidden(filename);
}

/* U14: faccessat()/access() deny — same, so access() agrees too. Called from the fs/open.c call-site.
 * Also covers /proc/luke (kernel #4). */
int lp_access_deny(const char __user *filename)
{
    return lp_configgz_hidden(filename) || lp_luke_hidden(filename);
}

/* U14: readdir — 1 when /proc/config.gz must be hidden from the CURRENT task's /proc listing (so it does
 * not appear in `ls /proc` while stat/open/access all say ENOENT). Mirrors the open/stat/access uid gate;
 * the readdir call-site (fs/proc/generic.c) matches the entry NAME, so there is no path arg here. */
int lp_hide_configgz_current(void)
{
    int uid;
    if (!g_hooks_enabled) return 0;
    uid = lp_cur_uid();
    if (uid < 10000 && !lp_uid_hides_configgz(uid)) return 0;
    return 1;
}

/*
 * lp_openat_hook — openat() choke-point (POST).
 *
 * Called from fs/open.c do_sys_openat2() just before it returns, when the
 * open succeeded (ret_fd >= 0). Tags the fd with a type so lp_read_hook can
 * rewrite the buffer on read. `dfd` and `flags` are carried for future use
 * (the current tracking logic keys only on the path + returned fd).
 */
void lp_openat_hook(int dfd, const char __user *filename, int flags, long ret_fd)
{
    (void)dfd;
    (void)flags;

    if (!g_hooks_enabled) return;

    {
        __u32 uid = (__u32)lp_cur_uid();
        if (lp_is_uid_excluded(uid)) return;
    }

    long fd = ret_fd;
    if (fd < 0) return;

    if (!filename) return;

    char path[MAX_PATH_LEN];
    long len = lp_copy_from_user(path, filename, sizeof(path) - 1);
    if (len > 0) path[len] = '\0';
    if (len <= 0) return;

    if (str_contains(path, "/sys/class/net") || str_contains(path, "/sys/class/bluetooth")) {
        lp_dbg("lukeprivacy: openat /sys path: %s fd=%ld\n", path, fd);
    }

    enum fd_type type = FD_TYPE_NONE;

    /* WiFi MAC sysfs leaks via /address + factory /macaddress on wlanN, plus
     * aware_nmi / swlan / p2p placeholder-MAC interfaces. */
    if ((str_contains(path, "/sys/class/net/wlan") &&
         (str_ends_with(path, "/address") || str_ends_with(path, "/macaddress"))) ||
        (str_contains(path, "/sys/class/net/aware_nmi") && str_ends_with(path, "/address")) ||
        (str_contains(path, "/sys/class/net/swlan") && str_ends_with(path, "/address")) ||
        (str_contains(path, "/sys/class/net/p2p") && str_ends_with(path, "/address"))) {
        type = FD_TYPE_WIFI_MAC;
    }
    else if (str_contains(path, "/sys/class/bluetooth/") && str_ends_with(path, "/address")) {
        type = FD_TYPE_BT_MAC;
    }
    /* Hardware serial number files in sysfs (fuel-gauge, OLED panel, UFS). */
    else if (str_ends_with(path, "/serial_number") &&
             (str_contains(path, "maxfg") ||
              str_contains(path, "power_supply/battery"))) {
        type = FD_TYPE_BATTERY_SERIAL;
    }
    else if (str_ends_with(path, "/serial_number") &&
             str_contains(path, "drmdsim")) {
        type = FD_TYPE_DISPLAY_SERIAL;
    }
    else if (str_ends_with(path, "/serial_number") &&
             str_contains(path, ".ufs")) {
        type = FD_TYPE_UFS_SERIAL;
    }
    /* Mount-namespace exposure surfaces (generic /mounts|/mountinfo|/mountstats
     * suffix + /proc/ prefix guard so /proc/self/mounts is caught too). */
    else if ((str_ends_with(path, "/mounts") ||
              str_ends_with(path, "/mountinfo") ||
              str_ends_with(path, "/mountstats")) &&
             starts_with_proc(path)) {
        type = FD_TYPE_PROC_MOUNTS;
    }
    else if (str_contains(path, "shared_prefs") && str_ends_with(path, ".xml")) {
        type = FD_TYPE_SHAREDPREFS;
    }
    /* SUSFS open_redirect bypass: app uids get real /proc paths on stock susfs
     * v2.0.0 GKI. Exact-match so we don't catch /proc/version.log etc. */
    else if (!strcmp(path, "/proc/version")) {
        type = FD_TYPE_PROC_VERSION;
    }
    else if (!strcmp(path, "/proc/cpuinfo")) {
        type = FD_TYPE_PROC_CPUINFO;
    }
    else if (g_profile.boot_id_spoof_enabled &&
             !strcmp(path, "/proc/sys/kernel/random/boot_id")) {
        type = FD_TYPE_PROC_BOOT_ID;
    }
    /* /sys/devices/soc0/ fingerprint surface — exact leaf match only. */
    else if (!strcmp(path, "/sys/devices/soc0/machine")) {
        type = FD_TYPE_SOC0_MACHINE;
    }
    else if (!strcmp(path, "/sys/devices/soc0/family")) {
        type = FD_TYPE_SOC0_FAMILY;
    }
    else if (!strcmp(path, "/sys/devices/soc0/soc_id")) {
        type = FD_TYPE_SOC0_SOCID;
    }
    else if (!strcmp(path, "/sys/devices/soc0/revision")) {
        type = FD_TYPE_SOC0_REVISION;
    }
    else if (!strcmp(path, "/sys/devices/soc0/serial_number")) {
        type = FD_TYPE_SOC0_SERIAL;
    }
    /* /proc/net/if_inet6 tracking REMOVED 2026-05-11 — faking it broke TikTok
     * network-connectivity check on the signup name screen, and the dummy0
     * EUI-64 is a per-boot privacy address that doesn't leak the real WiFi MAC.
     * FD_TYPE_PROC_INET6 stays defined for ABI compat with read_hook's handler
     * but is never assigned here. */

    /* TikTok keva store tracking — keva_hook.c intercepts write() on these fds. */
    if (is_tiktok_keva_path(path)) {
        lp_fd_mark_keva((int)fd);
        type = FD_TYPE_KEVA;
    }

    if (type != FD_TYPE_NONE) {
        int pid = current->tgid;
        int slot = find_free_slot_for(pid, (int)fd);
        tracked_fds[slot].fd = (int)fd;
        tracked_fds[slot].pid = pid;
        tracked_fds[slot].type = type;
        /* boot_id + mounts also go in their own eviction-proof tables. */
        if (type == FD_TYPE_PROC_BOOT_ID) bootid_fd_track((int)fd, pid);
        if (type == FD_TYPE_PROC_MOUNTS) mounts_fd_track((int)fd, pid);
        lp_dbg("lukeprivacy: tracking fd=%d pid=%d type=%d path=%s\n", (int)fd, pid, type, path);
    }
}

/*
 * lp_close_hook — close() choke-point.
 *
 * Natural lifetime end of a tracked fd. Without it the 64-slot tracked_fds
 * table fills up after enough sysfs opens (DHCP/connectivity opens
 * /sys/class/net/wlan0/address frequently) and find_free_slot starts evicting
 * live slots — at which point new MAC reads stop being spoofed. Recommended
 * call site: the close() syscall path (see FLAGS). Non-fatal if omitted: the
 * table has round-robin eviction as a fallback.
 */
void lp_close_hook(int fd)
{
    if (!g_hooks_enabled) return;
    if (fd < 0) return;
    int pid = current->tgid;
    clear_fd_tracking(fd, pid);
    bootid_fd_clear(fd, pid);
    mounts_fd_clear(fd, pid);
    /* Also clear keva bitmap — avoids stale bit aliasing on fd reuse. */
    lp_fd_unmark_keva(fd);
}

/* ─── setup-only lifecycle (no runtime syscall hooks any more) ──────────── */
int openat_hook_init(void)
{
    memset(tracked_fds, 0, sizeof(tracked_fds));
    memset(g_keva_fd_map, 0, sizeof(g_keva_fd_map));
    memset(bootid_fds, 0, sizeof(bootid_fds));
    memset(mounts_fds, 0, sizeof(mounts_fds));
    pr_info("lukeprivacy: openat/close choke-points ready (fd tracking)\n");
    return 0;
}

void openat_hook_exit(void)
{
}
