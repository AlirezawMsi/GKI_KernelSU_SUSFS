/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy - read() choke-point hook (built-in kernel port)
 *
 * Ported from KernelPatch KPM. The runtime syscall inline-hook is gone;
 * this logic is now invoked directly from fs/read_write.c via
 *   long lp_read_hook(int fd, char __user *buf, long ret);
 * called from ksys_read()/ksys_pread64() when vfs_read() returned > 0.
 *
 * Targets:
 * - /sys/class/bluetooth/.../address (Bluetooth MAC)
 * - /sys/class/net/wlan0/address (WiFi MAC)
 * - SharedPrefs XML files (Firebase FID, GAID)
 * - /proc/{version,cpuinfo,net/if_inet6,mounts,mountinfo}
 * - /proc/sys/kernel/random/boot_id
 * - /sys/devices/soc0/ + per-component hardware serials
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
#include <linux/rcupdate.h>

#include "profile.h"
#include "uaccess.h"
#include "lp_log.h"

/* Direct kernel symbols (built-in => no kallsyms_lookup_name). Both are
 * non-static kernel symbols; the extern prototypes below double as a
 * compile guard for trees whose <linux/sched.h> doesn't re-export them. */
extern struct task_struct *find_task_by_vpid(pid_t nr);
extern char *__get_task_comm(char *buf, size_t buf_size, struct task_struct *tsk);

#define MAX_BUF_SIZE 4096

/* getuid()/getpid() equivalents for the choke-point (real UID + TGID). */
static inline int lp_cur_uid(void)
{
    return (int)from_kuid(&init_user_ns, current_uid());
}

/* MUST stay byte-for-byte in sync with the matching enum in openat_hook.c —
 * fd→type mapping is written by openat_hook and read by read_hook through the
 * shared tracked_fds[] table. A mismatch in integer values silently shifts
 * every type by one, so SOC0_MACHINE reads get FAMILY fake, FAMILY reads get
 * SOCID fake, etc. (and the same happens to proc_version / cpuinfo / battery
 * /display / UFS — anything past the divergence point). KEVA isn't dispatched
 * here (keva_hook handles writes via its own bitmask), but the slot has to
 * exist so subsequent enum values match openat_hook's. */
enum fd_type {
    FD_TYPE_NONE = 0,
    FD_TYPE_WIFI_MAC,
    FD_TYPE_BT_MAC,
    FD_TYPE_SHAREDPREFS,
    FD_TYPE_KEVA,            /* slot mirror — handled by keva_hook, no-op here */
    FD_TYPE_PROC_VERSION,
    FD_TYPE_PROC_CPUINFO,
    FD_TYPE_PROC_INET6,
    FD_TYPE_PROC_BOOT_ID,
    FD_TYPE_BATTERY_SERIAL,
    FD_TYPE_DISPLAY_SERIAL,
    FD_TYPE_UFS_SERIAL,
    FD_TYPE_SOC0_MACHINE,
    FD_TYPE_SOC0_FAMILY,
    FD_TYPE_SOC0_SOCID,
    FD_TYPE_SOC0_REVISION,
    FD_TYPE_SOC0_SERIAL,
    FD_TYPE_PROC_MOUNTS,
};

/* Fake content for /proc/version. SUSFS-style: drop "Wild" kernel suffix +
 * "build-user@build-host" + epoch-0 timestamp; emit stock-looking Pixel 6
 * kernel-builder@kbuild-pixel-6 with current susfs spoofed build date.
 * Length kept ≤ realistic /proc/version output (~280 bytes); apps reading
 * with buffer ≥ FAKE_VERSION_LEN get exactly this, shorter readers truncate
 * cleanly (no "real bytes after our fake" leak because we always overwrite
 * up to ret bytes capped at FAKE_VERSION_LEN). */
static const char FAKE_PROC_VERSION[] =
    "Linux version 6.1.99-android14-11-gc8ed7156d "
    "(kernel-builder@kbuild-pixel-6) "
    "(Android (10087095, +pgo, +bolt, +lto, -mlgo, based on r487747c) "
    "clang version 17.0.2 "
    "(https://android.googlesource.com/toolchain/llvm-project "
    "d9f89f4d16663d5012e5c09495f3b30ece3d2362), LLD 17.0.2) "
    "#1 SMP PREEMPT Wed Mar 26 22:57:12 UTC 2025\n";
#define FAKE_PROC_VERSION_LEN (sizeof(FAKE_PROC_VERSION) - 1)

/* Fake /proc/cpuinfo for Pixel 6 (Tensor G1: 4× Cortex-A55 + 2× Cortex-A76 +
 * 2× Cortex-X1). Drop Hardware/Serial/Revision lines (potential fingerprint).
 * Per-core blocks ordered for stable hash regardless of which core processed
 * a fingerprint sample. */
static const char FAKE_PROC_CPUINFO[] =
    "processor\t: 0\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd05\nCPU revision\t: 0\n\n"
    "processor\t: 1\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd05\nCPU revision\t: 0\n\n"
    "processor\t: 2\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd05\nCPU revision\t: 0\n\n"
    "processor\t: 3\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd05\nCPU revision\t: 0\n\n"
    "processor\t: 4\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x4\nCPU part\t: 0xd0b\nCPU revision\t: 1\n\n"
    "processor\t: 5\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x4\nCPU part\t: 0xd0b\nCPU revision\t: 1\n\n"
    "processor\t: 6\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd44\nCPU revision\t: 1\n\n"
    "processor\t: 7\nBogoMIPS\t: 49.15\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd44\nCPU revision\t: 1\n\n";
#define FAKE_PROC_CPUINFO_LEN (sizeof(FAKE_PROC_CPUINFO) - 1)

/* Fake /proc/net/if_inet6: only loopback. Drop dummy0 EUI-64 entries that
 * leak per-boot random link-local MAC (not real WiFi but presence signal). */
static const char FAKE_PROC_INET6[] =
    "00000000000000000000000000000001 01 80 10 80       lo\n";
#define FAKE_PROC_INET6_LEN (sizeof(FAKE_PROC_INET6) - 1)

/* Fake /sys/devices/soc0/ — Pixel 6 (Tensor G1 / Oriole) values WITHOUT
 * the engineering "DVT" / "EVT" / "PVT" suffix that user-owned units often
 * leak (this Pixel reports `machine = "Oriole DVT"` — Design Verification
 * Test stage — which any fingerprint pipeline flags as non-retail). The
 * other three (family / soc_id / revision) are the same across every
 * production Pixel 6 with the GS101 SoC, so faking them is identity-neutral
 * but consistent with the spoofed `machine`. `serial_number` isn't exposed
 * on Pixel 6, but we register it anyway in case a future Tensor adds it.
 *
 * Files in sysfs always include a trailing newline when read; matching that
 * keeps `cat` output byte-identical to stock. */
static const char FAKE_SOC0_MACHINE[]   = "Oriole\n";
static const char FAKE_SOC0_FAMILY[]    = "Diablo\n";
static const char FAKE_SOC0_SOCID[]     = "GS101\n";
static const char FAKE_SOC0_REVISION[]  = "17\n";
#define FAKE_SOC0_MACHINE_LEN   (sizeof(FAKE_SOC0_MACHINE) - 1)
#define FAKE_SOC0_FAMILY_LEN    (sizeof(FAKE_SOC0_FAMILY) - 1)
#define FAKE_SOC0_SOCID_LEN     (sizeof(FAKE_SOC0_SOCID) - 1)
#define FAKE_SOC0_REVISION_LEN  (sizeof(FAKE_SOC0_REVISION) - 1)
/* serial_number is derived per android_id_seed (format-preserving 16 hex
 * + newline) so a future Tensor exposing it doesn't leak a per-chip ID. */
static char fake_soc0_serial[24];
static int  fake_soc0_serial_len = 0;

/* Per-component hardware serial spoofs. Derived from the same
 * android_id_seed already used for SSAID + MediaDRM + sensor offsets, so
 * a fraud SDK correlating across identifier surfaces sees a single
 * synthesized identity rather than mismatched real-and-fake bytes.
 *
 * Stable across reads (no per-UID variance — battery/display serials are
 * single hardware-tied facts, not per-app). Stable across reboots as long
 * as the seed is unchanged. Rotate the seed (via Randomize → fresh
 * ids.android_id) to get a fresh hardware identity for these too.
 *
 * Format-preserving: battery serial = 24 hex chars (Maxim MAX1720x style),
 * display serial = 14 hex chars (Samsung OLED panel serial style), UFS
 * serial = 16 hex chars (eMMC/UFS string descriptor style). */
static char fake_battery_serial[40];
static int fake_battery_serial_len = 0;
static char fake_display_serial[24];
static int fake_display_serial_len = 0;
static char fake_ufs_serial[24];
static int fake_ufs_serial_len = 0;
/* boot_id = per-boot UUID (36 chars: 8-4-4-4-12) + trailing '\n'. Derived from
 * android_id_seed (per-seed, NOT per-UID — real boot_id is identical across all
 * apps, so a per-app value would be a tell). Rotates when the seed changes. */
static char fake_boot_id[40];
static int fake_boot_id_len = 0;

/* Diagnostic counters — exposed in ctl0 ioctl_stats. */
unsigned int g_proc_version_spoofed = 0;
unsigned int g_proc_cpuinfo_spoofed = 0;
unsigned int g_proc_inet6_spoofed = 0;
unsigned int g_boot_id_spoofed = 0;
unsigned int g_battery_serial_spoofed = 0;
unsigned int g_display_serial_spoofed = 0;
unsigned int g_ufs_serial_spoofed = 0;
unsigned int g_soc0_spoofed = 0;
unsigned int g_mountinfo_filtered = 0;
unsigned int g_mountinfo_seen = 0;
/* UID-gated /proc/version redirect counter (profile.h extern).
 * Currently the existing FD_TYPE_PROC_VERSION path in lp_read_hook handles this.
 * proc_version_uid_redirect_enabled flag gates future extension (e.g. a
 * secondary pass for fds not caught by openat tracking). For now the counter
 * mirrors g_proc_version_spoofed when the flag is set.
 * Defined here to satisfy the extern in profile.h. */
unsigned int g_proc_version_uid_repl = 0;

/* splitmix64 — same primitive used in binder_hook.c for per-UID
 * derivation. Keeping the implementation local here avoids a cross-TU
 * symbol export; the few bytes of duplication are the cleanest option. */
static unsigned long long lp_splitmix64(unsigned long long x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static unsigned long long parse_seed_u64(const char *seed_hex)
{
    unsigned long long out = 0;
    for (int i = 0; i < 16 && seed_hex[i]; i++) {
        char c = seed_hex[i];
        unsigned long long v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else break;
        out = (out << 4) | v;
    }
    return out;
}

static void derive_hex_from_seed(unsigned long long base, char *out, int hex_len)
{
    static const char hex[] = "0123456789abcdef";
    unsigned long long state = base;
    for (int i = 0; i < hex_len; i++) {
        if ((i & 0xf) == 0) state = lp_splitmix64(state);
        out[i] = hex[(state >> ((i & 0xf) * 4)) & 0xf];
    }
}

/* Build fake_*_serial once per profile change. Called from lp_read_hook
 * lazily when seed transitions from empty→non-empty OR changes; we
 * detect "stale" by remembering the first byte of the seed we last
 * derived from. */
static char last_seen_seed_byte = 0;
static void refresh_fake_serials(void)
{
    if (!g_profile.android_id_seed[0]) {
        fake_battery_serial_len = 0;
        fake_display_serial_len = 0;
        fake_ufs_serial_len = 0;
        fake_boot_id_len = 0;
        last_seen_seed_byte = 0;
        return;
    }
    if (last_seen_seed_byte == g_profile.android_id_seed[0] && fake_battery_serial_len > 0) {
        return;
    }
    unsigned long long seed = parse_seed_u64(g_profile.android_id_seed);

    /* Battery serial: 24 hex (Maxim MAX1720x format is mixed alnum but
     * 24 hex is a plausible vendor encoding — apps don't validate
     * format beyond non-empty length). */
    derive_hex_from_seed(lp_splitmix64(seed ^ 0x4254525953524c30ULL /* "BTRYSRL0" */),
                         fake_battery_serial, 24);
    fake_battery_serial[24] = '\n';
    fake_battery_serial_len = 25;

    /* Display serial: 14 hex. Format observed on Pixel 6 OLED panel
     * (Samsung s6e3fc3) at the drmdsim serial_number sysfs node. */
    derive_hex_from_seed(lp_splitmix64(seed ^ 0x4453504c59534c30ULL /* "DSPLYSL0" */),
                         fake_display_serial, 14);
    fake_display_serial[14] = '\n';
    fake_display_serial_len = 15;

    /* UFS serial: 16 hex (eMMC/UFS string descriptor format). Pixel 6
     * currently exposes empty — keeping it derived gives consistency
     * regardless of how the kernel exposes this in future firmware. */
    derive_hex_from_seed(lp_splitmix64(seed ^ 0x5546535345524c30ULL /* "UFSSERL0" */),
                         fake_ufs_serial, 16);
    fake_ufs_serial[16] = '\n';
    fake_ufs_serial_len = 17;

    /* SoC serial (soc0/serial_number): 16 hex + \n. Not exposed on
     * Pixel 6's GS101, but registered so newer Tensor chips that DO
     * expose this don't leak per-chip identity. Distinct salt from UFS. */
    derive_hex_from_seed(lp_splitmix64(seed ^ 0x534f4330534e3030ULL /* "SOC0SN00" */),
                         fake_soc0_serial, 16);
    fake_soc0_serial[16] = '\n';
    fake_soc0_serial_len = 17;

    /* boot_id: per-boot UUID 8-4-4-4-12. Derived from the seed (identical
     * across all apps, matching real boot_id semantics), rotates on re-seed. */
    {
        char h[32];
        int j = 0, k = 0;
        derive_hex_from_seed(lp_splitmix64(seed ^ 0x424f4f5449443030ULL /* "BOOTID00" */), h, 32);
        for (int i = 0; i < 32; i++) {
            if (i == 8 || i == 12 || i == 16 || i == 20) fake_boot_id[j++] = '-';
            fake_boot_id[j++] = h[k++];
        }
        fake_boot_id[j++] = '\n';
        fake_boot_id_len = j; /* 36 UUID chars + '\n' = 37 */
    }

    last_seen_seed_byte = g_profile.android_id_seed[0];
}

/* Shared fd→type table lives in openat_hook.c (it owns the openat/close
 * choke-points that populate it). We consume it here via these externs.
 * COUPLING: the enum fd_type above MUST match openat_hook.c's copy, and the
 * (fd,pid) key must use the same pid dimension (current->tgid) in both. */
extern enum fd_type get_fd_type(int fd, int pid);
extern void clear_fd_tracking(int fd, int pid);
extern int is_bootid_fd(int fd, int pid);
extern int is_mounts_fd(int fd, int pid);

static inline bool is_valid_user_ptr(void __user *ptr)
{
    return ptr != NULL && ((unsigned long)ptr < 0x0000800000000000UL);
}

static void replace_mac_address(char *buf, const char *new_mac)
{
    for (int i = 0; i < 17 && new_mac[i]; i++) {
        buf[i] = new_mac[i];
    }
}

static bool str_contains(const char *haystack, size_t haystack_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len > haystack_len) return false;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

static char *find_xml_value(char *buf, size_t len, const char *key, size_t *value_len)
{
    char *found = NULL;
    size_t key_len = strlen(key);

    for (size_t i = 0; i + key_len + 8 <= len; i++) {
        if (buf[i] == 'n' && buf[i+1] == 'a' && buf[i+2] == 'm' && buf[i+3] == 'e' &&
            buf[i+4] == '=' && buf[i+5] == '"') {
            bool match = true;
            for (size_t j = 0; j < key_len; j++) {
                if (buf[i + 6 + j] != key[j]) {
                    match = false;
                    break;
                }
            }
            if (match && buf[i + 6 + key_len] == '"') {
                found = &buf[i];
                break;
            }
        }
    }

    if (!found) return NULL;

    char *gt = NULL;
    for (char *p = found; p < buf + len; p++) {
        if (*p == '>') { gt = p + 1; break; }
    }
    if (!gt) return NULL;

    char *lt = NULL;
    for (char *p = gt; p < buf + len; p++) {
        if (*p == '<') { lt = p; break; }
    }
    if (!lt) return NULL;

    *value_len = lt - gt;
    return gt;
}

static bool spoof_xml_value(char *buf, size_t len, const char *key, const char *new_val)
{
    size_t value_len;
    char *value = find_xml_value(buf, len, key, &value_len);
    if (!value) return false;

    size_t new_len = strlen(new_val);
    if (new_len > value_len) return false;

    memcpy(value, new_val, new_len);

    if (new_len < value_len) {
        for (size_t i = new_len; i < value_len; i++) {
            value[i] = ' ';
        }
    }

    return true;
}

static bool is_mac_format(const char *buf, size_t len)
{
    if (len < 17) return false;
    int colons = 0;
    int hex_chars = 0;
    for (int i = 0; i < 17; i++) {
        char c = buf[i];
        if (c == ':') {
            colons++;
        } else if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            hex_chars++;
        } else {
            return false;
        }
    }
    return (colons == 5 && hex_chars == 12);
}

/* Detect whether the calling PROCESS is still a bare zygote fork that hasn't
 * finished specialization. Android sets argv0 (and comm) to the placeholder
 * "<pre-initialized>" between fork and bindApplication; the ART runtime reads
 * /proc/sys/kernel/random/boot_id exactly once during this window — and,
 * empirically, from a *binder* worker thread (comm "binder:<pid>_N"), NOT the
 * main thread. So we can't look at the current thread's comm; we must read the
 * process-wide leader comm. find_task_by_vpid(tgid) yields the thread-group
 * leader, whose comm is "<pre-initialize" (TASK_COMM_LEN-truncated) until
 * bindApplication renames it to the package name.
 *
 * Spoofing that pre-init read wedges startup ("failed to complete startup"
 * ANR). App fingerprinting code reads boot_id later, once comm is the package
 * name, so it still gets the spoof.
 *
 * Direct kernel calls (built-in): find_task_by_vpid + __get_task_comm under
 * rcu_read_lock. Fail-safe: any lookup miss returns true (treat as pre-init →
 * skip spoof) so it can never re-break startup. */
static bool lp_task_is_preinit(void)
{
    char cmn[20];
    struct task_struct *leader;
    int tgid = current->tgid;

    cmn[0] = '\0';
    leader = NULL;
    rcu_read_lock();
    leader = find_task_by_vpid(tgid);
    if (leader) __get_task_comm(cmn, sizeof(cmn), leader);
    rcu_read_unlock();
    if (!leader) return true;
    cmn[sizeof(cmn) - 1] = '\0';
    /* comm is a TASK_COMM_LEN(16) truncation of Android's "<pre-initialized>"
     * argv0. On this kernel it truncates from the TAIL, giving
     * "re-initialized>" rather than a "<pre-…" head — so match the stable
     * interior substring "initial", which survives either truncation and never
     * appears in a real package name or thread name. */
    {
        int L = 0;
        while (L < (int)sizeof(cmn) && cmn[L]) L++;
        return str_contains(cmn, (size_t)L, "initial");
    }
}

/*
 * lp_read_hook — VFS read() choke-point.
 *
 * Called from fs/read_write.c ksys_read()/ksys_pread64() after a successful
 * vfs_read() (ret > 0). Returns the (possibly shrunk) byte count that the
 * syscall should report to userspace — the mount-filter path drops whole
 * lines and MUST propagate the reduced length, so this returns `ret` rather
 * than being void (see call-site note). pread64 shares this path: it passes
 * (fd, buf, ret); the file offset is irrelevant to substring filtering.
 */
long lp_read_hook(int fd, char __user *buf, long ret)
{
    if (!g_hooks_enabled) return ret;
    if (ret <= 0) return ret;

    void __user *ubuf = (void __user *)buf;
    if (!is_valid_user_ptr(ubuf)) return ret;

    int uid = lp_cur_uid();
    /* lp_is_uid_excluded also rejects UID 0 unconditionally (root daemons
     * never get spoofed). The check covers both that and the configured
     * exclusion list. */
    if (lp_is_uid_excluded((__u32)uid)) return ret;
    int pid = current->tgid;
    enum fd_type type = get_fd_type(fd, pid);

    /* Recover boot_id reads whose fd was evicted from the shared tracking
     * table before the read (Java InputStreamReader path). The dedicated
     * boot_id table never evicts, so a NONE here that is_bootid_fd catches
     * is a real boot_id read. */
    if (type == FD_TYPE_NONE && g_profile.boot_id_spoof_enabled && is_bootid_fd(fd, pid))
        type = FD_TYPE_PROC_BOOT_ID;

    /* Same recovery for the /proc mounts fd: a delayed big read() (Ferrite/dd
     * open -> table churns -> one read) loses its shared-table slot, so a NONE
     * that the eviction-proof mounts table catches is a real mounts read that
     * must still be filtered for the /data_mirror + APatch root tells. */
    if (type == FD_TYPE_NONE && is_mounts_fd(fd, pid))
        type = FD_TYPE_PROC_MOUNTS;

    if (type == FD_TYPE_NONE) return ret;

    /* Size-cap for fixed-size stack-buffer paths. Mount-filter path below
     * handles its own cap. Without this gate a read of e.g. 64 KB from
     * sharedprefs would overflow `char buf[4096]` and panic. */
    if (type != FD_TYPE_PROC_MOUNTS && ret > MAX_BUF_SIZE) return ret;

    if ((type == FD_TYPE_WIFI_MAC || type == FD_TYPE_BT_MAC) && ret >= 17 && ret <= 32) {
        /* Empty-profile bail-out: when wifi_mac_hook / bt_mac_hook are off
         * the companion APK pushes empty `set_wifi_mac:` / `set_bt_mac:`
         * so the corresponding profile field is "". Without this guard
         * replace_mac_address would write the empty string into the
         * sysfs read buffer, leaving the app with a corrupted MAC. */
        const char *new_mac = (type == FD_TYPE_WIFI_MAC) ? g_profile.wifi_mac : g_profile.bluetooth_mac;
        if (!new_mac[0]) return ret;

        char mbuf[64];
        long copied = lp_copy_from_user(mbuf, ubuf, ret);
        if (copied <= 0) return ret;
        mbuf[copied] = '\0';

        if (is_mac_format(mbuf, copied)) {
            replace_mac_address(mbuf, new_mac);
            lp_copy_to_user(ubuf, mbuf, ret);
        }
        return ret;
    }

    /* SUSFS open_redirect bypass: app uids reading /proc/{version,cpuinfo,
     * net/if_inet6} got the real content because susfs v2.0.0 GKI has
     * uid<=2000 limit. We overwrite the userspace buffer with our fake
     * content here, capped at `ret` (whatever the original syscall actually
     * filled), so apps that don't read the full file still get a clean
     * truncation. Source content is compile-time-const, no kalloc, no
     * sleep — safe in choke-point context. */
    if (type == FD_TYPE_PROC_VERSION) {
        size_t n = (size_t)ret;
        if (n > FAKE_PROC_VERSION_LEN) n = FAKE_PROC_VERSION_LEN;
        if (n > 0) lp_copy_to_user(ubuf, FAKE_PROC_VERSION, n);
        g_proc_version_spoofed++;
        /* Mirror into proc_version_uid_repl when UID-redirect flag is set. */
        if (g_profile.proc_version_uid_redirect_enabled) g_proc_version_uid_repl++;
        return ret;
    }
    if (type == FD_TYPE_PROC_CPUINFO) {
        size_t n = (size_t)ret;
        if (n > FAKE_PROC_CPUINFO_LEN) n = FAKE_PROC_CPUINFO_LEN;
        if (n > 0) lp_copy_to_user(ubuf, FAKE_PROC_CPUINFO, n);
        g_proc_cpuinfo_spoofed++;
        return ret;
    }
    if (type == FD_TYPE_PROC_INET6) {
        size_t n = (size_t)ret;
        if (n > FAKE_PROC_INET6_LEN) n = FAKE_PROC_INET6_LEN;
        if (n > 0) lp_copy_to_user(ubuf, FAKE_PROC_INET6, n);
        g_proc_inet6_spoofed++;
        return ret;
    }

    if (type == FD_TYPE_PROC_BOOT_ID) {
        if (g_profile.boot_id_spoof_enabled) {
            /* Only spoof for app UIDs (never system/zygote), and only once the
             * process has finished specialization. */
            int bid_uid = lp_cur_uid();
            if (bid_uid >= 10000 && !lp_is_uid_excluded((unsigned int)bid_uid) &&
                !lp_task_is_preinit()) {
                refresh_fake_serials();
                if (fake_boot_id_len > 0) {
                    size_t n = (size_t)ret;
                    if (n > (size_t)fake_boot_id_len) n = (size_t)fake_boot_id_len;
                    if (n > 0) lp_copy_to_user(ubuf, fake_boot_id, n);
                    g_boot_id_spoofed++;
                }
            }
        }
        return ret;
    }
    /* /sys/devices/soc0/ spoof DISABLED (v37, 2026-05-17).
     *
     * Reason: previous "Oriole DVT" -> "Oriole" rewrite created an impossible
     * combination for vendor Lyric camera HAL on engineering-sample Pixel 6
     * (real revision=17/A1 silicon + spoofed retail "Oriole" machine string).
     * Lyric rejected the inconsistency, refused to load the camera provider
     * APEX, leaving camera permanently black. */
    if (type == FD_TYPE_SOC0_MACHINE
        || type == FD_TYPE_SOC0_FAMILY
        || type == FD_TYPE_SOC0_SOCID
        || type == FD_TYPE_SOC0_REVISION
        || type == FD_TYPE_SOC0_SERIAL) {
        return ret;
    }
    /* Per-component sysfs serials. refresh_fake_serials() is a no-op
     * when the seed hasn't changed since last call. If the seed is empty
     * we fall through to no-op — apps see the real kernel-side serial.
     * Zero-init a local buffer, memcpy our fake into the head, copy the
     * full ret bytes back — any tail past our fake is guaranteed NUL, so
     * the kernel buffer's real-serial-suffix can't leak. */
    if (type == FD_TYPE_BATTERY_SERIAL) {
        refresh_fake_serials();
        if (fake_battery_serial_len > 0) {
            char sbuf[64] = {0};
            size_t n = (size_t)ret;
            if (n > sizeof(sbuf)) n = sizeof(sbuf);
            size_t hd = (size_t)fake_battery_serial_len;
            if (hd > n) hd = n;
            memcpy(sbuf, fake_battery_serial, hd);
            if (n > 0) lp_copy_to_user(ubuf, sbuf, n);
            g_battery_serial_spoofed++;
        }
        return ret;
    }
    if (type == FD_TYPE_DISPLAY_SERIAL) {
        refresh_fake_serials();
        if (fake_display_serial_len > 0) {
            char sbuf[64] = {0};
            size_t n = (size_t)ret;
            if (n > sizeof(sbuf)) n = sizeof(sbuf);
            size_t hd = (size_t)fake_display_serial_len;
            if (hd > n) hd = n;
            memcpy(sbuf, fake_display_serial, hd);
            if (n > 0) lp_copy_to_user(ubuf, sbuf, n);
            g_display_serial_spoofed++;
        }
        return ret;
    }
    if (type == FD_TYPE_UFS_SERIAL) {
        refresh_fake_serials();
        if (fake_ufs_serial_len > 0) {
            char sbuf[64] = {0};
            size_t n = (size_t)ret;
            if (n > sizeof(sbuf)) n = sizeof(sbuf);
            size_t hd = (size_t)fake_ufs_serial_len;
            if (hd > n) hd = n;
            memcpy(sbuf, fake_ufs_serial, hd);
            if (n > 0) lp_copy_to_user(ubuf, sbuf, n);
            g_ufs_serial_spoofed++;
        }
        return ret;
    }
    /* /proc/{mounts,self/mountinfo,<pid>/mountinfo}: drop ENTIRE lines that
     * contain any tell-tale substring. The kernel returned `ret` bytes; we
     * compact survivors and shrink the reported count (returned to the caller)
     * so userspace read() sees the smaller byte count. */
    if (type == FD_TYPE_PROC_MOUNTS) {
        g_mountinfo_seen++;
        static const char * const NEEDLES[] = {
            "lukeprivacy_kpm",
            "KPatch-Next",
            "kp-next",
            "KernelPatch",
            "lukeshield",
            "overlay KSU",    /* fs-type/source string emitted by KSU overlay mount */
            "/data/adb/ksu",
            "/data/adb/modules",
            "/data_mirror",   /* KernelSU AND APatch global data-mirror binds — stock
                               * Android has NO /data_mirror; its presence is a root tell */
            "APatch",         /* APatch magic-mount source marker; stock never emits it */
        };
        const int NEEDLE_COUNT = sizeof(NEEDLES) / sizeof(NEEDLES[0]);

        /* Filter using ONLY a 4 KB stack scratch — no kmalloc, no static BSS.
         * Read ubuf in <=4 KB windows aligned to the last '\n' so no mount line
         * is ever split across a window, filter each window's complete lines,
         * and compact survivors back into ubuf. write_off <= read_off always. */
        size_t total = (size_t)ret;
        if (total > 65536) total = 65536;
        char stackbuf[MAX_BUF_SIZE];
        size_t read_off = 0, write_off = 0;
        bool any_dropped = false;

        while (read_off < total) {
            size_t want = total - read_off;
            if (want > MAX_BUF_SIZE) want = MAX_BUF_SIZE;
            long got = lp_copy_from_user(stackbuf, ubuf + read_off, want);
            if (got <= 0) break;
            size_t glen = (size_t)got;

            bool final_window = (read_off + glen >= total);
            size_t proc_len = glen;
            if (!final_window) {
                bool found = false;
                for (size_t i = glen; i > 0; i--) {
                    if (stackbuf[i - 1] == '\n') { proc_len = i; found = true; break; }
                }
                if (!found) proc_len = glen;   /* no '\n' in 4 KB -> take all */
            }

            size_t wp = 0, ls = 0;
            for (size_t i = 0; i <= proc_len; i++) {
                if (i == proc_len || stackbuf[i] == '\n') {
                    if (i == proc_len && ls == i) break;
                    size_t le = (i == proc_len) ? i : (i + 1);  /* include '\n' */
                    size_t ll = le - ls;

                    bool drop = false;
                    for (int k = 0; k < NEEDLE_COUNT && !drop; k++) {
                        const char *needle = NEEDLES[k];
                        size_t nlen = 0;
                        while (needle[nlen]) nlen++;
                        if (nlen > ll) continue;
                        for (size_t off = 0; off + nlen <= ll; off++) {
                            bool match = true;
                            for (size_t j = 0; j < nlen; j++) {
                                if (stackbuf[ls + off + j] != needle[j]) { match = false; break; }
                            }
                            if (match) { drop = true; break; }
                        }
                    }

                    if (drop) {
                        any_dropped = true;
                    } else {
                        if (wp != ls) {
                            for (size_t j = 0; j < ll; j++) stackbuf[wp + j] = stackbuf[ls + j];
                        }
                        wp += ll;
                    }
                    ls = le;
                    if (i == proc_len) break;
                }
            }

            if (wp > 0) lp_copy_to_user(ubuf + write_off, stackbuf, wp);
            write_off += wp;
            read_off += proc_len;
            if (proc_len == 0) break;
        }

        if (any_dropped) {
            /* Zero the freed tail [write_off, total) so a reader that ignores
             * read()'s shrunk return and scans its whole buffer can't see the
             * stale root-mount lines we compacted out. */
            if (write_off < total) {
                char zeros[256];
                for (size_t j = 0; j < sizeof(zeros); j++) zeros[j] = 0;
                size_t z = write_off;
                while (z < total) {
                    size_t c = total - z;
                    if (c > sizeof(zeros)) c = sizeof(zeros);
                    lp_copy_to_user(ubuf + z, zeros, c);
                    z += c;
                }
            }
            ret = (long)write_off;   /* propagate shrunk count to caller */
            g_mountinfo_filtered++;
        }
        return ret;
    }

    char cbuf[MAX_BUF_SIZE];
    long copied = lp_copy_from_user(cbuf, ubuf, ret);
    if (copied <= 0) return ret;
    cbuf[copied] = '\0';

    bool modified = false;

    if (type == FD_TYPE_SHAREDPREFS) {
        /* Gate on profile value non-empty BEFORE calling spoof_xml_value.
         * Empty profile means the corresponding hook is toggled OFF (companion
         * pushes "" to clear g_profile.*). spoof_xml_value(value="") would
         * zero-replace + space-pad the existing value slot — pure corruption. */
        if (g_profile.advertising_id[0] &&
            (str_contains(cbuf, ret, "adid") || str_contains(cbuf, ret, "advertising"))) {
            if (spoof_xml_value(cbuf, ret, "adid", g_profile.advertising_id)) {
                modified = true;
            }
        }
        if (g_profile.firebase_id[0] &&
            (str_contains(cbuf, ret, "Fid") || str_contains(cbuf, ret, "firebase"))) {
            if (spoof_xml_value(cbuf, ret, "Fid", g_profile.firebase_id)) {
                modified = true;
            }
        }
    }

    if (modified) {
        lp_copy_to_user(ubuf, cbuf, ret);
    }

    return ret;
}

/* ─── setup-only lifecycle (no runtime syscall hooks any more) ────────────
 *
 * The boot_id proc_do_uuid / random_table pointer swap is REMOVED in the
 * built-in port: it was never installed in the KPM either (the workflow
 * reboots between accounts so boot_id rotates naturally), and proc_do_uuid /
 * random_table are static in drivers/char/random.c — unreachable by direct
 * symbol from this driver TU. boot_id spoofing still functions through the
 * FD_TYPE_PROC_BOOT_ID path above. */
int read_hook_init(void)
{
    /* Nothing to install; kept as a hook for future setup and to satisfy the
     * extern in lukeprivacy.c. */
    pr_info("lukeprivacy: read choke-point ready\n");
    return 0;
}

void read_hook_exit(void)
{
}
