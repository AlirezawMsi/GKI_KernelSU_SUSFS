/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy (built-in kernel port) - newfstatat()/fstat()/statx() st_dev spoof.
 * Holmes-style "Inconsistent Mount" check compares stat() st_dev between
 * parent and child paths under /system, /vendor, /product, /system_ext,
 * /apex. KSU module bind/overlay mounts give the child a fresh anon-bdev
 * (major=0); mismatch with the parent's real bdev is the tell. We rewrite
 * st_dev for app-context callers when the returned dev is overlay-anon,
 * normalising to the cached real dev for that prefix.
 *
 * PORT NOTES (vs KernelPatch KPM):
 *   - No syscall inline-hook. Logic is invoked from direct call-sites in
 *     fs/stat.c via lp_stat_hook(kind, upath, ubuf, ret) AFTER the stat
 *     struct has been copied to userspace. See "call-site" block below.
 *   - filp_open()/kernel_read()/filp_close() called directly (built-in).
 *   - uid via from_kuid(&init_user_ns, current_uid()).
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/types.h>

#include "profile.h"
#include "uaccess.h"

/* lp_stat_hook() dispatch kinds. Mirror in lp_hooks.h for the call-sites. */
#define LP_STAT_NEWFSTATAT 0
#define LP_STAT_STATX      1
#define LP_STAT_FSTAT      2

void lp_stat_hook(int kind, const char __user *upath, void __user *ubuf, long ret);

/* struct statx (linux/stat.h): stx_dev_major u32 @ 136, stx_dev_minor u32 @ 140. */
#define OFFSET_STX_DEV_MAJOR 136
#define OFFSET_STX_DEV_MINOR 140

/* asm-generic struct stat (aarch64): st_dev at offset 0, 8 bytes. */
#define OFFSET_ST_DEV 0
#define SIZE_ST_DEV   8

struct cached_dev {
    const char *prefix;
    int prefix_len;
    unsigned long long dev;
};

#define ROM_COUNT 5
static struct cached_dev g_real_dev[ROM_COUNT] = {
    { "/system",     7,  0 },
    { "/vendor",     7,  0 },
    { "/product",    8,  0 },
    { "/system_ext", 11, 0 },
    { "/apex",       5,  0 },
};

#define MAX_OVERLAY_DEVS 16
static unsigned long long g_overlay_devs[MAX_OVERLAY_DEVS];
static int g_overlay_devs_count = 0;

unsigned int g_stat_seen         = 0;
unsigned int g_stat_overlay_seen = 0;
unsigned int g_stat_rewritten    = 0;

static inline __u32 lp_current_uid(void)
{
    return from_kuid(&init_user_ns, current_uid());
}

static inline bool is_valid_user_ptr(void __user *ptr)
{
    return ptr != NULL && ((unsigned long)ptr < 0x0000800000000000UL);
}

/* Linux dev_t encoding: kernel internal new_encode_dev().
 *   encoded = ((major & ~0xFFF) << 32) | ((major & 0xFFF) << 8)
 *           | (minor & 0xFF) | ((minor & ~0xFF) << 12) */
static inline unsigned int dev_major(unsigned long long dev)
{
    return ((unsigned int)((dev >> 8) & 0xFFFULL))
         | ((unsigned int)((dev >> 32) & ~0xFFFULL));
}

static inline unsigned int dev_minor(unsigned long long dev)
{
    return ((unsigned int)(dev & 0xFFULL))
         | ((unsigned int)((dev >> 12) & ~0xFFULL));
}

static inline unsigned long long encode_dev(unsigned int major, unsigned int minor)
{
    return ((unsigned long long)(major & ~0xFFFU) << 32)
         | ((unsigned long long)(major & 0xFFFU) << 8)
         | ((unsigned long long)(minor & 0xFFU))
         | ((unsigned long long)(minor & ~0xFFU) << 12);
}

static int match_rom_prefix(const char *path)
{
    for (int i = 0; i < ROM_COUNT; i++) {
        int plen = g_real_dev[i].prefix_len;
        bool match = true;
        for (int j = 0; j < plen; j++) {
            if (path[j] != g_real_dev[i].prefix[j]) { match = false; break; }
        }
        if (!match) continue;
        char c = path[plen];
        if (c == '\0' || c == '/') return i;
    }
    return -1;
}

static bool is_overlay_dev(unsigned long long dev)
{
    for (int i = 0; i < g_overlay_devs_count; i++) {
        if (g_overlay_devs[i] == dev) return true;
    }
    return false;
}

/* ===== mountinfo parser: populate overlay_devs at init ===== */

static bool line_contains(const char *line, size_t llen, const char *needle)
{
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > llen) return false;
    for (size_t i = 0; i + nlen <= llen; i++) {
        bool m = true;
        for (size_t j = 0; j < nlen; j++) {
            if (line[i+j] != needle[j]) { m = false; break; }
        }
        if (m) return true;
    }
    return false;
}

static void mountinfo_line(const char *line, size_t llen)
{
    /* Filter: must be a KSU lukeprivacy overlay line. */
    if (!line_contains(line, llen, "overlay KSU")) return;
    if (!line_contains(line, llen, "lukeprivacy_kpm")) return;

    /* mountinfo format: <mountID> <parentID> <MAJOR:MINOR> <root> <mountpoint> ...
     * Skip past first two space-separated columns to land on column 3. */
    size_t pos = 0;
    int spaces = 0;
    while (pos < llen && spaces < 2) {
        if (line[pos] == ' ') spaces++;
        pos++;
    }
    if (spaces != 2 || pos >= llen) return;

    unsigned int major = 0, minor = 0;
    while (pos < llen && line[pos] >= '0' && line[pos] <= '9') {
        major = major * 10 + (line[pos] - '0');
        pos++;
    }
    if (pos >= llen || line[pos] != ':') return;
    pos++;
    while (pos < llen && line[pos] >= '0' && line[pos] <= '9') {
        minor = minor * 10 + (line[pos] - '0');
        pos++;
    }

    unsigned long long dev = encode_dev(major, minor);

    for (int i = 0; i < g_overlay_devs_count; i++) {
        if (g_overlay_devs[i] == dev) return; /* dedupe */
    }
    if (g_overlay_devs_count < MAX_OVERLAY_DEVS) {
        g_overlay_devs[g_overlay_devs_count++] = dev;
    }
}

static void scan_mountinfo(void)
{
    struct file *fp;
    static char chunk[4096];
    static char line[1024];
    size_t line_pos = 0;
    loff_t fpos = 0;

    fp = filp_open("/proc/self/mountinfo", O_RDONLY, 0);
    if (IS_ERR(fp) || !fp) {
        pr_warn("lukeprivacy: stat_hook: filp_open(/proc/self/mountinfo) failed\n");
        return;
    }

    for (;;) {
        ssize_t n = kernel_read(fp, chunk, sizeof(chunk), &fpos);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            char c = chunk[i];
            if (c == '\n') {
                if (line_pos > 0) mountinfo_line(line, line_pos);
                line_pos = 0;
            } else if (line_pos < sizeof(line) - 1) {
                line[line_pos++] = c;
            }
        }
    }
    if (line_pos > 0) mountinfo_line(line, line_pos);

    filp_close(fp, NULL);

    pr_info("lukeprivacy: stat_hook: cached %d overlay st_devs from mountinfo\n",
            g_overlay_devs_count);
}

/* ===== Hook bodies (uid gate + ret check already done in lp_stat_hook) ===== */

static void do_newfstatat(const char __user *upath, void __user *ubuf)
{
    if (!is_valid_user_ptr((void __user *)upath) || !is_valid_user_ptr(ubuf)) return;

    char path[260];
    long copied = lp_copy_from_user(path, upath, sizeof(path) - 1);
    if (copied <= 0) return;
    path[sizeof(path) - 1] = '\0';

    if (path[0] != '/') return;
    int rom = match_rom_prefix(path);
    if (rom < 0) return;

    g_stat_seen++;

    unsigned long long dev = 0;
    if (lp_copy_from_user(&dev, ubuf + OFFSET_ST_DEV, SIZE_ST_DEV) <= 0) return;

    unsigned int major = dev_major(dev);

    /* Cache real dev on the EXACT prefix path the first time we see a
     * major != 0 stat. */
    if (major != 0 && g_real_dev[rom].dev == 0) {
        if (path[g_real_dev[rom].prefix_len] == '\0') {
            g_real_dev[rom].dev = dev;
        }
    }

    /* Rewrite when: dev is anon-bdev (major=0) AND we have a cached real
     * dev for this rom, OR dev matches mountinfo overlay blacklist. */
    bool should_rewrite = false;
    if (major == 0 && g_real_dev[rom].dev != 0) should_rewrite = true;
    else if (is_overlay_dev(dev) && g_real_dev[rom].dev != 0) should_rewrite = true;

    if (should_rewrite) {
        g_stat_overlay_seen++;
        unsigned long long new_dev = g_real_dev[rom].dev;
        if (lp_copy_to_user(ubuf + OFFSET_ST_DEV, &new_dev, SIZE_ST_DEV) <= 0) return;
        g_stat_rewritten++;
    }
}

static void do_statx(const char __user *upath, void __user *ubuf)
{
    if (!is_valid_user_ptr(ubuf)) return;

    /* Path may be empty (AT_EMPTY_PATH + fd) or absolute. Try to read it
     * for prefix matching; if unreadable, fall through to blacklist path. */
    char path[260];
    path[0] = '\0';
    if (is_valid_user_ptr((void __user *)upath)) {
        long copied = lp_copy_from_user(path, upath, sizeof(path) - 1);
        if (copied > 0) path[sizeof(path) - 1] = '\0';
    }

    unsigned int cur_major = 0, cur_minor = 0;
    if (lp_copy_from_user(&cur_major, ubuf + OFFSET_STX_DEV_MAJOR, 4) <= 0) return;
    if (lp_copy_from_user(&cur_minor, ubuf + OFFSET_STX_DEV_MINOR, 4) <= 0) return;

    unsigned long long dev = encode_dev(cur_major, cur_minor);
    int rom = (path[0] == '/') ? match_rom_prefix(path) : -1;

    if (rom >= 0) g_stat_seen++;

    /* Lazy cache: exact prefix path + real major → cache for later. */
    if (rom >= 0 && cur_major != 0 && g_real_dev[rom].dev == 0) {
        if (path[g_real_dev[rom].prefix_len] == '\0') {
            g_real_dev[rom].dev = dev;
        }
    }

    /* Decide rewrite. */
    int target_rom = -1;
    if (rom >= 0 && cur_major == 0 && g_real_dev[rom].dev != 0) target_rom = rom;
    else if (is_overlay_dev(dev) && g_real_dev[0].dev != 0) target_rom = 0; /* fallback: ROM_SYSTEM */

    if (target_rom < 0) return;

    g_stat_overlay_seen++;
    unsigned int new_major = dev_major(g_real_dev[target_rom].dev);
    unsigned int new_minor = dev_minor(g_real_dev[target_rom].dev);
    if (lp_copy_to_user(ubuf + OFFSET_STX_DEV_MAJOR, &new_major, 4) <= 0) return;
    if (lp_copy_to_user(ubuf + OFFSET_STX_DEV_MINOR, &new_minor, 4) <= 0) return;
    g_stat_rewritten++;
}

static void do_fstat(void __user *ubuf)
{
    if (!is_valid_user_ptr(ubuf)) return;

    unsigned long long dev = 0;
    if (lp_copy_from_user(&dev, ubuf + OFFSET_ST_DEV, SIZE_ST_DEV) <= 0) return;

    /* Without path context we rely on the mountinfo-derived overlay-dev
     * blacklist + a cached real /system dev. */
    if (!is_overlay_dev(dev)) return;
    if (g_real_dev[0].dev == 0) return;  /* ROM_SYSTEM = index 0 */

    g_stat_seen++;
    g_stat_overlay_seen++;
    unsigned long long new_dev = g_real_dev[0].dev;
    if (lp_copy_to_user(ubuf + OFFSET_ST_DEV, &new_dev, SIZE_ST_DEV) <= 0) return;
    g_stat_rewritten++;
}

/* ===== Exposed call-site entry ===== *
 * Invoke AFTER the stat struct has been copied to userspace, on success.
 *   kind == LP_STAT_NEWFSTATAT : upath = user pathname, ubuf = struct stat *
 *   kind == LP_STAT_STATX      : upath = user pathname (may be ""), ubuf = struct statx *
 *   kind == LP_STAT_FSTAT      : upath = NULL, ubuf = struct stat *
 * ret is the syscall return value (0 == success). */
void lp_stat_hook(int kind, const char __user *upath, void __user *ubuf, long ret)
{
    if (!g_hooks_enabled) return;
    if (ret != 0) return;

    if (lp_is_uid_excluded(lp_current_uid())) return;

    switch (kind) {
    case LP_STAT_NEWFSTATAT: do_newfstatat(upath, ubuf); break;
    case LP_STAT_STATX:      do_statx(upath, ubuf);      break;
    case LP_STAT_FSTAT:      do_fstat(ubuf);             break;
    default: break;
    }
}

/* Setup-only: no syscall registration. Populates the overlay-dev blacklist
 * from mountinfo. Call once from the late init worker (after /proc is up).
 * FLAG: reads the init worker's mount namespace, not the app's — see FLAGS. */
int stat_hook_init(void)
{
    scan_mountinfo();
    return 0;
}

void stat_hook_exit(void)
{
}
