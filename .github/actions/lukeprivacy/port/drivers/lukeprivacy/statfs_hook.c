/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy (built-in kernel port) - statfs() / fstatfs() f_type spoof.
 * Rewrites OVERLAYFS_MAGIC -> EROFS_MAGIC for app-UID callers so fraud
 * SDKs (Holmes Narcissus etc.) cannot detect KSU module bind-mounts via
 * the statfs syscall path (which bypasses read() and the read_hook).
 *
 * PORT NOTES (vs KernelPatch KPM):
 *   - No syscall inline-hook. Invoked from a direct call-site in fs/statfs.c
 *     via lp_statfs_hook(ubuf, ret) AFTER the struct statfs has been copied
 *     to userspace (covers both statfs and fstatfs — same tail path).
 *   - uid via from_kuid(&init_user_ns, current_uid()).
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/types.h>

#include "profile.h"
#include "uaccess.h"

void lp_statfs_hook(void __user *buf, long ret);

static inline __u32 lp_current_uid(void)
{
    return from_kuid(&init_user_ns, current_uid());
}

static inline bool is_valid_user_ptr(void __user *ptr)
{
    return ptr != NULL && ((unsigned long)ptr < 0x0000800000000000UL);
}

/* AArch64 native struct statfs: f_type at offset 0, 8 bytes wide. */
#define OFFSET_F_TYPE 0
#define SIZE_F_TYPE   8

/* Linux fs magic numbers from include/uapi/linux/magic.h. */
#define OVERLAYFS_MAGIC  0x794C7630UL  /* "0vLy" */
#define EROFS_MAGIC      0xE0F5E1E2UL  /* Pixel 6 /system fs */
#define EROFS_MAGIC_V1   0xE0F5E1E0UL  /* legacy v1 magic */

unsigned int g_statfs_overlay_seen     = 0;
unsigned int g_statfs_overlay_rewritten = 0;

static void rewrite_overlay_to_erofs(void __user *buf)
{
    if (!is_valid_user_ptr(buf)) return;

    unsigned long long f_type = 0;
    if (lp_copy_from_user(&f_type, buf + OFFSET_F_TYPE, SIZE_F_TYPE) <= 0) return;

    if (f_type != OVERLAYFS_MAGIC && f_type != (unsigned long long)OVERLAYFS_MAGIC) return;

    g_statfs_overlay_seen++;

    /* Spoof to EROFS — Pixel 6 /system uses it natively. Apps that see
     * EROFS on a /system path see the expected stock value. We never see
     * overlayfs on /data or /sdcard (those are ext4/f2fs/sdcardfs), so
     * this default doesn't cross-contaminate other path types. */
    unsigned long long new_type = EROFS_MAGIC;
    if (lp_copy_to_user(buf + OFFSET_F_TYPE, &new_type, SIZE_F_TYPE) <= 0) return;
    g_statfs_overlay_rewritten++;
}

/* ===== Exposed call-site entry ===== *
 * Invoke AFTER the struct statfs has been copied to userspace, on success
 * (ret == 0), for both __NR_statfs and __NR_fstatfs. buf = struct statfs *. */
void lp_statfs_hook(void __user *buf, long ret)
{
    if (!g_hooks_enabled) return;

    /* statfs/fstatfs return 0 on success. Bail if it failed — no valid
     * struct to rewrite. */
    if (ret != 0) return;

    /* UID gate. Same policy as the other read-side hooks: app UID
     * (>= 10000) and not on the exclude list. Skips root, system_server,
     * Google packages, our companion APK. */
    if (lp_is_uid_excluded(lp_current_uid())) return;

    rewrite_overlay_to_erofs(buf);
}

/* Setup-only: no syscall registration. */
int statfs_hook_init(void)
{
    return 0;
}

void statfs_hook_exit(void)
{
}
