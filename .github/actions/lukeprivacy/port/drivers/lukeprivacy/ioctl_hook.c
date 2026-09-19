/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy (built-in kernel port) - Binder ioctl() diagnostic hook.
 *
 * Targets (diagnostic counters only — the actual IMSI/IMEI/ICCID spoof
 * happens in binder_hook.c with strict anchors):
 * - TelephonyManager (IMEI, IMSI, ICCID, phone number)
 * - SubscriptionInfo (carrier info)
 *
 * PORT NOTES (vs KernelPatch KPM):
 *   - No syscall inline-hook. Invoked from a direct call-site in
 *     drivers/android/binder.c :: binder_ioctl() via
 *     lp_ioctl_hook(cmd, arg, ret) AFTER binder_ioctl computed its return.
 *   - syscall_argn(args,1/2) -> cmd / arg function parameters.
 *   - uid via from_kuid(&init_user_ns, current_uid()).
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/types.h>

#include "profile.h"
#include "uaccess.h"
#include "lp_log.h"

void lp_ioctl_hook(unsigned int cmd, unsigned long arg, long ret);

#define BINDER_WRITE_READ_CMD 0xc0306201

#define BR_REPLY 0x80407203

#define MAX_PARCEL_SIZE 4096

typedef unsigned long binder_size_t;
typedef unsigned long binder_uintptr_t;

struct lp_binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct lp_binder_transaction_data {
    union {
        __u32 handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    __u32 code;
    __u32 flags;
    __s32 sender_pid;
    __u32 sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

static inline __u32 lp_current_uid(void)
{
    return from_kuid(&init_user_ns, current_uid());
}

static inline bool is_valid_user_ptr(void __user *ptr)
{
    return ptr != NULL && ((unsigned long)ptr < 0x0000800000000000UL);
}

static inline void __user *strip_mte_tag(void __user *ptr)
{
    return (void __user *)((unsigned long)ptr & 0x00FFFFFFFFFFFFFFUL);
}

/* PlanPrecision A1 (2026-05-11): removed `spoof_reply_string` + format
 * helpers and the ioctl-level parcel rewrite. binder_hook.c handles the
 * telephony replies with strict structural anchors, so this layer keeps
 * only the BR_REPLY parsing infrastructure + diagnostic counters so
 * ioctl_stats stays informative. */

int g_ioctl_binder_calls = 0;
int g_ioctl_br_reply = 0;
int g_ioctl_telephony_match = 0;
int g_ioctl_has_read = 0;
__u32 g_last_br_cmd = 0;
binder_size_t g_last_read_consumed = 0;
__u32 g_dump_first8[2] = {0};
binder_uintptr_t g_last_read_buf = 0;
binder_size_t g_last_write_size = 0;
binder_size_t g_last_read_size = 0;
int g_bwr_copy_ok = 0;
binder_uintptr_t g_last_argp = 0;
binder_size_t g_last_parcel_size = 0;
__u32 g_last_tx_code = 0;

/* ===== Exposed call-site entry ===== *
 * Invoke from binder_ioctl() with its cmd, arg and computed return value. */
void lp_ioctl_hook(unsigned int cmd, unsigned long arg, long ret)
{
    if (!g_hooks_enabled) return;

    if (lp_is_uid_excluded(lp_current_uid())) return;

    if (ret < 0) return;

    if (cmd != BINDER_WRITE_READ_CMD) return;

    g_ioctl_binder_calls++;

    void __user *argp = (void __user *)arg;
    g_last_argp = (binder_uintptr_t)argp;
    if (!is_valid_user_ptr(argp)) return;

    struct lp_binder_write_read bwr;
    long bwr_ret = lp_copy_from_user(&bwr, argp, sizeof(bwr));
    g_bwr_copy_ok = (int)bwr_ret;
    if (bwr_ret <= 0) return;

    binder_size_t min_size = sizeof(__u32) + sizeof(struct lp_binder_transaction_data);
    if (bwr.read_consumed < min_size) return;

    g_ioctl_has_read++;
    g_last_read_consumed = bwr.read_consumed;
    g_last_read_buf = bwr.read_buffer;
    g_last_write_size = bwr.write_size;
    g_last_read_size = bwr.read_size;

    void __user *read_buf = strip_mte_tag((void __user *)bwr.read_buffer);
    if (!is_valid_user_ptr(read_buf)) return;

    char scan_buf[256];
    binder_size_t scan_len = bwr.read_consumed < 256 ? bwr.read_consumed : 256;
    if (lp_copy_from_user(scan_buf, read_buf, scan_len) <= 0) return;

    g_dump_first8[0] = *((__u32 *)scan_buf);
    g_dump_first8[1] = *((__u32 *)(scan_buf + 4));
    g_last_br_cmd = g_dump_first8[0];

    __u32 *ptr = (__u32 *)scan_buf;
    binder_size_t offset = 0;
    bool found_reply = false;

    while (offset + sizeof(__u32) + sizeof(struct lp_binder_transaction_data) <= scan_len) {
        __u32 br_cmd = *ptr;
        if (br_cmd == BR_REPLY) {
            found_reply = true;
            g_ioctl_br_reply++;
            break;
        }
        if (br_cmd == 0x720c) { offset += 4; ptr++; continue; }
        if (br_cmd == 0x7206) { offset += 4; ptr++; continue; }
        offset += 4;
        ptr++;
    }

    if (!found_reply) return;

    struct lp_binder_transaction_data *tr =
        (struct lp_binder_transaction_data *)(scan_buf + offset + sizeof(__u32));
    if (offset + sizeof(__u32) + sizeof(struct lp_binder_transaction_data) > scan_len) return;

    g_last_parcel_size = tr->data_size;
    g_last_tx_code = tr->code;

    if (tr->data_size == 0 || tr->data_size > MAX_PARCEL_SIZE) return;

    void __user *tr_user = (void __user *)(bwr.read_buffer + offset + sizeof(__u32));
    tr_user = strip_mte_tag(tr_user);

    binder_uintptr_t parcel_buf_addr;
    size_t buf_offset = offsetof(struct lp_binder_transaction_data, data.ptr.buffer);
    if (lp_copy_from_user(&parcel_buf_addr, (void __user *)((char *)tr_user + buf_offset),
                          sizeof(parcel_buf_addr)) <= 0)
        return;

    void __user *parcel_ptr = strip_mte_tag((void __user *)parcel_buf_addr);
    if (!is_valid_user_ptr(parcel_ptr)) return;

    /* PlanPrecision A1: parcel rewrite at ioctl layer removed. The actual
     * IMSI/IMEI/ICCID spoof happens in binder_hook.c with strict anchors.
     * Counters above stay populated for diagnostics. */
    (void)parcel_ptr;
    (void)parcel_buf_addr;
}

/* Setup-only: no syscall registration. */
int ioctl_hook_init(void)
{
    return 0;
}

void ioctl_hook_exit(void)
{
}
