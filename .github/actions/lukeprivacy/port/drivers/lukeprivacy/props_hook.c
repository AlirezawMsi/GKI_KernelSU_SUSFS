/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy (built-in kernel port) — property service write hook
 * (DISABLED placeholder).
 *
 * History: an attempt to hook sendto() from radio UID 1001 to drop
 * gsm.operator.* prop_msg writes (so RIL couldn't overwrite our spoofed
 * carrier name) caused a kernel PANIC (0xbaba) on the very first Save
 * after install on 2026-05-11. The pstore ramoops was overwritten before
 * the trace could be recovered, so the exact failure mode is undiagnosed.
 *
 * Mitigation: companion APK SimMaintenanceService ticks at 500ms as a
 * ForegroundService. KPM-side blocking is the proper fix once we have a
 * reproducer with a captured stack.
 *
 * PORT NOTES: this file registers NOTHING. props_hook_init() is a no-op
 * that returns 0. There is NO call-site for this hook anywhere in the
 * kernel tree. Counters are kept so ioctl_stats still links.
 */

#include <linux/kernel.h>
#include <linux/printk.h>

#include "profile.h"

/* Counters exposed in ctl0 ioctl_stats. Keep declarations so lukeprivacy.c
 * `extern unsigned int g_prop_writes_seen, g_prop_writes_blocked;` still
 * links — values stay 0 while hook is disabled. */
unsigned int g_prop_writes_seen = 0;
unsigned int g_prop_writes_blocked = 0;

/* No-op init: no registration, no call-site. */
int props_hook_init(void)
{
    pr_info("lukeprivacy: props_hook DISABLED (kernel PANIC 0xbaba on first Save 2026-05-11)\n");
    return 0;
}

void props_hook_exit(void)
{
}
