/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LUKEPRIVACY_LP_LOG_H
#define _LUKEPRIVACY_LP_LOG_H

#include <linux/printk.h>

/* Per-call diagnostic logging. Off by default for production builds —
 * dmesg is readable by `shell` UID and would emit signals for anyone
 * inspecting kernel logs (captured real_phone_bare length, GNSS parcel
 * hits, openat path traces, ioctl reply offsets, per-package exclusion
 * resolution). Counters in g_* globals are surfaced via ctl0 ioctl_stats
 * and remain available for diagnostics regardless. Enable by passing
 * -DLP_DEBUG to the build. */
#ifdef LP_DEBUG
#define lp_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define lp_dbg(fmt, ...) do { } while (0)
#endif

#endif
