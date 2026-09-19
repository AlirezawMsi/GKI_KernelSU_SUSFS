/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy KPM - User access helpers
 */

#ifndef _LUKEPRIVACY_UACCESS_H
#define _LUKEPRIVACY_UACCESS_H

#include <linux/string.h>
#include <linux/uaccess.h>

extern int lp_init_uaccess(void);
extern long lp_copy_from_user(void *to, const void __user *from, unsigned long n);
extern long lp_copy_to_user_raw(void __user *to, const void *from, unsigned long n);

static inline int lp_copy_to_user(void __user *to, const void *from, int n)
{
    return (int)lp_copy_to_user_raw(to, from, n);
}

#endif
