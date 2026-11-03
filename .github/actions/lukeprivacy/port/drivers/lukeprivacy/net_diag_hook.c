// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <net/sock.h>

#include "profile.h"

extern unsigned int g_tcp_seq_hidden;

bool lp_netdiag_relay_hidden(const struct sock *sk)
{
    if (!sk || !g_hooks_enabled || !g_profile.net_hide_enabled)
        return false;
    if (from_kuid(&init_user_ns, current_uid()) < 10000)
        return false;
    if (!uid_eq(sock_i_uid(sk), GLOBAL_ROOT_UID))
        return false;
    if (sk->sk_num != 8899 && sk->sk_num != 8391)
        return false;
    g_tcp_seq_hidden++;
    return true;
}
