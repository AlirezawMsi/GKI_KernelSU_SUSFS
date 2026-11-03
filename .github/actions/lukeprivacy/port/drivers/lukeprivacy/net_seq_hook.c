/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Filter TCP and UNIX socket records before procfs formats them. TCP uses the
 * relay-cookie registry in net_diag_hook.c, which is valid for listener,
 * request, established, and TIME_WAIT records without querying socket ownership.
 * UNIX matches only the exact abstract oracle address.
 */

#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/lukeprivacy.h>
#include <net/sock.h>
#include <net/af_unix.h>

#include "profile.h"
#include "lp_log.h"

/* The UNIX name matches the root daemon. TCP relay cookies are tracked by
 * net_diag_hook.c from listen through accept and TIME_WAIT. */
#define LP_SEQ_UNIX_NEEDLE "cronet_ipc"

unsigned int g_tcp_seq_hidden = 0;
unsigned int g_unix_seq_hidden = 0;

static bool lp_seq_reader_hidden(void)
{
	if (!g_hooks_enabled || !g_profile.net_hide_enabled)
		return false;
	return from_kuid(&init_user_ns, current_uid()) >= 10000;
}

int lp_tcp_seq_hidden(struct sock *sk)
{
	if (sk == SEQ_START_TOKEN || !sk)
		return 0;
	return lp_netdiag_relay_hidden(sk) ? 1 : 0;
}

/* /proc/net/unix (unix_seq_show): drop only the exact abstract oracle address.
 * Lock-free u->addr read — see SAFETY note at top. */
int lp_unix_seq_hidden(const struct sock *sk)
{
	const struct unix_sock *u;
	const struct unix_address *addr;
	const char *name;
	int plen;
	static const char needle[] = LP_SEQ_UNIX_NEEDLE;
	const int nlen = (int)sizeof(needle) - 1;

	if (sk == SEQ_START_TOKEN || !sk)
		return 0;
	if (!lp_seq_reader_hidden())
		return 0;

	u = unix_sk(sk);
	addr = READ_ONCE(u->addr);              /* immutable after bind; NULL if unbound */
	if (!addr)
		return 0;

	plen = (int)addr->len - (int)offsetof(struct sockaddr_un, sun_path);
	if (plen != nlen + 1 || plen > (int)sizeof(addr->name->sun_path))
		return 0;
	name = addr->name->sun_path;
	if (name[0] == '\0' && memcmp(name + 1, needle, nlen) == 0) {
		g_unix_seq_hidden++;
		return 1;
	}
	return 0;
}
