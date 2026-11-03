/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy - per-record /proc/net seq_show row filter (net_hide airtight layer).
 *
 * Filter TCP and UNIX socket records before tcp4_seq_show, tcp6_seq_show, or
 * unix_seq_show formats them. This preserves unrelated socket rows, avoids
 * read-boundary leaks, and lets TCP filtering use actual socket ownership.
 * inet_diag filtering is implemented separately in net_diag_hook.c.
 *
 * SAFETY (single remote device — a wrong dereference here panics the kernel):
 *  - TCP: sk_num lives in sock_common and is valid for every seq_show record
 *    state. sock_i_uid uses sk_callback_lock and handles sockets without an
 *    inode, so no state-dependent inet_sk() dereference is needed.
 *  - UNIX: u->addr is published once at bind via smp_store_release and is
 *    immutable until the socket is destroyed; the seq iteration pins the socket,
 *    so it cannot be freed under us. We READ_ONCE() the pointer (NULL-or-valid,
 *    never torn) and bail on NULL — a lock-free read that matches the bind-once
 *    invariant and takes no lock (so it can never deadlock against the
 *    unix_state_lock the caller takes right after us).
 *  - Both predicates are inert (return 0) unless g_hooks_enabled AND
 *    g_profile.net_hide_enabled, so on a fresh boot — before kpm_apply arms
 *    net_hide — every record formats exactly as stock.
 */

#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/stddef.h>            /* offsetof */
#include <linux/compiler.h>          /* READ_ONCE */
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/socket.h>            /* sockaddr families (mirror net/unix/af_unix.c) */
#include <linux/un.h>                /* struct sockaddr_un, sun_path */
#include <net/sock.h>                /* struct sock, sk_num (sock_common) */
#include <net/af_unix.h>             /* unix_sk, struct unix_sock, struct unix_address */

#include "profile.h"
#include "lp_log.h"

/* Relay/oracle identities to hide, MUST stay in lockstep with root_relay.cpp,
 * net_diag_hook.c, and the root daemon's @cronet_ipc oracle name. */
static const u16 LP_SEQ_PORTS[] = { 0x22C3 /* 8899 CONNECT relay */, 0x20C7 /* 8391 SNI relay */ };
#define LP_SEQ_NPORTS ((int)(sizeof(LP_SEQ_PORTS) / sizeof(LP_SEQ_PORTS[0])))
#define LP_SEQ_UNIX_NEEDLE "cronet_ipc"

/* Diagnostic counters (read via crash/kallsyms if needed; behavioural test is the
 * primary verification — read the tables as the IG uid vs root). */
unsigned int g_tcp_seq_hidden = 0;
unsigned int g_unix_seq_hidden = 0;

/* These rows expose root instrumentation, not an app identity. Hide them from
 * every app reader, including UIDs excluded from identity spoofing. Root and
 * system readers retain the real table, and the filter is inert until armed. */
static bool lp_seq_reader_hidden(void)
{
	if (!g_hooks_enabled || !g_profile.net_hide_enabled)
		return false;
	return from_kuid(&init_user_ns, current_uid()) >= 10000;
}

/* /proc/net/tcp{,6}: hide root-owned relay sockets only. Another UID may
 * legitimately bind the same port on a different local address. */
int lp_tcp_seq_hidden(struct sock *sk)
{
	u16 lport;
	int i;

	if (sk == SEQ_START_TOKEN || !sk)
		return 0;
	if (!lp_seq_reader_hidden())
		return 0;
	if (!uid_eq(sock_i_uid(sk), GLOBAL_ROOT_UID))
		return 0;

	lport = sk->sk_num;   /* host-order bound local port; sock_common, all states */
	for (i = 0; i < LP_SEQ_NPORTS; i++) {
		if (lport == LP_SEQ_PORTS[i]) {
			g_tcp_seq_hidden++;
			return 1;
		}
	}
	return 0;
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
