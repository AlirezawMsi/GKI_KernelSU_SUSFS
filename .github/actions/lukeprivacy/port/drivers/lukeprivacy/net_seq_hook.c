/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy - per-record /proc/net seq_show row filter (net_hide airtight layer).
 *
 * The read_hook.c net_hide path filters /proc/net/tcp{,6} and /proc/net/unix at
 * the READ choke-point: it drops whole relay-listener / @cronet_ipc rows from the
 * userspace buffer AFTER seq_file formatted them. That path is proven and live,
 * but it has one irreducible residual (documented in read_hook.c): a row can be
 * split across a read() syscall boundary so the local-port / name field lands in
 * the NEXT read as a headless fragment, which stateless per-read filtering cannot
 * positively identify. A determined reader that chunks /proc/net/tcp6 to force a
 * boundary inside a relay row could recover the tail.
 *
 * This layer closes that seam at the SOURCE: the kernel's per-record seq_show
 * callbacks (tcp6_seq_show, unix_seq_show) call these predicates BEFORE formatting
 * a record, and skip the whole record if it is a relay/oracle socket for a
 * spoof-target reader. No bytes are ever emitted, so no read boundary can split
 * what was never written. The read_hook path stays as the catch-all (and the sole
 * cover for /proc/net/tcp v4, where no relay row has been observed).
 *
 * SAFETY (single remote device — a wrong dereference here panics the kernel):
 *  - TCP: we read ONLY sk->sk_num (the bound local port). It lives in
 *    struct sock_common, the shared first member of struct sock,
 *    inet_timewait_sock AND request_sock, so it is valid for every seq_show
 *    record state (LISTEN / ESTABLISHED / TIME_WAIT / NEW_SYN_RECV) without the
 *    state-dependent inet_sk() dereference that WOULD be wrong on a timewait /
 *    request socket. This is exactly why tcp6_seq_show itself reads sk->sk_state
 *    through a plain `struct sock *` before it knows the real type.
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

/* Relay/oracle identities to hide, MUST stay in lockstep with:
 *   - read_hook.c LP_NETHIDE_PORTS + lp_netunix_line_hidden() (the read-path twin),
 *   - ProxyRelay.java PORT(8899)/TPORT(8391), and the @cronet_ipc oracle name.
 * Duplicated locally (2 ports + 1 name) to avoid a cross-TU symbol export, matching
 * the splitmix64 duplication idiom in read_hook.c. */
static const u16 LP_SEQ_PORTS[] = { 0x22C3 /* 8899 CONNECT relay */, 0x20C7 /* 8391 SNI relay */ };
#define LP_SEQ_NPORTS ((int)(sizeof(LP_SEQ_PORTS) / sizeof(LP_SEQ_PORTS[0])))
#define LP_SEQ_UNIX_NEEDLE "cronet_ipc"

/* Diagnostic counters (read via crash/kallsyms if needed; behavioural test is the
 * primary verification — read the tables as the IG uid vs root). */
unsigned int g_tcp_seq_hidden = 0;
unsigned int g_unix_seq_hidden = 0;

/* True iff the CURRENT reader is a spoof target that must not see relay rows.
 * Mirrors the read_hook.c gate exactly: armed only when net_hide is enabled, and
 * excluded uids (root/system + the configured list) always read the real table. */
static bool lp_seq_reader_hidden(void)
{
	unsigned int uid;

	if (!g_hooks_enabled)
		return false;
	if (!g_profile.net_hide_enabled)
		return false;
	uid = from_kuid(&init_user_ns, current_uid());
	if (lp_is_uid_excluded(uid))
		return false;
	return true;
}

/* /proc/net/tcp6 (tcp6_seq_show): drop the record iff its bound local port is a
 * relay port for a spoof-target reader. Returns 1 to skip, 0 to keep. */
int lp_tcp_seq_hidden(const struct sock *sk)
{
	u16 lport;
	int i;

	if (!sk)
		return 0;
	if (!lp_seq_reader_hidden())
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

/* /proc/net/unix (unix_seq_show): drop the record iff its bound address contains
 * the oracle needle ("cronet_ipc") for a spoof-target reader. Returns 1 to skip,
 * 0 to keep. Lock-free u->addr read — see SAFETY note at top. */
int lp_unix_seq_hidden(const struct sock *sk)
{
	const struct unix_sock *u;
	const struct unix_address *addr;
	const char *name;
	int plen, off;
	static const char needle[] = LP_SEQ_UNIX_NEEDLE;
	const int nlen = (int)sizeof(needle) - 1;

	if (!sk)
		return 0;
	if (!lp_seq_reader_hidden())
		return 0;

	u = unix_sk(sk);
	addr = READ_ONCE(u->addr);              /* immutable after bind; NULL if unbound */
	if (!addr)
		return 0;

	/* Path bytes available after the sun_family header (abstract sockets carry a
	 * leading NUL then the label, matching how unix_seq_show prints '@'+name). */
	plen = (int)addr->len - (int)offsetof(struct sockaddr_un, sun_path);
	if (plen < nlen || plen > (int)sizeof(addr->name->sun_path))
		return 0;
	name = addr->name->sun_path;

	/* Substring match over the path bytes — lockstep with read_hook.c
	 * lp_netunix_line_hidden(), which matches the same needle on the formatted row. */
	for (off = 0; off + nlen <= plen; off++) {
		int j;
		bool m = true;

		for (j = 0; j < nlen; j++) {
			if (name[off + j] != needle[j]) {
				m = false;
				break;
			}
		}
		if (m) {
			g_unix_seq_hidden++;
			return 1;
		}
	}
	return 0;
}
