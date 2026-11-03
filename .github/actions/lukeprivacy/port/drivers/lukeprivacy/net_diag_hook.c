// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/cred.h>
#include <linux/jiffies.h>
#include <linux/sock_diag.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "profile.h"

#define LP_RELAY_MAX_COOKIES 1024
#define LP_RELAY_CLOSED_TIMEOUT (120 * HZ)

struct lp_relay_cookie {
	u64 value;
	unsigned long expires;
	bool listener;
};

static struct lp_relay_cookie lp_relay_cookies[LP_RELAY_MAX_COOKIES];
static DEFINE_SPINLOCK(lp_relay_cookies_lock);

extern unsigned int g_tcp_seq_hidden;
unsigned int g_relay_cookie_overflow = 0;

static bool lp_relay_port(const struct sock *sk)
{
	return sk && (sk->sk_num == 8899 || sk->sk_num == 8391);
}

static bool lp_relay_cookie_present(u64 cookie)
{
	unsigned long now = jiffies;
	bool found = false;
	int i;

	if (!cookie)
		return false;
	spin_lock_bh(&lp_relay_cookies_lock);
	for (i = 0; i < LP_RELAY_MAX_COOKIES; i++) {
		struct lp_relay_cookie *entry = &lp_relay_cookies[i];

		if (entry->value != cookie)
			continue;
		if (entry->expires && time_after_eq(now, entry->expires)) {
			entry->value = 0;
			entry->expires = 0;
			entry->listener = false;
		} else {
			found = true;
		}
		break;
	}
	spin_unlock_bh(&lp_relay_cookies_lock);
	return found;
}

static void lp_relay_cookie_store(u64 cookie, bool listener, bool pending)
{
	unsigned long now = jiffies;
	int empty = -1, retiring = -1, i;

	if (!cookie)
		return;
	spin_lock_bh(&lp_relay_cookies_lock);
	for (i = 0; i < LP_RELAY_MAX_COOKIES; i++) {
		struct lp_relay_cookie *entry = &lp_relay_cookies[i];

		if (entry->value == cookie) {
			entry->listener |= listener;
			entry->expires = pending ? now + LP_RELAY_CLOSED_TIMEOUT : 0;
			goto out;
		}
		if (!entry->value) {
			if (empty < 0)
				empty = i;
			continue;
		}
		if (entry->expires && time_after_eq(now, entry->expires)) {
			empty = i;
			break;
		}
		if (!entry->listener && entry->expires &&
		    (retiring < 0 || time_before(entry->expires,
						 lp_relay_cookies[retiring].expires)))
			retiring = i;
	}
	if (empty < 0)
		empty = retiring;
	if (empty >= 0) {
		lp_relay_cookies[empty].value = cookie;
		lp_relay_cookies[empty].listener = listener;
		lp_relay_cookies[empty].expires = pending ? now + LP_RELAY_CLOSED_TIMEOUT : 0;
	} else {
		g_relay_cookie_overflow++;
	}
out:
	spin_unlock_bh(&lp_relay_cookies_lock);
}

void lp_relay_listener(struct sock *sk)
{
	if (!lp_relay_port(sk) || !uid_eq(current_uid(), GLOBAL_ROOT_UID) ||
	    READ_ONCE(sk->sk_state) != TCP_LISTEN)
		return;
	lp_relay_cookie_store(sock_gen_cookie(sk), true, false);
}

void lp_relay_request(struct sock *listener, struct sock *request)
{
	if (!listener || !request || !lp_relay_cookie_present(sock_gen_cookie(listener)))
		return;
	lp_relay_cookie_store(sock_gen_cookie(request), false, true);
}

void lp_relay_accepted(struct sock *listener, struct sock *accepted)
{
	if (!listener || !accepted || !lp_relay_cookie_present(sock_gen_cookie(listener)))
		return;
	lp_relay_cookie_store(sock_gen_cookie(accepted), false, false);
}

void lp_relay_socket_closed(struct sock *sk)
{
	u64 cookie;
	int i;

	if (!sk)
		return;
	cookie = sock_gen_cookie(sk);
	spin_lock_bh(&lp_relay_cookies_lock);
	for (i = 0; i < LP_RELAY_MAX_COOKIES; i++) {
		struct lp_relay_cookie *entry = &lp_relay_cookies[i];

		if (entry->value != cookie)
			continue;
		if (entry->listener) {
			entry->value = 0;
			entry->expires = 0;
			entry->listener = false;
		} else {
			entry->expires = jiffies + LP_RELAY_CLOSED_TIMEOUT;
		}
		break;
	}
	spin_unlock_bh(&lp_relay_cookies_lock);
}

bool lp_netdiag_relay_hidden(struct sock *sk)
{
	if (!sk || !g_hooks_enabled || !g_profile.net_hide_enabled)
		return false;
	if (from_kuid(&init_user_ns, current_uid()) < 10000 || !lp_relay_port(sk))
		return false;
	if (!lp_relay_cookie_present(sock_gen_cookie(sk)))
		return false;
	g_tcp_seq_hidden++;
	return true;
}
