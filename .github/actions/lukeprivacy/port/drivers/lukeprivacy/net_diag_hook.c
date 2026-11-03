// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/cred.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sock_diag.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "profile.h"

#define LP_RELAY_CLOSED_TIMEOUT (120 * HZ)

struct lp_relay_cookie {
	u64 value;
	unsigned long expires;
	bool listener;
	struct list_head node;
};

static LIST_HEAD(lp_relay_cookies);
static DEFINE_SPINLOCK(lp_relay_cookies_lock);

extern unsigned int g_tcp_seq_hidden;
unsigned int g_relay_cookie_overflow = 0;

static bool lp_relay_port(const struct sock *sk)
{
	return sk && (sk->sk_num == 8899 || sk->sk_num == 8391);
}

static void lp_relay_expire_locked(void)
{
	struct lp_relay_cookie *entry, *tmp;
	unsigned long now = jiffies;

	list_for_each_entry_safe(entry, tmp, &lp_relay_cookies, node) {
		if (entry->expires && time_after_eq(now, entry->expires)) {
			list_del(&entry->node);
			kfree(entry);
		}
	}
}

static bool lp_relay_cookie_present(u64 cookie)
{
	struct lp_relay_cookie *entry, *tmp;
	unsigned long now = jiffies;
	bool found = false;

	if (!cookie)
		return false;
	spin_lock_bh(&lp_relay_cookies_lock);
	list_for_each_entry_safe(entry, tmp, &lp_relay_cookies, node) {
		if (entry->value != cookie)
			continue;
		if (entry->expires && time_after_eq(now, entry->expires)) {
			list_del(&entry->node);
			kfree(entry);
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
	struct lp_relay_cookie *entry;
	unsigned long now = jiffies;

	if (!cookie)
		return;
	spin_lock_bh(&lp_relay_cookies_lock);
	lp_relay_expire_locked();
	list_for_each_entry(entry, &lp_relay_cookies, node) {
		if (entry->value == cookie) {
			entry->listener |= listener;
			entry->expires = pending ? now + LP_RELAY_CLOSED_TIMEOUT : 0;
			goto out;
		}
	}
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		g_relay_cookie_overflow++;
		goto out;
	}
	entry->value = cookie;
	entry->listener = listener;
	entry->expires = pending ? now + LP_RELAY_CLOSED_TIMEOUT : 0;
	list_add_tail(&entry->node, &lp_relay_cookies);
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
	struct lp_relay_cookie *entry, *tmp;
	u64 cookie;

	if (!sk)
		return;
	cookie = sock_gen_cookie(sk);
	spin_lock_bh(&lp_relay_cookies_lock);
	list_for_each_entry_safe(entry, tmp, &lp_relay_cookies, node) {
		if (entry->value != cookie)
			continue;
		if (entry->listener) {
			list_del(&entry->node);
			kfree(entry);
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
