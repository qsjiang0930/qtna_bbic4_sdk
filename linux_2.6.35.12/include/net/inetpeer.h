/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>
#include <asm/atomic.h>

struct inetpeer_addr {
	union {
		__be32		a4;
		__be32		a6[4];
	};
	__u16	family;
};

struct inet_peer {
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;
	struct inetpeer_addr	daddr;
	__u32			avl_height;
	struct list_head	unused;
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
	atomic_t		refcnt;
	atomic_t		rid;		/* Frag reception counter */
	atomic_t		ip_id_count;	/* IP ID for the next packet */
	__u32			tcp_ts;
	__u32			tcp_ts_stamp;
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(const struct inetpeer_addr *daddr, int create);

static inline struct inet_peer *inet_getpeer_v4(__be32 v4daddr, int create)
{
	struct inetpeer_addr daddr;

	daddr.a4 = v4daddr;
	daddr.family = AF_INET;
	return inet_getpeer(&daddr, create);
}

static inline struct inet_peer *inet_getpeer_v6(struct in6_addr *v6daddr, int create)
{
	struct inetpeer_addr daddr;

	ipv6_addr_copy((struct in6_addr *)daddr.a6, v6daddr);
	daddr.family = AF_INET6;
	return inet_getpeer(&daddr, create);
}

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

/* can be called with or without local BH being disabled */
static inline int inet_getid(struct inet_peer *p, int more)
{
	int old, new;
	more++;
	do {
		old = atomic_read(&p->ip_id_count);
		new = old + more;
		if (!new)
			new = 1;
	} while (atomic_cmpxchg(&p->ip_id_count, old, new) != old);
	return new;
}

#endif /* _NET_INETPEER_H */
