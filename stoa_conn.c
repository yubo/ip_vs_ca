/*
 * stoa_conn.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>	/* for proc_net_* */
#include <linux/seq_file.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/net_namespace.h>
#include "stoa.h"

static struct list_head *stoa_conn_tab;

/*  SLAB cache for STOA connections */
static struct kmem_cache *stoa_conn_cachep __read_mostly;

/*  counter for current STOA connections */
static atomic_t stoa_conn_count = ATOMIC_INIT(0);

/* random value for STOA connection hash */
static unsigned int stoa_conn_rnd;

/*
 *  Fine locking granularity for big connection hash table
 */
#define CT_LOCKARRAY_BITS  8
#define CT_LOCKARRAY_SIZE  (1<<CT_LOCKARRAY_BITS)
#define CT_LOCKARRAY_MASK  (CT_LOCKARRAY_SIZE-1)

struct stoa_aligned_lock {
	rwlock_t l;
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));

/* lock array for conn table */
static struct stoa_aligned_lock
    __stoa_conntbl_lock_array[CT_LOCKARRAY_SIZE] __cacheline_aligned;

static inline void ct_read_lock(unsigned key)
{
	read_lock(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_unlock(unsigned key)
{
	read_unlock(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock(unsigned key)
{
	write_lock(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock(unsigned key)
{
	write_unlock(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_lock_bh(unsigned key)
{
	read_lock_bh(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_read_unlock_bh(unsigned key)
{
	read_unlock_bh(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock_bh(unsigned key)
{
	write_lock_bh(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock_bh(unsigned key)
{
	write_unlock_bh(&__stoa_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

/*
 *	Returns hash value for IPVS connection entry
 */
static unsigned int stoa_conn_hashkey(int af, unsigned proto, 
		const union nf_inet_addr *addr, __be16 port)
{
	return jhash_3words((__force u32) addr->ip, (__force u32) port, proto,
			    stoa_conn_rnd)
	    & STOA_CONN_TAB_MASK;
}

/*
 *  Hashed stoa_conn into stoa_conn_tab
 *	returns bool success.
 */

static inline int __stoa_conn_hash(struct stoa_conn *cp, unsigned hash)
{
	int ret;

	if (!(cp->flags & STOA_CONN_F_HASHED)) {
		list_add(&cp->c_list, &stoa_conn_tab[hash]);
		cp->flags |= STOA_CONN_F_HASHED;
		atomic_inc(&cp->refcnt);
		ret = 1;
	} else {
		STOA_ERR("request for already hashed, called from %pF\n",
		       __builtin_return_address(0));
		ret = 0;
	}

	return ret;
}

/*
 *	Hashed stoa_conn in two buckets of stoa_conn_tab
 *	by caddr/cport/vaddr/vport and raddr/rport/laddr/lport,
 *	returns bool success.
 */
static inline int stoa_conn_hash(struct stoa_conn *cp)
{
	unsigned hash;
	int ret;

	if (cp->flags & STOA_CONN_F_ONE_PACKET)
		return 0;

	hash =
	    stoa_conn_hashkey(cp->af, cp->protocol, &cp->s_addr, cp->s_port);
	ct_write_lock(hash);
	ret = __stoa_conn_hash(cp, hash);
	ct_write_unlock(hash);

	return ret;
}

/*
 *	UNhashes stoa_conn from stoa_conn_tab.
 *	cp->refcnt must be equal 2,
 *	returns bool success.
 */
static inline int stoa_conn_unhash(struct stoa_conn *cp)
{
	unsigned hash;
	int ret;

	hash =
	    stoa_conn_hashkey(cp->af, cp->protocol, &cp->s_addr, cp->s_port);

	/* locked */
	ct_write_lock(hash);

	/* unhashed */
	if ((cp->flags & STOA_CONN_F_HASHED)
	    && (atomic_read(&cp->refcnt) == 2)) {
		list_del(&cp->c_list);
		cp->flags &= ~STOA_CONN_F_HASHED;
		atomic_dec(&cp->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}
	ct_write_unlock(hash);

	return ret;
}

static void stoa_conn_expire(unsigned long data)
{
	struct stoa_conn *cp = (struct stoa_conn *)data;

	/*
	 * Set proper timeout.
	 */
	cp->timeout = 60 * HZ;

	/*
	 *      hey, I'm using it
	 */
	atomic_inc(&cp->refcnt);

	/*
	 *      unhash it if it is hashed in the conn table
	 */
	if (!stoa_conn_unhash(cp))
		goto expire_later;

	/*
	 *      refcnt==1 implies I'm the only one referrer
	 */
	if (likely(atomic_read(&cp->refcnt) == 1)) {
		/* delete the timer if it is activated by other users */
		if (timer_pending(&cp->timer))
			del_timer(&cp->timer);
		
		atomic_dec(&stoa_conn_count);

#if 0
		STOA_DBG("conn expire: %pI4:%d(%pI4:%d) -> %pI4:%d timer:%p\n",
				&cp->s_addr.ip, ntohs(cp->s_port),
				&cp->o_addr.ip, ntohs(cp->o_port),
				&cp->d_addr.ip, ntohs(cp->d_port),
				&cp->timer);
#endif
		kmem_cache_free(stoa_conn_cachep, cp);
		return;
	}

	/* hash it back to the table */
	stoa_conn_hash(cp);

expire_later:
	STOA_DBG("delayed: conn->refcnt-1=%d\n",
		  atomic_read(&cp->refcnt) - 1);

	stoa_conn_put(cp);
}

struct stoa_conn *stoa_conn_new(int af, int proto,
				  __be32 saddr, __be16 sport,
				  __be32 daddr, __be16 dport,
				  __be32 oaddr, __be16 oport,
				  struct sk_buff *skb)
{
	struct stoa_conn *cp;

	//EnterFunction();

	cp = kmem_cache_zalloc(stoa_conn_cachep, GFP_ATOMIC);
	if (cp == NULL) {
		STOA_ERR("%s(): no memory\n", __func__);
		return NULL;
	}

	/* now init connection */
	STOA_DBG("setup_timer, %p\n", &cp->timer);
	setup_timer(&cp->timer, stoa_conn_expire, (unsigned long)cp);
	cp->af = af;
	cp->protocol = proto;
	//stoa_addr_copy(af, &cp->saddr, saddr);
	cp->s_addr.ip = saddr;
	cp->s_port = sport;
	//stoa_addr_copy(af, &cp->oaddr, oaddr);
	cp->o_addr.ip = oaddr;
	cp->o_port = oport;
	//stoa_addr_copy(proto == IPPROTO_IP ? AF_UNSPEC : af, &cp->daddr, daddr);
	cp->d_addr.ip = daddr;
	cp->d_port = dport;

	cp->flags = 0;

	spin_lock_init(&cp->lock);
	atomic_set(&cp->refcnt, 1);
	atomic_inc(&stoa_conn_count);

	cp->state = 0;
	cp->timeout = 3 * HZ;

	stoa_conn_hash(cp);

	STOA_DBG("conn new: %pI4:%d(%pI4:%d) -> %pI4:%d\n",
			&cp->s_addr.ip, ntohs(cp->s_port),
			&cp->o_addr.ip, ntohs(cp->o_port),
			&cp->d_addr.ip, ntohs(cp->d_port));
	//LeaveFunction();
	return cp;
}

/*
 * just ipv4
 */
struct stoa_conn *stoa_conn_get
    (int af, int protocol,
	 const union nf_inet_addr *s_addr, __be16 s_port) {
	unsigned hash;
	struct stoa_conn *cp;

	hash = stoa_conn_hashkey(af, protocol, s_addr, s_port);

	ct_read_lock(hash);

	list_for_each_entry(cp, &stoa_conn_tab[hash], c_list) {
		if (cp->af == af &&
		    stoa_addr_equal(af, s_addr, &cp->s_addr) &&
		    s_port == cp->s_port &&
		    protocol == cp->protocol) {
			/* HIT */
			atomic_inc(&cp->refcnt);
			goto out;
		}
	}
	cp = NULL;

out:
	/*
	STOA_DBG("lookup %s %pI4:%d -> %pI4:%d %s\n",
				stoa_proto_name(protocol),
				&s_addr->ip, ntohs(s_port),
				&d_addr->ip, ntohs(d_port),
				cp ? "hit" : "not hit");
				*/

	ct_read_unlock(hash);
	return cp;
}

void stoa_conn_put(struct stoa_conn *cp)
{
	/* reset it expire in its timeout */
	mod_timer(&cp->timer, jiffies + cp->timeout);
	__stoa_conn_put(cp);
}

static void stoa_conn_expire_now(struct stoa_conn *cp)
{
	STOA_DBG("expire_now: timer(%p)\n", &cp->timer);
	if (del_timer(&cp->timer))
		mod_timer(&cp->timer, jiffies);
}

/*
 *      Flush all the connection entries in the ip_vs_conn_tab
 */
static void stoa_conn_flush(void)
{
	int idx;
	struct stoa_conn *cp;

flush_again:
	for (idx = 0; idx < STOA_CONN_TAB_SIZE; idx++) {
		/*
		 *  Lock is actually needed in this loop.
		 */
		ct_write_lock_bh(idx);

		list_for_each_entry(cp, &stoa_conn_tab[idx], c_list) {
			STOA_DBG("del connection\n");
			stoa_conn_expire_now(cp);
		}
		ct_write_unlock_bh(idx);
	}

	/* the counter may be not NULL, because maybe some conn entries
	   are run by slow timer handler or unhashed but still referred */
	if (atomic_read(&stoa_conn_count) != 0) {
		schedule();
		goto flush_again;
	}
}

int __init stoa_conn_init(void){
	int idx;

	stoa_conn_tab =
	    vmalloc(STOA_CONN_TAB_SIZE * (sizeof(struct list_head)));
	if (!stoa_conn_tab)
		return -ENOMEM;

	/* Allocate stoa_conn slab cache */
	stoa_conn_cachep = kmem_cache_create("stoa_conn",
					      sizeof(struct stoa_conn),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!stoa_conn_cachep) {
		vfree(stoa_conn_tab);
		return -ENOMEM;
	}

	STOA_INFO("Connection hash table configured "
		"(size=%d, memory=%ldKbytes)\n",
		STOA_CONN_TAB_SIZE,
		(long)(STOA_CONN_TAB_SIZE * sizeof(struct list_head)) / 1024);

	STOA_DBG("Each connection entry needs %Zd bytes at least\n",
		  sizeof(struct stoa_conn));

	for (idx = 0; idx < STOA_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&stoa_conn_tab[idx]);
	}

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++) {
		rwlock_init(&__stoa_conntbl_lock_array[idx].l);
	}

	/* calculate the random value for connection hash */
	get_random_bytes(&stoa_conn_rnd, sizeof(stoa_conn_rnd));

	return 0;
}

void stoa_conn_cleanup(void)
{
	stoa_conn_flush();
	kmem_cache_destroy(stoa_conn_cachep);
	vfree(stoa_conn_tab);
}
