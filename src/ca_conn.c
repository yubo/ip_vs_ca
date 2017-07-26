/*
 * ca_conn.c
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
#include "ca.h"

static struct list_head *ip_vs_ca_conn_tab;

/*  SLAB cache for IP_VS_CA connections */
static struct kmem_cache *ip_vs_ca_conn_cachep __read_mostly;

/*  counter for current IP_VS_CA connections */
static atomic_t ip_vs_ca_conn_count = ATOMIC_INIT(0);

/* random value for IP_VS_CA connection hash */
static unsigned int ip_vs_ca_conn_rnd;

/*
 *  Fine locking granularity for big connection hash table
 */
#define CT_LOCKARRAY_BITS  16
#define CT_LOCKARRAY_SIZE  (1<<CT_LOCKARRAY_BITS)
#define CT_LOCKARRAY_MASK  (CT_LOCKARRAY_SIZE-1)

struct ip_vs_ca_aligned_lock {
	spinlock_t l;
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));

/* lock array for conn table */
static struct ip_vs_ca_aligned_lock
    __ip_vs_ca_conntbl_lock_array[CT_LOCKARRAY_SIZE] __cacheline_aligned;

static inline void ct_lock(unsigned key)
{
	spin_lock_bh(&__ip_vs_ca_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

static inline void ct_unlock(unsigned key)
{
	spin_unlock_bh(&__ip_vs_ca_conntbl_lock_array[key & CT_LOCKARRAY_MASK].l);
}

/*
 *	Returns hash value for IPVS connection entry
 */
static unsigned int ip_vs_ca_conn_hashkey(int af, unsigned proto, 
		const union nf_inet_addr *addr, __be16 port)
{
	return jhash_3words((__force u32) addr->ip, (__force u32) port, proto,
			    ip_vs_ca_conn_rnd)
	    & IP_VS_CA_CONN_TAB_MASK;
}

/*
 *  Hashed ip_vs_ca_conn into ip_vs_ca_conn_tab
 *	returns bool success.
 */

static inline int __ip_vs_ca_conn_hash(struct ip_vs_ca_conn *cp, unsigned hash)
{
	int ret;

	if (!(cp->flags & IP_VS_CA_CONN_F_HASHED)) {
		list_add(&cp->c_list, &ip_vs_ca_conn_tab[hash]);
		cp->flags |= IP_VS_CA_CONN_F_HASHED;
		atomic_inc(&cp->refcnt);
		ret = 1;
	} else {
		IP_VS_CA_ERR("request for already hashed, called from %pF\n",
		       __builtin_return_address(0));
		ret = 0;
	}

	return ret;
}

/*
 *	Hashed ip_vs_ca_conn in two buckets of ip_vs_ca_conn_tab
 *	by caddr/cport/vaddr/vport and raddr/rport/laddr/lport,
 *	returns bool success.
 */
static int
ip_vs_ca_conn_hash(struct ip_vs_ca_conn *cp)
{
	unsigned hash;
	int ret;

	if (cp->flags & IP_VS_CA_CONN_F_ONE_PACKET)
		return 0;

	hash = ip_vs_ca_conn_hashkey(cp->af, cp->protocol,
			&cp->s_addr, cp->s_port);
	ct_lock(hash);
	ret = __ip_vs_ca_conn_hash(cp, hash);
	ct_unlock(hash);

	return ret;
}

/*
 *	UNhashes ip_vs_ca_conn from ip_vs_ca_conn_tab.
 *	cp->refcnt must be equal 2,
 *	returns bool success.
 */
static int
ip_vs_ca_conn_unhash(struct ip_vs_ca_conn *cp)
{
	unsigned hash;
	int ret;

	hash = ip_vs_ca_conn_hashkey(cp->af, cp->protocol,
			&cp->s_addr, cp->s_port);

	/* locked */
	ct_lock(hash);

	/* unhashed */
	if ((cp->flags & IP_VS_CA_CONN_F_HASHED)
	    && (atomic_read(&cp->refcnt) == 2)) {
		list_del(&cp->c_list);
		cp->flags &= ~IP_VS_CA_CONN_F_HASHED;
		atomic_dec(&cp->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}
	ct_unlock(hash);

	return ret;
}

static void ip_vs_ca_conn_expire(unsigned long data)
{
	struct ip_vs_ca_conn *cp = (struct ip_vs_ca_conn *)data;

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
	if (!ip_vs_ca_conn_unhash(cp))
		goto expire_later;

	/*
	 *      refcnt==1 implies I'm the only one referrer
	 */
	if (likely(atomic_read(&cp->refcnt) == 1)) {
		/* delete the timer if it is activated by other users */
		if (timer_pending(&cp->timer))
			del_timer(&cp->timer);
		
		atomic_dec(&ip_vs_ca_conn_count);
		IP_VS_CA_INC_STATS(ext_stats, CONN_DEL_CNT);

		IP_VS_CA_DBG("conn expire: %pI4:%d(%pI4:%d) -> %pI4:%d timer:%p\n",
				&cp->s_addr.ip, ntohs(cp->s_port),
				&cp->o_addr.ip, ntohs(cp->o_port),
				&cp->d_addr.ip, ntohs(cp->d_port),
				&cp->timer);
		kmem_cache_free(ip_vs_ca_conn_cachep, cp);
		return;
	}

	/* hash it back to the table */
	ip_vs_ca_conn_hash(cp);

expire_later:
	IP_VS_CA_DBG("delayed: conn->refcnt-1=%d\n",
		  atomic_read(&cp->refcnt) - 1);

	ip_vs_ca_conn_put(cp);
}

struct ip_vs_ca_conn *ip_vs_ca_conn_new(int af,
					struct ip_vs_ca_protocol *pp,
					__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport,
					__be32 oaddr, __be16 oport,
					struct sk_buff *skb)
{
	struct ip_vs_ca_conn *cp;

	//EnterFunction();

	cp = kmem_cache_zalloc(ip_vs_ca_conn_cachep, GFP_ATOMIC);
	if (cp == NULL) {
		IP_VS_CA_ERR("%s(): no memory\n", __func__);
		return NULL;
	}

	/* now init connection */
	IP_VS_CA_DBG("setup_timer, %p\n", &cp->timer);
	setup_timer(&cp->timer, ip_vs_ca_conn_expire, (unsigned long)cp);
	cp->af = af;
	cp->protocol = pp->protocol;
	//ip_vs_ca_addr_copy(af, &cp->saddr, saddr);
	cp->s_addr.ip = saddr;
	cp->s_port = sport;
	//ip_vs_ca_addr_copy(af, &cp->oaddr, oaddr);
	cp->o_addr.ip = oaddr;
	cp->o_port = oport;
	//ip_vs_ca_addr_copy(proto == IPPROTO_IP ? AF_UNSPEC : af, &cp->daddr, daddr);
	cp->d_addr.ip = daddr;
	cp->d_port = dport;

	cp->flags = 0;

	spin_lock_init(&cp->lock);
	atomic_set(&cp->refcnt, 1);
	atomic_inc(&ip_vs_ca_conn_count);
	IP_VS_CA_INC_STATS(ext_stats, CONN_NEW_CNT);

	cp->state = 0;
	cp->timeout = *pp->timeout;

	ip_vs_ca_conn_hash(cp);

	IP_VS_CA_DBG("conn new: proto:%u, %pI4:%d(%pI4:%d) -> %pI4:%d\n",
			cp->protocol,
			&cp->s_addr.ip, ntohs(cp->s_port),
			&cp->o_addr.ip, ntohs(cp->o_port),
			&cp->d_addr.ip, ntohs(cp->d_port));
	//LeaveFunction();
	return cp;
}

/*
 * just ipv4
 */
struct ip_vs_ca_conn *ip_vs_ca_conn_get
    (int af, __u8 protocol,
	 const union nf_inet_addr *s_addr, __be16 s_port) {
	unsigned hash;
	struct ip_vs_ca_conn *cp;

	hash = ip_vs_ca_conn_hashkey(af, protocol, s_addr, s_port);

	ct_lock(hash);

	list_for_each_entry(cp, &ip_vs_ca_conn_tab[hash], c_list) {
		if (cp->af == af &&
		    ip_vs_ca_addr_equal(af, s_addr, &cp->s_addr) &&
		    s_port == cp->s_port &&
		    protocol == cp->protocol) {
			/* HIT */
			atomic_inc(&cp->refcnt);
			ct_unlock(hash);
			return cp;
		}
	}
	ct_unlock(hash);
	return NULL;
}

void ip_vs_ca_conn_put(struct ip_vs_ca_conn *cp)
{
	/* reset it expire in its timeout */
	/* IP_VS_CA_DBG("mod_timer %lu\n", cp->timeout / HZ); */
	mod_timer(&cp->timer, jiffies + cp->timeout);
	__ip_vs_ca_conn_put(cp);
}

static void ip_vs_ca_conn_expire_now(struct ip_vs_ca_conn *cp)
{
	IP_VS_CA_DBG("expire_now: timer(%p)\n", &cp->timer);
	if (del_timer(&cp->timer))
		mod_timer(&cp->timer, jiffies);
}

/*
 *      Flush all the connection entries in the ip_vs_conn_tab
 */
static void ip_vs_ca_conn_flush(void)
{
	int idx;
	struct ip_vs_ca_conn *cp;

flush_again:
	for (idx = 0; idx < IP_VS_CA_CONN_TAB_SIZE; idx++) {
		/*
		 *  Lock is actually needed in this loop.
		 */
		ct_lock(idx);

		list_for_each_entry(cp, &ip_vs_ca_conn_tab[idx], c_list) {
			IP_VS_CA_DBG("del connection\n");
			ip_vs_ca_conn_expire_now(cp);
		}
		ct_unlock(idx);
	}

	/* the counter may be not NULL, because maybe some conn entries
	   are run by slow timer handler or unhashed but still referred */
	if (atomic_read(&ip_vs_ca_conn_count) != 0) {
		schedule();
		goto flush_again;
	}
}

int __init ip_vs_ca_conn_init(void){
	int idx;

	ip_vs_ca_conn_tab =
	    vmalloc(IP_VS_CA_CONN_TAB_SIZE * (sizeof(struct list_head)));
	if (!ip_vs_ca_conn_tab)
		return -ENOMEM;

	/* Allocate ip_vs_ca_conn slab cache */
	ip_vs_ca_conn_cachep = kmem_cache_create("ip_vs_ca_conn",
					      sizeof(struct ip_vs_ca_conn),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!ip_vs_ca_conn_cachep) {
		vfree(ip_vs_ca_conn_tab);
		return -ENOMEM;
	}

	IP_VS_CA_INFO("Connection hash table configured "
		"(size=%d, memory=%ldKbytes)\n",
		IP_VS_CA_CONN_TAB_SIZE,
		(long)(IP_VS_CA_CONN_TAB_SIZE * sizeof(struct list_head)) / 1024);

	IP_VS_CA_DBG("Each connection entry needs %Zd bytes at least\n",
		  sizeof(struct ip_vs_ca_conn));

	for (idx = 0; idx < IP_VS_CA_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&ip_vs_ca_conn_tab[idx]);
	}

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++) {
		spin_lock_init(&__ip_vs_ca_conntbl_lock_array[idx].l);
	}

	/* calculate the random value for connection hash */
	get_random_bytes(&ip_vs_ca_conn_rnd, sizeof(ip_vs_ca_conn_rnd));

	return 0;
}

void ip_vs_ca_conn_cleanup(void)
{
	ip_vs_ca_conn_flush();
	kmem_cache_destroy(ip_vs_ca_conn_cachep);
	vfree(ip_vs_ca_conn_tab);
}
