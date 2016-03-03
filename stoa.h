#ifndef __STOA_H__
#define __STOA_H__

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>		/* for struct ipv6hdr */
#include <net/ipv6.h>		/* for ipv6_addr_copy */

#define STOA_VERSION "0.0.1"

#define STOA_CONN_TAB_BITS     8
#define STOA_CONN_TAB_SIZE     (1 << STOA_CONN_TAB_BITS)
#define STOA_CONN_TAB_MASK     (STOA_CONN_TAB_SIZE - 1)

#define STOA_CONN_F_HASHED	0x0040		/* hashed entry */
#define STOA_CONN_F_ONE_PACKET	0x2000		/* forward only one packet */

#define EnterFunction()						\
	do {								\
			printk(KERN_DEBUG				\
			       pr_fmt("Enter: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)
#define LeaveFunction()						\
	do {								\
			printk(KERN_DEBUG				\
			       pr_fmt("Leave: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)

#define STOA_ERR(msg...)						\
	do {									\
		printk(KERN_ERR "[ERR] STOA: " msg);\
	} while (0)

#define STOA_DBG(msg...)							\
	do {										\
		printk(KERN_DEBUG "[DEBUG] STOA: " msg);\
	} while (0)

#define STOA_INFO(msg...)				\
	do {								\
		if (net_ratelimit())			\
		printk(KERN_INFO "[INFO] STOA: " msg);	\
	} while (0)

#define TCPOPT_STOA  254
/* MUST be 4n !!!! */
#define TCPOLEN_STOA 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

struct stoa_conn;
struct stoa_iphdr;
struct stoa_conn;

/*
static inline void stoa_addr_copy(int af, union nf_inet_addr *dst,
				   const union nf_inet_addr *src)
{
#ifdef CONFIG_STOA_IPV6
	if (af == AF_INET6)
		ipv6_addr_copy(&dst->in6, &src->in6);
	else
#endif
		dst->ip = src->ip;
}
*/


static inline int stoa_addr_equal(int af, const union nf_inet_addr *a,
				   const union nf_inet_addr *b)
{
#ifdef CONFIG_STOA_IPV6
	if (af == AF_INET6)
		return ipv6_addr_equal(&a->in6, &b->in6);
#endif
	return a->ip == b->ip;
}

struct stoa_iphdr {
	int len;
	__u8 protocol;
	union nf_inet_addr saddr;
	union nf_inet_addr daddr;
};

static inline void
stoa_fill_iphdr(int af, const void *nh, struct stoa_iphdr *iphdr)
{
	const struct iphdr *iph = nh;
	iphdr->len = iph->ihl * 4;
	iphdr->protocol = iph->protocol;
	iphdr->saddr.ip = iph->saddr;
	iphdr->daddr.ip = iph->daddr;
}


/*
 *	STOA structure allocated for each connection
 */
struct stoa_conn {
	struct list_head c_list;         /* hashed list heads */

	u16 af;                          /* address family */
	__u16 protocol;                  /* Which protocol (TCP/UDP) */
	union nf_inet_addr s_addr;       /* source address */
	union nf_inet_addr d_addr;       /* destination address */
	__be16 s_port;                   /* source port */
	__be16 d_port;                   /* destination port */

	union nf_inet_addr o_addr;       /* origin address */
	__be16 o_port;                   /* origin port */

	atomic_t refcnt;                 /* reference count */
	struct timer_list timer;         /* Expiration timer */
	volatile unsigned long timeout;  /* timeout */

	/* Flags and state transition */
	spinlock_t lock;	/* lock for state transition */
	volatile __u16 flags;	/* status flags */
	volatile __u16 state;	/* state info */
	volatile __u16 old_state;
};

/* MUST be 4 bytes alignment */
struct _tcp_stoa_data {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 ip;
};

union stoa_data {
	__u64 data;
	struct _tcp_stoa_data tcp;
};

/* statistics about toa in proc /proc/net/stoa_stat */
enum {
	SYN_RECV_SOCK_STOA_CNT = 1,
	SYN_RECV_SOCK_NO_STOA_CNT,
	GETNAME_STOA_OK_CNT,
	GETNAME_STOA_MISMATCH_CNT,
	GETNAME_STOA_BYPASS_CNT,
	GETNAME_STOA_EMPTY_CNT,
	STOA_STAT_LAST
};

struct stoa_stats_entry {
	char *name;
	int entry;
};

#define STOA_STAT_ITEM(_name, _entry) { \
	.name = _name,		\
	.entry = _entry,	\
}

#define STOA_STAT_END {	\
	NULL,		\
	0,		\
}

struct stoa_stat_mib {
	unsigned long mibs[STOA_STAT_LAST];
};

#define STOA_INC_STATS(mib, field)         \
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)



struct stoa_protocol {
	struct stoa_protocol *next;
	char *name;
	u16 protocol;
	u16 num_states;
	int dont_defrag;
	atomic_t appcnt;	/* counter of proto app incs */
	int *timeout_table;	/* protocol timeout table */

	int (*skb_process) (int af, struct sk_buff * skb,
			      struct stoa_protocol * pp,
			      const struct stoa_iphdr * iph,
			      int *verdict, struct stoa_conn ** cpp);

	void (*debug_packet) (struct stoa_protocol * pp,
			      const struct sk_buff * skb,
			      int offset, const char *msg);

	int (*set_state_timeout) (struct stoa_protocol * pp, char *sname,
				  int to);

	struct stoa_conn *
	    (*conn_get) (int af, const struct sk_buff * skb,
			    struct stoa_protocol * pp,
			    const struct stoa_iphdr * iph,
			    unsigned int proto_off);

	void (*conn_expire_handler) (struct stoa_protocol * pp,
				     struct stoa_conn * cp);
};

static inline void __stoa_conn_put(struct stoa_conn *cp)
{
	atomic_dec(&cp->refcnt);
}

extern int stoa_conn_init(void);
extern void stoa_conn_cleanup(void);
extern void stoa_conn_put(struct stoa_conn *cp);
extern void stoa_conn_cleanup(void);
extern struct stoa_conn *stoa_conn_get(int af, int protocol,
	 const union nf_inet_addr *s_addr, __be16 s_port);
extern struct stoa_conn *stoa_conn_new(int af, int proto,
				  __be32 saddr, __be16 sport,
				  __be32 daddr, __be16 dport,
				  __be32 oaddr, __be16 oport,
				  struct sk_buff *skb);

extern int stoa_protocol_init(void);
extern void stoa_protocol_cleanup(void);
extern struct stoa_protocol *stoa_proto_get(unsigned short proto);

extern int stoa_control_init(void);
extern void stoa_control_cleanup(void);

extern unsigned long **find_sys_call_table(void);
const char *stoa_proto_name(unsigned proto);


extern struct stoa_stat_mib *ext_stats;

#endif
