#ifndef __IP_VS_CA_H__
#define __IP_VS_CA_H__

#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>		/* for struct ipv6hdr */
#include <net/ipv6.h>		/* for ipv6_addr_copy */
#include <net/icmp.h>		/* for icmp_send */

#ifndef IP_VS_CA_VERSION
#define IP_VS_CA_VERSION "0.1.*"
#endif

/*#define IP_VS_CA_DEBUG*/

#define IP_VS_CA_CONN_TAB_BITS     8
#define IP_VS_CA_CONN_TAB_SIZE     (1 << IP_VS_CA_CONN_TAB_BITS)
#define IP_VS_CA_CONN_TAB_MASK     (IP_VS_CA_CONN_TAB_SIZE - 1)

#define IP_VS_CA_CONN_F_HASHED		0x0040		/* hashed entry */
#define IP_VS_CA_CONN_F_ONE_PACKET	0x2000		/* forward only one packet */

#define IP_VS_CA_ERR(msg...)					\
	do {							\
		printk(KERN_ERR "[ERR] IP_VS_CA: " msg);	\
	} while (0)

#ifdef IP_VS_CA_DEBUG
#define EnterFunction()						\
	do {							\
			printk(KERN_DEBUG			\
			pr_fmt("Enter: %s, %s line %i\n"),	\
				__func__, __FILE__, __LINE__);	\
	} while (0)
#define LeaveFunction()						\
	do {							\
		printk(KERN_DEBUG				\
			pr_fmt("Leave: %s, %s line %i\n"),	\
			__func__, __FILE__, __LINE__);		\
	} while (0)
#define IP_VS_CA_DBG(msg...)					\
	do {							\
		if (net_ratelimit())				\
		printk(KERN_DEBUG "[DEBUG] IP_VS_CA: " msg);	\
	} while (0)

#define IP_VS_CA_INFO(msg...)					\
	do {							\
		if (net_ratelimit())				\
		printk(KERN_INFO "[INFO] IP_VS_CA: " msg);	\
	} while (0)
#else

#define EnterFunction()  do {} while (0)
#define LeaveFunction()  do {} while (0)
#define IP_VS_CA_DBG(msg...)  do {} while (0)
#define IP_VS_CA_INFO(msg...)  do {} while (0)


#endif

/*#define TCPOPT_ADDR  254*/
extern int tcpopt_addr;
/* MUST be 4n !!!! */
#define TCPOLEN_ADDR 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

struct ip_vs_ca_conn;
struct ip_vs_ca_iphdr;
struct ip_vs_ca_conn;

/*
static inline void ip_vs_ca_addr_copy(int af, union nf_inet_addr *dst,
				   const union nf_inet_addr *src)
{
#ifdef CONFIG_IP_VS_CA_IPV6
	if (af == AF_INET6)
		ipv6_addr_copy(&dst->in6, &src->in6);
	else
#endif
		dst->ip = src->ip;
}
*/


static inline int ip_vs_ca_addr_equal(int af, const union nf_inet_addr *a,
				   const union nf_inet_addr *b)
{
#ifdef CONFIG_IP_VS_CA_IPV6
	if (af == AF_INET6)
		return ipv6_addr_equal(&a->in6, &b->in6);
#endif
	return a->ip == b->ip;
}

struct ip_vs_ca_iphdr {
	int len;
	__u8 protocol;
	union nf_inet_addr saddr;
	union nf_inet_addr daddr;
};

static inline void
ip_vs_ca_fill_iphdr(int af, const void *nh, struct ip_vs_ca_iphdr *iphdr)
{
	const struct iphdr *iph = nh;
	iphdr->len = iph->ihl * 4;
	iphdr->protocol = iph->protocol;
	iphdr->saddr.ip = iph->saddr;
	iphdr->daddr.ip = iph->daddr;
}


/*
 *	IP_VS_CA structure allocated for each connection
 */
struct ip_vs_ca_conn {
	struct list_head s_list;         /* hashed list heads for s_addr(lvs local ip) */
	struct list_head c_list;         /* hashed list heads for client ip */

	u16 af;                          /* address family */
	__u8 protocol;                  /* Which protocol (TCP/UDP) */
	union nf_inet_addr s_addr;       /* source address */
	union nf_inet_addr d_addr;       /* destination address */
	__be16 s_port;                   /* source port */
	__be16 d_port;                   /* destination port */

	union nf_inet_addr c_addr;       /* origin address */
	__be16 c_port;                   /* origin port */

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
struct ip_vs_tcpo_addr {
	__u8 opcode;
	__u8 opsize;
	__u16 port;
	__u32 addr;
} __attribute__((__packed__));


struct ipvs_ca {
	__u8 code;			/* magic code */
	__u8 protocol;		/* Which protocol (TCP/UDP) */
	__be16 sport;
	__be16 dport;
	struct ip_vs_tcpo_addr toa;
} __attribute__((__packed__));

union ip_vs_ca_data {
	__u64 data;
	struct ip_vs_tcpo_addr tcp;
};

/* statistics about toa in proc /proc/net/ip_vs_ca_stat */
enum {
	SYN_RECV_SOCK_IP_VS_CA_CNT = 1,
	SYN_RECV_SOCK_NO_IP_VS_CA_CNT,
	CONN_NEW_CNT,
	CONN_DEL_CNT,
	IP_VS_CA_STAT_LAST
};

enum {
	IP_VS_CA_S_TCP = 0,
	IP_VS_CA_S_UDP,
	IP_VS_CA_S_LAST
};

enum {
	IP_VS_CA_IN = 0,	/* in  s_addr -> c_addr */
	IP_VS_CA_OUT		/* out c_addr -> s_addr */
};


struct ip_vs_ca_stats_entry {
	char *name;
	int entry;
};

#define IP_VS_CA_STAT_ITEM(_name, _entry) {	\
	.name = _name,				\
	.entry = _entry,			\
}

#define IP_VS_CA_STAT_END {	\
	NULL,			\
	0,			\
}

struct ip_vs_ca_stat_mib {
	unsigned long mibs[IP_VS_CA_STAT_LAST];
};

#define IP_VS_CA_INC_STATS(mib, field)         \
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

struct syscall_links {
	asmlinkage long (*getpeername)(int, struct sockaddr __user *, int __user *);
	asmlinkage long (*accept4)(int, struct sockaddr __user *, int __user *, int);
	asmlinkage long (*recvfrom)(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int __user *);
	asmlinkage long (*connect)(int, struct sockaddr __user *, int);
	asmlinkage long (*accept)(int, struct sockaddr __user *, int __user *);
	asmlinkage long (*sendto)(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int);
};

struct ip_vs_ca_protocol {
	struct ip_vs_ca_protocol *next;
	char *name;
	__u8 protocol;
	u16 num_states;
	int dont_defrag;
	atomic_t appcnt;	/* counter of proto app incs */
	int *timeout;		/* protocol timeout table */

	int (*skb_process) (int af, struct sk_buff * skb,
			      struct ip_vs_ca_protocol * pp,
			      const struct ip_vs_ca_iphdr * iph,
			      int *verdict, struct ip_vs_ca_conn ** cpp);

	int (*icmp_process) (int af, struct sk_buff * skb,
			      struct ip_vs_ca_protocol * pp,
			      const struct ip_vs_ca_iphdr * iph,
				  struct icmphdr *icmph, struct ipvs_ca *ca,
			      int *verdict, struct ip_vs_ca_conn ** cpp);

	struct ip_vs_ca_conn *
	    (*conn_get) (int af, const struct sk_buff * skb,
			    struct ip_vs_ca_protocol * pp,
			    const struct ip_vs_ca_iphdr * iph,
			    unsigned int proto_off);

};

static inline void __ip_vs_ca_conn_put(struct ip_vs_ca_conn *cp)
{
	atomic_dec(&cp->refcnt);
}

extern int ip_vs_ca_conn_init(void);
extern void ip_vs_ca_conn_cleanup(void);
extern void ip_vs_ca_conn_put(struct ip_vs_ca_conn *cp);
extern void ip_vs_ca_conn_cleanup(void);
extern struct ip_vs_ca_conn *ip_vs_ca_conn_get(int af, __u8 protocol,
	 const union nf_inet_addr *s_addr, __be16 s_port, int dir);
struct ip_vs_ca_conn *ip_vs_ca_conn_new(int af,
					struct ip_vs_ca_protocol *pp,
					__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport,
					__be32 oaddr, __be16 oport,
					struct sk_buff *skb);

extern int ip_vs_ca_protocol_init(void);
extern void ip_vs_ca_protocol_cleanup(void);
extern struct ip_vs_ca_protocol *ip_vs_ca_proto_get(unsigned short proto);

extern int ip_vs_ca_control_init(void);
extern void ip_vs_ca_control_cleanup(void);

extern unsigned long **find_sys_call_table(void);
const char *ip_vs_ca_proto_name(unsigned proto);


extern struct ip_vs_ca_stat_mib *ext_stats;

#endif
