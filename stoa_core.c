/*
 * stoa_core.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <asm/paravirt.h>
#include "stoa.h"

unsigned long **sys_call_table;
unsigned long original_cr0;

asmlinkage int (*_getpeername) (int, struct sockaddr *, int *);
asmlinkage int (*_accept4) (int, struct sockaddr *, int *, int);

static int stoa_modify_uaddr(int fd, struct sockaddr *uaddr, int *ulen)
{
	int err, len;
	struct socket *sock;
	struct sockaddr_in sin;
	union nf_inet_addr addr;
	struct stoa_conn *cp;

	err = get_user(len, ulen);
	if (err)
		return 1;

	if (len != sizeof(sin)){
		return 2;
	}

	err = copy_from_user(&sin, uaddr, len);
	if (err)
		return 3;

	if (sin.sin_family != AF_INET)
		return 4;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return 5;

	STOA_DBG("%s called, sin{.family:%d, .port:%d, addr:%pI4} sock.type:%d\n",
			__func__, sin.sin_family, ntohs(sin.sin_port),
			&sin.sin_addr.s_addr, sock->type);

	addr.ip = sin.sin_addr.s_addr;

	if (sock->type == SOCK_STREAM){
		cp = stoa_conn_get(sin.sin_family, IPPROTO_TCP, &addr, sin.sin_port);
	}else if(sock->type == SOCK_DGRAM){
		cp = stoa_conn_get(sin.sin_family, IPPROTO_UDP, &addr, sin.sin_port);
	}else{
		return 6;
	}

	if (!cp)
		return 7;

	STOA_DBG("%s called, %d %pI4:%d(%pI4:%d)->%pI4:%d\n",
			__func__, cp->protocol,
			&sin.sin_addr.s_addr, ntohs(sin.sin_port),
			&cp->o_addr.ip, ntohs(cp->o_port),
			&cp->d_addr.ip, ntohs(cp->d_port));
	sin.sin_addr.s_addr = cp->o_addr.ip;
	sin.sin_port = cp->o_port;
	stoa_conn_put(cp);
	if(copy_to_user(uaddr, &sin, len))
		return 8;
	
	return 0;
}

/*
 * ./net/socket.c:1624
 */
asmlinkage int stoa_getpeername(int fd, struct sockaddr *usockaddr, int *usockaddr_len)
{
	int ret, err, len;
	struct sockaddr_in sin;

	STOA_DBG("getpeername called\n");

	ret =  _getpeername(fd, usockaddr, usockaddr_len);
	if (ret < 0)
		return ret;

	err = stoa_modify_uaddr(fd, usockaddr, usockaddr_len);
	if (err)
		STOA_DBG("stoa_modify_uaddr return:%d\n", err);

	return ret;
}

asmlinkage int
toa_accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags)
{
	int ret, err, len;

	STOA_DBG("accept4 called\n");

	ret = _accept4(fd, upeer_sockaddr, upeer_addrlen, flags);
	if (ret < 0)
		return ret;

	err = stoa_modify_uaddr(fd, upeer_sockaddr, upeer_addrlen);
	if (err)
		STOA_DBG("stoa_modify_uaddr err:%d\n", err);

	return ret;
}

const char *stoa_proto_name(unsigned proto)
{
	static char buf[20];

	switch (proto) {
		case IPPROTO_IP:
			return "IP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_ICMP:
			return "ICMP";
#ifdef CONFIG_IP_VS_IPV6
		case IPPROTO_ICMPV6:
			return "ICMPv6";
#endif
		default:
			sprintf(buf, "IP_%d", proto);
			return buf;
	}
}

static int stoa_syscall_init(void)
{
	if (!(sys_call_table = find_sys_call_table())){
		STOA_ERR("get sys call table failed.\n");
		return -1;
	}

	original_cr0 = read_cr0();
	write_cr0(original_cr0 & ~0x00010000);
	STOA_DBG("Loading stoa module, sys call table at %p\n", sys_call_table);
	_getpeername = (void *)(sys_call_table[__NR_getpeername]);
	_accept4 = (void *)(sys_call_table[__NR_accept4]);
	sys_call_table[__NR_getpeername] = (void *)toa_getpeername;
	sys_call_table[__NR_accept4] = (void *)toa_accept4;
	write_cr0(original_cr0);

	return 0;
}

static void stoa_syscall_cleanup(void)
{	
	if (!sys_call_table){
		return;
	}

	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_getpeername] = (void *)_getpeername;
	sys_call_table[__NR_accept4] = (void *)_accept4;
	write_cr0(original_cr0);
	//msleep(100);
	sys_call_table = NULL;
}

static unsigned int
stoa_in_hook(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn) (struct sk_buff *))
{
	struct stoa_iphdr iph;
	struct stoa_conn *cp;
	struct stoa_protocol *pp;
	int af;

	//EnterFunction();

	af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

	if (af != AF_INET) {
		goto out;
	}

	stoa_fill_iphdr(af, skb_network_header(skb), &iph);


	/*
	 *      Big tappo: only PACKET_HOST, including loopback for local client
	 *      Don't handle local packets on IPv6 for now
	 */
	if (unlikely(skb->pkt_type != PACKET_HOST)) {
		STOA_DBG("packet type=%d proto=%d daddr=%pI4 ignored\n",
				skb->pkt_type,
				iph.protocol, &iph.daddr.ip);
		goto out;
	}

	if (unlikely(iph.protocol == IPPROTO_ICMP)) {
		goto out;
	}

	/* Protocol supported? */
	pp = stoa_proto_get(iph.protocol);
	if (unlikely(!pp))
		goto out;

	/*
	 * Check if the packet belongs to an existing connection entry
	 */
	cp = pp->conn_get(af, skb, pp, &iph, iph.len);

	if (likely(cp)) {
		stoa_conn_put(cp);
		goto out;
	} else {
		int v;
		/* create a new connection */
		if(pp->skb_process(af, skb, pp, &iph, &v, &cp) == 0){
			//LeaveFunction();
			return v;
		}else{
			goto out;
		}
	}

out:
	//LeaveFunction();
	return NF_ACCEPT;
}

static struct nf_hook_ops stoa_ops[] __read_mostly = { 
	{
		.hook     = stoa_in_hook,         
		.owner    = THIS_MODULE,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN, 
		.priority = NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};

static int __init stoa_init(void)
{
	int ret;

	ret = stoa_syscall_init();
	if (ret < 0){
		STOA_ERR("can't modify syscall table.\n");
		goto out_err;
	}
	STOA_DBG("modify syscall table done.\n");

	stoa_protocol_init();
	STOA_DBG("stoa_protocol_init done.\n");

	ret = stoa_control_init();
	if (ret < 0){
		STOA_ERR("can't modify syscall table.\n");
		goto cleanup_syscall;
	}
	STOA_DBG("stoa_control_init done.\n");

	ret = stoa_conn_init();
	if (ret < 0){
		STOA_ERR("can't setup connection table.\n");
		goto cleanup_control;
	}
	STOA_DBG("stoa_conn_init done.\n");

	ret = nf_register_hooks(stoa_ops, ARRAY_SIZE(stoa_ops));
	if (ret < 0){
		STOA_ERR("can't register hooks.\n");
		goto cleanup_conn;
	}
	STOA_DBG("nf_register_hooks done.\n");

	STOA_INFO("stoa loaded.");
	return ret;

cleanup_conn:
	stoa_conn_cleanup();
cleanup_control:
	stoa_control_cleanup();
cleanup_syscall:
	stoa_syscall_cleanup();
out_err:
	return ret;
}

static void __exit stoa_exit(void)
{
	nf_unregister_hooks(stoa_ops, ARRAY_SIZE(stoa_ops));
	stoa_conn_cleanup();
	stoa_protocol_cleanup();
	stoa_control_cleanup();
	stoa_syscall_cleanup();
	STOA_INFO("stoa unloaded.");
}

module_init(stoa_init);
module_exit(stoa_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yu Bo<yubo@yubo.org>");

