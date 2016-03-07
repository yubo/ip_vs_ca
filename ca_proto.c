/*
 * ca_proto.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-25
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include "ca.h"

enum {
	IP_VS_CA_PROTO_TCP = 0,
	IP_VS_CA_PROTO_UDP,
	IP_VS_CA_PROTO_TAB_SIZE
};

static struct ip_vs_ca_protocol *ip_vs_ca_proto_table[IP_VS_CA_PROTO_TAB_SIZE];

static void
ip_vs_ca_tcpudp_debug_packet_v4(struct ip_vs_ca_protocol *pp,
			     const struct sk_buff *skb,
			     int offset, const char *msg)
{
	char buf[128];
	struct iphdr _iph, *ih;

	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (ih == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else if (ih->frag_off & htons(IP_OFFSET))
		sprintf(buf, "%s %pI4->%pI4 frag",
			pp->name, &ih->saddr, &ih->daddr);
	else {
		__be16 _ports[2], *pptr;
		pptr = skb_header_pointer(skb, offset + ih->ihl * 4,
					  sizeof(_ports), _ports);
		if (pptr == NULL)
			sprintf(buf, "%s TRUNCATED %pI4->%pI4",
				pp->name, &ih->saddr, &ih->daddr);
		else
			sprintf(buf, "%s %pI4:%u->%pI4:%u",
				pp->name,
				&ih->saddr, ntohs(pptr[0]),
				&ih->daddr, ntohs(pptr[1]));
	}

	pr_debug("%s: %s\n", msg, buf);
}

static void
ip_vs_ca_tcpudp_debug_packet(struct ip_vs_ca_protocol *pp,
			  const struct sk_buff *skb,
			  int offset, const char *msg)
{
#ifdef CONFIG_IP_VS_CA_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		/*
		 * ip_vs_ca_tcpudp_debug_packet_v6(pp, skb, offset, msg);
		 */
	else
#endif
		ip_vs_ca_tcpudp_debug_packet_v4(pp, skb, offset, msg);
}

/*
 * #################### tcp ##################
 */

static struct ip_vs_ca_conn *tcp_conn_get(int af, const struct sk_buff *skb,
					  struct ip_vs_ca_protocol *pp,
					  const struct ip_vs_ca_iphdr *iph,
					  unsigned int proto_off)
{
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	return ip_vs_ca_conn_get(af, iph->protocol,
			      &iph->saddr, pptr[0]);
}

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of toa_data in ret_ptr if we get client ip/port.
 */
static __u64 get_ip_vs_ca_data(struct tcphdr *th)
{
	int length;
	union ip_vs_ca_data tdata;
	unsigned char *ptr;

//	IP_VS_CA_DBG("get_ip_vs_ca_data called\n");

	if (NULL != th) {
		length = (th->doff * 4) - sizeof(struct tcphdr);
		ptr = (unsigned char *) (th + 1);

		while (length > 0) {
			int opcode = *ptr++;
			int opsize;
			switch (opcode) {
			case TCPOPT_EOL:
				return 0;
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
				opsize = *ptr++;
				if (opsize < 2)	/* "silly options" */
					return 0;
				if (opsize > length)
					/* don't parse partial options */
					return 0;
				if (TCPOPT_IP_VS_CA == opcode &&
				    TCPOLEN_IP_VS_CA == opsize) {
					memcpy(&tdata.data, ptr - 2, sizeof(tdata.data));
#if 0
					IP_VS_CA_DBG("find toa data: ip = "
						"%pI4, port = %u\n",
						&tdata.tcp.ip,
						ntohs(tdata.tcp.port));
					IP_VS_CA_DBG("coded toa data: %llx\n",
						tdata.data);
#endif
					return tdata.data;
				}
				ptr += opsize - 2;
				length -= opsize;
			}
		}
	}
	return 0;
}


static int
tcp_skb_process(int af, struct sk_buff *skb, struct ip_vs_ca_protocol *pp,
		  const struct ip_vs_ca_iphdr *iph,
		  int *verdict, struct ip_vs_ca_conn **cpp)
{
	struct tcphdr _tcph, *th;
	union ip_vs_ca_data tdata = {.data = 0};

	th = skb_header_pointer(skb, iph->len, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		goto out;
	}

	if (!th->syn){
		goto out;
	}

	if ((tdata.data = get_ip_vs_ca_data(th)) != 0){
		IP_VS_CA_INC_STATS(ext_stats, SYN_RECV_SOCK_IP_VS_CA_CNT);
		//create cp
		*cpp = ip_vs_ca_conn_new(af, iph->protocol, 
				iph->saddr.ip , th->source, 
				iph->daddr.ip, th->dest, 
				tdata.tcp.ip, tdata.tcp.port,
				skb);
		if (*cpp == NULL){
			goto out;
		} else{
			ip_vs_ca_conn_put(*cpp);
			*verdict = NF_ACCEPT;
			return 0;
		}
	}else{
		IP_VS_CA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_IP_VS_CA_CNT);
		goto out;
	}

out:
	*cpp = NULL;
	*verdict = NF_ACCEPT;
	return 1;
}


struct ip_vs_ca_protocol ip_vs_ca_protocol_tcp = {
	.name = "TCP",
	.protocol = IPPROTO_TCP,
	.skb_process = tcp_skb_process,
	.debug_packet = ip_vs_ca_tcpudp_debug_packet,
	.conn_get = tcp_conn_get,
};

/*
 * #################### udp ##################
 */

static struct ip_vs_ca_conn *udp_conn_get(int af, const struct sk_buff *skb,
					  struct ip_vs_ca_protocol *pp,
					  const struct ip_vs_ca_iphdr *iph,
					  unsigned int proto_off)
{
	return NULL;
}

static int
udp_skb_process(int af, struct sk_buff *skb, struct ip_vs_ca_protocol *pp,
		  const struct ip_vs_ca_iphdr *iph,
		  int *verdict, struct ip_vs_ca_conn **cpp)
{
	if (false){
		*cpp = NULL;
		*verdict = NF_ACCEPT;
		return 0;
	}
	return 1;
}


struct ip_vs_ca_protocol ip_vs_ca_protocol_udp = {
	.name = "UDP",
	.protocol = IPPROTO_UDP,
	.skb_process = udp_skb_process,
	.debug_packet = ip_vs_ca_tcpudp_debug_packet,
	.conn_get = udp_conn_get,
};





/*
 *	get ip_vs_ca_protocol object by its proto.
 */
struct ip_vs_ca_protocol *ip_vs_ca_proto_get(unsigned short proto)
{
	int i;

	for(i = 0; i<IP_VS_CA_PROTO_TAB_SIZE; i++){
		if (ip_vs_ca_proto_table[i]->protocol == proto)
			return ip_vs_ca_proto_table[i];
	}
	return NULL;
}


int __init ip_vs_ca_protocol_init(void)
{
	ip_vs_ca_proto_table[IP_VS_CA_PROTO_TCP] = &ip_vs_ca_protocol_tcp;
	ip_vs_ca_proto_table[IP_VS_CA_PROTO_UDP] = &ip_vs_ca_protocol_udp;
	return 0;
}

void ip_vs_ca_protocol_cleanup(void)
{

}
