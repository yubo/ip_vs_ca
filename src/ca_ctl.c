/*
 *	TOA: Address is a new TCP Option
 *	Address include ip+port, Now only support IPV4
 */

/*
 * ca_core.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */
#include "ca.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#include <linux/proc_fs.h>
#define USE_PROC_CTREATE1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define USE_PROC_CTREATE
#endif

int tcpopt_addr = 200;
struct ip_vs_ca_stat_mib *ext_stats;

#ifdef USE_PROC_CTREATE
static struct proc_dir_entry *ca_stats;
#endif
static struct ctl_table_header *sysctl_header;
extern int sysctl_ip_vs_ca_timeouts[IP_VS_CA_S_LAST + 1];
static int tcpopt_addr_min = 0;
static int tcpopt_addr_max = 255;

/*
 *	IPVS sysctl table (under the /proc/sys/net/ca/)
 *	Do not change order or insert new entries without
 *	align with netns init in ip_vs_control_net_init()
 */
static struct ctl_table vs_vars[] = {
	{
	 .procname     = "tcp_timeout",
	 .data         = &sysctl_ip_vs_ca_timeouts[IP_VS_CA_S_TCP],
	 .maxlen       = sizeof(int),
	 .mode         = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname     = "udp_timeout",
	 .data         = &sysctl_ip_vs_ca_timeouts[IP_VS_CA_S_UDP],
	 .maxlen       = sizeof(int),
	 .mode         = 0644,
	 .proc_handler = proc_dointvec_jiffies,
	 },
	{
	 .procname     = "tcpopt_addr",
	 .data         = &tcpopt_addr,
	 .maxlen       = sizeof(int),
	 .mode         = 0644,
	 .proc_handler = proc_dointvec_minmax,
	 .extra1       = &tcpopt_addr_min,
	 .extra2       = &tcpopt_addr_max,
	 },
	{.procname = 0}
};

const struct ctl_path net_vs_ctl_path[] = {
	{
		.procname = "net",
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		.ctl_name = CTL_NET,
#endif
	},
	{.procname = "ca"},
	{.procname = 0}
};
EXPORT_SYMBOL_GPL(net_vs_ctl_path);


struct ip_vs_ca_stats_entry ip_vs_ca_stats[] = {
	IP_VS_CA_STAT_ITEM("syn_recv_sock_ip_vs_ca", SYN_RECV_SOCK_IP_VS_CA_CNT),
	IP_VS_CA_STAT_ITEM("syn_recv_sock_no_ip_vs_ca", SYN_RECV_SOCK_NO_IP_VS_CA_CNT),
	IP_VS_CA_STAT_ITEM("conn_new", CONN_NEW_CNT),
	IP_VS_CA_STAT_ITEM("conn_del", CONN_DEL_CNT),
	IP_VS_CA_STAT_END
};


/*
 * Statistics of toa in proc /proc/net/ip_vs_ca_stats
 */
static int ip_vs_ca_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;
	char buff[10];

	/* print CPU first */
	seq_printf(seq, "IP_VS_CA(%s)\n", IP_VS_CA_VERSION);
	seq_printf(seq, "%-25s ", "");
	cpu_nr = num_possible_cpus();
	for (i = 0; i < cpu_nr; i++)
		if (cpu_online(i)){
			sprintf(buff, "CPU%d", i);
			seq_printf(seq, " %10s", buff);
		}
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != ip_vs_ca_stats[i].name) {
		seq_printf(seq, "%-25s:", ip_vs_ca_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, " %10lu", *(
					((unsigned long *) per_cpu_ptr(
					ext_stats, j)) + ip_vs_ca_stats[i].entry
					));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int ip_vs_ca_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, ip_vs_ca_stats_show, NULL);
}


static const struct file_operations ip_vs_ca_stats_fops = {
	.owner = THIS_MODULE,
	.open = ip_vs_ca_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int __init ip_vs_ca_control_init(void){
	ext_stats = alloc_percpu(struct ip_vs_ca_stat_mib);
	if (NULL == ext_stats)
		return 1;


#ifdef USE_PROC_CTREATE1
	proc_create("ip_vs_ca_stats", 0, init_net.proc_net, &ip_vs_ca_stats_fops);
#elif defined USE_PROC_CTREATE
	ca_stats = proc_create("ip_vs_ca_stats", 0, init_net.proc_net, &ip_vs_ca_stats_fops);
#else
	proc_net_fops_create(&init_net, "ip_vs_ca_stats", 0, &ip_vs_ca_stats_fops);
#endif

	sysctl_header = register_sysctl_paths(net_vs_ctl_path, vs_vars);

	return 0;
}

void ip_vs_ca_control_cleanup(void)
{
	synchronize_net();
	unregister_sysctl_table(sysctl_header);
#ifdef USE_PROC_CTREATE1
	remove_proc_entry("ip_vs_ca_stats", init_net.proc_net);
#elif defined USE_PROC_CTREATE
	proc_remove(ca_stats);
#else
	proc_net_remove(&init_net, "ip_vs_ca_stats");
#endif
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
} 
