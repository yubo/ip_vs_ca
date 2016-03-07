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

struct ip_vs_ca_stat_mib *ext_stats;

struct ip_vs_ca_stats_entry ip_vs_ca_stats[] = {
	IP_VS_CA_STAT_ITEM("syn_recv_sock_ip_vs_ca", SYN_RECV_SOCK_IP_VS_CA_CNT),
	IP_VS_CA_STAT_ITEM("syn_recv_sock_no_ip_vs_ca", SYN_RECV_SOCK_NO_IP_VS_CA_CNT),
	IP_VS_CA_STAT_ITEM("getname_ip_vs_ca_ok", GETNAME_IP_VS_CA_OK_CNT),
	IP_VS_CA_STAT_ITEM("getname_ip_vs_ca_mismatch", GETNAME_IP_VS_CA_MISMATCH_CNT),
	IP_VS_CA_STAT_ITEM("getname_ip_vs_ca_bypass", GETNAME_IP_VS_CA_BYPASS_CNT),
	IP_VS_CA_STAT_ITEM("getname_ip_vs_ca_empty", GETNAME_IP_VS_CA_EMPTY_CNT),
	IP_VS_CA_STAT_END
};


/*
 * Statistics of toa in proc /proc/net/ip_vs_ca_stats
 */
static int ip_vs_ca_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;

	/* print CPU first */
	seq_printf(seq, "                                  ");
	cpu_nr = num_possible_cpus();
	for (i = 0; i < cpu_nr; i++)
		if (cpu_online(i))
			seq_printf(seq, "CPU%d       ", i);
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != ip_vs_ca_stats[i].name) {
		seq_printf(seq, "%-25s:", ip_vs_ca_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ", *(
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

	proc_net_fops_create(&init_net, "ip_vs_ca_stats", 0, &ip_vs_ca_stats_fops);
	return 0;
}

void ip_vs_ca_control_cleanup(void)
{
	synchronize_net();
	proc_net_remove(&init_net, "ip_vs_ca_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
} 
