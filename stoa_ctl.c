/*
 *	TOA: Address is a new TCP Option
 *	Address include ip+port, Now only support IPV4
 */

/*
 * stoa_core.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include "stoa.h"

struct stoa_stat_mib *ext_stats;

struct stoa_stats_entry stoa_stats[] = {
	STOA_STAT_ITEM("syn_recv_sock_stoa", SYN_RECV_SOCK_STOA_CNT),
	STOA_STAT_ITEM("syn_recv_sock_no_stoa", SYN_RECV_SOCK_NO_STOA_CNT),
	STOA_STAT_ITEM("getname_stoa_ok", GETNAME_STOA_OK_CNT),
	STOA_STAT_ITEM("getname_stoa_mismatch", GETNAME_STOA_MISMATCH_CNT),
	STOA_STAT_ITEM("getname_stoa_bypass", GETNAME_STOA_BYPASS_CNT),
	STOA_STAT_ITEM("getname_stoa_empty", GETNAME_STOA_EMPTY_CNT),
	STOA_STAT_END
};


/*
 * Statistics of toa in proc /proc/net/stoa_stats
 */
static int stoa_stats_show(struct seq_file *seq, void *v)
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
	while (NULL != stoa_stats[i].name) {
		seq_printf(seq, "%-25s:", stoa_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ", *(
					((unsigned long *) per_cpu_ptr(
					ext_stats, j)) + stoa_stats[i].entry
					));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int stoa_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, stoa_stats_show, NULL);
}


static const struct file_operations stoa_stats_fops = {
	.owner = THIS_MODULE,
	.open = stoa_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int __init stoa_control_init(void){
	ext_stats = alloc_percpu(struct stoa_stat_mib);
	if (NULL == ext_stats)
		return 1;

	proc_net_fops_create(&init_net, "stoa_stats", 0, &stoa_stats_fops);
	return 0;
}

void stoa_control_cleanup(void)
{
	synchronize_net();
	proc_net_remove(&init_net, "stoa_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
} 
