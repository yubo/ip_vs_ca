/*
 * stoa
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include <linux/module.h>
#include <linux/syscalls.h>

unsigned long **find_sys_call_table(void) {

	unsigned long ptr;
	unsigned long *p;

	printk(KERN_ALERT "Found the sys_call_table!!!\n");
	for (ptr = (unsigned long)sys_close;
			ptr < (unsigned long)&loops_per_jiffy;
			ptr += sizeof(void *)) {

		p = (unsigned long *)ptr;

		if (p[__NR_close] == (unsigned long)sys_close) {
			printk(KERN_ALERT "Found the sys_call_table!!! __NR_close[%d] sys_close[%lx]\n"
					" __NR_getsockname[%d] sct[__NR_getsockname][0x%lx]\n",
					__NR_close, 
					(unsigned long)sys_close,
					__NR_getsockname, 
					p[__NR_getsockname]);
			return (unsigned long **)p;
		}
	}

	return NULL;
} 

