/*
 * utils.c
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include <linux/module.h>
#include <linux/syscalls.h>
#include "ca.h"

unsigned long **find_sys_call_table(void) {

	unsigned long ptr;
	unsigned long *p;

	IP_VS_CA_DBG("Found the sys_call_table!!!\n");
	for (ptr = (unsigned long)sys_close;
			ptr < (unsigned long)&loops_per_jiffy;
			ptr += sizeof(void *)) {

		p = (unsigned long *)ptr;

		if (p[__NR_close] == (unsigned long)sys_close) {
			IP_VS_CA_DBG("Found the sys_call_table!!! __NR_close[%d] sys_close[%lx]\n"
					" __NR_getpeername[%d] sct[__NR_getpeername][0x%lx]\n",
					__NR_close, 
					(unsigned long)sys_close,
					__NR_getpeername, 
					p[__NR_getpeername]);
			return (unsigned long **)p;
		}
	}

	return NULL;
} 

