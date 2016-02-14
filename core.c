/*
 * stoa
 * Copyright (C) 2016 yubo@yubo.org
 * 2016-02-14
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include "stoa.h"

unsigned long **sys_call_table;
unsigned long original_cr0;

asmlinkage int (*_getsockname) (int, struct sockaddr *, int);

asmlinkage int toa_getsockname(int fd, struct sockaddr *usockaddr, int usockaddr_len)
{
	return _getsockname(fd, usockaddr, usockaddr_len);
}

static int __init syscall_init(void)
{
	if (!(sys_call_table = find_sys_call_table())){
		printk(KERN_ALERT "get sys call table failed.\n");
		return -1;
	}

	original_cr0 = read_cr0();
	write_cr0(original_cr0 & ~0x00010000);
	printk(KERN_INFO "Loading stoa module, sys call table at %p\n", sys_call_table);
	_getsockname = (void *)(sys_call_table[__NR_getsockname]);
	sys_call_table[__NR_getsockname] = (void *)toa_getsockname;
	write_cr0(original_cr0);

	return 0;
}

static void __exit syscall_exit(void)
{
	if (!sys_call_table){
		return;
	}

	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_getsockname] = (void *)_getsockname;
	write_cr0(original_cr0);
	msleep(100);
}

module_init(syscall_init);
module_exit(syscall_exit);
MODULE_LICENSE("GPL");

