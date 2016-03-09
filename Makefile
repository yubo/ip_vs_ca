KERNEL_DIR = /lib/modules/`uname -r`/build
MODULEDIR := $(shell pwd)


.PHONY: modules start stop restart
default: modules

modules:
	make -C $(KERNEL_DIR) M=$(MODULEDIR) modules

clean distclean:
	rm -f *.o *.mod.c .*.*.cmd *.ko *.ko.unsigned
	rm -rf .tmp_versions
	rm -f udpd *.order *.symvers .*.cmd

start:
	insmod ./ip_vs_ca.ko

stop:
	rmmod ip_vs_ca

restart:
	remod ip_vs_ca && insmod ./ip_vs_ca.ko
