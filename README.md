# IPVS CA

get ip vs(fullnat) client addr 

由taobao/toa修改，可作为独立模块编译安装, 支持tcp/udp

支持 centos6.6(2.6.32-220) / centos7.2(linux 3.10.0-237.4.5)

对应内核在[github.com/yubo/LVS](https://github.com/yubo/LVS/tree/lvs_v2),兼容[taobao/LVS(lvs_v2)](https://github.com/alibaba/LVS/tree/lvs_v2)

## Feature
  - [x] Build as a module
  - [x] Support TCP
  - [x] Support UDP
  - [x] Support centos 6.6
  - [x] Support centos 7.2
  - [x] Support centos 7.2 rpmbuild

## Demo

lvs(fullnat) client address TCP
[![TCP](https://asciinema.org/a/7e1qyj3ovn8yfe6a3srfcj104.png)](https://asciinema.org/a/7e1qyj3ovn8yfe6a3srfcj104?autoplay=1)

lvs(fullnat) client address UDP
[![UDP](https://asciinema.org/a/c0q9u1jhr367qay237azaep5e.png)](https://asciinema.org/a/c0q9u1jhr367qay237azaep5e?autoplay=1)

## Install

#### build kmod
```shell
cd src/ip_vs_ca
make
insmod ./ip_vs_ca.ko
```

### build rpm
ip_vs_ca kmod for centos7.2(RHEL7)
```shell
yum groupinstall "Development tools"
yum install kernel-devel kernel-abi-whitelists bzip2
make
rpm -ivh ~/rpmbuild/RPMS/x86_64/kmod-ip_vs_ca-0.01-1.el7.centos.x86_64.rpm
modprobe ip_vs_ca
```

## Udpd example

[udpd.c](udpd.c)

```c
	char recvbuf[1024] = {0};
	struct sockaddr_in peeraddr[2];
	socklen_t peerlen;
	int n;

	peerlen = sizeof(peeraddr);
	n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
			(struct sockaddr *)peeraddr, &peerlen);
	if(peerlen == sizeof(struct sockaddr_in)){
		printf("recv %d %s:%d\n", peerlen,
			inet_ntoa(peeraddr[0].sin_addr),
			ntohs(peeraddr[0].sin_port));
	}else if(peerlen == sizeof(peeraddr)){
		printf("recv %d %s:%d", peerlen,
			inet_ntoa(peeraddr[0].sin_addr),
			ntohs(peeraddr[0].sin_port));
		printf("(%s:%d)\n",
			inet_ntoa(peeraddr[1].sin_addr),
			ntohs(peeraddr[1].sin_port));
	}
```
