# IPVS CA

get ip vs(fullnat) client addr 

由taobao/toa修改，可作为独立模块编译安装, 支持tcp/udp, 相应lvs内核稍后放出, 开发环境为centos 6.6/ linux 2.6.32,其他环境还未做适配

## Feature
  - [x] Build as a module
  - [x] Support TCP
  - [x] Support UDP
  - [x] Support centos 6.6
  - [ ] Support centos 7.x

## Demo

lvs(fullnat) client address TCP
[![TCP](https://asciinema.org/a/7e1qyj3ovn8yfe6a3srfcj104.png)](https://asciinema.org/a/7e1qyj3ovn8yfe6a3srfcj104?autoplay=1)

lvs(fullnat) client address UDP
[![UDP](https://asciinema.org/a/c0q9u1jhr367qay237azaep5e.png)](https://asciinema.org/a/c0q9u1jhr367qay237azaep5e?autoplay=1)

## Install
```shell
make
```

## Run
```shell
#install
insmod ./ip_vs_ca.ko
#remove
rmmod ip_vs_ca
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
		printf("recv %d %s:%d\n", peerlen, inet_ntoa(peeraddr[0].sin_addr), ntohs(peeraddr[0].sin_port));
	}else if(peerlen == sizeof(peeraddr)){
		printf("recv %d %s:%d", peerlen, inet_ntoa(peeraddr[0].sin_addr), ntohs(peeraddr[0].sin_port));
		printf("(%s:%d)\n", inet_ntoa(peeraddr[1].sin_addr), ntohs(peeraddr[1].sin_port));
	}
```
