#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include<string.h>

#define ERR_EXIT(m) \
do { \
	perror(m); \
	exit(EXIT_FAILURE); \
} while (0)

int main(int argc, char *argv[])
{
	int sock, on;
	struct sockaddr_in servaddr, peeraddr;
	char recvbuf[1024] = {0};
	socklen_t peerlen;
	int n;

	if (argc != 2) {
		fprintf(stderr, "Usage\n\t%s <port> \n",
				argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		ERR_EXIT("socket error");

	on = 1;
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(argv[1]));
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	printf("serv %s:%d \n", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));

	if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		ERR_EXIT("bind error");

	while (1){
		peerlen = sizeof(peeraddr);
		memset(recvbuf, 0, sizeof(recvbuf));
		n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
				(struct sockaddr *)&peeraddr, &peerlen);
		if(n == -1) {

			if (errno == EINTR)
				continue;

			ERR_EXIT("recvfrom error");
		}else if(n > 0) {
			printf("recv %d %s:%d\n", peerlen, inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));
			fputs(recvbuf, stdout);
		}
	}
	close(sock);

	return 0;
}
