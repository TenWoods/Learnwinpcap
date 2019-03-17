#define WIN32
#define HAVE_REMOTE
#define _CRT_SECURE_NO_DEPRECATE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock.h>

void ifprint(pcap_if_t *i);
char* iptostr(u_long in);
char *ip6tostr(struct sockaddr *sockaddr, char *address, int addrlen);

int main()
{
	pcap_if_t *devs;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];
	printf("Enter the device you want to list:\n"
            "rpcap://              ==> lists interfaces in the local machine\n"
            "rpcap://hostname:port ==> lists interfaces in a remote machine\n"
            "                          (rpcapd daemon must be up and running\n"
            "                           and it must accept 'null' authentication)\n"
            "file://foldername     ==> lists all pcap files in the give folder\n\n"
		"Enter your choice: ");
	fgets(source, PCAP_ERRBUF_SIZE, stdin);
	source[PCAP_ERRBUF_SIZE] = '\0';
	if (pcap_findalldevs_ex(source, NULL, &devs, errbuf) == -1)
	{
		fprintf(stderr, "ERROR in pcap_findalldevs_ex:%s\n", errbuf);
		exit(1);
	}
	int i = 0;
	for (pcap_if_t * t = devs; t != NULL; t = t->next)
	{
		printf("%d. ", ++i);
		ifprint(t);
	}
	if (i == 0)
	{
		printf("No interface found!\n");
		return -1;
	}
	getchar();
	pcap_freealldevs(devs);
	return 0;
}

//输出所有设备详细信息
void ifprint(pcap_if_t *i)
{
	char ip6str[128];
	if (i->description)
	{
		printf("(%s)\n", i->description);
	}
	printf("\tLoopback: %s\n", (i->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	for (pcap_addr_t *a = i->addresses; a != NULL; a = a->next)
	{
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptostr(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptostr(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptostr(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptostr(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tostr(a->addr, ip6str, sizeof(ip6str)));
			break;
		default:
			break;
		}
	}
}

#define IPTOSTRBUFFERS 12
//将ip地址转换为字符串
char* iptostr(u_long in)
{
	static char output[IPTOSTRBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSTRBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char *ip6tostr(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;
	sockaddrlen = sizeof(struct sockaddr_storage);
	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}