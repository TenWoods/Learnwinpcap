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
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//4�ֽڵ�ip��ַ
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//IPv4�ײ�
typedef struct ip_header
{
	u_char ver_ihl;       //�汾+�ײ�����
	u_char tos;           //��������
	u_char tlen;          //�ܳ�
	u_char identification;//��ʶ
	u_char flags_fo;      //��־λ+ƫ����
	u_char ttl;           //���ʱ��
	u_char proto;         //Э��
	u_short crc;          //�ײ�У��λ
	ip_address saddr;     //Դ��ַ
	ip_address daddr;     //Ŀ�ĵ�ַ
	u_int op_pad;         //ѡ�������
}ip_header;

//UDP�ײ�
typedef struct udp_header
{
	u_short sport;        //Դ�˿�
	u_short dport;		  //Ŀ�Ķ˿�
	u_short len;			  //UDP���ݰ�����
	u_short crc;          //У���
}udp_header;

int main()
{
	pcap_if_t *devs;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

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
	//�豸����
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
	//ָ�������������ı��
	int inum = 0;
	//ָ���������������
	printf("Enter the interface number(1~%d)", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("Error:Interface number out of range");
		pcap_freealldevs(devs);
		return -1;
	}

	//ѡ���豸��ָ��
	pcap_if_t *d = NULL;

	//���������ҵ�ָ���豸��ָ��
	for (d = devs, i = 0; i < inum - 1; i++, d = d->next);

	//��������
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\ncan't open device %s, ERRO: %s", d->name, errbuf);
		pcap_freealldevs(devs);
		return -1;
	}

	//���������·��,ֻ������̫��
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet network.\n");
		pcap_freealldevs(devs);
		return -1;
	}

	//��ȡ��һ����ַ������
	u_int netmask;
	if (d->addresses != NULL)
	{
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
	{
		//�ӿ��޵�ַ������һ��C��������
		netmask = 0xffffff;
	}

	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter.\n");
		pcap_freealldevs(devs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(devs);
		return -1;
	}

	printf("\nlistening on %s\n", d->description);

	pcap_freealldevs(devs);

	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	getchar();
	return 0;
}

//��������豸��ϸ��Ϣ
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
//��ip��ַת��Ϊ�ַ���
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

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	
	//ת��ʱ���
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	//��ӡ���ݰ���ʱ����ͳ���
	printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

	//��ȡ���ݰ�ͷ��λ��
	ih = (ip_header *)(pkt_data + 14); //��̫��ͷ������

	//��ȡUDP�ײ�λ��
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	//�������ֽ�����ת��Ϊ�����ֽ�����
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	printf("%d.%d.%d.%d.%d->%d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}