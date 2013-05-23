//
//  main.c
//  [20111208] pcap
//
//  Created by 土屋 貴裕 on 11/12/08.
//  Copyright (c) 2011年 __MyCompanyName__. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

void print_ethaddr(u_char *, const struct pcap_pkthdr *, const u_char *packet);

main(int argc, char *argv[]) {
	pcap_t *pd;
	int snaplen = 64;
    int pflag = 0;
    int timeout = 1000;
    char ebuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 localnet, netmask;
    pcap_handler callback;
    struct bpf_program;
    
	//macならen0とかubuntuならeth1とか
    if ((pd = pcap_open_live("en1", snaplen, !pflag, timeout, ebuf)) == NULL) {
		exit(1);
    }	
    
	if (pcap_lookupnet("en1", &localnet, &netmask, ebuf) < 0) {
		exit(1);
    }
    callback = print_ethaddr;
    if (pcap_loop(pd, -1, callback, NULL) < 0) {
		exit(1);
    }
	pcap_close(pd);
	exit(0);
}


void print_ethaddr(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *eh;		/* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */	
	int i;
    int mode = 0;
	int packetLen = 0;
	int size_ip;
	int size_tcp;
	int size_payload;
	int sendport = 5;
	int port = 5;
	eh = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes¥n", size_ip);
		return;
	}
    
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		//printf("   * Invalid TCP header length: %u bytes¥n", size_tcp);
		return;
	}
    printf("MAC: ");	
 	//送信元MACアドレス
    for (i = 0; i < 6; ++i) {
		printf("%02x", (int)eh->ether_shost[i]);
		if(i < 5){
			printf(":");
		}
	}
    printf(" -> ");
	//送信先MACアドレス
    for (i = 0; i < 6; ++i) {
		printf("%02x", (int)eh->ether_dhost[i]);
		if(i < 5){
			printf(":");
		}
	}
	printf("\n");
	printf("port: %d -> ",ntohs(tcp->th_sport));
	printf("%d\n",ntohs(tcp->th_dport));
    printf("length: %d\n", ip->ip_len);
	printf("==========================================\n");
}
