#ifndef INCLUDE_PACKET_PARSER_H_
#define INCLUDE_PACKET_PARSER_H_

#include <linux/filter.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <malloc.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <sys/time.h> // for setitimer and related structs
#include <signal.h>

#define TIME_OUT 1000
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define MAX_PACKET_NUM 1000
#define TCP_p 10
#define UDP_p 11
#define ICMP_p 12
#define IP_p 13
#define OTHER_p 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14
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
        #define IP_DF 0x4000            /* don't fragment flag */
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



/* User Defined */
typedef unsigned char u_char;
typedef unsigned int uint32;
typedef struct
{
	int tcp_count;
	int udp_count;
	int icmp_count;
	int other_count;
} packet_stats_t;



/* Externed golbal variables */
extern packet_stats_t * ptr ;
extern char dev[] ;                /* Interface name */
extern char filter_exp[];      /* The filter expression */
extern const u_char *packet;           /* The actual packet */
extern int  _Time;
extern pcap_t *handle;

void process_packet (const u_char *packet, packet_stats_t * stats);
int get_packet_protocol(const u_char *packet);
void print_stats(const packet_stats_t * stats);
void reset_counters(packet_stats_t * stats);
void timer_handler(int sig);


#endif
