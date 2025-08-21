/* raw_socket_sniffer.c - The Linux Channel */
//#include "libpcap-1.10.5/pcap/pcap.h"
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


#define ETHER_ADDR_LEN	6
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
typedef unsigned char  BYTE;    /* 8-bit   */








int total_packets = 0;
int tcp_packets = 0;
int udp_packets = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    total_packets++;
    
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    // Check if IPv4
    if (ntohs(eth->h_proto) == 0x0800) {
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        
        if (ip->protocol == 6) {      // TCP
            tcp_packets++;
        } else if (ip->protocol == 17) { // UDP
            udp_packets++;
        }
    }
    
    // Print stats every 50 packets
    if (total_packets % 50 == 0) {
        printf("Total: %d | TCP: %d | UDP: %d\n", total_packets, tcp_packets, udp_packets);
    }
}


struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};







#define SIZE_ETHERNET 14
const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;





















pcap_t *handle;		/* Session handle */
//char dev[] = "rl0";		/* Device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
struct bpf_program fp;		/* The compiled filter expression */
char filter_exp[] = "tcp";	/* The filter expression */
bpf_u_int32 mask;		/* The netmask of our sniffing device */
bpf_u_int32 net;		/* The IP of our sniffing device */
struct pcap_pkthdr header;	/* The header that pcap gives us */
const u_char *packet;		/* The actual packet */

enum _Boolean_ { FALSE=0, TRUE=1};

int sock_fd=0;

#define MAX_PKT_BUF 2000
unsigned char pkt_buf[MAX_PKT_BUF];
unsigned int pkt_buf_len=0;



struct sock_filter tcp_filter_code[] = {
    // Load EtherType field (offset 12)
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    // Check if IPv4 (0x0800), if not jump to reject
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0800, 0, 5),
    
    // Load IP protocol field (offset 23 in Ethernet frame: 14(Ethernet) + 9(IP header offset))
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
    // Check if TCP (protocol 6), if not jump to reject
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 6, 0, 3),
    
    // Check if packet length is sufficient (minimum 54 bytes: 14 Ethernet + 20 IP + 20 TCP)
    BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
    BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, 54, 1, 0),
    
    // Accept the packet
    BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
    // Reject the packet
    BPF_STMT(BPF_RET + BPF_K, 0),
};


struct sock_fprog tcp_filter = {
    .len = sizeof(tcp_filter_code) / sizeof(tcp_filter_code[0]),
    .filter = tcp_filter_code,
};



void parse_pkt(unsigned char *buf, unsigned int buf_len)
{
    struct ether_header *ep;
    struct ip *iph;
    unsigned short ether_type;
    int chcnt = 0;
    int len = buf_len;
    int i;

	for(i=0;i<buf_len;i++) 
	{ 
         printf("%02x ", buf[i]);
             
    }
	 printf("\n");
	 
	 printf("dest mac: %02x %02x %02x %02x %02x %02x \n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	 printf("src mac: %02x %02x %02x %02x %02x %02x \n", buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
	 printf("type: %02x %02x \n", buf[12], buf[13]);
	 
	 printf("src ip: %d.%d.%d.%d \n", buf[26], buf[27], buf[28], buf[29]);
	 printf("dst ip: %d.%d.%d.%d \n", buf[30], buf[31], buf[32], buf[33]);
	 printf("protocol: %d \n", buf[23]);
	 
    // Get Ethernet header.
    ep = (struct ether_header *)buf;
    // Get upper protocol type.
    ether_type = ntohs(ep->ether_type);
    
    

    if (ether_type == ETHERTYPE_IP) {
        printf("ETHER Source Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Dest Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");

        // Move packet pointer for upper protocol header.
        //packet += sizeof(struct ether_header);
        iph = (struct ip *)(buf+sizeof(struct ether_header));
        printf("IP Ver = %d\n", iph->ip_v);
        printf("IP Header len = %d\n", iph->ip_hl<<2);
        printf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
        printf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
        printf("IP Packet size = %d\n", len-16);
    }
    printf("-----------------------------------\n\n");
}

int create_socket(char *device)
{	int sock_fd;
   struct ifreq ifr;
   struct sockaddr_ll sll;
	memset(&ifr, 0, sizeof(ifr));
   memset(&sll, 0, sizeof(sll));

   sock_fd = socket (PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

   if(sock_fd == 0) { printf("ERR: socket creation for device: %s\n", device); return FALSE; }
   strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
   if(ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) { printf(" ERR: ioctl failed for device: %s\n", device); return FALSE; }
	
	sll.sll_family      = AF_PACKET;
	sll.sll_ifindex     = ifr.ifr_ifindex;
	sll.sll_protocol    = htons(ETH_P_ALL);

	


	if(bind(sock_fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) { printf("ERR: bind failed for device: %s\n", device); return FALSE; }
/*
	if(setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &tcp_filter, sizeof(tcp_filter)) == -1) {
        perror("failed to attach filter");
        close(sock_fd);
        return -1;
    }*/
  return sock_fd;
}


int main(int argc, char *argv[])
{
	char *dev = argv[1];
	printf("Device: %s\n", dev);
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE] ;

handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
if (handle == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	return(2);

}

printf("Starting packet capture with protocol counting...\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    
   
	pcap_close(handle);



if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "Can't get netmask for device %s\n", dev);
	net = 0;
	mask = 0;
}
if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
}
if (pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
}

packet = pcap_next(handle, &header);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
//	pcap_close(handle);
	//return(0);


	ethernet = (struct sniff_ethernet*)(packet);
ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
size_ip = IP_HL(ip)*4;
if (size_ip < 20) {
	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	return 0;
}
tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
size_tcp = TH_OFF(tcp)*4;
if (size_tcp < 20) {
	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
//	return 0;
}
payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
printf("%s",payload);
 /* sock_fd = create_socket(dev);
  if( !(sock_fd) ) { printf("no sock_fd found\n"); return 0; }
  while(1) 
  {  pkt_buf_len=0;
	  pkt_buf_len = read(sock_fd, pkt_buf, MAX_PKT_BUF);
	  if(pkt_buf_len>0) { parse_pkt(pkt_buf, pkt_buf_len); }
  }
  */


	pcap_close(handle);
  return 0;
} 



