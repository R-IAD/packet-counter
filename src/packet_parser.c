#include "../include/packet_parser.h"


static packet_stats_t received_packet;
packet_stats_t * ptr = &received_packet;


int _Time=5;
static int total_count;



/***** Session Handle ********/
pcap_t *handle;
//static char errbuf[PCAP_ERRBUF_SIZE]={0};  /* Error string */
static struct bpf_program fp;          /* The compiled filter expression */
char dev[] = "";                /* Interface name */
char filter_exp[] = "ip";      /* The filter expression */
//bpf_u_int32 mask;               /* The netmask of our sniffing device */
static bpf_u_int32 net;                /* The IP of our sniffing device */
//static struct pcap_pkthdr header;      /* The header that pcap gives us */
const u_char *packet;           /* The actual packet */


	/********* Static Functions ***********/

static int validate_tcp_header(const struct sniff_tcp* tcp) {
    // Get TCP header length
    int size_tcp = TH_OFF(tcp)*4;
    
    // Basic length validation
    if (size_tcp < 20 || size_tcp > 60) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 127;
    }
    
    return 0;
}

static int validate_ip_header(const struct sniff_ip* ip ,   int size_ip) {
    

    // Basic and Max length validation
    if (size_ip < 20 || size_ip > 60) {
        printf("   * Invalid IP header length: %u bytes (\n", size_ip);
        return 127;
    }

    // check IP version 4
    if (IP_V(ip) != 4) {
        printf("   * Invalid IP version: %u (expected 4)\n", IP_V(ip));
        return 127;
    }

    return 0; 
}




static void _packet_counter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	    (void)args;     // Silence unused parameter warning
	    (void)header;        
        process_packet(packet,ptr);
        total_count++;

}


	/************* User Function *******************/

/* Timer periodic function */
void timer_handler(int sig) {
    
	(void)sig;
	print_stats(ptr);
    	reset_counters(ptr);
}





void reset_counters(packet_stats_t * stats)
{
	stats->tcp_count=0;
	stats->udp_count=0;
	stats->icmp_count=0;
	stats->other_count=0;
	total_count=0;
}



void process_packet (const u_char *packet, packet_stats_t * stats)
{
        /* declare pointers to packet headers */
 //       const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;

        /* define packet headers */
        //ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	/* Validate IP header */
        if (validate_ip_header(ip,size_ip))return;
        
	
	/* determine protocol */
        switch(ip->ip_p) {
                case IPPROTO_TCP:
			if(validate_tcp_header(tcp))return; // Validate TCP header
                        stats->tcp_count++; break;
                case IPPROTO_UDP:
                        stats->udp_count++; break;
                case IPPROTO_ICMP:
                        stats->icmp_count++; break;
                default:
                        stats->other_count++; break;
        }
      


}









int get_packet_protocol(const u_char *packet)
{
	(void)packet;
        char errbuf[PCAP_ERRBUF_SIZE] ;

	/* open capture device */
	handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, TIME_OUT , errbuf);
        if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
        }
	
	
	/* compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }


        /* now we can set our callback function */
        pcap_loop(handle, -1 , _packet_counter, NULL);




        /* cleanup */
        pcap_freecode(&fp);

        return 0;
}









void print_stats(const packet_stats_t * stats)
{
	/* Print the results */
	printf("/**********************************/\n\n");
	printf("   Total TCP   Packets :  %d\n",stats->tcp_count);
	printf("   Total UDP   Packets :  %d\n",stats->udp_count);
	printf("   Total ICMP  Packets :  %d\n",stats->icmp_count);
	printf("   Total other Packets :  %d\n",stats->other_count);
	printf("   Total Packets       :  %d\n\n",total_count);
	printf("/**********************************/\n\n");
}



/*
void main (void){



get_packet_protocol(packet);
print_stats(ptr);    


}*/
