#include "../include/packet_parser.h"


packet_stats_t received_packet;




int total_count;



/***** Session Handle ********/
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
struct bpf_program fp;          /* The compiled filter expression */
char dev[] = "enp0s3";                /* Interface name */
char filter_exp[] = "tcp";      /* The filter expression */
bpf_u_int32 mask;               /* The netmask of our sniffing device */
bpf_u_int32 net;                /* The IP of our sniffing device */
struct pcap_pkthdr header;      /* The header that pcap gives us */
const u_char *packet;           /* The actual packet */



int validate_tcp_header(const struct sniff_tcp* tcp) {
    // Get TCP header length
    int size_tcp = TH_OFF(tcp)*4;
    
    // Basic length validation
    if (size_tcp < 20 || size_tcp > 60) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 127;
    }
    
    return 0;
}

int validate_ip_header(const struct sniff_ip* ip ,   int size_ip) {
    

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




void packet_counter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
        switch(get_packet_protocol(packet)) {
                case TCP_p:
                        received_packet.tcp_count++;
                        break;
                case UDP_p:
                        received_packet.udp_count++;
                        break;
                case ICMP_p:
                        received_packet.icmp_count++;
                        break;
                default:
                        received_packet.other_count++;
                        break;
        }
total_count++;

}



void process_packet (const u_char *packet, packet_stats_t * stats)
{

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

//packet = pcap_next(handle, &header);


/* now we can set our callback function */
pcap_loop(handle, 200 , packet_counter, NULL);




        /* cleanup */
        pcap_freecode(&fp);
        pcap_close(handle);


}









int get_packet_protocol(const u_char *packet)
{
        
        /* declare pointers to packet headers */
        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;

        /* define packet headers */
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	/* Validate IP header */
        if (validate_ip_header(ip,size_ip))return 127;
        
	
	/* determine protocol */
        switch(ip->ip_p) {
                case IPPROTO_TCP:
			if(validate_tcp_header(tcp))return 127; // Validate TCP header
                        printf("   Protocol: TCP %d\n",received_packet.tcp_count);
                        return TCP_p;
                case IPPROTO_UDP:
                        printf("   Protocol: UDP %d\n",received_packet.udp_count);
                        return UDP_p;
                case IPPROTO_ICMP:
                        printf("   Protocol: ICMP %d\n",received_packet.icmp_count);
                        return ICMP_p;
                default:
                        printf("   Protocol: unknown %d\n",received_packet.other_count);
                        return OTHER_p;
        }
      
return 0;

}









void print_stats(const packet_stats_t * stats)
{
	/* Print the results */
	printf("   Protocol: TCP %d\n",stats->tcp_count);
	printf("   Protocol: UDP %d\n",stats->udp_count);
	printf("   Protocol: ICMP %d\n",stats->icmp_count);
	printf("   Protocol: UNKNOWN %d\n",stats->other_count);
}




void main (void){


packet_stats_t * ptr = &received_packet;
process_packet(packet,ptr);
print_stats(ptr);    


}
