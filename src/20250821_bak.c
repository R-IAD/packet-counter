#include "../include/packet_parser.h"


packet_stats_t received_packet;




int total_count;



/***** Session Handle ********/
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
struct bpf_program fp;          /* The compiled filter expression */
char dev[] = "enp0s3";                /* Interface name */
char filter_exp[] = "udp";      /* The filter expression */
bpf_u_int32 mask;               /* The netmask of our sniffing device */
bpf_u_int32 net;                /* The IP of our sniffing device */
struct pcap_pkthdr header;      /* The header that pcap gives us */
const u_char *packet;           /* The actual packet */





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


/*
switch (get_packet_protocol("tcp"))
{
	case TCP_p: stats->tcp_count=header.len;break;
	case UDP_p: stats->udp_count=header.len;break;
	case ICMP_p: stats->icmp_count=header.len;break;
	default: stats->other_count=header.len;break;

}
*/

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
        int size_tcp;

//        printf("\nPacket number %d:\n", count);
//        count++;

        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);

        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return 127;
        }
        /* determine protocol */
        switch(ip->ip_p) {
                case IPPROTO_TCP:
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
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return 127;
        }
return 0;

}









void print_stats(const packet_stats_t * stats)
{


	
printf("   Protocol: TCP %d\n",received_packet.tcp_count);
printf("   Protocol: UDP %d\n",received_packet.udp_count);
printf("   Protocol: ICMP %d\n",received_packet.icmp_count);
printf("   Protocol: UNKNOWN %d\n",received_packet.other_count);


	/* And close the session */
//        pcap_close(handle);
        


}




void main (void){


packet_stats_t * ptr = &received_packet;
process_packet(packet,ptr);
print_stats(ptr);    


}
