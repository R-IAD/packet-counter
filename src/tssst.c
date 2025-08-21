#include "../include/packet_parser.h"
packet_stats received_packet;

received_packet.tcp_count=15;



/***** Session Handle ********/
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
struct bpf_program fp;          /* The compiled filter expression */
char dev[] = "";                /* Interface name */
char filter_exp[] = "";      /* The filter expression */
bpf_u_int32 mask;               /* The netmask of our sniffing device */
bpf_u_int32 net;                /* The IP of our sniffing device */
struct pcap_pkthdr header;      /* The header that pcap gives us */
const u_char *packet;           /* The actual packet */




void process_packet (const u_char *packet, packet_stats_t * stats)
{

char errbuf[PCAP_ERRBUF_SIZE] ;

handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, BYTES_MAX_NUM , errbuf);

if (handle == NULL)
{
 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
}


packet = pcap_next(handle, &header);

switch (get_packet_protocol("tcp"))
{
        case TCP_p: stats.tcp_count=header.len;break;
        case UDP_p: stats.udp_count=header.len;break;
        case ICMP_p: stats.icmp_count=header.len;break;
        default: stats.other_count=header.len;break;

}


}









int get_packet_protocol(const u_char *packet)
{
filter_exp = packet;
if ( strcmp(packet,"tcp")==0)
        return TCP_p;
else if ( strcmp(packet,"UDP")==0)
        return UDP_p;
else if ( strcmp(packet,"icmp")==0)
        return ICMP_p;
else
        return 0;
}



void print_stats(const packet_stats_t * stats)
{


        printf(" a packet with length of [%d]\n", stats.tcp_count);
        /* And close the session */
        pcap_close(handle);
        return(0);


}




void main (void){
printf("%d",received_packet.tcp_count);
dev="enp0s3";
process_packet(packet,&received_packet);
print_stats(&received_packet);

}



