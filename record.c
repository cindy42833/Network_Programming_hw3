#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <time.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char *timestamp = ctime((const time_t*)&header->ts.tv_sec);
    const struct sniff_ethernet *eth_hdr = (struct sniff_ethernet *)packet;
    
    /* Timestamp */
    *(timestamp + strlen(timestamp) - 1) = '\0';    // remove '\n'
    printf("Timestamp: %s ",timestamp);   
    
    /* Mac Address */
    printf("Dest mac address: %02x:%02x:%02x:%02x:%02x:%02x ",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    printf("Src mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    /* Ethernet Type */
    printf("Type: %x", ntohs(eth_hdr->ether_type));
}

int main(int argc, char **argv) {
    char *filename;
    char errbuf[1024];
    pcap_t *handle = NULL;
    // struct pcap_pkthdr header;
    const u_char *packet;


    if(argc < 2) {  // lack of argument 
        fprintf(stderr, "Invalid Format: ./record <pcap_filename>\n");
        return 0;
    }

    filename = argv[1]; // assign pcap filename

    if((handle = pcap_open_offline(filename, errbuf)) == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", errbuf);
        return 0;
    }

    if(pcap_loop(handle, 10, parse_packet, NULL) < 0) {
        fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
        return 0;
    }
    
    pcap_close(handle);

    return 0;
}