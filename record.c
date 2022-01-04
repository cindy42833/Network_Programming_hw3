#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <time.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
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

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
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

/* UDP header */
struct udphdr {
 u_short uh_sport;  /* source port */
 u_short uh_dport;  /* destination port */
 u_short uh_ulen;  /* udp length */
 u_short uh_sum;   /* udp checksum */
};


void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char *timestamp = ctime((const time_t*)&header->ts.tv_sec);
    const struct sniff_ethernet *eth_hdr = (struct sniff_ethernet *)packet;
    
    /* Timestamp */
    *(timestamp + strlen(timestamp) - 1) = '\0';    // remove '\n'
    printf("Timestamp: %s ",timestamp);   
    
    /* Mac Address */
    printf("Src mac: %02x:%02x:%02x:%02x:%02x:%02x ",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("Dst mac: %02x:%02x:%02x:%02x:%02x:%02x ",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    
    /* Ethernet Type */
    int ether_type_no = ntohs(eth_hdr->ether_type);
    char ether_type[32];

    memset(ether_type, 0, sizeof(ether_type));
    switch (ether_type_no) {
        case 0x0800:   // IPv4
            strncpy(ether_type, "IPv4", 4);
            break;
        case 0x86DD:   // IPv6
            strncpy(ether_type, "IPv6", 4);
            break;
        case 0x0806:   // ARP
            strncpy(ether_type, "ARP", 3);
            break;
        default:
            strncpy(ether_type, "Undefined", 9);
            break;
    }
    printf("Type: %s ", ether_type);

    if(strncmp(ether_type, "IPv6", 4) == 0 || strncmp(ether_type, "ARP", 3) == 0 || strncmp(ether_type, "Undefined", 9) == 0) {
        printf("\n");
        return;
    }
    /* IP Adress */
    const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    const int size_ip = (ip->ip_vhl & 0xf) * 4;     // extract the lower 4 bit of the first byte to get ip size
    char src_ip[32], dest_ip[32];

    memset(src_ip, 0, sizeof(src_ip));
    memset(dest_ip, 0, sizeof(dest_ip));

    if(size_ip < 20) {  // check IP header length
        printf("\n");
        fprintf(stderr, "Invalid IP header length: %d bytes\n", size_ip);
	    return;
    }

    inet_ntop(AF_INET, &ip->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->ip_dst, dest_ip, sizeof(dest_ip));
    printf("Src ip: %s ", src_ip);
    printf("Dst ip: %s ", dest_ip);

    int protocol_no = ip->ip_p;
    char protocol[32];

    memset(protocol, 0, sizeof(protocol));
    switch (protocol_no) {
        case 0x06:   // TCP
            strncpy(protocol, "TCP", 3);
            break;
        case 0x11:   // UDP
            strncpy(protocol, "UDP", 3);
            break;
        default:
            strncpy(protocol, "Undefined", 9);
            break;
    }

    if(strncmp(protocol, "Undefined", 9) == 0) {
        printf("\n");
	    return;

    } else if(strncmp(protocol, "TCP", 3) == 0) {
        const struct sniff_tcp *tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        const int size_tcp = ((tcp->th_offx2 & 0xf0) >> 4) * 4;
        
        if (size_tcp < 20) {
            fprintf(stderr, "Invalid TCP header length: %d bytes\n", size_tcp);
            return;
        }   
        printf("Protocol: %s ", protocol);
        printf("Src port: %d ", ntohs(tcp->th_sport));
        printf("Dst port: %d \n", ntohs(tcp->th_dport));
    } 
    else if(strncmp(protocol, "UDP", 3) == 0) {
        const struct udphdr *udp = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip);
        const int size_udp = ntohs(udp->uh_ulen);
        
        if (size_udp < 8) {
            fprintf(stderr, "Invalid UDP header length: %d bytes\n", size_udp);
            return;
        }   

        printf("Protocol: %s ", protocol);
        printf("Src port: %d ", ntohs(udp->uh_sport));
        printf("Dst port: %d \n", ntohs(udp->uh_dport));
    }
    return;
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

    if(pcap_loop(handle, 1000, parse_packet, NULL) < 0) {
        fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
        return 0;
    }
    
    pcap_close(handle);

    return 0;
}