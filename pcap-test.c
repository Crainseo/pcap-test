#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

#define ETHER_ADDR_LEN 6
struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

void print_mac(uint8_t *m){
   printf("%02x-%02x-%02x-%02x-%02x-%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_packet_info(const uint8_t* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
    printf("Source MAC: ");
    print_mac(eth_hdr->ether_shost);
    printf("\n");
    printf("Destination MAC: ");
    print_mac(eth_hdr->ether_dhost);
    printf("\n");

    if (ntohs(eth_hdr->ether_type) == 0x0800) { // IPv4
        const uint8_t* ip_hdr = packet + sizeof(struct libnet_ethernet_hdr);
        printf("Source IP: %d.%d.%d.%d\n", ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);
        printf("Destination IP: %d.%d.%d.%d\n", ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]);

        if (ip_hdr[9] == 6) { // TCP
            const uint8_t* tcp_hdr = ip_hdr + ((ip_hdr[0] & 0x0F) * 4);
            printf("Source Port: %u\n", (tcp_hdr[0] << 8) | tcp_hdr[1]);
            printf("Destination Port: %u\n", (tcp_hdr[2] << 8) | tcp_hdr[3]);

            int payload_len = packet[16 + ((ip_hdr[0] & 0x0F) * 4) + ((tcp_hdr[12] >> 4) * 4) + 2] - ((ip_hdr[0] & 0x0F) * 4) - ((tcp_hdr[12] >> 4) * 4);
            if (payload_len > 0) {
                printf("Payload: ");
                for (int i = 0; i < 10 && i < payload_len; i++) {
                    printf("%02x ", tcp_hdr[4 + ((tcp_hdr[12] >> 4) * 4) + i]);
                }
                printf("\n");
            }
        }
    }

    printf("\n");
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr header;
      const uint8_t* packet;
      packet = pcap_next(pcap, &header);
      if (packet == NULL) continue;

      printf("%u bytes captured\n", header.caplen);
      print_packet_info(packet);
   }

   pcap_close(pcap);
   return 0;
}
