#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "pcap_handle.h"

int send_arp(MAC s_mac, uint32_t s_ip, MAC t_mac, uint32_t t_ip, int op){
	
	// make ARP packet
	u_char* packet = (u_char*)malloc(0xC + 0x24);

	// build ethernet header
	Eth_header eth;
	memcpy(&(eth.dst_mac), &t_mac, 6);
	memcpy(&(eth.src_mac), &s_mac, 6);
	eth.ether_type = htons(ETHERTYPE_ARP);

	// build ARP header
	ARP_header arp;
	arp.hardware_type = 1;
	arp.protocol_type = htons(0x8000);
	arp.hw_addr_len = 6;
	arp.protocol_addr_len = 4;
	arp.opcode = op;
	memcpy(&(arp.sender_mac), &s_mac, 6);
	arp.sender_addr = s_ip;
	if(op == ARPOP_REQUEST)
		memset(&(arp.target_addr), 0, 6);
	else
		memcpy(&(arp.target_mac), &t_mac, 6);
	arp.target_addr = t_ip;

	// copy headers to the packet
	memcpy(packet, &eth, 0xC);
	memcpy(packet + 0xC, &arp, 0x24);

	// send packet


	return 0;
}

void print_MAC(const char* label, MAC mac){
	printf("%s : %02x:%02x:%02x:%02x:%02x:%02x\n", label,
		mac.i[0], mac.i[1], mac.i[2], mac.i[3], mac.i[4], mac.i[5]);
}

void print_IP(const char* label, uint32_t ip){
	printf("%s : %d.%d.%d.%d\n", label,
		(ip & 0xFF000000) >> 24,
		(ip & 0x00FF0000) >> 16,
		(ip & 0x0000FF00) >> 8,
		(ip & 0x000000FF));
}

void str_to_ip(char* ip_str, uint32_t* out){
	int i, st;
	int j = -1;
	uint8_t ip_arr[4];
	for(i = 0; i < 4; i++){
		st = j + 1;
		for(j = i; ip_str[j] != '.' && ip_str[j] != '\x00'; j++);
		ip_str[j] = '\x00';
		ip_arr[i] = atoi(ip_str + st);
	}
	memcpy(out, ip_arr, 4);
}