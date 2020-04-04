// PATRAȘ ANTON-FABIAN
// 324CB
// MARTIE 2020

#include "skel.h"
#include <sys/types.h>
#include <sys/stat.h>

#define IP_OFF (sizeof(struct ether_header))
#define ARP_OFF (sizeof(struct ether_header))
#define ARP_MESSAGE_OFF (sizeof(struct ether_header) + sizeof(struct ether_arp))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))
#define ARP_TABLE_CAP 100
#define MAC_LENGTH 6
#define IP_LENGTH 4
#define MAX_TTL 64


struct arp_entry {
	int32_t ip;
	uint8_t mac[MAC_LENGTH];
};


// sould store host bite order addresses
struct arp_entry* init_arp_table() {
	struct arp_entry* arpTable = calloc (ARP_TABLE_CAP, 
										sizeof(struct arp_entry));

	DIE(arpTable == NULL, "calloc arptable");

	return arpTable;
}

// size has to be no of crt entries
// returns 0 on succes
// returns -1 of the IP Address has no associated entry
int search_arp_entry(struct arp_entry* arpTable, 
					 int size, 
					 struct arp_entry* arpEntry, 
					 int32_t ip) {

	int i;
	for (i = 0; i < size; i++) {
		if((arpTable + i)->ip == ip) {
			memcpy(arpEntry, arpTable + i, sizeof(struct arp_entry));
			return 0;
		}
	}
	return -1;

}

// adds an arp entry to the arp table
// return 0 on succes
int add_arp_entry(struct arp_entry* arpTable, 
				  int* size, 
				  int32_t ip, 
				  uint8_t* mac) {

	DIE((*size >= ARP_TABLE_CAP), "size arp table");

	struct arp_entry aux;

	aux.ip = ip;
	//printf("~~~~~seg~~~~\n");
	memcpy(&(aux.mac), mac, MAC_LENGTH);

	memcpy((arpTable + *size), &aux, sizeof(struct arp_entry));
	
	(*size)++;

	return 0;
}


// generates in reply an arp request for ip
// which is to be sent on interface interface
// should work all the time xdddd
int generate_arp_request(int interface, 
						 uint32_t ip, 
						 packet* reply) {

	reply->len = ARP_MESSAGE_OFF;

	struct ether_header *eth_hdr = (struct ether_header *)reply->payload;
	struct ether_arp* reply_ether_arp_header = (struct ether_arp *)
										((reply->payload) + ARP_OFF);
	// broadcast mac NBO/HBO
	uint8_t b_mac[] = {255, 255, 255, 255, 255, 255};
	uint8_t mac[MAC_LENGTH];

	// mac of the interface
	get_interface_mac(interface, mac);

	// ip of interface
	struct in_addr addr;
	inet_aton(get_interface_ip(interface), &addr);
	uint32_t s_ip = addr.s_addr;

	// ethernet header
	memcpy(eth_hdr->ether_shost, mac, MAC_LENGTH);
	memcpy(eth_hdr->ether_dhost, b_mac, MAC_LENGTH);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// arp header
	reply_ether_arp_header->arp_hrd = htons(ARPHRD_ETHER); // Ethernet
	reply_ether_arp_header->arp_pro = htons(ETHERTYPE_IP); // IPv4
	reply_ether_arp_header->arp_hln = MAC_LENGTH; // 
	reply_ether_arp_header->arp_pln = IP_LENGTH; //
	reply_ether_arp_header->arp_op = htons(ARPOP_REQUEST); // ARP code

	memcpy(reply_ether_arp_header->arp_sha, mac, MAC_LENGTH); // s mac
	memset(reply_ether_arp_header->arp_tha, 0, MAC_LENGTH);
	memcpy(reply_ether_arp_header->arp_spa, &s_ip, sizeof(uint32_t)); // s ip
	memcpy(reply_ether_arp_header->arp_tpa, &ip, sizeof(uint32_t)); //

	return 0;
}


// return 0 on succes
// idk when it fails? 
// "returns" the reply packet based on what if found on 
// packet m
// it should be called with m - the packet whom to respond to
// it does not send the packet
int generate_arp_reply(packet m, packet* reply) {

	// copy from source packet
	memcpy(reply, &m, sizeof(packet));

	// source headers
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct ether_arp* ether_arp_header = (struct ether_arp *)
										 (m.payload + ARP_OFF);

	// getting the interface mac
	uint8_t mac[MAC_LENGTH];
	get_interface_mac(m.interface, mac);

	// reply headers
	struct ether_header *reply_eth_hdr = (struct ether_header *)
										(reply->payload);
	struct ether_arp* reply_ether_arp_header = (struct ether_arp *)
										((reply->payload) + ARP_OFF);

	// setting the packet

	// ether header
	memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LENGTH);
	memcpy(reply_eth_hdr->ether_shost, mac, MAC_LENGTH);
	reply_eth_hdr->ether_type = eth_hdr->ether_type;

	// arp header
	memcpy(reply_ether_arp_header->arp_sha,
		   &mac, MAC_LENGTH);
	memcpy(reply_ether_arp_header->arp_tha,
		   ether_arp_header->arp_sha, MAC_LENGTH);
	memcpy(reply_ether_arp_header->arp_spa,
		   ether_arp_header->arp_tpa, IP_LENGTH);
	memcpy(reply_ether_arp_header->arp_tpa,
		   ether_arp_header->arp_spa, IP_LENGTH);

	reply_ether_arp_header->arp_op = htons(ARPOP_REPLY);

	return 0;

}

// return 0 on succes
// dies on error
// "returns" the ip associated with the interface
// in uint32_t format in NETWORK BYTE ORDER
// working
uint32_t get_ip_uint32(int interface, int* ip) {
	char* ip_char;
	ip_char = get_interface_ip(interface);

	int rc = 0;
	struct in_addr in;
	rc = inet_aton(ip_char, &in);
	DIE(rc == -1, "get_ip");
	*ip = in.s_addr;
	return 0;
}



// returns 4 on succes, forward, ready to be sent
// returns 3 on succes, host_unreachable
// returns 2 on succes, ttl
// returns 1 on succes, ICMP_REPLY 
// returns 0 on succes, forward, but has to wait for arp
// returns -1 on some kind of failure
// wrong checksum is a failure so the router
// drops the packet
int forward_packet(packet* m, 
				   packet* reply, 
				   TNode* rt, 
				   struct arp_entry* arpt,
				   queue q,
				   int arp_size) {


	// headere packet primit
	struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct ip* ip_hdr = (struct ip*) (m->payload + IP_OFF);
	//struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + ICMP_OFF);
	// headere packet care trb trimis
	struct ether_header* r_eth_hdr = (struct ether_header *)reply->payload;
	struct ip* r_ip_hdr = (struct ip*) (reply->payload + IP_OFF);
	struct icmphdr* r_icmp_hdr = (struct icmphdr *)(reply->payload + ICMP_OFF);

	uint16_t check = ip_checksum((void*)ip_hdr, sizeof(struct ip));
	if (check != 0) {
		return -1;
	}

	memcpy(reply, m, sizeof(packet));
	reply->len = m->len;

	// daca e pt mine
	int my_ip;
	get_ip_uint32(m->interface, &my_ip);
	
	uint8_t mac[MAC_LENGTH];
	get_interface_mac(m->interface, mac);


	if(r_ip_hdr->ip_dst.s_addr == my_ip) {

		memcpy(r_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LENGTH);
		memcpy(r_eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_LENGTH);
		
		// ip hdr
		r_ip_hdr->ip_ttl = MAX_TTL;
		r_ip_hdr->ip_sum = 0;
		struct in_addr swap;
		memcpy(&swap, &(r_ip_hdr->ip_src), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_src), &(r_ip_hdr->ip_dst), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_dst), &swap, sizeof(struct in_addr));
		r_ip_hdr->ip_sum = ip_checksum(r_ip_hdr, sizeof(struct ip));

		// icmp hdr
		r_icmp_hdr->type = ICMP_ECHOREPLY;
		r_icmp_hdr->code = 0;
		r_icmp_hdr->checksum = 0;
		r_icmp_hdr->checksum = ip_checksum(r_icmp_hdr, sizeof(struct icmphdr));
		return 1;
	}

	if(r_ip_hdr->ip_ttl == 1) {
		
		reply->len = ICMP_OFF + sizeof(struct icmphdr);

		// ether hdr
		memcpy(r_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LENGTH);
		memcpy(r_eth_hdr->ether_shost, mac, MAC_LENGTH);

		// ip hdr
		struct in_addr swap;
		r_ip_hdr->ip_v = IP_LENGTH;
		r_ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr));
		r_ip_hdr->ip_p = 1;
		r_ip_hdr->ip_ttl = MAX_TTL;
		r_ip_hdr->ip_tos = 0;
		memcpy(&swap, &(r_ip_hdr->ip_src), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_src), &(r_ip_hdr->ip_dst), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_dst), &swap, sizeof(struct in_addr));
		r_ip_hdr->ip_sum = 0;
		r_ip_hdr->ip_sum = ip_checksum(r_ip_hdr, sizeof(struct ip));

		// icmp hdr
		r_icmp_hdr->type = ICMP_TIME_EXCEEDED;
		r_icmp_hdr->code = 0;
		r_icmp_hdr->checksum = 0;
		r_icmp_hdr->checksum = ip_checksum(r_icmp_hdr, sizeof(struct icmphdr));
		return 2;
	}

	uint32_t next_hop;
	int interface;
	int err_s;
	err_s = search_trie(rt, ip_hdr->ip_dst.s_addr, &next_hop, &interface);

	// host unreachable
	if(err_s == -1) {
		reply->len = ICMP_OFF + sizeof(struct icmphdr);

		// ether hdr
		memcpy(r_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LENGTH);
		memcpy(r_eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_LENGTH);
		
		// ip hdr
		r_ip_hdr->ip_p = 1;
		r_ip_hdr->ip_ttl = MAX_TTL;
		r_ip_hdr->ip_sum = 0;
		r_ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr));

		struct in_addr swap;
		memcpy(&swap, &(r_ip_hdr->ip_src), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_src), &(r_ip_hdr->ip_dst), sizeof(struct in_addr));
		memcpy(&(r_ip_hdr->ip_dst), &swap, sizeof(struct in_addr));
		r_ip_hdr->ip_sum = ip_checksum(r_ip_hdr, sizeof(struct ip));

		// icmp hdr
		r_icmp_hdr->type = 3;
		r_icmp_hdr->code = 0;
		r_icmp_hdr->checksum = 0;
		r_icmp_hdr->checksum = ip_checksum(r_icmp_hdr, sizeof(struct icmphdr));
		return 3;
	} 

	struct arp_entry arp_entry;

	int err_a;
	err_a = search_arp_entry(arpt, arp_size, &arp_entry, next_hop);

	if(err_a == -1) {
		// print
		// insert in queue
		packet* p = (packet*) calloc(1, sizeof(packet));
		DIE(p == NULL, "calloc p");
		memcpy(p, m, sizeof(packet));
		queue_enq(q, p);

		// generate and send arp request
		packet request;

		generate_arp_request(interface, next_hop, &request);
		send_packet(interface, &request);

		return 0;
	}

	// usual forward

	uint8_t mac2[MAC_LENGTH];
	get_interface_mac(interface, mac2);

	// ip header
	reply->interface = interface;

	// checksum update via incremental updates
	// as stated in RFC1624   [Eqn. 4]

	// acest "-" e pe aritmetica lui 2
	// iar ca sa compensez sa fie pe aritmetica lui 1
	// scad inainte sa neg bitii, ca atunci cand se 
	// efectueaza scaderea pe complementul lui 2 (adunare cu negat + 1)
	// 1 se duce cu 1 si face doar adunare cu negatu -> scaderea pe
	// complementul lui 1
	// suma e pe 16 bits, ttl pe 8, nu ma intereseaza ceilalti 8 
	// pentru ca nu se schimba (nu ar trebui sa-i schimb la o simpla forwardare)
	r_ip_hdr->ip_sum -= ~(r_ip_hdr->ip_ttl - 1);
	r_ip_hdr->ip_ttl --;
	r_ip_hdr->ip_sum -= r_ip_hdr->ip_ttl;


	// ether hdr
	memcpy(r_eth_hdr->ether_shost, mac2, MAC_LENGTH);
	memcpy(r_eth_hdr->ether_dhost, arp_entry.mac, MAC_LENGTH);
	return 4;
}


int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;


	int rt_size = 0;

	TNode* rt = parse_routing_table_trie(&rt_size);
	
	// initializing the arp table
	struct arp_entry* arpt = init_arp_table();
	// arp table currentyl holds 0 entries
	int arpt_size = 0;

	// init 
	init();

	queue q = queue_create();

	int my_ip[4];
	int i;
	for(i = 0; i < 4; i++) {
		get_ip_uint32(i, my_ip + i);
	}


	while (1) {
		rc = get_packet(&m);

		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct ether_arp* ether_arp_header = 
			(struct ether_arp *)(m.payload + ARP_OFF);


			// ARP request is detected
			if(ntohs(ether_arp_header->arp_op) == ARPOP_REQUEST) {

				// testing to see if arp req is for me
				uint32_t ip;
				memcpy(&ip, ether_arp_header->arp_tpa, sizeof(uint32_t));
				if(ip == my_ip[m.interface]) {
					// reply to arp req
					uint32_t s_ip;
					memcpy(&s_ip, ether_arp_header->arp_spa, sizeof(uint32_t));
					packet reply;
					generate_arp_reply(m, &reply);
					send_packet(m.interface, &reply);
				} else {
					DIE(1, "IDK man");
				}				

			} else if (ntohs(ether_arp_header->arp_op) == ARPOP_REPLY) {
				// add entry to arp_table
				uint32_t ip;
				memcpy(&ip, ether_arp_header->arp_spa, sizeof(uint32_t));
				struct arp_entry result;
				int ec;
				ec = search_arp_entry(arpt, arpt_size, &result, ip);
				if(ec == -1) {
					add_arp_entry(arpt, &arpt_size, ip, ether_arp_header->arp_sha);
				} else {
					DIE(1, "IDK man");
				}
				if(!queue_empty(q)) {
					packet* p2;
					p2 = (packet*) queue_deq(q);
					packet repl;
					int err_s;
					err_s = forward_packet(p2, &repl, rt, arpt, q, arpt_size);
					if(err_s == 4) {
						send_packet(repl.interface, &repl);
					} else {
						DIE(1, "IDK man");
					}
				}
			}

		// IP is detected
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			packet repl;
			int fw;
			fw = forward_packet(&m, &repl, rt, arpt, q, arpt_size); // ???
			/*if (fw == -1) {
				//continue;
			} else if (fw == 1 || fw == 2 || fw == 3 || fw == 4) {
				send_packet(repl.interface, &repl);
				//continue;
			} else if (fw == 0) {
				//continue;
			}*/
			if(fw != -1 && fw != 0) {
				send_packet(repl.interface, &repl);
			}
		}
	}
}
