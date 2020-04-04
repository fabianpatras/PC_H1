// PATRAȘ ANTON-FABIAN
// 324CB
// MARTIE 2020

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef TRIE_H
#define TRIE_H


typedef struct __attribute__((__packed__)) trie_node{
	struct trie_node* left; // 0
	struct trie_node* right; // 1
	int end_of_ip;
	uint32_t next_hop; //NBO
	int interface;
} TNode;

// initiating the trie
extern TNode* init_trie();
// return an empty new trie nod
extern TNode* new_node();
// reads the rtable.txt file and contructs a trie
// based on that information
// returns the trie
extern struct trie_node* parse_routing_table_trie(int* size);
// adds and entry to the "root" trie
extern int add_entry (TNode* root, uint32_t ip, uint32_t mask_len, uint32_t next_hop, uint32_t interface);
// searches for an ip
// return 0 on succes
// return -1 on failure
extern int search_trie(TNode* root, uint32_t ip, uint32_t* next_hop, int* interface);
#endif
