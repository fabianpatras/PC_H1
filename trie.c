// PATRAȘ ANTON-FABIAN
// 324CB
// MARTIE 2020

#include "trie.h"

TNode* new_node() {
	TNode* node = (TNode*) calloc(1, sizeof(TNode));
	if(!node) {
		printf("calloc fail\n");
		return NULL;
	}

	node->left = NULL;
	node->right = NULL;
	node->end_of_ip = 0;
	node->next_hop = 0; //NBO
	node->interface = 0;

	return node;
}


TNode* init_trie() {
	TNode* root = new_node();

	return root;
}

int add_entry (TNode* root, uint32_t ip, uint32_t mask_len, uint32_t next_hop, uint32_t interface) {
	TNode* crt = root;
	ip = ntohl(ip);
	uint32_t bit;
	for(int i = 0; i < mask_len; i++) {
		bit = 1UL << (31 - i);
		if(ip & bit) {
			if(crt->right == NULL) {
				crt->right = new_node();
				if(crt->right == NULL) {
					return -1;
				}
			}
			crt = crt->right;
		} else {
			if(crt->left == NULL) {
				crt->left = new_node();
				if(crt->left == NULL) {
					return -1;
				}

			}
			crt = crt->left;
		}
	}
	crt->end_of_ip = 1;
	crt->interface = interface;
	crt->next_hop = next_hop;

	return 0;
}

struct trie_node* parse_routing_table_trie(int* size) {
	FILE* rtable = fopen("rtable.txt", "r");
	int count = 0;
	char c;
	for(c = getc(rtable); c!= EOF; c = getc(rtable)) {
		if(c == '\n') {
			count++;
		}
	}
	fclose(rtable);

	TNode* root = init_trie();

	rtable = fopen("rtable.txt", "r");

	int i = 0;
	char buffer[100];
	char* pch;

	struct in_addr aux1;

	uint32_t ip;
	uint32_t next_hop;
	uint32_t mask_len;
	int interface;

	for(i = 0; i < count; i++) {
		fgets(buffer, 46, rtable);
		// split the line
		pch = strtok (buffer," ");
		inet_aton(pch, &aux1);
		ip = aux1.s_addr;

		pch = strtok (NULL, " ");
		inet_aton(pch, &aux1);
		next_hop = aux1.s_addr;

		pch = strtok (NULL, " ");
		inet_aton(pch, &aux1);
		// counts the set bits of the mask
		// that means the length of the mask
		mask_len = __builtin_popcount(aux1.s_addr);
		
		pch = strtok (NULL, " ");
		interface = atoi(pch);
		add_entry(root, ip, mask_len, next_hop, interface);
	}

	*size = count;
	return root;
}


int search_trie(TNode* root, uint32_t ip, uint32_t* next_hop, int* interface) {
	TNode* crt = root;
	int found = -1;
	uint32_t bit;
	ip = ntohl(ip);
	for(int i = 0; i < 32; i++) {
		if (crt->end_of_ip == 1) {
			found = 0;
			*next_hop = crt->next_hop;
			*interface = crt->interface;
		}
		bit = 1UL << (31 - i);
		if(ip & bit) {
			if(crt->right == NULL) {
				break;
			} else {
				crt = crt->right;
			}
		} else {
			if(crt->left == NULL) {
				break;
			} else {
				crt = crt->left;
			}
		}
	}
	return found;
}