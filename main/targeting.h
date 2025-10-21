#ifndef ATTACK_TARGETING
#define ATTACK_TARGETING

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	char ssid[33];
	uint8_t bssid[6];
	uint8_t primary_channel;
	bool cracked;
	char* hash;
} attack_target_t;


void add_target(attack_target_t* target);

attack_target_t* get_next_target();

void set_current_target_cracked(char* hash); 


int get_cracked_hashes_len();
void get_cracked_hashes(char* out, int out_length);
#endif
