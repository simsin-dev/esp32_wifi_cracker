#include "targeting.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool check_if_target_on_list(attack_target_t* target);

typedef struct target_ll {
	attack_target_t target;
	struct target_ll* next_target;
} target_ll;


target_ll* target_list = NULL;
target_ll* target_last = NULL;

target_ll* cracked_list = NULL;
target_ll* cracked_last = NULL;

void add_target(attack_target_t* target) {
	if(check_if_target_on_list(target)) return;

	target_ll* target_p = malloc(sizeof(target_ll));
	memcpy(&target_p->target, target, sizeof(attack_target_t));
	target_p->next_target = NULL;

	if(target_list == NULL) {
		target_list = target_p;
		target_last = target_p;
	} else {
		target_last->next_target = target_p;
		target_last = target_p;
	}
}

target_ll* current_target = NULL;
attack_target_t* get_next_target() {
	if(target_list == NULL) return NULL;

	target_ll* target_p = current_target == NULL ? target_list : current_target->next_target;
	while (target_p != NULL) {
		if(!target_p->target.cracked) {
			current_target = target_p;
			return &target_p->target;
		};

		target_p = target_p->next_target;
	}

	current_target=NULL;
	return NULL;
}

void set_current_target_cracked(char* hash) {
	current_target->target.cracked = true;
	current_target->target.hash = hash;
	current_target->next_target = NULL;

	if(cracked_list == NULL) {
		cracked_list = current_target;
		cracked_last = current_target;
	} else {
		cracked_last->next_target = current_target;
		cracked_last = current_target;
	}

	//remove from target list
	if(current_target == target_list) { //first element
		target_list = current_target->next_target;
		return;
	}

	target_ll* target_p = target_list;
	while(true) {
		if(target_p->next_target == current_target) {
			target_p->next_target = current_target->next_target;
			printf("Removed\n");
			return;
		}

		target_p = target_p->next_target;
	}
}

bool check_if_target_on_list(attack_target_t* target) {
	target_ll* target_p = target_list;
	while(target_p != NULL) {
		if(memcmp(target_p->target.bssid, target->bssid, 6) == 0) return true;
		target_p = target_p->next_target;
	}

	target_p = cracked_list;
	while(target_p != NULL) {
		if(memcmp(target_p->target.bssid, target->bssid, 6) == 0) return true;
		target_p = target_p->next_target;
	}
	return false;
}

int get_cracked_hashes_len() {
	int length = 0;
	target_ll* target_p = cracked_list;
	while(target_p != NULL) {
		length += strlen(target_p->target.hash);

		target_p = target_p->next_target;
	}

	return length;
}

void get_cracked_hashes(char* out, int out_length) {
	int length = 0;
	target_ll* target_p = cracked_list;
	while(target_p != NULL) {
		int current_length = strlen(target_p->target.hash);

		memcpy(out+length, target_p->target.hash, current_length);

		length += current_length;

		target_p = target_p->next_target;
	}
}
