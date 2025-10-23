#ifndef WIFI_H
#define WIFI_H
#include "esp_wifi_types_generic.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <stdint.h>


void wifi_init();

void wifi_scan();

void wifi_promisc_on_channel(uint8_t channel, wifi_promiscuous_cb_t callback_func); 

void wifi_promisc_off();

void deauth_ap(uint8_t bssid[6], int iterations); 

void sniff_eapol(uint8_t channel, char ssid[], uint8_t bssid[6]);

void uint8_to_hex_string(const uint8_t arr[], size_t len, char *out, size_t out_size) {
    size_t offset = 0;
    for (size_t i = 0; i < len; i++) {
        offset += snprintf(out + offset, out_size - offset, "%02x", arr[i]);
    }
}

typedef enum eapol_info{
	EAPOL_START_30,
	EAPOL_START_32,
	EAPOL_NONE
} eapol_info;

typedef enum frame_direction{
	TO_CLIENT,
	TO_AP
} frame_direction;

typedef struct eapol_frame_t{
	uint8_t message_number;
	uint8_t mac_to[6];
	uint8_t mac_from[6];
	uint8_t* nonce;
	uint8_t* mic;
	uint16_t full_eapol_length;
	uint8_t* full_eapol_packet;
} eapol_frame_t;

typedef enum eapol_message_pair {
	M1_M2,
	M1_M4,
	M2_M3,
	M3_M4
} eapol_message_pair;

#endif
