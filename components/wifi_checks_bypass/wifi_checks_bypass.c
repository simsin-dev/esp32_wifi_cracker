#include "wifi_checks_bypass.h"
#include "esp_wifi.h"

// function to override the sanity check included in the idf
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}

esp_err_t raw_80211_tx(wifi_interface_t ifx, const void* buffer, int len, bool en_sys_seq) {
	return esp_wifi_80211_tx(ifx, buffer, len, en_sys_seq);
}

