#ifndef WIFI_CHECKS_BYPASS
#define WIFI_CHECKS_BYPASS
#include "esp_err.h"
#include "esp_wifi_types_generic.h"
#include <stdint.h>

esp_err_t raw_80211_tx(wifi_interface_t ifx, const void* buffer, int len, bool en_sys_seq); 
#endif
