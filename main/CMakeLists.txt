idf_component_register(SRCS "program.c" "wifi.h" "wifi.c" "led.c" "led.h" "targeting.c" "targeting.h" "webserver.c" "webserver.h"
                    PRIV_REQUIRES esp_wifi nvs_flash esp_driver_rmt wifi_checks_bypass
                    INCLUDE_DIRS ".")
