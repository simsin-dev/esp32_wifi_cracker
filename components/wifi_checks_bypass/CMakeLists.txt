idf_component_register( 
	SRCS "wifi_checks_bypass.c"
	INCLUDE_DIRS "includes"
    PRIV_REQUIRES esp_wifi
)
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)
