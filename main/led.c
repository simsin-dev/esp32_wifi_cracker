#include <driver/rmt_tx.h>
#include "led.h"

#define T0H 0.4
#define T0L 0.85
#define T1H 0.8
#define T1L 0.45

#define RESOLUTION 10000000

rmt_channel_handle_t led_chan = NULL;
rmt_encoder_handle_t led_encoder = NULL;

rmt_transmit_config_t tx_cfg = {.loop_count = 0};
void led_init() {
    rmt_tx_channel_config_t tx_chan_cfg = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = 8,
        .mem_block_symbols = 64,
        .resolution_hz = RESOLUTION, 
        .trans_queue_depth = 4};
    rmt_new_tx_channel(&tx_chan_cfg, &led_chan);

 	rmt_bytes_encoder_config_t bytes_encoder_config = {
        .bit0 = {
            .level0 = 1,
            .duration0 = T0H * RESOLUTION / 1000000,
            .level1 = 0,
            .duration1 = T0L * RESOLUTION / 1000000},

        .bit1 = {
			.level0 = 1,
			.duration0 = T1H * RESOLUTION / 1000000,
			.level1 = 0, 
			.duration1 = T1L * RESOLUTION / 1000000},

        .flags.msb_first = 1};

	rmt_new_bytes_encoder(&bytes_encoder_config, &led_encoder);

    rmt_enable(led_chan);
}

void led_set_color(uint8_t r, uint8_t g, uint8_t b) {
	uint8_t rgb[3] = {g,r,b};
    rmt_transmit(led_chan, led_encoder, rgb, sizeof(rgb), &tx_cfg);
}
