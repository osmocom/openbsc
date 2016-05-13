#pragma once

#include <stdint.h>
#include <openbsc/common_cs.h>

struct gsm_network *bsc_network_init(void *ctx,
				     uint16_t country_code,
				     uint16_t network_code,
				     mncc_recv_cb_t mncc_recv);
