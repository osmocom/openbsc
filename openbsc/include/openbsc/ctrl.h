#pragma once

struct ctrl_handle *bsc_controlif_setup(struct gsm_network *net,
					const char *bind_addr, uint16_t port);
