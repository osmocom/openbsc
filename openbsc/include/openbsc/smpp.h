#pragma once

int smpp_openbsc_init(void *ctx, uint16_t port);
void smpp_openbsc_set_net(struct gsm_network *net);
