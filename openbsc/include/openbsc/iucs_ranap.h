#pragma once

struct gsm_network;
struct ue_conn_ctx;

int iucs_rx_ranap_event(struct gsm_network *network,
			struct ue_conn_ctx *ue_ctx, int type, void *data);
