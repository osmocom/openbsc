#pragma once

int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg,
			uint16_t *lac);

struct gsm_subscriber_connection *subscr_conn_lookup_iu(struct gsm_network *network,
							struct ue_conn_ctx *ue);
