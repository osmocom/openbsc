#pragma once

int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg);

struct gsm_subscriber_connection *subscr_conn_allocate_iu(struct gsm_network *network,
							  uint8_t link_id,
							  uint32_t conn_id);

struct gsm_subscriber_connection *subscr_conn_lookup_iu(struct gsm_network *network,
							struct ue_conn_ctx *ue);
