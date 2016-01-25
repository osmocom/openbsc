#pragma once

int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg, uint8_t link_id);
struct gsm_subscriber_connection *subscr_conn_allocate_iu(struct gsm_bts *bts);
	/* TODO "bts"? this is an hNodeB, really. */
