#pragma once

/* These functions receive or send MM|CC|... messages from/to the BSC|RNC
 * direction, while they are not concerned with which particular external
 * interface is actually involved (A or IuCS). */

/* receive a Level 3 Complete message */
int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel);
/* TODO: is chosen_channel NITB legacy? */

