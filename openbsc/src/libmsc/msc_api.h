#pragma once

#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>

/* TODO does this belong to openbsc/gsm_04_08.h ?? */
int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel);

/* Depending on conn->via_iface (A or IuCS), submit msg to the proper link api. */
extern int msc_submit_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg);
