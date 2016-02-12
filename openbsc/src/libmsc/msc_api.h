#pragma once

#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>

/* This callback structure allows linking specific components without having to
 * include entire infrastructures of external libraries. For example, a unit
 * test does not need to link against external ASN1 libraries if it is never
 * going to encode actual outgoing messages. It is up to each building scope to
 * plug meaningful sending/receiving callback functions, or to have mere dummy
 * implementations. */
struct msc_api {

	struct {
		/* libmsc calls this to send out messages to an A-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
	} a;

	struct {
		/* libmsc calls this to send out messages to an Iu-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
	} iu;
};

/* TODO does this belong to openbsc/gsm_04_08.h ?? */
int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel);

/* Depending on conn->via_iface (A or IuCS), submit msg to the proper link api. */
extern int msc_submit_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg);
