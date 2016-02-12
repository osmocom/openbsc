#pragma once

#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>

/* These are the interfaces of the MSC layer towards the BSC and RNC, i.e. in
 * the direction towards the mobile device (MS aka UE).
 *
 * 2G will use the A-interface,
 * 3G aka UMTS will use the Iu-interface (for the MSC, it's IuCS).
 *
 * Below callback structures allows linking parts of the MSC code without
 * having to include entire infrastructures of external libraries. For example,
 * a unit test does not need to link against external ASN1 libraries if it is
 * never going to encode actual outgoing messages. It is up to each building
 * scope to plug real world functions or to have mere dummy implementations. */

extern struct {

	struct {
		/* libmsc calls this to send out messages to an A-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
	} a;

	struct {
		/* libmsc calls this to send out messages to an Iu-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
	} iu_cs;

} msc_ifaces;



/* Depending on conn->via_iface (A or IuCS), submit msg to the proper link api. */
extern int msc_submit_dtap(struct gsm_subscriber_connection *conn,
			   struct msgb *msg);
