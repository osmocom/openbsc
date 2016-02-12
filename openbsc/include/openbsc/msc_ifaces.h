#pragma once

#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>

/* These are the interfaces of the MSC layer towards the BSC and RNC, i.e. in
 * the direction towards the mobile device (MS aka UE).
 *
 * 2G will use the A-interface,
 * 3G aka UMTS will use the Iu-interface (for the MSC, it's IuCS).
 *
 * Below callback structures allow linking parts of the MSC code without
 * having to include entire infrastructures of external libraries. For example,
 * a unit test does not need to link against external ASN1 libraries if it is
 * never going to encode actual outgoing messages. It is up to each building
 * scope to plug real world functions or to have mere dummy implementations.
 *
 * For example, for msc_tx_foo(ifaces, conn, msg), depending on
 * conn->via_iface, either ifaces.a.tx() or ifaces.iu_cs.tx() is called to
 * dispatch the msg.
 *
 * To replace the default dummy implementations, a user would do the likes of:
 *
 *   int my_iu_cs_tx(...)
 *   {
 *           ...
 *   }
 *
 *   int main(void)
 *   {
 *           global_msc_ifaces.network = my_network;
 *           global_msc_ifaces.iu_cs.tx = my_iu_cs_tx;
 *           ...
 *   }
 *
 * (or use readily available implementations like iu_tx() from libiu)
 */

struct msc_ifaces {

	/* global gsm_network to lookup BSC|RNC connections etc. */
	struct gsm_network *network;

	struct {
		/* libmsc calls this to send out messages to an A-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
		/* TODO: I don't understand sapi yet, may not apply to A-iface */
	} a;

	struct {
		/* libmsc calls this to send out messages to an Iu-interface */
		int (*tx)(struct msgb *msg, uint8_t sapi);
		/* TODO: I don't understand sapi yet */
	} iu_cs;

};

extern struct msc_ifaces global_msc_ifaces;


int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg);

