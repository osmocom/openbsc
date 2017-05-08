#pragma once

#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>

/* These are the interfaces of the MSC layer towards (from?) the BSC and RNC,
 * i.e. in the direction towards the mobile device (MS aka UE).
 *
 * 2G will use the A-interface,
 * 3G aka UMTS will use the Iu-interface (for the MSC, it's IuCS).
 *
 * To allow linking parts of the MSC code without having to include entire
 * infrastructures of external libraries, the core transmitting and receiving
 * functions are left unimplemented. For example, a unit test does not need to
 * link against external ASN1 libraries if it is never going to encode actual
 * outgoing messages. It is up to each building scope to implement real world
 * functions or to plug mere dummy implementations.
 *
 * For example, msc_tx_dtap(conn, msg), depending on conn->via_iface, will call
 * either iu_tx() or a_tx() [note: at time of writing, the A-interface is not
 * yet implemented]. When you try to link against libmsc, you will find that
 * the compiler complains about an undefined reference to iu_tx(). If you,
 * however, link against libiu as well as the osmo-iuh libs (etc.), iu_tx() is
 * available. A unit test may instead simply implement a dummy iu_tx() function
 * and not link against osmo-iuh.
 */

/* Each main linkage must implement this function (see comment above). */
extern int iu_tx(struct msgb *msg, uint8_t sapi);

/* So far this is a dummy implemented in libmsc/a_iface.c. When A-interface
 * gets implemented, it should be in a separate lib (like libiu), this function
 * should move there, and the following comment should remain here: "
 * Each main linkage must implement this function (see comment above).
 * " */
extern int a_tx(struct msgb *msg);

int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg);

int msc_gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn);
int msc_gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			     enum gsm48_reject_value value);

/* TODO: specific to A interface, move this away */
int msc_gsm0808_tx_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			       const uint8_t *key, int len, int include_imeisv);
