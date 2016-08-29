#ifndef _TRANSACT_H
#define _TRANSACT_H

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <osmocom/core/linuxlist.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/mncc.h>
#include <osmocom/gsm/gsm0411_smc.h>
#include <osmocom/gsm/gsm0411_smr.h>

/* One transaction */
struct gsm_trans {
	/* Entry in list of all transactions */
	struct llist_head entry;

	/* Back pointer to the network struct */
	struct gsm_network *net;

	/* The protocol within which we live */
	uint8_t protocol;

	/* The current transaction ID */
	uint8_t transaction_id;

	/* To whom we belong, unique identifier of remote MM entity */
	struct gsm_subscriber *subscr;

	/* The associated connection we are using to transmit messages */
	struct gsm_subscriber_connection *conn;

	/* reference from MNCC or other application */
	uint32_t callref;

	/* if traffic channel receive was requested */
	int tch_recv;

	/* is thats one paging? */
	struct subscr_request *paging_request;

	union {
		struct {

			/* current call state */
			int state;

			/* current timer and message queue */
			int Tcurrent;		/* current CC timer */
			int T308_second;	/* used to send release again */
			struct osmo_timer_list timer;
			struct gsm_mncc msg;	/* stores setup/disconnect/release message */
		} cc;
		struct {
			struct gsm411_smc_inst smc_inst;
			struct gsm411_smr_inst smr_inst;

			struct gsm_sms *sms;
		} sms;
	};
};



struct gsm_trans *trans_find_by_id(struct gsm_subscriber_connection *conn,
				   uint8_t proto, uint8_t trans_id);
struct gsm_trans *trans_find_by_callref(struct gsm_network *net,
					uint32_t callref);

struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct gsm_subscriber *subscr,
			      uint8_t protocol, uint8_t trans_id,
			      uint32_t callref);
void trans_free(struct gsm_trans *trans);

int trans_assign_trans_id(struct gsm_network *net, struct gsm_subscriber *subscr,
			  uint8_t protocol, uint8_t ti_flag);
int trans_has_conn(const struct gsm_subscriber_connection *conn);

#endif
