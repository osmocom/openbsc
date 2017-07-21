/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsup.h>

#include <openbsc/gsm_data.h>

#include "bsc_api.h"

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT OSMO_GSUP_PORT

enum subscr_conn_fsm_event {
	/* Mark 0 as invalid to catch uninitialized vars */
	SUBSCR_CONN_E_INVALID = 0,
	/* Timeout on connection establishment starts */
	SUBSCR_CONN_E_START,
	/* LU or Process Access FSM has determined that this conn is good */
	SUBSCR_CONN_E_ACCEPTED,
	/* received first reply from MS in "real" CC, SMS, USSD communication */
	SUBSCR_CONN_E_COMMUNICATING,
	/* Some async action has completed, check again whether all is done */
	SUBSCR_CONN_E_BUMP,
	/* MS/BTS/BSC originated close request */
	SUBSCR_CONN_E_MO_CLOSE,
	/* MSC originated close request, e.g. failed authentication */
	SUBSCR_CONN_E_CN_CLOSE,
};

enum subscr_conn_fsm_state {
	SUBSCR_CONN_S_INIT,
	SUBSCR_CONN_S_NEW,
	SUBSCR_CONN_S_ACCEPTED,
	SUBSCR_CONN_S_COMMUNICATING,
	SUBSCR_CONN_S_RELEASED,
};

enum subscr_conn_from {
	SUBSCR_CONN_FROM_INVALID,
	SUBSCR_CONN_FROM_LU,
	SUBSCR_CONN_FROM_CM_SERVICE_REQ,
	SUBSCR_CONN_FROM_PAGING_RESP,
};

extern const struct value_string subscr_conn_from_names[];
static inline const char *subscr_conn_from_name(enum subscr_conn_from val)
{
	return get_value_string(subscr_conn_from_names, val);
}

enum msc_compl_l3_rc {
	MSC_CONN_ACCEPT = 0,
	MSC_CONN_REJECT = 1,
};

struct bsc_api *msc_bsc_api();

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id);

int msc_vlr_alloc(struct gsm_network *net);
int msc_vlr_start(struct gsm_network *net);

int msc_compl_l3(struct gsm_subscriber_connection *conn,
		 struct msgb *msg, uint16_t chosen_channel);
void msc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id,
	      struct msgb *msg);
void msc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, uint8_t alg_id);
void msc_rx_sec_mode_compl(struct gsm_subscriber_connection *conn);

void msc_subscr_conn_init(void);
bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn);
void msc_subscr_conn_communicating(struct gsm_subscriber_connection *conn);
void msc_subscr_conn_close(struct gsm_subscriber_connection *conn,
			   uint32_t cause);

#define msc_subscr_conn_get(conn) \
	_msc_subscr_conn_get(conn, __BASE_FILE__, __LINE__)
#define msc_subscr_conn_put(conn) \
	_msc_subscr_conn_put(conn, __BASE_FILE__, __LINE__)
struct gsm_subscriber_connection *
_msc_subscr_conn_get(struct gsm_subscriber_connection *conn,
		     const char *file, int line);
void _msc_subscr_conn_put(struct gsm_subscriber_connection *conn,
			  const char *file, int line);

void msc_stop_paging(struct vlr_subscr *vsub);

#endif
