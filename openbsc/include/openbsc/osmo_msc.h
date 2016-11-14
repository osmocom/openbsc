/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>

#include <openbsc/gsm_data.h>

#include "bsc_api.h"

enum subscr_conn_fsm_event {
	/* LU FSM has terminated */
	SUB_CON_E_LU_RES,
	/* Process Access Request has terminated */
	SUB_CON_E_PARQ_RES,
	/* MS/BTS/BSC originated close request */
	SUB_CON_E_MO_CLOSE,
	/* MSC originated close request, primarily originates from
	 * subscr_con_put() in case reference coult reaches 0 */
	SUB_CON_E_CN_CLOSE,
	/* BSC erports confirmation of connection close */
	SUB_CON_E_CLOSE_CONF,
};


struct bsc_api *msc_bsc_api();
struct gsm_subscriber_connection *subscr_con_get(struct gsm_subscriber_connection *conn);
void subscr_con_put(struct gsm_subscriber_connection *conn);

struct osmo_fsm_inst *
msc_create_conn_fsm(struct gsm_subscriber_connection *conn,
		    const char *id);
#endif
