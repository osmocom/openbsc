#ifndef _GSM_SUP_H
#define _GSM_SUP_H

#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#define LOGGSUBSCRP(level, subscr, fmt, args...) \
	LOGP(DSUP, level, "SUBSCR(%s) " fmt, \
	     (subscr) ? (subscr)->imsi : "---", \
	     ## args)

#define LOGGSESSIONP(level, session_id, fmt, args...) \
	LOGP(DSUP, level, "SESSION(%d:%d) " fmt, \
	     session_id.h, session_id.l, \
	     ## args)

/* TODO move libosmocore */
enum osmo_gsup_charging_message_type {
	OSMO_GSUP_MSGT_RESERVE_UNITS_REQUEST	= 0b00100000,
	OSMO_GSUP_MSGT_RESERVE_UNITS_RESPONSE	= 0b00100010,
};
enum osmo_gsup_charging_request_type {
	OSMO_GSUP_MSGT_REQUEST_TYPE_INITIAL	= 0b00000001,
	OSMO_GSUP_MSGT_REQUEST_TYPE_UPDATE	= 0b00000010,
	OSMO_GSUP_MSGT_REQUEST_TYPE_TERMINATION	= 0b00000011,
	OSMO_GSUP_MSGT_REQUEST_TYPE_EVENT	= 0b00000100,
};
enum osmo_charging_service_type {
	OSMO_CHARGING_SERVICE_TYPE_SMS	= 0b00000001,
};

enum osmo_charging_result_code {
	OSMO_CHARGING_RESULT_CODE_SUCCESS	= 2001,
	OSMO_CHARGING_RESULT_CODE_CREDIT_LIMIT_REACHED	= 4012,
};

struct osmo_gsup_reserve_units_response {
	/* Message type: [Pres: M] [Format: V] [Length: 1] */
	uint8_t message_type;
	/* Session id: [Pres: M] [Format: V] [Length: 8] */
	struct charging_session_id session_id;
	/* Request type: [Pres: M] [Format: V] [Length: 1] */
	uint8_t request_type;
	/* Result code: [Pres: M] [Format: V] [Length: 4] */
	uint32_t result_code;
	/* Service units: [Pres: O] [Format: V] [Length: 4] */
	uint32_t service_units;
};

/* Callback for both HLR/auth and USSD SUP sockets */
int sup_read_cb(struct gsup_client *sup_client, struct msgb *msg);

/*
int subscr_query_auth_info(struct gsm_subscriber *subscr);
*/
int subscr_location_update(struct gsm_subscriber *subscr);
int subscr_purge_ms(struct gsm_subscriber *subscr);

int subscr_tx_sms_message(struct gsm_subscriber *subscr,
                          struct gsm411_rp_hdr *rph);

void init_charging_session_id(struct gsm_network *network);
struct charging_session_id get_charging_session_id(struct gsm_network *network);

int tx_reserve_units_request(enum osmo_gsup_charging_message_type msg_type,
			     enum osmo_gsup_charging_request_type request_type,
			     enum osmo_charging_service_type service_type,
			     struct gsm_trans *trans, uint32_t service_units);

#endif /* _GSM_SUP_H */
