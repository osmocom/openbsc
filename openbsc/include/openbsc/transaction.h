#ifndef _TRANSACT_H
#define _TRANSACT_H

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>

struct gsm_trans *trans_find_by_id(struct gsm_lchan *lchan, u_int8_t trans_id);
struct gsm_trans *trans_find_by_callref(struct gsm_network *net,
					u_int32_t callref);

struct gsm_trans *trans_alloc(struct gsm_subscriber *subscr,
			      u_int8_t protocol, u_int8_t trans_id,
			      u_int32_t callref);
void trans_free(struct gsm_trans *trans);

int trans_assign_trans_id(struct gsm_subscriber *subscr,
			  u_int8_t protocol, u_int8_t ti_flag);
#endif
