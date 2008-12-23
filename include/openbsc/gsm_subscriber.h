#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <sys/types.h>
#include "gsm_data.h"

struct gsm_subscriber {
	u_int8_t *name;
	u_int8_t tmsi[4];
};

struct gsm_subscriber *subscr_get_by_tmsi(u_int8_t *tmsi);
struct gsm_subscriber *subscr_get_by_imsi(u_int8_t *imsi);
int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts);

#endif /* _GSM_SUBSCR_H */
