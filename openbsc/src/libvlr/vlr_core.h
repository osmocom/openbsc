#pragma once

#include <openbsc/vlr.h>

#define LOGGSUPP(level, gsup, fmt, args...) \
	LOGP(DVLR, level, "GSUP(%s) " fmt, \
	     (gsup)->imsi, \
	     ## args)

#define LOGVSUBP(level, vsub, fmt, args...) \
	LOGP(DVLR, level, "SUBSCR(%s) " fmt, \
		vlr_subscr_name(vsub), ## args)


const char *vlr_subscr_name(struct vlr_subscr *vsub);
int vlr_subscr_req_lu(struct vlr_subscr *vsub, bool is_ps);
int vlr_subscr_req_sai(struct vlr_subscr *vsub, const uint8_t *auts,
		       const uint8_t *auts_rand);
struct vlr_subscr *vlr_subscr_alloc(struct vlr_instance *vlr);
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup);
