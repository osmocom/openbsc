#pragma once

#include <openbsc/vlr.h>

#define LOGGSUPP(level, gsup, fmt, args...) \
	LOGP(DVLR, level, "GSUP(%s) " fmt, \
	     (gsup)->imsi, \
	     ## args)

#define LOGVSUBP(level, vsub, fmt, args...) \
	LOGP(DVLR, level, "SUBSCR(%s) " fmt, \
		vlr_sub_name(vsub), ## args)


const char *vlr_sub_name(struct vlr_subscriber *vsub);
struct vlr_subscriber *vlr_subscr_find_by_imsi(struct vlr_instance *vlr,
					       const char *imsi);
struct vlr_subscriber *vlr_subscr_find_by_tmsi(struct vlr_instance *vlr,
					       uint32_t tmsi);
int vlr_sub_req_lu(struct vlr_subscriber *vsub, bool is_ps);
int vlr_sub_req_sai(struct vlr_subscriber *vsub, const uint8_t *auts,
		    const uint8_t *auts_rand);
struct vlr_subscriber *vlr_sub_alloc(struct vlr_instance *vlr);
void vlr_sub_update_tuples(struct vlr_subscriber *vsub,
			   const struct osmo_gsup_message *gsup);
