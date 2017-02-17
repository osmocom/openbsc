#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DRLL,
	DCC,
	DMM,
	DRR,
	DRSL,
	DNM,
	DMNCC,
	DPAG,
	DMEAS,
	DSCCP,
	DMSC,
	DMGCP,
	DHO,
	DDB,
	DREF,
	DGPRS,
	DNS,
	DBSSGP,
	DLLC,
	DSNDCP,
	DSLHC,
	DNAT,
	DCTRL,
	DSMPP,
	DFILTER,
	DGTPHUB,
	DRANAP,
	DSUA,
	DV42BIS,
	Debug_LastEntry,
};

/* we don't need a header dependency for this... */
struct gprs_nsvc;
struct bssgp_bvc_ctx;
struct gsm_subscriber;

void log_set_imsi_filter(struct log_target *target, struct gsm_subscriber *subscr);
void log_set_nsvc_filter(struct log_target *target,
			 struct gprs_nsvc *nsvc);
void log_set_bvc_filter(struct log_target *target,
			struct bssgp_bvc_ctx *bctx);

extern const struct log_info log_info;

#endif /* _DEBUG_H */
