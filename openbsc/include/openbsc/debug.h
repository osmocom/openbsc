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
	DIUCS,
	Debug_LastEntry,
};

/* context */
#define BSC_CTX_LCHAN	0
#define BSC_CTX_SUBSCR	1
#define BSC_CTX_BTS	2
#define BSC_CTX_SCCP	3

/* target */

enum {
	//DEBUG_FILTER_ALL = 1 << 0,
	LOG_FILTER_IMSI = 1 << 1,
	LOG_FILTER_NSVC = 1 << 2,
	LOG_FILTER_BVC  = 1 << 3,
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
