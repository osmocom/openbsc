#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <osmocore/linuxlist.h>

#define DEBUG
#include <osmocore/logging.h>

/* Debug Areas of the code */
enum {
	DRLL,
	DCC,
	DMM,
	DRR,
	DRSL,
	DNM,
	DMNCC,
	DSMS,
	DPAG,
	DMEAS,
	DMI,
	DMIB,
	DMUX,
	DINP,
	DSCCP,
	DMSC,
	DMGCP,
	DHO,
	DDB,
	DREF,
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
};

void log_set_imsi_filter(struct log_target *target, const char *imsi);

extern const struct log_info log_info;

#endif /* _DEBUG_H */
