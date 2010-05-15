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
	DGPRS,
	DNS,
	DBSSGP,
	DLLC,
	DSNDCP,
	Debug_LastEntry,
};

/* context */
#define BSC_CTX_LCHAN	0
#define BSC_CTX_SUBSCR	1
#define BSC_CTX_BTS	2
#define BSC_CTX_SCCP	3
#define BSC_CTX_NSVC	4

#define LOGGING_STR	"Configure log message to this terminal\n"
#define FILTER_STR	"Filter log messages\n"

/* target */

enum {
	//DEBUG_FILTER_ALL = 1 << 0,
	LOG_FILTER_IMSI = 1 << 1,
	LOG_FILTER_NSVC = 1 << 2,
};

/* we don't need a header dependency for this... */
struct gprs_nsvc;

void log_set_imsi_filter(struct log_target *target, const char *imsi);
void log_set_nsvc_filter(struct log_target *target,
			 const struct gprs_nsvc *nsvc);

extern const struct log_info log_info;

#endif /* _DEBUG_H */
