#ifndef _SUP_H
#define _SUP_H

#include <openbsc/reg_proxy.h>

#define LOGGSUPP(level, sup, fmt, args...) \
	LOGP(DGPRS, level, "SUP(%s) " fmt, \
	     (sup)->imsi, \
	     ## args)

int sup_server_init(struct reg_proxy *reg);

int handle_location_update_result(struct gsm_sup_server *sup_server,
								 char *imsi, char *msisdn);

int handle_purge_ms_result(struct gsm_sup_server *sup_server,
								 char *imsi);

#endif /* _SUP_H */
