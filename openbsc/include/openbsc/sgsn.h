#ifndef _SGSN_H
#define _SGSN_H

#include <sys/types.h>

#include <osmocore/msgb.h>

#include <openbsc/gprs_ns.h>

struct sgsn_config {
	/* parsed from config file */
	u_int32_t nsip_listen_ip;
	u_int16_t nsip_listen_port;

	/* misc */
	struct gprs_ns_inst *nsi;
};


/* sgsn_vty.c */

int sgsn_vty_init(void);
int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg);

/* sgsn.c */

/* Main input function for Gb proxy */
int sgsn_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci);

#endif
