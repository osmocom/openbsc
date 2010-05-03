#ifndef _GB_PROXY_H
#define _GB_PROXY_H

#include <sys/types.h>

#include <osmocore/msgb.h>

#include <openbsc/gprs_ns.h>

struct gbproxy_config {
	/* parsed from config file */
	u_int32_t nsip_listen_ip;
	u_int16_t nsip_listen_port;

	u_int32_t nsip_sgsn_ip;
	u_int16_t nsip_sgsn_port;

	u_int16_t nsip_sgsn_nsei;
	u_int16_t nsip_sgsn_nsvci;

	/* misc */
	struct gprs_ns_inst *nsi;
};

extern struct gbproxy_config gbcfg;

/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);


/* gb_proxy.c */

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci);

#endif
