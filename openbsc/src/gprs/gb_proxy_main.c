/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>
#include <osmocore/select.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/telnet_interface.h>
#include <openbsc/vty.h>
#include <openbsc/gb_proxy.h>

#include "../../bscconfig.h"

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

void *tall_bsc_ctx;

struct gprs_ns_inst *gbprox_nsi;

const char *openbsc_version = "Osmocom NSIP Proxy " PACKAGE_VERSION;
const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\n"
	"Dieter Spaar, Andreas Eversberg, Holger Freyther\n\n"
	"License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n";

static char *config_file = "osmo_gbproxy.cfg";
struct gbproxy_config gbcfg;

/* Pointer to the SGSN peer */
extern struct gbprox_peer *gbprox_peer_sgsn;

/* call-back function for the NS protocol */
static int proxy_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, u_int16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		rc = gbprox_rcvmsg(msg, nsvc, bvci);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "SGSN: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}


int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	struct log_target *stderr_target;
	struct sockaddr_in sin;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 0, "nsip_proxy");

	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	telnet_init(&dummy_network, 4244);
	rc = gbproxy_parse_config(config_file, &gbcfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file\n");
		exit(2);
	}

	gbprox_nsi = gprs_ns_instantiate(&proxy_ns_cb);
	if (!gbprox_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	gbcfg.nsi = gbprox_nsi;
	register_signal_handler(SS_NS, &gbprox_signal, NULL);
	nsip_listen(gbprox_nsi, gbcfg.nsip_listen_port);

	/* 'establish' the outgoing connection to the SGSN */
	sin.sin_family = AF_INET;
	sin.sin_port = htons(gbcfg.nsip_sgsn_port);
	sin.sin_addr.s_addr = htonl(gbcfg.nsip_sgsn_ip);
	nsip_connect(gbprox_nsi, &sin, gbcfg.nsip_sgsn_nsei,
			gbcfg.nsip_sgsn_nsvci);

	while (1) {
		rc = bsc_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

struct gsm_network;
int bsc_vty_init(struct gsm_network *dummy)
{
	cmd_init(1);
	vty_init();

	openbsc_vty_add_cmds();
        gbproxy_vty_init();
	return 0;
}

