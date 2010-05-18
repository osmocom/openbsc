/* GPRS SGSN Implementation */

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
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>
#include <osmocore/select.h>
#include <osmocore/rate_ctr.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/telnet_interface.h>
#include <openbsc/vty.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

#include <gtp.h>

#include "../../bscconfig.h"

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

void *tall_bsc_ctx;

struct gprs_ns_inst *sgsn_nsi;
const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\n"
	"License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n";

static struct sgsn_instance sgsn_inst = {
	.config_file = "osmo_sgsn.cfg",
	.cfg = {
		.gtp_statedir = "./",
	},
};
struct sgsn_instance *sgsn = &sgsn_inst;

/* call-back function for the NS protocol */
static int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, u_int16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_rcvmsg(msg);
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

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		dispatch_signal(SS_GLOBAL, S_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

/* NSI that BSSGP uses when transmitting on NS */
extern struct gprs_ns_inst *bssgp_nsi;
extern void *tall_msgb_ctx;
static struct sgsn_ggsn_ctx _ggsn;
struct sgsn_ggsn_ctx *dummy_ggsn = &_ggsn;

int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	struct log_target *stderr_target;
	struct sockaddr_in sin;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 0, "osmo_sgsn");
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	vty_init("Osmocom SGSN", PACKAGE_VERSION, openbsc_copyright);
	logging_vty_add_cmds();
        sgsn_vty_init();

	rate_ctr_init(tall_bsc_ctx);
	rc = telnet_init(tall_bsc_ctx, &dummy_network, 4245);
	if (rc < 0)
		exit(1);

	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb);
	if (!sgsn_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bssgp_nsi = sgsn_inst.cfg.nsi = sgsn_nsi;
	gprs_ns_vty_init(bssgp_nsi);
	gprs_bssgp_vty_init();
	gprs_llc_vty_init();
	/* FIXME: register signal handler for SS_NS */

	rc = sgsn_parse_config(sgsn_inst.config_file, &sgsn_inst.cfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file\n");
		exit(2);
	}

	rc = sgsn_gtp_init(&sgsn_inst);
	nsip_listen(sgsn_nsi, sgsn_inst.cfg.nsip_listen_port);

	_ggsn.gtp_version = 1;
	inet_aton("192.168.100.239", &_ggsn.remote_addr);
	_ggsn.gsn = sgsn_inst.gsn;

	while (1) {
		rc = bsc_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}
