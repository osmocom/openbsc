/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The main method to drive it as a standalone process      */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <sys/socket.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/vty.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/stats.h>

#include "../../bscconfig.h"

#ifdef BUILD_MGCP_TRANSCODING
#include "openbsc/mgcp_transcode.h"
#endif

#define _GNU_SOURCE
#include <getopt.h>

#warning "Make use of the rtp proxy code"

static struct mgcp_config *cfg;
static struct mgcp_trunk_config *reset_trunk;
static int reset_endpoints = 0;
static int daemonize = 0;

const char *openbsc_copyright =
	"Copyright (C) 2009-2010 Holger Freyther and On-Waves\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Harald Welte\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static char *config_file = "mgcp.cfg";

/* used by msgb and mgcp */
void *tall_bsc_ctx = NULL;

static void print_help()
{
	printf("Some useful help...\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
	printf(" -s --disable-color\n");
	printf(" -D --daemonize Fork the process into a background daemon\n");
	printf(" -V --version Print the version number\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"daemonize", 0, 0, 'D'},
			{"version", 0, 0, 'V'},
			{"disable-color", 0, 0, 's'},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:VD", long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			config_file = talloc_strdup(tall_bsc_ctx, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'D':
			daemonize = 1;
			break;
		default:
			/* ignore */
			break;
		};
	}
}

/* simply remember this */
static int mgcp_rsip_cb(struct mgcp_trunk_config *tcfg)
{
	reset_endpoints = 1;
	reset_trunk = tcfg;

	return 0;
}

static int read_call_agent(struct osmo_fd *fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct msgb *msg;
	struct msgb *resp;
	int i;

	msg = (struct msgb *) fd->data;

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(cfg->gw_fd.bfd.fd, msg->data, msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %zu %zu\n",
			(size_t) slen, sizeof(addr));
		return -1;
	}

	/* handle message now */
	msg->l2h = msgb_put(msg, rc);
	resp = mgcp_handle_message(cfg, msg);
	msgb_reset(msg);

	if (resp) {
		sendto(cfg->gw_fd.bfd.fd, resp->l2h, msgb_l2len(resp), 0, (struct sockaddr *) &addr, sizeof(addr));
		msgb_free(resp);
	}

	if (reset_endpoints) {
		LOGP(DMGCP, LOGL_NOTICE,
		     "Asked to reset endpoints: %d/%d\n",
		     reset_trunk->trunk_nr, reset_trunk->trunk_type);
		reset_endpoints = 0;

		/* is checking in_addr.s_addr == INADDR_LOOPBACK making it more secure? */
		for (i = 1; i < reset_trunk->number_endpoints; ++i)
			mgcp_release_endp(&reset_trunk->endpoints[i]);
	}

	return 0;
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OpenBSC MGCP",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	struct sockaddr_in addr;
	int on = 1, rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "mgcp-callagent");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);

	osmo_init_ignore_signals();
	osmo_init_logging(&log_info);

	cfg = mgcp_config_alloc();
	if (!cfg)
		return -1;

#ifdef BUILD_MGCP_TRANSCODING
	cfg->setup_rtp_processing_cb = &mgcp_transcoding_setup;
	cfg->rtp_processing_cb = &mgcp_transcoding_process_rtp;
	cfg->get_net_downlink_format_cb = &mgcp_transcoding_net_downlink_format;
#endif

	cfg->trunk.force_realloc = 1;

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(NULL);
	osmo_stats_vty_add_cmds(&log_info);
	mgcp_vty_init();

	handle_options(argc, argv);

	rate_ctr_init(tall_bsc_ctx);
	osmo_stats_init(tall_bsc_ctx);

	rc = mgcp_parse_config(config_file, cfg, MGCP_BSC);
	if (rc < 0)
		return rc;

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_bsc_ctx, &dummy_network,
			       vty_get_bind_addr(), OSMO_VTY_PORT_BSC_MGCP);
	if (rc < 0)
		return rc;

	/* set some callbacks */
	cfg->reset_cb = mgcp_rsip_cb;

        /* we need to bind a socket */
        if (rc == 0) {
		cfg->gw_fd.bfd.when = BSC_FD_READ;
		cfg->gw_fd.bfd.cb = read_call_agent;
		cfg->gw_fd.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (cfg->gw_fd.bfd.fd < 0) {
			perror("Gateway failed to listen");
			return -1;
		}

		setsockopt(cfg->gw_fd.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(cfg->source_port);
		inet_aton(cfg->source_addr, &addr.sin_addr);

		if (bind(cfg->gw_fd.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("Gateway failed to bind");
			return -1;
		}

		cfg->gw_fd.bfd.data = msgb_alloc(4096, "mgcp-msg");
		if (!cfg->gw_fd.bfd.data) {
			fprintf(stderr, "Gateway memory error.\n");
			return -1;
		}

		if (cfg->call_agent_addr) {
			addr.sin_port = htons(2727);
			inet_aton(cfg->call_agent_addr, &addr.sin_addr);
			if (connect(cfg->gw_fd.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				LOGP(DMGCP, LOGL_ERROR, "Failed to connect to: '%s'. errno: %d\n",
				     cfg->call_agent_addr, errno);
				close(cfg->gw_fd.bfd.fd);
				cfg->gw_fd.bfd.fd = -1;
				return -1;
			}
		}

		if (osmo_fd_register(&cfg->gw_fd.bfd) != 0) {
			LOGP(DMGCP, LOGL_FATAL, "Failed to register the fd\n");
			return -1;
		}

		LOGP(DMGCP, LOGL_NOTICE, "Configured for MGCP.\n");
	}

	/* initialisation */
	srand(time(NULL));

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	/* main loop */
	while (1) {
		osmo_select_main(0);
	}


	return 0;
}
