/* ip.access nanoBTS configuration tool */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <openbsc/select.h>
#include <openbsc/timer.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>

static struct gsm_network *gsmnet;

static int restart;
static char *prim_oml_ip;
static char *unit_id;

/*
static u_int8_t prim_oml_attr[] = { 0x95, 0x00, 7, 0x88, 192, 168, 100, 11, 0x00, 0x00 };
static u_int8_t unit_id_attr[] = { 0x91, 0x00, 9, '2', '3', '4', '2', '/' , '0', '/', '0', 0x00 };
*/

static void bootstrap_om(struct gsm_bts *bts)
{
	int len;
	static u_int8_t buf[1024];

	printf("OML link established\n");

	if (unit_id) {
		len = strlen(unit_id);
		if (len > sizeof(buf)-10)
			return;
		buf[0] = NM_ATT_IPACC_UNIT_ID;
		buf[1] = (len+1) >> 8;
		buf[2] = (len+1) & 0xff;
		memcpy(buf+3, unit_id, len);
		buf[3+len] = 0;
		printf("setting Unit ID to '%s'\n", unit_id);
		abis_nm_ipaccess_set_nvattr(bts, buf, 3+len+1);
	}
	if (prim_oml_ip) {
		struct in_addr ia;
		u_int8_t *cur = buf;

		if (!inet_aton(prim_oml_ip, &ia)) {
			fprintf(stderr, "invalid IP address: %s\n",
				prim_oml_ip);
			return;
		}

		/* 0x88 + IP + port */
		len = 1 + sizeof(ia) + 2;

		*cur++ = NM_ATT_IPACC_PRIM_OML_IP;
		*cur++ = (len) >> 8;
		*cur++ = (len) & 0xff;
		*cur++ = 0x88;
		memcpy(cur, &ia, sizeof(ia));
		cur += sizeof(ia);
		*cur++ = 0;
		*cur++ = 0;
		printf("setting primary OML link IP to '%s'\n", inet_ntoa(ia));
		abis_nm_ipaccess_set_nvattr(bts, buf, 3+len);
	}

	if (restart) {
		printf("restarting BTS\n");
		abis_nm_ipaccess_restart(bts);
	}
}

void input_event(int event, enum e1inp_sign_type type, struct gsm_bts_trx *trx)
{
	switch (event) {
	case EVT_E1_TEI_UP:
		switch (type) {
		case E1INP_SIGN_OML:
			bootstrap_om(trx->bts);
			break;
		case E1INP_SIGN_RSL:
			/* FIXME */
			break;
		default:
			break;
		}
		break;
	case EVT_E1_TEI_DN:
		fprintf(stderr, "Lost some E1 TEI link\n");
		/* FIXME: deal with TEI or L1 link loss */
		break;
	default:
		break;
	}
}

int nm_state_event(enum nm_evt evt, u_int8_t obj_class, void *obj,
		   struct gsm_nm_state *old_state, struct gsm_nm_state *new_state)
{
	return 0;
}

int main(int argc, char **argv)
{
	struct gsm_bts *bts;
	struct sockaddr_in sin;
	int rc, option_index = 0;

	printf("ipaccess-config (C) 2009 by Harald Welte\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	while (1) {
		int c;
		static struct option long_options[] = {
			{ "unit-id", 1, 0, 'u' },
			{ "oml-ip", 1, 0, 'o' },
			{ "restart", 0, 0, 'r' },
		};

		c = getopt_long(argc, argv, "u:o:r", long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'u':
			unit_id = optarg;
			break;
		case 'o':
			prim_oml_ip = optarg;
			break;
		case 'r':
			restart = 1;
			break;
		}
	};

	if (optind >= argc) {
		fprintf(stderr, "you have to specify the IP address of the BTS\n");
		exit(2);
	}

	gsmnet = gsm_network_init(1, 1, NULL);
	if (!gsmnet)
		exit(1);

	bts = gsm_bts_alloc(gsmnet, GSM_BTS_TYPE_NANOBTS_900, HARDCODED_TSC,
				HARDCODED_BSIC);
	
	printf("Trying to connect to ip.access BTS ...\n");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	inet_aton(argv[optind], &sin.sin_addr);
	rc = ia_config_connect(bts, &sin);
	if (rc < 0) {
		perror("Error connecting to the BTS");
		exit(1);
	}
	
	while (1) {
		rc = bsc_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

