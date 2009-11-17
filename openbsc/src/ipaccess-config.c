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
#include <openbsc/signal.h>
#include <openbsc/debug.h>

static struct gsm_network *gsmnet;

static int net_listen_testnr;
static int restart;
static char *prim_oml_ip;
static char *unit_id;
static u_int16_t nv_flags;
static u_int16_t nv_mask;

/*
static u_int8_t prim_oml_attr[] = { 0x95, 0x00, 7, 0x88, 192, 168, 100, 11, 0x00, 0x00 };
static u_int8_t unit_id_attr[] = { 0x91, 0x00, 9, '2', '3', '4', '2', '/' , '0', '/', '0', 0x00 };
*/

/*
 * Callback function for NACK on the OML NM
 *
 * Currently we send the config requests but don't check the
 * result. The nanoBTS will send us a NACK when we did something the
 * BTS didn't like.
 */
static int ipacc_msg_nack(u_int8_t mt)
{
	fprintf(stderr, "Failure to set attribute. This seems fatal\n");
	exit(-1);
	return 0;
}

struct ipacc_ferr_elem {
	int16_t freq_err;
	u_int8_t freq_qual;
	u_int8_t arfcn;
} __attribute__((packed));

struct ipacc_cusage_elem {
	u_int16_t arfcn:10,
		  rxlev:6;
} __attribute__ ((packed));

static int test_rep(void *_msg)
{
	struct msgb *msg = _msg;
	struct abis_om_fom_hdr *foh = msgb_l3(msg);
	u_int16_t test_rep_len, ferr_list_len;
	struct ipacc_ferr_elem *ife;
	struct ipac_bcch_info binfo;
	int i, rc;

	DEBUGP(DNM, "TEST REPORT: ");

	if (foh->data[0] != NM_ATT_TEST_NO ||
	    foh->data[2] != NM_ATT_TEST_REPORT)
		return -EINVAL;

	DEBUGPC(DNM, "test_no=0x%02x ", foh->data[1]);
	/* data[2] == NM_ATT_TEST_REPORT */
	/* data[3..4]: test_rep_len */
	test_rep_len = ntohs(*(u_int16_t *) &foh->data[3]);
	/* data[5]: ip.access test result */
	DEBUGPC(DNM, "test_res=%s\n", ipacc_testres_name(foh->data[5]));

	/* data[6]: ip.access nested IE. 3 == freq_err_list */
	switch (foh->data[6]) {
	case NM_IPAC_EIE_FREQ_ERR_LIST:
		/* data[7..8]: length of ferr_list */
		ferr_list_len = ntohs(*(u_int16_t *) &foh->data[7]);

		/* data[9...]: frequency error list elements */
		for (i = 0; i < ferr_list_len; i+= sizeof(*ife)) {
			ife = (struct ipacc_ferr_elem *) (foh->data + 9 + i);
			DEBUGP(DNM, "==> ARFCN %4u, Frequency Error %6hd\n",
			ife->arfcn, ntohs(ife->freq_err));
		}
		break;
	case NM_IPAC_EIE_CHAN_USE_LIST:
		/* data[7..8]: length of ferr_list */
		ferr_list_len = ntohs(*(u_int16_t *) &foh->data[7]);

		/* data[9...]: channel usage list elements */
		for (i = 0; i < ferr_list_len; i+= 2) {
			u_int16_t *cu_ptr = (u_int16_t *)(foh->data + 9 + i);
			u_int16_t cu = ntohs(*cu_ptr);
			DEBUGP(DNM, "==> ARFCN %4u, RxLev %2u\n",
				cu & 0x3ff, cu >> 10);
		}
		break;
	case NM_IPAC_EIE_BCCH_INFO_TYPE:
		break;
	case NM_IPAC_EIE_BCCH_INFO:
		rc = ipac_parse_bcch_info(&binfo, foh->data+6);
		if (rc < 0) {
			DEBUGP(DNM, "BCCH Info parsing failed\n");
			break;
		}
		DEBUGP(DNM, "==> ARFCN %u, RxLev %2u, RxQual %2u: %3d-%d, LAC %d CI %d\n",
			binfo.arfcn, binfo.rx_lev, binfo.rx_qual,
			binfo.cgi.mcc, binfo.cgi.mnc,
			binfo.cgi.lac, binfo.cgi.ci);
		break;
	default:
		break;
	}

	return 0;
}

static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	u_int8_t *msg_type;

	switch (signal) {
	case S_NM_IPACC_NACK:
		msg_type = signal_data;
		return ipacc_msg_nack(*msg_type);
	case S_NM_TEST_REP:
		return test_rep(signal_data);
	default:
		break;
	}

	return 0;
}

static void bootstrap_om(struct gsm_bts *bts)
{
	int len;
	static u_int8_t buf[1024];
	u_int8_t *cur = buf;

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

		if (!inet_aton(prim_oml_ip, &ia)) {
			fprintf(stderr, "invalid IP address: %s\n",
				prim_oml_ip);
			return;
		}

		/* 0x88 + IP + port */
		len = 1 + sizeof(ia) + 2;

		*cur++ = NM_ATT_IPACC_PRIM_OML_CFG_LIST;
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
	if (nv_mask) {
		len = 4;

		*cur++ = NM_ATT_IPACC_NV_FLAGS;
		*cur++ = (len) >> 8;
		*cur++ = (len) & 0xff;
		*cur++ = nv_flags & 0xff;
		*cur++ = nv_mask & 0xff;
		*cur++ = nv_flags >> 8;
		*cur++ = nv_mask >> 8;
		printf("setting NV Flags/Mask to 0x%04x/0x%04x\n",
			nv_flags, nv_mask);
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
	if (evt == EVT_STATECHG_OPER &&
	    obj_class == NM_OC_RADIO_CARRIER &&
	    new_state->availability == 3 &&
	    net_listen_testnr) {
		struct gsm_bts_trx *trx = obj;
		u_int8_t phys_config[] = { 0x02, 0x0a, 0x00, 0x01, 0x02 };
		abis_nm_perform_test(trx->bts, 2, 0, 0, 0xff,
				     net_listen_testnr, 1,
				     phys_config, sizeof(phys_config));
	}
	return 0;
}

static void print_usage(void)
{
	printf("Usage: ipaccess-config\n");
}

static void print_help(void)
{
	printf("  -u --unit-id UNIT_ID\n");
	printf("  -o --oml-ip ip\n");
	printf("  -r --restart\n");
	printf("  -n flags/mask\tSet NVRAM attributes.\n");
	printf("  -l --listen testnr \tPerform speciified test number\n");
	printf("  -h --help this text\n");
	printf("  -s --stream-id ID\n");
}

int main(int argc, char **argv)
{
	struct gsm_bts *bts;
	struct sockaddr_in sin;
	int rc, option_index = 0, stream_id = 0xff;

	printf("ipaccess-config (C) 2009 by Harald Welte\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	while (1) {
		int c;
		unsigned long ul;
		char *slash;
		static struct option long_options[] = {
			{ "unit-id", 1, 0, 'u' },
			{ "oml-ip", 1, 0, 'o' },
			{ "restart", 0, 0, 'r' },
			{ "help", 0, 0, 'h' },
			{ "listen", 1, 0, 'l' },
			{ "stream-id", 1, 0, 's' },
		};

		c = getopt_long(argc, argv, "u:o:rn:l:hs:", long_options,
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
		case 'n':
			slash = strchr(optarg, '/');
			if (!slash)
				exit(2);
			ul = strtoul(optarg, NULL, 16);
			nv_flags = ul & 0xffff;
			ul = strtoul(slash+1, NULL, 16);
			nv_mask = ul & 0xffff;
			break;
		case 'l':
			net_listen_testnr = atoi(optarg);
			break;
		case 's':
			stream_id = atoi(optarg);
			printf("foo: %d\n", stream_id);
			break;
		case 'h':
			print_usage();
			print_help();
			exit(0);
		}
	};

	if (optind >= argc) {
		fprintf(stderr, "you have to specify the IP address of the BTS. Use --help for more information\n");
		exit(2);
	}

	gsmnet = gsm_network_init(1, 1, NULL);
	if (!gsmnet)
		exit(1);

	bts = gsm_bts_alloc(gsmnet, GSM_BTS_TYPE_NANOBTS, HARDCODED_TSC,
				HARDCODED_BSIC);
	bts->oml_tei = stream_id;
	
	register_signal_handler(SS_NM, nm_sig_cb, NULL);
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

