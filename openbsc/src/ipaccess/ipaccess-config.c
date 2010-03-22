/* ip.access nanoBTS configuration tool */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther
 * (C) 2009 by On Waves
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


#include <osmocore/select.h>
#include <osmocore/timer.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <osmocore/talloc.h>

static struct gsm_network *gsmnet;

static int net_listen_testnr;
static int restart;
static char *prim_oml_ip;
static char *unit_id;
static u_int16_t nv_flags;
static u_int16_t nv_mask;
static char *software = NULL;
static int sw_load_state = 0;
static int oml_state = 0;
static int dump_files = 0;

struct sw_load {
	u_int8_t file_id[255];
	u_int8_t file_id_len;

	u_int8_t file_version[255];
	u_int8_t file_version_len;
};

static void *tall_ctx_config = NULL;
static struct sw_load *sw_load1 = NULL;
static struct sw_load *sw_load2 = NULL;

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

static int ipacc_msg_ack(u_int8_t mt, struct gsm_bts *bts)
{
	if (sw_load_state == 1) {
		fprintf(stderr, "The new software is activaed.\n");

		if (restart) {
			abis_nm_ipaccess_restart(bts);
		} else {
			exit(0);
		}
	} else if (oml_state == 1) {
		fprintf(stderr, "Set the primary OML IP.\n");
		if (restart) {
			abis_nm_ipaccess_restart(bts);
		} else {
			exit(0);
		}
	}

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
	struct ipacc_ack_signal_data *ipacc_data;

	switch (signal) {
	case S_NM_IPACC_NACK:
		ipacc_data = signal_data;
		return ipacc_msg_nack(ipacc_data->msg_type);
	case S_NM_IPACC_ACK:
		ipacc_data = signal_data;
		return ipacc_msg_ack(ipacc_data->msg_type, ipacc_data->bts);
	case S_NM_TEST_REP:
		return test_rep(signal_data);
	case S_NM_IPACC_RESTART_ACK:
		printf("The BTS has acked the restart. Exiting.\n");
		exit(0);
		break;
	case S_NM_IPACC_RESTART_NACK:
		printf("The BTS has nacked the restart. Exiting.\n");
		exit(0);
		break;
	default:
		break;
	}

	return 0;
}

/* callback function passed to the ABIS OML code */
static int percent;
static int percent_old;
static int swload_cbfn(unsigned int hook, unsigned int event, struct msgb *_msg,
		       void *data, void *param)
{
	struct msgb *msg;
	struct gsm_bts *bts;

	if (hook != GSM_HOOK_NM_SWLOAD)
		return 0;

	bts = (struct gsm_bts *) data;

	switch (event) {
	case NM_MT_LOAD_INIT_ACK:
		fprintf(stdout, "Software Load Initiate ACK\n");
		break;
	case NM_MT_LOAD_INIT_NACK:
		fprintf(stderr, "ERROR: Software Load Initiate NACK\n");
		exit(5);
		break;
	case NM_MT_LOAD_END_ACK:
		fprintf(stderr, "LOAD END ACK...");
		/* now make it the default */
		sw_load_state = 1;

		msg = msgb_alloc(1024, "sw: nvattr");
		msg->l2h = msgb_put(msg, 3);
		msg->l3h = &msg->l2h[3];

		/* activate software */
		if (sw_load1) {
			msgb_v_put(msg, NM_ATT_SW_DESCR);
			msgb_tl16v_put(msg, NM_ATT_FILE_ID, sw_load1->file_id_len, sw_load1->file_id);
			msgb_tl16v_put(msg, NM_ATT_FILE_VERSION, sw_load1->file_version_len,
					sw_load1->file_version);
		}

		if (sw_load2) {
			msgb_v_put(msg, NM_ATT_SW_DESCR);
			msgb_tl16v_put(msg, NM_ATT_FILE_ID, sw_load2->file_id_len, sw_load2->file_id);
			msgb_tl16v_put(msg, NM_ATT_FILE_VERSION, sw_load2->file_version_len,
					sw_load2->file_version);
		}

		/* fill in the data */
		msg->l2h[0] = NM_ATT_IPACC_CUR_SW_CFG;
		msg->l2h[1] = msgb_l3len(msg) >> 8;
		msg->l2h[2] = msgb_l3len(msg) & 0xff;
		printf("Foo l2h: %p l3h: %p... length l2: %u  l3: %u\n", msg->l2h, msg->l3h, msgb_l2len(msg), msgb_l3len(msg));
		abis_nm_ipaccess_set_nvattr(bts->c0, msg->l2h, msgb_l2len(msg));
		msgb_free(msg);
		break;
	case NM_MT_LOAD_END_NACK:
		fprintf(stderr, "ERROR: Software Load End NACK\n");
		exit(3);
		break;
	case NM_MT_ACTIVATE_SW_NACK:
		fprintf(stderr, "ERROR: Activate Software NACK\n");
		exit(4);
		break;
	case NM_MT_ACTIVATE_SW_ACK:
		break;
	case NM_MT_LOAD_SEG_ACK:
		percent = abis_nm_software_load_status(bts);
		if (percent > percent_old)
			printf("Software Download Progress: %d%%\n", percent);
		percent_old = percent;
		break;
	case NM_MT_LOAD_ABORT:
		fprintf(stderr, "ERROR: Load aborted by the BTS.\n");
		exit(6);
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
		abis_nm_ipaccess_set_nvattr(bts->c0, buf, 3+len+1);
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
		oml_state = 1;
		abis_nm_ipaccess_set_nvattr(bts->c0, buf, 3+len);
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
		abis_nm_ipaccess_set_nvattr(bts->c0, buf, 3+len);
	}

	if (restart && !prim_oml_ip && !software) {
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
	    new_state->availability == 3) {
		struct gsm_bts_trx *trx = obj;

		if (net_listen_testnr) {
			u_int8_t phys_config[] = { 0x02, 0x0a, 0x00, 0x01, 0x02 };
			abis_nm_perform_test(trx->bts, 2, 0, 0, 0xff,
					     net_listen_testnr, 1,
					     phys_config, sizeof(phys_config));
		} else if (software) {
			int rc;
			printf("Attempting software upload with '%s'\n", software);
			rc = abis_nm_software_load(trx->bts, software, 19, 0, swload_cbfn, trx->bts);
			if (rc < 0) {
				fprintf(stderr, "Failed to start software load\n");
				exit(-3);
			}
		}
	}
	return 0;
}

static struct sw_load *create_swload(struct sdp_header *header)
{
	struct sw_load *load;

	load = talloc_zero(tall_ctx_config, struct sw_load);

	strncpy((char *)load->file_id, header->firmware_info.sw_part, 20);
	load->file_id_len = strlen(header->firmware_info.sw_part) + 1;

	strncpy((char *)load->file_version, header->firmware_info.version, 20);
	load->file_version_len = strlen(header->firmware_info.version) + 1;

	return load;
}

static int find_sw_load_params(const char *filename)
{
	struct stat stat;
	struct sdp_header *header;
	struct llist_head *entry;
	int fd;
	void *tall_firm_ctx = 0;

	entry = talloc_zero(tall_firm_ctx, struct llist_head);
	INIT_LLIST_HEAD(entry);

	fd = open(filename, O_RDONLY);
	if (!fd) {
		perror("nada");
		return -1;
	}

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		return -1;
	}

	ipaccess_analyze_file(fd, stat.st_size, 0, entry);
	if (close(fd) != 0) {
		perror("Close failed.\n");
		return -1;
	}

	/* try to find what we are looking for */
	llist_for_each_entry(header, entry, entry) {
		if (ntohs(header->firmware_info.more_more_magic) == 0x1000) {
			sw_load1 = create_swload(header);
		} else if (ntohs(header->firmware_info.more_more_magic) == 0x2001) {
			sw_load2 = create_swload(header);
		}
	}

	if (!sw_load1 || !sw_load2) {
		fprintf(stderr, "Did not find data.\n");
		talloc_free(tall_firm_ctx);
		return -1;
        }

	talloc_free(tall_firm_ctx);
	return 0;
}

static void dump_entry(struct sdp_header_item *sub_entry, int part, int fd)
{
	int out_fd;
	int copied;
	char filename[4096];
	off_t target;

	if (!dump_files)
		return;

	if (sub_entry->header_entry.something1 == 0)
		return;

	snprintf(filename, sizeof(filename), "part.%d", part++);
	out_fd = open(filename, O_WRONLY | O_CREAT, 0660);
	if (out_fd < 0) {
		perror("Can not dump firmware");
		return;
	}

	target = sub_entry->absolute_offset;
	if (lseek(fd, target, SEEK_SET) != target) {
		perror("seek failed");
		close(out_fd);
		return;
	}

	for (copied = 0; copied < ntohl(sub_entry->header_entry.length); ++copied) {
		char c;
		if (read(fd, &c, sizeof(c)) != sizeof(c)) {
			perror("copy failed");
			break;
		}

		if (write(out_fd, &c, sizeof(c)) != sizeof(c)) {
			perror("write failed");
			break;
		}
	}

	close(out_fd);
}

static void analyze_firmware(const char *filename)
{
	struct stat stat;
	struct sdp_header *header;
	struct sdp_header_item *sub_entry;
	struct llist_head *entry;
	int fd;
	void *tall_firm_ctx = 0;
	int part = 0;

	entry = talloc_zero(tall_firm_ctx, struct llist_head);
	INIT_LLIST_HEAD(entry);

	printf("Opening possible firmware '%s'\n", filename);
	fd = open(filename, O_RDONLY);
	if (!fd) {
		perror("nada");
		return;
	}

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		return;
	}

	ipaccess_analyze_file(fd, stat.st_size, 0, entry);

	llist_for_each_entry(header, entry, entry) {
		printf("Printing header information:\n");
		printf("more_more_magic: 0x%x\n", ntohs(header->firmware_info.more_more_magic));
		printf("header_length: %u\n", ntohl(header->firmware_info.header_length));
		printf("file_length: %u\n", ntohl(header->firmware_info.file_length));
		printf("sw_part: %.20s\n", header->firmware_info.sw_part);
		printf("text1: %.64s\n", header->firmware_info.text1);
		printf("time: %.12s\n", header->firmware_info.time);
		printf("date: %.14s\n", header->firmware_info.date);
		printf("text2: %.10s\n", header->firmware_info.text2);
		printf("version: %.20s\n", header->firmware_info.version);
		printf("subitems...\n");

		llist_for_each_entry(sub_entry, &header->header_list, entry) {
			printf("\tsomething1: %u\n", sub_entry->header_entry.something1);
			printf("\ttext1: %.64s\n", sub_entry->header_entry.text1);
			printf("\ttime: %.12s\n", sub_entry->header_entry.time);
			printf("\tdate: %.14s\n", sub_entry->header_entry.date);
			printf("\ttext2: %.10s\n", sub_entry->header_entry.text2);
			printf("\tversion: %.20s\n", sub_entry->header_entry.version);
			printf("\tlength: %u\n", ntohl(sub_entry->header_entry.length));
			printf("\taddr1: 0x%x\n", ntohl(sub_entry->header_entry.addr1));
			printf("\taddr2: 0x%x\n", ntohl(sub_entry->header_entry.addr2));
			printf("\tstart: 0x%x\n", ntohl(sub_entry->header_entry.start));
			printf("\tabs. offset: 0x%lx\n", sub_entry->absolute_offset);
			printf("\n\n");

			dump_entry(sub_entry, part++, fd);
		}
		printf("\n\n");
	}

	if (close(fd) != 0) {
		perror("Close failed.\n");
		return;
	}

	talloc_free(tall_firm_ctx);
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
	printf("  -l --listen testnr \tPerform specified test number\n");
	printf("  -h --help this text\n");
	printf("  -s --stream-id ID\n");
	printf("  -d --software firmware\n");
	printf("  -f --firmware firmware Provide firmware information\n");
	printf("  -w --write-firmware. This will dump the firmware parts to the filesystem. Use with -f.\n");
}

int main(int argc, char **argv)
{
	struct gsm_bts *bts;
	struct sockaddr_in sin;
	int rc, option_index = 0, stream_id = 0xff;
	struct debug_target *stderr_target;

	debug_init();
	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);
	debug_set_all_filter(stderr_target, 1);
	debug_set_log_level(stderr_target, 0);
	debug_parse_category_mask(stderr_target, "DNM,0");
	bts_model_nanobts_init();

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
			{ "software", 1, 0, 'd' },
			{ "firmware", 1, 0, 'f' },
			{ "write-firmware", 0, 0, 'w' },
		};

		c = getopt_long(argc, argv, "u:o:rn:l:hs:d:f:w", long_options,
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
			break;
		case 'd':
			software = strdup(optarg);
			if (find_sw_load_params(optarg) != 0)
				exit(0);
			break;
		case 'f':
			analyze_firmware(optarg);
			exit(0);
		case 'w':
			dump_files = 1;
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
	/* ip.access supports up to 4 chained TRX */
	gsm_bts_trx_alloc(bts);
	gsm_bts_trx_alloc(bts);
	gsm_bts_trx_alloc(bts);
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

