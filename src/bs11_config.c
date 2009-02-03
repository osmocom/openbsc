/* Siemens BS-11 microBTS configuration tool */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This software is based on ideas (but not code) of BS11Config 
 * (C) 2009 by Dieter Spaar <spaar@mirider.augusta.de>
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/select.h>

/* state of our bs11_config application */
enum bs11cfg_state {
	STATE_NONE,
	STATE_LOGON_WAIT,
	STATE_LOGON_ACK,
	STATE_SWLOAD,
};
static enum bs11cfg_state bs11cfg_state = STATE_NONE;

static const u_int8_t obj_li_attr[] = { 
	NM_ATT_BS11_BIT_ERR_THESH, 0x09, 0x00,
	NM_ATT_BS11_L1_PROT_TYPE, 0x00, 
	NM_ATT_BS11_LINE_CFG, 0x00,
};
static const u_int8_t obj_bbsig0_attr[] = {
	NM_ATT_BS11_RSSI_OFFS, 0x02, 0x00, 0x00,
	NM_ATT_BS11_DIVERSITY, 0x01, 0x00,
};
static const u_int8_t obj_pa0_attr[] = {
	NM_ATT_BS11_TXPWR, 0x01, BS11_TRX_POWER_GSM_30mW,
};
static const char *trx1_password = "1111111111";
#define TEI_OML	25

static const u_int8_t too_fast[] = { 0x12, 0x80, 0x00, 0x00, 0x02, 0x02 };


int handle_serial_msg(struct msgb *rx_msg);

static int create_trx1_objects(struct gsm_bts *bts)
{
	u_int8_t bbsig1_attr[sizeof(obj_bbsig0_attr)+12];
	u_int8_t *cur = bbsig1_attr;
	
	abis_nm_bs11_set_trx1_pw(bts, trx1_password);

	cur = tlv_put(cur, NM_ATT_BS11_PASSWORD, 10,
		      (u_int8_t *)trx1_password);
	memcpy(cur, obj_bbsig0_attr, sizeof(obj_bbsig0_attr));
	abis_nm_bs11_create_object(bts, BS11_OBJ_BBSIG, 1,
				   sizeof(bbsig1_attr), bbsig1_attr);

	abis_nm_bs11_create_object(bts, BS11_OBJ_PA, 1,
				   sizeof(obj_pa0_attr), obj_pa0_attr);

	abis_nm_bs11_set_trx_power(&bts->trx[1], BS11_TRX_POWER_GSM_30mW);

	return 0;
}

/* create all objects for an initial configuration */
static int create_objects(struct gsm_bts *bts)
{
	abis_nm_bs11_create_object(bts, BS11_OBJ_LI, 0, sizeof(obj_li_attr),
				   obj_li_attr);
	abis_nm_bs11_create_object(bts, BS11_OBJ_GPSU, 0, 0, NULL);
	abis_nm_bs11_create_object(bts, BS11_OBJ_ALCO, 0, 0, NULL);
	abis_nm_bs11_create_object(bts, BS11_OBJ_CCLK, 0, 0, NULL);
	abis_nm_bs11_create_object(bts, BS11_OBJ_BBSIG, 0,
				   sizeof(obj_bbsig0_attr), obj_bbsig0_attr);
	abis_nm_bs11_create_object(bts, BS11_OBJ_PA, 0,
				   sizeof(obj_pa0_attr), obj_pa0_attr);
	abis_nm_bs11_create_envaBTSE(bts, 0);
	abis_nm_bs11_create_envaBTSE(bts, 1);
	abis_nm_bs11_create_envaBTSE(bts, 2);
	abis_nm_bs11_create_envaBTSE(bts, 3);

	abis_nm_bs11_conn_oml(bts, 0, 1, 0xff);
	abis_nm_bs11_set_oml_tei(bts, TEI_OML);

	abis_nm_bs11_set_trx_power(&bts->trx[0], BS11_TRX_POWER_GSM_30mW);
	
	return 0;
}

static char *serial_port = "/dev/ttyUSB0";
static char *fname_safety = "BTSBMC76.SWI";
static char *fname_software = "HS011106.SWL";
static int delay_ms = 0;
static int have_trx1 = 0;
static int win_size = 8;
static int param_disconnect = 0;
static int param_forced = 0;
static struct gsm_bts *g_bts;

static int file_is_readable(const char *fname)
{
	int rc;
	struct stat st;

	rc = stat(fname, &st);
	if (rc < 0)
		return 0;

	if (S_ISREG(st.st_mode) && (st.st_mode & S_IRUSR))
		return 1;

	return 0;
}

static int percent;
static int percent_old;

/* callback function passed to the ABIS OML code */
static int swload_cbfn(unsigned int hook, unsigned int event, struct msgb *msg,
		       void *data, void *param)
{
	if (hook != GSM_HOOK_NM_SWLOAD)
		return 0;

	switch (event) {
	case NM_MT_LOAD_INIT_ACK:
		fprintf(stdout, "Software Load Initiate ACK\n");
		break;
	case NM_MT_LOAD_INIT_NACK:
		fprintf(stderr, "ERROR: Software Load Initiate NACK\n");
		exit(5);
		break;
	case NM_MT_LOAD_END_ACK:
		/* FIXME: activate in case we want to */
		if (data)
			abis_nm_software_activate(g_bts, fname_safety,
						  swload_cbfn, g_bts);
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
		bs11cfg_state = STATE_NONE;
		
		break;
	case NM_MT_LOAD_SEG_ACK:
		percent = abis_nm_software_load_status(g_bts);
		if (percent > percent_old)
			printf("Software Download Progress: %d%%\n", percent);
		percent_old = percent;
		break;
	}
	return 0;
}

static const char *bs11_link_state[] = {
	[0x00]	= "Down",
	[0x01]	= "Up",
	[0x02]	= "Restoring",
};

static const char *linkstate_name(u_int8_t linkstate)
{
	if (linkstate > ARRAY_SIZE(bs11_link_state))
		return "Unknown";

	return bs11_link_state[linkstate];
}

static const char *mbccu_load[] = {
	[0]	= "No Load",
	[1]	= "Load BTSCAC",
	[2]	= "Load BTSDRX",
	[3]	= "Load BTSBBX",
	[4]	= "Load BTSARC",
	[5]	= "Load",
};

static const char *mbccu_load_name(u_int8_t linkstate)
{
	if (linkstate > ARRAY_SIZE(mbccu_load))
		return "Unknown";

	return mbccu_load[linkstate];
}


static void print_state(struct abis_nm_bs11_state *st)
{
	enum abis_bs11_phase phase = st->phase;

	printf("Abis-link: %-9s MBCCU0: %-11s MBCCU1: %-11s PHASE: %u ",
		linkstate_name(st->abis_link & 0xf),
		mbccu_load_name(st->mbccu >> 4), mbccu_load_name(st->mbccu & 0xf),
		phase & 0xf);

	switch (phase) {
	case BS11_STATE_WARM_UP:
	case BS11_STATE_WARM_UP_2:
		printf("Warm Up...\n");
		break;
	case BS11_STATE_LOAD_SMU_SAFETY:
		printf("Load SMU Safety...\n");
		break;
	case BS11_STATE_LOAD_SMU_INTENDED:
		printf("Load SMU Intended...\n");
		break;
	case BS11_STATE_LOAD_MBCCU:
		printf("Load MBCCU...\n");
		break;
	case BS11_STATE_SOFTWARE_RQD:
		printf("Software required...\n");
		break;
	case BS11_STATE_WAIT_MIN_CFG:
	case BS11_STATE_WAIT_MIN_CFG_2:
		printf("Wait minimal config...\n");
		break;
	case BS11_STATE_MAINTENANCE:
		printf("Maintenance...\n");
		break;
	case BS11_STATE_NORMAL:
		printf("Normal...\n");
		break;
	default:
		printf("Unknown phase 0x%02x\n", phase);
		break;
	}
}

/* handle a response from the BTS to a GET STATE command */
static int handle_state_resp(enum abis_bs11_phase state)
{
	int rc = 0;

	switch (state) {
	case BS11_STATE_WARM_UP:
	case BS11_STATE_LOAD_SMU_SAFETY:
	case BS11_STATE_LOAD_SMU_INTENDED:
	case BS11_STATE_LOAD_MBCCU:
		sleep(5);
		break;
	case BS11_STATE_SOFTWARE_RQD:
		bs11cfg_state = STATE_SWLOAD;
		/* send safety load. Use g_bts as private 'param'
		 * argument, so our swload_cbfn can distinguish
		 * a safety load from a regular software */
		if (file_is_readable(fname_safety))
			rc = abis_nm_software_load(g_bts, fname_safety,
						   win_size, param_forced,
						   swload_cbfn, g_bts);
		else
			fprintf(stderr, "No valid Safety Load file \"%s\"\n",
				fname_safety);
		break;
	case BS11_STATE_WAIT_MIN_CFG:
	case BS11_STATE_WAIT_MIN_CFG_2:
		bs11cfg_state = STATE_SWLOAD;
		rc = create_objects(g_bts);
		break;
	case BS11_STATE_MAINTENANCE:
		if (bs11cfg_state != STATE_SWLOAD) {
			bs11cfg_state = STATE_SWLOAD;
			/* send software (FIXME: over A-bis?) */
			if (file_is_readable(fname_software))
				rc = abis_nm_bs11_load_swl(g_bts, fname_software,
							   win_size, param_forced,
							   swload_cbfn);
			else
				fprintf(stderr, "No valid Software file \"%s\"\n",
					fname_software);
		}
		break;
	case BS11_STATE_NORMAL:
		if (have_trx1)
			create_trx1_objects(g_bts);
		//return 1;
	default:
		sleep(5);
		break;
	}
	return rc;
}

/* handle a fully-received message/packet from the RS232 port */
int handle_serial_msg(struct msgb *rx_msg)
{
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	struct abis_nm_bs11_state *st;
	int rc = -1;

#if 0
	if (rx_msg->len < LAPD_HDR_LEN
			  + sizeof(struct abis_om_fom_hdr)
			  + sizeof(struct abis_om_hdr)) {
		if (!memcmp(rx_msg->data + 2, too_fast,
			    sizeof(too_fast))) {
			fprintf(stderr, "BS11 tells us we're too "
				"fast, try --delay bigger than %u\n",
				delay_ms);
			return -E2BIG;
		} else
			fprintf(stderr, "unknown BS11 message\n");
	}
#endif

	oh = (struct abis_om_hdr *) msgb_l2(rx_msg);
	foh = (struct abis_om_fom_hdr *) oh->data;
	switch (foh->msg_type) {
	case NM_MT_BS11_LMT_LOGON_ACK:
		printf("LMT LOGON: ACK\n");
		if (bs11cfg_state == STATE_NONE)
			bs11cfg_state = STATE_LOGON_ACK;
		rc = 0;
		break;
	case NM_MT_BS11_LMT_LOGOFF_ACK:
		exit(0);
		break;
	case NM_MT_BS11_GET_STATE_ACK:
		st = (struct abis_nm_bs11_state *) &foh->data[0];
		print_state(st);
		rc = handle_state_resp(st->phase);
		break;
	default:
		rc = abis_nm_rcvmsg(rx_msg);
	}
	if (rc < 0) {
		perror("ERROR in main loop");
		//break;
	}
	if (rc == 1)
		return rc;

	switch (bs11cfg_state) {
	case STATE_NONE:
		abis_nm_bs11_factory_logon(g_bts, 1);
		break;
	case STATE_LOGON_ACK:
		abis_nm_bs11_get_state(g_bts);
		break;
	default:
		break;
	}

	return rc;
}

static void print_banner(void)
{
	printf("bs11_config (C) 2009 by Harald Welte and Dieter Spaar\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");
}

static void print_help(void)
{
	printf("Supported arguments:\n");
	printf("\t-h --help\t\t\tPrint this help text\n");
	printf("\t-p --port </dev/ttyXXX>\t\tSpecify serial port\n");
	printf("\t-t --with-trx1\t\t\tAssume the BS-11 has 2 TRX\n");
	printf("\t-s --software <file>\t\tSpecify Software file\n");
	printf("\t-S --safety <file>\t\tSpecify Safety Load file\n");
	printf("\t-d --delay <file>\t\tSpecify delay\n");
	printf("\t-D --disconnect\t\t\tDisconnect BTS from BSC\n");
	printf("\t-w --win-size <num>\t\tSpecify Window Size\n");
	printf("\t-f --forced\t\t\tForce Software Load\n");
}

static void handle_options(int argc, char **argv)
{
	print_banner();

	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "port", 1, 0, 'p' },
			{ "with-trx1", 0, 0, 't' },
			{ "software", 1, 0, 's' },
			{ "safety", 1, 0, 'S' },
			{ "delay", 1, 0, 'd' },
			{ "disconnect", 0, 0, 'D' },
			{ "win-size", 1, 0, 'w' },
			{ "forced", 0, 0, 'f' },
		};

		c = getopt_long(argc, argv, "hp:s:S:td:Dw:f",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
		case 'p':
			serial_port = optarg;
			break;
		case 't':
			have_trx1 = 1;
			break;
		case 's':
			fname_software = optarg;
			break;
		case 'S':
			fname_safety = optarg;
			break;
		case 'd':
			delay_ms = atoi(optarg);
			break;
		case 'w':
			win_size = atoi(optarg);
			break;
		case 'D':
			param_disconnect = 1;
			break;
		case 'f':
			param_forced = 1;
			break;
		default:
			break;
		}
	}
}

static int num_sigint;

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		num_sigint++;
		abis_nm_bs11_factory_logon(g_bts, 0);
		if (num_sigint >= 3)
			exit(0);
		break;
	}
}

int main(int argc, char **argv)
{
	struct gsm_network *gsmnet;
	int rc;

	handle_options(argc, argv);

	gsmnet = gsm_network_init(1, 1, 1);
	if (!gsmnet) {
		fprintf(stderr, "Unable to allocate gsm network\n");
		exit(1);
	}
	g_bts = &gsmnet->bts[0];

	rc = rs232_setup(serial_port, delay_ms);
	if (rc < 0) {
		fprintf(stderr, "Problem setting up serial port\n");
		exit(1);
	}

	signal(SIGINT, &signal_handler);

	abis_nm_bs11_factory_logon(g_bts, 1);
	//abis_nm_bs11_get_serno(g_bts);

	if (param_disconnect)
		abis_nm_bs11_bsc_disconnect(g_bts, 0);

	while (1) {
		bsc_select_main();
	}

	abis_nm_bs11_factory_logon(g_bts, 0);

	exit(0);
}
