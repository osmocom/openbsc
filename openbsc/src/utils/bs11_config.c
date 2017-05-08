/* Siemens BS-11 microBTS configuration tool */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This software is based on ideas (but not code) of BS11Config
 * (C) 2009 by Dieter Spaar <spaar@mirider.augusta.de>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/stat.h>

#include <openbsc/common_bsc.h>
#include <openbsc/abis_nm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>
#include <openbsc/debug.h>
#include <osmocom/core/select.h>
#include <openbsc/rs232.h>
#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>

static void *tall_bs11cfg_ctx;
static struct e1inp_sign_link *oml_link;

/* state of our bs11_config application */
enum bs11cfg_state {
	STATE_NONE,
	STATE_LOGON_WAIT,
	STATE_LOGON_ACK,
	STATE_SWLOAD,
	STATE_QUERY,
};
static enum bs11cfg_state bs11cfg_state = STATE_NONE;
static char *command, *value;
struct osmo_timer_list status_timer;

static const uint8_t obj_li_attr[] = {
	NM_ATT_BS11_BIT_ERR_THESH, 0x09, 0x00,
	NM_ATT_BS11_L1_PROT_TYPE, 0x00,
	NM_ATT_BS11_LINE_CFG, 0x00,
};
static const uint8_t obj_bbsig0_attr[] = {
	NM_ATT_BS11_RSSI_OFFS, 0x02, 0x00, 0x00,
	NM_ATT_BS11_DIVERSITY, 0x01, 0x00,
};
static const uint8_t obj_pa0_attr[] = {
	NM_ATT_BS11_TXPWR, 0x01, BS11_TRX_POWER_GSM_30mW,
};
static const char *trx1_password = "1111111111";
#define TEI_OML	25

/* dummy function to keep gsm_data.c happy */
struct osmo_counter *osmo_counter_alloc(const char *name)
{
	return NULL;
}

int handle_serial_msg(struct msgb *rx_msg);

/* create all objects for an initial configuration */
static int create_objects(struct gsm_bts *bts)
{
	fprintf(stdout, "Crating Objects for minimal config\n");
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

	abis_nm_bs11_conn_oml_tei(bts, 0, 1, 0xff, TEI_OML);

	abis_nm_bs11_set_trx_power(bts->c0, BS11_TRX_POWER_GSM_30mW);
	
	sleep(1);

	abis_nm_bs11_set_trx1_pw(bts, trx1_password);

	sleep(1);

	return 0;
}

static int create_trx1(struct gsm_bts *bts)
{
	uint8_t bbsig1_attr[sizeof(obj_bbsig0_attr)+12];
	uint8_t *cur = bbsig1_attr;
	struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, 1);

	if (!trx)
		trx = gsm_bts_trx_alloc(bts);

	fprintf(stdout, "Crating Objects for TRX1\n");

	abis_nm_bs11_set_trx1_pw(bts, trx1_password);

	sleep(1);

	cur = tlv_put(cur, NM_ATT_BS11_PASSWORD, 10,
		      (uint8_t *)trx1_password);
	memcpy(cur, obj_bbsig0_attr, sizeof(obj_bbsig0_attr));
	abis_nm_bs11_create_object(bts, BS11_OBJ_BBSIG, 1,
				   sizeof(bbsig1_attr), bbsig1_attr);
	abis_nm_bs11_create_object(bts, BS11_OBJ_PA, 1,
				   sizeof(obj_pa0_attr), obj_pa0_attr);
	abis_nm_bs11_set_trx_power(trx, BS11_TRX_POWER_GSM_30mW);
	
	return 0;
}

static char *serial_port = "/dev/ttyUSB0";
static char *fname_safety = "BTSBMC76.SWI";
static char *fname_software = "HS011106.SWL";
static int delay_ms = 0;
static int win_size = 8;
static int param_disconnect = 0;
static int param_restart = 0;
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
		if (data) {
			/* we did a safety load and must activate it */
			abis_nm_software_activate(g_bts, fname_safety,
						  swload_cbfn, g_bts);
			sleep(5);
		}
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

static const struct value_string bs11_linkst_names[] = {
	{ 0,	"Down" },
	{ 1,	"Up" },
	{ 2,	"Restoring" },
	{ 0,	NULL }
};

static const char *linkstate_name(uint8_t linkstate)
{
	return get_value_string(bs11_linkst_names, linkstate);
}

static const struct value_string mbccu_load_names[] = {
	{ 0,	"No Load" },
	{ 1,	"Load BTSCAC" },
	{ 2,	"Load BTSDRX" },
	{ 3,	"Load BTSBBX" },
	{ 4,	"Load BTSARC" },
	{ 5,	"Load" },
	{ 0,	NULL }
};

static const char *mbccu_load_name(uint8_t linkstate)
{
	return get_value_string(mbccu_load_names, linkstate);
}

static const char *bts_phase_name(uint8_t phase)
{
	switch (phase) {
	case BS11_STATE_WARM_UP:
	case BS11_STATE_WARM_UP_2:
		return "Warm Up";
		break;
	case BS11_STATE_LOAD_SMU_SAFETY:
		return "Load SMU Safety";
		break;
	case BS11_STATE_LOAD_SMU_INTENDED:
		return "Load SMU Intended";
		break;
	case BS11_STATE_LOAD_MBCCU:
		return "Load MBCCU";
		break;
	case BS11_STATE_SOFTWARE_RQD:
		return "Software required";
		break;
	case BS11_STATE_WAIT_MIN_CFG:
	case BS11_STATE_WAIT_MIN_CFG_2:
		return "Wait minimal config";
		break;
	case BS11_STATE_MAINTENANCE:
		return "Maintenance";
		break;
	case BS11_STATE_NORMAL:
		return "Normal";
		break;
	case BS11_STATE_ABIS_LOAD:
		return "Abis load";
		break;
	default:
		return "Unknown";
		break;
	}
}

static const char *trx_power_name(uint8_t pwr)
{
	switch (pwr) {
	case BS11_TRX_POWER_GSM_2W:	
		return "2W (GSM)";
	case BS11_TRX_POWER_GSM_250mW:
		return "250mW (GSM)";
	case BS11_TRX_POWER_GSM_80mW:
		return "80mW (GSM)";
	case BS11_TRX_POWER_GSM_30mW:
		return "30mW (GSM)";
	case BS11_TRX_POWER_DCS_3W:
		return "3W (DCS)";
	case BS11_TRX_POWER_DCS_1W6:
		return "1.6W (DCS)";
	case BS11_TRX_POWER_DCS_500mW:
		return "500mW (DCS)";
	case BS11_TRX_POWER_DCS_160mW:
		return "160mW (DCS)";
	default:
		return "unknown value";
	}
}

static const char *pll_mode_name(uint8_t mode)
{
	switch (mode) {
	case BS11_LI_PLL_LOCKED:
		return "E1 Locked";
	case BS11_LI_PLL_STANDALONE:
		return "Standalone";
	default:
		return "unknown";
	}
}

static const char *cclk_acc_name(uint8_t acc)
{
	switch (acc) {
	case 0:
		/* Out of the demanded +/- 0.05ppm */
		return "Medium";
	case 1:
		/* Synchronized with Abis, within demanded tolerance +/- 0.05ppm */
		return "High";
	default:
		return "unknown";
	}
}

static const char *bport_lcfg_name(uint8_t lcfg)
{
	switch (lcfg) {
	case BS11_LINE_CFG_STAR:
		return "Star";
	case BS11_LINE_CFG_MULTIDROP:
		return "Multi-Drop";
	default:
		return "unknown";
	}
}

static const char *obj_name(struct abis_om_fom_hdr *foh)
{
	static char retbuf[256];

	retbuf[0] = 0;

	switch (foh->obj_class) {
	case NM_OC_BS11:
		strcat(retbuf, "BS11 ");
		switch (foh->obj_inst.bts_nr) {
		case BS11_OBJ_PA:
			sprintf(retbuf+strlen(retbuf), "Power Amplifier %d ",
				foh->obj_inst.ts_nr);
			break;
		case BS11_OBJ_LI:
			sprintf(retbuf+strlen(retbuf), "Line Interface ");
			break;
		case BS11_OBJ_CCLK:
			sprintf(retbuf+strlen(retbuf), "CCLK ");
			break;
		}
		break;
	case NM_OC_SITE_MANAGER:
		strcat(retbuf, "SITE MANAGER ");
		break;
	case NM_OC_BS11_BPORT:
		sprintf(retbuf+strlen(retbuf), "BPORT%u ",
			foh->obj_inst.bts_nr);
		break;
	}
	return retbuf;
}

static void print_state(struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, NM_ATT_BS11_BTS_STATE)) {
		uint8_t phase, mbccu;
		if (TLVP_LEN(tp, NM_ATT_BS11_BTS_STATE) >= 1) {
			phase = *TLVP_VAL(tp, NM_ATT_BS11_BTS_STATE);
			printf("PHASE: %u %-20s ", phase & 0xf,
				bts_phase_name(phase));
		}
		if (TLVP_LEN(tp, NM_ATT_BS11_BTS_STATE) >= 2) {
			mbccu = *(TLVP_VAL(tp, NM_ATT_BS11_BTS_STATE)+1);
			printf("MBCCU0: %-11s MBCCU1: %-11s ",
				mbccu_load_name(mbccu & 0xf), mbccu_load_name(mbccu >> 4));
		}
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_E1_STATE) &&
	    TLVP_LEN(tp, NM_ATT_BS11_E1_STATE) >= 1) {
		uint8_t e1_state = *TLVP_VAL(tp, NM_ATT_BS11_E1_STATE);
		printf("Abis-link: %-9s ", linkstate_name(e1_state & 0xf));
	}
	printf("\n");
}

static int print_attr(struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, NM_ATT_BS11_ESN_PCB_SERIAL)) {
		printf("\tBS-11 ESN PCB Serial Number: %s\n",
			TLVP_VAL(tp, NM_ATT_BS11_ESN_PCB_SERIAL));
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_ESN_HW_CODE_NO)) {
		printf("\tBS-11 ESN Hardware Code Number: %s\n",
			TLVP_VAL(tp, NM_ATT_BS11_ESN_HW_CODE_NO)+6);
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_ESN_FW_CODE_NO)) {
		printf("\tBS-11 ESN Firmware Code Number: %s\n",
			TLVP_VAL(tp, NM_ATT_BS11_ESN_FW_CODE_NO)+6);
	}
#if 0
	if (TLVP_PRESENT(tp, NM_ATT_BS11_BOOT_SW_VERS)) {
		printf("BS-11 Boot Software Version: %s\n",
			TLVP_VAL(tp, NM_ATT_BS11_BOOT_SW_VERS)+6);
	}
#endif
	if (TLVP_PRESENT(tp, NM_ATT_ABIS_CHANNEL) &&
	    TLVP_LEN(tp, NM_ATT_ABIS_CHANNEL) >= 3) {
		const uint8_t *chan = TLVP_VAL(tp, NM_ATT_ABIS_CHANNEL);
		printf("\tE1 Channel: Port=%u Timeslot=%u ",
			chan[0], chan[1]);
		if (chan[2] == 0xff)
			printf("(Full Slot)\n");
		else
			printf("Subslot=%u\n", chan[2]);
	}
	if (TLVP_PRESENT(tp, NM_ATT_TEI))
		printf("\tTEI: %d\n", *TLVP_VAL(tp, NM_ATT_TEI));
	if (TLVP_PRESENT(tp, NM_ATT_BS11_TXPWR) &&
	    TLVP_LEN(tp, NM_ATT_BS11_TXPWR) >= 1) {
		printf("\tTRX Power: %s\n",
			trx_power_name(*TLVP_VAL(tp, NM_ATT_BS11_TXPWR)));
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_PLL_MODE) &&
	    TLVP_LEN(tp, NM_ATT_BS11_PLL_MODE) >= 1) {
		printf("\tPLL Mode: %s\n",
			pll_mode_name(*TLVP_VAL(tp, NM_ATT_BS11_PLL_MODE)));
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_PLL) &&
	    TLVP_LEN(tp, NM_ATT_BS11_PLL) >= 4) {
		const uint8_t *vp = TLVP_VAL(tp, NM_ATT_BS11_PLL);
		printf("\tPLL Set Value=%d, Work Value=%d\n",
			vp[0] << 8 | vp[1], vp[2] << 8 | vp[3]);
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_CCLK_ACCURACY) &&
	    TLVP_LEN(tp, NM_ATT_BS11_CCLK_ACCURACY) >= 1) {
		const uint8_t *acc = TLVP_VAL(tp, NM_ATT_BS11_CCLK_ACCURACY);
		printf("\tCCLK Accuracy: %s (%d)\n", cclk_acc_name(*acc), *acc);
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_CCLK_TYPE) &&
	    TLVP_LEN(tp, NM_ATT_BS11_CCLK_TYPE) >= 1) {
		const uint8_t *acc = TLVP_VAL(tp, NM_ATT_BS11_CCLK_TYPE);
		printf("\tCCLK Type=%d\n", *acc);
	}
	if (TLVP_PRESENT(tp, NM_ATT_BS11_LINE_CFG) &&
	    TLVP_LEN(tp, NM_ATT_BS11_LINE_CFG) >= 1) {
		const uint8_t *lcfg = TLVP_VAL(tp, NM_ATT_BS11_LINE_CFG);
		printf("\tLine Configuration: %s (%d)\n",
			bport_lcfg_name(*lcfg), *lcfg);
	}



	return 0;
}

static void cmd_query(void)
{
	struct gsm_bts_trx *trx = g_bts->c0;

	bs11cfg_state = STATE_QUERY;
	abis_nm_bs11_get_serno(g_bts);
	abis_nm_bs11_get_oml_tei_ts(g_bts);
	abis_nm_bs11_get_pll_mode(g_bts);
	abis_nm_bs11_get_cclk(g_bts);
	abis_nm_bs11_get_trx_power(trx);
	trx = gsm_bts_trx_num(g_bts, 1);
	if (trx)
		abis_nm_bs11_get_trx_power(trx);
	abis_nm_bs11_get_bport_line_cfg(g_bts, 0);
	abis_nm_bs11_get_bport_line_cfg(g_bts, 1);
	sleep(1);
	abis_nm_bs11_factory_logon(g_bts, 0);
	command = NULL;
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
		break;
	case BS11_STATE_SOFTWARE_RQD:
		bs11cfg_state = STATE_SWLOAD;
		/* send safety load. Use g_bts as private 'param'
		 * argument, so our swload_cbfn can distinguish
		 * a safety load from a regular software */
		if (file_is_readable(fname_safety))
			rc = abis_nm_software_load(g_bts, 0xff, fname_safety,
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
		if (command) {
			if (!strcmp(command, "disconnect"))
				abis_nm_bs11_factory_logon(g_bts, 0);
			else if (!strcmp(command, "reconnect"))
				rc = abis_nm_bs11_bsc_disconnect(g_bts, 1);
			else if (!strcmp(command, "software")
			    && bs11cfg_state != STATE_SWLOAD) {
				bs11cfg_state = STATE_SWLOAD;
				/* send software (FIXME: over A-bis?) */
				if (file_is_readable(fname_software))
					rc = abis_nm_bs11_load_swl(g_bts, fname_software,
								   win_size, param_forced,
								   swload_cbfn);
				else
					fprintf(stderr, "No valid Software file \"%s\"\n",
						fname_software);
			} else if (!strcmp(command, "delete-trx1")) {
				printf("Locing BBSIG and PA objects of TRX1\n");
				abis_nm_chg_adm_state(g_bts, NM_OC_BS11,
						      BS11_OBJ_BBSIG, 0, 1,
						      NM_STATE_LOCKED);
				abis_nm_chg_adm_state(g_bts, NM_OC_BS11,
						      BS11_OBJ_PA, 0, 1,
						      NM_STATE_LOCKED);
				sleep(1);
				printf("Deleting BBSIG and PA objects of TRX1\n");
				abis_nm_bs11_delete_object(g_bts, BS11_OBJ_BBSIG, 1);
				abis_nm_bs11_delete_object(g_bts, BS11_OBJ_PA, 1);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "create-trx1")) {
				create_trx1(g_bts);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "pll-e1-locked")) {
				abis_nm_bs11_set_pll_locked(g_bts, 1);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "pll-standalone")) {
				abis_nm_bs11_set_pll_locked(g_bts, 0);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "pll-setvalue")) {
				abis_nm_bs11_set_pll(g_bts, atoi(value));
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "pll-workvalue")) {
				/* To set the work value we need to login as FIELD */
				abis_nm_bs11_factory_logon(g_bts, 0);
				sleep(1);
				abis_nm_bs11_infield_logon(g_bts, 1);
				sleep(1);
				abis_nm_bs11_set_pll(g_bts, atoi(value));
				sleep(1);
				abis_nm_bs11_infield_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "oml-tei")) {
				abis_nm_bs11_conn_oml_tei(g_bts, 0, 1, 0xff, TEI_OML);
				command = NULL;
			} else if (!strcmp(command, "restart")) {
				abis_nm_bs11_restart(g_bts);
				command = NULL;
			} else if (!strcmp(command, "query")) {
				cmd_query();
			} else if (!strcmp(command, "create-bport1")) {
				abis_nm_bs11_create_bport(g_bts, 1);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "delete-bport1")) {
				abis_nm_chg_adm_state(g_bts, NM_OC_BS11_BPORT, 1, 0xff, 0xff, NM_STATE_LOCKED);
				sleep(1);
				abis_nm_bs11_delete_bport(g_bts, 1);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "bport0-star")) {
				abis_nm_bs11_set_bport_line_cfg(g_bts, 0, BS11_LINE_CFG_STAR);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "bport0-multidrop")) {
				abis_nm_bs11_set_bport_line_cfg(g_bts, 0, BS11_LINE_CFG_MULTIDROP);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			} else if (!strcmp(command, "bport1-multidrop")) {
				abis_nm_bs11_set_bport_line_cfg(g_bts, 1, BS11_LINE_CFG_MULTIDROP);
				sleep(1);
				abis_nm_bs11_factory_logon(g_bts, 0);
				command = NULL;
			}

		}
		break;
	case BS11_STATE_NORMAL:
		if (command) {
			if (!strcmp(command, "reconnect"))
				abis_nm_bs11_factory_logon(g_bts, 0);
			else if (!strcmp(command, "disconnect"))
				abis_nm_bs11_bsc_disconnect(g_bts, 0);
			else if (!strcmp(command, "query")) {
				cmd_query();
			}
		} else if (param_disconnect) {
			param_disconnect = 0;
			abis_nm_bs11_bsc_disconnect(g_bts, 0);
			if (param_restart) {
				param_restart = 0;
				abis_nm_bs11_restart(g_bts);
			}
		}
		break;
	default:
		break;
	}
	return rc;
}

/* handle a fully-received message/packet from the RS232 port */
static int abis_nm_bs11cfg_rcvmsg(struct msgb *rx_msg)
{
	struct e1inp_sign_link *link = rx_msg->dst;
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	struct tlv_parsed tp;
	int rc = -1;

#if 0
	const uint8_t too_fast[] = { 0x12, 0x80, 0x00, 0x00, 0x02, 0x02 };

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
		printf("LMT LOGON: ACK\n\n");
		if (bs11cfg_state == STATE_NONE)
			bs11cfg_state = STATE_LOGON_ACK;
		rc = abis_nm_bs11_get_state(g_bts);
		break;
	case NM_MT_BS11_LMT_LOGOFF_ACK:
		printf("LMT LOGOFF: ACK\n");
		exit(0);
		break;
	case NM_MT_BS11_GET_STATE_ACK:
		rc = abis_nm_tlv_parse(&tp, g_bts, foh->data, oh->length-sizeof(*foh));
		print_state(&tp);
		if (TLVP_PRESENT(&tp, NM_ATT_BS11_BTS_STATE) &&
		    TLVP_LEN(&tp, NM_ATT_BS11_BTS_STATE) >= 1)
			rc = handle_state_resp(*TLVP_VAL(&tp, NM_ATT_BS11_BTS_STATE));
		break;
	case NM_MT_GET_ATTR_RESP:
		printf("\n%sATTRIBUTES:\n", obj_name(foh));
		abis_nm_tlv_parse(&tp, g_bts, foh->data, oh->length-sizeof(*foh));
		rc = print_attr(&tp);
		//osmo_hexdump(foh->data, oh->length-sizeof(*foh));
		break;
	case NM_MT_BS11_SET_ATTR_ACK:
		printf("SET ATTRIBUTE ObjClass=0x%02x ObjInst=(%d,%d,%d) ACK\n",
			foh->obj_class, foh->obj_inst.bts_nr,
			foh->obj_inst.trx_nr, foh->obj_inst.ts_nr);
		rc = 0;
		break;
	case NM_MT_BS11_SET_ATTR_NACK:
		printf("SET ATTRIBUTE ObjClass=0x%02x ObjInst=(%d,%d,%d) NACK\n",
			foh->obj_class, foh->obj_inst.bts_nr,
			foh->obj_inst.trx_nr, foh->obj_inst.ts_nr);
		break;
	case NM_MT_GET_ATTR_NACK:
		printf("\n%sGET ATTR NACK\n", obj_name(foh));
		break;
	case NM_MT_BS11_CREATE_OBJ_ACK:
		printf("\n%sCREATE OBJECT ACK\n", obj_name(foh));
		break;
	case NM_MT_BS11_CREATE_OBJ_NACK:
		printf("\n%sCREATE OBJECT NACK\n", obj_name(foh));
		break;
	case NM_MT_BS11_DELETE_OBJ_ACK:
		printf("\n%sDELETE OBJECT ACK\n", obj_name(foh));
		break;
	case NM_MT_BS11_DELETE_OBJ_NACK:
		printf("\n%sDELETE OBJECT NACK\n", obj_name(foh));
		break;
	default:
		rc = abis_nm_rcvmsg(rx_msg);
	}
	if (rc < 0) {
		perror("ERROR in main loop");
		//break;
	}
	/* flush the queue of pending messages to be sent. */
	abis_nm_queue_send_next(link->trx->bts);
	if (rc == 1)
		return rc;

	switch (bs11cfg_state) {
	case STATE_NONE:
		abis_nm_bs11_factory_logon(g_bts, 1);
		break;
	case STATE_LOGON_ACK:
		osmo_timer_schedule(&status_timer, 5, 0);
		break;
	default:
		break;
	}

	return rc;
}

void status_timer_cb(void *data)
{
	abis_nm_bs11_get_state(g_bts);
}

static void print_banner(void)
{
	printf("bs11_config (C) 2009-2010 by Harald Welte and Dieter Spaar\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");
}

static void print_help(void)
{
	printf("bs11_config [options] [command]\n");
	printf("\nSupported options:\n");
	printf("\t-h --help\t\t\tPrint this help text\n");
	printf("\t-p --port </dev/ttyXXX>\t\tSpecify serial port\n");
	printf("\t-s --software <file>\t\tSpecify Software file\n");
	printf("\t-S --safety <file>\t\tSpecify Safety Load file\n");
	printf("\t-d --delay <ms>\t\t\tSpecify delay in milliseconds\n");
	printf("\t-D --disconnect\t\t\tDisconnect BTS from BSC\n");
	printf("\t-w --win-size <num>\t\tSpecify Window Size\n");
	printf("\t-f --forced\t\t\tForce Software Load\n");
	printf("\nSupported commands:\n");
	printf("\tquery\t\t\tQuery the BS-11 about serial number and configuration\n");
	printf("\tdisconnect\t\tDisconnect A-bis link (go into administrative state)\n");
	printf("\tresconnect\t\tReconnect A-bis link (go into normal state)\n");
	printf("\trestart\t\t\tRestart the BTS\n");
	printf("\tsoftware\t\tDownload Software (only in administrative state)\n");
	printf("\tcreate-trx1\t\tCreate objects for TRX1 (Danger: Your BS-11 might overheat)\n");
	printf("\tdelete-trx1\t\tDelete objects for TRX1\n");
	printf("\tpll-e1-locked\t\tSet the PLL to be locked to E1 clock\n");
	printf("\tpll-standalone\t\tSet the PLL to be in standalone mode\n");
	printf("\tpll-setvalue <value>\tSet the PLL set value\n");
	printf("\tpll-workvalue <value>\tSet the PLL work value\n");
	printf("\toml-tei\t\t\tSet OML E1 TS and TEI\n");
	printf("\tbport0-star\t\tSet BPORT0 line config to star\n");
	printf("\tbport0-multidrop\tSet BPORT0 line config to multidrop\n");
	printf("\tbport1-multidrop\tSet BPORT1 line config to multidrop\n");
	printf("\tcreate-bport1\t\tCreate BPORT1 object\n");
	printf("\tdelete-bport1\t\tDelete BPORT1 object\n");
}

static void handle_options(int argc, char **argv)
{
	int option_index = 0;
	print_banner();

	while (1) {
		int c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "port", 1, 0, 'p' },
			{ "software", 1, 0, 's' },
			{ "safety", 1, 0, 'S' },
			{ "delay", 1, 0, 'd' },
			{ "disconnect", 0, 0, 'D' },
			{ "win-size", 1, 0, 'w' },
			{ "forced", 0, 0, 'f' },
			{ "restart", 0, 0, 'r' },
			{ "debug", 1, 0, 'b'},
		};

		c = getopt_long(argc, argv, "hp:s:S:td:Dw:fra:",
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
		case 'b':
			log_parse_category_mask(osmo_stderr_target, optarg);
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
		case 'r':
			param_disconnect = 1;
			param_restart = 1;
			break;
		default:
			break;
		}
	}
	if (optind < argc) {
		command = argv[optind];
	        if (optind+1 < argc)
			value = argv[optind+1];
	}

}

static int num_sigint;

static void signal_handler(int signal)
{
	fprintf(stdout, "\nsignal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		num_sigint++;
		abis_nm_bs11_factory_logon(g_bts, 0);
		if (num_sigint >= 3)
			exit(0);
		break;
	}
}

static int bs11cfg_sign_link(struct msgb *msg)
{
	msg->dst = oml_link;
	return abis_nm_bs11cfg_rcvmsg(msg);
}

struct e1inp_line_ops bs11cfg_e1inp_line_ops = {
	.sign_link	= bs11cfg_sign_link,
};

extern int bts_model_bs11_init(void);
int main(int argc, char **argv)
{
	struct gsm_network *gsmnet;
	struct e1inp_line *line;

	tall_bs11cfg_ctx = talloc_named_const(NULL, 0, "bs11-config");
	msgb_talloc_ctx_init(tall_bs11cfg_ctx, 0);

	osmo_init_logging(&log_info);
	handle_options(argc, argv);
	bts_model_bs11_init();

	gsmnet = bsc_network_init(tall_bs11cfg_ctx, 1, 1, NULL);
	if (!gsmnet) {
		fprintf(stderr, "Unable to allocate gsm network\n");
		exit(1);
	}
	g_bts = gsm_bts_alloc_register(gsmnet, GSM_BTS_TYPE_BS11,
					HARDCODED_BSIC);

	/* Override existing OML callback handler to set our own. */
	g_bts->model->oml_rcvmsg = abis_nm_bs11cfg_rcvmsg;

	libosmo_abis_init(tall_bs11cfg_ctx);

	/* Initialize virtual E1 line over rs232. */
	line = talloc_zero(tall_bs11cfg_ctx, struct e1inp_line);
	if (!line) {
		fprintf(stderr, "Unable to allocate memory for virtual E1 line\n");
		exit(1);
	}
	/* set the serial port. */
	bs11cfg_e1inp_line_ops.cfg.rs232.port = serial_port;
	bs11cfg_e1inp_line_ops.cfg.rs232.delay = delay_ms;

	line->driver = e1inp_driver_find("rs232");
	if (!line->driver) {
		fprintf(stderr, "cannot find `rs232' driver, giving up.\n");
		exit(1);
	}
	e1inp_line_bind_ops(line, &bs11cfg_e1inp_line_ops);

	/* configure and create signalling link for OML. */
	e1inp_ts_config_sign(&line->ts[0], line);
	g_bts->oml_link = oml_link =
		e1inp_sign_link_create(&line->ts[0], E1INP_SIGN_OML,
					g_bts->c0, TEI_OML, 0);

	e1inp_line_update(line);

	signal(SIGINT, &signal_handler);

	abis_nm_bs11_factory_logon(g_bts, 1);
	//abis_nm_bs11_get_serno(g_bts);

	osmo_timer_setup(&status_timer, status_timer_cb, NULL);

	while (1) {
		if (osmo_select_main(0) < 0)
			break;
	}

	abis_nm_bs11_factory_logon(g_bts, 0);

	exit(0);
}
