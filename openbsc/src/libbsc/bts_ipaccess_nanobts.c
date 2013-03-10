/* ip.access nanoBTS specific code */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <arpa/inet.h>

#include <osmocom/gsm/tlv.h>

#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>
#include <openbsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/logging.h>
#include <openbsc/ipaccess.h>

extern struct gsm_network *bsc_gsmnet;

static int bts_model_nanobts_start(struct gsm_network *net);
static void bts_model_nanobts_e1line_bind_ops(struct e1inp_line *line);

struct gsm_bts_model bts_model_nanobts = {
	.type = GSM_BTS_TYPE_NANOBTS,
	.name = "nanobts",
	.start = bts_model_nanobts_start,
	.oml_rcvmsg = &abis_nm_rcvmsg,
	.e1line_bind_ops = bts_model_nanobts_e1line_bind_ops, 
	.nm_att_tlvdef = {
		.def = {
			/* ip.access specifics */
			[NM_ATT_IPACC_DST_IP] =		{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_DST_IP_PORT] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_STREAM_ID] =	{ TLV_TYPE_TV, },
			[NM_ATT_IPACC_SEC_OML_CFG] =	{ TLV_TYPE_FIXED, 6 },
			[NM_ATT_IPACC_IP_IF_CFG] =	{ TLV_TYPE_FIXED, 8 },
			[NM_ATT_IPACC_IP_GW_CFG] =	{ TLV_TYPE_FIXED, 12 },
			[NM_ATT_IPACC_IN_SERV_TIME] =	{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_LOCATION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PAGING_CFG] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_UNIT_ID] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UNIT_NAME] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SNMP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PRIM_OML_CFG_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NV_FLAGS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_FREQ_CTRL] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_PRIM_OML_FB_TOUT] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CUR_SW_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIMING_BUS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CGI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RAC] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_OBJ_VERSION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_GPRS_PAGING_CFG]= { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSEI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_CFG] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BSSGP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_LINK_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_ALM_THRESH_LIST]=	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_MONIT_VAL_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIB_CONTROL] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SUPP_FEATURES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CODING_SCHEMES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_2] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_HEARTB_TOUT] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UPTIME] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_3] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SSL_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SEC_POSSIBLE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_IML_SSL_STATE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_REVOC_DATE] =	{ TLV_TYPE_TL16V },
		},
	},
};

static unsigned char nanobts_attr_bts[] = {
	NM_ATT_INTERF_BOUND, 0x55, 0x5b, 0x61, 0x67, 0x6d, 0x73,
	/* interference avg. period in numbers of SACCH multifr */
	NM_ATT_INTAVE_PARAM, 0x06,
	/* conn fail based on SACCH error rate */
	NM_ATT_CONN_FAIL_CRIT, 0x00, 0x02, 0x01, 0x10,
	NM_ATT_T200, 0x1e, 0x24, 0x24, 0xa8, 0x34, 0x21, 0xa8,
	NM_ATT_MAX_TA, 0x3f,
	NM_ATT_OVERL_PERIOD, 0x00, 0x01, 10, /* seconds */
	NM_ATT_CCCH_L_T, 10, /* percent */
	NM_ATT_CCCH_L_I_P, 1, /* seconds */
	NM_ATT_RACH_B_THRESH, 10, /* busy threshold in - dBm */
	NM_ATT_LDAVG_SLOTS, 0x03, 0xe8, /* rach load averaging 1000 slots */
	NM_ATT_BTS_AIR_TIMER, 128, /* miliseconds */
	NM_ATT_NY1, 10, /* 10 retransmissions of physical config */
	NM_ATT_BCCH_ARFCN, HARDCODED_ARFCN >> 8, HARDCODED_ARFCN & 0xff,
	NM_ATT_BSIC, HARDCODED_BSIC,
	NM_ATT_IPACC_CGI, 0, 7,  0x00, 0xf1, 0x10, 0x00, 0x01, 0x00, 0x00,
};

static unsigned char nanobts_attr_radio[] = {
	NM_ATT_RF_MAXPOWR_R, 0x0c, /* number of -2dB reduction steps / Pn */
	NM_ATT_ARFCN_LIST, 0x00, 0x02, HARDCODED_ARFCN >> 8, HARDCODED_ARFCN & 0xff,
};

static unsigned char nanobts_attr_nse[] = {
	NM_ATT_IPACC_NSEI, 0, 2,  0x03, 0x9d, /* NSEI 925 */
	/* all timers in seconds */
	NM_ATT_IPACC_NS_CFG, 0, 7,  3,  /* (un)blocking timer (Tns-block) */
				    3,  /* (un)blocking retries */
				    3,  /* reset timer (Tns-reset) */
				    3,  /* reset retries */
				    30,  /* test timer (Tns-test) */
				    3,  /* alive timer (Tns-alive) */
				    10, /* alive retrires */
	/* all timers in seconds, unless otherwise stated */
	NM_ATT_IPACC_BSSGP_CFG, 0, 11,
				    3,  /* blockimg timer (T1) */
				    3,  /* blocking retries */
				    3,  /* unblocking retries */
				    3,  /* reset timer (T2) */
				    3,  /* reset retries */
				    10, /* suspend timer (T3) in 100ms */
				    3,  /* suspend retries */
				    10, /* resume timer (T4) in 100ms */
				    3,  /* resume retries */
				    10, /* capability update timer (T5) */
				    3,  /* capability update retries */
};

static unsigned char nanobts_attr_cell[] = {
	NM_ATT_IPACC_RAC, 0, 1,  1, /* routing area code */
	NM_ATT_IPACC_GPRS_PAGING_CFG, 0, 2,
		5,	/* repeat time (50ms) */
		3,	/* repeat count */
	NM_ATT_IPACC_BVCI, 0, 2,  0x03, 0x9d, /* BVCI 925 */
	/* all timers in seconds, unless otherwise stated */
	NM_ATT_IPACC_RLC_CFG, 0, 9,
		20, 	/* T3142 */
		5, 	/* T3169 */
		5,	/* T3191 */
		160,	/* T3193 (units of 10ms) */
		5,	/* T3195 */
		10,	/* N3101 */
		4,	/* N3103 */
		8,	/* N3105 */
		15,	/* RLC CV countdown */
	NM_ATT_IPACC_CODING_SCHEMES, 0, 2,  0x0f, 0x00,	/* CS1..CS4 */
	NM_ATT_IPACC_RLC_CFG_2, 0, 5,
		0x00, 250,	/* T downlink TBF extension (0..500) */
		0x00, 250,	/* T uplink TBF extension (0..500) */
		2,	/* CS2 */
#if 0
	/* EDGE model only, breaks older models.
	 * Should inquire the BTS capabilities */
	NM_ATT_IPACC_RLC_CFG_3, 0, 1,
		2,	/* MCS2 */
#endif
};

static unsigned char nanobts_attr_nsvc0[] = {
	NM_ATT_IPACC_NSVCI, 0, 2,  0x03, 0x9d, /* 925 */
	NM_ATT_IPACC_NS_LINK_CFG, 0, 8,
		0x59, 0xd8, /* remote udp port (23000) */
		192, 168, 100, 11, /* remote ip address */
		0x59, 0xd8, /* local udp port (23000) */
};

static void patch_16(uint8_t *data, const uint16_t val)
{
	memcpy(data, &val, sizeof(val));
}

static void patch_32(uint8_t *data, const uint32_t val)
{
	memcpy(data, &val, sizeof(val));
}

/*
 * Patch the various SYSTEM INFORMATION tables to update
 * the LAI
 */
static void patch_nm_tables(struct gsm_bts *bts)
{
	uint8_t arfcn_low = bts->c0->arfcn & 0xff;
	uint8_t arfcn_high = (bts->c0->arfcn >> 8) & 0x0f;

	/* patch ARFCN into BTS Attributes */
	nanobts_attr_bts[42] &= 0xf0;
	nanobts_attr_bts[42] |= arfcn_high;
	nanobts_attr_bts[43] = arfcn_low;

	/* patch the RACH attributes */
	if (bts->rach_b_thresh != -1) {
		nanobts_attr_bts[33] = bts->rach_b_thresh & 0xff;
	}

	if (bts->rach_ldavg_slots != -1) {
		uint8_t avg_high = bts->rach_ldavg_slots & 0xff;
		uint8_t avg_low = (bts->rach_ldavg_slots >> 8) & 0x0f;

		nanobts_attr_bts[35] = avg_high;
		nanobts_attr_bts[36] = avg_low;
	}

	/* patch BSIC */
	nanobts_attr_bts[sizeof(nanobts_attr_bts)-11] = bts->bsic;

	/* patch CGI */
	abis_nm_ipaccess_cgi(nanobts_attr_bts+sizeof(nanobts_attr_bts)-7, bts);

	/* patch CON_FAIL_CRIT */
	nanobts_attr_bts[13] =
		get_radio_link_timeout(&bts->si_common.cell_options);

	/* patch the power reduction */
	nanobts_attr_radio[1] = bts->c0->max_power_red / 2;

	/* patch NSEI */
	nanobts_attr_nse[3] = bts->gprs.nse.nsei >> 8;
	nanobts_attr_nse[4] = bts->gprs.nse.nsei & 0xff;
	memcpy(nanobts_attr_nse+8, bts->gprs.nse.timer,
		ARRAY_SIZE(bts->gprs.nse.timer));
	memcpy(nanobts_attr_nse+18, bts->gprs.cell.timer,
		ARRAY_SIZE(bts->gprs.cell.timer));

	/* patch NSVCI */
	nanobts_attr_nsvc0[3] = bts->gprs.nsvc[0].nsvci >> 8;
	nanobts_attr_nsvc0[4] = bts->gprs.nsvc[0].nsvci & 0xff;

	/* patch IP address as SGSN IP */
	patch_16(nanobts_attr_nsvc0 + 8, 
			htons(bts->gprs.nsvc[0].remote_port));
	patch_32(nanobts_attr_nsvc0 + 10,
			htonl(bts->gprs.nsvc[0].remote_ip));
	patch_16(nanobts_attr_nsvc0 + 14,
			htons(bts->gprs.nsvc[0].local_port));

	/* patch BVCI */
	nanobts_attr_cell[12] = bts->gprs.cell.bvci >> 8;
	nanobts_attr_cell[13] = bts->gprs.cell.bvci & 0xff;
	/* patch RAC */
	nanobts_attr_cell[3] = bts->gprs.rac;

	if (bts->gprs.mode == BTS_GPRS_EGPRS) {
		/* patch EGPRS coding schemes MCS 1..9 */
		nanobts_attr_cell[29] = 0x8f;
		nanobts_attr_cell[30] = 0xff;
	}
}

static uint8_t *nanobts_attr_bts_get(struct gsm_bts *bts, size_t *data_len)
{
	patch_nm_tables(bts);
	*data_len = sizeof(nanobts_attr_bts);
	return nanobts_attr_bts;
}

static uint8_t *nanobts_attr_nse_get(struct gsm_bts *bts, size_t *data_len)
{
	patch_nm_tables(bts);
	*data_len = sizeof(nanobts_attr_nse);
	return nanobts_attr_nse;
}

static uint8_t *nanobts_attr_cell_get(struct gsm_bts *bts, size_t *data_len)
{
	patch_nm_tables(bts);
	*data_len = sizeof(nanobts_attr_cell);
	return nanobts_attr_cell;
}

static uint8_t *nanobts_attr_nscv_get(struct gsm_bts *bts, size_t *data_len)
{
	patch_nm_tables(bts);
	*data_len = sizeof(nanobts_attr_nsvc0);
	return nanobts_attr_nsvc0;
}

static uint8_t *nanobts_attr_radio_get(struct gsm_bts *bts, size_t *data_len)
{
	patch_nm_tables(bts);
	*data_len = sizeof(nanobts_attr_radio);
	return nanobts_attr_radio;
}

/* Callback function to be called whenever we get a GSM 12.21 state change event */
static int nm_statechg_event(int evt, struct nm_statechg_signal_data *nsd)
{
	uint8_t obj_class = nsd->obj_class;
	void *obj = nsd->obj;
	struct gsm_nm_state *new_state = nsd->new_state;

	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_bts_gprs_nsvc *nsvc;

	uint8_t *data;
	size_t data_len;

	if (!is_ipaccess_bts(nsd->bts))
		return 0;

	/* This event-driven BTS setup is currently only required on nanoBTS */

	/* S_NM_STATECHG_ADM is called after we call chg_adm_state() and would create
	 * endless loop */
	if (evt != S_NM_STATECHG_OPER)
		return 0;

	switch (obj_class) {
	case NM_OC_SITE_MANAGER:
		bts = container_of(obj, struct gsm_bts, site_mgr);
		if ((new_state->operational == NM_OPSTATE_ENABLED &&
		     new_state->availability == NM_AVSTATE_OK) ||
		    (new_state->operational == NM_OPSTATE_DISABLED &&
		     new_state->availability == NM_AVSTATE_OFF_LINE))
			abis_nm_opstart(bts, obj_class, 0xff, 0xff, 0xff);
		break;
	case NM_OC_BTS:
		bts = obj;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			data = nanobts_attr_bts_get(bts, &data_len);
			abis_nm_set_bts_attr(bts, data, data_len);
			abis_nm_chg_adm_state(bts, obj_class,
					      bts->bts_nr, 0xff, 0xff,
					      NM_STATE_UNLOCKED);
			abis_nm_opstart(bts, obj_class,
					bts->bts_nr, 0xff, 0xff);
		}
		break;
	case NM_OC_CHANNEL:
		ts = obj;
		trx = ts->trx;
		if (new_state->operational == NM_OPSTATE_DISABLED &&
		    new_state->availability == NM_AVSTATE_DEPENDENCY) {
			enum abis_nm_chan_comb ccomb =
						abis_nm_chcomb4pchan(ts->pchan);
			if (abis_nm_set_channel_attr(ts, ccomb) == -EINVAL) {
				ipaccess_drop_oml(trx->bts);
				return -1;
			}
			abis_nm_chg_adm_state(trx->bts, obj_class,
					      trx->bts->bts_nr, trx->nr, ts->nr,
					      NM_STATE_UNLOCKED);
			abis_nm_opstart(trx->bts, obj_class,
					trx->bts->bts_nr, trx->nr, ts->nr);
		}
		break;
	case NM_OC_RADIO_CARRIER:
		trx = obj;
		if (new_state->operational == NM_OPSTATE_DISABLED &&
		    new_state->availability == NM_AVSTATE_OK)
			abis_nm_opstart(trx->bts, obj_class, trx->bts->bts_nr,
					trx->nr, 0xff);
		break;
	case NM_OC_GPRS_NSE:
		bts = container_of(obj, struct gsm_bts, gprs.nse);
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			data = nanobts_attr_nse_get(bts, &data_len);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  0xff, 0xff, data, data_len);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					0xff, 0xff);
		}
		break;
	case NM_OC_GPRS_CELL:
		bts = container_of(obj, struct gsm_bts, gprs.cell);
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		if (new_state->availability == NM_AVSTATE_DEPENDENCY) {
			data = nanobts_attr_cell_get(bts, &data_len);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  0, 0xff, data, data_len);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					0, 0xff);
			abis_nm_chg_adm_state(bts, obj_class, bts->bts_nr,
					      0, 0xff, NM_STATE_UNLOCKED);
			abis_nm_chg_adm_state(bts, NM_OC_GPRS_NSE, bts->bts_nr,
					      0xff, 0xff, NM_STATE_UNLOCKED);
		}
		break;
	case NM_OC_GPRS_NSVC:
		nsvc = obj;
		bts = nsvc->bts;
		if (bts->gprs.mode == BTS_GPRS_NONE)
			break;
		/* We skip NSVC1 since we only use NSVC0 */
		if (nsvc->id == 1)
			break;
		if ((new_state->availability == NM_AVSTATE_OFF_LINE) ||
		    (new_state->availability == NM_AVSTATE_DEPENDENCY)) {
			data = nanobts_attr_nscv_get(bts, &data_len);
			abis_nm_ipaccess_set_attr(bts, obj_class, bts->bts_nr,
						  nsvc->id, 0xff,
						  data, data_len);
			abis_nm_opstart(bts, obj_class, bts->bts_nr,
					nsvc->id, 0xff);
			abis_nm_chg_adm_state(bts, obj_class, bts->bts_nr,
					      nsvc->id, 0xff,
					      NM_STATE_UNLOCKED);
		}
	default:
		break;
	}
	return 0;
}

/* Callback function to be called every time we receive a 12.21 SW activated report */
static int sw_activ_rep(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, foh->obj_inst.trx_nr);

	if (!trx)
		return -EINVAL;

	if (!is_ipaccess_bts(trx->bts))
		return 0;

	switch (foh->obj_class) {
	case NM_OC_BASEB_TRANSC:
		abis_nm_chg_adm_state(trx->bts, foh->obj_class,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      NM_STATE_UNLOCKED);
		abis_nm_opstart(trx->bts, foh->obj_class,
				trx->bts->bts_nr, trx->nr, 0xff);
		/* TRX software is active, tell it to initiate RSL Link */
		abis_nm_ipaccess_rsl_connect(trx, trx->bts->ip_access.rsl_ip,
					     3003, trx->rsl_tei);
		break;
	case NM_OC_RADIO_CARRIER: {
		/*
		 * Locking the radio carrier will make it go
		 * offline again and we would come here. The
		 * framework should determine that there was
		 * no change and avoid recursion.
		 *
		 * This code is here to make sure that on start
		 * a TRX remains locked.
		 */
		int rc_state = trx->mo.nm_state.administrative;
		/* Patch ARFCN into radio attribute */
		size_t data_len;
		uint8_t *data = nanobts_attr_radio_get(trx->bts, &data_len);
		data[5] &= 0xf0;
		data[5] |= trx->arfcn >> 8;
		data[6] = trx->arfcn & 0xff;
		abis_nm_set_radio_attr(trx, data, data_len);
		abis_nm_chg_adm_state(trx->bts, foh->obj_class,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      rc_state);
		abis_nm_opstart(trx->bts, foh->obj_class, trx->bts->bts_nr,
				trx->nr, 0xff);
		break;
		}
	}
	return 0;
}

/* Callback function to be called every time we receive a signal from NM */
static int bts_ipa_nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	if (subsys != SS_NM)
		return 0;

	switch (signal) {
	case S_NM_SW_ACTIV_REP:
		return sw_activ_rep(signal_data);
	case S_NM_STATECHG_OPER:
	case S_NM_STATECHG_ADM:
		return nm_statechg_event(signal, signal_data);
	default:
		break;
	}
	return 0;
}

static int bts_model_nanobts_start(struct gsm_network *net)
{
	osmo_signal_unregister_handler(SS_NM, bts_ipa_nm_sig_cb, NULL);
	osmo_signal_register_handler(SS_NM, bts_ipa_nm_sig_cb, NULL);
	return 0;
}

int bts_model_nanobts_init(void)
{
	bts_model_nanobts.features.data = &bts_model_nanobts._features_data[0];
	bts_model_nanobts.features.data_len =
				sizeof(bts_model_nanobts._features_data);

	gsm_btsmodel_set_feature(&bts_model_nanobts, BTS_FEAT_GPRS);
	gsm_btsmodel_set_feature(&bts_model_nanobts, BTS_FEAT_EGPRS);
	gsm_btsmodel_set_feature(&bts_model_nanobts, BTS_FEAT_MULTI_TSC);

	return gsm_bts_model_register(&bts_model_nanobts);
}

#define OML_UP         0x0001
#define RSL_UP         0x0002

static struct gsm_bts *
find_bts_by_unitid(struct gsm_network *net, uint16_t site_id, uint16_t bts_id)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		if (bts->ip_access.site_id == site_id &&
		    bts->ip_access.bts_id == bts_id)
			return bts;
	}
	return NULL;
}

/* These are exported because they are used by the VTY interface. */
void ipaccess_drop_rsl(struct gsm_bts_trx *trx)
{
	if (!trx->rsl_link)
		return;

	e1inp_sign_link_destroy(trx->rsl_link);
	trx->rsl_link = NULL;
}

void ipaccess_drop_oml(struct gsm_bts *bts)
{
	struct gsm_bts *rdep_bts;
	struct gsm_bts_trx *trx;

	if (!bts->oml_link)
		return;

	e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = NULL;

	/* we have issues reconnecting RSL, drop everything. */
	llist_for_each_entry(trx, &bts->trx_list, list)
		ipaccess_drop_rsl(trx);

	bts->ip_access.flags = 0;

	/*
	 * Go through the list and see if we are the depndency of a BTS
	 * and then drop the BTS. This can lead to some recursion but it
	 * should be fine in userspace.
	 * The oml_link is serving as recursion anchor for us and
	 * it is set to NULL some lines above.
	 */
	llist_for_each_entry(rdep_bts, &bts->network->bts_list, list) {
		if (!bts_depend_is_depedency(rdep_bts, bts))
			continue;
		LOGP(DLINP, LOGL_NOTICE, "Dropping BTS(%u) due BTS(%u).\n",
			rdep_bts->nr, bts->nr);
		ipaccess_drop_oml(rdep_bts);
	}
}

/* This function is called once the OML/RSL link becomes up. */
static struct e1inp_sign_link *
ipaccess_sign_link_up(void *unit_data, struct e1inp_line *line,
		      enum e1inp_sign_type type)
{
	struct gsm_bts *bts;
	struct ipaccess_unit *dev = unit_data;
	struct e1inp_sign_link *sign_link = NULL;

	bts = find_bts_by_unitid(bsc_gsmnet, dev->site_id, dev->bts_id);
	if (!bts) {
		LOGP(DLINP, LOGL_ERROR, "Unable to find BTS configuration for "
			" %u/%u/%u, disconnecting\n", dev->site_id,
			dev->bts_id, dev->trx_id);
		return NULL;
	}
	DEBUGP(DLINP, "Identified BTS %u/%u/%u\n",
			dev->site_id, dev->bts_id, dev->trx_id);

	switch(type) {
	case E1INP_SIGN_OML:
		/* remove old OML signal link for this BTS. */
		ipaccess_drop_oml(bts);

		if (!bts_depend_check(bts)) {
			LOGP(DLINP, LOGL_NOTICE,
				"Dependency not full-filled for %u/%u/%u\n",
				dev->site_id, dev->bts_id, dev->trx_id);
			return NULL;
		}

		/* create new OML link. */
		sign_link = bts->oml_link =
			e1inp_sign_link_create(&line->ts[E1INP_SIGN_OML - 1],
						E1INP_SIGN_OML, bts->c0,
						bts->oml_tei, 0);
		break;
	case E1INP_SIGN_RSL: {
		struct e1inp_ts *ts;
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, dev->trx_id);

		/* no OML link set yet? give up. */
		if (!bts->oml_link || !trx)
			return NULL;

		/* remove old RSL link for this TRX. */
		ipaccess_drop_rsl(trx);

		/* set new RSL link for this TRX. */
		line = bts->oml_link->ts->line;
		ts = &line->ts[E1INP_SIGN_RSL + dev->trx_id - 1];
		e1inp_ts_config_sign(ts, line);
		sign_link = trx->rsl_link =
				e1inp_sign_link_create(ts, E1INP_SIGN_RSL,
						       trx, trx->rsl_tei, 0);
		trx->rsl_link->ts->sign.delay = 0;
		break;
	}
	default:
		break;
	}
	return sign_link;
}

static void ipaccess_sign_link_down(struct e1inp_line *line)
{
	/* No matter what link went down, we close both signal links. */
	struct e1inp_ts *ts = &line->ts[E1INP_SIGN_OML-1];
	struct e1inp_sign_link *link;

	llist_for_each_entry(link, &ts->sign.sign_links, list) {
		struct gsm_bts *bts = link->trx->bts;

		ipaccess_drop_oml(bts);
		/* Yes, we only use the first element of the list. */
		break;
	}
}

/* This function is called if we receive one OML/RSL message. */
static int ipaccess_sign_link(struct msgb *msg)
{
	int ret = 0;
	struct e1inp_sign_link *link = msg->dst;
	struct e1inp_ts *e1i_ts = link->ts;

	switch (link->type) {
	case E1INP_SIGN_RSL:
		if (!(link->trx->bts->ip_access.flags &
					(RSL_UP << link->trx->nr))) {
			e1inp_event(e1i_ts, S_L_INP_TEI_UP,
					link->tei, link->sapi);
			link->trx->bts->ip_access.flags |=
					(RSL_UP << link->trx->nr);
		}
	        ret = abis_rsl_rcvmsg(msg);
	        break;
	case E1INP_SIGN_OML:
		if (!(link->trx->bts->ip_access.flags & OML_UP)) {
			e1inp_event(e1i_ts, S_L_INP_TEI_UP,
					link->tei, link->sapi);
			link->trx->bts->ip_access.flags |= OML_UP;
		}
	        ret = abis_nm_rcvmsg(msg);
	        break;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown signal link type %d\n",
			link->type);
		msgb_free(msg);
		break;
	}
	return ret;
}

/* not static, ipaccess-config needs it. */
struct e1inp_line_ops ipaccess_e1inp_line_ops = {
	.cfg = {
		.ipa = {
			.addr = "0.0.0.0",
			.role = E1INP_LINE_R_BSC,
		},
	},
	.sign_link_up	= ipaccess_sign_link_up,
	.sign_link_down	= ipaccess_sign_link_down,
	.sign_link	= ipaccess_sign_link,
};

static void bts_model_nanobts_e1line_bind_ops(struct e1inp_line *line)
{
        e1inp_line_bind_ops(line, &ipaccess_e1inp_line_ops);
}
