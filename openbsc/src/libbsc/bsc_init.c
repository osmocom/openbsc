/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/gsm_data.h>
#include <osmocom/gsm/gsm_utils.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>
#include <openbsc/misdn.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <openbsc/system_information.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/chan_alloc.h>
#include <osmocom/core/talloc.h>
#include <openbsc/ipaccess.h>
#include <osmocom/gsm/sysinfo.h>
#include <openbsc/e1_config.h>
#include <openbsc/common_bsc.h>
#include <openbsc/pcu_if.h>
#include <openbsc/osmo_msc.h>
#include <limits.h>

/* global pointer to the gsm network data structure */
extern struct gsm_network *bsc_gsmnet;

/* Callback function for NACK on the OML NM */
static int oml_msg_nack(struct nm_nack_signal_data *nack)
{
	if (nack->mt == NM_MT_GET_ATTR_NACK) {
		LOGP(DNM, LOGL_ERROR, "BTS%u does not support Get Attributes "
		     "OML message.\n", nack->bts->nr);
		return 0;
	}

	if (nack->mt == NM_MT_SET_BTS_ATTR_NACK)
		LOGP(DNM, LOGL_ERROR, "Failed to set BTS attributes. That is fatal. "
		     "Was the bts type and frequency properly specified?\n");
	else
		LOGP(DNM, LOGL_ERROR, "Got %s NACK going to drop the OML links.\n",
		     abis_nm_nack_name(nack->mt));

	if (!nack->bts) {
		LOGP(DNM, LOGL_ERROR, "Unknown bts. Can not drop it.\n");
		return 0;
	}

	if (is_ipaccess_bts(nack->bts))
		ipaccess_drop_oml(nack->bts);

	return 0;
}

/* Callback function to be called every time we receive a signal from NM */
static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	struct nm_nack_signal_data *nack;

	switch (signal) {
	case S_NM_NACK:
		nack = signal_data;
		return oml_msg_nack(nack);
	default:
		break;
	}
	return 0;
}

int bsc_shutdown_net(struct gsm_network *net)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		LOGP(DNM, LOGL_NOTICE, "shutting down OML for BTS %u\n", bts->nr);
		osmo_signal_dispatch(SS_L_GLOBAL, S_GLOBAL_BTS_CLOSE_OM, bts);
	}

	return 0;
}

static int rsl_si(struct gsm_bts_trx *trx, enum osmo_sysinfo_type i, int si_len)
{
	struct gsm_bts *bts = trx->bts;
	int rc, j;

	DEBUGP(DRR, "SI%s: %s\n", get_value_string(osmo_sitype_strs, i),
		osmo_hexdump(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN));

	switch (i) {
	case SYSINFO_TYPE_5:
	case SYSINFO_TYPE_5bis:
	case SYSINFO_TYPE_5ter:
	case SYSINFO_TYPE_6:
		rc = rsl_sacch_filling(trx, osmo_sitype2rsl(i),
				       GSM_BTS_SI(bts, i), si_len);
		break;
	case SYSINFO_TYPE_2quater:
		for (j = 0; j <= bts->si2q_count; j++)
			rc = rsl_bcch_info(trx, i, (const uint8_t *)GSM_BTS_SI2Q(bts, j), GSM_MACBLOCK_LEN);
		break;
	default:
		rc = rsl_bcch_info(trx, i, GSM_BTS_SI(bts, i), si_len);
		break;
	}

	return rc;
}

/* set all system information types for a TRX */
int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx)
{
	int i, rc;
	struct gsm_bts *bts = trx->bts;
	uint8_t gen_si[_MAX_SYSINFO_TYPE], n_si = 0, n;
	int si_len[_MAX_SYSINFO_TYPE];

	bts->si_common.cell_sel_par.ms_txpwr_max_ccch =
			ms_pwr_ctl_lvl(bts->band, bts->ms_max_power);
	bts->si_common.cell_sel_par.neci = bts->network->neci;

	/* Zero, forget the state of the SIs */
	bts->si_valid = 0;

	/* First, we determine which of the SI messages we actually need */

	if (trx == bts->c0) {
		/* 1...4 are always present on a C0 TRX */
		gen_si[n_si++] = SYSINFO_TYPE_1;
		gen_si[n_si++] = SYSINFO_TYPE_2;
		gen_si[n_si++] = SYSINFO_TYPE_2bis;
		gen_si[n_si++] = SYSINFO_TYPE_2ter;
		gen_si[n_si++] = SYSINFO_TYPE_2quater;
		gen_si[n_si++] = SYSINFO_TYPE_3;
		gen_si[n_si++] = SYSINFO_TYPE_4;

		/* 13 is always present on a C0 TRX of a GPRS BTS */
		if (bts->gprs.mode != BTS_GPRS_NONE)
			gen_si[n_si++] = SYSINFO_TYPE_13;
	}

	/* 5 and 6 are always present on every TRX */
	gen_si[n_si++] = SYSINFO_TYPE_5;
	gen_si[n_si++] = SYSINFO_TYPE_5bis;
	gen_si[n_si++] = SYSINFO_TYPE_5ter;
	gen_si[n_si++] = SYSINFO_TYPE_6;

	/* Second, we generate the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		/* Only generate SI if this SI is not in "static" (user-defined) mode */
		if (!(bts->si_mode_static & (1 << i))) {
			/* Set SI as being valid. gsm_generate_si() might unset
			 * it, if SI is not required. */
			bts->si_valid |= (1 << i);
			rc = gsm_generate_si(bts, i);
			if (rc < 0)
				goto err_out;
			si_len[i] = rc;
		} else {
			if (i == SYSINFO_TYPE_5 || i == SYSINFO_TYPE_5bis
			 || i == SYSINFO_TYPE_5ter)
				si_len[i] = 18;
			else if (i == SYSINFO_TYPE_6)
				si_len[i] = 11;
			else
				si_len[i] = 23;
		}
	}

	/* Third, we send the selected SI via RSL */

	for (n = 0; n < n_si; n++) {
		i = gen_si[n];
		if (!GSM_BTS_HAS_SI(bts, i))
			continue;
		rc = rsl_si(trx, i, si_len[i]);
		if (rc < 0)
			return rc;
	}

	/* Make sure the PCU is aware (in case anything GPRS related has
	 * changed in SI */
	pcu_info_update(bts);

	return 0;
err_out:
	LOGP(DRR, LOGL_ERROR, "Cannot generate SI%s for BTS %u: error <%s>, "
	     "most likely a problem with neighbor cell list generation\n",
	     get_value_string(osmo_sitype_strs, i), bts->nr, strerror(-rc));
	return rc;
}

/* set all system information types for a BTS */
int gsm_bts_set_system_infos(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	/* Generate a new ID */
	bts->bcch_change_mark += 1;
	bts->bcch_change_mark %= 0x7;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int rc;

		rc = gsm_bts_trx_set_system_infos(trx);
		if (rc != 0)
			return rc;
	}

	return 0;
}

/* Produce a MA as specified in 10.5.2.21 */
static int generate_ma_for_ts(struct gsm_bts_trx_ts *ts)
{
	/* we have three bitvecs: the per-timeslot ARFCNs, the cell chan ARFCNs
	 * and the MA */
	struct bitvec *cell_chan = &ts->trx->bts->si_common.cell_alloc;
	struct bitvec *ts_arfcn = &ts->hopping.arfcns;
	struct bitvec *ma = &ts->hopping.ma;
	unsigned int num_cell_arfcns, bitnum, n_chan;
	int i;

	/* re-set the MA to all-zero */
	ma->cur_bit = 0;
	ts->hopping.ma_len = 0;
	memset(ma->data, 0, ma->data_len);

	if (!ts->hopping.enabled)
		return 0;

	/* count the number of ARFCNs in the cell channel allocation */
	num_cell_arfcns = 0;
	for (i = 0; i < 1024; i++) {
		if (bitvec_get_bit_pos(cell_chan, i))
			num_cell_arfcns++;
	}

	/* pad it to octet-aligned number of bits */
	ts->hopping.ma_len = num_cell_arfcns / 8;
	if (num_cell_arfcns % 8)
		ts->hopping.ma_len++;

	n_chan = 0;
	for (i = 0; i < 1024; i++) {
		if (!bitvec_get_bit_pos(cell_chan, i))
			continue;
		/* set the corresponding bit in the MA */
		bitnum = (ts->hopping.ma_len * 8) - 1 - n_chan;
		if (bitvec_get_bit_pos(ts_arfcn, i))
			bitvec_set_bit_pos(ma, bitnum, 1);
		else
			bitvec_set_bit_pos(ma, bitnum, 0);
		n_chan++;
	}

	/* ARFCN 0 is special: It is coded last in the bitmask */
	if (bitvec_get_bit_pos(cell_chan, 0)) {
		n_chan++;
		/* set the corresponding bit in the MA */
		bitnum = (ts->hopping.ma_len * 8) - 1 - n_chan;
		if (bitvec_get_bit_pos(ts_arfcn, 0))
			bitvec_set_bit_pos(ma, bitnum, 1);
		else
			bitvec_set_bit_pos(ma, bitnum, 0);
	}

	return 0;
}

static void bootstrap_rsl(struct gsm_bts_trx *trx)
{
	unsigned int i;

	LOGP(DRSL, LOGL_NOTICE, "bootstrapping RSL for BTS/TRX (%u/%u) "
		"on ARFCN %u using MCC=%u MNC=%u LAC=%u CID=%u BSIC=%u\n",
		trx->bts->nr, trx->nr, trx->arfcn, bsc_gsmnet->country_code,
		bsc_gsmnet->network_code, trx->bts->location_area_code,
		trx->bts->cell_identity, trx->bts->bsic);

	if (trx->bts->type == GSM_BTS_TYPE_NOKIA_SITE) {
		rsl_nokia_si_begin(trx);
	}

	gsm_bts_trx_set_system_infos(trx);

	if (trx->bts->type == GSM_BTS_TYPE_NOKIA_SITE) {
		/* channel unspecific, power reduction in 2 dB steps */
		rsl_bs_power_control(trx, 0xFF, trx->max_power_red / 2);
		rsl_nokia_si_end(trx);
	}

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++)
		generate_ma_for_ts(&trx->ts[i]);
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;
	struct gsm_bts_trx *trx = isd->trx;
	int ts_no, lchan_no;
	/* N. B: we rely on attribute order when parsing response in abis_nm_rx_get_attr_resp() */
	const uint8_t bts_attr[] = { NM_ATT_MANUF_ID, NM_ATT_SW_CONFIG, };
	const uint8_t trx_attr[] = { NM_ATT_MANUF_STATE, NM_ATT_SW_CONFIG, };

	/* we should not request more attributes than we're ready to handle */
	OSMO_ASSERT(sizeof(bts_attr) < MAX_BTS_ATTR);
	OSMO_ASSERT(sizeof(trx_attr) < MAX_BTS_ATTR);

	if (subsys != SS_L_INPUT)
		return -EINVAL;

	LOGP(DLMI, LOGL_DEBUG, "%s(): Input signal '%s' received\n", __func__,
		get_value_string(e1inp_signal_names, signal));
	switch (signal) {
	case S_L_INP_TEI_UP:
		if (isd->link_type == E1INP_SIGN_OML) {
			/* TODO: this is required for the Nokia BTS, hopping is configured
			   during OML, other MA is not set.  */
			struct gsm_bts_trx *cur_trx;
			/* was static in system_information.c */
			extern int generate_cell_chan_list(uint8_t *chan_list, struct gsm_bts *bts);
			uint8_t ca[20];
			/* has to be called before generate_ma_for_ts to
			  set bts->si_common.cell_alloc */
			generate_cell_chan_list(ca, trx->bts);

			/* Request generic BTS-level attributes */
			abis_nm_get_attr(trx->bts, NM_OC_BTS, trx->bts->nr, trx->nr, 0xFF, bts_attr, sizeof(bts_attr));

			llist_for_each_entry(cur_trx, &trx->bts->trx_list, list) {
				int i;
				/* Request TRX-level attributes */
				abis_nm_get_attr(cur_trx->bts, NM_OC_BASEB_TRANSC, cur_trx->bts->nr, cur_trx->nr, 0xFF,
						 trx_attr, sizeof(trx_attr));
				for (i = 0; i < ARRAY_SIZE(cur_trx->ts); i++)
					generate_ma_for_ts(&cur_trx->ts[i]);
			}
		}
		if (isd->link_type == E1INP_SIGN_RSL)
			bootstrap_rsl(trx);
		break;
	case S_L_INP_TEI_DN:
		LOGP(DLMI, LOGL_ERROR, "Lost some E1 TEI link: %d %p\n", isd->link_type, trx);

		if (isd->link_type == E1INP_SIGN_OML)
			rate_ctr_inc(&trx->bts->network->bsc_ctrs->ctr[BSC_CTR_BTS_OML_FAIL]);
		else if (isd->link_type == E1INP_SIGN_RSL)
			rate_ctr_inc(&trx->bts->network->bsc_ctrs->ctr[BSC_CTR_BTS_RSL_FAIL]);

		/*
		 * free all allocated channels. change the nm_state so the
		 * trx and trx_ts becomes unusable and chan_alloc.c can not
		 * allocate from it.
		 */
		for (ts_no = 0; ts_no < ARRAY_SIZE(trx->ts); ++ts_no) {
			struct gsm_bts_trx_ts *ts = &trx->ts[ts_no];

			for (lchan_no = 0; lchan_no < ARRAY_SIZE(ts->lchan); ++lchan_no) {
				if (ts->lchan[lchan_no].state != LCHAN_S_NONE)
					lchan_free(&ts->lchan[lchan_no]);
				lchan_reset(&ts->lchan[lchan_no]);
			}
		}

		gsm_bts_mo_reset(trx->bts);

		abis_nm_clear_queue(trx->bts);
		break;
	default:
		break;
	}

	return 0;
}

static int bootstrap_bts(struct gsm_bts *bts)
{
	int i, n;

	if (!bts->model)
		return -EFAULT;

	if (bts->model->start && !bts->model->started) {
		int ret = bts->model->start(bts->network);
		if (ret < 0)
			return ret;

		bts->model->started = true;
	}

	/* FIXME: What about secondary TRX of a BTS?  What about a BTS that has TRX
	 * in different bands? Why is 'band' a parameter of the BTS and not of the TRX? */
	switch (bts->band) {
	case GSM_BAND_1800:
		if (bts->c0->arfcn < 512 || bts->c0->arfcn > 885) {
			LOGP(DNM, LOGL_ERROR, "GSM1800 channel must be between 512-885.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_1900:
		if (bts->c0->arfcn < 512 || bts->c0->arfcn > 810) {
			LOGP(DNM, LOGL_ERROR, "GSM1900 channel must be between 512-810.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_900:
		if ((bts->c0->arfcn > 124 && bts->c0->arfcn < 955) ||
		    bts->c0->arfcn > 1023)  {
			LOGP(DNM, LOGL_ERROR, "GSM900 channel must be between 0-124, 955-1023.\n");
			return -EINVAL;
		}
		break;
	case GSM_BAND_850:
		if (bts->c0->arfcn < 128 || bts->c0->arfcn > 251) {
			LOGP(DNM, LOGL_ERROR, "GSM850 channel must be between 128-251.\n");
			return -EINVAL;
		}
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "Unsupported frequency band.\n");
		return -EINVAL;
	}

	if (bts->network->auth_policy == GSM_AUTH_POLICY_ACCEPT_ALL &&
	    !bts->si_common.rach_control.cell_bar)
		LOGP(DNM, LOGL_ERROR, "\nWARNING: You are running an 'accept-all' "
			"network on a BTS that is not barred.  This "
			"configuration is likely to interfere with production "
			"GSM networks and should only be used in a RF "
			"shielded environment such as a faraday cage!\n\n");

	/* Control Channel Description is set from vty/config */

	/* T3212 is set from vty/config */

	/* Set ccch config by looking at ts config */
	for (n=0, i=0; i<8; i++)
		n += bts->c0->ts[i].pchan == GSM_PCHAN_CCCH ? 1 : 0;

	/* Indicate R99 MSC in SI3 */
	bts->si_common.chan_desc.mscr = 1;

	switch (n) {
	case 0:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_C;
		/* Limit reserved block to 2 on combined channel according to
		   3GPP TS 44.018 Table 10.5.2.11.1 */
		if (bts->si_common.chan_desc.bs_ag_blks_res > 2) {
			LOGP(DNM, LOGL_NOTICE, "CCCH is combined with SDCCHs, "
			     "reducing BS-AG-BLKS-RES value %d -> 2\n",
			     bts->si_common.chan_desc.bs_ag_blks_res);
			bts->si_common.chan_desc.bs_ag_blks_res = 2;
		}
		break;
	case 1:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_NC;
		break;
	case 2:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_2_NC;
		break;
	case 3:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_3_NC;
		break;
	case 4:
		bts->si_common.chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_4_NC;
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "Unsupported CCCH timeslot configuration\n");
		return -EINVAL;
	}

	bts->si_common.cell_options.pwrc = 0; /* PWRC not set */

	bts->si_common.cell_sel_par.acs = 0;

	bts->si_common.ncc_permitted = 0xff;

	/* Initialize the BTS state */
	gsm_bts_mo_reset(bts);

	return 0;
}

int bsc_network_alloc(mncc_recv_cb_t mncc_recv)
{
	/* initialize our data structures */
	bsc_gsmnet = bsc_network_init(tall_bsc_ctx, 1, 1, mncc_recv);
	if (!bsc_gsmnet)
		return -ENOMEM;

	bsc_gsmnet->name_long = talloc_strdup(bsc_gsmnet, "OpenBSC");
	bsc_gsmnet->name_short = talloc_strdup(bsc_gsmnet, "OpenBSC");

	/* TODO: move to libmsc when gsm_network is split between libbsc and
	 * libmsc */
	bsc_gsmnet->gsup_server_addr_str = talloc_strdup(bsc_gsmnet,
							 MSC_HLR_REMOTE_IP_DEFAULT);
	bsc_gsmnet->gsup_server_port = MSC_HLR_REMOTE_PORT_DEFAULT;

	return 0;
}

int bsc_network_configure(const char *config_file)
{
	struct gsm_bts *bts;
	int rc;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		LOGP(DNM, LOGL_FATAL, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_bsc_ctx, bsc_gsmnet, vty_get_bind_addr(),
			       OSMO_VTY_PORT_NITB_BSC);
	if (rc < 0)
		return rc;

	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		rc = bootstrap_bts(bts);
		if (rc < 0) {
			LOGP(DNM, LOGL_FATAL, "Error bootstrapping BTS\n");
			return rc;
		}
		rc = e1_reconfig_bts(bts);
		if (rc < 0) {
			LOGP(DNM, LOGL_FATAL, "Error enabling E1 input driver\n");
			return rc;
		}
	}

	return 0;
}
