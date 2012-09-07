/* Ericsson RBS-2xxx specific code */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
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


#include <osmocom/gsm/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <openbsc/signal.h>

#include <osmocom/abis/lapd.h>

static void bootstrap_om_bts(struct gsm_bts *bts)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for BTS %u\n", bts->nr);
	abis_om2k_tx_start_req(bts, &om2k_mo_cf);
	/* FIXME */
}

static void bootstrap_om_trx(struct gsm_bts_trx *trx)
{
	struct abis_om2k_mo trx_mo = { OM2K_MO_CLS_TRXC, 0, 255, trx->nr };

	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for TRX %u/%u\n",
	     trx->bts->nr, trx->nr);

	abis_om2k_tx_reset_cmd(trx->bts, &trx_mo);
}

static int shutdown_om(struct gsm_bts *bts)
{
	/* FIXME */
	return 0;
}


/* Tell LAPD to start start the SAP (send SABM requests) for all signalling
 * timeslots in this line */
static void start_sabm_in_line(struct e1inp_line *line, int start)
{
	struct e1inp_sign_link *link;
	int i;

	for (i = 0; i < ARRAY_SIZE(line->ts); i++) {
		struct e1inp_ts *ts = &line->ts[i];

		if (ts->type != E1INP_TS_TYPE_SIGN)
			continue;

		llist_for_each_entry(link, &ts->sign.sign_links, list) {
			if (start)
				lapd_sap_start(ts->lapd, link->tei, link->sapi);
			else
				lapd_sap_stop(ts->lapd, link->tei, link->sapi);
		}
	}
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_L_GLOBAL)
		return 0;

	switch (signal) {
	case S_GLOBAL_BTS_CLOSE_OM:
		bts = signal_data;
		if (bts->type == GSM_BTS_TYPE_RBS2000)
			shutdown_om(signal_data);
		break;
	}

	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;

	if (subsys != SS_L_INPUT)
		return 0;

	switch (signal) {
	case S_L_INP_TEI_UP:
		switch (isd->link_type) {
		case E1INP_SIGN_OML:
			if (isd->trx->bts->type != GSM_BTS_TYPE_RBS2000)
				break;
			if (isd->tei == isd->trx->bts->oml_tei)
				bootstrap_om_bts(isd->trx->bts);
			else
				bootstrap_om_trx(isd->trx);
			break;
		}
		break;
	case S_L_INP_LINE_INIT:
	case S_L_INP_LINE_NOALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI")
		 && strcasecmp(isd->line->driver->name, "MISDN_LAPD"))
			break;
		start_sabm_in_line(isd->line, 1);
		break;
	case S_L_INP_LINE_ALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI")
		 && strcasecmp(isd->line->driver->name, "MISDN_LAPD"))
			break;
		start_sabm_in_line(isd->line, 0);
		break;
	}

	return 0;
}

static void nm_statechg_evt(unsigned int signal,
			    struct nm_statechg_signal_data *nsd)
{
	struct abis_om2k_mo mo;

	if (nsd->bts->type != GSM_BTS_TYPE_RBS2000)
		return;

	switch (nsd->om2k_mo->class) {
	case OM2K_MO_CLS_CF:
		if (nsd->new_state->operational != NM_OPSTATE_ENABLED ||
		    nsd->new_state->availability != OM2K_MO_S_STARTED)
			break;
		/* CF has started, we can trigger IS and TF start */
		abis_om2k_tx_connect_cmd(nsd->bts, &om2k_mo_is);
		abis_om2k_tx_connect_cmd(nsd->bts, &om2k_mo_tf);
		break;
	case OM2K_MO_CLS_IS:
		if (nsd->new_state->availability == OM2K_MO_S_ENABLED) {
			/* IS is enabled, we can proceed with TRXC/RX/TX/TS */
			break;
		}
		if (nsd->new_state->operational != NM_OPSTATE_ENABLED)
			break;
		/* IS has started, we can configure + enable it */
		abis_om2k_tx_is_conf_req(nsd->bts);
		break;
	case OM2K_MO_CLS_TF:
		if (nsd->new_state->operational != NM_OPSTATE_ENABLED ||
		    nsd->new_state->availability == OM2K_MO_S_DISABLED)
			break;
		if (nsd->new_state->availability == OM2K_MO_S_STARTED) {
			/* TF has started, configure + enable it */
			abis_om2k_tx_tf_conf_req(nsd->bts);
		}
		break;
	case OM2K_MO_CLS_TRXC:
		if (nsd->new_state->availability != OM2K_MO_S_STARTED)
			break;
		/* TRXC is started, connect the TX and RX objects */
		memcpy(&mo, nsd->om2k_mo, sizeof(mo));
		mo.class = OM2K_MO_CLS_TX;
		abis_om2k_tx_connect_cmd(nsd->bts, &mo);
		mo.class = OM2K_MO_CLS_RX;
		abis_om2k_tx_connect_cmd(nsd->bts, &mo);
		break;
	case OM2K_MO_CLS_RX:
		if (nsd->new_state->operational != NM_OPSTATE_ENABLED ||
		    nsd->new_state->availability != OM2K_MO_S_STARTED)
			break;
		/* RX is started, configure + enable it */
		abis_om2k_tx_rx_conf_req(nsd->obj);
		break;
	case OM2K_MO_CLS_TX:
		if (nsd->new_state->operational != NM_OPSTATE_ENABLED ||
		    nsd->new_state->availability != OM2K_MO_S_STARTED)
			break;
		/* RX is started, configure + enable it */
		abis_om2k_tx_tx_conf_req(nsd->obj);
		break;
	}
}

static void nm_conf_res(struct nm_om2k_signal_data *nsd)
{
	switch (nsd->om2k_mo->class) {
	case OM2K_MO_CLS_IS:
	case OM2K_MO_CLS_TF:
	case OM2K_MO_CLS_RX:
	case OM2K_MO_CLS_TX:
		/* If configuration was a success, enable it */
		abis_om2k_tx_enable_req(nsd->bts, nsd->om2k_mo);
		break;
	}
}

static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	if (subsys != SS_NM)
		return 0;

	switch (signal) {
	case S_NM_STATECHG_OPER:
	case S_NM_STATECHG_ADM:
		nm_statechg_evt(signal, signal_data);
		break;
	case S_NM_OM2K_CONF_RES:
		nm_conf_res(signal_data);
		break;
	default:
		break;
	}

	return 0;
}

static void config_write_bts(struct vty *vty, struct gsm_bts *bts)
{
	abis_om2k_config_write_bts(vty, bts);
}

static int bts_model_rbs2k_start(struct gsm_network *net);

static void bts_model_rbs2k_e1line_bind_ops(struct e1inp_line *line)
{
	e1inp_line_bind_ops(line, &bts_isdn_e1inp_line_ops);
}

static struct gsm_bts_model model_rbs2k = {
	.type = GSM_BTS_TYPE_RBS2000,
	.name = "rbs2000",
	.start = bts_model_rbs2k_start,
	.oml_rcvmsg = &abis_om2k_rcvmsg,
	.config_write_bts = &config_write_bts,
	.e1line_bind_ops = &bts_model_rbs2k_e1line_bind_ops,
};

static int bts_model_rbs2k_start(struct gsm_network *net)
{
	model_rbs2k.features.data = &model_rbs2k._features_data[0];
	model_rbs2k.features.data_len = sizeof(model_rbs2k._features_data);

	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HSCSD);

	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_GLOBAL, gbl_sig_cb, NULL);
	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);

	return 0;
}

int bts_model_rbs2k_init(void)
{
	return gsm_bts_model_register(&model_rbs2k);
}
