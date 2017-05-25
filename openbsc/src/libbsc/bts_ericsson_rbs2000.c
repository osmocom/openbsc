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

	/* FIXME: this is global init, not bootstrapping */
	abis_om2k_bts_init(bts);
	abis_om2k_trx_init(bts->c0);

	/* TODO: Should we wait for a Failure report? */
	om2k_bts_fsm_start(bts);
}

static void bootstrap_om_trx(struct gsm_bts_trx *trx)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for TRX %u/%u\n",
	     trx->bts->nr, trx->nr);
	/* FIXME */
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
			if (!ts->lapd)
				continue;
			lapd_instance_set_profile(ts->lapd,
						  &lapd_profile_abis_ericsson);

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
	struct e1inp_ts *e1i_ts;

	if (subsys != SS_L_INPUT)
		return 0;

	LOGP(DNM, LOGL_DEBUG, "%s(): Input signal '%s' received\n", __func__,
			get_value_string(e1inp_signal_names, signal));
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
	case S_L_INP_TEI_DN:
		if (isd->trx->bts->type != GSM_BTS_TYPE_RBS2000)
			break;
		LOGP(DNM, LOGL_NOTICE, "Line-%u TS-%u TEI-%u SAPI-%u: Link "
		     "Lost for Ericsson RBS2000. Re-starting DL Establishment\n",
		     isd->line->num, isd->ts_nr, isd->tei, isd->sapi);
		/* Some datalink for a given TEI/SAPI went down, try to re-start it */
		e1i_ts = &isd->line->ts[isd->ts_nr-1];
		OSMO_ASSERT(e1i_ts->type == E1INP_TS_TYPE_SIGN);
		lapd_sap_start(e1i_ts->lapd, isd->tei, isd->sapi);
		break;
	case S_L_INP_LINE_INIT:
	case S_L_INP_LINE_NOALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI")
		 && strcasecmp(isd->line->driver->name, "MISDN_LAPD")
		 && strcasecmp(isd->line->driver->name, "UNIXSOCKET"))
			break;
		start_sabm_in_line(isd->line, 1);
		break;
	case S_L_INP_LINE_ALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI")
		 && strcasecmp(isd->line->driver->name, "MISDN_LAPD")
		 && strcasecmp(isd->line->driver->name, "UNIXSOCKET"))
			break;
		start_sabm_in_line(isd->line, 0);
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

	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_GPRS);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_EGPRS);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HSCSD);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_MULTI_TSC);

	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_GLOBAL, gbl_sig_cb, NULL);

	return 0;
}

int bts_model_rbs2k_init(void)
{
	return gsm_bts_model_register(&model_rbs2k);
}
