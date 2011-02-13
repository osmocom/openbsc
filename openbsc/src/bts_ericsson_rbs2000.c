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

#include <sys/types.h>

#include <osmocore/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/e1_input.h>
#include <openbsc/signal.h>

#include "input/lapd.h"

static struct gsm_bts_model model_rbs2k = {
	.type = GSM_BTS_TYPE_RBS2000,
	.name = "rbs2000",
	.oml_rcvmsg = &abis_om2k_rcvmsg,
};

static void bootstrap_om_bts(struct gsm_bts *bts)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for BTS %u\n", bts->nr);
	abis_om2k_tx_start_req(bts, &om2k_mo_cf);
	/* FIXME */
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
			if (start)
				lapd_sap_start(ts->driver.dahdi.lapd, link->tei, link->sapi);
			else
				lapd_sap_stop(ts->driver.dahdi.lapd, link->tei, link->sapi);
		}
	}
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_GLOBAL)
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

	if (subsys != SS_INPUT)
		return 0;

	switch (signal) {
	case S_INP_TEI_UP:
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
	case S_INP_LINE_INIT:
		/* Right now Ericsson RBS are only supported on DAHDI */
		if (strcasecmp(isd->line->driver->name, "DAHDI"))
			break;
		start_sabm_in_line(isd->line, 1);
		break;
	case S_INP_LINE_ALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI"))
			break;
		start_sabm_in_line(isd->line, 0);
		break;
	case S_INP_LINE_NOALARM:
		if (strcasecmp(isd->line->driver->name, "DAHDI"))
			break;
		start_sabm_in_line(isd->line, 1);
		break;
	}

	return 0;
}

int bts_model_rbs2k_init(void)
{
	model_rbs2k.features.data = &model_rbs2k._features_data[0];
	model_rbs2k.features.data_len = sizeof(model_rbs2k._features_data);

	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_rbs2k, BTS_FEAT_HSCSD);

	register_signal_handler(SS_INPUT, inp_sig_cb, NULL);
	register_signal_handler(SS_GLOBAL, gbl_sig_cb, NULL);

	return gsm_bts_model_register(&model_rbs2k);
}
