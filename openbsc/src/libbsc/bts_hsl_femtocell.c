/* OpenBSC support code for HSL Femtocell */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by OnWaves
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

#include <inttypes.h>

#include <arpa/inet.h>

#include <osmocom/gsm/tlv.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <osmocom/core/logging.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipaccess.h>

static int bts_model_hslfemto_start(struct gsm_network *net);
static void bts_model_hslfemto_e1line_bind_ops(struct e1inp_line *line);

static struct gsm_bts_model model_hslfemto = {
	.type = GSM_BTS_TYPE_HSL_FEMTO,
	.start = bts_model_hslfemto_start,
	.e1line_bind_ops = &bts_model_hslfemto_e1line_bind_ops,
	.nm_att_tlvdef = {
		.def = {
			/* no HSL specific OML attributes that we know of */
		},
	},
};


static const uint8_t l1_msg[] = {
#ifdef HSL_SR_1_0
	0x80, 0x8a,
#else
	0x81, 0x8a,
#endif
		0xC4, 0x0b,
};

static const uint8_t conn_trau_msg[] = {
#ifdef HSL_SR_1_0
	0x80, 0x81,
#else
	0x81, 0x81,
#endif
		0xC1, 16,
			0x02, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0xEA, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t conn_trau_msg2[] = {
#ifdef HSL_SR_1_0
	0x80, 0x81,
#else
	0x81, 0x81,
#endif
		0xC1, 16,
			0x02, 0x00, 0xd4, 0x07, 0xC0, 0xA8, 0xEA, 0x01,
			0x38, 0xA4, 0x45, 0x00, 0x04, 0x59, 0x40, 0x00
};

static uint8_t oml_arfcn_bsic[] = {
#ifdef HSL_SR_1_0
	0x81, 0x80, 0x00, 10,
#else
	0x80, 0x80, 0x00, 10,
#endif
		NM_MT_SET_BTS_ATTR, NM_OC_BTS, 0xff, 0xff, 0xff,
			NM_ATT_BCCH_ARFCN, 0x03, 0x67,
			NM_ATT_BSIC, 0x00
};

static inline struct msgb *hsl_alloc_msgb(void)
{
	return msgb_alloc_headroom(1024, 127, "HSL");
}

static int hslfemto_bootstrap_om(struct gsm_bts *bts)
{
	struct msgb *msg;

	msg = hsl_alloc_msgb();
	msgb_put(msg, sizeof(l1_msg));
	memcpy(msg->data, l1_msg, sizeof(l1_msg));
	msg->dst = bts->c0->rsl_link;
	abis_rsl_sendmsg(msg);

#if 1
	msg = hsl_alloc_msgb();
	msgb_put(msg, sizeof(conn_trau_msg));
	memcpy(msg->data, conn_trau_msg, sizeof(conn_trau_msg));
	msg->dst = bts->c0->rsl_link;
	abis_rsl_sendmsg(msg);
#endif
	msg = hsl_alloc_msgb();
	msgb_put(msg, sizeof(conn_trau_msg2));
	memcpy(msg->data, conn_trau_msg2, sizeof(conn_trau_msg2));
	msg->dst = bts->c0->rsl_link;
	abis_rsl_sendmsg(msg);

	*((uint16_t *)oml_arfcn_bsic+10) = htons(bts->c0->arfcn);
	oml_arfcn_bsic[13] = bts->bsic;

	msg = hsl_alloc_msgb();
	msgb_put(msg, sizeof(oml_arfcn_bsic));
	memcpy(msg->data, oml_arfcn_bsic, sizeof(oml_arfcn_bsic));
	msg->dst = bts->c0->rsl_link;
	abis_sendmsg(msg);

	/* Delay the OPSTART until after SI have been set via RSL */
	//abis_nm_opstart(bts, NM_OC_BTS, 255, 255, 255);

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
			if (isd->trx->bts->type == GSM_BTS_TYPE_HSL_FEMTO)
				hslfemto_bootstrap_om(isd->trx->bts);
			break;
		}
	}

	return 0;
}

static struct gsm_network *hsl_gsmnet;

static int bts_model_hslfemto_start(struct gsm_network *net)
{
	model_hslfemto.features.data = &model_hslfemto._features_data[0];
	model_hslfemto.features.data_len = sizeof(model_hslfemto._features_data);

	gsm_btsmodel_set_feature(&model_hslfemto, BTS_FEAT_GPRS);
	gsm_btsmodel_set_feature(&model_hslfemto, BTS_FEAT_EGPRS);

	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);

	hsl_gsmnet = net;
	return 0;
}

int bts_model_hslfemto_init(void)
{
	return gsm_bts_model_register(&model_hslfemto);
}

#define OML_UP		0x0001
#define RSL_UP		0x0002

struct gsm_bts *find_bts_by_serno(struct gsm_network *net, uint64_t serno)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (bts->type != GSM_BTS_TYPE_HSL_FEMTO)
			continue;

		if (serno == bts->hsl.serno)
			return bts;
	}
	return NULL;
}

/* This function is called once the OML/RSL link becomes up. */
static struct e1inp_sign_link *
hsl_sign_link_up(void *unit_data, struct e1inp_line *line,
		 enum e1inp_sign_type type)
{
	struct hsl_unit *dev = unit_data;
	struct gsm_bts *bts;

	bts = find_bts_by_serno(hsl_gsmnet, dev->serno);
	if (!bts) {
		LOGP(DLINP, LOGL_ERROR, "Unable to find BTS config for "
				"serial number %"PRIx64"\n", dev->serno);
		return NULL;
	}
	DEBUGP(DLINP, "Identified HSL BTS Serial Number %"PRIx64"\n", dev->serno);

	/* we shouldn't hardcode it, but HSL femto also hardcodes it... */
	bts->oml_tei = 255;
	bts->c0->rsl_tei = 0;
	bts->oml_link = e1inp_sign_link_create(&line->ts[E1INP_SIGN_OML-1],
					       E1INP_SIGN_OML, bts->c0,
					       bts->oml_tei, 0);
	bts->c0->rsl_link = e1inp_sign_link_create(&line->ts[E1INP_SIGN_OML-1],
						   E1INP_SIGN_RSL, bts->c0,
						   bts->c0->rsl_tei, 0);
	e1inp_event(&line->ts[E1INP_SIGN_OML-1], S_L_INP_TEI_UP, 255, 0);
	e1inp_event(&line->ts[E1INP_SIGN_OML-1], S_L_INP_TEI_UP, 0, 0);
	bts->ip_access.flags |= OML_UP;
	bts->ip_access.flags |= (RSL_UP << 0);

	return bts->oml_link;
}

void hsl_drop_oml(struct gsm_bts *bts)
{
	if (!bts->oml_link)
		return;

	e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = NULL;

	e1inp_sign_link_destroy(bts->c0->rsl_link);
	bts->c0->rsl_link = NULL;

	bts->ip_access.flags = 0;
}

static void hsl_sign_link_down(struct e1inp_line *line)
{
	/* No matter what link went down, we close both signal links. */
	struct e1inp_ts *ts = &line->ts[E1INP_SIGN_OML-1];
	struct e1inp_sign_link *link;

	llist_for_each_entry(link, &ts->sign.sign_links, list) {
		struct gsm_bts *bts = link->trx->bts;

		hsl_drop_oml(bts);
		/* Yes, we only use the first element of the list. */
		break;
       }
}

/* This function is called if we receive one OML/RSL message. */
static int hsl_sign_link(struct msgb *msg)
{
	int ret = 0;
	struct e1inp_sign_link *link = msg->dst;
	struct e1inp_ts *e1i_ts = link->ts;

	switch (link->type) {
	case E1INP_SIGN_OML:
		if (!(link->trx->bts->ip_access.flags & OML_UP)) {
			e1inp_event(e1i_ts, S_L_INP_TEI_UP,
					link->tei, link->sapi);
			link->trx->bts->ip_access.flags |= OML_UP;
		}
		ret = abis_nm_rcvmsg(msg);
		break;
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
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown signal link type %d\n",
			link->type);
		msgb_free(msg);
	break;
	}
	return ret;
}

static struct e1inp_line_ops hsl_e1inp_line_ops = {
	.cfg = {
		.ipa = {
			.addr	= "0.0.0.0",
			.role	= E1INP_LINE_R_BSC,
		},
	},
       .sign_link_up	= hsl_sign_link_up,
       .sign_link_down	= hsl_sign_link_down,
       .sign_link	= hsl_sign_link,
};

static void bts_model_hslfemto_e1line_bind_ops(struct e1inp_line *line)
{
	e1inp_line_bind_ops(line, &hsl_e1inp_line_ops);
}
