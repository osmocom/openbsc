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


#include <arpa/inet.h>

#include <osmocom/gsm/tlv.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>
#include <openbsc/e1_input.h>

static struct gsm_bts_model model_hslfemto = {
	.type = GSM_BTS_TYPE_HSL_FEMTO,
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
	uint8_t *cur;

	msg = hsl_alloc_msgb();
	cur = msgb_put(msg, sizeof(l1_msg));
	memcpy(msg->data, l1_msg, sizeof(l1_msg));
	msg->trx = bts->c0;
	abis_rsl_sendmsg(msg);

#if 1
	msg = hsl_alloc_msgb();
	cur = msgb_put(msg, sizeof(conn_trau_msg));
	memcpy(msg->data, conn_trau_msg, sizeof(conn_trau_msg));
	msg->trx = bts->c0;
	abis_rsl_sendmsg(msg);
#endif
	msg = hsl_alloc_msgb();
	cur = msgb_put(msg, sizeof(conn_trau_msg2));
	memcpy(msg->data, conn_trau_msg2, sizeof(conn_trau_msg2));
	msg->trx = bts->c0;
	abis_rsl_sendmsg(msg);

	*((uint16_t *)oml_arfcn_bsic+10) = htons(bts->c0->arfcn);
	oml_arfcn_bsic[13] = bts->bsic;

	msg = hsl_alloc_msgb();
	cur = msgb_put(msg, sizeof(oml_arfcn_bsic));
	memcpy(msg->data, oml_arfcn_bsic, sizeof(oml_arfcn_bsic));
	msg->trx = bts->c0;
	_abis_nm_sendmsg(msg, 0);

	/* Delay the OPSTART until after SI have been set via RSL */
	//abis_nm_opstart(bts, NM_OC_BTS, 255, 255, 255);

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
			if (isd->trx->bts->type == GSM_BTS_TYPE_HSL_FEMTO)
				hslfemto_bootstrap_om(isd->trx->bts);
			break;
		}
	}

	return 0;
}

int bts_model_hslfemto_init(void)
{
	model_hslfemto.features.data = &model_hslfemto._features_data[0];
	model_hslfemto.features.data_len = sizeof(model_hslfemto._features_data);

	gsm_btsmodel_set_feature(&model_hslfemto, BTS_FEAT_GPRS);
	gsm_btsmodel_set_feature(&model_hslfemto, BTS_FEAT_EGPRS);

	register_signal_handler(SS_INPUT, inp_sig_cb, NULL);

	return gsm_bts_model_register(&model_hslfemto);
}
