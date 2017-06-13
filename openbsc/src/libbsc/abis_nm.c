/* GSM Network Management (OML) messages on the A-bis interface
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libgen.h>
#include <time.h>
#include <limits.h>

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <openbsc/abis_nm.h>
#include <openbsc/misdn.h>
#include <openbsc/signal.h>
#include <osmocom/abis/e1_input.h>

#define OM_ALLOC_SIZE		1024
#define OM_HEADROOM_SIZE	128
#define IPACC_SEGMENT_SIZE	245

int abis_nm_tlv_parse(struct tlv_parsed *tp, struct gsm_bts *bts, const uint8_t *buf, int len)
{
	if (!bts->model)
		return -EIO;
	return tlv_parse(tp, &bts->model->nm_att_tlvdef, buf, len, 0, 0);
}

static int is_in_arr(enum abis_nm_msgtype mt, const enum abis_nm_msgtype *arr, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (arr[i] == mt)
			return 1;
	}

	return 0;
}

#if 0
/* is this msgtype the usual ACK/NACK type ? */
static int is_ack_nack(enum abis_nm_msgtype mt)
{
	return !is_in_arr(mt, no_ack_nack, ARRAY_SIZE(no_ack_nack));
}
#endif

/* is this msgtype a report ? */
static int is_report(enum abis_nm_msgtype mt)
{
	return is_in_arr(mt, abis_nm_reports, ARRAY_SIZE(abis_nm_reports));
}

#define MT_ACK(x)	(x+1)
#define MT_NACK(x)	(x+2)

static void fill_om_hdr(struct abis_om_hdr *oh, uint8_t len)
{
	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = len;
}

static struct abis_om_fom_hdr *fill_om_fom_hdr(struct abis_om_hdr *oh, uint8_t len,
			    uint8_t msg_type, uint8_t obj_class,
			    uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr)
{
	struct abis_om_fom_hdr *foh =
			(struct abis_om_fom_hdr *) oh->data;

	fill_om_hdr(oh, len+sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;
	return foh;
}

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE,
				   "OML");
}

int _abis_nm_sendmsg(struct msgb *msg)
{
	msg->l2h = msg->data;

	if (!msg->dst) {
		LOGP(DNM, LOGL_ERROR, "%s: msg->dst == NULL\n", __func__);
		return -EINVAL;
	}

	return abis_sendmsg(msg);
}

/* Send a OML NM Message from BSC to BTS */
static int abis_nm_queue_msg(struct gsm_bts *bts, struct msgb *msg)
{
	msg->dst = bts->oml_link;

	/* queue OML messages */
	if (llist_empty(&bts->abis_queue) && !bts->abis_nm_pend) {
		bts->abis_nm_pend = OBSC_NM_W_ACK_CB(msg);
		return _abis_nm_sendmsg(msg);
	} else {
		msgb_enqueue(&bts->abis_queue, msg);
		return 0;
	}

}

int abis_nm_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	OBSC_NM_W_ACK_CB(msg) = 1;
	return abis_nm_queue_msg(bts, msg);
}

static int abis_nm_sendmsg_direct(struct gsm_bts *bts, struct msgb *msg)
{
	OBSC_NM_W_ACK_CB(msg) = 0;
	return abis_nm_queue_msg(bts, msg);
}

static int abis_nm_rcvmsg_sw(struct msgb *mb);

int nm_is_running(struct gsm_nm_state *s) {
	return (s->operational == NM_OPSTATE_ENABLED) && (
		(s->availability == NM_AVSTATE_OK) ||
		(s->availability == 0xff)
	);
}

/* Update the administrative state of a given object in our in-memory data
 * structures and send an event to the higher layer */
static int update_admstate(struct gsm_bts *bts, uint8_t obj_class,
			   struct abis_om_obj_inst *obj_inst, uint8_t adm_state)
{
	struct gsm_nm_state *nm_state, new_state;
	struct nm_statechg_signal_data nsd;

	memset(&nsd, 0, sizeof(nsd));

	nsd.obj = gsm_objclass2obj(bts, obj_class, obj_inst);
	if (!nsd.obj)
		return -EINVAL;
	nm_state = gsm_objclass2nmstate(bts, obj_class, obj_inst);
	if (!nm_state)
		return -1;

	new_state = *nm_state;
	new_state.administrative = adm_state;

	nsd.bts = bts;
	nsd.obj_class = obj_class;
	nsd.old_state = nm_state;
	nsd.new_state = &new_state;
	nsd.obj_inst = obj_inst;
	osmo_signal_dispatch(SS_NM, S_NM_STATECHG_ADM, &nsd);

	nm_state->administrative = adm_state;

	return 0;
}

static int abis_nm_rx_statechg_rep(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct tlv_parsed tp;
	struct gsm_nm_state *nm_state, new_state;

	DEBUGPC(DNM, "STATE CHG: ");

	memset(&new_state, 0, sizeof(new_state));

	nm_state = gsm_objclass2nmstate(bts, foh->obj_class, &foh->obj_inst);
	if (!nm_state) {
		DEBUGPC(DNM, "unknown object class\n");
		return -EINVAL;
	}

	new_state = *nm_state;
	
	abis_nm_tlv_parse(&tp, bts, foh->data, oh->length-sizeof(*foh));
	if (TLVP_PRESENT(&tp, NM_ATT_OPER_STATE)) {
		new_state.operational = *TLVP_VAL(&tp, NM_ATT_OPER_STATE);
		DEBUGPC(DNM, "OP_STATE=%s ",
			abis_nm_opstate_name(new_state.operational));
	}
	if (TLVP_PRESENT(&tp, NM_ATT_AVAIL_STATUS)) {
		if (TLVP_LEN(&tp, NM_ATT_AVAIL_STATUS) == 0)
			new_state.availability = 0xff;
		else
			new_state.availability = *TLVP_VAL(&tp, NM_ATT_AVAIL_STATUS);
		DEBUGPC(DNM, "AVAIL=%s(%02x) ",
			abis_nm_avail_name(new_state.availability),
			new_state.availability);
	} else
		new_state.availability = 0xff;
	if (TLVP_PRESENT(&tp, NM_ATT_ADM_STATE)) {
		new_state.administrative = *TLVP_VAL(&tp, NM_ATT_ADM_STATE);
		DEBUGPC(DNM, "ADM=%2s ",
			get_value_string(abis_nm_adm_state_names,
					 new_state.administrative));
	}
	DEBUGPC(DNM, "\n");

	if ((new_state.administrative != 0 && nm_state->administrative == 0) ||
	    new_state.operational != nm_state->operational ||
	    new_state.availability != nm_state->availability) {
		/* Update the operational state of a given object in our in-memory data
 		* structures and send an event to the higher layer */
		struct nm_statechg_signal_data nsd;
		nsd.obj = gsm_objclass2obj(bts, foh->obj_class, &foh->obj_inst);
		nsd.obj_class = foh->obj_class;
		nsd.old_state = nm_state;
		nsd.new_state = &new_state;
		nsd.obj_inst = &foh->obj_inst;
		nsd.bts = bts;
		osmo_signal_dispatch(SS_NM, S_NM_STATECHG_OPER, &nsd);
		nm_state->operational = new_state.operational;
		nm_state->availability = new_state.availability;
		if (nm_state->administrative == 0)
			nm_state->administrative = new_state.administrative;
	}
#if 0
	if (op_state == 1) {
		/* try to enable objects that are disabled */
		abis_nm_opstart(bts, foh->obj_class,
				foh->obj_inst.bts_nr,
				foh->obj_inst.trx_nr,
				foh->obj_inst.ts_nr);
	}
#endif
	return 0;
}

static inline void log_oml_fail_rep(const struct gsm_bts *bts, const char *type,
				    const char *severity, const uint8_t *p_val,
				    const char *text)
{
	enum abis_nm_pcause_type pcause = p_val[0];
	enum abis_mm_event_causes cause = osmo_load16be(p_val + 1);

	LOGPC(DNM, LOGL_ERROR, "BTS %u: Failure Event Report: ", bts->nr);
	if (type)
		LOGPC(DNM, LOGL_ERROR, "Type=%s, ", type);
	if (severity)
		LOGPC(DNM, LOGL_ERROR, "Severity=%s, ", severity);

	LOGPC(DNM, LOGL_ERROR, "Probable cause=%s: ",
	      get_value_string(abis_nm_pcause_type_names, pcause));

	if (pcause == NM_PCAUSE_T_MANUF)
		LOGPC(DNM, LOGL_ERROR, "%s, ",
		      get_value_string(abis_mm_event_cause_names, cause));
	else
		LOGPC(DNM, LOGL_ERROR, "%02X %02X ", p_val[1], p_val[2]);

	if (text) {
		LOGPC(DNM, LOGL_ERROR, "Additional Text=%s. ", text);
	}

	LOGPC(DNM, LOGL_ERROR, "\n");
}

static inline void handle_manufact_report(struct gsm_bts *bts, const uint8_t *p_val, const char *type,
					  const char *severity, const char *text)
{
	enum abis_mm_event_causes cause = osmo_load16be(p_val + 1);

	switch (cause) {
	case OSMO_EVT_PCU_VERS:
		if (text) {
			LOGPC(DNM, LOGL_NOTICE, "BTS %u reported connected PCU version %s\n", bts->nr, text);
			osmo_strlcpy(bts->pcu_version, text, sizeof(bts->pcu_version));
		} else {
			LOGPC(DNM, LOGL_ERROR, "BTS %u reported PCU disconnection.\n", bts->nr);
			bts->pcu_version[0] = '\0';
		}
		break;
	default:
		log_oml_fail_rep(bts, type, severity, p_val, text);
	};
}

static int rx_fail_evt_rep(struct msgb *mb, struct gsm_bts *bts)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;
	int rc = 0;
	const uint8_t *p_val = NULL;
	char *p_text = NULL;
	const char *e_type = NULL, *severity = NULL;

	abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data,
			  oh->length-sizeof(*foh));

	if (TLVP_PRESENT(&tp, NM_ATT_ADD_TEXT)) {
		p_val = TLVP_VAL(&tp, NM_ATT_ADD_TEXT);
		p_text = talloc_strndup(tall_bsc_ctx, (const char *) p_val,
					TLVP_LEN(&tp, NM_ATT_ADD_TEXT));
	}

	if (TLVP_PRESENT(&tp, NM_ATT_EVENT_TYPE))
		e_type = abis_nm_event_type_name(*TLVP_VAL(&tp,
							   NM_ATT_EVENT_TYPE));

	if (TLVP_PRESENT(&tp, NM_ATT_SEVERITY))
		severity = abis_nm_severity_name(*TLVP_VAL(&tp,
							   NM_ATT_SEVERITY));

	if (TLVP_PRESENT(&tp, NM_ATT_PROB_CAUSE)) {
		p_val = TLVP_VAL(&tp, NM_ATT_PROB_CAUSE);

		switch (p_val[0]) {
		case NM_PCAUSE_T_MANUF:
			handle_manufact_report(bts, p_val, e_type, severity,
					       p_text);
			break;
		default:
			log_oml_fail_rep(bts, e_type, severity, p_val, p_text);
		};
	} else {
		LOGPC(DNM, LOGL_ERROR, "BTS%u: Failure Event Report without "
		      "Probable Cause?!\n", bts->nr);
		rc = -EINVAL;
	}

	if (p_text)
		talloc_free(p_text);

	return rc;
}

static int abis_nm_rcvmsg_report(struct msgb *mb, struct gsm_bts *bts)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	uint8_t mt = foh->msg_type;

	abis_nm_debugp_foh(DNM, foh);

	//nmh->cfg->report_cb(mb, foh);

	switch (mt) {
	case NM_MT_STATECHG_EVENT_REP:
		return abis_nm_rx_statechg_rep(mb);
		break;
	case NM_MT_SW_ACTIVATED_REP:
		DEBUGPC(DNM, "Software Activated Report\n");
		osmo_signal_dispatch(SS_NM, S_NM_SW_ACTIV_REP, mb);
		break;
	case NM_MT_FAILURE_EVENT_REP:
		rx_fail_evt_rep(mb, bts);
		osmo_signal_dispatch(SS_NM, S_NM_FAIL_REP, mb);
		break;
	case NM_MT_TEST_REP:
		DEBUGPC(DNM, "Test Report\n");
		osmo_signal_dispatch(SS_NM, S_NM_TEST_REP, mb);
		break;
	default:
		DEBUGPC(DNM, "reporting NM MT 0x%02x\n", mt);
		break;
		
	};

	return 0;
}

/* Activate the specified software into the BTS */
static int ipacc_sw_activate(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0, uint8_t i1,
			     uint8_t i2, const struct abis_nm_sw_desc *sw_desc)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint16_t len = abis_nm_sw_desc_len(sw_desc, true);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ACTIVATE_SW, obj_class, i0, i1, i2);
	abis_nm_put_sw_desc(msg, sw_desc, true);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_select_newest_sw(const struct abis_nm_sw_desc *sw_descr,
			     const size_t size)
{
	int res = 0;
	int i;

	for (i = 1; i < size; ++i) {
		if (memcmp(sw_descr[res].file_version, sw_descr[i].file_version,
			   OSMO_MIN(sw_descr[i].file_version_len,
				    sw_descr[res].file_version_len)) < 0) {
			res = i;
		}
	}

	return res;
}

static inline bool handle_attr(const struct gsm_bts *bts, enum bts_attribute id, uint8_t *val, uint8_t len)
{
	switch (id) {
	case BTS_TYPE_VARIANT:
		LOGP(DNM, LOGL_NOTICE, "BTS%u reported variant: %s\n", bts->nr, val);
		break;
	case BTS_SUB_MODEL:
		LOGP(DNM, LOGL_NOTICE, "BTS%u reported submodel: %s\n", bts->nr, val);
		break;
	default:
		return false;
	}
	return true;
}

/* Parse Attribute Response Info - return pointer to the actual content */
static inline uint8_t *parse_attr_resp_info_unreported(uint8_t bts_nr, uint8_t *ari, uint16_t ari_len, uint16_t *out_len)
{
	uint8_t num_unreported = ari[0], i;

	DEBUGP(DNM, "BTS%u Get Attributes Response Info: %u bytes total with %u unreported attributes\n",
	       bts_nr, ari_len, num_unreported);

	/* +1 because we have to account for number of unreported attributes, prefixing the list: */
	for (i = 0; i < num_unreported; i++)
		LOGP(DNM, LOGL_ERROR, "BTS%u Attribute %s is unreported\n",
		     bts_nr, get_value_string(abis_nm_att_names, ari[i + 1]));

	/* the data starts right after the list of unreported attributes + space for length of that list */
	*out_len = ari_len - (num_unreported + 2);

	return ari + num_unreported + 1; /* we have to account for 1st byte with number of unreported attributes */
}

/* Parse Attribute Response Info content for 3GPP TS 52.021 §9.4.30 Manufacturer Id */
static inline uint8_t *parse_attr_resp_info_manuf_id(struct gsm_bts *bts, uint8_t *data, uint16_t *data_len)
{
	struct tlv_parsed tp;
	uint16_t m_id_len = 0;
	uint8_t adjust = 0, i;

	abis_nm_tlv_parse(&tp, bts, data, *data_len);
	if (TLVP_PRES_LEN(&tp, NM_ATT_MANUF_ID, 2)) {
		m_id_len = TLVP_LEN(&tp, NM_ATT_MANUF_ID);

		/* log potential BTS feature vector overflow */
		if (m_id_len > sizeof(bts->_features_data))
			LOGP(DNM, LOGL_NOTICE, "BTS%u Get Attributes Response: feature vector is truncated to %u bytes\n",
			     bts->nr, MAX_BTS_FEATURES/8);

		/* check that max. expected BTS attribute is above given feature vector length */
		if (m_id_len > OSMO_BYTES_FOR_BITS(_NUM_BTS_FEAT))
			LOGP(DNM, LOGL_NOTICE, "BTS%u Get Attributes Response: reported unexpectedly long (%u bytes) "
			     "feature vector - most likely it was compiled against newer BSC headers. "
			     "Consider upgrading your BSC to later version.\n",
			     bts->nr, m_id_len);

		memcpy(bts->_features_data, TLVP_VAL(&tp, NM_ATT_MANUF_ID), sizeof(bts->_features_data));
		adjust = m_id_len + 3; /* adjust for parsed TL16V struct */

		for (i = 0; i < _NUM_BTS_FEAT; i++)
			if (gsm_bts_has_feature(bts, i) != gsm_btsmodel_has_feature(bts->model, i))
				LOGP(DNM, LOGL_NOTICE, "BTS%u feature '%s' reported via OML does not match statically "
				     "set feature: %u != %u. Please fix.\n", bts->nr,
				     get_value_string(gsm_bts_features_descs, i),
				     gsm_bts_has_feature(bts, i), gsm_btsmodel_has_feature(bts->model, i));
	}

	*data_len -= adjust;

	return data + adjust;
}

/* Parse Attribute Response Info content for 3GPP TS 52.021 §9.4.28 Manufacturer Dependent State */
static inline uint8_t *parse_attr_resp_info_manuf_state(const struct gsm_bts_trx *trx, uint8_t *data, uint16_t *data_len)
{
	struct tlv_parsed tp;
	const uint8_t *power;
	uint8_t adjust = 0;

	if (!trx) /* this attribute does not make sense on BTS level, only on TRX level */
		return data;

	abis_nm_tlv_parse(&tp, trx->bts, data, *data_len);
	if (TLVP_PRES_LEN(&tp, NM_ATT_MANUF_STATE, 1)) {
		power = TLVP_VAL(&tp, NM_ATT_MANUF_STATE);
		LOGP(DNM, LOGL_NOTICE, "%s Get Attributes Response: nominal power is %u\n", gsm_trx_name(trx), *power);
		adjust = 2; /* adjust for parsed TV struct */
	}

	*data_len -= adjust;

	return data + adjust;
}

/* Handle 3GPP TS 52.021 §9.4.64 Get Attribute Response Info */
static int abis_nm_rx_get_attr_resp(struct msgb *mb, const struct gsm_bts_trx *trx)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct gsm_bts *bts = trx ? trx->bts : sign_link->trx->bts;
	struct tlv_parsed tp;
	uint8_t *data, i;
	uint16_t data_len;
	int rc;
	struct abis_nm_sw_desc sw_descr[MAX_BTS_ATTR];

	abis_nm_debugp_foh(DNM, foh);

	DEBUGPC(DNM, "Get Attributes Response for BTS%u\n", bts->nr);

	abis_nm_tlv_parse(&tp, bts, foh->data, oh->length-sizeof(*foh));
	if (!TLVP_PRES_LEN(&tp, NM_ATT_GET_ARI, 1)) {
		LOGP(DNM, LOGL_ERROR, "BTS%u: Get Attributes Response without Response Info?!\n", bts->nr);
		return -EINVAL;
	}

	data = parse_attr_resp_info_unreported(bts->nr, TLVP_VAL(&tp, NM_ATT_GET_ARI), TLVP_LEN(&tp, NM_ATT_GET_ARI),
					       &data_len);

	data = parse_attr_resp_info_manuf_state(trx, data, &data_len);
	data = parse_attr_resp_info_manuf_id(bts, data, &data_len);

	/* after parsing manufacturer-specific attributes there's list of replies in form of sw-conf structure: */
	rc = abis_nm_get_sw_conf(data, data_len, &sw_descr[0], ARRAY_SIZE(sw_descr));
	if (rc > 0) {
		for (i = 0; i < rc; i++) {
			if (!handle_attr(bts, str2btsattr((const char *)sw_descr[i].file_id),
					 sw_descr[i].file_version, sw_descr[i].file_version_len))
				LOGP(DNM, LOGL_NOTICE, "BTS%u: ARI reported sw[%d/%d]: %s is %s\n",
				     bts->nr, i, rc, sw_descr[i].file_id, sw_descr[i].file_version);
		}
	} else
		LOGP(DNM, LOGL_ERROR, "BTS%u: failed to parse SW-Config part of Get Attribute Response Info: %s\n",
		     bts->nr, strerror(-rc));

	return 0;
}

/* 3GPP TS 52.021 §6.2.5 */
static int abis_nm_rx_sw_act_req(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;
	const uint8_t *sw_config;
	int ret, sw_config_len, len;
	struct abis_nm_sw_desc sw_descr[MAX_BTS_ATTR];

	abis_nm_debugp_foh(DNM, foh);

	DEBUGPC(DNM, "SW Activate Request: ");

	DEBUGP(DNM, "Software Activate Request, ACKing and Activating\n");

	ret = abis_nm_sw_act_req_ack(sign_link->trx->bts, foh->obj_class,
				      foh->obj_inst.bts_nr,
				      foh->obj_inst.trx_nr,
				      foh->obj_inst.ts_nr, 0,
				      foh->data, oh->length-sizeof(*foh));
	if (ret != 0) {
		LOGP(DNM, LOGL_ERROR,
			"Sending SW ActReq ACK failed: %d\n", ret);
		return ret;
	}

	abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length-sizeof(*foh));
	sw_config = TLVP_VAL(&tp, NM_ATT_SW_CONFIG);
	sw_config_len = TLVP_LEN(&tp, NM_ATT_SW_CONFIG);
	if (!TLVP_PRESENT(&tp, NM_ATT_SW_CONFIG)) {
		LOGP(DNM, LOGL_ERROR,
			"SW config not found! Can't continue.\n");
		return -EINVAL;
	} else {
		DEBUGP(DNM, "Found SW config: %s\n", osmo_hexdump(sw_config, sw_config_len));
	}

	/* Parse up to two sw descriptions from the data */
	len = abis_nm_get_sw_conf(sw_config, sw_config_len, &sw_descr[0],
				  ARRAY_SIZE(sw_descr));
	if (len <= 0) {
		LOGP(DNM, LOGL_ERROR, "Failed to parse SW Config.\n");
		return -EINVAL;
	}

	ret = abis_nm_select_newest_sw(&sw_descr[0], len);
	DEBUGP(DNM, "Selected sw description %d of %d\n", ret, len);

	return ipacc_sw_activate(sign_link->trx->bts, foh->obj_class,
				 foh->obj_inst.bts_nr,
				 foh->obj_inst.trx_nr,
				 foh->obj_inst.ts_nr,
				 &sw_descr[ret]);
}

/* Receive a CHANGE_ADM_STATE_ACK, parse the TLV and update local state */
static int abis_nm_rx_chg_adm_state_ack(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;
	uint8_t adm_state;

	abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length-sizeof(*foh));
	if (!TLVP_PRESENT(&tp, NM_ATT_ADM_STATE))
		return -EINVAL;

	adm_state = *TLVP_VAL(&tp, NM_ATT_ADM_STATE);

	return update_admstate(sign_link->trx->bts, foh->obj_class, &foh->obj_inst, adm_state);
}

static int abis_nm_rx_lmt_event(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	struct tlv_parsed tp;

	DEBUGP(DNM, "LMT Event ");
	abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length-sizeof(*foh));
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_LOGON_SESSION) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_LOGON_SESSION) >= 1) {
		uint8_t onoff = *TLVP_VAL(&tp, NM_ATT_BS11_LMT_LOGON_SESSION);
		DEBUGPC(DNM, "LOG%s ", onoff ? "ON" : "OFF");
	}
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV) >= 1) {
		uint8_t level = *TLVP_VAL(&tp, NM_ATT_BS11_LMT_USER_ACC_LEV);
		DEBUGPC(DNM, "Level=%u ", level);
	}
	if (TLVP_PRESENT(&tp, NM_ATT_BS11_LMT_USER_NAME) &&
	    TLVP_LEN(&tp, NM_ATT_BS11_LMT_USER_NAME) >= 1) {
		char *name = (char *) TLVP_VAL(&tp, NM_ATT_BS11_LMT_USER_NAME);
		DEBUGPC(DNM, "Username=%s ", name);
	}
	DEBUGPC(DNM, "\n");
	/* FIXME: parse LMT LOGON TIME */
	return 0;
}

void abis_nm_queue_send_next(struct gsm_bts *bts)
{
	int wait = 0;
	struct msgb *msg;
	/* the queue is empty */
	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		wait = OBSC_NM_W_ACK_CB(msg);
		_abis_nm_sendmsg(msg);

		if (wait)
			break;
	}

	bts->abis_nm_pend = wait;
}

/* Receive a OML NM Message from BTS */
static int abis_nm_rcvmsg_fom(struct msgb *mb)
{
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	uint8_t mt = foh->msg_type;
	/* sign_link might get deleted via osmo_signal_dispatch -> save bts */
	struct gsm_bts *bts = sign_link->trx->bts;
	int ret = 0;

	/* check for unsolicited message */
	if (is_report(mt))
		return abis_nm_rcvmsg_report(mb, bts);

	if (is_in_arr(mt, abis_nm_sw_load_msgs, ARRAY_SIZE(abis_nm_sw_load_msgs)))
		return abis_nm_rcvmsg_sw(mb);

	if (is_in_arr(mt, abis_nm_nacks, ARRAY_SIZE(abis_nm_nacks))) {
		struct nm_nack_signal_data nack_data;
		struct tlv_parsed tp;

		abis_nm_debugp_foh(DNM, foh);

		DEBUGPC(DNM, "%s NACK ", abis_nm_nack_name(mt));

		abis_nm_tlv_parse(&tp, bts, foh->data, oh->length-sizeof(*foh));
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			DEBUGPC(DNM, "CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			DEBUGPC(DNM, "\n");

		nack_data.msg = mb;
		nack_data.mt = mt;
		nack_data.bts = bts;
		osmo_signal_dispatch(SS_NM, S_NM_NACK, &nack_data);
		abis_nm_queue_send_next(bts);
		return 0;
	}
#if 0
	/* check if last message is to be acked */
	if (is_ack_nack(nmh->last_msgtype)) {
		if (mt == MT_ACK(nmh->last_msgtype)) {
			DEBUGP(DNM, "received ACK (0x%x)\n", foh->msg_type);
			/* we got our ACK, continue sending the next msg */
		} else if (mt == MT_NACK(nmh->last_msgtype)) {
			/* we got a NACK, signal this to the caller */
			DEBUGP(DNM, "received NACK (0x%x)\n", foh->msg_type);
			/* FIXME: somehow signal this to the caller */
		} else {
			/* really strange things happen */
			return -EINVAL;
		}
	}
#endif

	switch (mt) {
	case NM_MT_CHG_ADM_STATE_ACK:
		ret = abis_nm_rx_chg_adm_state_ack(mb);
		break;
	case NM_MT_SW_ACT_REQ:
		ret = abis_nm_rx_sw_act_req(mb);
		break;
	case NM_MT_BS11_LMT_SESSION:
		ret = abis_nm_rx_lmt_event(mb);
		break;
	case NM_MT_OPSTART_ACK:
		abis_nm_debugp_foh(DNM, foh);
		DEBUGPC(DNM, "Opstart ACK\n");
		break;
	case NM_MT_SET_CHAN_ATTR_ACK:
		abis_nm_debugp_foh(DNM, foh);
		DEBUGPC(DNM, "Set Channel Attributes ACK\n");
		break;
	case NM_MT_SET_RADIO_ATTR_ACK:
		abis_nm_debugp_foh(DNM, foh);
		DEBUGPC(DNM, "Set Radio Carrier Attributes ACK\n");
		break;
	case NM_MT_CONN_MDROP_LINK_ACK:
		abis_nm_debugp_foh(DNM, foh);
		DEBUGPC(DNM, "CONN MDROP LINK ACK\n");
		break;
	case NM_MT_IPACC_RESTART_ACK:
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_RESTART_ACK, NULL);
		break;
	case NM_MT_IPACC_RESTART_NACK:
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_RESTART_NACK, NULL);
		break;
	case NM_MT_SET_BTS_ATTR_ACK:
		break;
	case NM_MT_GET_ATTR_RESP:
		ret = abis_nm_rx_get_attr_resp(mb, gsm_bts_trx_num(bts, (foh)->obj_inst.trx_nr));
		break;
	default:
		abis_nm_debugp_foh(DNM, foh);
		LOGPC(DNM, LOGL_ERROR, "Unhandled message %s\n",
		      get_value_string(abis_nm_msgtype_names, mt));
	}

	abis_nm_queue_send_next(bts);
	return ret;
}

static int abis_nm_rx_ipacc(struct msgb *mb);

static int abis_nm_rcvmsg_manuf(struct msgb *mb)
{
	int rc;
	struct e1inp_sign_link *sign_link = mb->dst;
	int bts_type = sign_link->trx->bts->type;

	switch (bts_type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		rc = abis_nm_rx_ipacc(mb);
		abis_nm_queue_send_next(sign_link->trx->bts);
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "don't know how to parse OML for this "
		     "BTS type (%u)\n", bts_type);
		rc = 0;
		break;
	}

	return rc;
}

/* High-Level API */
/* Entry-point where L2 OML from BTS enters the NM code */
int abis_nm_rcvmsg(struct msgb *msg)
{
	struct abis_om_hdr *oh = msgb_l2(msg);
	int rc = 0;

	/* Various consistency checks */
	if (oh->placement != ABIS_OM_PLACEMENT_ONLY) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML placement 0x%x not supported\n",
			oh->placement);
		if (oh->placement != ABIS_OM_PLACEMENT_FIRST) {
			rc = -EINVAL;
			goto err;
		}
	}
	if (oh->sequence != 0) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML sequence 0x%x != 0x00\n",
			oh->sequence);
		rc = -EINVAL;
		goto err;
	}
#if 0
	unsigned int l2_len = msg->tail - (uint8_t *)msgb_l2(msg);
	unsigned int hlen = sizeof(*oh) + sizeof(struct abis_om_fom_hdr);
	if (oh->length + hlen > l2_len) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML truncated message (%u > %u)\n",
			oh->length + sizeof(*oh), l2_len);
		return -EINVAL;
	}
	if (oh->length + hlen < l2_len)
		LOGP(DNM, LOGL_ERROR, "ABIS OML message with extra trailer?!? (oh->len=%d, sizeof_oh=%d l2_len=%d\n", oh->length, sizeof(*oh), l2_len);
#endif
	msg->l3h = (unsigned char *)oh + sizeof(*oh);

	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		rc = abis_nm_rcvmsg_fom(msg);
		break;
	case ABIS_OM_MDISC_MANUF:
		rc = abis_nm_rcvmsg_manuf(msg);
		break;
	case ABIS_OM_MDISC_MMI:
	case ABIS_OM_MDISC_TRAU:
		LOGP(DNM, LOGL_ERROR, "unimplemented ABIS OML message discriminator 0x%x\n",
			oh->mdisc);
		break;
	default:
		LOGP(DNM, LOGL_ERROR, "unknown ABIS OML message discriminator 0x%x\n",
			oh->mdisc);
		rc = -EINVAL;
		break;
	}
err:
	msgb_free(msg);
	return rc;
}

#if 0
/* initialized all resources */
struct abis_nm_h *abis_nm_init(struct abis_nm_cfg *cfg)
{
	struct abis_nm_h *nmh;

	nmh = malloc(sizeof(*nmh));
	if (!nmh)
		return NULL;

	nmh->cfg = cfg;

	return nmh;
}

/* free all resources */
void abis_nm_fini(struct abis_nm_h *nmh)
{
	free(nmh);
}
#endif

/* Here we are trying to define a high-level API that can be used by
 * the actual BSC implementation.  However, the architecture is currently
 * still under design.  Ideally the calls to this API would be synchronous,
 * while the underlying stack behind the APi runs in a traditional select
 * based state machine.
 */

/* 6.2 Software Load: */
enum sw_state {
	SW_STATE_NONE,
	SW_STATE_WAIT_INITACK,
	SW_STATE_WAIT_SEGACK,
	SW_STATE_WAIT_ENDACK,
	SW_STATE_WAIT_ACTACK,
	SW_STATE_ERROR,
};

struct abis_nm_sw {
	struct gsm_bts *bts;
	int trx_nr;
	gsm_cbfn *cbfn;
	void *cb_data;
	int forced;

	/* this will become part of the SW LOAD INITIATE */
	uint8_t obj_class;
	uint8_t obj_instance[3];

	uint8_t file_id[255];
	uint8_t file_id_len;

	uint8_t file_version[255];
	uint8_t file_version_len;

	uint8_t window_size;
	uint8_t seg_in_window;

	int fd;
	FILE *stream;
	enum sw_state state;
	int last_seg;
};

static struct abis_nm_sw g_sw;

static void sw_add_file_id_and_ver(struct abis_nm_sw *sw, struct msgb *msg)
{
	if (sw->bts->type == GSM_BTS_TYPE_NANOBTS) {
		msgb_v_put(msg, NM_ATT_SW_DESCR);
		msgb_tl16v_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
		msgb_tl16v_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
			       sw->file_version);
	} else if (sw->bts->type == GSM_BTS_TYPE_BS11) {
		msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
		msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
			     sw->file_version);
	} else {
		LOGP(DNM, LOGL_ERROR, "Please implement this for the BTS.\n");
	}
}

/* 6.2.1 / 8.3.1: Load Data Initiate */
static int sw_load_init(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 3*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_INIT, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	sw_add_file_id_and_ver(sw, msg);
	msgb_tv_put(msg, NM_ATT_WINDOW_SIZE, sw->window_size);
	
	return abis_nm_sendmsg(sw->bts, msg);
}

static int is_last_line(FILE *stream)
{
	char next_seg_buf[256];
	long pos;

	/* check if we're sending the last line */
	pos = ftell(stream);

	/* Did ftell fail? Then we are at the end for sure */
	if (pos < 0)
		return 1;

	if (!fgets(next_seg_buf, sizeof(next_seg_buf)-2, stream)) {
		int rc = fseek(stream, pos, SEEK_SET);
		if (rc < 0)
			return rc;
		return 1;
	}

	fseek(stream, pos, SEEK_SET);
	return 0;
}

/* 6.2.2 / 8.3.2 Load Data Segment */
static int sw_load_segment(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	char seg_buf[256];
	char *line_buf = seg_buf+2;
	unsigned char *tlv;
	int len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);

	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		if (fgets(line_buf, sizeof(seg_buf)-2, sw->stream) == NULL) {
			perror("fgets reading segment");
			return -EINVAL;
		}
		seg_buf[0] = 0x00;

		/* check if we're sending the last line */
		sw->last_seg = is_last_line(sw->stream);
		if (sw->last_seg)
			seg_buf[1] = 0;
		else
			seg_buf[1] = 1 + sw->seg_in_window++;

		len = strlen(line_buf) + 2;
		tlv = msgb_put(msg, TLV_GROSS_LEN(len));
		tlv_put(tlv, NM_ATT_BS11_FILE_DATA, len, (uint8_t *)seg_buf);
		/* BS11 wants CR + LF in excess of the TLV length !?! */
		tlv[1] -= 2;

		/* we only now know the exact length for the OM hdr */
		len = strlen(line_buf)+2;
		break;
	case GSM_BTS_TYPE_NANOBTS: {
		osmo_static_assert(sizeof(seg_buf) >= IPACC_SEGMENT_SIZE, buffer_big_enough);
		len = read(sw->fd, &seg_buf, IPACC_SEGMENT_SIZE);
		if (len < 0) {
			perror("read failed");
			return -EINVAL;
		}

		if (len != IPACC_SEGMENT_SIZE)
			sw->last_seg = 1;

		++sw->seg_in_window;
		msgb_tl16v_put(msg, NM_ATT_IPACC_FILE_DATA, len, (const uint8_t *) seg_buf);
		len += 3;
		break;
	}
	default:
		LOGP(DNM, LOGL_ERROR, "sw_load_segment needs implementation for the BTS.\n");
		/* FIXME: Other BTS types */
		return -1;
	}

	fill_om_fom_hdr(oh, len, NM_MT_LOAD_SEG, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	return abis_nm_sendmsg_direct(sw->bts, msg);
}

/* 6.2.4 / 8.3.4 Load Data End */
static int sw_load_end(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_END, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	sw_add_file_id_and_ver(sw, msg);
	return abis_nm_sendmsg(sw->bts, msg);
}

/* Activate the specified software into the BTS */
static int sw_activate(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ACTIVATE_SW, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	/* FIXME: this is BS11 specific format */
	msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
		     sw->file_version);

	return abis_nm_sendmsg(sw->bts, msg);
}

struct sdp_firmware {
	char magic[4];
	char more_magic[4];
	unsigned int header_length;
	unsigned int file_length;
} __attribute__ ((packed));

static int parse_sdp_header(struct abis_nm_sw *sw)
{
	struct sdp_firmware firmware_header;
	int rc;
	struct stat stat;

	rc = read(sw->fd, &firmware_header, sizeof(firmware_header));
	if (rc != sizeof(firmware_header)) {
		LOGP(DNM, LOGL_ERROR, "Could not read SDP file header.\n");
		return -1;
	}

	if (strncmp(firmware_header.magic, " SDP", 4) != 0) {
		LOGP(DNM, LOGL_ERROR, "The magic number1 is wrong.\n");
		return -1;
	}

	if (firmware_header.more_magic[0] != 0x10 ||
	    firmware_header.more_magic[1] != 0x02 ||
	    firmware_header.more_magic[2] != 0x00 ||
	    firmware_header.more_magic[3] != 0x00) {
		LOGP(DNM, LOGL_ERROR, "The more magic number is wrong.\n");
		return -1;
	}


	if (fstat(sw->fd, &stat) == -1) {
		LOGP(DNM, LOGL_ERROR, "Could not stat the file.\n");
		return -1;
	}

	if (ntohl(firmware_header.file_length) != stat.st_size) {
		LOGP(DNM, LOGL_ERROR, "The filesizes do not match.\n");
		return -1;
	}

	/* go back to the start as we checked the whole filesize.. */
	lseek(sw->fd, 0l, SEEK_SET);
	LOGP(DNM, LOGL_NOTICE, "The ipaccess SDP header is not fully understood.\n"
			       "There might be checksums in the file that are not\n"
			       "verified and incomplete firmware might be flashed.\n"
			       "There is absolutely no WARRANTY that flashing will\n"
			       "work.\n");
	return 0;
}

static int sw_open_file(struct abis_nm_sw *sw, const char *fname)
{
	char file_id[12+1];
	char file_version[80+1];
	int rc;

	sw->fd = open(fname, O_RDONLY);
	if (sw->fd < 0)
		return sw->fd;

	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		sw->stream = fdopen(sw->fd, "r");
		if (!sw->stream) {
			perror("fdopen");
			return -1;
		}
		/* read first line and parse file ID and VERSION */
		rc = fscanf(sw->stream, "@(#)%12s:%80s\r\n",
			    file_id, file_version);
		if (rc != 2) {
			perror("parsing header line of software file");
			return -1;
		}
		strcpy((char *)sw->file_id, file_id);
		sw->file_id_len = strlen(file_id);
		strcpy((char *)sw->file_version, file_version);
		sw->file_version_len = strlen(file_version);
		/* rewind to start of file */
		rewind(sw->stream);
		break;	
	case GSM_BTS_TYPE_NANOBTS:
		/* TODO: extract that from the filename or content */
		rc = parse_sdp_header(sw);
		if (rc < 0) {
			fprintf(stderr, "Could not parse the ipaccess SDP header\n");
			return -1;
		}

		strcpy((char *)sw->file_id, "id");
		sw->file_id_len = 3;
		strcpy((char *)sw->file_version, "version");
		sw->file_version_len = 8;
		break;
	default:
		/* We don't know how to treat them yet */
		close(sw->fd);
		return -EINVAL;
	}

	return 0;
}
	
static void sw_close_file(struct abis_nm_sw *sw)
{
	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		fclose(sw->stream);
		break;
	default:
		close(sw->fd);
		break;
	}
}

/* Fill the window */
static int sw_fill_window(struct abis_nm_sw *sw)
{
	int rc;

	while (sw->seg_in_window < sw->window_size) {
		rc = sw_load_segment(sw);
		if (rc < 0)
			return rc;
		if (sw->last_seg)
			break;
	}
	return 0;
}

/* callback function from abis_nm_rcvmsg() handler */
static int abis_nm_rcvmsg_sw(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct e1inp_sign_link *sign_link = mb->dst;
	int rc = -1;
	struct abis_nm_sw *sw = &g_sw;
	enum sw_state old_state = sw->state;
	
	//DEBUGP(DNM, "state %u, NM MT 0x%02x\n", sw->state, foh->msg_type);

	switch (sw->state) {
	case SW_STATE_WAIT_INITACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_INIT_ACK:
			/* fill window with segments */
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_INIT_ACK, mb,
					 sw->cb_data, NULL);
			rc = sw_fill_window(sw);
			sw->state = SW_STATE_WAIT_SEGACK;
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_INIT_NACK:
			if (sw->forced) {
				DEBUGP(DNM, "FORCED: Ignoring Software Load "
					"Init NACK\n");
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_INIT_ACK, mb,
						 sw->cb_data, NULL);
				rc = sw_fill_window(sw);
				sw->state = SW_STATE_WAIT_SEGACK;
			} else {
				DEBUGP(DNM, "Software Load Init NACK\n");
				/* FIXME: cause */
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_INIT_NACK, mb,
						 sw->cb_data, NULL);
				sw->state = SW_STATE_ERROR;
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
		break;
	case SW_STATE_WAIT_SEGACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_SEG_ACK:
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_SEG_ACK, mb,
					 sw->cb_data, NULL);
			sw->seg_in_window = 0;
			if (!sw->last_seg) {
				/* fill window with more segments */
				rc = sw_fill_window(sw);
				sw->state = SW_STATE_WAIT_SEGACK;
			} else {
				/* end the transfer */
				sw->state = SW_STATE_WAIT_ENDACK;
				rc = sw_load_end(sw);
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_ABORT:
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_ABORT, mb,
					 sw->cb_data, NULL);
			break;
		}
		break;
	case SW_STATE_WAIT_ENDACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_END_ACK:
			sw_close_file(sw);
			DEBUGP(DNM, "Software Load End (BTS %u)\n",
				sw->bts->nr);
			sw->state = SW_STATE_NONE;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_LOAD_END_ACK, mb,
					 sw->cb_data, NULL);
			rc = 0;
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_LOAD_END_NACK:
			if (sw->forced) {
				DEBUGP(DNM, "FORCED: Ignoring Software Load"
					"End NACK\n");
				sw->state = SW_STATE_NONE;
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_END_ACK, mb,
						 sw->cb_data, NULL);
			} else {
				DEBUGP(DNM, "Software Load End NACK\n");
				/* FIXME: cause */
				sw->state = SW_STATE_ERROR;
				if (sw->cbfn)
					sw->cbfn(GSM_HOOK_NM_SWLOAD,
						 NM_MT_LOAD_END_NACK, mb,
						 sw->cb_data, NULL);
			}
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
	case SW_STATE_WAIT_ACTACK:
		switch (foh->msg_type) {
		case NM_MT_ACTIVATE_SW_ACK:
			/* we're done */
			DEBUGP(DNM, "Activate Software DONE!\n");
			sw->state = SW_STATE_NONE;
			rc = 0;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_ACTIVATE_SW_ACK, mb,
					 sw->cb_data, NULL);
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		case NM_MT_ACTIVATE_SW_NACK:
			DEBUGP(DNM, "Activate Software NACK\n");
			/* FIXME: cause */
			sw->state = SW_STATE_ERROR;
			if (sw->cbfn)
				sw->cbfn(GSM_HOOK_NM_SWLOAD,
					 NM_MT_ACTIVATE_SW_NACK, mb,
					 sw->cb_data, NULL);
			abis_nm_queue_send_next(sign_link->trx->bts);
			break;
		}
	case SW_STATE_NONE:
		switch (foh->msg_type) {
		case NM_MT_ACTIVATE_SW_ACK:
			rc = 0;
			break;
		}
		break;
	case SW_STATE_ERROR:
		break;
	}

	if (rc)
		DEBUGP(DNM, "unexpected NM MT 0x%02x in state %u -> %u\n",
			foh->msg_type, old_state, sw->state);

	return rc;
}

/* Load the specified software into the BTS */
int abis_nm_software_load(struct gsm_bts *bts, int trx_nr, const char *fname,
			  uint8_t win_size, int forced,
			  gsm_cbfn *cbfn, void *cb_data)
{
	struct abis_nm_sw *sw = &g_sw;
	int rc;

	DEBUGP(DNM, "Software Load (BTS %u, File \"%s\")\n",
		bts->nr, fname);

	if (sw->state != SW_STATE_NONE)
		return -EBUSY;

	sw->bts = bts;
	sw->trx_nr = trx_nr;

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		sw->obj_class = NM_OC_SITE_MANAGER;
		sw->obj_instance[0] = 0xff;
		sw->obj_instance[1] = 0xff;
		sw->obj_instance[2] = 0xff;
		break;
	case GSM_BTS_TYPE_NANOBTS:
		sw->obj_class = NM_OC_BASEB_TRANSC;
		sw->obj_instance[0] = sw->bts->nr;
		sw->obj_instance[1] = sw->trx_nr;
		sw->obj_instance[2] = 0xff;
		break;
	case GSM_BTS_TYPE_UNKNOWN:
	default:
		LOGPC(DNM, LOGL_ERROR, "Software Load not properly implemented.\n");
		return -1;
		break;
	}
	sw->window_size = win_size;
	sw->state = SW_STATE_WAIT_INITACK;
	sw->cbfn = cbfn;
	sw->cb_data = cb_data;
	sw->forced = forced;

	rc = sw_open_file(sw, fname);
	if (rc < 0) {
		sw->state = SW_STATE_NONE;
		return rc;
	}

	return sw_load_init(sw);
}

int abis_nm_software_load_status(struct gsm_bts *bts)
{
	struct abis_nm_sw *sw = &g_sw;
	struct stat st;
	int rc, percent;

	rc = fstat(sw->fd, &st);
	if (rc < 0) {
		perror("ERROR during stat");
		return rc;
	}

	if (sw->stream)
		percent = (ftell(sw->stream) * 100) / st.st_size;
	else
		percent = (lseek(sw->fd, 0, SEEK_CUR) * 100) / st.st_size;
	return percent;
}

/* Activate the specified software into the BTS */
int abis_nm_software_activate(struct gsm_bts *bts, const char *fname,
			      gsm_cbfn *cbfn, void *cb_data)
{
	struct abis_nm_sw *sw = &g_sw;
	int rc;

	DEBUGP(DNM, "Activating Software (BTS %u, File \"%s\")\n",
		bts->nr, fname);

	if (sw->state != SW_STATE_NONE)
		return -EBUSY;

	sw->bts = bts;
	sw->obj_class = NM_OC_SITE_MANAGER;
	sw->obj_instance[0] = 0xff;
	sw->obj_instance[1] = 0xff;
	sw->obj_instance[2] = 0xff;
	sw->state = SW_STATE_WAIT_ACTACK;
	sw->cbfn = cbfn;
	sw->cb_data = cb_data;

	/* Open the file in order to fill some sw struct members */
	rc = sw_open_file(sw, fname);
	if (rc < 0) {
		sw->state = SW_STATE_NONE;
		return rc;
	}
	sw_close_file(sw);

	return sw_activate(sw);
}

static void fill_nm_channel(struct abis_nm_channel *ch, uint8_t bts_port,
		       uint8_t ts_nr, uint8_t subslot_nr)
{
	ch->attrib = NM_ATT_ABIS_CHANNEL;
	ch->bts_port = bts_port;
	ch->timeslot = ts_nr;
	ch->subslot = subslot_nr;	
}

int abis_nm_establish_tei(struct gsm_bts *bts, uint8_t trx_nr,
			  uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot,
			  uint8_t tei)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	uint8_t len = sizeof(*ch) + 2;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ESTABLISH_TEI, NM_OC_RADIO_CARRIER,
			bts->bts_nr, trx_nr, 0xff);
	
	msgb_tv_put(msg, NM_ATT_TEI, tei);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

/* connect signalling of one (BTS,TRX) to a particular timeslot on the E1 */
int abis_nm_conn_terr_sign(struct gsm_bts_trx *trx,
			   uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot)
{
	struct gsm_bts *bts = trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_SIGN,
			NM_OC_RADIO_CARRIER, bts->bts_nr, trx->nr, 0xff);
	
	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_sign(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan)
{
}
#endif

int abis_nm_conn_terr_traf(struct gsm_bts_trx_ts *ts,
			   uint8_t e1_port, uint8_t e1_timeslot,
			   uint8_t e1_subslot)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_TRAF,
			NM_OC_CHANNEL, bts->bts_nr, ts->trx->nr, ts->nr);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	DEBUGP(DNM, "CONNECT TERR TRAF Um=%s E1=(%u,%u,%u)\n",
		gsm_ts_name(ts),
		e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_traf(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan,
			   uint8_t subchan)
{
}
#endif

/* 3GPP TS 52.021 § 8.11.1 */
int abis_nm_get_attr(struct gsm_bts *bts, uint8_t obj_class, uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
		     const uint8_t *attr, uint8_t attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	DEBUGP(DNM, "Get Attr (bts=%d)\n", bts->nr);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_GET_ATTR, obj_class,
			bts_nr, trx_nr, ts_nr);
	msgb_tl16v_put(msg, NM_ATT_LIST_REQ_ATTR, attr_len, attr);

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.6.1 */
int abis_nm_set_bts_attr(struct gsm_bts *bts, uint8_t *attr, int attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	DEBUGP(DNM, "Set BTS Attr (bts=%d)\n", bts->nr);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_SET_BTS_ATTR, NM_OC_BTS, bts->bts_nr, 0xff, 0xff);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.6.2 */
int abis_nm_set_radio_attr(struct gsm_bts_trx *trx, uint8_t *attr, int attr_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	DEBUGP(DNM, "Set TRX Attr (bts=%d,trx=%d)\n", trx->bts->nr, trx->nr);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_SET_RADIO_ATTR, NM_OC_RADIO_CARRIER,
			trx->bts->bts_nr, trx->nr, 0xff);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_update_max_power_red(struct gsm_bts_trx *trx)
{
	uint8_t attr[] = { NM_ATT_RF_MAXPOWR_R, trx->max_power_red / 2 };
	return abis_nm_set_radio_attr(trx, attr, ARRAY_SIZE(attr));
}

static int verify_chan_comb(struct gsm_bts_trx_ts *ts, uint8_t chan_comb,
			const char **reason)
{
	int i;

	*reason = "Reason unknown";

	/* As it turns out, the BS-11 has some very peculiar restrictions
	 * on the channel combinations it allows */
	switch (ts->trx->bts->type) {
	case GSM_BTS_TYPE_BS11:
		switch (chan_comb) {
		case NM_CHANC_TCHHalf:
		case NM_CHANC_TCHHalf2:
		case NM_CHANC_OSMO_TCHFull_TCHHalf_PDCH:
			/* not supported */
			*reason = "TCH/H is not supported.";
			return -EINVAL;
		case NM_CHANC_SDCCH:
			/* only one SDCCH/8 per TRX */
			for (i = 0; i < TRX_NR_TS; i++) {
				if (i == ts->nr)
					continue;
				if (ts->trx->ts[i].nm_chan_comb ==
				    NM_CHANC_SDCCH) {
					*reason = "Only one SDCCH/8 per TRX allowed.";
					return -EINVAL;
				}
			}
			/* not allowed for TS0 of BCCH-TRX */
			if (ts->trx == ts->trx->bts->c0 &&
			    ts->nr == 0) {
				*reason = "SDCCH/8 must be on TS0.";
				return -EINVAL;
			}

			/* not on the same TRX that has a BCCH+SDCCH4
			 * combination */
			if (ts->trx != ts->trx->bts->c0 &&
			    (ts->trx->ts[0].nm_chan_comb == 5 ||
			     ts->trx->ts[0].nm_chan_comb == 8)) {
				*reason = "SDCCH/8 and BCCH must be on the same TRX.";
				return -EINVAL;
			}
			break;
		case NM_CHANC_mainBCCH:
		case NM_CHANC_BCCHComb:
			/* allowed only for TS0 of C0 */
			if (ts->trx != ts->trx->bts->c0 || ts->nr != 0) {
				*reason = "Main BCCH must be on TS0.";
				return -EINVAL;
			}
			break;
		case NM_CHANC_BCCH:
			/* allowed only for TS 2/4/6 of C0 */
			if (ts->trx != ts->trx->bts->c0) {
				*reason = "BCCH must be on C0.";
				return -EINVAL;
			}
			if (ts->nr != 2 && ts->nr != 4 && ts->nr != 6) {
				*reason = "BCCH must be on TS 2/4/6.";
				return -EINVAL;
			}
			break;
		case 8: /* this is not like 08.58, but in fact
			 * FCCH+SCH+BCCH+CCCH+SDCCH/4+SACCH/C4+CBCH */
			/* FIXME: only one CBCH allowed per cell */
			break;
		}
		break;
	case GSM_BTS_TYPE_NANOBTS:
		switch (ts->nr) {
		case 0:
			if (ts->trx->nr == 0) {
				/* only on TRX0 */
				switch (chan_comb) {
				case NM_CHANC_BCCH:
				case NM_CHANC_mainBCCH:
				case NM_CHANC_BCCHComb:
					return 0;
					break;
				default:
					*reason = "TS0 of TRX0 must carry a BCCH.";
					return -EINVAL;
				}
			} else {
				switch (chan_comb) {
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
					return 0;
				default:
					*reason = "TS0 must carry a TCH/F or TCH/H.";
					return -EINVAL;
				}
			}
			break;
		case 1:
			if (ts->trx->nr == 0) {
				switch (chan_comb) {
				case NM_CHANC_SDCCH_CBCH:
					if (ts->trx->ts[0].nm_chan_comb ==
					    NM_CHANC_mainBCCH)
						return 0;
					*reason = "TS0 must be the main BCCH for CBCH.";
					return -EINVAL;
				case NM_CHANC_SDCCH:
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_PDCH:
				case NM_CHANC_OSMO_TCHFull_TCHHalf_PDCH:
					return 0;
				default:
					*reason = "TS1 must carry a CBCH, SDCCH or TCH.";
					return -EINVAL;
				}
			} else {
				switch (chan_comb) {
				case NM_CHANC_SDCCH:
				case NM_CHANC_TCHFull:
				case NM_CHANC_TCHHalf:
				case NM_CHANC_IPAC_TCHFull_TCHHalf:
					return 0;
				default:
					*reason = "TS1 must carry a SDCCH or TCH.";
					return -EINVAL;
				}
			}
			break;
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
			switch (chan_comb) {
			case NM_CHANC_TCHFull:
			case NM_CHANC_TCHHalf:
			case NM_CHANC_IPAC_TCHFull_TCHHalf:
				return 0;
			case NM_CHANC_IPAC_PDCH:
			case NM_CHANC_IPAC_TCHFull_PDCH:
			case NM_CHANC_OSMO_TCHFull_TCHHalf_PDCH:
				if (ts->trx->nr == 0)
					return 0;
				else {
					*reason = "PDCH must be on TRX0.";
					return -EINVAL;
				}
			}
			break;
		}
		*reason = "Unknown combination";
		return -EINVAL;
	case GSM_BTS_TYPE_OSMOBTS:
		/* no known restrictions */
		return 0;
	default:
		/* unknown BTS type */
		return 0;
	}
	return 0;
}

/* Chapter 8.6.3 */
int abis_nm_set_channel_attr(struct gsm_bts_trx_ts *ts, uint8_t chan_comb)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	uint8_t zero = 0x00;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t len = 2 + 2;
	const char *reason = NULL;

	if (bts->type == GSM_BTS_TYPE_BS11)
		len += 4 + 2 + 2 + 3;

	DEBUGP(DNM, "Set Chan Attr %s\n", gsm_ts_name(ts));
	if (verify_chan_comb(ts, chan_comb, &reason) < 0) {
		msgb_free(msg);
		LOGP(DNM, LOGL_ERROR,
			"Invalid Channel Combination %d on %s. Reason: %s\n",
			chan_comb, gsm_ts_name(ts), reason);
		return -EINVAL;
	}
	ts->nm_chan_comb = chan_comb;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_SET_CHAN_ATTR,
			NM_OC_CHANNEL, bts->bts_nr,
			ts->trx->nr, ts->nr);
	msgb_tv_put(msg, NM_ATT_CHAN_COMB, chan_comb);
	if (ts->hopping.enabled) {
		unsigned int i;
		uint8_t *len;

		msgb_tv_put(msg, NM_ATT_HSN, ts->hopping.hsn);
		msgb_tv_put(msg, NM_ATT_MAIO, ts->hopping.maio);

		/* build the ARFCN list */
		msgb_put_u8(msg, NM_ATT_ARFCN_LIST);
		len = msgb_put(msg, 1);
		*len = 0;
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (bitvec_get_bit_pos(&ts->hopping.arfcns, i)) {
				msgb_put_u16(msg, i);
				/* At least BS-11 wants a TLV16 here */
				if (bts->type == GSM_BTS_TYPE_BS11)
					*len += 1;
				else
					*len += sizeof(uint16_t);
			}
		}
	}
	msgb_tv_put(msg, NM_ATT_TSC, gsm_ts_tsc(ts));	/* training sequence */
	if (bts->type == GSM_BTS_TYPE_BS11)
		msgb_tlv_put(msg, 0x59, 1, &zero);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_sw_act_req_ack(struct gsm_bts *bts, uint8_t obj_class, uint8_t i1,
			uint8_t i2, uint8_t i3, int nack, uint8_t *attr, int att_len)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t msgtype = NM_MT_SW_ACT_REQ_ACK;
	uint8_t len = att_len;

	if (nack) {
		len += 2;
		msgtype = NM_MT_SW_ACT_REQ_NACK;
	}

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, att_len, msgtype, obj_class, i1, i2, i3);

	if (attr) {
		uint8_t *ptr = msgb_put(msg, att_len);
		memcpy(ptr, attr, att_len);
	}
	if (nack)
		msgb_tv_put(msg, NM_ATT_NACK_CAUSES, NM_NACK_OBJCLASS_NOTSUPP);

	return abis_nm_sendmsg_direct(bts, msg);
}

int abis_nm_raw_msg(struct gsm_bts *bts, int len, uint8_t *rawmsg)
{
	struct msgb *msg = nm_msgb_alloc();
	struct abis_om_hdr *oh;
	uint8_t *data;

	oh = (struct abis_om_hdr *) msgb_put(msg, sizeof(*oh));
	fill_om_hdr(oh, len);
	data = msgb_put(msg, len);
	memcpy(data, rawmsg, len);

	return abis_nm_sendmsg(bts, msg);
}

/* Siemens specific commands */
static int __simple_cmd(struct gsm_bts *bts, uint8_t msg_type)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, msg_type, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.9.2 */
int abis_nm_opstart(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0, uint8_t i1, uint8_t i2)
{
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	foh = fill_om_fom_hdr(oh, 0, NM_MT_OPSTART, obj_class, i0, i1, i2);

	abis_nm_debugp_foh(DNM, foh);
	DEBUGPC(DNM, "Sending OPSTART\n");

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.8.5 */
int abis_nm_chg_adm_state(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0,
			  uint8_t i1, uint8_t i2, enum abis_nm_adm_state adm_state)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2, NM_MT_CHG_ADM_STATE, obj_class, i0, i1, i2);
	msgb_tv_put(msg, NM_ATT_ADM_STATE, adm_state);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_conn_mdrop_link(struct gsm_bts *bts, uint8_t e1_port0, uint8_t ts0,
			    uint8_t e1_port1, uint8_t ts1)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *attr;

	DEBUGP(DNM, "CONNECT MDROP LINK E1=(%u,%u) -> E1=(%u, %u)\n",
		e1_port0, ts0, e1_port1, ts1);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 6, NM_MT_CONN_MDROP_LINK,
			NM_OC_SITE_MANAGER, 0x00, 0x00, 0x00);

	attr = msgb_put(msg, 3);
	attr[0] = NM_ATT_MDROP_LINK;
	attr[1] = e1_port0;
	attr[2] = ts0;

	attr = msgb_put(msg, 3);
	attr[0] = NM_ATT_MDROP_NEXT;
	attr[1] = e1_port1;
	attr[2] = ts1;

	return abis_nm_sendmsg(bts, msg);
}

/* Chapter 8.7.1 */
int abis_nm_perform_test(struct gsm_bts *bts, uint8_t obj_class,
			 uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t test_nr, uint8_t auton_report, struct msgb *msg)
{
	struct abis_om_hdr *oh;

	DEBUGP(DNM, "PEFORM TEST %s\n", abis_nm_test_name(test_nr));

	if (!msg)
		msg = nm_msgb_alloc();

	msgb_tv_push(msg, NM_ATT_AUTON_REPORT, auton_report);
	msgb_tv_push(msg, NM_ATT_TEST_NO, test_nr);
	oh = (struct abis_om_hdr *) msgb_push(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, msgb_l3len(msg), NM_MT_PERF_TEST,
			obj_class, bts_nr, trx_nr, ts_nr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_event_reports(struct gsm_bts *bts, int on)
{
	if (on == 0)
		return __simple_cmd(bts, NM_MT_STOP_EVENT_REP);
	else
		return __simple_cmd(bts, NM_MT_REST_EVENT_REP);
}

/* Siemens (or BS-11) specific commands */

int abis_nm_bs11_bsc_disconnect(struct gsm_bts *bts, int reconnect)
{
	if (reconnect == 0)
		return __simple_cmd(bts, NM_MT_BS11_DISCONNECT);
	else
		return __simple_cmd(bts, NM_MT_BS11_RECONNECT);
}

int abis_nm_bs11_restart(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_RESTART);
}


struct bs11_date_time {
	uint16_t	year;
	uint8_t	month;
	uint8_t	day;
	uint8_t	hour;
	uint8_t	min;
	uint8_t	sec;
} __attribute__((packed));


void get_bs11_date_time(struct bs11_date_time *aet)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);
	aet->sec = tm->tm_sec;
	aet->min = tm->tm_min;
	aet->hour = tm->tm_hour;
	aet->day = tm->tm_mday;
	aet->month = tm->tm_mon;
	aet->year = htons(1900 + tm->tm_year);
}

int abis_nm_bs11_reset_resource(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_RESET_RESOURCE);
}

int abis_nm_bs11_db_transmission(struct gsm_bts *bts, int begin)
{
	if (begin)
		return __simple_cmd(bts, NM_MT_BS11_BEGIN_DB_TX);
	else
		return __simple_cmd(bts, NM_MT_BS11_END_DB_TX);
}

int abis_nm_bs11_create_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, uint8_t idx,
				uint8_t attr_len, const uint8_t *attr)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t *cur;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11, type, 0, idx);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_delete_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_DELETE_OBJ,
			NM_OC_BS11, type, 0, idx);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_envaBTSE(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t zero = 0x00;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11_ENVABTSE, 0, idx, 0xff);
	msgb_tlv_put(msg, 0x99, 1, &zero);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_bport(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_CREATE_OBJ, NM_OC_BS11_BPORT,
			idx, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_delete_bport(struct gsm_bts *bts, uint8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_DELETE_OBJ, NM_OC_BS11_BPORT,
			idx, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

static const uint8_t sm_attr[] = { NM_ATT_TEI, NM_ATT_ABIS_CHANNEL };
int abis_nm_bs11_get_oml_tei_ts(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(sm_attr), NM_MT_GET_ATTR, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(sm_attr), sm_attr);

	return abis_nm_sendmsg(bts, msg);
}

/* like abis_nm_conn_terr_traf + set_tei */
int abis_nm_bs11_conn_oml_tei(struct gsm_bts *bts, uint8_t e1_port,
			  uint8_t e1_timeslot, uint8_t e1_subslot,
			  uint8_t tei)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch)+2, NM_MT_BS11_SET_ATTR,
			NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);
	msgb_tv_put(msg, NM_ATT_TEI, tei);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx_power(struct gsm_bts_trx *trx, uint8_t level)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_PA, 0x00, trx->nr);
	msgb_tlv_put(msg, NM_ATT_BS11_TXPWR, 1, &level);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_bs11_get_trx_power(struct gsm_bts_trx *trx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr = NM_ATT_BS11_TXPWR;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_PA, 0x00, trx->nr);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), &attr);

	return abis_nm_sendmsg(trx->bts, msg);
}

int abis_nm_bs11_get_pll_mode(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr[] = { NM_ATT_BS11_PLL_MODE };

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_LI, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_cclk(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr[] = { NM_ATT_BS11_CCLK_ACCURACY,
			    NM_ATT_BS11_CCLK_TYPE };

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11, BS11_OBJ_CCLK, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), attr);

	return abis_nm_sendmsg(bts, msg);

}

//static const uint8_t bs11_logon_c7[] = { 0x07, 0xd9, 0x01, 0x11, 0x0d, 0x10, 0x20 };

int abis_nm_bs11_factory_logon(struct gsm_bts *bts, int on)
{
	return abis_nm_bs11_logon(bts, 0x02, "FACTORY", on);
}

int abis_nm_bs11_infield_logon(struct gsm_bts *bts, int on)
{
	return abis_nm_bs11_logon(bts, 0x03, "FIELD  ", on);
}

int abis_nm_bs11_logon(struct gsm_bts *bts, uint8_t level, const char *name, int on)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time bdt;

	get_bs11_date_time(&bdt);

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	if (on) {
		uint8_t len = 3*2 + sizeof(bdt)
				+ 1 + strlen(name);
		fill_om_fom_hdr(oh, len, NM_MT_BS11_LMT_LOGON,
				NM_OC_BS11_BTSE, 0xff, 0xff, 0xff);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_LOGIN_TIME,
			     sizeof(bdt), (uint8_t *) &bdt);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_USER_ACC_LEV,
			     1, &level);
		msgb_tlv_put(msg, NM_ATT_BS11_LMT_USER_NAME,
			     strlen(name), (uint8_t *)name);
	} else {
		fill_om_fom_hdr(oh, 0, NM_MT_BS11_LMT_LOGOFF,
				NM_OC_BS11_BTSE, 0xff, 0xff, 0xff);
	}
	
	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx1_pw(struct gsm_bts *bts, const char *password)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;

	if (strlen(password) != 10)
		return -EINVAL;

 	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+strlen(password), NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_TRX1, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_BS11_PASSWORD, 10, (const uint8_t *)password);

	return abis_nm_sendmsg(bts, msg);
}

/* change the BS-11 PLL Mode to either locked (E1 derived) or standalone */
int abis_nm_bs11_set_pll_locked(struct gsm_bts *bts, int locked)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;
	uint8_t tlv_value;
	
	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR, NM_OC_BS11,
			BS11_OBJ_LI, 0x00, 0x00);

	if (locked)
		tlv_value = BS11_LI_PLL_LOCKED;
	else
		tlv_value = BS11_LI_PLL_STANDALONE;
	
	msgb_tlv_put(msg, NM_ATT_BS11_PLL_MODE, 1, &tlv_value);
	
	return abis_nm_sendmsg(bts, msg);
}

/* Set the calibration value of the PLL (work value/set value)
 * It depends on the login which one is changed */
int abis_nm_bs11_set_pll(struct gsm_bts *bts, int value)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;
	uint8_t tlv_value[2];

	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR, NM_OC_BS11,
			BS11_OBJ_TRX1, 0x00, 0x00);

	tlv_value[0] = value>>8;
	tlv_value[1] = value&0xff;

	msgb_tlv_put(msg, NM_ATT_BS11_PLL, 2, tlv_value);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_state(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_GET_STATE);
}

/* BS11 SWL */

void *tall_fle_ctx;

struct abis_nm_bs11_sw {
	struct gsm_bts *bts;
	char swl_fname[PATH_MAX];
	uint8_t win_size;
	int forced;
	struct llist_head file_list;
	gsm_cbfn *user_cb;	/* specified by the user */
};
static struct abis_nm_bs11_sw _g_bs11_sw, *g_bs11_sw = &_g_bs11_sw;

struct file_list_entry {
	struct llist_head list;
	char fname[PATH_MAX];
};

struct file_list_entry *fl_dequeue(struct llist_head *queue)
{
	struct llist_head *lh;

	if (llist_empty(queue))
		return NULL;

	lh = queue->next;
	llist_del(lh);
	
	return llist_entry(lh, struct file_list_entry, list);
}

static int bs11_read_swl_file(struct abis_nm_bs11_sw *bs11_sw)
{
	char linebuf[255];
	struct llist_head *lh, *lh2;
	FILE *swl;
	int rc = 0;

	swl = fopen(bs11_sw->swl_fname, "r");
	if (!swl)
		return -ENODEV;

	/* zero the stale file list, if any */
	llist_for_each_safe(lh, lh2, &bs11_sw->file_list) {
		llist_del(lh);
		talloc_free(lh);
	}

	while (fgets(linebuf, sizeof(linebuf), swl)) {
		char file_id[12+1];
		char file_version[80+1];
		struct file_list_entry *fle;
		static char dir[PATH_MAX];

		if (strlen(linebuf) < 4)
			continue;
	
		rc = sscanf(linebuf+4, "%12s:%80s\r\n", file_id, file_version);
		if (rc < 0) {
			perror("ERR parsing SWL file");
			rc = -EINVAL;
			goto out;
		}
		if (rc < 2)
			continue;

		fle = talloc_zero(tall_fle_ctx, struct file_list_entry);
		if (!fle) {
			rc = -ENOMEM;
			goto out;
		}

		/* construct new filename */
		osmo_strlcpy(dir, bs11_sw->swl_fname, sizeof(dir));
		strncat(fle->fname, dirname(dir), sizeof(fle->fname) - 1);
		strcat(fle->fname, "/");
		strncat(fle->fname, file_id, sizeof(fle->fname) - 1 -strlen(fle->fname));
		
		llist_add_tail(&fle->list, &bs11_sw->file_list);
	}

out:
	fclose(swl);
	return rc;
}

/* bs11 swload specific callback, passed to abis_nm core swload */
static int bs11_swload_cbfn(unsigned int hook, unsigned int event,
			    struct msgb *msg, void *data, void *param)
{
	struct abis_nm_bs11_sw *bs11_sw = data;
	struct file_list_entry *fle;
	int rc = 0;

	switch (event) {
	case NM_MT_LOAD_END_ACK:
		fle = fl_dequeue(&bs11_sw->file_list);
		if (fle) {
			/* start download the next file of our file list */
			rc = abis_nm_software_load(bs11_sw->bts, 0xff, fle->fname,
						   bs11_sw->win_size,
						   bs11_sw->forced,
						   &bs11_swload_cbfn, bs11_sw);
			talloc_free(fle);
		} else {
			/* activate the SWL */
			rc = abis_nm_software_activate(bs11_sw->bts,
							bs11_sw->swl_fname,
							bs11_swload_cbfn,
							bs11_sw);
		}
		break;
	case NM_MT_LOAD_SEG_ACK:
	case NM_MT_LOAD_END_NACK:
	case NM_MT_LOAD_INIT_ACK:
	case NM_MT_LOAD_INIT_NACK:
	case NM_MT_ACTIVATE_SW_NACK:
	case NM_MT_ACTIVATE_SW_ACK:
	default:
		/* fallthrough to the user callback */
		if (bs11_sw->user_cb)
			rc = bs11_sw->user_cb(hook, event, msg, NULL, NULL);
		break;
	}

	return rc;
}

/* Siemens provides a SWL file that is a mere listing of all the other
 * files that are part of a software release.  We need to upload first
 * the list file, and then each file that is listed in the list file */
int abis_nm_bs11_load_swl(struct gsm_bts *bts, const char *fname,
			  uint8_t win_size, int forced, gsm_cbfn *cbfn)
{
	struct abis_nm_bs11_sw *bs11_sw = g_bs11_sw;
	struct file_list_entry *fle;
	int rc = 0;

	INIT_LLIST_HEAD(&bs11_sw->file_list);
	bs11_sw->bts = bts;
	bs11_sw->win_size = win_size;
	bs11_sw->user_cb = cbfn;
	bs11_sw->forced = forced;

	osmo_strlcpy(bs11_sw->swl_fname, fname, sizeof(bs11_sw->swl_fname));
	rc = bs11_read_swl_file(bs11_sw);
	if (rc < 0)
		return rc;

	/* dequeue next item in file list */
	fle = fl_dequeue(&bs11_sw->file_list);
	if (!fle)
		return -EINVAL;

	/* start download the next file of our file list */
	rc = abis_nm_software_load(bts, 0xff, fle->fname, win_size, forced,
				   bs11_swload_cbfn, bs11_sw);
	talloc_free(fle);
	return rc;
}

#if 0
static uint8_t req_attr_btse[] = {
	NM_ATT_ADM_STATE, NM_ATT_BS11_LMT_LOGON_SESSION,
	NM_ATT_BS11_LMT_LOGIN_TIME, NM_ATT_BS11_LMT_USER_ACC_LEV,
	NM_ATT_BS11_LMT_USER_NAME,

	0xaf, NM_ATT_BS11_RX_OFFSET, NM_ATT_BS11_VENDOR_NAME,

	NM_ATT_BS11_SW_LOAD_INTENDED, NM_ATT_BS11_SW_LOAD_SAFETY,

	NM_ATT_BS11_SW_LOAD_STORED };

static uint8_t req_attr_btsm[] = {
	NM_ATT_ABIS_CHANNEL, NM_ATT_TEI, NM_ATT_BS11_ABIS_EXT_TIME,
	NM_ATT_ADM_STATE, NM_ATT_AVAIL_STATUS, 0xce, NM_ATT_FILE_ID,
	NM_ATT_FILE_VERSION, NM_ATT_OPER_STATE, 0xe8, NM_ATT_BS11_ALL_TEST_CATG,
	NM_ATT_SW_DESCR, NM_ATT_GET_ARI };
#endif
	
static uint8_t req_attr[] = {
	NM_ATT_ADM_STATE, NM_ATT_AVAIL_STATUS, 0xa8, NM_ATT_OPER_STATE,
	0xd5, 0xa1, NM_ATT_BS11_ESN_FW_CODE_NO, NM_ATT_BS11_ESN_HW_CODE_NO,
	0x42, NM_ATT_BS11_ESN_PCB_SERIAL, NM_ATT_BS11_PLL };

int abis_nm_bs11_get_serno(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	/* SiemensHW CCTRL object */
	fill_om_fom_hdr(oh, 2+sizeof(req_attr), NM_MT_GET_ATTR, NM_OC_BS11,
			0x03, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(req_attr), req_attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_ext_time(struct gsm_bts *bts)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time aet;

	get_bs11_date_time(&aet);
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	/* SiemensHW CCTRL object */
	fill_om_fom_hdr(oh, 2+sizeof(aet), NM_MT_BS11_SET_ATTR, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);
	msgb_tlv_put(msg, NM_ATT_BS11_ABIS_EXT_TIME, sizeof(aet), (uint8_t *) &aet);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_bport_line_cfg(struct gsm_bts *bts, uint8_t bport)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	uint8_t attr = NM_ATT_BS11_LINE_CFG;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+sizeof(attr), NM_MT_GET_ATTR,
			NM_OC_BS11_BPORT, bport, 0xff, 0x02);
	msgb_tlv_put(msg, NM_ATT_LIST_REQ_ATTR, sizeof(attr), &attr);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_bport_line_cfg(struct gsm_bts *bts, uint8_t bport, enum abis_bs11_line_cfg line_cfg)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	struct bs11_date_time aet;

	get_bs11_date_time(&aet);
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2, NM_MT_BS11_SET_ATTR, NM_OC_BS11_BPORT,
			bport, 0xff, 0x02);
	msgb_tv_put(msg, NM_ATT_BS11_LINE_CFG, line_cfg);

	return abis_nm_sendmsg(bts, msg);
}

/* ip.access nanoBTS specific commands */
static const char ipaccess_magic[] = "com.ipaccess";


static int abis_nm_rx_ipacc(struct msgb *msg)
{
	struct in_addr addr;
	struct abis_om_hdr *oh = msgb_l2(msg);
	struct abis_om_fom_hdr *foh;
	uint8_t idstrlen = oh->data[0];
	struct tlv_parsed tp;
	struct ipacc_ack_signal_data signal;
	struct e1inp_sign_link *sign_link = msg->dst;

	if (strncmp((char *)&oh->data[1], ipaccess_magic, idstrlen)) {
		LOGP(DNM, LOGL_ERROR, "id string is not com.ipaccess !?!\n");
		return -EINVAL;
	}

	foh = (struct abis_om_fom_hdr *) (oh->data + 1 + idstrlen);
	abis_nm_tlv_parse(&tp, sign_link->trx->bts, foh->data, oh->length-sizeof(*foh));

	abis_nm_debugp_foh(DNM, foh);

	DEBUGPC(DNM, "IPACCESS(0x%02x): ", foh->msg_type);

	switch (foh->msg_type) {
	case NM_MT_IPACC_RSL_CONNECT_ACK:
		DEBUGPC(DNM, "RSL CONNECT ACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_DST_IP)) {
			memcpy(&addr,
				TLVP_VAL(&tp, NM_ATT_IPACC_DST_IP), sizeof(addr));

			DEBUGPC(DNM, "IP=%s ", inet_ntoa(addr));
		}
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_DST_IP_PORT))
			DEBUGPC(DNM, "PORT=%u ",
				ntohs(*((uint16_t *)
					TLVP_VAL(&tp, NM_ATT_IPACC_DST_IP_PORT))));
		if (TLVP_PRESENT(&tp, NM_ATT_IPACC_STREAM_ID))
			DEBUGPC(DNM, "STREAM=0x%02x ",
					*TLVP_VAL(&tp, NM_ATT_IPACC_STREAM_ID));
		DEBUGPC(DNM, "\n");
		break;
	case NM_MT_IPACC_RSL_CONNECT_NACK:
		LOGP(DNM, LOGL_ERROR, "RSL CONNECT NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	case NM_MT_IPACC_SET_NVATTR_ACK:
		DEBUGPC(DNM, "SET NVATTR ACK\n");
		/* FIXME: decode and show the actual attributes */
		break;
	case NM_MT_IPACC_SET_NVATTR_NACK:
		LOGP(DNM, LOGL_ERROR, "SET NVATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	case NM_MT_IPACC_GET_NVATTR_ACK:
		DEBUGPC(DNM, "GET NVATTR ACK\n");
		/* FIXME: decode and show the actual attributes */
		break;
	case NM_MT_IPACC_GET_NVATTR_NACK:
		LOGPC(DNM, LOGL_ERROR, "GET NVATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	case NM_MT_IPACC_SET_ATTR_ACK:
		DEBUGPC(DNM, "SET ATTR ACK\n");
		break;
	case NM_MT_IPACC_SET_ATTR_NACK:
		LOGPC(DNM, LOGL_ERROR, "SET ATTR NACK ");
		if (TLVP_PRESENT(&tp, NM_ATT_NACK_CAUSES))
			LOGPC(DNM, LOGL_ERROR, " CAUSE=%s\n",
				abis_nm_nack_cause_name(*TLVP_VAL(&tp, NM_ATT_NACK_CAUSES)));
		else
			LOGPC(DNM, LOGL_ERROR, "\n");
		break;
	default:
		DEBUGPC(DNM, "unknown\n");
		break;
	}

	/* signal handling */
	switch  (foh->msg_type) {
	case NM_MT_IPACC_RSL_CONNECT_NACK:
	case NM_MT_IPACC_SET_NVATTR_NACK:
	case NM_MT_IPACC_GET_NVATTR_NACK:
		signal.trx = gsm_bts_trx_by_nr(sign_link->trx->bts, foh->obj_inst.trx_nr);
		signal.msg_type = foh->msg_type;
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_NACK, &signal);
		break;
	case NM_MT_IPACC_SET_NVATTR_ACK:
		signal.trx = gsm_bts_trx_by_nr(sign_link->trx->bts, foh->obj_inst.trx_nr);
		signal.msg_type = foh->msg_type;
		osmo_signal_dispatch(SS_NM, S_NM_IPACC_ACK, &signal);
		break;
	default:
		break;
	}

	return 0;
}

/* send an ip-access manufacturer specific message */
int abis_nm_ipaccess_msg(struct gsm_bts *bts, uint8_t msg_type,
			 uint8_t obj_class, uint8_t bts_nr,
			 uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t *attr, int attr_len)
{
	struct msgb *msg = nm_msgb_alloc();
	struct abis_om_hdr *oh;
	struct abis_om_fom_hdr *foh;
	uint8_t *data;

	/* construct the 12.21 OM header, observe the erroneous length */
	oh = (struct abis_om_hdr *) msgb_put(msg, sizeof(*oh));
	fill_om_hdr(oh, sizeof(*foh) + attr_len);
	oh->mdisc = ABIS_OM_MDISC_MANUF;

	/* add the ip.access magic */
	data = msgb_put(msg, sizeof(ipaccess_magic)+1);
	*data++ = sizeof(ipaccess_magic);
	memcpy(data, ipaccess_magic, sizeof(ipaccess_magic));

	/* fill the 12.21 FOM header */
	foh = (struct abis_om_fom_hdr *) msgb_put(msg, sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;

	if (attr && attr_len) {
		data = msgb_put(msg, attr_len);
		memcpy(data, attr, attr_len);
	}

	return abis_nm_sendmsg(bts, msg);
}

/* set some attributes in NVRAM */
int abis_nm_ipaccess_set_nvattr(struct gsm_bts_trx *trx, uint8_t *attr,
				int attr_len)
{
	return abis_nm_ipaccess_msg(trx->bts, NM_MT_IPACC_SET_NVATTR,
				    NM_OC_BASEB_TRANSC, 0, trx->nr, 0xff, attr,
				    attr_len);
}

int abis_nm_ipaccess_rsl_connect(struct gsm_bts_trx *trx,
				 uint32_t ip, uint16_t port, uint8_t stream)
{
	struct in_addr ia;
	uint8_t attr[] = { NM_ATT_IPACC_STREAM_ID, 0,
			    NM_ATT_IPACC_DST_IP_PORT, 0, 0,
			    NM_ATT_IPACC_DST_IP, 0, 0, 0, 0 };

	int attr_len = sizeof(attr);

	ia.s_addr = htonl(ip);
	attr[1] = stream;
	attr[3] = port >> 8;
	attr[4] = port & 0xff;
	*(uint32_t *)(attr+6) = ia.s_addr;

	/* if ip == 0, we use the default IP */
	if (ip == 0)
		attr_len -= 5;

	DEBUGP(DNM, "ip.access RSL CONNECT IP=%s PORT=%u STREAM=0x%02x\n",
		inet_ntoa(ia), port, stream);

	return abis_nm_ipaccess_msg(trx->bts, NM_MT_IPACC_RSL_CONNECT,
				    NM_OC_BASEB_TRANSC, trx->bts->bts_nr,
				    trx->nr, 0xff, attr, attr_len);
}

/* restart / reboot an ip.access nanoBTS */
int abis_nm_ipaccess_restart(struct gsm_bts_trx *trx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_IPACC_RESTART, NM_OC_BASEB_TRANSC,
			trx->bts->nr, trx->nr, 0xff);

	return abis_nm_sendmsg_direct(trx->bts, msg);
}

int abis_nm_ipaccess_set_attr(struct gsm_bts *bts, uint8_t obj_class,
				uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
				uint8_t *attr, uint8_t attr_len)
{
	return abis_nm_ipaccess_msg(bts, NM_MT_IPACC_SET_ATTR,
				    obj_class, bts_nr, trx_nr, ts_nr,
				     attr, attr_len);
}

void abis_nm_ipaccess_cgi(uint8_t *buf, struct gsm_bts *bts)
{
	/* we simply reuse the GSM48 function and overwrite the RAC
	 * with the Cell ID */
	gsm48_ra_id_by_bts(buf, bts);
	*((uint16_t *)(buf + 5)) = htons(bts->cell_identity);
}

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, int locked)
{
	int new_state = locked ? NM_STATE_LOCKED : NM_STATE_UNLOCKED;

	trx->mo.nm_state.administrative = new_state;
	if (!trx->bts || !trx->bts->oml_link)
		return;

	abis_nm_chg_adm_state(trx->bts, NM_OC_RADIO_CARRIER,
			      trx->bts->bts_nr, trx->nr, 0xff,
			      new_state);
}

static const struct value_string ipacc_testres_names[] = {
	{ NM_IPACC_TESTRES_SUCCESS,	"SUCCESS" },
	{ NM_IPACC_TESTRES_TIMEOUT,	"TIMEOUT" },
	{ NM_IPACC_TESTRES_NO_CHANS,	"NO CHANNELS" },
	{ NM_IPACC_TESTRES_PARTIAL,	"PARTIAL" },
	{ NM_IPACC_TESTRES_STOPPED,	"STOPPED" },
	{ 0,				NULL }
};

const char *ipacc_testres_name(uint8_t res)
{
	return get_value_string(ipacc_testres_names, res);
}

void ipac_parse_cgi(struct cell_global_id *cid, const uint8_t *buf)
{
	cid->mcc = (buf[0] & 0xf) * 100;
	cid->mcc += (buf[0] >> 4) *  10;
	cid->mcc += (buf[1] & 0xf) *  1;

	if (buf[1] >> 4 == 0xf) {
		cid->mnc = (buf[2] & 0xf) * 10;
		cid->mnc += (buf[2] >> 4) *  1;
	} else {
		cid->mnc = (buf[2] & 0xf) * 100;
		cid->mnc += (buf[2] >> 4) *  10;
		cid->mnc += (buf[1] >> 4) *   1;
	}

	cid->lac = ntohs(*((uint16_t *)&buf[3]));
	cid->ci = ntohs(*((uint16_t *)&buf[5]));
}

/* parse BCCH information IEI from wire format to struct ipac_bcch_info */
int ipac_parse_bcch_info(struct ipac_bcch_info *binf, uint8_t *buf)
{
	uint8_t *cur = buf;
	uint16_t len __attribute__((unused));

	memset(binf, 0, sizeof(*binf));

	if (cur[0] != NM_IPAC_EIE_BCCH_INFO)
		return -EINVAL;
	cur++;

	len = ntohs(*(uint16_t *)cur);
	cur += 2;

	binf->info_type = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FREQ_ERR_QUAL)
		binf->freq_qual = *cur >> 2;

	binf->arfcn = (*cur++ & 3) << 8;
	binf->arfcn |= *cur++;

	if (binf->info_type & IPAC_BINF_RXLEV)
		binf->rx_lev = *cur & 0x3f;
	cur++;

	if (binf->info_type & IPAC_BINF_RXQUAL)
		binf->rx_qual = *cur & 0x7;
	cur++;

	if (binf->info_type & IPAC_BINF_FREQ_ERR_QUAL)
		binf->freq_err = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FRAME_OFFSET)
		binf->frame_offset = ntohs(*(uint16_t *)cur);
	cur += 2;

	if (binf->info_type & IPAC_BINF_FRAME_NR_OFFSET)
		binf->frame_nr_offset = ntohl(*(uint32_t *)cur);
	cur += 4;

#if 0
	/* Somehow this is not set correctly */
	if (binf->info_type & IPAC_BINF_BSIC)
#endif
		binf->bsic = *cur & 0x3f;
	cur++;

	ipac_parse_cgi(&binf->cgi, cur);
	cur += 7;

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2) {
		memcpy(binf->ba_list_si2, cur, sizeof(binf->ba_list_si2));
		cur += sizeof(binf->ba_list_si2);
	}

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2bis) {
		memcpy(binf->ba_list_si2bis, cur,
			sizeof(binf->ba_list_si2bis));
		cur += sizeof(binf->ba_list_si2bis);
	}

	if (binf->info_type & IPAC_BINF_NEIGH_BA_SI2ter) {
		memcpy(binf->ba_list_si2ter, cur,
			sizeof(binf->ba_list_si2ter));
		cur += sizeof(binf->ba_list_si2ter);
	}

	return 0;
}

void abis_nm_clear_queue(struct gsm_bts *bts)
{
	struct msgb *msg;

	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		msgb_free(msg);
	}

	bts->abis_nm_pend = 0;
}
