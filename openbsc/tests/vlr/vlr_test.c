#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>

#include <openbsc/vlr.h>
#include <openbsc/debug.h>

#define S(x)	(1 << (x))

/*
 * TODO:
 * * test FSM for all testvlr_mode (and more)
 * * test also the time-outs in the vlr code
 * * test for memory leaks
 * * how to get the HLR running? Or test against stub?
 * * test disappearing MS connection
 * * test absence of HLR
 */

void *tall_bsc_ctx;
static struct vlr_instance *g_vlr;

/***********************************************************************
 * Finite State Machine simulating MS and MSC towards VLR
 ***********************************************************************/

static void timer_error_cb(struct osmo_fsm_inst *fi)
{
	struct vlr_subscriber *vsub = fi->priv;
	LOGPFSM(fi, "timer expired waiting for completion\n");
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	vlr_sub_cleanup(vsub);
}

enum testvlr_mode {
	MODE_SUCCESS,
	MODE_SUCCESS_TMSI,
	MODE_AUTH_FAIL,
	MODE_AUTH_RESYNC,
};

struct testvlr_priv {
	enum testvlr_mode mode;
	uint32_t tmsi;
	char imsi[16];
	char imei[16];
	struct osmo_location_area_id old_lai;
	struct osmo_location_area_id new_lai;

	struct vlr_subscriber *subscr;
};

#define fsi_priv(x)	(struct testvlr_priv *)(x)->priv

enum f_state {
	/*! initial state */
	ST_NULL,
	/*! LU was sent by MS */
	ST_LU_SENT,
	/*! waiting for auth re-sync */
	ST_RESYNC_SENT,
	/* Waiting for LU ACK */
	ST_WAIT_LU_ACK,
	ST_DONE,
	ST_FAILED,
};

enum f_event {
	/* events from MS */
	EVT_MS_TX_LU,		/* transmit LU REQ to network */
	EVT_MS_TX_ID_RESP,	/* tranmit ID RSP to network */
	EVT_MS_TX_AUTH_RESP,	/* transmit AUTH RESP to network */
	EVT_MS_TX_AUTH_FAIL,	/* transmit AUTH FAIL to network */
	EVT_MS_CONN_LOST,	/* connection to MS was lost */

	/* events from VLR */
	EVT_VLR_AUTH_REQ,	/* transmit AUTH REQ to MS */
	EVT_VLR_ID_REQ_IMSI,	/* transmit ID REQ(IMSI) to MS */
	EVT_VLR_ID_REQ_IMEI,	/* tramsmit ID REQ(IMEI) to MS */
	EVT_VLR_ID_REQ_IMEISV,	/* trasnmit ID REQ(IMEISV) to MS */
	EVT_VLR_AUTH_REJ,	/* transmit AUTH REJ to MS */
	EVT_VLR_SET_CIPH,	/* transmit SET CIPH to MS */
	EVT_VLR_LU_ACK,		/* transmit LU ACK to MS */
	EVT_VLR_LU_REJ,		/* transmit LU REJ to MS */
};

static struct value_string f_event_names[] = {
	{ EVT_MS_TX_LU,		"MS-TX-LU" },
	{ EVT_MS_TX_ID_RESP,	"MS-TX-ID-RESP" },
	{ EVT_MS_TX_AUTH_RESP,	"MS-TX-AUTH-RESP" },
	{ EVT_MS_TX_AUTH_FAIL,	"MS-TX-AUTH-FAIL" },
	{ EVT_MS_CONN_LOST,	"MS-CONN-LOST" },

	{ EVT_VLR_AUTH_REQ,	"VLR-AUTH-REQ" },
	{ EVT_VLR_ID_REQ_IMSI,	"VLR-ID-REQ-IMSI" },
	{ EVT_VLR_ID_REQ_IMEI,	"VLR-ID-REQ-IMEI" },
	{ EVT_VLR_ID_REQ_IMEISV,"VLR-ID-REQ-IMEISV" },
	{ EVT_VLR_AUTH_REJ,	"VLR-AUTH-REJ" },
	{ EVT_VLR_SET_CIPH,	"VLR-SET-CIPH" },
	{ EVT_VLR_LU_ACK,	"VLR-LU-ACK" },
	{ EVT_VLR_LU_REJ,	"VLR-LU-REJ" },
	{ 0, NULL }
};

static void fsm_f_allstate(struct osmo_fsm_inst *fi, uint32_t event,
			   void *data)
{
	struct testvlr_priv *priv = fsi_priv(fi);
	uint8_t mi[16];
	unsigned int mi_len;

	switch (event) {
	case EVT_VLR_ID_REQ_IMSI:
		if (priv->mode != MODE_SUCCESS_TMSI) {
			LOGP(DGPRS, LOGL_NOTICE, "Unexpected ID REQ "
			     "(IMSI)\n");
		}
		mi_len = gsm48_generate_mid_from_imsi(mi, priv->imsi);
		vlr_sub_rx_id_resp(priv->subscr, mi+2, mi_len-2);
		break;
	case EVT_VLR_ID_REQ_IMEI:
		mi_len = gsm48_generate_mid_from_imsi(mi, priv->imei);
		mi[0] = (mi[0] & 0xf8) | GSM_MI_TYPE_IMEI;
		vlr_sub_rx_id_resp(priv->subscr+2, mi, mi_len-2);
		break;
	case EVT_VLR_ID_REQ_IMEISV:
		mi_len = gsm48_generate_mid_from_imsi(mi, priv->imei);
		mi[0] = (mi[0] & 0xf8) | GSM_MI_TYPE_IMEISV;
		vlr_sub_rx_id_resp(priv->subscr, mi+2, mi_len-2);
		break;
	case EVT_MS_CONN_LOST:
		vlr_sub_disconnected(priv->subscr);
		/* IDEA: not release but keep around in extra state to
		 * see if VLR still sends us anything? */
		osmo_fsm_inst_free(fi);
		break;
	}
}

static void fsm_f_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct testvlr_priv *priv = fsi_priv(fi);
	uint32_t tmsi = 0;
	const char *imsi = NULL;

	switch (event) {
	case EVT_MS_TX_LU:
		/* send LU to VLR */
		if (priv->mode == MODE_SUCCESS)
			imsi = priv->imsi;
		else
			tmsi = priv->tmsi;
		priv->subscr = vlr_loc_update(g_vlr, fi,
					      VLR_LU_TYPE_IMSI_ATTACH,
					      tmsi, imsi,
					      &priv->old_lai,
					      &priv->new_lai);
		OSMO_ASSERT(priv->subscr);
		osmo_fsm_inst_state_chg(fi, ST_LU_SENT, 0, 0);
		break;
	default:
		break;
	}
}

static void fsm_f_lu_sent(struct osmo_fsm_inst *fi, uint32_t event,
			  void *data)
{
	struct gsm_auth_tuple *at = NULL;
	struct testvlr_priv *priv = fsi_priv(fi);
	uint8_t res_fail[4];
	uint8_t auts[16];

	switch (event) {
	case EVT_VLR_AUTH_REQ:
		at = data;
		OSMO_ASSERT(at);
		DEBUGP(DGPRS, "%s: at->res=%s\n", __func__, osmo_hexdump(at->vec.res, at->vec.res_len));
		switch (priv->mode) {
		case MODE_SUCCESS:
		case MODE_SUCCESS_TMSI:
			/* return matching SRES/AUTS */
			vlr_sub_rx_auth_resp(priv->subscr, true, false,
					     at->vec.res, at->vec.res_len);
			break;
		case MODE_AUTH_FAIL:
			/* return not matching SRES/AUTS */
			vlr_sub_rx_auth_resp(priv->subscr, true, false,
					     res_fail, sizeof(res_fail));
			/* FIXME: state transition? */
			break;
		case MODE_AUTH_RESYNC:
			/* return SRES/AUTS requesting re-sync */
			/* FIXME: generate a proper authenticating
			 * re-sync request */
			vlr_sub_rx_auth_fail(priv->subscr, auts);
			/* FIXME: state transition? */
			osmo_fsm_inst_state_chg(fi, ST_RESYNC_SENT, 0, 0);
			break;
		}
		osmo_fsm_inst_state_chg(fi, ST_WAIT_LU_ACK, 0, 0);
		break;
	case EVT_VLR_LU_REJ:
		{
		uint8_t cause = *(uint8_t *)data;
		LOGP(DGPRS, LOGL_NOTICE, "LU(%s): Rejected; cause=0x%02x\n",
			priv->imsi, cause);

		}
		break;
	default:
		break;
	}
}

static void fsm_f_resync_sent(struct osmo_fsm_inst *fi, uint32_t event,
			      void *data)
{
	struct testvlr_priv *priv = fsi_priv(fi);
	struct gsm_auth_tuple *at = NULL;

	/* second auth request is supposed to succed after the
	 * re-sync procedure before */
	switch (event) {
	case EVT_VLR_AUTH_REQ:
		at = data;
		/* return matching SRES/AUTS now */
		vlr_sub_rx_auth_resp(priv->subscr, true, false,
				     at->vec.res, at->vec.res_len);
		osmo_fsm_inst_state_chg(fi, ST_WAIT_LU_ACK, 0, 0);
		break;
	}
}

static void fsm_f_wait_lu_ack(struct osmo_fsm_inst *fi, uint32_t event,
			      void *data)
{
	struct testvlr_priv *priv = fsi_priv(fi);

	switch (event) {
	case EVT_VLR_LU_ACK:
		if (priv->subscr->tmsi != GSM_RESERVED_TMSI) {
			/* we need to send an TMSI REALLOC COMPL */
			vlr_sub_rx_tmsi_reall_compl(priv->subscr);
		}
		osmo_fsm_inst_state_chg(fi, ST_DONE, 0, 0);
		break;
	case EVT_VLR_LU_REJ:
		osmo_fsm_inst_state_chg(fi, ST_FAILED, 0, 0);
		break;
	}
}

static void fsm_f_imsi_sent(struct osmo_fsm_inst *fi, uint32_t event,
			    void *data)
{
	switch (event) {
	case EVT_MS_TX_ID_RESP:
		break;
	}
}

static void fsm_f_areq_sent(struct osmo_fsm_inst *fi, uint32_t event,
			    void *data)
{
	switch (event) {
	case EVT_MS_TX_AUTH_RESP:
		break;
	case EVT_MS_TX_AUTH_FAIL:
		break;
	}
}

static struct osmo_fsm_state fsm_success_states[] = {
	[ST_NULL] = {
		.in_event_mask = S(EVT_MS_TX_LU),
		.out_state_mask = S(ST_LU_SENT),
		.name = "NULL",
		.action = fsm_f_null,
	},
	[ST_LU_SENT] = {
		.in_event_mask = S(EVT_VLR_AUTH_REQ) |
				 S(EVT_VLR_LU_REJ),
		//.out_state_mask = S(ST_IDREQ_IMSI_SENT) | S(ST_AUTH_REQ_SENT),
		.out_state_mask = S(ST_WAIT_LU_ACK),
		.name = "LU Sent",
		.action = fsm_f_lu_sent,
	},
	[ST_RESYNC_SENT] = {
		.in_event_mask = S(EVT_VLR_AUTH_REQ),
		.out_state_mask = S(ST_WAIT_LU_ACK),
		.name = "AUTH-RESYNC sent",
		.action = fsm_f_imsi_sent,
	},
	[ST_WAIT_LU_ACK] = {
		.in_event_mask = S(EVT_VLR_LU_ACK) |
				 S(EVT_VLR_SET_CIPH) |
				 S(EVT_VLR_LU_REJ),
		.out_state_mask = S(ST_DONE),
		.name = "WAIT-LU-ACK",
		.action = fsm_f_wait_lu_ack,
	},
	[ST_DONE] = {
		.name = "DONE"
	},
};

static struct osmo_fsm vlr_test_fsm = {
	.name = "VLR Test FSM",
	.states = fsm_success_states,
	.num_states = ARRAY_SIZE(fsm_success_states),
	.log_subsys = DGPRS,
	.event_names = f_event_names,
	.allstate_event_mask = S(EVT_MS_CONN_LOST) |
			       S(EVT_VLR_ID_REQ_IMSI) |
			       S(EVT_VLR_ID_REQ_IMEI) |
			       S(EVT_VLR_ID_REQ_IMEISV),
	.allstate_action = fsm_f_allstate,
};

/* Testing of Subscriber_Present_VLR */

enum test_sub_pres_state {
	TSPV_S_INIT,
	TSPV_S_RUNNING,
};

enum test_sub_pres_evt {
	TSPV_E_START,
	TSPV_E_COMPL,
};

static void tspv_f_running(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vlr_subscriber *vsub = fi->priv;

	switch (event) {
	case TSPV_E_COMPL:
		OSMO_ASSERT(vsub);
		OSMO_ASSERT(vsub->ms_not_reachable_flag == false);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	}
}

static void tspv_f_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_fsm_inst *spv;
	struct vlr_subscriber *vsub = fi->priv;

	switch (event) {
	case TSPV_E_START:
		OSMO_ASSERT(vsub);
		vsub->ms_not_reachable_flag = true;
		spv = sub_pres_vlr_fsm_start(fi, vsub, TSPV_E_COMPL);
		OSMO_ASSERT(spv);
		osmo_fsm_inst_state_chg(fi, TSPV_S_RUNNING, 4, 0);
		break;
	}
}

static const struct osmo_fsm_state test_sub_pres_vlr_states[] = {
	[TSPV_S_INIT] = {
		.in_event_mask = S(TSPV_E_START),
		.out_state_mask = S(TSPV_S_RUNNING),
		.name = "INIT",
		.action = tspv_f_init,
	},
	[TSPV_S_RUNNING] = {
		.in_event_mask = S(TSPV_E_COMPL),
		.out_state_mask = 0,
		.name = "RUNNING",
		.action = tspv_f_running,
	},
};

static struct osmo_fsm test_sub_pres_vlr_fsm = {
	.name = "Test Subscriber_Present_VLR",
	.states = test_sub_pres_vlr_states,
	.num_states = ARRAY_SIZE(test_sub_pres_vlr_states),
	.log_subsys = DGPRS,
	.event_names = f_event_names,
	.timer_cb = timer_error_cb,
};

static void start_sub_pres_vlr(void *ctx, uint32_t tmsi, const char *imsi)
{
	struct osmo_fsm_inst *fi;
	struct vlr_subscriber *vsub = vlr_sub_alloc(g_vlr);

	vsub->tmsi = tmsi;
	strncpy(vsub->imsi, imsi, sizeof(vsub->imsi));
	fi = osmo_fsm_inst_alloc(&test_sub_pres_vlr_fsm, ctx, vsub, LOGL_DEBUG, vsub->imsi);
	osmo_fsm_inst_dispatch(fi, TSPV_E_START, NULL);
}

/* Testing of Update_HLR_VLR */

enum test_update_hlr_vlr_state {
	TUHV_S_INIT,
	TUHV_S_RUNNING,
};

enum test_update_hlr_vlr_event {
	TUHV_E_START,
	TUHV_E_COMPL,
};

static void tuhv_f_running(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vlr_subscriber *vsub = fi->priv;
	enum gsm48_gmm_cause *res = data;

	switch (event) {
	case TUHV_E_COMPL:
		if (!res) {
			/* Success */
			LOGPFSM(fi, "success\n");
		} else {
			/* error */
			LOGPFSM(fi, "errror cause=0x%u\n", *res);
		}
		vlr_sub_cleanup(vsub);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	}
}

static void tuhv_f_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_fsm_inst *child;
	struct vlr_subscriber *vsub = fi->priv;

	switch (event) {
	case TUHV_E_START:
		child = upd_hlr_vlr_proc_start(fi, vsub, TUHV_E_COMPL);
		OSMO_ASSERT(child);
		osmo_fsm_inst_state_chg(fi, TUHV_S_RUNNING, 4, 0);
		break;
	}
}

static const struct osmo_fsm_state test_upd_hlr_vlr_states[] = {
	[TUHV_S_INIT] = {
		.in_event_mask = S(TUHV_E_START),
		.out_state_mask = S(TUHV_S_RUNNING),
		.name = "INIT",
		.action = tuhv_f_init,
	},
	[TUHV_S_RUNNING] = {
		.in_event_mask = S(TUHV_E_COMPL),
		.out_state_mask = 0,
		.name = "RUNNING",
		.action = tuhv_f_running,
	},
};

static struct osmo_fsm test_upd_hlr_vlr_fsm = {
	.name = "Test Update_HLR_VLR",
	.states = test_upd_hlr_vlr_states,
	.num_states = ARRAY_SIZE(test_upd_hlr_vlr_states),
	.log_subsys = DGPRS,
	.event_names = f_event_names,
	.timer_cb = timer_error_cb,
};

static void start_upd_hlr_vlr(void *ctx, uint32_t tmsi, const char *imsi)
{
	struct osmo_fsm_inst *fi;
	struct vlr_subscriber *vsub = vlr_sub_alloc(g_vlr);

	vsub->tmsi = tmsi;
	strncpy(vsub->imsi, imsi, sizeof(vsub->imsi));


	fi = osmo_fsm_inst_alloc(&test_upd_hlr_vlr_fsm, ctx, vsub, LOGL_DEBUG,
				vsub->imsi);
	/* we need to set this to fool vlr.c in an ongoing LU */
	vsub->lu_fsm = fi;
	osmo_fsm_inst_dispatch(fi, TUHV_E_START, NULL);
}

/***********************************************************************
 * Integration with VLR code
 ***********************************************************************/

static struct vlr_instance *g_vlr;

/* VLR asks us to send an authentication request */
static int msc_vlr_tx_auth_req(void *msc_conn_ref, struct gsm_auth_tuple *at)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	OSMO_ASSERT(at);
	DEBUGP(DGPRS, "%s: RES=%s\n", __func__,
		osmo_hexdump_nospc(at->vec.res, at->vec.res_len));
	osmo_fsm_inst_dispatch(fi, EVT_VLR_AUTH_REQ, at);
	return 0;
}

/* VLR asks us to send an authentication reject */
static int msc_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	DEBUGP(DGPRS, "%s\n", __func__);
	osmo_fsm_inst_dispatch(fi, EVT_VLR_AUTH_REJ, NULL);
	return 0;
}

/* VLR asks us to transmit an Identity Request of given type */
static int msc_vlr_tx_id_req(void *msc_conn_ref, uint8_t mi_type)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	uint32_t event;

	DEBUGP(DGPRS, "%s (%u)\n", __func__, mi_type);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		event = EVT_VLR_ID_REQ_IMSI;
		break;
	case GSM_MI_TYPE_IMEI:
		event = EVT_VLR_ID_REQ_IMEI;
		break;
	case GSM_MI_TYPE_IMEISV:
		event = EVT_VLR_ID_REQ_IMEISV;
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "Unknown identity 0x%02x\n",
			mi_type);
		return -1;
	}
	osmo_fsm_inst_dispatch(fi, event, NULL);
	return 0;
}

/* VLR asks us to transmit a Location Update Accept */
static int msc_vlr_tx_lu_ack(void *msc_conn_ref)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	DEBUGP(DGPRS, "%s\n", __func__);
	osmo_fsm_inst_dispatch(fi, EVT_VLR_LU_ACK, NULL);
	return 0;
}

/* VLR asks us to transmit a Location Update Reject */
static int msc_vlr_tx_lu_rej(void *msc_conn_ref, uint8_t cause)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	DEBUGP(DGPRS, "%s\n", __func__);
	osmo_fsm_inst_dispatch(fi, EVT_VLR_LU_REJ, (void *) &cause);
	return 0;
}

static int msc_vlr_set_ciph_mode(void *msc_conn_ref)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	DEBUGP(DGPRS, "%s\n", __func__);
	osmo_fsm_inst_dispatch(fi, EVT_VLR_SET_CIPH, NULL);
	return 0;
}

/* VLR informs us that the subscriber data has somehow been modified */
static void msc_vlr_subscr_update(struct vlr_subscriber *subscr)
{
	DEBUGP(DGPRS, "%s\n", __func__);
	/* FIXME */
}

static void msc_vlr_subscr_assoc(void *msc_conn_ref, struct vlr_subscriber *vsub)
{
	struct osmo_fsm_inst *fi = msc_conn_ref;
	struct testvlr_priv *priv = fsi_priv(fi);
	DEBUGP(DGPRS, "%s(%p, %s)\n", __func__, msc_conn_ref, vlr_sub_name(vsub));
	priv->subscr = vsub;
}

/* operations that we need to implement for libvlr */
static const struct vlr_ops test_vlr_ops = {
	.tx_auth_req = msc_vlr_tx_auth_req,
	.tx_auth_rej = msc_vlr_tx_auth_rej,
	.tx_id_req = msc_vlr_tx_id_req,
	.tx_lu_ack = msc_vlr_tx_lu_ack,
	.tx_lu_rej = msc_vlr_tx_lu_rej,
	.set_ciph_mode = msc_vlr_set_ciph_mode,
	.subscr_update = msc_vlr_subscr_update,
	.subscr_assoc = msc_vlr_subscr_assoc,
};

/***********************************************************************
 * Actual test cases
 ***********************************************************************/


static struct osmo_fsm_inst *
start_lu(enum testvlr_mode mode, uint32_t tmsi,
	 const char *imsi, const char *imei)
{
	struct testvlr_priv *vp;
	struct osmo_fsm_inst *fi;

	vp = talloc_zero(tall_bsc_ctx, struct testvlr_priv);
	vp->mode = mode;
	vp->tmsi = tmsi;
	strncpy(vp->imsi, imsi, sizeof(vp->imsi));
	strncpy(vp->imei, imei, sizeof(vp->imei));

	fi = osmo_fsm_inst_alloc(&vlr_test_fsm, vp, vp, LOGL_DEBUG, vp->imsi);
	osmo_fsm_inst_dispatch(fi, EVT_MS_TX_LU, NULL);
	return fi;
}

/***********************************************************************
 * Main / Misc
 ***********************************************************************/

/* dummy for debug.c */
struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr)
{
	return subscr;
}
/* dummy for debug.c */
struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr)
{
	return subscr;
}

static struct osmo_timer_list tmr;

static void timer_cb(void *data)
{
	uint32_t tmsi = rand() % 1000000;
	uint64_t imsi = 901790000000000 + tmsi;
	char imsi_str[32];

	snprintf(imsi_str, sizeof(imsi_str), "%lu", imsi);
	//start_lu(MODE_AUTH_FAIL, tmsi, imsi_str, "23422342");
	start_lu(MODE_SUCCESS_TMSI, tmsi, imsi_str, "23422342");
	//start_lu(MODE_SUCCESS, tmsi, imsi_str, "23422342");
	//start_upd_hlr_vlr(tall_bsc_ctx, tmsi, imsi_str);
	//start_sub_pres_vlr(tall_bsc_ctx);
	osmo_timer_schedule(&tmr, 8, 0);
}

static void sighdlr(int sig)
{
	switch (sig) {
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	}
}

int main(int argc, char **argv)
{
	tall_bsc_ctx = talloc_named_const(NULL, 1, "tall_bsc_ctx");

	signal(SIGUSR1, sighdlr);

	osmo_init_logging(&log_info);

	g_vlr = vlr_init(NULL, &test_vlr_ops, "localhost", 2222);
	OSMO_ASSERT(g_vlr);
	osmo_fsm_register(&vlr_test_fsm);
	osmo_fsm_register(&test_sub_pres_vlr_fsm);
	osmo_fsm_register(&test_upd_hlr_vlr_fsm);

	g_vlr->cfg.alloc_tmsi = true;

	tmr.cb = timer_cb;
	timer_cb(NULL);

	while (1) {
		osmo_select_main(0);
	}

	exit(0);
}
