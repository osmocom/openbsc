/* mncc_builtin.c - default, minimal built-in MNCC Application for
 *		    standalone bsc_hack (network-in-the-box mode) */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/mncc.h>
#include <openbsc/mncc_int.h>
#include <osmocom/core/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>

void *tall_call_ctx;

static LLIST_HEAD(call_list);

static uint32_t new_callref = 0x00000001;

struct mncc_int mncc_int = {
	.def_codec = { GSM48_CMODE_SPEECH_V1, GSM48_CMODE_SPEECH_V1 },
};

static void free_call(struct gsm_call *call)
{
	llist_del(&call->entry);
	DEBUGP(DMNCC, "(call %x) Call removed.\n", call->callref);
	talloc_free(call);
}


static struct gsm_call *get_call_ref(uint32_t callref)
{
	struct gsm_call *callt;

	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref)
			return callt;
	}
	return NULL;
}

uint8_t mncc_codec_for_mode(int lchan_type)
{
	/* FIXME: check codec capabilities of the phone */

	if (lchan_type != GSM_LCHAN_TCH_H)
		return mncc_int.def_codec[0];
	else
		return mncc_int.def_codec[1];
}

static uint8_t determine_lchan_mode(struct gsm_mncc *setup)
{
	return mncc_codec_for_mode(setup->lchan_type);
}

/* on incoming call, look up database and send setup to remote subscr. */
static int mncc_setup_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *setup)
{
	struct gsm_mncc mncc;
	struct gsm_call *remote;

	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;

	/* already have remote call */
	if (call->remote_ref)
		return 0;
	
	/* transfer mode 1 would be packet mode, which was never specified */
	if (setup->bearer_cap.mode != 0) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We don't support "
			"packet mode\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	/* we currently only do speech */
	if (setup->bearer_cap.transfer != GSM_MNCC_BCAP_SPEECH) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We only support "
			"voice calls\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	/* create remote call */
	if (!(remote = talloc_zero(tall_call_ctx, struct gsm_call))) {
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		goto out_reject;
	}
	llist_add_tail(&remote->entry, &call_list);
	remote->net = call->net;
	remote->callref = new_callref++;
	DEBUGP(DMNCC, "(call %x) Creating new remote instance %x.\n",
		call->callref, remote->callref);

	/* link remote call */
	call->remote_ref = remote->callref;
	remote->remote_ref = call->callref;

	/* send call proceeding */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Accepting call.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_CALL_PROC_REQ, &mncc);

	/* modify mode */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	mncc.lchan_mode = determine_lchan_mode(setup);
	DEBUGP(DMNCC, "(call %x) Modify channel mode: %s\n", call->callref,
	       get_value_string(gsm48_chan_mode_names, mncc.lchan_mode));
	mncc_tx_to_cc(call->net, MNCC_LCHAN_MODIFY, &mncc);

	/* send setup to remote */
//	setup->fields |= MNCC_F_SIGNAL;
//	setup->signal = GSM48_SIGNAL_DIALTONE;
	setup->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding SETUP to remote.\n", call->callref);
	return mncc_tx_to_cc(remote->net, MNCC_SETUP_REQ, setup);

out_reject:
	mncc_tx_to_cc(call->net, MNCC_REJ_REQ, &mncc);
	free_call(call);
	return 0;
}

static int mncc_alert_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *alert)
{
	struct gsm_call *remote;

	/* send alerting to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	alert->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding ALERT to remote.\n", call->callref);
	return mncc_tx_to_cc(remote->net, MNCC_ALERT_REQ, alert);
}

static int mncc_notify_ind(struct gsm_call *call, int msg_type,
			   struct gsm_mncc *notify)
{
	struct gsm_call *remote;

	/* send notify to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	notify->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding NOTIF to remote.\n", call->callref);
	return mncc_tx_to_cc(remote->net, MNCC_NOTIFY_REQ, notify);
}

static int mncc_setup_cnf(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *connect)
{
	struct gsm_mncc connect_ack, frame_recv;
	struct gsm_network *net = call->net;
	struct gsm_call *remote;
	struct gsm_mncc_bridge bridge = { .msg_type = MNCC_BRIDGE };

	/* acknowledge connect */
	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Acknowledge SETUP.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_SETUP_COMPL_REQ, &connect_ack);

	/* send connect message to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	connect->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Sending CONNECT to remote.\n", call->callref);
	mncc_tx_to_cc(remote->net, MNCC_SETUP_RSP, connect);

	/* bridge tch */
	bridge.callref[0] = call->callref;
	bridge.callref[1] = call->remote_ref;
	DEBUGP(DMNCC, "(call %x) Bridging with remote.\n", call->callref);

	/* in direct mode, we always have to bridge the channels */
	if (ipacc_rtp_direct)
		return mncc_tx_to_cc(call->net, MNCC_BRIDGE, &bridge);

	/* proxy mode */
	if (!net->handover.active) {
		/* in the no-handover case, we can bridge, i.e. use
		 * the old RTP proxy code */
		return mncc_tx_to_cc(call->net, MNCC_BRIDGE, &bridge);
	} else {
		/* in case of handover, we need to re-write the RTP
		 * SSRC, sequence and timestamp values and thus
		 * need to enable RTP receive for both directions */
		memset(&frame_recv, 0, sizeof(struct gsm_mncc));
		frame_recv.callref = call->callref;
		mncc_tx_to_cc(call->net, MNCC_FRAME_RECV, &frame_recv);
		frame_recv.callref = call->remote_ref;
		return mncc_tx_to_cc(call->net, MNCC_FRAME_RECV, &frame_recv);
	}
}

static int mncc_disc_ind(struct gsm_call *call, int msg_type,
			 struct gsm_mncc *disc)
{
	struct gsm_call *remote;

	/* send release */
	DEBUGP(DMNCC, "(call %x) Releasing call with cause %d\n",
		call->callref, disc->cause.value);
	mncc_tx_to_cc(call->net, MNCC_REL_REQ, disc);

	/* send disc to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		return 0;
	}
	disc->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Disconnecting remote with cause %d\n",
		remote->callref, disc->cause.value);
	return mncc_tx_to_cc(remote->net, MNCC_DISC_REQ, disc);
}

static int mncc_rel_ind(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	struct gsm_call *remote;

	/* send release to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		free_call(call);
		return 0;
	}

	rel->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Releasing remote with cause %d\n",
		call->callref, rel->cause.value);

	/*
	 * Release this side of the call right now. Otherwise we end up
	 * in this method for the other call and will also try to release
	 * it and then we will end up with a double free and a crash
	 */
	free_call(call);
	mncc_tx_to_cc(remote->net, MNCC_REL_REQ, rel);

	return 0;
}

static int mncc_rel_cnf(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	free_call(call);
	return 0;
}

/* receiving a (speech) traffic frame from the BSC code */
static int mncc_rcv_data(struct gsm_call *call, int msg_type,
			 struct gsm_data_frame *dfr)
{
	struct gsm_trans *remote_trans;

	remote_trans = trans_find_by_callref(call->net, call->remote_ref);

	/* this shouldn't really happen */
	if (!remote_trans || !remote_trans->conn) {
		LOGP(DMNCC, LOGL_ERROR, "No transaction or transaction without lchan?!?\n");
		return -EIO;
	}

	/* RTP socket of remote end has meanwhile died */
	if (!remote_trans->conn->lchan->abis_ip.rtp_socket)
		return -EIO;

	return rtp_send_frame(remote_trans->conn->lchan->abis_ip.rtp_socket, dfr);
}


/* Internal MNCC handler input function (from CC -> MNCC -> here) */
int int_mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	void *arg = msgb_data(msg);
	struct gsm_mncc *data = arg;
	int msg_type = data->msg_type;
	int callref;
	struct gsm_call *call = NULL, *callt;
	int rc = 0;

	/* Special messages */
	switch(msg_type) {
	}
	
	/* find callref */
	callref = data->callref;
	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref) {
			call = callt;
			break;
		}
	}

	/* create callref, if setup is received */
	if (!call) {
		if (msg_type != MNCC_SETUP_IND)
			goto out_free; /* drop */
		/* create call */
		if (!(call = talloc_zero(tall_call_ctx, struct gsm_call))) {
			struct gsm_mncc rel;
			
			memset(&rel, 0, sizeof(struct gsm_mncc));
			rel.callref = callref;
			mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				       GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			mncc_tx_to_cc(net, MNCC_REL_REQ, &rel);
			goto out_free;
		}
		llist_add_tail(&call->entry, &call_list);
		call->net = net;
		call->callref = callref;
		DEBUGP(DMNCC, "(call %x) Call created.\n", call->callref);
	}

	if (mncc_is_data_frame(msg_type)) {
		rc = mncc_rcv_data(call, msg_type, arg);
		goto out_free;
	}

	DEBUGP(DMNCC, "(call %x) Received message %s\n", call->callref,
		get_mncc_name(msg_type));

	switch(msg_type) {
	case MNCC_SETUP_IND:
		rc = mncc_setup_ind(call, msg_type, arg);
		break;
	case MNCC_SETUP_CNF:
		rc = mncc_setup_cnf(call, msg_type, arg);
		break;
	case MNCC_SETUP_COMPL_IND:
		break;
	case MNCC_CALL_CONF_IND:
		/* we now need to MODIFY the channel */
		data->lchan_mode = determine_lchan_mode(data);
		mncc_tx_to_cc(call->net, MNCC_LCHAN_MODIFY, data);
		break;
	case MNCC_ALERT_IND:
		rc = mncc_alert_ind(call, msg_type, arg);
		break;
	case MNCC_NOTIFY_IND:
		rc = mncc_notify_ind(call, msg_type, arg);
		break;
	case MNCC_DISC_IND:
		rc = mncc_disc_ind(call, msg_type, arg);
		break;
	case MNCC_REL_IND:
	case MNCC_REJ_IND:
		rc = mncc_rel_ind(call, msg_type, arg);
		break;
	case MNCC_REL_CNF:
		rc = mncc_rel_cnf(call, msg_type, arg);
		break;
	case MNCC_FACILITY_IND:
		break;
	case MNCC_START_DTMF_IND:
		rc = mncc_tx_to_cc(net, MNCC_START_DTMF_REJ, data);
		break;
	case MNCC_STOP_DTMF_IND:
		rc = mncc_tx_to_cc(net, MNCC_STOP_DTMF_RSP, data);
		break;
	case MNCC_MODIFY_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting MODIFY with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_MODIFY_REJ, data);
		break;
	case MNCC_MODIFY_CNF:
		break;
	case MNCC_HOLD_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting HOLD with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_HOLD_REJ, data);
		break;
	case MNCC_RETRIEVE_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting RETRIEVE with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_RETRIEVE_REJ, data);
		break;
	default:
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) Message unhandled\n", callref);
		break;
	}

out_free:
	msgb_free(msg);

	return rc;
}
