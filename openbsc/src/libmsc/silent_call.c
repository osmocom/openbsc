/* GSM silent call feature */

/*
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/osmo_msc.h>

/* paging of the requested subscriber has completed */
static int paging_cb_silent(unsigned int hooknum, unsigned int event,
			    struct msgb *msg, void *_conn, void *_data)
{
	struct gsm_subscriber_connection *conn = _conn;
	struct scall_signal_data sigdata;
	int rc = 0;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	DEBUGP(DLSMS, "paging_cb_silent: ");

	sigdata.conn = conn;
	sigdata.data = _data;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		DEBUGPC(DLSMS, "success, using Timeslot %u on ARFCN %u\n",
			conn->lchan->ts->nr, conn->lchan->ts->trx->arfcn);
		conn->silent_call = 1;
		msc_subscr_conn_get(conn);
		/* increment lchan reference count */
		osmo_signal_dispatch(SS_SCALL, S_SCALL_SUCCESS, &sigdata);
		break;
	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_BUSY:
	case GSM_PAGING_OOM:
		DEBUGP(DLSMS, "expired\n");
		osmo_signal_dispatch(SS_SCALL, S_SCALL_EXPIRED, &sigdata);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

#if 0
/* receive a layer 3 message from a silent call */
int silent_call_rx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	/* FIXME: do something like sending it through a UDP port */
	LOGP(DLSMS, LOGL_NOTICE, "Discarding L3 message from a silent call.\n");
	return 0;
}
#endif

struct msg_match {
	uint8_t pdisc;
	uint8_t msg_type;
};

/* list of messages that are handled inside OpenBSC, even in a silent call */
static const struct msg_match silent_call_accept[] = {
	{ GSM48_PDISC_MM, GSM48_MT_MM_LOC_UPD_REQUEST },
	{ GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_REQ },
};

#if 0
/* decide if we need to reroute a message as part of a silent call */
int silent_call_reroute(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	int i;

	/* if we're not part of a silent call, never reroute */
	if (!conn->silent_call)
		return 0;

	/* check if we are a special message that is handled in openbsc */
	for (i = 0; i < ARRAY_SIZE(silent_call_accept); i++) {
		if (silent_call_accept[i].pdisc == pdisc &&
		    silent_call_accept[i].msg_type == msg_type)
			return 0;
	}

	/* otherwise, reroute */
	LOGP(DLSMS, LOGL_INFO, "Rerouting L3 message from a silent call.\n");
	return 1;
}
#endif


/* initiate a silent call with a given subscriber */
int gsm_silent_call_start(struct vlr_subscr *vsub, void *data, int type)
{
	struct subscr_request *req;

	req = subscr_request_channel(vsub, type, paging_cb_silent, data);
	return req != NULL;
}

/* end a silent call with a given subscriber */
int gsm_silent_call_stop(struct vlr_subscr *vsub)
{
	struct gsm_subscriber_connection *conn;

	conn = connection_for_subscr(vsub);
	if (!conn)
		return -EINVAL;

	/* did we actually establish a silent call for this guy? */
	if (!conn->silent_call)
		return -EINVAL;

	DEBUGPC(DLSMS, "Stopping silent call using Timeslot %u on ARFCN %u\n",
		conn->lchan->ts->nr, conn->lchan->ts->trx->arfcn);

	conn->silent_call = 0;
	msc_subscr_conn_put(conn);

	return 0;
}
