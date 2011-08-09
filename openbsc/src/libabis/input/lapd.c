/* OpenBSC minimal LAPD implementation */

/* (C) 2009 by oystein@homelien.no
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by Digium and Matthew Fredrickson <creslin@digium.com>
 * (C) 2011 by Harald Welte <laforge@gnumonks.org>
 *
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

/* TODO:
	* detect RR timeout and set SAP state back to SABM_RETRANSMIT
	* use of value_string
	* further code cleanup (spaghetti)
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "lapd.h"

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <openbsc/debug.h>

#define SABM_INTERVAL		0, 300000

typedef enum {
	LAPD_TEI_NONE = 0,
	LAPD_TEI_ASSIGNED,
	LAPD_TEI_ACTIVE,
} lapd_tei_state;

const char *lapd_tei_states[] = {
	"NONE",
	"ASSIGNED",
	"ACTIVE",
};

typedef enum {
	LAPD_TYPE_NONE = 0,

	LAPD_TYPE_I,
	LAPD_TYPE_S,
	LAPD_TYPE_U,
} lapd_msg_type;

typedef enum {
	/* commands/responses */
	LAPD_CMD_NONE = 0,

	LAPD_CMD_I,
	LAPD_CMD_RR,
	LAPD_CMD_RNR,
	LAPD_CMD_REJ,

	LAPD_CMD_SABME,
	LAPD_CMD_DM,
	LAPD_CMD_UI,
	LAPD_CMD_DISC,
	LAPD_CMD_UA,
	LAPD_CMD_FRMR,
	LAPD_CMD_XID,
} lapd_cmd_type;

const char *lapd_cmd_types[] = {
	"NONE",

	"I",
	"RR",
	"RNR",
	"REJ",

	"SABME",
	"DM",
	"UI",
	"DISC",
	"UA",
	"FRMR",
	"XID",

};

enum lapd_sap_state {
	SAP_STATE_INACTIVE,
	SAP_STATE_SABM_RETRANS,
	SAP_STATE_ACTIVE,
};

const char *lapd_sap_states[] = {
	"INACTIVE",
	"SABM_RETRANS",
	"ACTIVE",
};

const char *lapd_msg_types = "?ISU";

/* structure representing an allocated TEI within a LAPD instance */
struct lapd_tei {
	struct llist_head list;
	struct lapd_instance *li;
	uint8_t tei;
	lapd_tei_state state;

	struct llist_head sap_list;
};

/* Structure representing a SAP within a TEI. We use this for TE-mode to
 * re-transmit SABM */
struct lapd_sap {
	struct llist_head list;
	struct lapd_tei *tei;
	uint8_t sapi;
	enum lapd_sap_state state;

	/* A valid N(R) value is one that is in the range V(A) ≤ N(R) ≤ V(S). */
	int vs;			/* next to be transmitted */
	int va;			/* last acked by peer */
	int vr;			/* next expected to be received */

	struct osmo_timer_list sabme_timer;	/* timer to re-transmit SABM message */
};

/* 3.5.2.2   Send state variable V(S)
 * Each point-to-point data link connection endpoint shall have an associated V(S) when using I frame
 * commands. V(S) denotes the sequence number of the next I frame to be transmitted. The V(S) can
 * take on the value 0 through n minus 1. The value of V(S) shall be incremented by 1 with each
 * successive I frame transmission, and shall not exceed V(A) by more than the maximum number of
 * outstanding I frames k. The value of k may be in the range of 1 ≤ k ≤ 127.
 *
 * 3.5.2.3   Acknowledge state variable V(A)
 * Each point-to-point data link connection endpoint shall have an associated V(A) when using I frame
 * commands and supervisory frame commands/responses. V(A) identifies the last I frame that has been
 * acknowledged by its peer [V(A) − 1 equals the N(S) of the last acknowledged I frame]. V(A) can
 * take on the value 0 through n minus 1. The value of V(A) shall be updated by the valid N(R) values
 * received from its peer (see 3.5.2.6). A valid N(R) value is one that is in the range V(A) ≤ N(R) ≤
 * V(S).
 *
 * 3.5.2.5    Receive state variable V(R)
 * Each point-to-point data link connection endpoint shall have an associated V(R) when using I frame
 * commands and supervisory frame commands/responses. V(R) denotes the sequence number of the
 * next in-sequence I frame expected to be received. V(R) can take on the value 0 through n minus 1.
 * The value of V(R) shall be incremented by one with the receipt of an error-free, in-sequence I frame
 * whose N(S) equals V(R).
 */
#define	LAPD_NS(sap) (sap->vs)
#define	LAPD_NR(sap) (sap->vr)

/* 3.5.2.4    Send sequence number N(S)
 * Only I frames contain N(S), the send sequence number of transmitted I frames. At the time that an in-
 * sequence I frame is designated for transmission, the value of N(S) is set equal to V(S).
 *
 * 3.5.2.6    Receive sequence number N(R)
 * All I frames and supervisory frames contain N(R), the expected send sequence number of the next
 * received I frame. At the time that a frame of the above types is designated for transmission, the value
 * of N(R) is set equal to V(R). N(R) indicates that the data link layer entity transmitting the N(R) has
 * correctly received all I frames numbered up to and including N(R) − 1.
 */

/* Resolve TEI structure from given numeric TEI */
static struct lapd_tei *teip_from_tei(struct lapd_instance *li, uint8_t tei)
{
	struct lapd_tei *lt;

	llist_for_each_entry(lt, &li->tei_list, list) {
		if (lt->tei == tei)
			return lt;
	}
	return NULL;
};

static void lapd_tei_set_state(struct lapd_tei *teip, int newstate)
{
	DEBUGP(DMI, "state change on TEI %d: %s -> %s\n", teip->tei,
		   lapd_tei_states[teip->state], lapd_tei_states[newstate]);
	teip->state = newstate;
};

/* Allocate a new TEI */
struct lapd_tei *lapd_tei_alloc(struct lapd_instance *li, uint8_t tei)
{
	struct lapd_tei *teip;

	teip = talloc_zero(li, struct lapd_tei);
	if (!teip)
		return NULL;

	teip->li = li;
	teip->tei = tei;
	llist_add(&teip->list, &li->tei_list);
	INIT_LLIST_HEAD(&teip->sap_list);

	lapd_tei_set_state(teip, LAPD_TEI_ASSIGNED);

	return teip;
}

/* Find a SAP within a given TEI */
static struct lapd_sap *lapd_sap_find(struct lapd_tei *teip, uint8_t sapi)
{
	struct lapd_sap *sap;

	llist_for_each_entry(sap, &teip->sap_list, list) {
		if (sap->sapi == sapi)
			return sap;
	}

	return NULL;
}

static void sabme_timer_cb(void *_sap);

/* Allocate a new SAP within a given TEI */
static struct lapd_sap *lapd_sap_alloc(struct lapd_tei *teip, uint8_t sapi)
{
	struct lapd_sap *sap = talloc_zero(teip, struct lapd_sap);

	LOGP(DMI, LOGL_INFO, "Allocating SAP for SAPI=%u / TEI=%u\n",
		sapi, teip->tei);

	sap->sapi = sapi;
	sap->tei = teip;
	sap->sabme_timer.cb = &sabme_timer_cb;
	sap->sabme_timer.data = sap;

	llist_add(&sap->list, &teip->sap_list);

	return sap;
}

static void lapd_sap_set_state(struct lapd_tei *teip, uint8_t sapi,
				enum lapd_sap_state newstate)
{
	struct lapd_sap *sap = lapd_sap_find(teip, sapi);
	if (!sap)
		return;

	DEBUGP(DMI, "state change on TEI %u / SAPI %u: %s -> %s\n", teip->tei,
		sapi, lapd_sap_states[sap->state], lapd_sap_states[newstate]);
	switch (sap->state) {
	case SAP_STATE_SABM_RETRANS:
		if (newstate != SAP_STATE_SABM_RETRANS)
			osmo_timer_del(&sap->sabme_timer);
		break;
	default:
		if (newstate == SAP_STATE_SABM_RETRANS)
			osmo_timer_schedule(&sap->sabme_timer, SABM_INTERVAL);
		break;
	}

	sap->state = newstate;
};

/* Input function into TEI manager */
static void lapd_tei_receive(struct lapd_instance *li, uint8_t *data, int len)
{
	uint8_t entity = data[0];
	uint8_t ref = data[1];
	uint8_t mt = data[3];
	uint8_t action = data[4] >> 1;
	uint8_t e = data[4] & 1;
	uint8_t resp[8];
	struct lapd_tei *teip;

	DEBUGP(DMI, "TEIMGR: entity %x, ref %x, mt %x, action %x, e %x\n", entity, ref, mt, action, e);

	switch (mt) {
	case 0x01:	/* IDENTITY REQUEST */
		DEBUGP(DMI, "TEIMGR: identity request for TEI %u\n", action);

		teip = teip_from_tei(li, action);
		if (!teip) {
			LOGP(DMI, LOGL_INFO, "TEI MGR: New TEI %u\n", action);
			teip = lapd_tei_alloc(li, action);
		}

		/* Send ACCEPT */
		memmove(resp, "\xfe\xff\x03\x0f\x00\x00\x02\x00", 8);
		resp[7] = (action << 1) | 1;
		li->transmit_cb(resp, 8, li->cbdata);

		if (teip->state == LAPD_TEI_NONE)
			lapd_tei_set_state(teip, LAPD_TEI_ASSIGNED);
		break;
	default:
		LOGP(DMI, LOGL_NOTICE, "TEIMGR: unknown mt %x action %x\n",
		     mt, action);
		break;
	};
};

/* General input function for any data received for this LAPD instance */
uint8_t *lapd_receive(struct lapd_instance *li, uint8_t * data, unsigned int len,
		      int *ilen, lapd_mph_type *prim)
{
	uint8_t sapi, cr, tei, command;
	int pf, ns, nr;
	uint8_t *contents;
	struct lapd_tei *teip;
	struct lapd_sap *sap;

	uint8_t resp[8];
	int l = 0;

	*ilen = 0;
	*prim = 0;

	if (len < 2) {
		DEBUGP(DMI, "len %d < 2\n", len);
		return NULL;
	};

	if ((data[0] & 1) != 0 || (data[1] & 1) != 1) {
		DEBUGP(DMI, "address field %x/%x not well formed\n", data[0],
			   data[1]);
		return NULL;
	};

	sapi = data[0] >> 2;
	cr = (data[0] >> 1) & 1;
	tei = data[1] >> 1;
	command = li->network_side ^ cr;
	//DEBUGP(DMI, "  address sapi %x tei %d cmd %d cr %d\n", sapi, tei, command, cr);

	if (len < 3) {
		DEBUGP(DMI, "len %d < 3\n", len);
		return NULL;
	};

	lapd_msg_type typ = 0;
	lapd_cmd_type cmd = 0;
	pf = -1;
	ns = -1;
	nr = -1;
	if ((data[2] & 1) == 0) {
		typ = LAPD_TYPE_I;
		if (len < 4) {
			LOGP(DMI, LOGL_ERROR, "LAPD I frame, len %d < 4\n", len);
			return NULL;
		}
		ns = data[2] >> 1;
		nr = data[3] >> 1;
		pf = data[3] & 1;
		cmd = LAPD_CMD_I;
	} else if ((data[2] & 3) == 1) {
		typ = LAPD_TYPE_S;
		if (len < 4) {
			LOGP(DMI, LOGL_ERROR, "LAPD S frame, len %d < 4\n", len);
			return NULL;
		}
		nr = data[3] >> 1;
		pf = data[3] & 1;
		switch (data[2]) {
		case 0x1:
			cmd = LAPD_CMD_RR;
			break;
		case 0x5:
			cmd = LAPD_CMD_RNR;
			break;
		case 0x9:
			cmd = LAPD_CMD_REJ;
			break;
		default:
			LOGP(DMI, LOGL_ERROR, "unknown LAPD S cmd %x\n", data[2]);
			return NULL;
		};
	} else if ((data[2] & 3) == 3) {
		typ = LAPD_TYPE_U;
		pf = (data[2] >> 4) & 1;
		int val = data[2] & ~(1 << 4);
		switch (val) {
		case 0x6f:
			cmd = LAPD_CMD_SABME;
			break;
		case 0x0f:
			cmd = LAPD_CMD_DM;
			break;
		case 0x03:
			cmd = LAPD_CMD_UI;
			break;
		case 0x43:
			cmd = LAPD_CMD_DISC;
			break;
		case 0x63:
			cmd = LAPD_CMD_UA;
			break;
		case 0x87:
			cmd = LAPD_CMD_FRMR;
			break;
		case 0xaf:
			cmd = LAPD_CMD_XID;
			break;

		default:
			LOGP(DMI, LOGL_ERROR, "unknown U cmd %x "
			     "(pf %x data %x)\n", val, pf, data[2]);
			return NULL;
		};
	};

	contents = &data[4];
	if (typ == LAPD_TYPE_U)
		contents--;
	*ilen = len - (contents - data);

	if (tei == 127)
		lapd_tei_receive(li, contents, *ilen);

	teip = teip_from_tei(li, tei);
	if (!teip) {
		LOGP(DMI, LOGL_NOTICE, "Unknown TEI %u\n", tei);
		return NULL;
	}

	sap = lapd_sap_find(teip, sapi);
	if (!sap) {
		LOGP(DMI, LOGL_INFO, "No SAP for TEI=%u / SAPI=%u, "
			"allocating\n", tei, sapi);
		sap = lapd_sap_alloc(teip, sapi);
	}

	DEBUGP(DMI, "<- %c %s sapi %x tei %3d cmd %x pf %x ns %3d nr %3d "
	     "ilen %d teip %p vs %d va %d vr %d len %d\n",
	     lapd_msg_types[typ], lapd_cmd_types[cmd], sapi, tei, command, pf,
	     ns, nr, *ilen, teip, sap->vs, sap->va, sap->vr, len);

	switch (cmd) {
	case LAPD_CMD_I:
		if (ns != sap->vr) {
			DEBUGP(DMI, "ns %d != vr %d\n", ns, sap->vr);
			if (ns == ((sap->vr - 1) & 0x7f)) {
				DEBUGP(DMI, "DOUBLE FRAME, ignoring\n");
				cmd = 0;	// ignore
			} else {
				LOGP(DMI, LOGL_ERROR, "LAPD: Out of order "
					"ns %d != vr %d, ignoring\n", ns, sap->vr);
				return NULL;
			};
		} else {
			//printf("IN SEQUENCE\n");
			sap->vr = (ns + 1) & 0x7f;	// FIXME: hack!
		};

		break;
	case LAPD_CMD_UI:
		break;
	case LAPD_CMD_SABME:
		sap->vs = 0;
		sap->vr = 0;
		sap->va = 0;

		// ua
		resp[l++] = data[0];
		resp[l++] = (tei << 1) | 1;
		resp[l++] = 0x73;
		li->transmit_cb(resp, l, li->cbdata);
		if (teip->state != LAPD_TEI_ACTIVE) {
			if (teip->state == LAPD_TEI_ASSIGNED) {
				lapd_tei_set_state(teip,
						   LAPD_TEI_ACTIVE);
				//printf("ASSIGNED and ACTIVE\n");
			} else {
#if 0
				DEBUGP(DMI, "rr in strange state, send rej\n");

				// rej
				resp[l++] = (sap-> sapi << 2) | (li->network_side ? 0 : 2);
				resp[l++] = (tei << 1) | 1;
				resp[l++] = 0x09;	//rej
				resp[l++] = ((sap->vr + 1) << 1) | 0;
				li->transmit_cb(resp, l, li->cbdata);
				pf = 0;	// dont reply
#endif
			};
		};

		*prim = LAPD_MPH_ACTIVATE_IND;
		break;
	case LAPD_CMD_UA:
		sap->vs = 0;
		sap->vr = 0;
		sap->va = 0;
		lapd_tei_set_state(teip, LAPD_TEI_ACTIVE);
		lapd_sap_set_state(teip, sapi, SAP_STATE_ACTIVE);
		*prim = LAPD_MPH_ACTIVATE_IND;
		break;
	case LAPD_CMD_RR:
		sap->va = (nr & 0x7f);
#if 0
		if (teip->state != LAPD_TEI_ACTIVE) {
			if (teip->state == LAPD_TEI_ASSIGNED) {
				lapd_tei_set_state(teip, LAPD_TEI_ACTIVE);
				*prim = LAPD_MPH_ACTIVATE_IND;
				//printf("ASSIGNED and ACTIVE\n");
			} else {
#if 0
				DEBUGP(DMI, "rr in strange " "state, send rej\n");

				// rej
				resp[l++] = (sap-> sapi << 2) | (li->network_side ? 0 : 2);
				resp[l++] = (tei << 1) | 1;
				resp[l++] = 0x09;	//rej
				resp[l++] =
				    ((sap->vr + 1) << 1) | 0;
				li->transmit_cb(resp, l, li->cbdata);
				pf = 0;	// dont reply
#endif
			};
		};
#endif
		if (pf) {
			// interrogating us, send rr
			resp[l++] = data[0];
			resp[l++] = (tei << 1) | 1;
			resp[l++] = 0x01;	// rr
			resp[l++] = (LAPD_NR(sap) << 1) | (data[3] & 1);	// pf bit from req

			li->transmit_cb(resp, l, li->cbdata);

		};
		break;
	case LAPD_CMD_FRMR:
		// frame reject
#if 0
		if (teip->state == LAPD_TEI_ACTIVE)
			*prim = LAPD_MPH_DEACTIVATE_IND;
		lapd_tei_set_state(teip, LAPD_TEI_ASSIGNED);
#endif
		LOGP(DMI, LOGL_NOTICE, "frame reject, ignoring\n");
		break;
	case LAPD_CMD_DISC:
		// disconnect
		resp[l++] = data[0];
		resp[l++] = (tei << 1) | 1;
		resp[l++] = 0x73;
		li->transmit_cb(resp, l, li->cbdata);
		lapd_tei_set_state(teip, LAPD_TEI_NONE);
		break;
	default:
		LOGP(DMI, LOGL_NOTICE, "unknown cmd for tei %d (cmd %x)\n",
		     tei, cmd);
		break;
	}

	if (typ == LAPD_TYPE_I) {
		/* send rr
		 * Thu Jan 22 19:17:13 2009 <4000> sangoma.c:340 read  (62/25)   4: fa 33 01 0a 
		 * lapd <- S RR sapi 3e tei  25 cmd 0 pf 0 ns  -1 nr   5 ilen 0 teip 0x613800 vs 7 va 5 vr 2 len 4
		 */

		/* interrogating us, send rr */
		DEBUGP(DMI, "Sending RR response\n");
		resp[l++] = data[0];
		resp[l++] = (tei << 1) | 1;
		resp[l++] = 0x01;	// rr
		resp[l++] = (LAPD_NR(sap) << 1) | (data[3] & 1);	// pf bit from req

		li->transmit_cb(resp, l, li->cbdata);

		if (cmd != 0) {
			*prim = LAPD_DL_DATA_IND;
			return contents;
		}
	} else if (tei != 127 && typ == LAPD_TYPE_U && cmd == LAPD_CMD_UI) {
		*prim = LAPD_DL_UNITDATA_IND;
		return contents;
	}

	return NULL;
};

/* low-level function to send a single SABM message */
static int lapd_send_sabm(struct lapd_instance *li, uint8_t tei, uint8_t sapi)
{
	struct msgb *msg = msgb_alloc_headroom(1024, 128, "LAPD SABM");
	if (!msg)
		return -ENOMEM;

	DEBUGP(DMI, "Sending SABM for TEI=%u, SAPI=%u\n", tei, sapi);

	msgb_put_u8(msg, (sapi << 2) | (li->network_side ? 2 : 0));
	msgb_put_u8(msg, (tei << 1) | 1);
	msgb_put_u8(msg, 0x7F);

	li->transmit_cb(msg->data, msg->len, li->cbdata);

	msgb_free(msg);

	return 0;
}

/* timer call-back function for SABM re-transmission */
static void sabme_timer_cb(void *_sap)
{
	struct lapd_sap *sap = _sap;

	lapd_send_sabm(sap->tei->li, sap->tei->tei, sap->sapi);

	if (sap->state == SAP_STATE_SABM_RETRANS)
		osmo_timer_schedule(&sap->sabme_timer, SABM_INTERVAL);
}

/* Start a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_start(struct lapd_instance *li, uint8_t tei, uint8_t sapi)
{
	struct lapd_sap *sap;
	struct lapd_tei *teip;

	teip = teip_from_tei(li, tei);
	if (!teip)
		teip = lapd_tei_alloc(li, tei);

	sap = lapd_sap_find(teip, sapi);
	if (sap)
		return -EEXIST;

	sap = lapd_sap_alloc(teip, sapi);

	lapd_sap_set_state(teip, sapi, SAP_STATE_SABM_RETRANS);

	return 0;
}

/* Stop a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_stop(struct lapd_instance *li, uint8_t tei, uint8_t sapi)
{
	struct lapd_tei *teip;
	struct lapd_sap *sap;

	teip = teip_from_tei(li, tei);
	if (!teip)
		return -ENODEV;

	sap = lapd_sap_find(teip, sapi);
	if (!sap)
		return -ENODEV;

	lapd_sap_set_state(teip, sapi, SAP_STATE_INACTIVE);

	llist_del(&sap->list);
	talloc_free(sap);

	return 0;
}

/* Transmit Data (I-Frame) on the given LAPD Instance / TEI / SAPI */
void lapd_transmit(struct lapd_instance *li, uint8_t tei, uint8_t sapi,
		   uint8_t *data, unsigned int len)
{
	struct lapd_tei *teip = teip_from_tei(li, tei);
	struct lapd_sap *sap;

	if (!teip) {
		LOGP(DMI, LOGL_ERROR, "Cannot transmit on non-existing "
		     "TEI %u\n", tei);
		return;
	}

	sap = lapd_sap_find(teip, sapi);
	if (!sap) {
		LOGP(DMI, LOGL_INFO, "Tx on unknown SAPI=%u in TEI=%u, "
			"allocating\n", sapi, tei);
		sap = lapd_sap_alloc(teip, sapi);
	}

	/* prepend stuff */
	uint8_t buf[10000];
	memset(buf, 0, sizeof(buf));
	memmove(buf + 4, data, len);
	len += 4;

	buf[0] = (sapi << 2) | (li->network_side ? 2 : 0);
	buf[1] = (tei << 1) | 1;
	buf[2] = (LAPD_NS(sap) << 1);
	buf[3] = (LAPD_NR(sap) << 1) | 0;

	sap->vs = (sap->vs + 1) & 0x7f;

	li->transmit_cb(buf, len, li->cbdata);
};

/* Allocate a new LAPD instance */
struct lapd_instance *lapd_instance_alloc(int network_side,
					  void (*tx_cb)(uint8_t *data, int len,
							void *cbdata), void *cbdata)
{
	struct lapd_instance *li;

	li = talloc_zero(NULL, struct lapd_instance);
	if (!li)
		return NULL;

	li->transmit_cb = tx_cb;
	li->cbdata = cbdata;
	li->network_side = network_side;
	INIT_LLIST_HEAD(&li->tei_list);

	return li;
}
