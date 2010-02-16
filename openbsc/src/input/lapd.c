
/*
 * minimal standalone network-side lap-d implementation
 * oystein@homelien.no, 2009
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lapd.h"
#include "openbsc/debug.h"

#define	DEBUG_LAPD(f, args...)	{ printf("lapd "); printf(f, ## args); };

typedef enum {
	LAPD_TEI_NONE	= 0,

	LAPD_TEI_ASSIGNED,

	LAPD_TEI_ACTIVE,
} lapd_tei_state;

const char *lapd_tei_states[] = {
	"NONE",
	"ASSIGNED",
	"ACTIVE",
};

typedef enum {
	LAPD_TYPE_NONE	= 0,

	LAPD_TYPE_I,
	LAPD_TYPE_S,
	LAPD_TYPE_U,
} lapd_msg_type;

typedef enum {
	// commands/responses
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



const char	*lapd_msg_types = "?ISU";
const int	network_side = 1; // 0 for user side

typedef struct {
	int				tei;
	int				sapi;
	//A valid N(R) value is one that is in the range V(A) ≤ N(R) ≤ V(S).
	int				vs; // next to be transmitted
	int				va; // last acked by peer
	int				vr; // next expected to be received
	lapd_tei_state	state;
} lapd_tei_t;

// 3.5.2.2   Send state variable V(S)
// Each point-to-point data link connection endpoint shall have an associated V(S) when using I frame
// commands. V(S) denotes the sequence number of the next I frame to be transmitted. The V(S) can
// take on the value 0 through n minus 1. The value of V(S) shall be incremented by 1 with each
// successive I frame transmission, and shall not exceed V(A) by more than the maximum number of
// outstanding I frames k. The value of k may be in the range of 1 ≤ k ≤ 127.
//
// 3.5.2.3   Acknowledge state variable V(A)
// Each point-to-point data link connection endpoint shall have an associated V(A) when using I frame
// commands and supervisory frame commands/responses. V(A) identifies the last I frame that has been
// acknowledged by its peer [V(A) − 1 equals the N(S) of the last acknowledged I frame]. V(A) can
// take on the value 0 through n minus 1. The value of V(A) shall be updated by the valid N(R) values
// received from its peer (see 3.5.2.6). A valid N(R) value is one that is in the range V(A) ≤ N(R) ≤
// V(S).
//
// 3.5.2.5    Receive state variable V(R)
// Each point-to-point data link connection endpoint shall have an associated V(R) when using I frame
// commands and supervisory frame commands/responses. V(R) denotes the sequence number of the
// next in-sequence I frame expected to be received. V(R) can take on the value 0 through n minus 1.
// The value of V(R) shall be incremented by one with the receipt of an error-free, in-sequence I frame
// whose N(S) equals V(R).
//
#define	LAPD_NS(teip) (teip->vs)
#define	LAPD_NR(teip) (teip->vr)

// 3.5.2.4    Send sequence number N(S)
// Only I frames contain N(S), the send sequence number of transmitted I frames. At the time that an in-
// sequence I frame is designated for transmission, the value of N(S) is set equal to V(S).
//
// 3.5.2.6    Receive sequence number N(R)
// All I frames and supervisory frames contain N(R), the expected send sequence number of the next
// received I frame. At the time that a frame of the above types is designated for transmission, the value
// of N(R) is set equal to V(R). N(R) indicates that the data link layer entity transmitting the N(R) has
// correctly received all I frames numbered up to and including N(R) − 1.

void (*lapd_transmit_cb)(uint8_t *data, int len, void *cbdata);

static lapd_tei_t tei_list[] = {
	{ 25, 62, },
	{ 1, 0, },
	{ -1 },
};

lapd_tei_t *teip_from_tei(int tei) {
	lapd_tei_t *p;
	for (p = tei_list; p->tei != -1; p++) {
		if (p->tei == tei) return p;
	};
	return NULL;
};

void lapd_tei_set_state(lapd_tei_t *teip, int newstate) {
	DEBUG_LAPD("state change on tei %d: %s -> %s\n", teip->tei, lapd_tei_states[teip->state], lapd_tei_states[newstate]);
	teip->state = newstate;
};

void lapd_tei_receive(uint8_t *data, int len, void *cbdata) {
	//DEBUG_LAPD("tei receive %p, %d\n", data, len);
	int entity = data[0];
	int	ref = data[1];
	int mt = data[3];
	int	action = data[4] >> 1;
	int	e = data[4] & 1;
	//DEBUG_LAPD("tei mgmt: entity %x, ref %x, mt %x, action %x, e %x\n", entity, ref, mt, action, e);

	switch (mt) {
		case 0x01: {// identity request
			int tei = action;
			DEBUG_LAPD("tei mgmt: identity request, accepting tei %d\n", tei);
			//printf("tei: %d\n", tei);
			uint8_t resp[8];
			memmove(resp, "\xfe\xff\x03\x0f\x00\x00\x02\x00", 8);
			resp[7] = (tei << 1) | 1;
			lapd_transmit_cb(resp, 8, cbdata);
			lapd_tei_t *teip = teip_from_tei (tei);
			if (teip->state == LAPD_TEI_NONE)
				lapd_tei_set_state(teip, LAPD_TEI_ASSIGNED);
			break; }
		default: 
			DEBUG_LAPD("tei mgmt: unknown mt %x action %x\n", mt, action);
			assert(0);
	};
};

uint8_t *lapd_receive(uint8_t *data, int len, int *ilen, lapd_mph_type *prim, void *cbdata) {
#if 0
	DEBUG_LAPD("receive %p, %d\n", data, len);
	hexdump(data, len);
#endif

	*ilen = 0;
	*prim = 0;

	if (len < 2) {
		DEBUG_LAPD("len %d < 2\n", len);
		return NULL;
	};

	if ((data[0] & 1) != 0 || (data[1] & 1) != 1) {
		DEBUG_LAPD("address field %x/%x not well formed\n", data[0], data[1]);
		return NULL;
	};

	int	sapi = data[0] >> 2;
	int cr = (data[0] >> 1) & 1;
	int tei = data[1] >> 1;
	int command = network_side ^ cr;
	//DEBUG_LAPD("  address sapi %x tei %d cmd %d cr %d\n", sapi, tei, command, cr);

	if (len < 3) {
		DEBUG_LAPD("len %d < 4\n", len);
		return NULL;
	};

	lapd_msg_type typ = 0;
	lapd_cmd_type cmd = 0;
	int	pf = -1;
	int	ns = -1;
	int	nr = -1;
	if ((data[2] & 1) == 0) {
		typ = LAPD_TYPE_I;
		assert(len >= 4);
		ns = data[2] >> 1;
		nr = data[3] >> 1;
		pf = data[3] & 1;
		cmd = LAPD_CMD_I;
	} else if ((data[2] & 3) == 1) {
		typ = LAPD_TYPE_S;
		assert(len >= 4);
		nr = data[3] >> 1;
		pf = data[3] & 1;
		switch (data[2]) {
			case 0x1: cmd = LAPD_CMD_RR; break;
			case 0x5: cmd = LAPD_CMD_RNR; break;
			case 0x9: cmd = LAPD_CMD_REJ; break;
			default: 
				DEBUG_LAPD("unknown S cmd %x\n", data[2]);
				assert(0);
		};
	} else if ((data[2] & 3) == 3) {
		typ = LAPD_TYPE_U;
		pf = (data[2] >> 4) & 1;
		int val = data[2] & ~(1<<4);
		switch (val) {
			case 0x6f: cmd = LAPD_CMD_SABME; break;
			case 0x0f: cmd = LAPD_CMD_DM; break;
			case 0x03: cmd = LAPD_CMD_UI; break;
			case 0x43: cmd = LAPD_CMD_DISC; break;
			case 0x63: cmd = LAPD_CMD_UA; break;
			case 0x87: cmd = LAPD_CMD_FRMR; break;
			case 0xaf: cmd = LAPD_CMD_XID; break;
	
			default: 
				DEBUG_LAPD("unknown U cmd %x (pf %x data %x)\n", val, pf, data[2]);
				assert(0);
		};
	};
	
	uint8_t *contents = &data[4];
	if (typ == LAPD_TYPE_U) contents--;
	*ilen = len - (contents - data);
	
	lapd_tei_t *teip = teip_from_tei(tei);
	if (tei == 127)
		lapd_tei_receive(contents, *ilen, cbdata);

	DEBUG_LAPD("<- %c %s sapi %x tei %3d cmd %x pf %x ns %3d nr %3d ilen %d teip %p vs %d va %d vr %d len %d\n", lapd_msg_types[typ], lapd_cmd_types[cmd], sapi, tei, command, pf, ns, nr, *ilen, teip, teip ? teip->vs : -1, teip ? teip->va : -1, teip ? teip->vr : -1, len);

	if (teip) {
		switch (cmd) {
			case LAPD_CMD_I: {
				if (ns != teip->vr) {
					DEBUG_LAPD("ns %d != vr %d\n", ns, teip->vr);
					if (ns == teip->vr-1) {
						DEBUG_LAPD("DOUBLE FRAME, ignoring\n");
						cmd = 0; // ignore
					} else {
						assert(0);
					};
				} else {
					//printf("IN SEQUENCE\n");
				};
				teip->vr = (ns + 1) & 0x7f; // FIXME: hack!

				
				break; }
			case LAPD_CMD_SABME: {
				teip->vs = 0;
				teip->vr = 0;
				teip->va = 0;

				// ua
				uint8_t resp[8];
				int l = 0;
				resp[l++] = data[0];
				resp[l++] = (tei << 1) | 1;
				resp[l++] = 0x73;
				lapd_transmit_cb(resp, l, cbdata);
				
				break; }
			case LAPD_CMD_RR: {
				teip->va = (nr & 0x7f);
				if (teip->state != LAPD_TEI_ACTIVE) {
					if (teip->state == LAPD_TEI_ASSIGNED) {
						lapd_tei_set_state(teip, LAPD_TEI_ACTIVE);
						*prim = LAPD_MPH_ACTIVATE_IND;
						//printf("ASSIGNED and ACTIVE\n");
					} else {
#if 0
						DEBUG_LAPD("rr in strange state, send rej\n");

						// rej
						uint8_t resp[8];
						int l = 0;
						resp[l++] = (teip->sapi << 2) | (network_side ? 0 : 2);
						resp[l++] = (tei << 1) | 1;
						resp[l++] = 0x09; //rej
						resp[l++] = ((teip->vr+1) << 1) | 0;
						lapd_transmit_cb(resp, l, cbdata);
						pf = 0; // dont reply
#endif
					};
				};
				if (pf) {
					// interrogating us, send rr
					uint8_t resp[8];
					int l = 0;
					resp[l++] = data[0];
					resp[l++] = (tei << 1) | 1;
					resp[l++] = 0x01; // rr
					resp[l++] = (LAPD_NR(teip) << 1) | (data[3] & 1); // pf bit from req
	
					lapd_transmit_cb(resp, l, cbdata);
					
				};

				break; }
			case LAPD_CMD_FRMR: { // frame reject
#if 0
				if (teip->state == LAPD_TEI_ACTIVE)
					*prim = LAPD_MPH_DEACTIVATE_IND;
				lapd_tei_set_state(teip, LAPD_TEI_ASSIGNED);
#endif
				DEBUG_LAPD("frame reject, ignoring\n");
				assert(0);
				break; }
			case LAPD_CMD_DISC: { // disconnect
				uint8_t resp[8];
				int l = 0;
				resp[l++] = data[0];
				resp[l++] = (tei << 1) | 1;
				resp[l++] = 0x73;
				lapd_transmit_cb(resp, l, cbdata);
				lapd_tei_set_state(teip, LAPD_TEI_NONE);
				break; }
			default: 
				DEBUG_LAPD("unknown cmd for tei %d (cmd %x)\n", tei, cmd);
				assert(0);
		};
	};

	//if ((*prim == 0) && (ilen > 0) && (typ != LAPD_TYPE_S)) {
	//if (cmd == LAPD_CMD_I) {
	if (typ == LAPD_TYPE_I) {
		// send rr
		// Thu Jan 22 19:17:13 2009 <4000> sangoma.c:340 read  (62/25)   4: fa 33 01 0a 
		// lapd <- S RR sapi 3e tei  25 cmd 0 pf 0 ns  -1 nr   5 ilen 0 teip 0x613800 vs 7 va 5 vr 2 len 4

		// interrogating us, send rr
		uint8_t resp[8];
		int l = 0;
		resp[l++] = data[0];
		resp[l++] = (tei << 1) | 1;
		resp[l++] = 0x01; // rr
		resp[l++] = (LAPD_NR(teip) << 1) | (data[3] & 1); // pf bit from req

		lapd_transmit_cb(resp, l, cbdata);

		*prim = LAPD_DL_DATA_IND;
		return contents;
	};

	return NULL;
};

void lapd_transmit(int tei, uint8_t *data, int len, void *cbdata) {
	//printf("lapd_transmit %d, %d\n", tei, len);
	//hexdump(data, len);
	lapd_tei_t *teip = teip_from_tei(tei);
	//printf("teip %p\n", teip);

	// prepend stuff
	uint8_t	buf[10000];
	memset(buf, 0, sizeof(buf));
	memmove(buf+4, data, len);
	len += 4;

	buf[0] = (teip->sapi << 2) | (network_side ? 2 : 0);
	buf[1] = (teip->tei << 1) | 1;
	buf[2] = (LAPD_NS(teip) << 1);
	buf[3] = (LAPD_NR(teip) << 1) | 0;

	teip->vs = (teip->vs + 1) & 0x7f;

	lapd_transmit_cb(buf, len, cbdata);
};

