#ifndef _GPRS_LLC_H
#define _GPRS_LLC_H

#include <stdint.h>

/* Section 4.7 LLC Layer Structure */
enum gprs_llc_sapi {
	GPRS_SAPI_GMM		= 1,
	GPRS_SAPI_TOM2		= 2,
	GPRS_SAPI_SNDCP3	= 3,
	GPRS_SAPI_SNDCP5	= 5,
	GPRS_SAPI_SMS		= 7,
	GPRS_SAPI_TOM8		= 8,
	GPRS_SAPI_SNDCP9	= 9,
	GPRS_SAPI_SNDCP11	= 11,
};

/* Section 6.4 Commands and Responses */
enum gprs_llc_u_cmd {
	GPRS_LLC_U_DM_RESP		= 0x01,
	GPRS_LLC_U_DISC_CMD		= 0x04,
	GPRS_LLC_U_UA_RESP		= 0x06,
	GPRS_LLC_U_SABM_CMD		= 0x07,
	GPRS_LLC_U_FRMR_RESP		= 0x08,
	GPRS_LLC_U_XID			= 0x0b,
	GPRS_LLC_U_NULL_CMD		= 0x00,
};

/* TS 04.64 Section 7.1.2 Table 7: LLC layer primitives (GMM/SNDCP/SMS/TOM) */
/* TS 04.65 Section 5.1.2 Table 2: Service primitives used by SNDCP */
enum gprs_llc_primitive {
	/* GMM <-> LLME */
	LLGMM_ASSIGN_REQ,	/* GMM tells us new TLLI: TLLI old, TLLI new, Kc, CiphAlg */
	LLGMM_RESET_REQ,	/* GMM tells us to perform XID negotiation: TLLI */
	LLGMM_RESET_CNF,	/* LLC informs GMM that XID has completed: TLLI */
	LLGMM_SUSPEND_REQ,	/* GMM tells us MS has suspended: TLLI, Page */
	LLGMM_RESUME_REQ,	/* GMM tells us MS has resumed: TLLI */
	LLGMM_PAGE_IND,		/* LLC asks GMM to page MS: TLLI */
	LLGMM_IOV_REQ,		/* GMM tells us to perform XID: TLLI */
	LLGMM_STATUS_IND,	/* LLC informs GMM about error: TLLI, Cause */
	/* LLE <-> (GMM/SNDCP/SMS/TOM) */
	LL_RESET_IND,		/* TLLI */
	LL_ESTABLISH_REQ,	/* TLLI, XID Req */
	LL_ESTABLISH_IND,	/* TLLI, XID Req, N201-I, N201-U */
	LL_ESTABLISH_RESP,	/* TLLI, XID Negotiated */
	LL_ESTABLISH_CONF,	/* TLLI, XID Neg, N201-i, N201-U */
	LL_RELEASE_REQ,		/* TLLI, Local */
	LL_RELEASE_IND,		/* TLLI, Cause */
	LL_RELEASE_CONF,	/* TLLI */
	LL_XID_REQ,		/* TLLI, XID Requested */
	LL_XID_IND,		/* TLLI, XID Req, N201-I, N201-U */
	LL_XID_RESP,		/* TLLI, XID Negotiated */
	LL_XID_CONF,		/* TLLI, XID Neg, N201-I, N201-U */
	LL_DATA_REQ,		/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	LL_DATA_IND,		/* TLLI, SN-PDU */
	LL_DATA_CONF,		/* TLLI, Ref */
	LL_UNITDATA_REQ,	/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	LL_UNITDATA_IND,	/* TLLI, SN-PDU */
	LL_STATUS_IND,		/* TLLI, Cause */
};

/* Section 4.5.2 Logical Link States + Annex C.2 */
enum gprs_llc_ll_state {
	GPRS_LLS_UNASSIGNED	= 1,	/* No TLLI yet */
	GPRS_LLS_ASSIGNED_ADM	= 2,	/* TLLI assigned */
	GPRS_LLS_LOCAL_EST	= 3,	/* Local Establishment */
	GPRS_LLS_REMOTE_EST	= 4,	/* Remote Establishment */
	GPRS_LLS_ABM		= 5,
	GPRS_LLS_LOCAL_REL	= 6,	/* Local Release */
	GPRS_LLS_TIMER_REC 	= 7,	/* Timer Recovery */
};

/* Section 4.7.1: Logical Link Entity: One per DLCI (TLLI + SAPI) */
struct gprs_llc_lle {
	struct llist_head list;

	struct timer_list t200;
	struct timer_list t201;	/* wait for acknowledgement */

	enum gprs_llc_ll_state state;

	uint32_t tlli;
	uint32_t sapi;

	uint16_t v_sent;
	uint16_t v_ack;
	uint16_t v_recv;

	uint16_t vu_send;
	uint16_t vu_recv;

	unsigned int n200;
	unsigned int retrans_ctr;

	/* over which BSSGP BTS ctx do we need to transmit */
	uint16_t bvci;
	uint16_t nsei;
};

extern struct llist_head gprs_llc_lles;

/* BSSGP-UL-UNITDATA.ind */
int gprs_llc_rcvmsg(struct msgb *msg, struct tlv_parsed *tv);

/* LL-UNITDATA.req */
int gprs_llc_tx_ui(struct msgb *msg, uint8_t sapi, int command);

int gprs_llc_vty_init(void);

#endif
