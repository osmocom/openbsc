#ifndef _INT_SNDCP_H
#define _INT_SNDCP_H

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/* A fragment queue header, maintaining list of fragments for one N-PDU */
struct defrag_state {
	/* PDU number for which the defragmentation state applies */
	uint16_t npdu;
	/* highest segment number we have received so far */
	uint8_t highest_seg;
	/* bitmask of the segments we already have */
	uint32_t seg_have;
	/* do we still expect more segments? */
	unsigned int no_more;
	/* total length of all segments together */
	unsigned int tot_len;

	/* linked list of defrag_queue_entry: one for each fragment  */
	struct llist_head frag_list;

	struct osmo_timer_list timer;

	/* Holds state to know which compression mode is used
	 * when the packet is re-assembled */
	uint8_t pcomp;
	uint8_t dcomp;

	/* Holds the pointers to the compression entity list
	 * that is used when the re-assembled packet is decompressed */
	struct llist_head *proto;
	struct llist_head *data;
};

/* See 6.7.1.2 Reassembly */
enum sndcp_rx_state {
	SNDCP_RX_S_FIRST,
	SNDCP_RX_S_SUBSEQ,
	SNDCP_RX_S_DISCARD,
};

struct gprs_sndcp_entity {
	struct llist_head list;

	/* FIXME: move this RA_ID up to the LLME or even higher */
	struct gprs_ra_id ra_id;
	/* reference to the LLC Entity below this SNDCP entity */
	struct gprs_llc_lle *lle;
	/* The NSAPI we shall use on top of LLC */
	uint8_t nsapi;

	/* NPDU number for the GTP->SNDCP side */
	uint16_t tx_npdu_nr;
	/* SNDCP eeceiver state */
	enum sndcp_rx_state rx_state;
	/* The defragmentation queue */
	struct defrag_state defrag;
};

extern struct llist_head gprs_sndcp_entities;

/* Set of SNDCP-XID negotiation (See also: TS 144 065,
 * Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_req(struct gprs_llc_lle *lle, uint8_t nsapi);

/* Process SNDCP-XID indication (See also: TS 144 065,
 * Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_ind(struct gprs_llc_xid_field *xid_field_indication,
		     struct gprs_llc_xid_field *xid_field_response,
		     struct gprs_llc_lle *lle);

/* Process SNDCP-XID indication
 * (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_conf(struct gprs_llc_xid_field *xid_field_conf,
		      struct gprs_llc_xid_field *xid_field_request,
		      struct gprs_llc_lle *lle);

#endif	/* INT_SNDCP_H */
