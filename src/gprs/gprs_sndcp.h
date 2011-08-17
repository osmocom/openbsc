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

#endif	/* INT_SNDCP_H */
