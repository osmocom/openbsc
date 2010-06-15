/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#ifndef BSC_NAT_H
#define BSC_NAT_H

#include <sys/types.h>
#include <sccp/sccp_types.h>

#include <osmocore/select.h>
#include <osmocore/msgb.h>
#include <osmocore/timer.h>
#include <osmocore/write_queue.h>

#define DIR_BSC 1
#define DIR_MSC 2

struct bsc_nat;

/*
 * For the NAT we will need to analyze and later patch
 * the received message. This would require us to parse
 * the IPA and SCCP header twice. Instead of doing this
 * we will have one analyze structure and have the patching
 * and filter operate on the same structure.
 */
struct bsc_nat_parsed {
	/* ip access prototype */
	int ipa_proto;

	/* source local reference */
	struct sccp_source_reference *src_local_ref;

	/* destination local reference */
	struct sccp_source_reference *dest_local_ref;

	/* called ssn number */
	int called_ssn;

	/* calling ssn number */
	int calling_ssn;

	/* sccp message type */
	int sccp_type;

	/* bssap type, e.g. 0 for BSS Management */
	int bssap;

	/* the gsm0808 message type */
	int gsm_type;
};

/*
 * Per BSC data structure
 */
struct bsc_connection {
	struct llist_head list_entry;

	/* do we know anything about this BSC? */
	int authenticated;

	/* the fd we use to communicate */
	struct write_queue write_queue;

	/* the LAC assigned to this connection */
	unsigned int lac;

	/* a timeout node */
	struct timer_list id_timeout;

	/* a back pointer */
	struct bsc_nat *nat;
};

/*
 * Per SCCP source local reference patch table. It needs to
 * be updated on new SCCP connections, connection confirm and reject,
 * and on the loss of the BSC connection.
 */
struct sccp_connections {
	struct llist_head list_entry;

	struct bsc_connection *bsc;

	struct sccp_source_reference real_ref;
	struct sccp_source_reference patched_ref;
};

/**
 * One BSC entry in the config
 */
struct bsc_config {
	struct llist_head entry;

	char *token;
	unsigned int lac;
	int nr;

	struct bsc_nat *nat;
};

/**
 * the structure of the "nat" network
 */
struct bsc_nat {
	/* active SCCP connections that need patching */
	struct llist_head sccp_connections;

	/* active BSC connections that need patching */
	struct llist_head bsc_connections;

	/* known BSC's */
	struct llist_head bsc_configs;
	int num_bsc;
};

/* create and init the structures */
struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token, unsigned int lac);
struct bsc_config *bsc_config_num(struct bsc_nat *nat, int num);


/**
 * parse the given message into the above structure
 */
struct bsc_nat_parsed *bsc_nat_parse(struct msgb *msg);

/**
 * filter based on IP Access header in both directions
 */
int bsc_nat_filter_ipa(int direction, struct msgb *msg, struct bsc_nat_parsed *parsed);
int bsc_nat_vty_init(struct bsc_nat *nat);

/**
 * SCCP patching and handling
 */
int create_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed);
void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed);
struct bsc_connection *patch_sccp_src_ref_to_bsc(struct msgb *, struct bsc_nat_parsed *, struct bsc_nat *);
struct bsc_connection *patch_sccp_src_ref_to_msc(struct msgb *, struct bsc_nat_parsed *, struct bsc_nat *);

#endif
