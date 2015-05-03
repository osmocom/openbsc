/* NAT utilities using SCCP types */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#ifndef BSC_NAT_SCCP_H
#define BSC_NAT_SCCP_H

#include "bsc_msg_filter.h"

#include <osmocom/sccp/sccp_types.h>

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

	/* original value */
	struct sccp_source_reference original_dest_ref;

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
 * Per SCCP source local reference patch table. It needs to
 * be updated on new SCCP connections, connection confirm and reject,
 * and on the loss of the BSC connection.
 */
struct nat_sccp_connection {
	struct llist_head list_entry;

	struct bsc_connection *bsc;
	struct bsc_msc_connection *msc_con;

	struct sccp_source_reference real_ref;
	struct sccp_source_reference patched_ref;
	struct sccp_source_reference remote_ref;
	int has_remote_ref;

	/* status */
	int con_local;
	int authorized;

	struct bsc_filter_state filter_state;

	uint16_t lac;
	uint16_t ci;

	/* remember which Transactions we run over the bypass */
	char ussd_ti[8];

	/*
	 * audio handling. Remember if we have ever send a CRCX,
	 * remember the endpoint used by the MSC and BSC.
	 */
	int msc_endp;
	int bsc_endp;

	/* timeout handling */
	struct timespec creation_time;
};


#endif
