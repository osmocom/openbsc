/* BSC Multiplexer/NAT */

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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/ipaccess.h>
#include <openbsc/debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

/*
 * The idea is to have a simple struct describing a IPA packet with
 * SCCP SSN and the GSM 08.08 payload and decide. We will both have
 * a white and a blacklist of packets we want to handle.
 *
 * TODO: Implement a "NOT" in the filter language.
 */

#define ALLOW_ANY -1

#define FILTER_TO_BSC	1
#define FILTER_TO_MSC	2
#define FILTER_TO_BOTH	3


struct bsc_pkt_filter {
	int ipa_proto;
	int dest_ssn;
	int bssap;
	int gsm;
	int filter_dir;
};

static struct bsc_pkt_filter black_list[] = {
	/* filter reset messages to the MSC */
	{ IPAC_PROTO_SCCP, SCCP_SSN_BSSAP, 0, BSS_MAP_MSG_RESET, FILTER_TO_MSC },

	/* filter reset ack messages to the BSC */
	{ IPAC_PROTO_SCCP, SCCP_SSN_BSSAP, 0, BSS_MAP_MSG_RESET_ACKNOWLEDGE, FILTER_TO_BSC },

	/* filter ip access */
	{ IPAC_PROTO_IPACCESS, ALLOW_ANY, ALLOW_ANY, ALLOW_ANY, FILTER_TO_MSC },
};

static struct bsc_pkt_filter white_list[] = {
	/* allow IPAC_PROTO_SCCP messages to both sides */
	{ IPAC_PROTO_SCCP, ALLOW_ANY, ALLOW_ANY, ALLOW_ANY, FILTER_TO_BOTH },

	/* allow MGCP messages to both sides */
	{ IPAC_PROTO_MGCP_OLD, ALLOW_ANY, ALLOW_ANY, ALLOW_ANY, FILTER_TO_BOTH },
};

struct bsc_nat_parsed *bsc_nat_parse(struct msgb *msg)
{
	struct sccp_parse_result result;
	struct bsc_nat_parsed *parsed;
	struct ipaccess_head *hh;

	/* quick fail */
	if (msg->len < 4)
		return NULL;

	parsed = talloc_zero(msg, struct bsc_nat_parsed);
	if (!parsed)
		return NULL;

	/* more init */
	parsed->ipa_proto = parsed->called_ssn = parsed->calling_ssn = -1;
	parsed->sccp_type = parsed->bssap = parsed->gsm_type = -1;

	/* start parsing */
	hh = (struct ipaccess_head *) msg->data;
	parsed->ipa_proto = hh->proto;

	msg->l2h = &hh->data[0];

	/* do a size check on the input */
	if (ntohs(hh->len) != msgb_l2len(msg)) {
		LOGP(DLINP, LOGL_ERROR, "Wrong input length?\n");
		talloc_free(parsed);
		return NULL;
	}

	/* analyze sccp down here */
	if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
		memset(&result, 0, sizeof(result));
		if (sccp_parse_header(msg, &result) != 0) {
			talloc_free(parsed);
			return 0;
		}

		if (msg->l3h && msgb_l3len(msg) < 3) {
			LOGP(DNAT, LOGL_ERROR, "Not enough space or GSM payload\n");
			talloc_free(parsed);
			return 0;
		}

		parsed->sccp_type = sccp_determine_msg_type(msg);
		parsed->src_local_ref = result.source_local_reference;
		parsed->dest_local_ref = result.destination_local_reference;
		if (parsed->dest_local_ref)
			parsed->original_dest_ref = *parsed->dest_local_ref;
		parsed->called_ssn = result.called.ssn;
		parsed->calling_ssn = result.calling.ssn;

		/* in case of connection confirm we have no payload */
		if (msg->l3h) {
			parsed->bssap = msg->l3h[0];
			parsed->gsm_type = msg->l3h[2];
		}
	}

	return parsed;
}

int bsc_nat_filter_ipa(int dir, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	int i;

	/* go through the blacklist now */
	for (i = 0; i < ARRAY_SIZE(black_list); ++i) {
		/* ignore the rule? */
		if (black_list[i].filter_dir != FILTER_TO_BOTH
		    && black_list[i].filter_dir != dir)
			continue;

		/* the proto is not blacklisted */
		if (black_list[i].ipa_proto != ALLOW_ANY
		    && black_list[i].ipa_proto != parsed->ipa_proto)
			continue;

		if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
			/* the SSN is not blacklisted */
			if (black_list[i].dest_ssn != ALLOW_ANY
			    && black_list[i].dest_ssn != parsed->called_ssn)
				continue;

			/* bssap */
			if (black_list[i].bssap != ALLOW_ANY
			    && black_list[i].bssap != parsed->bssap)
				continue;

			/* gsm */
			if (black_list[i].gsm != ALLOW_ANY
			    && black_list[i].gsm != parsed->gsm_type)
				continue;

			/* blacklisted */
			LOGP(DNAT, LOGL_INFO, "Blacklisted with rule %d\n", i);
			return 1;
		} else {
			/* blacklisted, we have no content sniffing yet */
			LOGP(DNAT, LOGL_INFO, "Blacklisted with rule %d\n", i);
			return 1;
		}
	}

	/* go through the whitelust now */
	for (i = 0; i < ARRAY_SIZE(white_list); ++i) {
		/* ignore the rule? */
		if (white_list[i].filter_dir != FILTER_TO_BOTH
		    && white_list[i].filter_dir != dir)
			continue;

		/* the proto is not whitelisted */
		if (white_list[i].ipa_proto != ALLOW_ANY
		    && white_list[i].ipa_proto != parsed->ipa_proto)
			continue;

		if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
			/* the SSN is not whitelisted */
			if (white_list[i].dest_ssn != ALLOW_ANY
			    && white_list[i].dest_ssn != parsed->called_ssn)
				continue;

			/* bssap */
			if (white_list[i].bssap != ALLOW_ANY
			    && white_list[i].bssap != parsed->bssap)
				continue;

			/* gsm */
			if (white_list[i].gsm != ALLOW_ANY
			    && white_list[i].gsm != parsed->gsm_type)
				continue;

			/* whitelisted */
			LOGP(DNAT, LOGL_INFO, "Whitelisted with rule %d\n", i);
			return 0;
		} else {
			/* whitelisted */
			return 0;
		}
	}

	return 1;
}
