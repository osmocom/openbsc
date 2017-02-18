/* Code used by both libbsc and libmsc (common_cs means "BSC or MSC").
 *
 * (C) 2016 by sysmocom s.m.f.c. <info@sysmocom.de>
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2014 by Holger Hans Peter Freyther
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

#include <stdbool.h>

#include <osmocom/gsm/gsm0480.h>

#include <openbsc/common_cs.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>

/* Warning: if bsc_network_init() is not called, some of the members of
 * gsm_network are not initialized properly and must not be used! (In
 * particular the llist heads and stats counters.)
 * The long term aim should be to have entirely separate structs for libbsc and
 * libmsc with some common general items.
 */
struct gsm_network *gsm_network_init(void *ctx,
				     uint16_t country_code,
				     uint16_t network_code,
				     mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net;

	const char *default_regexp = ".*";

	net = talloc_zero(ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->subscr_group = talloc_zero(net, struct gsm_subscriber_group);
	if (!net->subscr_group) {
		talloc_free(net);
		return NULL;
	}

	if (gsm_parse_reg(net, &net->authorized_regexp, &net->authorized_reg_str, 1,
			  &default_regexp) != 0)
		return NULL;

	net->subscr_group->net = net;
	net->auto_create_subscr = true;
	net->auto_assign_exten = true;

	net->country_code = country_code;
	net->network_code = network_code;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->subscr_conns);

	net->bsc_subscribers = talloc_zero(net, struct llist_head);
	INIT_LLIST_HEAD(net->bsc_subscribers);

	/* init statistics */
	net->msc_ctrs = rate_ctr_group_alloc(net, &msc_ctrg_desc, 0);
	net->active_calls = osmo_counter_alloc("msc.active_calls");

	net->mncc_recv = mncc_recv;
	net->ext_min = GSM_MIN_EXTEN;
	net->ext_max = GSM_MAX_EXTEN;

	net->dyn_ts_allow_tch_f = true;

	return net;
}

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;

	return msg;
}

struct msgb *gsm48_create_loc_upd_rej(uint8_t cause)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;
	return msg;
}

uint8_t sms_next_rp_msg_ref(uint8_t *next_rp_ref)
{
	const uint8_t rp_msg_ref = *next_rp_ref;
	/*
	 * This should wrap as the valid range is 0 to 255. We only
	 * transfer one SMS at a time so we don't need to check if
	 * the id has been already assigned.
	 */
	*next_rp_ref += 1;

	return rp_msg_ref;
}
