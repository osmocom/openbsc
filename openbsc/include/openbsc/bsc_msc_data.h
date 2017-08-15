/*
 * Data for the true BSC
 *
 * (C) 2010-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2015 by On-Waves
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

/*
 * NOTE: This is about a *remote* MSC for OsmoBSC and is not part of libmsc.
 */

#ifndef _OSMO_MSC_DATA_H
#define _OSMO_MSC_DATA_H

#include "bsc_msc.h"

#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>


#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/core/fsm.h>

#include <regex.h>

struct osmo_bsc_rf;
struct gsm_network;

struct gsm_audio_support {
        uint8_t hr  : 1,
                ver : 7;
};

enum {
	MSC_CON_TYPE_NORMAL,
	MSC_CON_TYPE_LOCAL,
};

/*! /brief Information on a remote MSC for libbsc.
 */
struct bsc_msc_data {
	struct llist_head entry;

	/* Back pointer */
	struct gsm_network *network;

	int allow_emerg;
	int type;

	/* local call routing */
	char *local_pref;
	regex_t local_pref_reg;


	/* Connection data */
	char *bsc_token;
	uint8_t bsc_key[16];
	uint8_t bsc_key_present;

	int ping_timeout;
	int pong_timeout;
	struct osmo_timer_list ping_timer;
	struct osmo_timer_list pong_timer;
	int advanced_ping;
	struct bsc_msc_connection *msc_con;
	int core_mnc;
	int core_mcc;
	int core_lac;
	int core_ci;
	int rtp_base;

	/* audio codecs */
	struct gsm48_multi_rate_conf amr_conf;
	struct gsm_audio_support **audio_support;
	int audio_length;

	/* destinations */
	struct llist_head dests;

	/* ussd welcome text */
	char *ussd_welcome_txt;

	/* mgcp agent */
	struct osmo_wqueue mgcp_agent;

	int nr;

	/* ussd msc connection lost text */
	char *ussd_msc_lost_txt;

	/* ussd text when MSC has entered the grace period */
	char *ussd_grace_txt;

	char *acc_lst_name;

	/* Sigtran connection data */
	struct {
		uint32_t cs7_instance;
		bool cs7_instance_valid;
		struct osmo_sccp_instance *sccp;
		struct osmo_sccp_user *sccp_user;

		/* Holds a copy of the our local MSC address,
		 * this will be the sccp-address that is associated
		 * with the A interface of this particular BSC,
		 * this address is filled up by the VTY interface */
		struct osmo_sccp_addr bsc_addr;
		char *bsc_addr_name;

		/* Holds a copy of the MSC address. This is the
		 * address of the MSC that handles the calls of
		 * this BSC. The address is configured via the
		 * VTY interface */
		struct osmo_sccp_addr msc_addr;
		char *msc_addr_name;

		struct a_reset_ctx *reset;
	} a;
};

/*
 * Per BSC data.
 */
struct osmo_bsc_data {
	struct gsm_network *network;

	/* msc configuration */
	struct llist_head mscs;

	/* rf ctl related bits */
	char *mid_call_txt;
	int mid_call_timeout;
	char *rf_ctrl_name;
	struct osmo_bsc_rf *rf_ctrl;
	int auto_off_timeout;

	/* ussd text when there is no MSC available */
	char *ussd_no_msc_txt;

	char *acc_lst_name;
};


int osmo_bsc_msc_init(struct bsc_msc_data *msc);
int osmo_bsc_sccp_init(struct gsm_network *gsmnet);
int msc_queue_write(struct bsc_msc_connection *conn, struct msgb *msg, int proto);
int msc_queue_write_with_ping(struct bsc_msc_connection *, struct msgb *msg, int proto);

int osmo_bsc_audio_init(struct gsm_network *network);

struct bsc_msc_data *osmo_msc_data_find(struct gsm_network *, int);
struct bsc_msc_data *osmo_msc_data_alloc(struct gsm_network *, int);


#endif
