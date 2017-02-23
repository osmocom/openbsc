/* Generic signalling/notification infrastructure */
/* (C) 2009-2010, 2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#ifndef OPENBSC_SIGNAL_H
#define OPENBSC_SIGNAL_H

#include <stdlib.h>
#include <errno.h>

#include <openbsc/gsm_data.h>

#include <osmocom/core/signal.h>

/*
 * Signalling subsystems
 */
enum signal_subsystems {
	SS_PAGING,
	SS_SMS,
	SS_ABISIP,
	SS_NM,
	SS_LCHAN,
	SS_SUBSCR,
	SS_SCALL,
	SS_CHALLOC,
	SS_IPAC_NWL,
	SS_RF,
	SS_MSC,
	SS_HO,
	SS_CCCH,
	SS_SGSN,
};

/* SS_PAGING signals */
enum signal_paging {
	S_PAGING_SUCCEEDED,
	S_PAGING_EXPIRED,
};

/* SS_SMS signals */
enum signal_sms {
	S_SMS_SUBMITTED,	/* A SMS has been successfully submitted to us */
	S_SMS_DELIVERED,	/* A SMS has been successfully delivered to a MS */
	S_SMS_SMMA,		/* A MS tells us it has more space available */
	S_SMS_MEM_EXCEEDED,	/* A MS tells us it has no more space available */
	S_SMS_UNKNOWN_ERROR,	/* A MS tells us it has an error */
};

/* SS_ABISIP signals */
enum signal_abisip {
	S_ABISIP_CRCX_ACK,
	S_ABISIP_MDCX_ACK,
	S_ABISIP_DLCX_IND,
};

/* SS_NM signals */
enum signal_nm {
	S_NM_SW_ACTIV_REP,	/* GSM 12.21 software activated report */
	S_NM_FAIL_REP,		/* GSM 12.21 failure event report */
	S_NM_NACK,		/* GSM 12.21 various NM_MT_*_NACK happened */
	S_NM_IPACC_NACK,	/* GSM 12.21 nanoBTS extensions NM_MT_IPACC_*_*_NACK happened */
	S_NM_IPACC_ACK,		/* GSM 12.21 nanoBTS extensions NM_MT_IPACC_*_*_ACK happened */
	S_NM_IPACC_RESTART_ACK, /* nanoBTS has send a restart ack */
	S_NM_IPACC_RESTART_NACK,/* nanoBTS has send a restart ack */
	S_NM_TEST_REP,		/* GSM 12.21 Test Report */
	S_NM_STATECHG_OPER,	/* Operational State changed*/
	S_NM_STATECHG_ADM,	/* Administrative State changed */
	S_NM_OM2K_CONF_RES,	/* OM2K Configuration Result */
};

/* SS_LCHAN signals */
enum signal_lchan {
	/*
	 * The lchan got freed with an use_count != 0 and error
	 * recovery needs to be carried out from within the
	 * signal handler.
	 */
	S_LCHAN_UNEXPECTED_RELEASE,
	S_LCHAN_ACTIVATE_ACK,		/* 08.58 Channel Activate ACK */
	S_LCHAN_ACTIVATE_NACK,		/* 08.58 Channel Activate NACK */
	S_LCHAN_HANDOVER_COMPL,		/* 04.08 Handover Completed */
	S_LCHAN_HANDOVER_FAIL,		/* 04.08 Handover Failed */
	S_LCHAN_HANDOVER_DETECT,	/* 08.58 Handover Detect */
	S_LCHAN_MEAS_REP,		/* 08.58 Measurement Report */
};

/* SS_CHALLOC signals */
enum signal_challoc {
	S_CHALLOC_ALLOC_FAIL,	/* allocation of lchan has failed */
	S_CHALLOC_FREED,	/* lchan has been successfully freed */
};

/* SS_SUBSCR signals */
enum signal_subscr {
	S_SUBSCR_ATTACHED,
	S_SUBSCR_DETACHED,
	S_SUBSCR_IDENTITY,		/* we've received some identity information */
};

/* SS_SCALL signals */
enum signal_scall {
	S_SCALL_SUCCESS,
	S_SCALL_EXPIRED,
	S_SCALL_DETACHED,
};

/* SS_IPAC_NWL signals */
enum signal_ipaccess {
	S_IPAC_NWL_COMPLETE,
};

enum signal_global {
	S_GLOBAL_BTS_CLOSE_OM,
};

/* SS_RF signals */
enum signal_rf {
	S_RF_OFF,
	S_RF_ON,
	S_RF_GRACE,
};

struct gsm_subscriber;

struct paging_signal_data {
	struct gsm_subscriber *subscr;
	struct gsm_bts *bts;

	int paging_result;

	/* NULL in case the paging didn't work */
	struct gsm_subscriber_connection *conn;
};

struct scall_signal_data {
	struct gsm_subscriber_connection *conn;
	void *data;
};

struct ipacc_ack_signal_data {
	struct gsm_bts_trx *trx;
	uint8_t msg_type;
};

struct abis_om2k_mo;

struct nm_statechg_signal_data {
	struct gsm_bts *bts;
	uint8_t obj_class;
	void *obj;
	struct gsm_nm_state *old_state;
	struct gsm_nm_state *new_state;

	/* This pointer is vaold for TS 12.21 MO */
	struct abis_om_obj_inst *obj_inst;
	/* This pointer is vaold for RBS2000 MO */
	struct abis_om2k_mo *om2k_mo;
};

struct nm_om2k_signal_data {
	struct gsm_bts *bts;
	void *obj;
	struct abis_om2k_mo *om2k_mo;

	uint8_t accordance_ind;
};

struct nm_nack_signal_data {
	struct msgb *msg;
	struct gsm_bts *bts;
	uint8_t mt;
};

struct challoc_signal_data {
	struct gsm_bts *bts;
	struct gsm_lchan *lchan;
	enum gsm_chan_t type;
};

struct rf_signal_data {
	struct gsm_network *net;
};

struct sms_signal_data {
	/* The transaction where this occured */
	struct gsm_trans *trans;
	/* Can be NULL for SMMA */
	struct gsm_sms *sms;
	/* int paging result. Only the ones with > 0 */
	int paging_result;
};

struct lchan_signal_data {
	/* The lchan the signal happened on */
	struct gsm_lchan *lchan;
	/* Measurement reports on this lchan */
	struct gsm_meas_rep *mr;
};

/* MSC signals */
enum signal_msc {
	S_MSC_LOST,
	S_MSC_CONNECTED,
	S_MSC_AUTHENTICATED,
};

struct bsc_msc_data;
struct msc_signal_data {
	struct bsc_msc_data *data;
};

/* SS_CCCH signals */
enum signal_ccch {
	S_CCCH_PAGING_LOAD,
	S_CCCH_RACH_LOAD,
};

struct ccch_signal_data {
	struct gsm_bts *bts;
	uint16_t pg_buf_space;
	uint16_t rach_slot_count;
	uint16_t rach_busy_count;
	uint16_t rach_access_count;
};

/* GPRS SGSN signals SS_SGSN */
enum signal_sgsn {
	S_SGSN_ATTACH,
	S_SGSN_DETACH,
	S_SGSN_UPDATE,
	S_SGSN_PDP_ACT,
	S_SGSN_PDP_DEACT,
	S_SGSN_PDP_TERMINATE,
	S_SGSN_PDP_FREE,
	S_SGSN_MM_FREE,
};

struct sgsn_mm_ctx;
struct sgsn_signal_data {
	struct sgsn_mm_ctx *mm;
	struct sgsn_pdp_ctx *pdp;	/* non-NULL for PDP_ACT, PDP_DEACT, PDP_FREE */
};

#endif
