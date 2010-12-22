/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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

#ifndef _RSL_H
#define _RSL_H

#include <osmocore/protocol/gsm_08_58.h>

#include <osmocore/msgb.h>

struct gsm_bts;
struct gsm_lchan;
struct gsm_subscriber;


int rsl_bcch_info(struct gsm_bts_trx *trx, u_int8_t type,
		  const u_int8_t *data, int len);
int rsl_sacch_filling(struct gsm_bts_trx *trx, u_int8_t type, 
		      const u_int8_t *data, int len);
int rsl_chan_activate(struct gsm_bts_trx *trx, u_int8_t chan_nr,
		      u_int8_t act_type,
		      struct rsl_ie_chan_mode *chan_mode,
		      struct rsl_ie_chan_ident *chan_ident,
		      u_int8_t bs_power, u_int8_t ms_power,
		      u_int8_t ta);
int rsl_chan_activate_lchan(struct gsm_lchan *lchan, u_int8_t act_type, 
			    u_int8_t ta, u_int8_t ho_ref);
int rsl_chan_mode_modify_req(struct gsm_lchan *ts);
int rsl_encryption_cmd(struct msgb *msg);
int rsl_paging_cmd(struct gsm_bts *bts, u_int8_t paging_group, u_int8_t len,
		   u_int8_t *ms_ident, u_int8_t chan_needed);
int rsl_imm_assign_cmd(struct gsm_bts *bts, u_int8_t len, u_int8_t *val);

int rsl_data_request(struct msgb *msg, u_int8_t link_id);
int rsl_establish_request(struct gsm_lchan *lchan, u_int8_t link_id);
int rsl_relase_request(struct gsm_lchan *lchan, u_int8_t link_id);

/* Siemens vendor-specific RSL extensions */
int rsl_siemens_mrpci(struct gsm_lchan *lchan, struct rsl_mrpci *mrpci);

/* ip.access specfic RSL extensions */
int rsl_ipacc_crcx(struct gsm_lchan *lchan);
int rsl_ipacc_mdcx(struct gsm_lchan *lchan, u_int32_t ip,
		   u_int16_t port, u_int8_t rtp_payload2);
int rsl_ipacc_mdcx_to_rtpsock(struct gsm_lchan *lchan);
int rsl_ipacc_pdch_activate(struct gsm_lchan *lchan, int act);

int abis_rsl_rcvmsg(struct msgb *msg);

unsigned int get_paging_group(u_int64_t imsi, unsigned int bs_cc_chans,
			      int n_pag_blocks);
unsigned int n_pag_blocks(int bs_ccch_sdcch_comb, unsigned int bs_ag_blks_res);
u_int64_t str_to_imsi(const char *imsi_str);
u_int8_t lchan2chan_nr(const struct gsm_lchan *lchan);
int rsl_release_request(struct gsm_lchan *lchan, u_int8_t link_id, u_int8_t reason);

int rsl_lchan_set_state(struct gsm_lchan *lchan, int);

/* to be provided by external code */
int abis_rsl_sendmsg(struct msgb *msg);
int rsl_deact_sacch(struct gsm_lchan *lchan);
int rsl_lchan_rll_release(struct gsm_lchan *lchan, u_int8_t link_id);

/* BCCH related code */
int rsl_ccch_conf_to_bs_cc_chans(int ccch_conf);
int rsl_ccch_conf_to_bs_ccch_sdcch_comb(int ccch_conf);
int rsl_number_of_paging_subchannels(struct gsm_bts *bts);

int rsl_chan_bs_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int db);
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int dbm);

/* SMSCB functionality */
int rsl_sms_cb_command(struct gsm_bts *bts, uint8_t chan_number,
		       uint8_t cb_command, const uint8_t *data, int len);

#endif /* RSL_MT_H */

