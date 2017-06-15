/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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

#ifndef _RSL_H
#define _RSL_H

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/core/msgb.h>

struct gsm_bts;
struct gsm_lchan;
struct gsm_subscriber;
struct gsm_bts_trx_ts;

#define GSM48_LEN2PLEN(a)	(((a) << 2) | 1)

int rsl_bcch_info(const struct gsm_bts_trx *trx, enum osmo_sysinfo_type si_type, const uint8_t *data, int len);
int rsl_sacch_filling(struct gsm_bts_trx *trx, uint8_t type,
		      const uint8_t *data, int len);
int rsl_chan_activate(struct gsm_bts_trx *trx, uint8_t chan_nr,
		      uint8_t act_type,
		      struct rsl_ie_chan_mode *chan_mode,
		      struct rsl_ie_chan_ident *chan_ident,
		      uint8_t bs_power, uint8_t ms_power,
		      uint8_t ta);
int rsl_chan_activate_lchan(struct gsm_lchan *lchan, uint8_t act_type,
			    uint8_t ho_ref);
int rsl_chan_mode_modify_req(struct gsm_lchan *ts);
int rsl_encryption_cmd(struct msgb *msg);
int rsl_paging_cmd(struct gsm_bts *bts, uint8_t paging_group, uint8_t len,
		   uint8_t *ms_ident, uint8_t chan_needed, bool is_gprs);
int rsl_imm_assign_cmd(struct gsm_bts *bts, uint8_t len, uint8_t *val);

int rsl_data_request(struct msgb *msg, uint8_t link_id);
int rsl_establish_request(struct gsm_lchan *lchan, uint8_t link_id);
int rsl_relase_request(struct gsm_lchan *lchan, uint8_t link_id);

/* Ericcson vendor specific RSL extensions */
int rsl_ericsson_imm_assign_cmd(struct gsm_bts *bts, uint32_t tlli, uint8_t len, uint8_t *val);

/* Siemens vendor-specific RSL extensions */
int rsl_siemens_mrpci(struct gsm_lchan *lchan, struct rsl_mrpci *mrpci);

/* ip.access specfic RSL extensions */
int rsl_ipacc_crcx(struct gsm_lchan *lchan);
int rsl_ipacc_mdcx(struct gsm_lchan *lchan, uint32_t ip,
		   uint16_t port, uint8_t rtp_payload2);
int rsl_ipacc_mdcx_to_rtpsock(struct gsm_lchan *lchan);
int rsl_ipacc_pdch_activate(struct gsm_bts_trx_ts *ts, int act);

int abis_rsl_rcvmsg(struct msgb *msg);

uint64_t str_to_imsi(const char *imsi_str);
int rsl_release_request(struct gsm_lchan *lchan, uint8_t link_id,
			enum rsl_rel_mode release_mode);

int rsl_lchan_set_state(struct gsm_lchan *lchan, int);
int rsl_lchan_mark_broken(struct gsm_lchan *lchan, const char *broken);

/* to be provided by external code */
int rsl_deact_sacch(struct gsm_lchan *lchan);

/* BCCH related code */
int rsl_ccch_conf_to_bs_cc_chans(int ccch_conf);
int rsl_ccch_conf_to_bs_ccch_sdcch_comb(int ccch_conf);

int rsl_sacch_info_modify(struct gsm_lchan *lchan, uint8_t type,
			  const uint8_t *data, int len);

int rsl_chan_bs_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int db);
int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int dbm);

/* SMSCB functionality */
int rsl_sms_cb_command(struct gsm_bts *bts, uint8_t chan_number,
		       struct rsl_ie_cb_cmd_type cb_command,
		       const uint8_t *data, int len);

/* some Nokia specific stuff */
int rsl_nokia_si_begin(struct gsm_bts_trx *trx);
int rsl_nokia_si_end(struct gsm_bts_trx *trx);

/* required for Nokia BTS power control */
int rsl_bs_power_control(struct gsm_bts_trx *trx, uint8_t channel, uint8_t reduction);


int rsl_release_sapis_from(struct gsm_lchan *lchan, int start,
				enum rsl_rel_mode release_mode);
int rsl_start_t3109(struct gsm_lchan *lchan);

int rsl_direct_rf_release(struct gsm_lchan *lchan);

void dyn_ts_init(struct gsm_bts_trx_ts *ts);
int dyn_ts_switchover_start(struct gsm_bts_trx_ts *ts,
			    enum gsm_phys_chan_config to_pchan);

#endif /* RSL_MT_H */

