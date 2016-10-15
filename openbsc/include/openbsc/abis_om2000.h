#ifndef OPENBSC_ABIS_OM2K_H
#define OPENBSC_ABIS_OM2K_H
/* Ericsson RBS 2xxx GSM O&M (OM2000) messages on the A-bis interface
 * implemented based on protocol trace analysis, no formal documentation */

/* (C) 2010-2011 by Harald Welte <laforge@gnumonks.org>
 *
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

enum abis_om2k_mo_cls {
	OM2K_MO_CLS_TRXC			= 0x01,
	OM2K_MO_CLS_TS				= 0x03,
	OM2K_MO_CLS_TF				= 0x04,
	OM2K_MO_CLS_IS				= 0x05,
	OM2K_MO_CLS_CON				= 0x06,
	OM2K_MO_CLS_DP				= 0x07,
	OM2K_MO_CLS_CF				= 0x0a,
	OM2K_MO_CLS_TX				= 0x0b,
	OM2K_MO_CLS_RX				= 0x0c,
};

enum om2k_mo_state {
	OM2K_MO_S_RESET = 0,
	OM2K_MO_S_STARTED,
	OM2K_MO_S_ENABLED,
	OM2K_MO_S_DISABLED,
};

/* on-wire format for IS conn group */
struct om2k_is_conn_grp {
	uint16_t icp1;
	uint16_t icp2;
	uint8_t cont_idx;
} __attribute__ ((packed));

/* internal data formant for IS conn group */
struct is_conn_group {
	struct llist_head list;
	uint16_t icp1;
	uint16_t icp2;
	uint8_t ci;
};

extern const struct abis_om2k_mo om2k_mo_cf;
extern const struct abis_om2k_mo om2k_mo_is;
extern const struct abis_om2k_mo om2k_mo_con;
extern const struct abis_om2k_mo om2k_mo_tf;

extern const struct value_string om2k_mo_class_short_vals[];

int abis_om2k_rcvmsg(struct msgb *msg);

extern const struct abis_om2k_mo om2k_mo_cf;

int abis_om2k_tx_reset_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_start_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_status_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_connect_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_disconnect_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_enable_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_disable_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_test_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_op_info(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
			 uint8_t operational);
int abis_om2k_tx_cap_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo);
int abis_om2k_tx_is_conf_req(struct gsm_bts *bts);
int abis_om2k_tx_tf_conf_req(struct gsm_bts *bts);
int abis_om2k_tx_rx_conf_req(struct gsm_bts_trx *trx);
int abis_om2k_tx_tx_conf_req(struct gsm_bts_trx *trx);
int abis_om2k_tx_ts_conf_req(struct gsm_bts_trx_ts *ts);

struct osmo_fsm_inst *om2k_bts_fsm_start(struct gsm_bts *bts);
void abis_om2k_bts_init(struct gsm_bts *bts);
void abis_om2k_trx_init(struct gsm_bts_trx *trx);

int abis_om2k_vty_init(void);

struct vty;
void abis_om2k_config_write_bts(struct vty *vty, struct gsm_bts *bts);

#endif /* OPENBCS_ABIS_OM2K_H */
