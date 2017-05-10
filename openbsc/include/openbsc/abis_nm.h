/* GSM Network Management messages on the A-bis interface 
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#ifndef _NM_H
#define _NM_H

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <openbsc/gsm_data.h>

/* max number of attributes represented as 3GPP TS 52.021 §9.4.62 SW Description array */
#define MAX_BTS_ATTR 5

struct cell_global_id {
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	uint16_t ci;
};

/* The BCCH info from an ip.access test, in host byte order
 * and already parsed... */
struct ipac_bcch_info {
	struct llist_head list;

	uint16_t info_type;
	uint8_t freq_qual;
	uint16_t arfcn;
	uint8_t rx_lev;
	uint8_t rx_qual;
	int16_t freq_err;
	uint16_t frame_offset;
	uint32_t frame_nr_offset;
	uint8_t bsic;
	struct cell_global_id cgi;
	uint8_t ba_list_si2[16];
	uint8_t ba_list_si2bis[16];
	uint8_t ba_list_si2ter[16];
	uint8_t ca_list_si1[16];
};

/* PUBLIC */

struct msgb;

struct abis_nm_cfg {
	/* callback for unidirectional reports */
	int (*report_cb)(struct msgb *,
			 struct abis_om_fom_hdr *);
	/* callback for software activate requests from BTS */
	int (*sw_act_req)(struct msgb *);
};

extern int abis_nm_rcvmsg(struct msgb *msg);

int abis_nm_tlv_parse(struct tlv_parsed *tp, struct gsm_bts *bts, const uint8_t *buf, int len);
int abis_nm_rx(struct msgb *msg);
int abis_nm_opstart(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0, uint8_t i1, uint8_t i2);
int abis_nm_chg_adm_state(struct gsm_bts *bts, uint8_t obj_class, uint8_t i0,
			  uint8_t i1, uint8_t i2, enum abis_nm_adm_state adm_state);
int abis_nm_establish_tei(struct gsm_bts *bts, uint8_t trx_nr,
			  uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot,
			  uint8_t tei);
int abis_nm_conn_terr_sign(struct gsm_bts_trx *trx,
			   uint8_t e1_port, uint8_t e1_timeslot, uint8_t e1_subslot);
int abis_nm_conn_terr_traf(struct gsm_bts_trx_ts *ts,
			   uint8_t e1_port, uint8_t e1_timeslot,
			   uint8_t e1_subslot);
int abis_nm_get_attr(struct gsm_bts *bts, uint8_t obj_class,
		     uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
		     const uint8_t *attr, uint8_t attr_len);
int abis_nm_set_bts_attr(struct gsm_bts *bts, uint8_t *attr, int attr_len);
int abis_nm_set_radio_attr(struct gsm_bts_trx *trx, uint8_t *attr, int attr_len);
int abis_nm_set_channel_attr(struct gsm_bts_trx_ts *ts, uint8_t chan_comb);
int abis_nm_sw_act_req_ack(struct gsm_bts *bts, uint8_t obj_class, uint8_t i1,
			uint8_t i2, uint8_t i3, int nack, uint8_t *attr, int att_len);
int abis_nm_raw_msg(struct gsm_bts *bts, int len, uint8_t *msg);
int abis_nm_event_reports(struct gsm_bts *bts, int on);
int abis_nm_reset_resource(struct gsm_bts *bts);
int abis_nm_software_load(struct gsm_bts *bts, int trx_nr, const char *fname,
			  uint8_t win_size, int forced,
			  gsm_cbfn *cbfn, void *cb_data);
int abis_nm_software_load_status(struct gsm_bts *bts);
int abis_nm_software_activate(struct gsm_bts *bts, const char *fname,
			      gsm_cbfn *cbfn, void *cb_data);

int abis_nm_conn_mdrop_link(struct gsm_bts *bts, uint8_t e1_port0, uint8_t ts0,
			    uint8_t e1_port1, uint8_t ts1);

int abis_nm_perform_test(struct gsm_bts *bts, uint8_t obj_class,
			 uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t test_nr, uint8_t auton_report, struct msgb *msg);

/* Siemens / BS-11 specific */
int abis_nm_bs11_reset_resource(struct gsm_bts *bts);
int abis_nm_bs11_db_transmission(struct gsm_bts *bts, int begin);
int abis_nm_bs11_create_object(struct gsm_bts *bts, enum abis_bs11_objtype type,
			  uint8_t idx, uint8_t attr_len, const uint8_t *attr);
int abis_nm_bs11_create_envaBTSE(struct gsm_bts *bts, uint8_t idx);
int abis_nm_bs11_create_bport(struct gsm_bts *bts, uint8_t idx);
int abis_nm_bs11_delete_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, uint8_t idx);
int abis_nm_bs11_delete_bport(struct gsm_bts *bts, uint8_t idx);
int abis_nm_bs11_conn_oml_tei(struct gsm_bts *bts, uint8_t e1_port,
			  uint8_t e1_timeslot, uint8_t e1_subslot, uint8_t tei);
int abis_nm_bs11_get_oml_tei_ts(struct gsm_bts *bts);
int abis_nm_bs11_get_serno(struct gsm_bts *bts);
int abis_nm_bs11_set_trx_power(struct gsm_bts_trx *trx, uint8_t level);
int abis_nm_bs11_get_trx_power(struct gsm_bts_trx *trx);
int abis_nm_bs11_logon(struct gsm_bts *bts, uint8_t level, const char *name, int on);
int abis_nm_bs11_factory_logon(struct gsm_bts *bts, int on);
int abis_nm_bs11_infield_logon(struct gsm_bts *bts, int on);
int abis_nm_bs11_set_trx1_pw(struct gsm_bts *bts, const char *password);
int abis_nm_bs11_set_pll_locked(struct gsm_bts *bts, int locked);
int abis_nm_bs11_get_pll_mode(struct gsm_bts *bts);
int abis_nm_bs11_set_pll(struct gsm_bts *bts, int value);
int abis_nm_bs11_get_cclk(struct gsm_bts *bts);
int abis_nm_bs11_get_state(struct gsm_bts *bts);
int abis_nm_bs11_load_swl(struct gsm_bts *bts, const char *fname,
			  uint8_t win_size, int forced, gsm_cbfn *cbfn);
int abis_nm_bs11_set_ext_time(struct gsm_bts *bts);
int abis_nm_bs11_get_bport_line_cfg(struct gsm_bts *bts, uint8_t bport);
int abis_nm_bs11_set_bport_line_cfg(struct gsm_bts *bts, uint8_t bport, enum abis_bs11_line_cfg line_cfg);
int abis_nm_bs11_bsc_disconnect(struct gsm_bts *bts, int reconnect);
int abis_nm_bs11_restart(struct gsm_bts *bts);

/* ip.access nanoBTS specific commands */
int abis_nm_ipaccess_msg(struct gsm_bts *bts, uint8_t msg_type,
			 uint8_t obj_class, uint8_t bts_nr,
			 uint8_t trx_nr, uint8_t ts_nr,
			 uint8_t *attr, int attr_len);
int abis_nm_ipaccess_set_nvattr(struct gsm_bts_trx *trx, uint8_t *attr,
				int attr_len);
int abis_nm_ipaccess_restart(struct gsm_bts_trx *trx);
int abis_nm_ipaccess_set_attr(struct gsm_bts *bts, uint8_t obj_class,
				uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr,
				uint8_t *attr, uint8_t attr_len);
int abis_nm_ipaccess_rsl_connect(struct gsm_bts_trx *trx, 
				 uint32_t ip, uint16_t port, uint8_t stream);
void abis_nm_ipaccess_cgi(uint8_t *buf, struct gsm_bts *bts);
int ipac_parse_bcch_info(struct ipac_bcch_info *binf, uint8_t *buf);
const char *ipacc_testres_name(uint8_t res);

/* Functions calling into other code parts */
int nm_is_running(struct gsm_nm_state *s);

int abis_nm_vty_init(void);

void abis_nm_clear_queue(struct gsm_bts *bts);

int _abis_nm_sendmsg(struct msgb *msg);

void abis_nm_queue_send_next(struct gsm_bts *bts);	/* for bs11_config. */

int abis_nm_select_newest_sw(const struct abis_nm_sw_desc *sw, const size_t len);

/* Helper functions for updating attributes */
int abis_nm_update_max_power_red(struct gsm_bts_trx *trx);

#endif /* _NM_H */
