/* GSM Network Management messages on the A-bis interface 
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#ifndef _NM_H
#define _NM_H

#include <sys/types.h>
#include <osmocore/tlv.h>
#include <osmocore/protocol/gsm_12_21.h>

struct cell_global_id {
	u_int16_t mcc;
	u_int16_t mnc;
	u_int16_t lac;
	u_int16_t ci;
};

/* The BCCH info from an ip.access test, in host byte order
 * and already parsed... */
struct ipac_bcch_info {
	struct llist_head list;

	u_int16_t info_type;
	u_int8_t freq_qual;
	u_int16_t arfcn;
	u_int8_t rx_lev;
	u_int8_t rx_qual;
	int16_t freq_err;
	u_int16_t frame_offset;
	u_int32_t frame_nr_offset;
	u_int8_t bsic;
	struct cell_global_id cgi;
	u_int8_t ba_list_si2[16];
	u_int8_t ba_list_si2bis[16];
	u_int8_t ba_list_si2ter[16];
	u_int8_t ca_list_si1[16];
};

extern const struct tlv_definition nm_att_tlvdef;

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

int abis_nm_tlv_parse(struct tlv_parsed *tp, struct gsm_bts *bts, const u_int8_t *buf, int len);
int abis_nm_rx(struct msgb *msg);
int abis_nm_opstart(struct gsm_bts *bts, u_int8_t obj_class, u_int8_t i0, u_int8_t i1, u_int8_t i2);
int abis_nm_chg_adm_state(struct gsm_bts *bts, u_int8_t obj_class, u_int8_t i0,
			  u_int8_t i1, u_int8_t i2, enum abis_nm_adm_state adm_state);
int abis_nm_establish_tei(struct gsm_bts *bts, u_int8_t trx_nr,
			  u_int8_t e1_port, u_int8_t e1_timeslot, u_int8_t e1_subslot,
			  u_int8_t tei);
int abis_nm_conn_terr_sign(struct gsm_bts_trx *trx,
			   u_int8_t e1_port, u_int8_t e1_timeslot, u_int8_t e1_subslot);
int abis_nm_conn_terr_traf(struct gsm_bts_trx_ts *ts,
			   u_int8_t e1_port, u_int8_t e1_timeslot,
			   u_int8_t e1_subslot);
int abis_nm_set_bts_attr(struct gsm_bts *bts, u_int8_t *attr, int attr_len);
int abis_nm_set_radio_attr(struct gsm_bts_trx *trx, u_int8_t *attr, int attr_len);
int abis_nm_set_channel_attr(struct gsm_bts_trx_ts *ts, u_int8_t chan_comb);
int abis_nm_sw_act_req_ack(struct gsm_bts *bts, u_int8_t obj_class, u_int8_t i1,
			u_int8_t i2, u_int8_t i3, int nack, u_int8_t *attr, int att_len);
int abis_nm_raw_msg(struct gsm_bts *bts, int len, u_int8_t *msg);
int abis_nm_event_reports(struct gsm_bts *bts, int on);
int abis_nm_reset_resource(struct gsm_bts *bts);
int abis_nm_software_load(struct gsm_bts *bts, int trx_nr, const char *fname,
			  u_int8_t win_size, int forced,
			  gsm_cbfn *cbfn, void *cb_data);
int abis_nm_software_load_status(struct gsm_bts *bts);
int abis_nm_software_activate(struct gsm_bts *bts, const char *fname,
			      gsm_cbfn *cbfn, void *cb_data);

int abis_nm_conn_mdrop_link(struct gsm_bts *bts, u_int8_t e1_port0, u_int8_t ts0,
			    u_int8_t e1_port1, u_int8_t ts1);

int abis_nm_perform_test(struct gsm_bts *bts, u_int8_t obj_class,
			 u_int8_t bts_nr, u_int8_t trx_nr, u_int8_t ts_nr,
			 u_int8_t test_nr, u_int8_t auton_report,
			 u_int8_t *phys_config, u_int16_t phys_config_len);

int abis_nm_chcomb4pchan(enum gsm_phys_chan_config pchan);

/* Siemens / BS-11 specific */
int abis_nm_bs11_reset_resource(struct gsm_bts *bts);
int abis_nm_bs11_db_transmission(struct gsm_bts *bts, int begin);
int abis_nm_bs11_create_object(struct gsm_bts *bts, enum abis_bs11_objtype type,
			  u_int8_t idx, u_int8_t attr_len, const u_int8_t *attr);
int abis_nm_bs11_create_envaBTSE(struct gsm_bts *bts, u_int8_t idx);
int abis_nm_bs11_create_bport(struct gsm_bts *bts, u_int8_t idx);
int abis_nm_bs11_delete_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, u_int8_t idx);
int abis_nm_bs11_delete_bport(struct gsm_bts *bts, u_int8_t idx);
int abis_nm_bs11_conn_oml_tei(struct gsm_bts *bts, u_int8_t e1_port,
			  u_int8_t e1_timeslot, u_int8_t e1_subslot, u_int8_t tei);
int abis_nm_bs11_get_oml_tei_ts(struct gsm_bts *bts);
int abis_nm_bs11_get_serno(struct gsm_bts *bts);
int abis_nm_bs11_set_trx_power(struct gsm_bts_trx *trx, u_int8_t level);
int abis_nm_bs11_get_trx_power(struct gsm_bts_trx *trx);
int abis_nm_bs11_logon(struct gsm_bts *bts, u_int8_t level, const char *name, int on);
int abis_nm_bs11_factory_logon(struct gsm_bts *bts, int on);
int abis_nm_bs11_infield_logon(struct gsm_bts *bts, int on);
int abis_nm_bs11_set_trx1_pw(struct gsm_bts *bts, const char *password);
int abis_nm_bs11_set_pll_locked(struct gsm_bts *bts, int locked);
int abis_nm_bs11_get_pll_mode(struct gsm_bts *bts);
int abis_nm_bs11_set_pll(struct gsm_bts *bts, int value);
int abis_nm_bs11_get_cclk(struct gsm_bts *bts);
int abis_nm_bs11_get_state(struct gsm_bts *bts);
int abis_nm_bs11_load_swl(struct gsm_bts *bts, const char *fname,
			  u_int8_t win_size, int forced, gsm_cbfn *cbfn);
int abis_nm_bs11_set_ext_time(struct gsm_bts *bts);
int abis_nm_bs11_set_bport_line_cfg(struct gsm_bts *bts, u_int8_t bport, enum abis_bs11_line_cfg line_cfg);
int abis_nm_bs11_bsc_disconnect(struct gsm_bts *bts, int reconnect);
int abis_nm_bs11_restart(struct gsm_bts *bts);

/* ip.access nanoBTS specific commands */
int abis_nm_ipaccess_msg(struct gsm_bts *bts, u_int8_t msg_type,
			 u_int8_t obj_class, u_int8_t bts_nr,
			 u_int8_t trx_nr, u_int8_t ts_nr,
			 u_int8_t *attr, int attr_len);
int abis_nm_ipaccess_set_nvattr(struct gsm_bts_trx *trx, u_int8_t *attr,
				int attr_len);
int abis_nm_ipaccess_restart(struct gsm_bts_trx *trx);
int abis_nm_ipaccess_set_attr(struct gsm_bts *bts, u_int8_t obj_class,
				u_int8_t bts_nr, u_int8_t trx_nr, u_int8_t ts_nr,
				u_int8_t *attr, u_int8_t attr_len);
int abis_nm_ipaccess_rsl_connect(struct gsm_bts_trx *trx, 
				 u_int32_t ip, u_int16_t port, u_int8_t stream);
void abis_nm_ipaccess_cgi(u_int8_t *buf, struct gsm_bts *bts);
int ipac_parse_bcch_info(struct ipac_bcch_info *binf, u_int8_t *buf);
const char *ipacc_testres_name(u_int8_t res);

/* Functions calling into other code parts */
enum nm_evt {
	EVT_STATECHG_OPER,
	EVT_STATECHG_ADM,
};
int nm_state_event(enum nm_evt evt, u_int8_t obj_class, void *obj,
		   struct gsm_nm_state *old_state, struct gsm_nm_state *new_state,
		   struct abis_om_obj_inst *obj_inst);

const char *nm_opstate_name(u_int8_t os);
const char *nm_avail_name(u_int8_t avail);
int nm_is_running(struct gsm_nm_state *s);
#endif /* _NM_H */
