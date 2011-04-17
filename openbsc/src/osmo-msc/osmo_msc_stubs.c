/* Stubs to make it compile */

/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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

#include <osmocom/gsm/tlv.h>

#include <openbsc/gsm_data.h>

#include <stdlib.h>

/* For talloc_context */
void *tall_fle_ctx;
void *tall_paging_ctx;
void *tall_tqe_ctx;
void *tall_map_ctx;
void *tall_upq_ctx;

/* For gsm_bts_model_register */
const struct tlv_definition nm_att_tlvdef = {};


/* BSC API */
int bsc_api_init(struct gsm_network *network, struct bsc_api *api)
{
	abort();
}

int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			struct msgb *msg, int link_id, int allow_sach)
{
	abort();
}

int gsm0808_assign_req(struct gsm_subscriber_connection *conn,
		       int chan_mode, int full_rate)
{
	abort();
}

int gsm0808_clear(struct gsm_subscriber_connection *conn)
{
	abort();
}

int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn,
		        int cipher, const uint8_t *key, int len,
			int include_imeisv)
{
	abort();
}

int gsm0808_page(struct gsm_bts *bts, unsigned int page_group,
		 unsigned int mi_len, uint8_t *mi, int chan_type)
{
	abort();
}

/* paging handling */
int paging_request(struct gsm_network *network, struct gsm_subscriber *subscr,
		   int type, gsm_cbfn *cbfn, void *data)
{
	abort();
}

int paging_request_stop(struct gsm_bts *bts, struct gsm_subscriber *subscr,
			struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	abort();
}

/* subscriber con handling */
struct gsm_subscriber_connection *connection_for_subscr(struct gsm_subscriber *subscr)
{
	abort();
}

void subscr_con_free(struct gsm_subscriber_connection *conn)
{
	abort();
}


/* misc stubs */
int ipacc_rtp_direct = 0;

void bsc_bootstrap_network() { abort(); }
void bsc_shutdown_net() { abort(); }
void bsc_vty_init() { abort(); }
struct msgb *gsm48_create_loc_upd_rej(uint8_t cause) { abort(); }
struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value val) { abort(); }
int gsm48_handle_paging_resp(struct gsm_subscriber_connection *conn, struct msgb *msg, struct gsm_subscriber *subscr) { abort();}
int gsm48_paging_extract_mi(struct gsm48_pag_resp *pag, int length, char *mi_string, u_int8_t *mi_type) { abort(); }
int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg) { abort(); }
void gsm_net_update_ctype(struct gsm_network *net) { abort(); }
void on_dso_load_ho_dec() { abort(); }
void rsl_ipacc_mdcx() { abort(); }
void rsl_ipacc_mdcx_to_rtpsock() { abort(); }
void rtp_send_frame() { abort(); }
void rtp_socket_connect() { abort(); }
void rtp_socket_create() { abort(); }
void rtp_socket_free() { abort(); }
void rtp_socket_proxy() { abort(); }
void rtp_socket_upstream() { abort(); }
int send_siemens_mrpci(struct gsm_lchan *lchan, u_int8_t *classmark2_lv) { abort(); }
void trau_mux_map_lchan() { abort(); }
void trau_mux_unmap() { abort(); }
void trau_recv_lchan() { abort(); }
void trau_send_frame() { abort(); }


