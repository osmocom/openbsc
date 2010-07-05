#ifndef _GSM_04_08_H
#define _GSM_04_08_H

#include <openbsc/meas_rep.h>

#include <osmocore/protocol/gsm_04_08.h>
#include <osmocore/gsm48.h>

struct msgb;
struct gsm_bts;
struct gsm_subscriber;
struct gsm_network;
struct gsm_trans;
struct gsm_subscriber_connection;

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

static inline struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM,
				   "GSM 04.08");
}

/* config options controlling the behaviour of the lower leves */
void gsm0408_allow_everyone(int allow);
void gsm0408_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);
int gsm0408_dispatch(struct gsm_subscriber_connection *conn, struct msgb *msg);

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id);
int gsm0408_new_conn(struct gsm_subscriber_connection *conn);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);
enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);

int gsm48_tx_mm_info(struct gsm_subscriber_connection *conn);
int gsm48_tx_mm_auth_req(struct gsm_subscriber_connection *conn, u_int8_t *rand, int key_seq);
int gsm48_tx_mm_auth_rej(struct gsm_subscriber_connection *conn);
int gsm48_send_rr_release(struct gsm_lchan *lchan);
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv);
int gsm48_send_rr_app_info(struct gsm_subscriber_connection *conn, u_int8_t apdu_id,
			   u_int8_t apdu_len, const u_int8_t *apdu);
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, u_int8_t power_class);
int gsm48_send_ho_cmd(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan,
		      u_int8_t power_command, u_int8_t ho_ref);

int bsc_upqueue(struct gsm_network *net);

int mncc_send(struct gsm_network *net, int msg_type, void *arg);

/* convert a ASCII phone number to call-control BCD */
int encode_bcd_number(u_int8_t *bcd_lv, u_int8_t max_len,
		      int h_len, const char *input);
int decode_bcd_number(char *output, int output_len, const u_int8_t *bcd_lv,
		      int h_len);

int send_siemens_mrpci(struct gsm_lchan *lchan, u_int8_t *classmark2_lv);
int gsm48_extract_mi(uint8_t *classmark2, int length, char *mi_string, uint8_t *mi_type);
int gsm48_paging_extract_mi(struct gsm48_pag_resp *pag, int length, char *mi_string, u_int8_t *mi_type);
int gsm48_handle_paging_resp(struct gsm_subscriber_connection *conn, struct msgb *msg, struct gsm_subscriber *subscr);

int gsm48_lchan_modify(struct gsm_lchan *lchan, u_int8_t lchan_mode);
int gsm48_rx_rr_modif_ack(struct msgb *msg);
int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg);

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value);
struct msgb *gsm48_create_loc_upd_rej(uint8_t cause);
void gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			   const struct gsm_lchan *lchan);

#endif
