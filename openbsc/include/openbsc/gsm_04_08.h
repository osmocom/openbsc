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

/* config options controlling the behaviour of the lower leves */
void gsm0408_allow_everyone(int allow);

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id);
void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
		u_int16_t mnc, u_int16_t lac);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);
enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci);

int gsm48_tx_mm_info(struct gsm_lchan *lchan);
int gsm48_tx_mm_auth_req(struct gsm_lchan *lchan, u_int8_t *rand, int key_seq);
int gsm48_tx_mm_auth_rej(struct gsm_lchan *lchan);
struct msgb *gsm48_msgb_alloc(void);
int gsm48_sendmsg(struct msgb *msg, struct gsm_trans *trans);
int gsm48_generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi);
int gsm48_generate_mid_from_imsi(u_int8_t *buf, const char* imsi);
int gsm48_mi_to_string(char *string, const int str_len, const u_int8_t *mi, const int mi_len);

int gsm48_send_rr_release(struct gsm_lchan *lchan);
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv);
int gsm48_send_rr_app_info(struct gsm_lchan *lchan, u_int8_t apdu_id,
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

extern const char *gsm0408_cc_msg_names[];

int send_siemens_mrpci(struct gsm_lchan *lchan, u_int8_t *classmark2_lv);
int gsm48_paging_extract_mi(struct msgb *msg, char *mi_string, u_int8_t *mi_type);
int gsm48_handle_paging_resp(struct msgb *msg, struct gsm_subscriber *subscr);

int gsm48_lchan_modify(struct gsm_lchan *lchan, u_int8_t lchan_mode);
int gsm48_rx_rr_modif_ack(struct msgb *msg);
int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg);


#endif
