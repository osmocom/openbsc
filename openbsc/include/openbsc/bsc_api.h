/* GSM 08.08 like API for OpenBSC */

#ifndef OPENBSC_BSC_API_H
#define OPENBSC_BSC_API_H

#include "gsm_data.h"

#define BSC_API_CONN_POL_ACCEPT	0
#define BSC_API_CONN_POL_REJECT	1

struct bsc_api {
	void (*sapi_n_reject)(struct gsm_subscriber_connection *conn, int dlci);
	void (*cipher_mode_compl)(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint8_t chosen_encr);
	int (*compl_l3)(struct gsm_subscriber_connection *conn,
			struct msgb *msg, uint16_t chosen_channel); 
	void (*dtap)(struct gsm_subscriber_connection *conn, uint8_t link_id,
			struct msgb *msg);
	void (*assign_compl)(struct gsm_subscriber_connection *conn,
			  uint8_t rr_cause, uint8_t chosen_channel,
			  uint8_t encr_alg_id, uint8_t speech_mode);
	void (*assign_fail)(struct gsm_subscriber_connection *conn,
			 uint8_t cause, uint8_t *rr_cause);
	int (*clear_request)(struct gsm_subscriber_connection *conn,
			      uint32_t cause);
};

int bsc_api_init(struct gsm_network *network, struct bsc_api *api);
int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg, int link_id);
int gsm0808_assign_req(struct gsm_subscriber_connection *conn, int chan_type, int audio);
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			uint8_t *key, int len);
int gsm0808_page(struct gsm_bts *bts, unsigned int page_group,
		 unsigned int mi_len, uint8_t *mi, int chan_type);
int gsm0808_clear(struct gsm_subscriber_connection *conn);

#endif
