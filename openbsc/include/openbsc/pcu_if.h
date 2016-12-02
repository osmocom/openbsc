#ifndef _PCU_IF_H
#define _PCU_IF_H

#define PCU_SOCK_DEFAULT	"/tmp/pcu_bts"

#include <osmocom/gsm/l1sap.h>

extern int pcu_direct;

struct pcu_sock_state {
	struct gsm_network *net;
	struct osmo_fd listen_bfd;	/* fd for listen socket */
	struct osmo_fd conn_bfd;	/* fd for connection to lcr */
	struct llist_head upqueue;	/* queue for sending messages */
};

/* PCU relevant information has changed; Inform PCU (if connected) */
void pcu_info_update(struct gsm_bts *bts);

/* Forward rach indication to PCU */
int pcu_tx_rach_ind(struct gsm_bts *bts, int16_t qta, uint16_t ra, uint32_t fn,
	uint8_t is_11bit, enum ph_burst_type burst_type);

/* Forward timing intformation (frame number) to PCU */
int pcu_tx_time_ind(struct gsm_bts *bts, uint32_t fn);

int pcu_tx_data_ind(struct gsm_bts *bts, struct gsm_bts_trx_ts *ts, uint8_t is_ptcch, uint32_t fn,
	uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len,
		    int8_t rssi, uint16_t ber10k, int16_t bto, int16_t lqual);

int pcu_tx_pag_req(struct gsm_bts *bts, const uint8_t *identity_lv, uint8_t chan_needed);
int pcu_tx_pch_data_cnf(struct gsm_bts *bts, uint32_t fn, uint8_t *data, uint8_t len);


/* Confirm the sending of an immediate assignment to the pcu */
int pcu_tx_imm_ass_sent(struct gsm_bts *bts, uint32_t tlli);

/* Open connection to PCU */
int pcu_sock_init(const char *path, struct gsm_bts *bts);

/* Close connection to PCU */
void pcu_sock_exit(struct gsm_bts *bts);

#endif /* _PCU_IF_H */
