/* From GSM08.08 */

#ifndef BSSAP_H
#define BSSAP_H

#include <stdlib.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <openbsc/gsm_data.h>


int bssmap_rcvmsg_dt1(struct sccp_connection *conn, struct msgb *msg, unsigned int length);
int bssmap_rcvmsg_udt(struct gsm_network *net, struct msgb *msg, unsigned int length);

struct msgb *bssmap_create_layer3(struct msgb *msg);
struct msgb *bssmap_create_reset(void);
struct msgb *bssmap_create_clear_complete(void);
struct msgb *bssmap_create_cipher_complete(struct msgb *layer3);
struct msgb *bssmap_create_cipher_reject(u_int8_t cause);
struct msgb *bssmap_create_sapi_reject(u_int8_t link_id);
struct msgb *bssmap_create_assignment_completed(struct gsm_lchan *lchan, u_int8_t rr_cause);
struct msgb *bssmap_create_assignment_failure(u_int8_t cause, u_int8_t *rr_cause);
struct msgb *bssmap_create_classmark_update(const u_int8_t *classmark, u_int8_t length);

void gsm0808_send_assignment_failure(struct gsm_lchan *l, u_int8_t cause, u_int8_t *rr_value);
void gsm0808_send_assignment_compl(struct gsm_lchan *l, u_int8_t rr_value);

int dtap_rcvmsg(struct gsm_lchan *lchan, struct msgb *msg, unsigned int length);
struct msgb *dtap_create_msg(struct msgb *msg_l3, u_int8_t link_id);

void bsc_queue_connection_write(struct sccp_connection *conn, struct msgb *msg);
void bsc_free_queued(struct sccp_connection *conn);
void bsc_send_queued(struct sccp_connection *conn);

void bts_send_queued(struct bss_sccp_connection_data*);
void bts_free_queued(struct bss_sccp_connection_data*);
void bts_unblock_queue(struct bss_sccp_connection_data*);

#endif
