#ifndef _HANDOVER_H
#define _HANDOVER_H

struct gsm_subscriber_connection;

int bsc_handover_start(struct gsm_lchan *old_lchan, struct gsm_bts *bts);

/* clear any operation for this connection */
void bsc_clear_handover(struct gsm_subscriber_connection *conn, int free_lchan);

/* Return the old lchan or NULL. This is meant for audio handling */
struct gsm_lchan *bsc_handover_pending(struct gsm_lchan *new_lchan);

#endif /* _HANDOVER_H */
