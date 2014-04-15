#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

struct gsm_network;
struct gsm_sms_queue;
struct vty;
struct ctrl_cmd;

int sms_queue_start(struct gsm_network *, int in_flight);
int sms_queue_trigger(struct gsm_sms_queue *);

/* Ctrl interface helper function */
int sms_queue_pending_stat(struct gsm_network *net, struct ctrl_cmd *cmd);
int sms_queue_get_max_failure(struct gsm_sms_queue *smsq);

/* vty helper functions */
int sms_queue_stats(struct gsm_sms_queue *, struct vty* vty);
int sms_queue_set_max_pending(struct gsm_sms_queue *, int max);
int sms_queue_set_max_failure(struct gsm_sms_queue *, int fail);
int sms_queue_clear(struct gsm_sms_queue *);

#endif
