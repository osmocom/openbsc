#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

struct gsm_network;

int sms_queue_start(struct gsm_network *, int in_flight);

#endif
