#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

struct gsm_subscriber_connection;

extern int gsm_silent_call_start(struct gsm_subscriber *subscr,
                                 void *data, int type);
extern int gsm_silent_call_stop(struct gsm_subscriber *subscr);
extern int silent_call_rx(struct gsm_subscriber_connection *conn, struct msgb *msg);
extern int silent_call_reroute(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif /* _SILENT_CALL_H */
