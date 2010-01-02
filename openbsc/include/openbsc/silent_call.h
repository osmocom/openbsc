#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

extern int gsm_silent_call_start(struct gsm_subscriber *subscr,
                                 void *data, int type);
extern int gsm_silent_call_stop(struct gsm_subscriber *subscr);
extern int silent_call_rx(struct msgb *msg);
extern int silent_call_reroute(struct msgb *msg);

#endif /* _SILENT_CALL_H */
