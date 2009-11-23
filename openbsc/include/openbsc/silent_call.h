#ifndef _SILENT_CALL_H
#define _SILENT_CALL_H

extern int gsm_silent_call_start(struct gsm_subscriber *subscr, void *data);
extern int gsm_silent_call_stop(struct gsm_subscriber *subscr);

#endif /* _SILENT_CALL_H */
