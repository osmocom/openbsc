#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocore/msgb.h>
#include <osmocore/protocol/gsm_04_80.h>
#include <osmocore/gsm0480.h>

int gsm0480_send_ussd_response(const struct msgb *in_msg, const char* response_text, 
						const struct ussd_request *req);
int gsm0480_send_ussd_reject(const struct msgb *msg, 
				const struct ussd_request *request);

int gsm0480_send_ussdNotify(struct gsm_lchan *lchan, int level, const char *text);
int gsm0480_send_releaseComplete(struct gsm_lchan *lchan);

#endif
