#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocore/msgb.h>
#include <osmocore/protocol/gsm_04_80.h>

#define MAX_LEN_USSD_STRING	31

struct ussd_request {
			char text[MAX_LEN_USSD_STRING + 1];
			u_int8_t transaction_id;
			u_int8_t invoke_id;
};

int gsm0480_decode_ussd_request(const struct msgb *msg, 
				struct ussd_request *request); 
int gsm0480_send_ussd_response(const struct msgb *in_msg, const char* response_text, 
						const struct ussd_request *req);
int gsm0480_send_ussd_reject(const struct msgb *msg, 
				const struct ussd_request *request);

#endif
