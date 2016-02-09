#ifndef _GSM_USSD_MAP_PROTO_H
#define _GSM_USSD_MAP_PROTO_H

#include <osmocom/gsm/gsm0480.h>


enum {
    FMAP_MSISDN        = 0x80
};

int subscr_uss_message(struct msgb *msg,
		       struct ss_header *req,
		       const char* extension,
		       uint32_t ref,
		       const uint8_t *component_data);

int rx_uss_message_parse(const uint8_t* data,
			 size_t len,
			 struct ss_header *ss,
			 uint32_t *ref,
			 char* extention,
			 size_t extention_len);


#endif /* _GSM_USSD_MAP_PROTO_H */
