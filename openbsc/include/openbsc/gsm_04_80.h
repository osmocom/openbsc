#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocore/msgb.h>
#include <osmocore/protocol/gsm_04_80.h>

/* 29.002 V8.9.0 / 17.7.5 */
enum gsm0902_map_ss_code {
	/* line identification */
	MAP_SS_CODE_CLIP	= 0x11,		/* calling line id present */
	MAP_SS_CODE_CLIR	= 0x12,		/* calling line id restrict */
	MAP_SS_CODE_COLP	= 0x13,		/* connected line id present */
	MAP_SS_CODE_COLR	= 0x14,		/* onnected line id restrict */
	MAP_SS_CODE_MCI		= 0x15,		/* malicious call id */

	/* name identification */
	MAP_SS_CODE_CNAP	= 0x19,		/* calling name presentation */

	/* forwarding */
	MAP_SS_CODE_CFU		= 0x21,		/* call forw unconditional */
	MAP_SS_CODE_CFB		= 0x29,		/* call forw subscr busy */
	MAP_SS_CODE_CFNRY	= 0x2a,		/* call forw no reply */
	MAP_SS_CODE_CFNRC	= 0x2b,		/* call forw not reachable */
	MAP_SS_CODE_CD		= 0x24,		/* call deflection */

	/* call offering */
	MAP_SS_CODE_ECT		= 0x31,		/* explicit call transfer */
	MAP_SS_CODE_MAH		= 0x32,		/* mobile access hunting */

	/* call completion SS */
	MAP_SS_CODE_CW		= 0x41,		/* call waiting */
	MAP_SS_CODE_HOLD	= 0x42,		/* call hold */
	MAP_SS_CODE_CCBS_A	= 0x43,
	MAP_SS_CODE_CCBS_B	= 0x44,
	MAP_SS_CODE_MC		= 0x45,		/* multicall */

	MAP_SS_CODE_MPTY	= 0x51,		/* multiparty */

	MAP_SS_CODE_CUG		= 0x61,		/* closed user group */

	MAP_SS_CODE_AOCI	= 0x71,		/* advice of charge info */
	MAP_SS_CODE_AOCC	= 0x72,		/* advice of charge charging */

	MAP_SS_CODE_UUS1	= 0x81,
	MAP_SS_CODE_UUS2	= 0x82,
	MAP_SS_CODE_UUS3	= 0x83,

	/* barring */
	MAP_SS_CODE_BOOC	= 0x91,
	MAP_SS_CODE_BAOC	= 0x92,		/* barr all outgoing calls */
	MAP_SS_CODE_BOIC	= 0x93,		/* barr outgoing intl calls */
	MAP_SS_CODE_BAIC	= 0x9a,		/* barr all incoming calls */
	MAP_SS_CODE_BICROAM	= 0x9b,		/* barr incoming calls in roaming */
};

/* SS-Status + 23.011 Section 2.1.2.1 Table 2.1 */
#define SS_STATUS_Q_BIT		0x08	/* quiescent */
#define SS_STATUS_P_BIT		0x04	/* provisioned */
#define SS_STATUS_R_BIT		0x02	/* registered */
#define SS_STATUS_A_BIT		0x01	/* active */


#define MAX_LEN_USSD_STRING	31

struct ussd_request {
	uint8_t opcode;

	uint8_t transaction_id;
	uint8_t invoke_id;

	union {
		struct {
			char text[MAX_LEN_USSD_STRING + 1];
		} unstructured;
		struct {
			uint8_t ss_code;
		} interrogate;
	};
};

int gsm0480_decode_ussd_request(const struct msgb *msg, 
				struct ussd_request *request); 
int gsm0480_send_ussd_response(const struct msgb *in_msg, const char* response_text, 
						const struct ussd_request *req);
int gsm0480_send_ussd_reject(const struct msgb *msg, 
				const struct ussd_request *request);
int gsm0480_send_ss_interr_resp(const struct msgb *in_msg, uint8_t status,
				const struct ussd_request *req);

#endif
