#ifndef FILTER_INTERFACE_H
#define FILTER_INTERFACE_H

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>


struct filter_connection {
	void *priv;
	struct osmo_fd fd;
};

#define FILTER_DOWNLINK_MSG	0  // BTS => MS
#define FILTER_UPLINK_MSG	1  // MS => BTS
#define FILTER_SILENT_CALL	2

struct filter_head {
	uint8_t msg_type;
        uint16_t len;	/* network byte order, num of remaining bytes */
	uint8_t data[0];
} __attribute__ ((packed));

struct filter_msg {
        void *priv1; /* trx from msgb  */
        void *priv2; /* lchan from msgb  */
	uint8_t data[0];
} __attribute__ ((packed));

#define FILTER_SUBSCR_ID_TYPE_EXT	0
#define FILTER_SUBSCR_ID_TYPE_IMSI	1
#define FILTER_SUBSCR_ID_TYPE_TMSI	2
#define FILTER_SUBSCR_ID_TYPE_ID	3

struct filter_silentcall_req {
	uint8_t activate;
	uint8_t channel_type;
	uint8_t subscr_id_type;
	uint8_t subscr_id[0];
} __attribute__ ((packed));

struct filter_silentcall_resp {
	void *priv1; /* trx from msgb  */
	void *priv2; /* lchan from msgb  */
	uint8_t	chan_nr; /* chan_nr for abis rsl hdr */
	uint8_t error;
} __attribute__ ((packed));

int filter_init(void *tall_ctx, void *priv, int port);
int filter_is_active();
int filter_send_msg(struct msgb *msg, int msg_type);

extern int _abis_rsl_sendmsg(struct msgb *msg);
extern int _abis_rsl_rcvmsg(struct msgb *msg);


#endif
