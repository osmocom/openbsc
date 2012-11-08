#ifndef _SMPP_SMSC_H
#define _SMPP_SMSC_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/write_queue.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

enum esme_read_state {
	READ_ST_IN_LEN = 0,
	READ_ST_IN_MSG = 1,
};

struct osmo_esme {
	struct llist_head list;
	struct smsc *smsc;

	int use;

	struct osmo_wqueue wqueue;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	enum esme_read_state read_state;
	uint32_t read_len;
	uint32_t read_idx;
	struct msgb *read_msg;

	uint8_t smpp_version;
	char system_id[16+1];

	uint8_t bind_flags;
};

struct smsc {
	struct osmo_fd listen_ofd;
	struct llist_head esme_list;
	char system_id[16+1];
	void *priv;
};


int smpp_smsc_init(struct smsc *smsc, uint16_t port);

void smpp_esme_get(struct osmo_esme *esme);
void smpp_esme_put(struct osmo_esme *esme);

int smpp_tx_submit_r(struct osmo_esme *esme, uint32_t sequence_nr,
		     uint32_t command_status, char *msg_id);

int handle_smpp_submit(struct osmo_esme *esme, struct submit_sm_t *submit,
			struct submit_sm_resp_t *submit_r);

#endif
