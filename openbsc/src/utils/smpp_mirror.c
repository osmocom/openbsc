#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>

#include <openbsc/debug.h>

/* FIXME: merge with smpp_smsc.c */
#define SMPP_SYS_ID_LEN	16
enum esme_read_state {
	READ_ST_IN_LEN = 0,
	READ_ST_IN_MSG = 1,
};
/* FIXME: merge with smpp_smsc.c */

struct esme {
	struct osmo_fd ofd;

	uint32_t own_seq_nr;

	struct osmo_wqueue wqueue;
	enum esme_read_state read_state;
	uint32_t read_len;
	uint32_t read_idx;
	struct msgb *read_msg;

	uint8_t smpp_version;
	char system_id[SMPP_SYS_ID_LEN+1];
	char password[SMPP_SYS_ID_LEN+1];
};

/* FIXME: merge with smpp_smsc.c */
#define SMPP34_UNPACK(rc, type, str, data, len)		\
	memset(str, 0, sizeof(*str));			\
	rc = smpp34_unpack(type, str, data, len)
#define INIT_RESP(type, resp, req) 		{ \
	memset((resp), 0, sizeof(*(resp)));	  \
	(resp)->command_length	= 0;		  \
	(resp)->command_id	= type;		  \
	(resp)->command_status	= ESME_ROK;	  \
	(resp)->sequence_number	= (req)->sequence_number;	\
}
#define PACK_AND_SEND(esme, ptr)	pack_and_send(esme, (ptr)->command_id, ptr)
static inline uint32_t smpp_msgb_cmdid(struct msgb *msg)
{
	uint8_t *tmp = msgb_data(msg) + 4;
	return ntohl(*(uint32_t *)tmp);
}
static uint32_t esme_inc_seq_nr(struct esme *esme)
{
	esme->own_seq_nr++;
	if (esme->own_seq_nr > 0x7fffffff)
		esme->own_seq_nr = 1;

	return esme->own_seq_nr;
}
static int pack_and_send(struct esme *esme, uint32_t type, void *ptr)
{
	struct msgb *msg = msgb_alloc(4096, "SMPP_Tx");
	int rc, rlen;
	if (!msg)
		return -ENOMEM;

	rc = smpp34_pack(type, msg->tail, msgb_tailroom(msg), &rlen, ptr);
	if (rc != 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error during smpp34_pack(): %s\n",
		     esme->system_id, smpp34_strerror);
		msgb_free(msg);
		return -EINVAL;
	}
	msgb_put(msg, rlen);

	if (osmo_wqueue_enqueue(&esme->wqueue, msg) != 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Write queue full. Dropping message\n",
		     esme->system_id);
		msgb_free(msg);
		return -EAGAIN;
	}
	return 0;
}
/* FIXME: merge with smpp_smsc.c */


static int smpp_handle_deliver(struct esme *esme, struct msgb *msg)
{
	struct deliver_sm_t deliver;
	struct deliver_sm_resp_t deliver_r;
	struct submit_sm_t submit;
	int rc;

	memset(&deliver, 0, sizeof(deliver));
	SMPP34_UNPACK(rc, DELIVER_SM, &deliver, msgb_data(msg), msgb_length(msg));
	if (rc < 0)
		return rc;

	INIT_RESP(DELIVER_SM_RESP, &deliver_r, &deliver);

	PACK_AND_SEND(esme, &deliver_r);

	memset(&submit, 0, sizeof(submit));
	submit.command_id = SUBMIT_SM;
	submit.command_status = ESME_ROK;
	submit.sequence_number = esme_inc_seq_nr(esme);

	submit.dest_addr_ton =  deliver.source_addr_ton;
	submit.dest_addr_npi =  deliver.source_addr_npi;
	memcpy(submit.destination_addr, deliver.source_addr,
		OSMO_MIN(sizeof(submit.destination_addr),
			 sizeof(deliver.source_addr)));

	submit.source_addr_ton = deliver.dest_addr_ton;
	submit.source_addr_npi = deliver.dest_addr_npi;
	memcpy(submit.source_addr, deliver.destination_addr,
		OSMO_MIN(sizeof(submit.source_addr),
			 sizeof(deliver.destination_addr)));

	submit.esm_class = deliver.esm_class;
	submit.protocol_id = deliver.protocol_id;
	submit.priority_flag = deliver.priority_flag;
	memcpy(submit.schedule_delivery_time, deliver.schedule_delivery_time,
	       OSMO_MIN(sizeof(submit.schedule_delivery_time),
		        sizeof(deliver.schedule_delivery_time)));
	memcpy(submit.validity_period, deliver.validity_period,
		OSMO_MIN(sizeof(submit.validity_period),
			 sizeof(deliver.validity_period)));
	submit.registered_delivery = deliver.registered_delivery;
	submit.replace_if_present_flag = deliver.replace_if_present_flag;
	submit.data_coding = deliver.data_coding;
	submit.sm_default_msg_id = deliver.sm_default_msg_id;
	submit.sm_length = deliver.sm_length;
	memcpy(submit.short_message, deliver.short_message,
		OSMO_MIN(sizeof(submit.short_message),
			 sizeof(deliver.short_message)));
	/* FIXME: TLV? */

	return PACK_AND_SEND(esme, &submit);
}

static int bind_transceiver(struct esme *esme)
{
	struct bind_transceiver_t bind;

	memset(&bind, 0, sizeof(bind));
	bind.command_id = BIND_TRANSCEIVER;
	bind.sequence_number = esme_inc_seq_nr(esme);
	snprintf((char *)bind.system_id, sizeof(bind.system_id), "%s", esme->system_id);
	snprintf((char *)bind.password, sizeof(bind.password), "%s", esme->password);
	snprintf((char *)bind.system_type, sizeof(bind.system_type), "mirror");
	bind.interface_version = esme->smpp_version;

	return PACK_AND_SEND(esme, &bind);
}

static int smpp_pdu_rx(struct esme *esme, struct msgb *msg)
{
	uint32_t cmd_id = smpp_msgb_cmdid(msg);
	int rc;

	switch (cmd_id) {
	case DELIVER_SM:
		rc = smpp_handle_deliver(esme, msg);
		break;
	default:
		LOGP(DSMPP, LOGL_NOTICE, "unhandled case %d\n", cmd_id);
		rc = 0;
		break;
	}

	return rc;
}

/* FIXME: merge with smpp_smsc.c */
static int esme_read_cb(struct osmo_fd *ofd)
{
	struct esme *esme = ofd->data;
	uint32_t len;
	uint8_t *lenptr = (uint8_t *) &len;
	uint8_t *cur;
	struct msgb *msg;
	int rdlen;
	int rc;

	switch (esme->read_state) {
	case READ_ST_IN_LEN:
		rdlen = sizeof(uint32_t) - esme->read_idx;
		rc = read(ofd->fd, lenptr + esme->read_idx, rdlen);
		if (rc < 0) {
			LOGP(DSMPP, LOGL_ERROR, "[%s] read returned %d\n",
			     esme->system_id, rc);
		} else if (rc == 0) {
			goto dead_socket;
		} else
			esme->read_idx += rc;
		if (esme->read_idx >= sizeof(uint32_t)) {
			esme->read_len = ntohl(len);
			msg = msgb_alloc(esme->read_len, "SMPP Rx");
			if (!msg)
				return -ENOMEM;
			esme->read_msg = msg;
			cur = msgb_put(msg, sizeof(uint32_t));
			memcpy(cur, lenptr, sizeof(uint32_t));
			esme->read_state = READ_ST_IN_MSG;
			esme->read_idx = sizeof(uint32_t);
		}
		break;
	case READ_ST_IN_MSG:
		msg = esme->read_msg;
		rdlen = esme->read_len - esme->read_idx;
		rc = read(ofd->fd, msg->tail, OSMO_MIN(rdlen, msgb_tailroom(msg)));
		if (rc < 0) {
			LOGP(DSMPP, LOGL_ERROR, "[%s] read returned %d\n",
				esme->system_id, rc);
		} else if (rc == 0) {
			goto dead_socket;
		} else {
			esme->read_idx += rc;
			msgb_put(msg, rc);
		}

		if (esme->read_idx >= esme->read_len) {
			rc = smpp_pdu_rx(esme, esme->read_msg);
			esme->read_msg = NULL;
			esme->read_idx = 0;
			esme->read_len = 0;
			esme->read_state = READ_ST_IN_LEN;
		}
		break;
	}

	return 0;
dead_socket:
	msgb_free(esme->read_msg);
	osmo_fd_unregister(&esme->wqueue.bfd);
	close(esme->wqueue.bfd.fd);
	esme->wqueue.bfd.fd = -1;
	exit(2342);

	return 0;
}

static int esme_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	struct esme *esme = ofd->data;
	int rc;

	rc = write(ofd->fd, msgb_data(msg), msgb_length(msg));
	if (rc == 0) {
		osmo_fd_unregister(&esme->wqueue.bfd);
		close(esme->wqueue.bfd.fd);
		esme->wqueue.bfd.fd = -1;
		exit(99);
	} else if (rc < msgb_length(msg)) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Short write\n", esme->system_id);
		return 0;
	}

	return 0;
}

static int smpp_esme_init(struct esme *esme, const char *host, uint16_t port)
{
	int rc;

	if (port == 0)
		port = 2775;

	esme->own_seq_nr = rand();
	esme_inc_seq_nr(esme);
	osmo_wqueue_init(&esme->wqueue, 10);
	esme->wqueue.bfd.data = esme;
	esme->wqueue.read_cb = esme_read_cb;
	esme->wqueue.write_cb = esme_write_cb;

	rc = osmo_sock_init_ofd(&esme->wqueue.bfd, AF_UNSPEC, SOCK_STREAM,
				IPPROTO_TCP, host, port, OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	return bind_transceiver(esme);
}


int main(int argc, char **argv)
{
	struct esme esme;
	char *host = "localhost";
	int port = 0;
	int rc;

	msgb_talloc_ctx_init(NULL, 0);

	memset(&esme, 0, sizeof(esme));

	osmo_init_logging(&log_info);

	snprintf((char *) esme.system_id, sizeof(esme.system_id), "mirror");
	snprintf((char *) esme.password, sizeof(esme.password), "mirror");
	esme.smpp_version = 0x34;

	if (argc >= 2)
		host = argv[1];
	if (argc >= 3)
		port = atoi(argv[2]);

	rc = smpp_esme_init(&esme, host, port);
	if (rc < 0)
		exit(1);

	while (1) {
		osmo_select_main(0);
	}

	exit(0);
}
