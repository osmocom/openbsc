#ifndef _SMPP_SMSC_H
#define _SMPP_SMSC_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#define SMPP_SYS_ID_LEN	16
#define SMPP_PASSWD_LEN	16

#define MODE_7BIT	7
#define MODE_8BIT	8

enum esme_read_state {
	READ_ST_IN_LEN = 0,
	READ_ST_IN_MSG = 1,
};

struct osmo_smpp_acl;

struct osmo_smpp_addr {
	uint8_t ton;
	uint8_t npi;
	char addr[21+1];
};

struct osmo_esme {
	struct llist_head list;
	struct smsc *smsc;
	struct osmo_smpp_acl *acl;
	int use;

	struct llist_head smpp_cmd_list;

	uint32_t own_seq_nr;

	struct osmo_wqueue wqueue;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	enum esme_read_state read_state;
	uint32_t read_len;
	uint32_t read_idx;
	struct msgb *read_msg;

	uint8_t smpp_version;
	char system_id[SMPP_SYS_ID_LEN+1];

	uint8_t bind_flags;
};

struct osmo_smpp_acl {
	struct llist_head list;
	struct smsc *smsc;
	struct osmo_esme *esme;
	char *description;
	char system_id[SMPP_SYS_ID_LEN+1];
	char passwd[SMPP_PASSWD_LEN+1];
	int default_route;
	int deliver_src_imsi;
	int osmocom_ext;
	int dcs_transparent;
	struct llist_head route_list;
};

enum osmo_smpp_rtype {
	SMPP_ROUTE_NONE,
	SMPP_ROUTE_PREFIX,
};

struct osmo_smpp_route {
	struct llist_head list;	/*!< in acl.route_list */
	struct llist_head global_list; /*!< in smsc->route_list */
	struct osmo_smpp_acl *acl;
	enum osmo_smpp_rtype type;
	union {
		struct osmo_smpp_addr prefix;
	} u;
};

struct osmo_smpp_cmd {
	struct llist_head	list;
	struct gsm_subscriber	*subscr;
	struct gsm_sms		*sms;
	uint32_t		sequence_nr;
	struct osmo_timer_list	response_timer;
};

struct osmo_smpp_cmd *smpp_cmd_find_by_seqnum(struct osmo_esme *esme,
					      uint32_t sequence_number);
void smpp_cmd_ack(struct osmo_smpp_cmd *cmd);
void smpp_cmd_err(struct osmo_smpp_cmd *cmd, uint32_t status);
void smpp_cmd_flush_pending(struct osmo_esme *esme);

struct smsc {
	struct osmo_fd listen_ofd;
	struct llist_head esme_list;
	struct llist_head acl_list;
	struct llist_head route_list;
	const char *bind_addr;
	uint16_t listen_port;
	char system_id[SMPP_SYS_ID_LEN+1];
	int accept_all;
	int smpp_first;
	struct osmo_smpp_acl *def_route;
	void *priv;
};

int smpp_addr_eq(const struct osmo_smpp_addr *a,
		 const struct osmo_smpp_addr *b);

struct smsc *smpp_smsc_alloc_init(void *ctx);
int smpp_smsc_conf(struct smsc *smsc, const char *bind_addr, uint16_t port);
int smpp_smsc_start(struct smsc *smsc, const char *bind_addr, uint16_t port);
int smpp_smsc_restart(struct smsc *smsc, const char *bind_addr, uint16_t port);
void smpp_smsc_stop(struct smsc *smsc);

void smpp_esme_get(struct osmo_esme *esme);
void smpp_esme_put(struct osmo_esme *esme);

struct osmo_esme *
smpp_route(const struct smsc *smsc, const struct osmo_smpp_addr *dest);

struct osmo_smpp_acl *smpp_acl_alloc(struct smsc *smsc, const char *sys_id);
struct osmo_smpp_acl *smpp_acl_by_system_id(struct smsc *smsc,
					    const char *sys_id);
void smpp_acl_delete(struct osmo_smpp_acl *acl);

int smpp_tx_submit_r(struct osmo_esme *esme, uint32_t sequence_nr,
		     uint32_t command_status, char *msg_id);

int smpp_tx_alert(struct osmo_esme *esme, uint8_t ton, uint8_t npi,
		  const char *addr, uint8_t avail_status);

int smpp_tx_deliver(struct osmo_esme *esme, struct deliver_sm_t *deliver);

int handle_smpp_submit(struct osmo_esme *esme, struct submit_sm_t *submit,
			struct submit_sm_resp_t *submit_r);

int smpp_route_pfx_add(struct osmo_smpp_acl *acl,
		       const struct osmo_smpp_addr *pfx);
int smpp_route_pfx_del(struct osmo_smpp_acl *acl,
		       const struct osmo_smpp_addr *pfx);

int smpp_vty_init(void);

int smpp_determine_scheme(uint8_t dcs, uint8_t *data_coding, int *mode);



struct gsm_sms;
struct gsm_subscriber_connection;

int smpp_route_smpp_first(struct gsm_sms *sms,
			    struct gsm_subscriber_connection *conn);
int smpp_try_deliver(struct gsm_sms *sms,
		     struct gsm_subscriber_connection *conn, bool *deferred);
#endif
