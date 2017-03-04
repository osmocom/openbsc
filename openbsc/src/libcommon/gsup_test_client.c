#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsup.h>

#include <openbsc/gsup_client.h>
#include <openbsc/debug.h>

static struct gsup_client *g_gc;


/***********************************************************************
 * IMSI Operation
 ***********************************************************************/
static LLIST_HEAD(g_imsi_ops);

struct imsi_op_stats {
	uint32_t num_alloc;
	uint32_t num_released;
	uint32_t num_rx_success;
	uint32_t num_rx_error;
	uint32_t num_timeout;
};

enum imsi_op_type {
	IMSI_OP_SAI,
	IMSI_OP_LU,
	IMSI_OP_ISD,
	_NUM_IMSI_OP
};

static const struct value_string imsi_op_names[] = {
	{ IMSI_OP_SAI, "SAI" },
	{ IMSI_OP_LU, "LU" },
	{ IMSI_OP_ISD, "ISD" },
	{ 0, NULL }
};

static struct imsi_op_stats imsi_op_stats[_NUM_IMSI_OP];

struct imsi_op {
	struct llist_head list;
	char imsi[17];
	enum imsi_op_type type;
	struct osmo_timer_list timer;
};

static struct imsi_op *imsi_op_find(const char *imsi,
			     enum imsi_op_type type)
{
	struct imsi_op *io;

	llist_for_each_entry(io, &g_imsi_ops, list) {
		if (!strcmp(io->imsi, imsi) && io->type == type)
			return io;
	}
	return NULL;
}

static void imsi_op_timer_cb(void *data);

static struct imsi_op *imsi_op_alloc(void *ctx, const char *imsi,
				enum imsi_op_type type)
{
	struct imsi_op *io;

	if (imsi_op_find(imsi, type))
		return NULL;

	io = talloc_zero(ctx, struct imsi_op);
	osmo_strlcpy(io->imsi, imsi, sizeof(io->imsi));
	io->type = type;
	osmo_timer_setup(&io->timer, imsi_op_timer_cb, io);
	llist_add(&io->list, &g_imsi_ops);
	imsi_op_stats[type].num_alloc++;

	return io;
}

static void imsi_op_release(struct imsi_op *io)
{
	osmo_timer_del(&io->timer);
	llist_del(&io->list);
	imsi_op_stats[io->type].num_released++;
	talloc_free(io);
}

static void imsi_op_timer_cb(void *data)
{
	struct imsi_op *io = data;
	printf("%s: Timer expiration\n", io->imsi);
	imsi_op_stats[io->type].num_timeout++;
	imsi_op_release(io);
}

/* allocate + generate + send Send-Auth-Info */
int req_auth_info(const char *imsi)
{
	struct imsi_op *io = imsi_op_alloc(g_gc, imsi, IMSI_OP_SAI);
	struct osmo_gsup_message gsup = {0};
	struct msgb *msg = msgb_alloc_headroom(1200, 200, __func__);

	osmo_strlcpy(gsup.imsi, io->imsi, sizeof(gsup.imsi));
	gsup.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;

	osmo_gsup_encode(msg, &gsup);

	return gsup_client_send(g_gc, msg);
}

/* allocate + generate + send Send-Auth-Info */
int req_loc_upd(const char *imsi)
{
	struct imsi_op *io = imsi_op_alloc(g_gc, imsi, IMSI_OP_LU);
	struct osmo_gsup_message gsup = {0};
	struct msgb *msg = msgb_alloc_headroom(1200, 200, __func__);

	osmo_strlcpy(gsup.imsi, io->imsi, sizeof(gsup.imsi));
	gsup.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;

	osmo_gsup_encode(msg, &gsup);

	return gsup_client_send(g_gc, msg);
}

int resp_isd(struct imsi_op *io)
{
	struct osmo_gsup_message gsup = {0};
	struct msgb *msg = msgb_alloc_headroom(1200, 200, __func__);

	osmo_strlcpy(gsup.imsi, io->imsi, sizeof(gsup.imsi));
	gsup.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;

	osmo_gsup_encode(msg, &gsup);

	imsi_op_release(io);

	return gsup_client_send(g_gc, msg);
}

/* receive an incoming GSUP message */
static void imsi_op_rx_gsup(struct imsi_op *io, const struct osmo_gsup_message *gsup)
{
	int is_error = 0;

	if (OSMO_GSUP_IS_MSGT_ERROR(gsup->message_type)) {
		imsi_op_stats[io->type].num_rx_error++;
		is_error = 1;
	} else
		imsi_op_stats[io->type].num_rx_success++;

	switch (io->type) {
	case IMSI_OP_SAI:
		printf("%s; SAI Response%s\n", io->imsi, is_error ? ": ERROR" : "");
		/* now that we have auth tuples, request LU */
		req_loc_upd(io->imsi);
		imsi_op_release(io);
		break;
	case IMSI_OP_LU:
		printf("%s; LU Response%s\n", io->imsi, is_error ? ": ERROR" : "");
		imsi_op_release(io);
		break;
	case IMSI_OP_ISD:
		printf("%s; ISD Request%s\n", io->imsi, is_error ? ": ERROR" : "");
		resp_isd(io);
		break;
	default:
		printf("%s: Unknown\n", io->imsi);
		imsi_op_release(io);
		break;
	}
}

static int op_type_by_gsup_msgt(enum osmo_gsup_message_type msg_type)
{
	switch (msg_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		return IMSI_OP_SAI;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		return IMSI_OP_LU;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		return IMSI_OP_ISD;
	default:
		printf("Unknown GSUP msg_type %u\n", msg_type);
		return -1;
	}
}

static int gsupc_read_cb(struct gsup_client *gsupc, struct msgb *msg)
{
	struct osmo_gsup_message gsup_msg = {0};
	struct imsi_op *io;
	int rc;

	DEBUGP(DGPRS, "Rx GSUP %s\n", osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup_msg);
	if (rc < 0)
		return rc;

	if (!gsup_msg.imsi[0])
		return -1;

	rc = op_type_by_gsup_msgt(gsup_msg.message_type);
	if (rc < 0)
		return rc;

	switch (rc) {
	case IMSI_OP_SAI:
	case IMSI_OP_LU:
		io = imsi_op_find(gsup_msg.imsi, rc);
		if (!io)
			return -1;
		break;
	case IMSI_OP_ISD:
		/* ISD is an inbound transaction */
		io = imsi_op_alloc(g_gc, gsup_msg.imsi, IMSI_OP_ISD);
		break;
	}

	imsi_op_rx_gsup(io, &gsup_msg);
	msgb_free(msg);

	return 0;
}

static void print_report(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(imsi_op_stats); i++) {
		struct imsi_op_stats *st = &imsi_op_stats[i];
		const char *name = get_value_string(imsi_op_names, i);
		printf("%s: %u alloc, %u released, %u success, %u error , %u tout\n",
			name, st->num_alloc, st->num_released, st->num_rx_success,
			st->num_rx_error, st->num_timeout);
	}
}

static void sig_cb(int sig)
{
	switch (sig) {
	case SIGINT:
		print_report();
		exit(0);
		break;
	}
}

void *tall_bsc_ctx = NULL;

/* default categories */
static struct log_info_cat default_categories[] = {
};

static const struct log_info gsup_test_client_log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	unsigned long long i;
	char *server_host = "127.0.0.1";
	uint16_t server_port = 2222;

	osmo_init_logging(&gsup_test_client_log_info);

	g_gc = gsup_client_create("GSUPTEST", server_host, server_port,
				  gsupc_read_cb, NULL);


	signal(SIGINT, sig_cb);

	for (i = 0; i < 10000; i++) {
		unsigned long long imsi = 901790000000000 + i;
		char imsi_buf[17];
		snprintf(imsi_buf, sizeof(imsi_buf), "%015llu", imsi);
		req_auth_info(imsi_buf);
		osmo_select_main(0);
	}

	while (1) {
		osmo_select_main(0);
	}

	print_report();
	exit(0);
}
