/* UDP-Feed of measurement reports */

#include <unistd.h>

#include <sys/socket.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/meas_feed.h>
#include <openbsc/vty.h>

#include "meas_feed.h"

struct meas_feed_state {
	struct osmo_wqueue wqueue;
	char scenario[31+1];
	char *dst_host;
	uint16_t dst_port;
};


static struct meas_feed_state g_mfs;

static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct msgb *msg;
	struct meas_feed_meas *mfm;
	struct gsm_subscriber *subscr;

	/* ignore measurements as long as we don't know who it is */
	if (!mr->lchan || !mr->lchan->conn || !mr->lchan->conn->subscr)
		return 0;

	subscr = mr->lchan->conn->subscr;

	msg = msgb_alloc(sizeof(struct meas_feed_meas), "Meas. Feed");
	if (!msg)
		return 0;

	/* fill in the header */
	mfm = (struct meas_feed_meas *) msgb_put(msg, sizeof(*mfm));
	mfm->hdr.msg_type = MEAS_FEED_MEAS;
	mfm->hdr.version = MEAS_FEED_VERSION;

	/* fill in MEAS_FEED_MEAS specific header */
	osmo_strlcpy(mfm->imsi, subscr->imsi, sizeof(mfm->imsi));
	osmo_strlcpy(mfm->name, subscr->name, sizeof(mfm->name));
	osmo_strlcpy(mfm->scenario, g_mfs.scenario, sizeof(mfm->scenario));

	/* copy the entire measurement report */
	memcpy(&mfm->mr, mr, sizeof(mfm->mr));

	/* copy channel information */
	/* we assume that the measurement report always belong to some timeslot */
	mfm->lchan_type = (uint8_t)mr->lchan->type;
	mfm->pchan_type = (uint8_t)mr->lchan->ts->pchan;
	mfm->bts_nr = mr->lchan->ts->trx->bts->nr;
	mfm->trx_nr = mr->lchan->ts->trx->nr;
	mfm->ts_nr = mr->lchan->ts->nr;
	mfm->ss_nr = mr->lchan->nr;

	/* and send it to the socket */
	if (osmo_wqueue_enqueue(&g_mfs.wqueue, msg) != 0)
		msgb_free(msg);

	return 0;
}

static int meas_feed_sig_cb(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct lchan_signal_data *sdata = signal_data;

	if (subsys != SS_LCHAN)
		return 0;

	if (signal == S_LCHAN_MEAS_REP)
		process_meas_rep(sdata->mr);

	return 0;
}

static int feed_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	return write(ofd->fd, msgb_data(msg), msgb_length(msg));
}

static int feed_read_cb(struct osmo_fd *ofd)
{
	int rc;
	char buf[256];

	rc = read(ofd->fd, buf, sizeof(buf));
	ofd->fd &= ~BSC_FD_READ;

	return rc;
}

int meas_feed_cfg_set(const char *dst_host, uint16_t dst_port)
{
	int rc;
	int already_initialized = 0;

	if (g_mfs.wqueue.bfd.fd)
		already_initialized = 1;


	if (already_initialized &&
	    !strcmp(dst_host, g_mfs.dst_host) &&
	    dst_port == g_mfs.dst_port)
		return 0;

	if (!already_initialized) {
		osmo_wqueue_init(&g_mfs.wqueue, 10);
		g_mfs.wqueue.write_cb = feed_write_cb;
		g_mfs.wqueue.read_cb = feed_read_cb;
		osmo_signal_register_handler(SS_LCHAN, meas_feed_sig_cb, NULL);
	}

	if (already_initialized) {
		osmo_wqueue_clear(&g_mfs.wqueue);
		osmo_fd_unregister(&g_mfs.wqueue.bfd);
		close(g_mfs.wqueue.bfd.fd);
		/* don't set to zero, as that would mean 'not yet initialized' */
		g_mfs.wqueue.bfd.fd = -1;
	}
	rc = osmo_sock_init_ofd(&g_mfs.wqueue.bfd, AF_UNSPEC, SOCK_DGRAM,
				IPPROTO_UDP, dst_host, dst_port,
				OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	g_mfs.wqueue.bfd.when &= ~BSC_FD_READ;

	if (g_mfs.dst_host)
		talloc_free(g_mfs.dst_host);
	g_mfs.dst_host = talloc_strdup(NULL, dst_host);
	g_mfs.dst_port = dst_port;

	return 0;
}

void meas_feed_cfg_get(char **host, uint16_t *port)
{
	*port = g_mfs.dst_port;
	*host = g_mfs.dst_host;
}

void meas_feed_scenario_set(const char *name)
{
	osmo_strlcpy(g_mfs.scenario, name, sizeof(g_mfs.scenario));
}

const char *meas_feed_scenario_get(void)
{
	return g_mfs.scenario;
}
