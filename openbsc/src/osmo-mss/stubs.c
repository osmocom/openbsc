#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>

struct gsm_subscriber_connection *connection_for_subscr(struct gsm_subscriber *subscr)
{
	struct gsm_bts *bts;
	struct gsm_network *net = subscr->group->net;
	struct gsm_lchan *lchan;

	/* FIXME: iterate over all existing GAN associations and see if we have
	 * any for subscr */

	return NULL;
}

/*! \brief process incoming 08.08 DTAP from MSC (send via GANC
 * association to MS) */
int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			struct msgb *msg, int link_id, int allow_sacch)
{
	/* FIXME */

	return -EINVAL;
}

/* Release all occupied RF Channels but stay around for more. */
int gsm0808_clear(struct gsm_subscriber_connection *conn)
{
	/* FIXME */
	conn->lchan = NULL;
	conn->secondary_lchan = NULL;
	conn->ho_lchan = NULL;
	conn->bts = NULL;

	osmo_timer_del(&conn->T10);

	return 0;
}
/*! \brief We received a GSM 08.08 CIPHER MODE from the MSC */
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	if (cipher > 0 && key == NULL) {
		LOGP(DRSL, LOGL_ERROR, "Need to have an encrytpion key.\n");
		return -1;
	}

	if (len > MAX_A5_KEY_LEN) {
		LOGP(DRSL, LOGL_ERROR, "The key is too long: %d\n", len);
		return -1;
	}
}

/* MSC has requested that we page the given subscriber */
int paging_request(struct gsm_network *network, struct gsm_subscriber *subscr,
		   int type, gsm_cbfn *cbfn, void *data)
{
	/* FIXME */
	return -EINVAL;
}

/* Stop paging on all other bts' */
void paging_request_stop(struct gsm_bts *_bts, struct gsm_subscriber *subscr,
			 struct gsm_subscriber_connection *conn,
			 struct msgb *msg)
{
	/* FIXME */
}

/* cleanup at release subscriber_connection */
void subscr_con_free(struct gsm_subscriber_connection *conn)
{
	/* FIXME: merge with libbsc/bsc_api.c implementation */
	if (!conn)
		return;

	if (conn->subscr) {
		subscr_put(conn->subscr);
		conn->subscr = NULL;
	}

	if (conn->lchan) {
		LOGP(DNM, LOGL_ERROR, "The lchan should have been cleared.\n");
		conn->lchan->conn = NULL;
	}

	if (conn->secondary_lchan) {
		LOGP(DNM, LOGL_ERROR, "The secondary_lchan should have been cleared.\n");
		conn->secondary_lchan->conn = NULL;
	}

	llist_del(&conn->entry);
	talloc_free(conn);
}

void gsm_net_update_ctype(struct gsm_network *network)
{
	/* a MSC doesn't really need this, does it? */
	return;
}


