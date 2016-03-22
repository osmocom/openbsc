#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/msgb.h>

struct msgb;
struct ue_conn_ctx;
struct gsm_auth_tuple;

int iu_tx(struct msgb *msg, uint8_t sapi)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_tx() dummy called, NOT transmitting %d bytes: %s\n",
	     msg->len, osmo_hexdump(msg->data, msg->len));
	return 0;
}

