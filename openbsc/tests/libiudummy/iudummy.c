#include <stdint.h>
#include <stdbool.h>

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

int iu_tx_sec_mode_cmd(struct ue_conn_ctx *uectx, struct gsm_auth_tuple *tp,
		       int send_ck)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_tx_sec_mode_cmd() dummy called, NOT transmitting Security Mode Command\n");
	return 0;
}

int iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_page_cs() dummy called, NOT paging\n");
	return 0;
}

int iu_page_ps(const char *imsi, const uint32_t *ptmsi, uint16_t lac, uint8_t rac)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_page_ps() dummy called, NOT paging\n");
	return 0;
}

struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id, uint32_t rtp_ip,
					    uint16_t rtp_port,
					    bool use_x213_nsap)
{
	LOGP(DLGLOBAL, LOGL_INFO, "ranap_new_msg_rab_assign_voice() dummy called, NOT composing RAB Assignment\n");
	return NULL;
}

int iu_rab_act(struct ue_conn_ctx *ue_ctx, struct msgb *msg)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_rab_act() dummy called, NOT activating RAB\n");
	return 0;
}

int iu_tx_common_id(struct ue_conn_ctx *uectx, const char *imsi)
{
	LOGP(DLGLOBAL, LOGL_INFO, "iu_tx_common_id() dummy called, NOT sending CommonID\n");
	return 0;
}
