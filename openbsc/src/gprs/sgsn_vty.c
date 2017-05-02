/*
 * (C) 2010-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2015 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <openbsc/debug.h>
#include <openbsc/sgsn.h>
#include <osmocom/gprs/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/vty.h>
#include <openbsc/gsup_client.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/abis/ipa.h>

#include <pdp.h>

static struct sgsn_config *g_cfg = NULL;

const struct value_string sgsn_auth_pol_strs[] = {
	{ SGSN_AUTH_POLICY_OPEN,	"accept-all" },
	{ SGSN_AUTH_POLICY_CLOSED,	"closed" },
	{ SGSN_AUTH_POLICY_ACL_ONLY,    "acl-only" },
	{ SGSN_AUTH_POLICY_REMOTE,      "remote" },
	{ 0, NULL }
};

/* Section 11.2.2 / Table 11.3a GPRS Mobility management timers – MS side */
#define GSM0408_T3312_SECS	(10*60)	/* periodic RAU interval, default 54min */

/* Section 11.2.2 / Table 11.4 MM timers netwokr side */
#define GSM0408_T3322_SECS	6	/* DETACH_REQ -> DETACH_ACC */
#define GSM0408_T3350_SECS	6	/* waiting for ATT/RAU/TMSI COMPL */
#define GSM0408_T3360_SECS	6	/* waiting for AUTH/CIPH RESP */
#define GSM0408_T3370_SECS	6	/* waiting for ID RESP */

/* Section 11.2.2 / Table 11.4a MM timers network side */
#define GSM0408_T3313_SECS	30	/* waiting for paging response */
#define GSM0408_T3314_SECS	44	/* force to STBY on expiry, Ready timer */
#define GSM0408_T3316_SECS	44

/* Section 11.3 / Table 11.2d Timers of Session Management - network side */
#define GSM0408_T3385_SECS	8	/* wait for ACT PDP CTX REQ */
#define GSM0408_T3386_SECS	8	/* wait for MODIFY PDP CTX ACK */
#define GSM0408_T3395_SECS	8	/* wait for DEACT PDP CTX ACK */
#define GSM0408_T3397_SECS	8	/* wait for DEACT AA PDP CTX ACK */

#define DECLARE_TIMER(number, doc) \
    DEFUN(cfg_sgsn_T##number,					\
      cfg_sgsn_T##number##_cmd,					\
      "timer t" #number  " <0-65535>",				\
      "Configure GPRS Timers\n"					\
      doc "\nTimer Value in seconds\n")				\
{								\
	int value = atoi(argv[0]);				\
								\
	if (value < 0 || value > 65535) {			\
		vty_out(vty, "Timer value %s out of range.%s",	\
		        argv[0], VTY_NEWLINE);			\
		return CMD_WARNING;				\
	}							\
								\
	g_cfg->timers.T##number = value;			\
	return CMD_SUCCESS;					\
}

DECLARE_TIMER(3312, "Periodic RA Update timer (s)")
DECLARE_TIMER(3322, "Detach request -> accept timer (s)")
DECLARE_TIMER(3350, "Waiting for ATT/RAU/TMSI_COMPL timer (s)")
DECLARE_TIMER(3360, "Waiting for AUTH/CIPH response timer (s)")
DECLARE_TIMER(3370, "Waiting for IDENTITY response timer (s)")

DECLARE_TIMER(3313, "Waiting for paging response timer (s)")
DECLARE_TIMER(3314, "Force to STANDBY on expiry timer (s)")
DECLARE_TIMER(3316, "AA-Ready timer (s)")

DECLARE_TIMER(3385, "Wait for ACT PDP CTX REQ timer (s)")
DECLARE_TIMER(3386, "Wait for MODIFY PDP CTX ACK timer (s)")
DECLARE_TIMER(3395, "Wait for DEACT PDP CTX ACK timer (s)")
DECLARE_TIMER(3397, "Wait for DEACT AA PDP CTX ACK timer (s)")


#define GSM48_MAX_APN_LEN	102	/* 10.5.6.1 */
/* TODO: consolidate with gprs_apn_to_str(). */
/** Copy apn to a static buffer, replacing the length octets in apn_enc with '.'
 * and terminating with a '\0'. Return the static buffer.
 * len: the length of the encoded APN (which has no terminating zero).
 */
static char *gprs_apn2str(uint8_t *apn, unsigned int len)
{
	static char apnbuf[GSM48_MAX_APN_LEN+1];
	unsigned int i = 0;

	if (!apn)
		return "";

	if (len > sizeof(apnbuf)-1)
		len = sizeof(apnbuf)-1;

	memcpy(apnbuf, apn, len);
	apnbuf[len] = '\0';

	/* replace the domain name step sizes with dots */
	while (i < len) {
		unsigned int step = apnbuf[i];
		apnbuf[i] = '.';
		i += step+1;
	}

	return apnbuf+1;
}

char *gprs_pdpaddr2str(uint8_t *pdpa, uint8_t len)
{
	static char str[INET6_ADDRSTRLEN + 10];

	if (!pdpa || len < 2)
		return "none";

	switch (pdpa[0] & 0x0f) {
	case PDP_TYPE_ORG_IETF:
		switch (pdpa[1]) {
		case PDP_TYPE_N_IETF_IPv4:
			if (len < 2 + 4)
				break;
			strcpy(str, "IPv4 ");
			inet_ntop(AF_INET, pdpa+2, str+5, sizeof(str)-5);
			return str;
		case PDP_TYPE_N_IETF_IPv6:
			if (len < 2 + 8)
				break;
			strcpy(str, "IPv6 ");
			inet_ntop(AF_INET6, pdpa+2, str+5, sizeof(str)-5);
			return str;
		default:
			break;
		}
		break;
	case PDP_TYPE_ORG_ETSI:
		if (pdpa[1] == PDP_TYPE_N_ETSI_PPP)
			return "PPP";
		break;
	default:
		break;
	}

	return "invalid";
}

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(config-sgsn)# ",
	1,
};

static int config_write_sgsn(struct vty *vty)
{
	struct sgsn_ggsn_ctx *gctx;
	struct imsi_acl_entry *acl;
	struct apn_ctx *actx;
	struct ares_addr_node *server;

	vty_out(vty, "sgsn%s", VTY_NEWLINE);

	vty_out(vty, " gtp local-ip %s%s",
		inet_ntoa(g_cfg->gtp_listenaddr.sin_addr), VTY_NEWLINE);

	llist_for_each_entry(gctx, &sgsn_ggsn_ctxts, list) {
		if (gctx->id == UINT32_MAX)
			continue;

		vty_out(vty, " ggsn %u remote-ip %s%s", gctx->id,
			inet_ntoa(gctx->remote_addr), VTY_NEWLINE);
		vty_out(vty, " ggsn %u gtp-version %u%s", gctx->id,
			gctx->gtp_version, VTY_NEWLINE);
	}

	if (sgsn->cfg.dynamic_lookup)
		vty_out(vty, " ggsn dynamic%s", VTY_NEWLINE);

	for (server = sgsn->ares_servers; server; server = server->next)
		vty_out(vty, " grx-dns-add %s%s", inet_ntoa(server->addr.addr4), VTY_NEWLINE);

	if (g_cfg->cipher != GPRS_ALGO_GEA0)
		vty_out(vty, " encryption %s%s",
			get_value_string(gprs_cipher_names, g_cfg->cipher),
			VTY_NEWLINE);
	if (g_cfg->gsup_server_addr.sin_addr.s_addr)
		vty_out(vty, " gsup remote-ip %s%s",
			inet_ntoa(g_cfg->gsup_server_addr.sin_addr), VTY_NEWLINE);
	if (g_cfg->gsup_server_port)
		vty_out(vty, " gsup remote-port %d%s",
			g_cfg->gsup_server_port, VTY_NEWLINE);
	vty_out(vty, " auth-policy %s%s",
		get_value_string(sgsn_auth_pol_strs, g_cfg->auth_policy),
		VTY_NEWLINE);

	vty_out(vty, " gsup oap-id %d%s",
		(int)g_cfg->oap.client_id, VTY_NEWLINE);
	if (g_cfg->oap.secret_k_present != 0)
		vty_out(vty, " gsup oap-k %s%s",
			osmo_hexdump_nospc(g_cfg->oap.secret_k, sizeof(g_cfg->oap.secret_k)),
			VTY_NEWLINE);
	if (g_cfg->oap.secret_opc_present != 0)
		vty_out(vty, " gsup oap-opc %s%s",
			osmo_hexdump_nospc(g_cfg->oap.secret_opc, sizeof(g_cfg->oap.secret_opc)),
			VTY_NEWLINE);

	llist_for_each_entry(acl, &g_cfg->imsi_acl, list)
		vty_out(vty, " imsi-acl add %s%s", acl->imsi, VTY_NEWLINE);

	if (llist_empty(&sgsn_apn_ctxts))
		vty_out(vty, " ! apn * ggsn 0%s", VTY_NEWLINE);
	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		if (strlen(actx->imsi_prefix) > 0)
			vty_out(vty, " apn %s imsi-prefix %s ggsn %u%s",
				actx->name, actx->imsi_prefix, actx->ggsn->id,
				VTY_NEWLINE);
		else
			vty_out(vty, " apn %s ggsn %u%s", actx->name,
				actx->ggsn->id, VTY_NEWLINE);
	}

	if (g_cfg->cdr.filename)
		vty_out(vty, " cdr filename %s%s", g_cfg->cdr.filename, VTY_NEWLINE);
	else
		vty_out(vty, " no cdr filename%s", VTY_NEWLINE);
	vty_out(vty, " cdr interval %d%s", g_cfg->cdr.interval, VTY_NEWLINE);

	vty_out(vty, " timer t3312 %d%s", g_cfg->timers.T3312, VTY_NEWLINE);
	vty_out(vty, " timer t3322 %d%s", g_cfg->timers.T3322, VTY_NEWLINE);
	vty_out(vty, " timer t3350 %d%s", g_cfg->timers.T3350, VTY_NEWLINE);
	vty_out(vty, " timer t3360 %d%s", g_cfg->timers.T3360, VTY_NEWLINE);
	vty_out(vty, " timer t3370 %d%s", g_cfg->timers.T3370, VTY_NEWLINE);
	vty_out(vty, " timer t3313 %d%s", g_cfg->timers.T3313, VTY_NEWLINE);
	vty_out(vty, " timer t3314 %d%s", g_cfg->timers.T3314, VTY_NEWLINE);
	vty_out(vty, " timer t3316 %d%s", g_cfg->timers.T3316, VTY_NEWLINE);
	vty_out(vty, " timer t3385 %d%s", g_cfg->timers.T3385, VTY_NEWLINE);
	vty_out(vty, " timer t3386 %d%s", g_cfg->timers.T3386, VTY_NEWLINE);
	vty_out(vty, " timer t3395 %d%s", g_cfg->timers.T3395, VTY_NEWLINE);
	vty_out(vty, " timer t3397 %d%s", g_cfg->timers.T3397, VTY_NEWLINE);

	if (g_cfg->pcomp_rfc1144.active) {
		vty_out(vty, " compression rfc1144 active slots %d%s",
			g_cfg->pcomp_rfc1144.s01 + 1, VTY_NEWLINE);
	} else if (g_cfg->pcomp_rfc1144.passive) {
		vty_out(vty, " compression rfc1144 passive%s", VTY_NEWLINE);
	} else
		vty_out(vty, " no compression rfc1144%s", VTY_NEWLINE);

	if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 1) {
		vty_out(vty,
			" compression v42bis active direction sgsn codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 2) {
		vty_out(vty,
			" compression v42bis active direction ms codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 3) {
		vty_out(vty,
			" compression v42bis active direction both codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.passive) {
		vty_out(vty, " compression v42bis passive%s", VTY_NEWLINE);
	} else
		vty_out(vty, " no compression v42bis%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

#define SGSN_STR	"Configure the SGSN\n"
#define GGSN_STR	"Configure the GGSN information\n"

DEFUN(cfg_sgsn, cfg_sgsn_cmd,
	"sgsn",
	SGSN_STR)
{
	vty->node = SGSN_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn_bind_addr, cfg_sgsn_bind_addr_cmd,
	"gtp local-ip A.B.C.D",
	"GTP Parameters\n"
	"Set the IP address for the local GTP bind\n"
	"IPv4 Address\n")
{
	inet_aton(argv[0], &g_cfg->gtp_listenaddr.sin_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_remote_ip, cfg_ggsn_remote_ip_cmd,
	"ggsn <0-255> remote-ip A.B.C.D",
	GGSN_STR "GGSN Number\n" IP_STR "IPv4 Address\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	inet_aton(argv[1], &ggc->remote_addr);

	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_ggsn_remote_port, cfg_ggsn_remote_port_cmd,
	"ggsn <0-255> remote-port <0-65535>",
	"")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);
	uint16_t port = atoi(argv[1]);

}
#endif

DEFUN(cfg_ggsn_gtp_version, cfg_ggsn_gtp_version_cmd,
	"ggsn <0-255> gtp-version (0|1)",
	GGSN_STR "GGSN Number\n" "GTP Version\n"
	"Version 0\n" "Version 1\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	if (atoi(argv[1]))
		ggc->gtp_version = 1;
	else
		ggc->gtp_version = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_dynamic_lookup, cfg_ggsn_dynamic_lookup_cmd,
	"ggsn dynamic",
	GGSN_STR "Enable dynamic GRX based look-up (requires restart)\n")
{
	sgsn->cfg.dynamic_lookup = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_grx_ggsn, cfg_grx_ggsn_cmd,
	"grx-dns-add A.B.C.D",
	"Add DNS server\nIPv4 address\n")
{
	struct ares_addr_node *node = talloc_zero(tall_bsc_ctx, struct ares_addr_node);
	node->family = AF_INET;
	inet_aton(argv[0], &node->addr.addr4);

	node->next = sgsn->ares_servers;
	sgsn->ares_servers = node;
	return CMD_SUCCESS;
}

#define APN_STR	"Configure the information per APN\n"
#define APN_GW_STR "The APN gateway name optionally prefixed by '*' (wildcard)\n"

static int add_apn_ggsn_mapping(struct vty *vty, const char *apn_str,
				const char *imsi_prefix, int ggsn_id)
{
	struct apn_ctx *actx;
	struct sgsn_ggsn_ctx *ggsn;

	ggsn = sgsn_ggsn_ctx_by_id(ggsn_id);
	if (ggsn == NULL) {
		vty_out(vty, "%% a GGSN with id %d has not been defined%s",
			ggsn_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	actx = sgsn_apn_ctx_find_alloc(apn_str, imsi_prefix);
	if (!actx) {
		vty_out(vty, "%% unable to create APN context for %s/%s%s",
			apn_str, imsi_prefix, VTY_NEWLINE);
		return CMD_WARNING;
	}

	actx->ggsn = ggsn;

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ggsn, cfg_apn_ggsn_cmd,
	"apn APNAME ggsn <0-255>",
	APN_STR APN_GW_STR
	"Select the GGSN to use when the APN gateway prefix matches\n"
	"The GGSN id")
{

	return add_apn_ggsn_mapping(vty, argv[0], "", atoi(argv[1]));
}

DEFUN(cfg_apn_imsi_ggsn, cfg_apn_imsi_ggsn_cmd,
	"apn APNAME imsi-prefix IMSIPRE ggsn <0-255>",
	APN_STR APN_GW_STR
	"Restrict rule to a certain IMSI prefix\n"
	"An IMSI prefix\n"
	"Select the GGSN to use when APN gateway and IMSI prefix match\n"
	"The GGSN id")
{

	return add_apn_ggsn_mapping(vty, argv[0], argv[1], atoi(argv[2]));
}

const struct value_string gprs_mm_st_strs[] = {
	{ GMM_DEREGISTERED, "DEREGISTERED" },
	{ GMM_COMMON_PROC_INIT, "COMMON PROCEDURE (INIT)" },
	{ GMM_REGISTERED_NORMAL, "REGISTERED (NORMAL)" },
	{ GMM_REGISTERED_SUSPENDED, "REGISTERED (SUSPENDED)" },
	{ GMM_DEREGISTERED_INIT, "DEREGISTERED (INIT)" },
	{ 0, NULL }
};

static char *gtp_ntoa(struct ul16_t *ul)
{
	if (ul->l == 4) {
		struct in_addr *ia = (struct in_addr *) ul;
		return inet_ntoa(*ia);
	} else {
		return "UNKNOWN";
	}
}

static void vty_dump_pdp(struct vty *vty, const char *pfx,
			 struct sgsn_pdp_ctx *pdp)
{
	const char *imsi = pdp->mm ? pdp->mm->imsi : "(detaching)";
	vty_out(vty, "%sPDP Context IMSI: %s, SAPI: %u, NSAPI: %u, TI: %u%s",
		pfx, imsi, pdp->sapi, pdp->nsapi, pdp->ti, VTY_NEWLINE);
	vty_out(vty, "%s  APN: %s%s", pfx,
		gprs_apn2str(pdp->lib->apn_use.v, pdp->lib->apn_use.l),
		VTY_NEWLINE);
	vty_out(vty, "%s  PDP Address: %s%s", pfx,
		gprs_pdpaddr2str(pdp->lib->eua.v, pdp->lib->eua.l),
		VTY_NEWLINE);
	vty_out(vty, "%s  GTP Local Control(%s / TEIC: 0x%08x) ", pfx,
		gtp_ntoa(&pdp->lib->gsnlc), pdp->lib->teic_own);
	vty_out(vty, "Data(%s / TEID: 0x%08x)%s",
		gtp_ntoa(&pdp->lib->gsnlu), pdp->lib->teid_own, VTY_NEWLINE);
	vty_out(vty, "%s  GTP Remote Control(%s / TEIC: 0x%08x) ", pfx,
		gtp_ntoa(&pdp->lib->gsnrc), pdp->lib->teic_gn);
	vty_out(vty, "Data(%s / TEID: 0x%08x)%s",
		gtp_ntoa(&pdp->lib->gsnru), pdp->lib->teid_gn, VTY_NEWLINE);

	vty_out_rate_ctr_group(vty, " ", pdp->ctrg);
}

static void vty_dump_mmctx(struct vty *vty, const char *pfx,
			   struct sgsn_mm_ctx *mm, int pdp)
{
	vty_out(vty, "%sMM Context for IMSI %s, IMEI %s, P-TMSI %08x%s",
		pfx, mm->imsi, mm->imei, mm->p_tmsi, VTY_NEWLINE);
	vty_out(vty, "%s  MSISDN: %s, TLLI: %08x%s HLR: %s",
		pfx, mm->msisdn, mm->gb.tlli, mm->hlr, VTY_NEWLINE);
	vty_out(vty, "%s  MM State: %s, Routeing Area: %u-%u-%u-%u, "
		"Cell ID: %u%s", pfx,
		get_value_string(gprs_mm_st_strs, mm->gmm_state),
		mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac,
		mm->gb.cell_id, VTY_NEWLINE);

	vty_out_rate_ctr_group(vty, " ", mm->ctrg);

	if (pdp) {
		struct sgsn_pdp_ctx *pdp;

		llist_for_each_entry(pdp, &mm->pdp_list, list)
			vty_dump_pdp(vty, "  ", pdp);
	}
}

DEFUN(show_sgsn, show_sgsn_cmd, "show sgsn",
      SHOW_STR "Display information about the SGSN")
{
	if (sgsn->gsup_client) {
		struct ipa_client_conn *link = sgsn->gsup_client->link;
		vty_out(vty,
			"  Remote authorization: %sconnected to %s:%d via GSUP%s",
			sgsn->gsup_client->is_connected ? "" : "not ",
			link->addr, link->port,
			VTY_NEWLINE);
	}
	/* FIXME: statistics */
	return CMD_SUCCESS;
}

#define MMCTX_STR "MM Context\n"
#define INCLUDE_PDP_STR "Include PDP Context Information\n"

#if 0
DEFUN(show_mmctx_tlli, show_mmctx_tlli_cmd,
	"show mm-context tlli HEX [pdp]",
	SHOW_STR MMCTX_STR "Identify by TLLI\n" "TLLI\n" INCLUDE_PDP_STR)
{
	uint32_t tlli;
	struct sgsn_mm_ctx *mm;

	tlli = strtoul(argv[0], NULL, 16);
	mm = sgsn_mm_ctx_by_tlli(tlli);
	if (!mm) {
		vty_out(vty, "No MM context for TLLI %08x%s",
			tlli, VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_dump_mmctx(vty, "", mm, argv[1] ? 1 : 0);
	return CMD_SUCCESS;
}
#endif

DEFUN(swow_mmctx_imsi, show_mmctx_imsi_cmd,
	"show mm-context imsi IMSI [pdp]",
	SHOW_STR MMCTX_STR "Identify by IMSI\n" "IMSI of the MM Context\n"
	INCLUDE_PDP_STR)
{
	struct sgsn_mm_ctx *mm;

	mm = sgsn_mm_ctx_by_imsi(argv[0]);
	if (!mm) {
		vty_out(vty, "No MM context for IMSI %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_dump_mmctx(vty, "", mm, argv[1] ? 1 : 0);
	return CMD_SUCCESS;
}

DEFUN(swow_mmctx_all, show_mmctx_all_cmd,
	"show mm-context all [pdp]",
	SHOW_STR MMCTX_STR "All MM Contexts\n" INCLUDE_PDP_STR)
{
	struct sgsn_mm_ctx *mm;

	llist_for_each_entry(mm, &sgsn_mm_ctxts, list)
		vty_dump_mmctx(vty, "", mm, argv[0] ? 1 : 0);

	return CMD_SUCCESS;
}

DEFUN(show_pdpctx_all, show_pdpctx_all_cmd,
	"show pdp-context all",
	SHOW_STR "Display information on PDP Context\n" "Show everything\n")
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &sgsn_pdp_ctxts, g_list)
		vty_dump_pdp(vty, "", pdp);

	return CMD_SUCCESS;
}


DEFUN(imsi_acl, cfg_imsi_acl_cmd,
	"imsi-acl (add|del) IMSI",
	"Access Control List of foreign IMSIs\n"
	"Add IMSI to ACL\n"
	"Remove IMSI from ACL\n"
	"IMSI of subscriber\n")
{
	char imsi_sanitized[GSM23003_IMSI_MAX_DIGITS+1];
	const char *op = argv[0];
	const char *imsi = imsi_sanitized;
	int rc;

	/* Sanitize IMSI */
	if (strlen(argv[1]) > GSM23003_IMSI_MAX_DIGITS) {
		vty_out(vty, "%% IMSI (%s) too long -- ignored!%s",
			argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	memset(imsi_sanitized, '0', sizeof(imsi_sanitized));
	strcpy(imsi_sanitized+GSM23003_IMSI_MAX_DIGITS-strlen(argv[1]),argv[1]);

	if (!strcmp(op, "add"))
		rc = sgsn_acl_add(imsi, g_cfg);
	else
		rc = sgsn_acl_del(imsi, g_cfg);

	if (rc < 0) {
		vty_out(vty, "%% unable to %s ACL%s", op, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_encrypt, cfg_encrypt_cmd,
      "encryption (GEA0|GEA1|GEA2|GEA3|GEA4)",
      "Set encryption algorithm for SGSN\n"
      "Use GEA0 (no encryption)\n"
      "Use GEA1\nUse GEA2\nUse GEA3\nUse GEA4\n")
{
	enum gprs_ciph_algo c = get_string_value(gprs_cipher_names, argv[0]);
	if (c != GPRS_ALGO_GEA0) {
		if (!gprs_cipher_supported(c)) {
			vty_out(vty, "%% cipher %s is unsupported in current version%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		if (!g_cfg->require_authentication) {
			vty_out(vty, "%% unable to use encryption %s without authentication: please adjust auth-policy%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	g_cfg->cipher = c;

	return CMD_SUCCESS;
}

DEFUN(cfg_auth_policy, cfg_auth_policy_cmd,
	"auth-policy (accept-all|closed|acl-only|remote)",
	"Autorization Policy of SGSN\n"
	"Accept all IMSIs (DANGEROUS)\n"
	"Accept only home network subscribers or those in the ACL\n"
	"Accept only subscribers in the ACL\n"
	"Use remote subscription data only (HLR)\n")
{
	int val = get_string_value(sgsn_auth_pol_strs, argv[0]);
	OSMO_ASSERT(val >= SGSN_AUTH_POLICY_OPEN && val <= SGSN_AUTH_POLICY_REMOTE);
	g_cfg->auth_policy = val;
	g_cfg->require_authentication = (val == SGSN_AUTH_POLICY_REMOTE);
	g_cfg->require_update_location = (val == SGSN_AUTH_POLICY_REMOTE);

	return CMD_SUCCESS;
}

/* Subscriber */
#include <openbsc/gprs_subscriber.h>

static void subscr_dump_full_vty(struct vty *vty, struct gprs_subscr *gsub, int pending)
{
#if 0
	char expire_time[200];
#endif
	struct gsm_auth_tuple *at;
	int at_idx;
	struct sgsn_subscriber_pdp_data *pdp;

	vty_out(vty, "    Authorized: %d%s",
		gsub->authorized, VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		gsub->lac, gsub->lac, VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", gsub->imsi, VTY_NEWLINE);
	if (gsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", gsub->tmsi,
			VTY_NEWLINE);
	if (gsub->sgsn_data->msisdn_len > 0)
		vty_out(vty, "    MSISDN (BCD): %s%s",
			osmo_hexdump(gsub->sgsn_data->msisdn,
				     gsub->sgsn_data->msisdn_len),
			VTY_NEWLINE);

	if (strlen(gsub->imei) > 0)
		vty_out(vty, "    IMEI: %s%s", gsub->imei, VTY_NEWLINE);

	for (at_idx = 0; at_idx < ARRAY_SIZE(gsub->sgsn_data->auth_triplets);
	     at_idx++) {
		at = &gsub->sgsn_data->auth_triplets[at_idx];
		if (at->key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		vty_out(vty, "    A3A8 tuple (used %d times): ",
			at->use_count);
		vty_out(vty, "     CKSN: %d, ",
			at->key_seq);
		if (at->vec.auth_types & OSMO_AUTH_TYPE_GSM) {
			vty_out(vty, "RAND: %s, ",
				osmo_hexdump(at->vec.rand,
					     sizeof(at->vec.rand)));
			vty_out(vty, "SRES: %s, ",
				osmo_hexdump(at->vec.sres,
					     sizeof(at->vec.sres)));
			vty_out(vty, "Kc: %s%s",
				osmo_hexdump(at->vec.kc,
					     sizeof(at->vec.kc)), VTY_NEWLINE);
		}
		if (at->vec.auth_types & OSMO_AUTH_TYPE_UMTS) {
			vty_out(vty, "     AUTN: %s, ",
				osmo_hexdump(at->vec.autn,
					     sizeof(at->vec.autn)));
			vty_out(vty, "RES: %s, ",
				osmo_hexdump(at->vec.res, at->vec.res_len));
			vty_out(vty, "IK: %s, ",
				osmo_hexdump(at->vec.ik, sizeof(at->vec.ik)));
			vty_out(vty, "CK: %s, ",
				osmo_hexdump(at->vec.ck, sizeof(at->vec.ck)));
		}
	}

	llist_for_each_entry(pdp, &gsub->sgsn_data->pdp_list, list) {
		vty_out(vty, "    PDP info: Id: %d, Type: 0x%04x, APN: '%s' QoS: %s%s",
			pdp->context_id, pdp->pdp_type, pdp->apn_str,
			osmo_hexdump(pdp->qos_subscribed, pdp->qos_subscribed_len),
			VTY_NEWLINE);
	}

#if 0
	/* print the expiration time of a subscriber */
	if (gsub->expire_lu) {
		strftime(expire_time, sizeof(expire_time),
			 "%a, %d %b %Y %T %z", localtime(&gsub->expire_lu));
		expire_time[sizeof(expire_time) - 1] = '\0';
		vty_out(vty, "    Expiration Time: %s%s", expire_time, VTY_NEWLINE);
	}
#endif

	if (gsub->flags)
		vty_out(vty, "    Flags: %s%s%s%s%s%s",
			gsub->flags & GPRS_SUBSCRIBER_FIRST_CONTACT ?
			"FIRST_CONTACT " : "",
			gsub->flags & GPRS_SUBSCRIBER_CANCELLED ?
			"CANCELLED " : "",
			gsub->flags & GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING ?
			"UPDATE_LOCATION_PENDING " : "",
			gsub->flags & GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING ?
			"AUTH_INFO_PENDING " : "",
			gsub->flags & GPRS_SUBSCRIBER_ENABLE_PURGE ?
			"ENABLE_PURGE " : "",
			VTY_NEWLINE);

	vty_out(vty, "    Use count: %u%s", gsub->use_count, VTY_NEWLINE);
}

DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Show information about subscribers\n"
	"Display contents of subscriber cache\n")
{
	struct gprs_subscr *subscr;

	llist_for_each_entry(subscr, gprs_subscribers, entry) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, subscr, 0);
	}

	return CMD_SUCCESS;
}

#define UPDATE_SUBSCR_STR "update-subscriber imsi IMSI "
#define UPDATE_SUBSCR_HELP "Update subscriber list\n" \
	"Use the IMSI to select the subscriber\n" \
	"The IMSI\n"

#define UPDATE_SUBSCR_INSERT_HELP "Insert data into the subscriber record\n"

DEFUN(update_subscr_insert_auth_triplet, update_subscr_insert_auth_triplet_cmd,
	UPDATE_SUBSCR_STR "insert auth-triplet <1-5> sres SRES rand RAND kc KC",
	UPDATE_SUBSCR_HELP
	UPDATE_SUBSCR_INSERT_HELP
	"Update authentication triplet\n"
	"Triplet index\n"
	"Set SRES value\nSRES value (4 byte) in hex\n"
	"Set RAND value\nRAND value (16 byte) in hex\n"
	"Set Kc value\nKc value (8 byte) in hex\n")
{
	const char *imsi = argv[0];
	const int cksn = atoi(argv[1]) - 1;
	const char *sres_str = argv[2];
	const char *rand_str = argv[3];
	const char *kc_str = argv[4];
	struct gsm_auth_tuple at = {0,};

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	OSMO_ASSERT(subscr->sgsn_data);

	if (osmo_hexparse(sres_str, &at.vec.sres[0], sizeof(at.vec.sres)) < 0) {
		vty_out(vty, "%% invalid SRES value '%s'%s",
			sres_str, VTY_NEWLINE);
		goto failed;
	}
	if (osmo_hexparse(rand_str, &at.vec.rand[0], sizeof(at.vec.rand)) < 0) {
		vty_out(vty, "%% invalid RAND value '%s'%s",
			rand_str, VTY_NEWLINE);
		goto failed;
	}
	if (osmo_hexparse(kc_str, &at.vec.kc[0], sizeof(at.vec.kc)) < 0) {
		vty_out(vty, "%% invalid Kc value '%s'%s",
			kc_str, VTY_NEWLINE);
		goto failed;
	}
	at.key_seq = cksn;

	subscr->sgsn_data->auth_triplets[cksn] = at;
	subscr->sgsn_data->auth_triplets_updated = 1;

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;

failed:
	gprs_subscr_put(subscr);
	return CMD_SUCCESS;
}

DEFUN(update_subscr_cancel, update_subscr_cancel_cmd,
	UPDATE_SUBSCR_STR "cancel (update-procedure|subscription-withdraw)",
	UPDATE_SUBSCR_HELP
	"Cancel (remove) subscriber record\n"
	"The MS moved to another SGSN\n"
	"The subscription is no longer valid\n")
{
	const char *imsi = argv[0];
	const char *cancel_type = argv[1];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% no subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(cancel_type, "update-procedure") == 0)
		subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	else
		subscr->sgsn_data->error_cause = GMM_CAUSE_IMPL_DETACHED;

	gprs_subscr_cancel(subscr);
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_create, update_subscr_create_cmd,
	UPDATE_SUBSCR_STR "create",
	UPDATE_SUBSCR_HELP
	"Create a subscriber entry\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (subscr) {
		vty_out(vty, "%% subscriber record already exists for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr = gprs_subscr_get_or_create(imsi);
	subscr->keep_in_ram = 1;
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_destroy, update_subscr_destroy_cmd,
	UPDATE_SUBSCR_STR "destroy",
	UPDATE_SUBSCR_HELP
	"Destroy a subscriber entry\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% subscriber record does not exist for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr->keep_in_ram = 0;
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_cancel(subscr);
	if (subscr->use_count > 1)
		vty_out(vty, "%% subscriber is still in use%s",
			VTY_NEWLINE);
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

#define UL_ERR_STR "system-failure|data-missing|unexpected-data-value|" \
		   "unknown-subscriber|roaming-not-allowed"

#define UL_ERR_HELP \
		"Force error code SystemFailure\n" \
		"Force error code DataMissing\n" \
		"Force error code UnexpectedDataValue\n" \
		"Force error code UnknownSubscriber\n" \
		"Force error code RoamingNotAllowed\n"

DEFUN(update_subscr_update_location_result, update_subscr_update_location_result_cmd,
	UPDATE_SUBSCR_STR "update-location-result (ok|" UL_ERR_STR ")",
	UPDATE_SUBSCR_HELP
	"Complete the update location procedure\n"
	"The update location request succeeded\n"
	UL_ERR_HELP)
{
	const char *imsi = argv[0];
	const char *ret_code_str = argv[1];

	struct gprs_subscr *subscr;

	const struct value_string cause_mapping[] = {
		{ GMM_CAUSE_NET_FAIL,		"system-failure" },
		{ GMM_CAUSE_INV_MAND_INFO,	"data-missing" },
		{ GMM_CAUSE_PROTO_ERR_UNSPEC,   "unexpected-data-value" },
		{ GMM_CAUSE_IMSI_UNKNOWN,       "unknown-subscriber" },
		{ GMM_CAUSE_GPRS_NOTALLOWED,    "roaming-not-allowed" },
		{ 0, NULL }
	};

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable to get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(ret_code_str, "ok") == 0) {
		subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
		subscr->authorized = 1;
	} else {
		subscr->sgsn_data->error_cause =
			get_string_value(cause_mapping, ret_code_str);
		subscr->authorized = 0;
	}

	gprs_subscr_update(subscr);

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_update_auth_info, update_subscr_update_auth_info_cmd,
	UPDATE_SUBSCR_STR "update-auth-info",
	UPDATE_SUBSCR_HELP
	"Complete the send authentication info procedure\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable to get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_subscr_update_auth_info(subscr);

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_remote_ip, cfg_gsup_remote_ip_cmd,
	"gsup remote-ip A.B.C.D",
	"GSUP Parameters\n"
	"Set the IP address of the remote GSUP server\n"
	"IPv4 Address\n")
{
	inet_aton(argv[0], &g_cfg->gsup_server_addr.sin_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_remote_port, cfg_gsup_remote_port_cmd,
	"gsup remote-port <0-65535>",
	"GSUP Parameters\n"
	"Set the TCP port of the remote GSUP server\n"
	"Remote TCP port\n")
{
	g_cfg->gsup_server_port = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_id, cfg_gsup_oap_id_cmd,
	"gsup oap-id <0-65535>",
	"GSUP Parameters\n"
	"Set the SGSN's OAP client ID\nOAP client ID (0 == disabled)\n")
{
	/* VTY ensures range */
	g_cfg->oap.client_id = (uint16_t)atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_k, cfg_gsup_oap_k_cmd,
	"gsup oap-k K",
	"GSUP Parameters\n"
	"Set the OAP shared secret K\nK value (16 byte) hex\n")
{
	const char *k = argv[0];

	g_cfg->oap.secret_k_present = 0;

	if ((!k) || (strlen(k) == 0))
		goto disable;

	int k_len = osmo_hexparse(k,
				  g_cfg->oap.secret_k,
				  sizeof(g_cfg->oap.secret_k));
	if (k_len != 16) {
		vty_out(vty, "%% need exactly 16 octets for oap-k, got %d.%s",
			k_len, VTY_NEWLINE);
		goto disable;
	}

	g_cfg->oap.secret_k_present = 1;
	return CMD_SUCCESS;

disable:
	if (g_cfg->oap.client_id > 0) {
		vty_out(vty, "%% OAP client ID set, but invalid oap-k value disables OAP.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_opc, cfg_gsup_oap_opc_cmd,
	"gsup oap-opc OPC",
	"GSUP Parameters\n"
	"Set the OAP shared secret OPC\nOPC value (16 byte) hex\n")
{
	const char *opc = argv[0];

	g_cfg->oap.secret_opc_present = 0;

	if ((!opc) || (strlen(opc) == 0))
		goto disable;

	int opc_len = osmo_hexparse(opc,
				    g_cfg->oap.secret_opc,
				    sizeof(g_cfg->oap.secret_opc));
	if (opc_len != 16) {
		vty_out(vty, "%% need exactly 16 octets for oap-opc, got %d.%s",
			opc_len, VTY_NEWLINE);
		goto disable;
	}

	g_cfg->oap.secret_opc_present = 1;
	return CMD_SUCCESS;

disable:
	if (g_cfg->oap.client_id > 0) {
		vty_out(vty, "%% OAP client ID set, but invalid oap-opc value disables OAP.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_name, cfg_apn_name_cmd,
	"access-point-name NAME",
	"Configure a global list of allowed APNs\n"
	"Add this NAME to the list\n")
{
	return add_apn_ggsn_mapping(vty, argv[0], "", 0);
}

DEFUN(cfg_no_apn_name, cfg_no_apn_name_cmd,
	"no access-point-name NAME",
	NO_STR "Configure a global list of allowed APNs\n"
	"Remove entry with NAME\n")
{
	struct apn_ctx *apn_ctx = sgsn_apn_ctx_by_name(argv[0], "");
	if (!apn_ctx)
		return CMD_SUCCESS;

	sgsn_apn_ctx_free(apn_ctx);
	return CMD_SUCCESS;
}

DEFUN(cfg_cdr_filename, cfg_cdr_filename_cmd,
	"cdr filename NAME",
	"CDR\nSet filename\nname\n")
{
	talloc_free(g_cfg->cdr.filename);
	g_cfg->cdr.filename = talloc_strdup(tall_vty_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_cdr_filename, cfg_no_cdr_filename_cmd,
	"no cdr filename",
	NO_STR "CDR\nDisable CDR generation\n")
{
	talloc_free(g_cfg->cdr.filename);
	g_cfg->cdr.filename = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_cdr_interval, cfg_cdr_interval_cmd,
	"cdr interval <1-2147483647>",
	"CDR\nPDP periodic log interval\nSeconds\n")
{
	g_cfg->cdr.interval = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define COMPRESSION_STR "Configure compression\n"
DEFUN(cfg_no_comp_rfc1144, cfg_no_comp_rfc1144_cmd,
      "no compression rfc1144",
      NO_STR COMPRESSION_STR "disable rfc1144 TCP/IP header compression\n")
{
	g_cfg->pcomp_rfc1144.active = 0;
	g_cfg->pcomp_rfc1144.passive = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_rfc1144, cfg_comp_rfc1144_cmd,
      "compression rfc1144 active slots <1-256>",
      COMPRESSION_STR
      "RFC1144 Header compresion scheme\n"
      "Compression is actively proposed\n"
      "Number of compression state slots\n"
      "Number of compression state slots\n")
{
	g_cfg->pcomp_rfc1144.active = 1;
	g_cfg->pcomp_rfc1144.passive = 1;
	g_cfg->pcomp_rfc1144.s01 = atoi(argv[0]) - 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_rfc1144p, cfg_comp_rfc1144p_cmd,
      "compression rfc1144 passive",
      COMPRESSION_STR
      "RFC1144 Header compresion scheme\n"
      "Compression is available on request\n")
{
	g_cfg->pcomp_rfc1144.active = 0;
	g_cfg->pcomp_rfc1144.passive = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_comp_v42bis, cfg_no_comp_v42bis_cmd,
      "no compression v42bis",
      NO_STR COMPRESSION_STR "disable V.42bis data compression\n")
{
	g_cfg->dcomp_v42bis.active = 0;
	g_cfg->dcomp_v42bis.passive = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_v42bis, cfg_comp_v42bis_cmd,
      "compression v42bis active direction (ms|sgsn|both) codewords <512-65535> strlen <6-250>",
      COMPRESSION_STR
      "V.42bis data compresion scheme\n"
      "Compression is actively proposed\n"
      "Direction in which the compression shall be active (p0)\n"
      "Compress ms->sgsn direction only\n"
      "Compress sgsn->ms direction only\n"
      "Both directions\n"
      "Number of codewords (p1)\n"
      "Number of codewords\n"
      "Maximum string length (p2)\n" "Maximum string length\n")
{
	g_cfg->dcomp_v42bis.active = 1;
	g_cfg->dcomp_v42bis.passive = 1;

	switch (argv[0][0]) {
	case 'm':
		g_cfg->dcomp_v42bis.p0 = 1;
		break;
	case 's':
		g_cfg->dcomp_v42bis.p0 = 2;
		break;
	case 'b':
		g_cfg->dcomp_v42bis.p0 = 3;
		break;
	}

	g_cfg->dcomp_v42bis.p1 = atoi(argv[1]);
	g_cfg->dcomp_v42bis.p2 = atoi(argv[2]);
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_v42bisp, cfg_comp_v42bisp_cmd,
      "compression v42bis passive",
      COMPRESSION_STR
      "V.42bis data compresion scheme\n"
      "Compression is available on request\n")
{
	g_cfg->dcomp_v42bis.active = 0;
	g_cfg->dcomp_v42bis.passive = 1;
	return CMD_SUCCESS;
}

int sgsn_vty_init(void)
{
	install_element_ve(&show_sgsn_cmd);
	//install_element_ve(&show_mmctx_tlli_cmd);
	install_element_ve(&show_mmctx_imsi_cmd);
	install_element_ve(&show_mmctx_all_cmd);
	install_element_ve(&show_pdpctx_all_cmd);
	install_element_ve(&show_subscr_cache_cmd);

	install_element(ENABLE_NODE, &update_subscr_insert_auth_triplet_cmd);
	install_element(ENABLE_NODE, &update_subscr_create_cmd);
	install_element(ENABLE_NODE, &update_subscr_destroy_cmd);
	install_element(ENABLE_NODE, &update_subscr_cancel_cmd);
	install_element(ENABLE_NODE, &update_subscr_update_location_result_cmd);
	install_element(ENABLE_NODE, &update_subscr_update_auth_info_cmd);

	install_element(CONFIG_NODE, &cfg_sgsn_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	vty_install_default(SGSN_NODE);
	install_element(SGSN_NODE, &cfg_sgsn_bind_addr_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_remote_ip_cmd);
	//install_element(SGSN_NODE, &cfg_ggsn_remote_port_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_gtp_version_cmd);
	install_element(SGSN_NODE, &cfg_imsi_acl_cmd);
	install_element(SGSN_NODE, &cfg_auth_policy_cmd);
	install_element(SGSN_NODE, &cfg_encrypt_cmd);
	install_element(SGSN_NODE, &cfg_gsup_remote_ip_cmd);
	install_element(SGSN_NODE, &cfg_gsup_remote_port_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_id_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_k_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_opc_cmd);
	install_element(SGSN_NODE, &cfg_apn_ggsn_cmd);
	install_element(SGSN_NODE, &cfg_apn_imsi_ggsn_cmd);
	install_element(SGSN_NODE, &cfg_apn_name_cmd);
	install_element(SGSN_NODE, &cfg_no_apn_name_cmd);
	install_element(SGSN_NODE, &cfg_cdr_filename_cmd);
	install_element(SGSN_NODE, &cfg_no_cdr_filename_cmd);
	install_element(SGSN_NODE, &cfg_cdr_interval_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_dynamic_lookup_cmd);
	install_element(SGSN_NODE, &cfg_grx_ggsn_cmd);

	install_element(SGSN_NODE, &cfg_sgsn_T3312_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3322_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3350_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3360_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3370_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3313_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3314_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3316_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3385_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3386_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3395_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_T3397_cmd);

	install_element(SGSN_NODE, &cfg_no_comp_rfc1144_cmd);
	install_element(SGSN_NODE, &cfg_comp_rfc1144_cmd);
	install_element(SGSN_NODE, &cfg_comp_rfc1144p_cmd);
	install_element(SGSN_NODE, &cfg_no_comp_v42bis_cmd);
	install_element(SGSN_NODE, &cfg_comp_v42bis_cmd);
	install_element(SGSN_NODE, &cfg_comp_v42bisp_cmd);
	return 0;
}

int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg)
{
	int rc;

	g_cfg = cfg;

	g_cfg->timers.T3312 = GSM0408_T3312_SECS;
	g_cfg->timers.T3322 = GSM0408_T3322_SECS;
	g_cfg->timers.T3350 = GSM0408_T3350_SECS;
	g_cfg->timers.T3360 = GSM0408_T3360_SECS;
	g_cfg->timers.T3370 = GSM0408_T3370_SECS;
	g_cfg->timers.T3313 = GSM0408_T3313_SECS;
	g_cfg->timers.T3314 = GSM0408_T3314_SECS;
	g_cfg->timers.T3316 = GSM0408_T3316_SECS;
	g_cfg->timers.T3385 = GSM0408_T3385_SECS;
	g_cfg->timers.T3386 = GSM0408_T3386_SECS;
	g_cfg->timers.T3395 = GSM0408_T3395_SECS;
	g_cfg->timers.T3397 = GSM0408_T3397_SECS;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	if (g_cfg->auth_policy == SGSN_AUTH_POLICY_REMOTE
	    && !(g_cfg->gsup_server_addr.sin_addr.s_addr
		 && g_cfg->gsup_server_port)) {
		fprintf(stderr, "Configuration error:"
			" 'auth-policy remote' requires both"
			" 'gsup remote-ip' and 'gsup remote-port'\n");
		return -EINVAL;
	}

	return 0;
}
