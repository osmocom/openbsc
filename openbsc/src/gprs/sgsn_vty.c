/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>

#include <openbsc/debug.h>
#include <openbsc/sgsn.h>
#include <osmocom/gprs/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/vty.h>
#include <openbsc/gsm_04_08_gprs.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

#include <pdp.h>

static struct sgsn_config *g_cfg = NULL;


#define GSM48_MAX_APN_LEN	102	/* 10.5.6.1 */
static char *gprs_apn2str(uint8_t *apn, unsigned int len)
{
	static char apnbuf[GSM48_MAX_APN_LEN+1];
	unsigned int i;

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

static char *gprs_pdpaddr2str(uint8_t *pdpa, uint8_t len)
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

	vty_out(vty, "sgsn%s", VTY_NEWLINE);

	vty_out(vty, " gtp local-ip %s%s",
		inet_ntoa(g_cfg->gtp_listenaddr.sin_addr), VTY_NEWLINE);

	llist_for_each_entry(gctx, &sgsn_ggsn_ctxts, list) {
		vty_out(vty, " ggsn %u remote-ip %s%s", gctx->id,
			inet_ntoa(gctx->remote_addr), VTY_NEWLINE);
		vty_out(vty, " ggsn %u gtp-version %u%s", gctx->id,
			gctx->gtp_version, VTY_NEWLINE);
	}

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

#if 0
DEFUN(cfg_apn_ggsn, cfg_apn_ggsn_cmd,
	"apn APNAME ggsn <0-255>",
	"")
{
	struct apn_ctx **
}
#endif

const struct value_string gprs_mm_st_strs[] = {
	{ GMM_DEREGISTERED, "DEREGISTERED" },
	{ GMM_COMMON_PROC_INIT, "COMMON PROCEDURE (INIT)" },
	{ GMM_REGISTERED_NORMAL, "REGISTERED (NORMAL)" },
	{ GMM_REGISTERED_SUSPENDED, "REGISTERED (SUSPENDED)" },
	{ GMM_DEREGISTERED_INIT, "DEREGISTERED (INIT)" },
	{ 0, NULL }
};

static void vty_dump_pdp(struct vty *vty, const char *pfx,
			 struct sgsn_pdp_ctx *pdp)
{
	vty_out(vty, "%sPDP Context IMSI: %s, SAPI: %u, NSAPI: %u%s",
		pfx, pdp->mm->imsi, pdp->sapi, pdp->nsapi, VTY_NEWLINE);
	vty_out(vty, "%s  APN: %s%s", pfx,
		gprs_apn2str(pdp->lib->apn_use.v, pdp->lib->apn_use.l),
		VTY_NEWLINE);
	vty_out(vty, "%s  PDP Address: %s%s", pfx,
		gprs_pdpaddr2str(pdp->lib->eua.v, pdp->lib->eua.l),
		VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", pdp->ctrg);
}

static void vty_dump_mmctx(struct vty *vty, const char *pfx,
			   struct sgsn_mm_ctx *mm, int pdp)
{
	vty_out(vty, "%sMM Context for IMSI %s, IMEI %s, P-TMSI %08x%s",
		pfx, mm->imsi, mm->imei, mm->p_tmsi, VTY_NEWLINE);
	vty_out(vty, "%s  MSISDN: %s, TLLI: %08x%s", pfx, mm->msisdn,
		mm->tlli, VTY_NEWLINE);
	vty_out(vty, "%s  MM State: %s, Routeing Area: %u-%u-%u-%u, "
		"Cell ID: %u%s", pfx,
		get_value_string(gprs_mm_st_strs, mm->mm_state),
		mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac,
		mm->cell_id, VTY_NEWLINE);

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

DEFUN(show_ggsn, show_ggsn_cmd,
	"show ggsn",
	"")
{

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

int sgsn_vty_init(void)
{
	install_element_ve(&show_sgsn_cmd);
	//install_element_ve(&show_mmctx_tlli_cmd);
	install_element_ve(&show_mmctx_imsi_cmd);
	install_element_ve(&show_mmctx_all_cmd);
	install_element_ve(&show_pdpctx_all_cmd);

	install_element(CONFIG_NODE, &cfg_sgsn_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	install_default(SGSN_NODE);
	install_element(SGSN_NODE, &ournode_exit_cmd);
	install_element(SGSN_NODE, &ournode_end_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_bind_addr_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_remote_ip_cmd);
	//install_element(SGSN_NODE, &cfg_ggsn_remote_port_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_gtp_version_cmd);

	return 0;
}

int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg)
{
	int rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
