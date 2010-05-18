/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>
#include <osmocore/utils.h>

#include <openbsc/debug.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/vty.h>

#include <vty/command.h>
#include <vty/vty.h>

#include <pdp.h>

static struct sgsn_config *g_cfg = NULL;

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(sgsn)#",
	1,
};

static int config_write_sgsn(struct vty *vty)
{
	struct in_addr ia;
	struct sgsn_ggsn_ctx *gctx;

	vty_out(vty, "sgsn%s", VTY_NEWLINE);

	if (g_cfg->nsip_listen_ip) {
		ia.s_addr = htonl(g_cfg->nsip_listen_ip);
		vty_out(vty, "  nsip local ip %s%s", inet_ntoa(ia),
			VTY_NEWLINE);
	}
	vty_out(vty, "  nsip local port %u%s", g_cfg->nsip_listen_port,
		VTY_NEWLINE);

	llist_for_each_entry(gctx, &sgsn_ggsn_ctxts, list) {
		vty_out(vty, "  ggsn %u remote-ip %s%s", gctx->id,
			inet_ntoa(gctx->remote_addr), VTY_NEWLINE);
		vty_out(vty, "  ggsn %u gtp-version %u%s", gctx->id,
			gctx->gtp_version, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn,
      cfg_sgsn_cmd,
      "sgsn",
      "Configure the SGSN")
{
	vty->node = SGSN_NODE;
	return CMD_SUCCESS;
}


DEFUN(cfg_nsip_local_ip,
      cfg_nsip_local_ip_cmd,
      "nsip local ip A.B.C.D",
      "Set the IP address on which we listen for BSS connects")
{
	struct in_addr ia;

	inet_aton(argv[0], &ia);
	g_cfg->nsip_listen_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_local_port,
      cfg_nsip_local_port_cmd,
      "nsip local port <0-65534>",
      "Set the UDP port on which we listen for BSS connects")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_listen_port = port;

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_remote_ip, cfg_ggsn_remote_ip_cmd,
	"ggsn <0-255> remote-ip A.B.C.D",
	"")
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
	"")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);
	uint16_t port = atoi(argv[1]);

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
	{ GMM_REGISTERED_SUSPENDED, "REGISTeRED (SUSPENDED)" },
	{ GMM_DEREGISTERED_INIT, "DEREGISTERED (INIT)" },
	{ 0, NULL }
};

static void vty_dump_pdp(struct vty *vty, const char *pfx,
			 struct sgsn_pdp_ctx *pdp)
{
	vty_out(vty, "%sPDP Context IMSI: %s, SAPI: %u, NSAPI: %u%s",
		pfx, pdp->mm->imsi, pdp->sapi, pdp->nsapi, VTY_NEWLINE);
	vty_out(vty, "%s  APN: %s\n", pfx, pdp->lib->apn_use.v);
	/* FIXME: statistics */
	//vty_out_rate_ctr_group(vty, " ", pdp->ctrg);
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
	SHOW_STR "Display information on PDP Context\n")
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
	install_element(SGSN_NODE, &cfg_nsip_local_ip_cmd);
	install_element(SGSN_NODE, &cfg_nsip_local_port_cmd);
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
