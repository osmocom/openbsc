/* Osmo GANC VTY Configuration */
/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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


#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/vty.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/sccp/sccp.h>

#include <openbsc/osmo_bsc.h>

#include "ganc_data.h"
#include "conn.h"

const struct value_string ganc_state_names[] = {
	{ GA_S_CSR_IDLE, "Idle" },
	{ GA_S_CSR_DEDICATED, "Dedicated" },
	{ 0, NULL }
};

static void show_peer_table(struct vty *vty, struct gan_peer *peer,
			    struct timeval *now)
{
	struct timeval rem;
	int rc;

	rc = osmo_timer_remaining(&peer->keepalive_timer, NULL, &rem);
/*                   " 012345678901234 111.111.111.111 01234 012 1 1 262 010 01234 01234 ... */
#define PEER_TBL_HDR "            IMSI       Remote IP  Port Tka R S MCC MNC   LAC    CI AP Name%s"

	vty_out(vty, " %15s %15s %5u %3u %c %c %03u %03u %05u %05u %s%s",
		peer->imsi,
		peer->conn ? peer->conn->remote.host : "",
		peer->conn ? peer->conn->remote.port : 0,
		rc == 0 ? (int) rem.tv_sec : 0,
		peer->flags & GAN_PF_REGISTERED ? 'R' : '-',
		peer->csr_state == GA_S_CSR_DEDICATED ? 'D' : 'I',
		peer->ra_id.mcc, peer->ra_id.mnc, peer->ra_id.lac,
		peer->cell_id,
		peer->ap_serv_name ? peer->ap_serv_name : "",
		VTY_NEWLINE);

}

static char *print_mac(uint8_t *mac)
{
	static char mac_buf[6*3];

	if (!mac)
		return "-unknown-";

	snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	mac_buf[sizeof(mac_buf)-1] = '\0';

	return mac_buf;
}

static void show_peer(struct vty *vty, struct gan_peer *peer,
		      struct timeval *now)
{
	struct timeval rem;
	int rc;

	/* we determine the time once globally if we leave the select
	 * loop, and not for every peer we display */
	rc = osmo_timer_remaining(&peer->keepalive_timer, now, &rem);


	vty_out(vty, "IMSI: %s,  State: %s,  Timeout: %us,  LAC: %03u-%03u-%05u(%x)%s",
		peer->imsi, get_value_string(ganc_state_names, peer->csr_state),
		rc == 0 ? (int) rem.tv_sec : 0, peer->ra_id.mcc,
		peer->ra_id.mnc, peer->ra_id.lac, peer->ra_id.lac, VTY_NEWLINE);
	if (peer->conn) {
		struct osmo_conn *conn = peer->conn;
		vty_out(vty, " GAN MS Remote IP/Port: %s:%u%s",
			conn->remote.host, conn->remote.port, VTY_NEWLINE);
	}
	if (peer->ap_serv_name)
		vty_out(vty, " AP Service Name: `%s'%s",
			peer->ap_serv_name, VTY_NEWLINE);

	vty_out(vty, " MS Radio ID: %s,  ", print_mac(peer->ms_radio_id));
	vty_out(vty, " AP Radio ID: %s%s", print_mac(peer->ap_radio_id), VTY_NEWLINE);

	if (peer->bts) {
		struct ganc_bts *bts = peer->bts;
		vty_out(vty, " BTS: LAC=%u/0x%x RAC=%u/0x%x CI=%u/0x%x "
			"BSIC=%u ARFCN=%u%s",
			bts->location_area_code, bts->location_area_code,
			bts->routing_area_code, bts->routing_area_code,
			bts->cell_identity, bts->cell_identity,
			bts->bsic, bts->arfcn, VTY_NEWLINE);
		vty_out(vty, " SEGW: %s, GANC: %s:%u%s",
			bts->segw_host, bts->ganc_host, bts->ganc_port,
			VTY_NEWLINE);
	}

	if (peer->sccp_con) {
		if (peer->sccp_con->sccp) {
			struct sccp_connection *sccp = peer->sccp_con->sccp;

			vty_out(vty, " MSC SCCP Local Ref: %u, Dest Ref: %u%s",
				sccp_src_ref_to_int(&sccp->source_local_reference),
				sccp_src_ref_to_int(&sccp->destination_local_reference),
				VTY_NEWLINE);
		}
	}
}

DEFUN(show_gan_peer_det, show_gan_peer_det_cmd,
	"show gan-peer details",
	SHOW_STR "GANC Peers (MS attached to the GANC)")
{
	struct gan_peer *peer;
	struct timeval now;

	gettimeofday(&now, NULL);

	llist_for_each_entry(peer, &g_ganc_bts->net->peers, entry) {
		show_peer(vty, peer, &now);
		vty_out(vty, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


DEFUN(show_gan_peer, show_gan_peer_cmd,
	"show gan-peer",
	SHOW_STR "GANC Peers (MS attached to the GANC)")
{
	struct gan_peer *peer;
	struct timeval now;

	gettimeofday(&now, NULL);

	if (!llist_empty(&g_ganc_bts->net->peers))
		vty_out(vty, PEER_TBL_HDR, VTY_NEWLINE);

	llist_for_each_entry(peer, &g_ganc_bts->net->peers, entry)
		show_peer_table(vty, peer, &now);

	return CMD_SUCCESS;
}

struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(network)# ",
	1,
};

DEFUN(cfg_network, cfg_network_cmd,
	"network",
	"Configure the GSM Network")
{
	vty->index = g_ganc_net;
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	vty_out(vty, "network%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

struct cmd_node bts_node = {
	BTS_NODE,
	"%s(bts)# ",
	1,
};

DEFUN(cfg_bts, cfg_bts_cmd,
	"bts BTS_NR",
	"Select a BTS to configure\n" "BTS Number\n")
{
	struct ganc_bts *bts = g_ganc_bts;

	vty->index = g_ganc_bts;
	vty->index_sub = &bts->description;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

#define SEGW_STR "Security Gateway\n"
#define GANC_STR "GAN Controller\n"

DEFUN(cfg_segw_host, cfg_segw_host_cmd,
	"segw hostname NAME",
	SEGW_STR "Host-name of the SEGW\n")
{
	struct ganc_bts *bts = vty->index;

	if (bts->segw_host)
		talloc_free(bts->segw_host);

	bts->segw_host = talloc_strdup(bts, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ganc_host, cfg_ganc_host_cmd,
	"ganc hostname NAME",
	GANC_STR "Host-name of the GANC\n")
{
	struct ganc_bts *bts = vty->index;

	if (bts->ganc_host)
		talloc_free(bts->ganc_host);

	bts->ganc_host = talloc_strdup(bts, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ganc_port, cfg_ganc_port_cmd,
	"ganc port <1-65535>",
	GANC_STR "TCP port number of the GANC\n")
{
	struct ganc_bts *bts = vty->index;

	bts->ganc_port = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_lac, cfg_bts_lac_cmd,
	"location-arrea-code <1-65535>",
	"Set the location area code (LAC)\n")
{
	struct ganc_bts *bts = vty->index;
	bts->location_area_code = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rac, cfg_bts_rac_cmd,
	"routing-area-code <1-65535>",
	"Set the routing area code (RAC)\n")
{
	struct ganc_bts *bts = vty->index;
	bts->routing_area_code = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cid, cfg_bts_cid_cmd,
	"cell-identity <1-65535>",
	"Set the cell identity (CID)\n")
{
	struct ganc_bts *bts = vty->index;
	bts->cell_identity = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_bcch_arfcn, cfg_bts_bcch_arfcn_cmd,
	"bcch-arfcn <0-1023>",
	"Virtual ARFCN for this cell\n")
{
	struct ganc_bts *bts = vty->index;
	bts->arfcn = atoi(argv[0]);
	return CMD_SUCCESS;
}


static int config_write_bts_single(struct vty *vty, struct ganc_bts *bts)
{
	vty_out(vty, " bts FIXME%s", VTY_NEWLINE);
	vty_out(vty, "  location-area-code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	vty_out(vty, "  routing-area-code %u%s", bts->routing_area_code,
		VTY_NEWLINE);
	vty_out(vty, "  cell-identity %u%s", bts->cell_identity,
		VTY_NEWLINE);
	vty_out(vty, "  bcch-arfcn %u%s", bts->arfcn, VTY_NEWLINE);

	if (bts->segw_host)
		vty_out(vty, "  segw hostname %s%s", bts->segw_host, VTY_NEWLINE);
	if (bts->ganc_host) {
		vty_out(vty, "  ganc hostname %s%s", bts->ganc_host, VTY_NEWLINE);
		vty_out(vty, "  ganc port %u%s", bts->ganc_port, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

static int config_write_bts(struct vty *vty)
{
	struct ganc_bts *bts;

	//llist_for_each_entry(bts, &g_ganc_net->bts_list, list)
	//	config_write_bts_single(bts);


	config_write_bts_single(vty, g_ganc_bts);

	return CMD_SUCCESS;
}

DEFUN(ganc_exit, ganc_exit_cmd, "exit",
	"Exit current node and down to previous node\n")
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case BTS_NODE:
		vty->node = GSMNET_NODE;
		{
			struct ganc_bts *bts = vty->index;
			vty->index = bts->net;
			vty->index_sub = NULL;
		}
		break;
	default:
		break;
	}

	return CMD_SUCCESS;
}

DEFUN(ganc_end, ganc_end_cmd, "end",
	"End current mode and change back to enable mode\n")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		break;
	case CONFIG_NODE:
	case GSMNET_NODE:
	case BTS_NODE:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	default:
		break;
	}

	return CMD_SUCCESS;
}

int ganc_vty_init_extra(void)
{
	install_element_ve(&show_gan_peer_cmd);
	install_element_ve(&show_gan_peer_det_cmd);

	install_element(CONFIG_NODE, &cfg_network_cmd);
	install_node(&net_node, config_write_net);
	install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &ganc_exit_cmd);
	install_element(GSMNET_NODE, &ganc_end_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node,  config_write_bts);
	install_default(BTS_NODE);
	install_element(BTS_NODE, &ganc_exit_cmd);
	install_element(BTS_NODE, &ganc_end_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_rac_cmd);
	install_element(BTS_NODE, &cfg_bts_cid_cmd);
	install_element(BTS_NODE, &cfg_bts_bcch_arfcn_cmd);
	install_element(BTS_NODE, &cfg_segw_host_cmd);
	install_element(BTS_NODE, &cfg_ganc_host_cmd);
	install_element(BTS_NODE, &cfg_ganc_port_cmd);

	return 0;
}
