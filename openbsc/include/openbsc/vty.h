#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct vty;

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;

enum bsc_vty_node {
	GSMNET_NODE = _LAST_OSMOVTY_NODE + 1,
	BTS_NODE,
	TRX_NODE,
	TS_NODE,
	SUBSCR_NODE,
	MGCP_NODE,
	GBPROXY_NODE,
	SGSN_NODE,
	OML_NODE,
	NAT_NODE,
	NAT_BSC_NODE,
	MSC_NODE,
	OM2K_NODE,
	OM2K_CON_GROUP_NODE,
	TRUNK_NODE,
	PGROUP_NODE,
	MNCC_INT_NODE,
	NITB_NODE,
	BSC_NODE,
	SMPP_NODE,
	SMPP_ESME_NODE,
	GTPHUB_NODE,
};

extern int bsc_vty_is_config_node(struct vty *vty, int node);

struct log_info;
int bsc_vty_init(struct gsm_network *network);
int bsc_vty_init_extra(void);

struct gsm_network *gsmnet_from_vty(struct vty *vty);

#endif
