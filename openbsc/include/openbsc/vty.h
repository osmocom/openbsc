#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct vty;

void logging_vty_add_cmds(void);
void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;
extern struct cmd_element ournode_exit_cmd;
extern struct cmd_element ournode_end_cmd;

enum bsc_vty_node {
	GSMNET_NODE = _LAST_OSMOVTY_NODE + 1,
	BTS_NODE,
	TRX_NODE,
	TS_NODE,
	SUBSCR_NODE,
	MGCP_NODE,
	GBPROXY_NODE,
	SGSN_NODE,
	NS_NODE,
	BSSGP_NODE,
	OML_NODE,
};

#endif
