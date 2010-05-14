#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <vty/vty.h>
#include <vty/buffer.h>

struct gsm_network;
struct vty;

void openbsc_vty_add_cmds(void);
void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;
extern struct cmd_element ournode_exit_cmd;
extern struct cmd_element ournode_end_cmd;

#endif
