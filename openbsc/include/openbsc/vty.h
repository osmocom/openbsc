#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

struct gsm_network;
struct vty;

void openbsc_vty_add_cmds(void);
void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

#endif
