#ifndef _HANDOVER_DECISION_H
#define _HANDOVER_DECISION_H

void bts_dump_vty_handover(struct vty *vty, struct gsm_bts *bts);
void config_write_bts_handover(struct vty *vty, struct gsm_bts *bts);
void config_write_net_handover(struct vty *vty);
void bsc_vty_init_handover(void);

void init_ho_1(void);

#endif /* _HANDOVER_DECISION_H */

