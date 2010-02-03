#ifndef _HANDOVER_H
#define _HANDOVER_H
/* Hand over the specified logical channel to the specified new BTS.
 * This is the main entry point for the actual handover algorithm,
 * after it has decided it wants to initiate HO to a specific BTS */
int bsc_handover_start(struct gsm_lchan *old_lchan, struct gsm_bts *bts);

#endif /* _HANDOVER_H */
