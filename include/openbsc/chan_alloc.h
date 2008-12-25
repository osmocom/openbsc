#ifndef _CHAN_ALLOC_H
#define _CHAN_ALLOC_H

/* Special allocator for C0 of BTS */
struct gsm_bts_trx_ts *ts_c0_alloc(struct gsm_bts *bts,
				   enum gsm_phys_chan_config pchan);

/* Regular physical channel allocator */
struct gsm_bts_trx_ts *ts_alloc(struct gsm_bts *bts,
				enum gsm_phys_chan_config pchan);

/* Regular physical channel (TS) */
void ts_free(struct gsm_bts_trx_ts *ts);


/* Allocate a logical channel (SDCCH, TCH, ...) */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type);

/* Free a logical channel (SDCCH, TCH, ...) */
void lchan_free(struct gsm_lchan *lchan);

#endif /* _CHAN_ALLOC_H */
