#ifndef _E1_CONFIG_H
#define _E1_CONFIG_H

#include <openbsc/gsm_data_shared.h>

int e1_reconfig_ts(struct gsm_bts_trx_ts *ts);
int e1_reconfig_trx(struct gsm_bts_trx *trx);
int e1_reconfig_bts(struct gsm_bts *bts);

#endif /* _E1_CONFIG_H */

