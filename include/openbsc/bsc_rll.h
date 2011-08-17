#ifndef _BSC_RLL_H
#define _BSC_RLL_H

#include <openbsc/gsm_data.h>

enum bsc_rllr_ind {
	BSC_RLLR_IND_EST_CONF,
	BSC_RLLR_IND_REL_IND,
	BSC_RLLR_IND_ERR_IND,
	BSC_RLLR_IND_TIMEOUT,
};

int rll_establish(struct gsm_lchan *lchan, uint8_t link_id,
		  void (*cb)(struct gsm_lchan *, uint8_t, void *,
			     enum bsc_rllr_ind),
		  void *data);
void rll_indication(struct gsm_lchan *lchan, uint8_t link_id, uint8_t type);

#endif /* _BSC_RLL_H */
