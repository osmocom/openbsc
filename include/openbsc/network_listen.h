#ifndef _OPENBSC_NWL_H
#define _OPENBSC_NWL_H

#include <stdint.h>
#include <openbsc/gsm_data.h>

void ipac_nwl_init(void);

/* Start a NWL test.  It will raise the S_IPAC_TEST_COMPLETE signal. */
int ipac_nwl_test_start(struct gsm_bts_trx *trx, uint8_t testnr,
			const uint8_t *phys_conf, unsigned int phys_conf_len);

int ipac_rxlevstat2whitelist(uint16_t *buf, const struct rxlev_stats *st, uint8_t min_rxlev,
			     uint16_t max_num_arfcns);

#endif /* _OPENBSC_NWL_H */
