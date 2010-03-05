#ifndef _OPENBSC_NWL_H
#define _OPENBSC_NWL_H

#include <stdint.h>
#include <openbsc/gsm_data.h>

void ipac_nwl_init(void);

/* Start a NWL test.  It will raise the S_IPAC_TEST_COMPLETE signal. */
int ipac_nwl_test_start(struct gsm_bts_trx *trx, uint8_t testnr);

#endif /* _OPENBSC_NWL_H */
