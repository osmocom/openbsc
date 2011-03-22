#ifndef _GPRS_GMM_H
#define _GPRS_GMM_H

#include <osmocom/core/msgb.h>
#include <openbsc/gprs_sgsn.h>

int gsm48_tx_gsm_deact_pdp_req(struct sgsn_pdp_ctx *pdp, uint8_t sm_cause);
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v);
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp);
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp);

int gsm0408_gprs_rcvmsg(struct msgb *msg, struct gprs_llc_llme *llme);

int gprs_gmm_rx_suspend(struct gprs_ra_id *raid, uint32_t tlli);
int gprs_gmm_rx_resume(struct gprs_ra_id *raid, uint32_t tlli,
		       uint8_t suspend_ref);

#endif /* _GPRS_GMM_H */
