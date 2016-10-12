#ifndef _GPRS_GMM_H
#define _GPRS_GMM_H

#include <osmocom/core/msgb.h>
#include <openbsc/gprs_sgsn.h>

#include <stdbool.h>

int gsm48_tx_gsm_deact_pdp_req(struct sgsn_pdp_ctx *pdp, uint8_t sm_cause);
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v);
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp);
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp);

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
int gsm0408_gprs_rcvmsg_iu(struct msgb *msg, struct gprs_ra_id *ra_id,
			   uint16_t *sai);
int gsm0408_gprs_force_reattach(struct sgsn_mm_ctx *mmctx);
int gsm0408_gprs_force_reattach_oldmsg(struct msgb *msg,
				       struct gprs_llc_llme *llme);
void gsm0408_gprs_access_granted(struct sgsn_mm_ctx *mmctx);
void gsm0408_gprs_access_denied(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_access_cancelled(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_authenticate(struct sgsn_mm_ctx *mmctx);

int gprs_gmm_rx_suspend(struct gprs_ra_id *raid, uint32_t tlli);
int gprs_gmm_rx_resume(struct gprs_ra_id *raid, uint32_t tlli,
		       uint8_t suspend_ref);

time_t gprs_max_time_to_idle(void);

int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp);

#endif /* _GPRS_GMM_H */
