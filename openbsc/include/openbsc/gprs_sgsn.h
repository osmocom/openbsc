#ifndef _GPRS_SGSN_H
#define _GPRS_SGSN_H

/* TS 04.08 4.1.3.3 GMM mobility management states on the network side */
enum gprs_mm_state {
	GMM_DEREGISTERED,		/* 4.1.3.3.1.1 */
	GMM_COMMON_PROC_INIT,		/* 4.1.3.3.1.2 */
	GMM_REGISTERED_NORMAL,		/* 4.1.3.3.2.1 */
	GMM_REGISTERED_SUSPENDED,	/* 4.1.3.3.2.2 */
	GMM_DEREGISTERED_INIT,		/* 4.1.3.3.1.4 */
};

enum gprs_ciph_algo {
	GPRS_ALGO_GEA0,
	GPRS_ALGO_GEA1,
	GPRS_ALGO_GEA2,
};

#define MS_RADIO_ACCESS_CAPA

/* According to TS 03.60, Table 5: SGSN MM and PDP Contexts */
struct sgsn_mm_ctx {
	struct llist_head	list;

	char 			imsi[GSM_IMSI_LENGTH];
	enum gprs_mm_state	mm_state;
	u_int32_t 		p_tmsi;
	u_int32_t 		p_tmsi_sig;
	char 			imei[GSM_IMEI_LENGTH];
	char 			msisdn[GSM_EXTENSION_LENGTH];
	struct gprs_ra_id	ra;
	u_int16_t		cell_id;
	u_int32_t		cell_id_age;
	/* VLR number */
	u_int32_t		new_sgsn_addr;
	/* Authentication Triplets */
	/* Kc */
	/* CKSN */
	enum gprs_ciph_algo	ciph_algo;
	struct {
		u_int8_t	buf[14];	/* 10.5.5.12a */
		u_int8_t	len;
	} ms_radio_access_capa;
	struct {
		u_int8_t	buf[4];		/* 10.5.5.12 */
		u_int8_t	len;
	} ms_network_capa;
	u_int16_t		drx_parms;
	int			mnrg;	/* MS reported to HLR? */
	int			ngaf;	/* MS reported to MSC/VLR? */
	int			ppf;	/* paging for GPRS + non-GPRS? */
	/* SMS Parameters */
	int			recovery;
	u_int8_t		radio_prio_sms;

	struct llist_head	pdp_list;

	/* Additional bits not present in the GSM TS */
	u_int32_t		tlli;
	struct timer_list	timer;
	unsigned int		T;
};

enum pdp_ctx_state {
	PDP_STAE_NONE,
};

enum pdp_type {
	PDP_TYPE_NONE,
};

struct sgsn_pdp_ctx {
	struct llist_head	list;

	unsigned int		id;
	enum pdp_ctx_state	state;
	enum pdp_type		type;
	u_int32_t		addresss;
	char 			*apn_subscribed;
	char 			*apn_used;
	u_int16_t		nsapi;
	u_int8_t		ti;	/* transaction identifier */
	u_int32_t		ggsn_in_use;
	int			vplmn_allowed;
	u_int32_t		qos_profile_subscr;
	u_int32_t		qos_profile_req;
	u_int32_t		qos_profile_neg;
	u_int8_t		radio_prio;
	u_int32_t		tx_npdu_nr;
	u_int32_t		rx_npdu_nr;
	u_int32_t		tx_gtp_snd;
	u_int32_t		rx_gtp_snu;
	u_int32_t		charging_id;
	int			reordering_reqd;
};

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(u_int32_t tlli,
					const struct gprs_ra_id *raid);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(u_int32_t tmsi);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi);

/* Allocate a new SGSN MM context */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc(u_int32_t tlli,
					const struct gprs_ra_id *raid);

#endif /* _GPRS_SGSN_H */
