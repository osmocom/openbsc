#ifndef _REST_OCTETS_H
#define _REST_OCTETS_H

#include <sys/types.h>
#include <openbsc/gsm_04_08.h>

/* generate SI1 rest octets */
int rest_octets_si1(u_int8_t *data, u_int8_t *nch_pos);

struct gsm48_si_selection_params {
	u_int16_t penalty_time:5,
		  temp_offs:3,
		  cell_resel_off:6,
		  cbq:1,
		  present:1;
};

struct gsm48_si_power_offset {
	u_int8_t power_offset:2,
		 present:1;
};

struct gsm48_si3_gprs_ind {
	u_int8_t si13_position:1,
		 ra_colour:3,
		 present:1;
};

struct gsm48_lsa_params {
	u_int32_t prio_thr:3,
		 lsa_offset:3,
		 mcc:12,
		 mnc:12;
	unsigned int present;
};

struct gsm48_si_ro_info {
	struct gsm48_si_selection_params selection_params;
	struct gsm48_si_power_offset power_offset;
	u_int8_t si2ter_indicator;
	u_int8_t early_cm_ctrl;
	struct {
		u_int8_t where:3,
			 present:1;
	} scheduling;
	struct gsm48_si3_gprs_ind gprs_ind;

	/* SI 4 specific */
	struct gsm48_lsa_params lsa_params;
	u_int16_t cell_id;
	u_int8_t break_ind;	/* do we have SI7 + SI8 ? */
};


/* Generate SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72) */
int rest_octets_si3(u_int8_t *data, const struct gsm48_si_ro_info *si3);

/* Generate SI4 Rest Octets (Chapter 10.5.2.35) */
int rest_octets_si4(u_int8_t *data, const struct gsm48_si_ro_info *si4);

enum pbcch_carrier_type {
	PBCCH_BCCH,
	PBCCH_ARFCN,
	PBCCH_MAIO
};

/* TS 03.60 Chapter 6.3.3.1: Network Mode of Operation */
enum gprs_nmo {
	GPRS_NMO_I	= 0,	/* CS pagin on GPRS paging or traffic channel */
	GPRS_NMO_II	= 1,	/* all paging on CCCH */
	GPRS_NMO_III	= 2,	/* no paging coordination */
};

struct gprs_cell_options {
	enum gprs_nmo nmo;
	/* T3168: wait for packet uplink assignment message */
	u_int32_t t3168;	/* in milliseconds */
	/* T3192: wait for release of the TBF after reception of the final block */
	u_int32_t t3192;	/* in milliseconds */
	u_int32_t drx_timer_max;/* in seconds */
	u_int32_t bs_cv_max;
};

/* TS 04.60 Table 12.9.2 */
struct gprs_power_ctrl_pars {
	u_int8_t alpha;
	u_int8_t t_avg_w;
	u_int8_t t_avg_t;
	u_int8_t pc_meas_chan;
	u_int8_t n_avg_i;
};

struct gsm48_si13_info {
	struct gprs_cell_options cell_opts;
	struct gprs_power_ctrl_pars pwr_ctrl_pars;
	u_int8_t bcch_change_mark;
	u_int8_t si_change_field;
	u_int8_t pbcch_present;

	union {
		struct {
			u_int8_t rac;
			u_int8_t spgc_ccch_sup;
			u_int8_t net_ctrl_ord;
			u_int8_t prio_acc_thr;
		} no_pbcch;
		struct {
			u_int8_t psi1_rep_per;
			u_int8_t pb;
			u_int8_t tsc;
			u_int8_t tn;
			enum pbcch_carrier_type carrier_type;
			u_int16_t arfcn;
			u_int8_t maio;
		} pbcch;
	};
};

/* Generate SI13 Rest Octests (Chapter 10.5.2.37b) */
int rest_octets_si13(u_int8_t *data, const struct gsm48_si13_info *si13);

#endif /* _REST_OCTETS_H */
