#ifndef _REST_OCTETS_H
#define _REST_OCTETS_H

#include <stdbool.h>
#include <openbsc/gsm_04_08.h>
#include <osmocom/gsm/sysinfo.h>

/* generate SI1 rest octets */
int rest_octets_si1(uint8_t *data, uint8_t *nch_pos, int is1800_net);
int rest_octets_si2quater(uint8_t *data, struct gsm_bts *bts);
int rest_octets_si6(uint8_t *data, bool is1800_net);

struct gsm48_si_selection_params {
	uint16_t penalty_time:5,
		  temp_offs:3,
		  cell_resel_off:6,
		  cbq:1,
		  present:1;
};

struct gsm48_si_power_offset {
	uint8_t power_offset:2,
		 present:1;
};

struct gsm48_si3_gprs_ind {
	uint8_t si13_position:1,
		 ra_colour:3,
		 present:1;
};

struct gsm48_lsa_params {
	uint32_t prio_thr:3,
		 lsa_offset:3,
		 mcc:12,
		 mnc:12;
	unsigned int present;
};

struct gsm48_si_ro_info {
	struct gsm48_si_selection_params selection_params;
	struct gsm48_si_power_offset power_offset;
	uint8_t si2ter_indicator;
	uint8_t early_cm_ctrl;
	struct {
		uint8_t where:3,
			 present:1;
	} scheduling;
	struct gsm48_si3_gprs_ind gprs_ind;
	/* SI 3 specific */
	uint8_t si2quater_indicator;
	/* SI 4 specific */
	struct gsm48_lsa_params lsa_params;
	uint16_t cell_id;
	uint8_t break_ind;	/* do we have SI7 + SI8 ? */
};


/* Generate SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72) */
int rest_octets_si3(uint8_t *data, const struct gsm48_si_ro_info *si3);

/* Generate SI4 Rest Octets (Chapter 10.5.2.35) */
int rest_octets_si4(uint8_t *data, const struct gsm48_si_ro_info *si4, int len);

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

/* TS 04.60 12.24 */
struct gprs_cell_options {
	enum gprs_nmo nmo;
	/* T3168: wait for packet uplink assignment message */
	uint32_t t3168;	/* in milliseconds */
	/* T3192: wait for release of the TBF after reception of the final block */
	uint32_t t3192;	/* in milliseconds */
	uint32_t drx_timer_max;/* in seconds */
	uint32_t bs_cv_max;
	uint8_t  supports_egprs_11bit_rach;
	bool ctrl_ack_type_use_block; /* use PACKET CONTROL ACKNOWLEDGMENT */

	uint8_t ext_info_present;
	struct {
		uint8_t egprs_supported;
			uint8_t use_egprs_p_ch_req;
			uint8_t bep_period;
		uint8_t pfc_supported;
		uint8_t dtm_supported;
		uint8_t bss_paging_coordination;
	} ext_info;
};

/* TS 04.60 Table 12.9.2 */
struct gprs_power_ctrl_pars {
	uint8_t alpha;
	uint8_t t_avg_w;
	uint8_t t_avg_t;
	uint8_t pc_meas_chan;
	uint8_t n_avg_i;
};

struct gsm48_si13_info {
	struct gprs_cell_options cell_opts;
	struct gprs_power_ctrl_pars pwr_ctrl_pars;
	uint8_t bcch_change_mark;
	uint8_t si_change_field;
	uint8_t pbcch_present;

	union {
		struct {
			uint8_t rac;
			uint8_t spgc_ccch_sup;
			uint8_t net_ctrl_ord;
			uint8_t prio_acc_thr;
		} no_pbcch;
		struct {
			uint8_t psi1_rep_per;
			uint8_t pb;
			uint8_t tsc;
			uint8_t tn;
			enum pbcch_carrier_type carrier_type;
			uint16_t arfcn;
			uint8_t maio;
		} pbcch;
	};
};

/* Generate SI13 Rest Octests (Chapter 10.5.2.37b) */
int rest_octets_si13(uint8_t *data, const struct gsm48_si13_info *si13);

#endif /* _REST_OCTETS_H */
