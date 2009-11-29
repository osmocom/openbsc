#ifndef _MEAS_REP_H
#define _MEAS_REP_H

/* extracted from a L3 measurement report IE */
struct gsm_meas_rep_cell {
	u_int8_t rxlev;
	u_int8_t bcch_freq;	/* FIXME: translate to ARFCN */
	u_int8_t bsic;
};

/* RX Level and RX Quality */
struct gsm_rx_lev_qual {
	u_int8_t rx_lev;
	u_int8_t rx_qual;
};

/* unidirectional measumrement report */
struct gsm_meas_rep_unidir {
	struct gsm_rx_lev_qual full;
	struct gsm_rx_lev_qual sub;
};

#define MEAS_REP_F_UL_DTX	0x01
#define MEAS_REP_F_DL_VALID	0x02
#define MEAS_REP_F_BA1		0x04
#define MEAS_REP_F_DL_DTX	0x08
#define MEAS_REP_F_MS_TO	0x10
#define MEAS_REP_F_MS_L1	0x20
#define MEAS_REP_F_FPC		0x40

/* parsed uplink and downlink measurement result */
struct gsm_meas_rep {
	u_int8_t nr;
	unsigned int flags;

	struct gsm_meas_rep_unidir ul;
	struct gsm_meas_rep_unidir dl;

	u_int8_t bs_power;
	u_int8_t ms_timing_offset;
	struct {
		int8_t pwr;	/* MS power in dBm */
		u_int8_t ta;	/* MS timing advance */
	} ms_l1;

	int num_cell;
	struct gsm_meas_rep_cell cell[6];
};

#endif /* _MEAS_REP_H */
