#ifndef _SYSTEM_INFO_H
#define _SYSTEM_INFO_H

#include <osmocom/gsm/sysinfo.h>

#include <openbsc/arfcn_range_encode.h>

struct gsm_bts;

int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type type);
size_t si2q_earfcn_count(const struct osmo_earfcn_si2q *e);
unsigned range1024_p(unsigned n);
unsigned range512_q(unsigned m);
int range_encode(enum gsm48_range r, int *arfcns, int arfcns_used, int *w,
		 int f0, uint8_t *chan_list);
uint8_t si2q_num(struct gsm_bts *bts);
int bts_earfcn_add(struct gsm_bts *bts, uint16_t earfcn, uint8_t thresh_hi, uint8_t thresh_lo, uint8_t prio,
		   uint8_t qrx, uint8_t meas_bw);
int bts_uarfcn_del(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble);
int bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble,
		   bool diversity);
#endif
