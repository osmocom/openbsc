#ifndef _SYSTEM_INFO_H
#define _SYSTEM_INFO_H

#include <osmocom/gsm/sysinfo.h>

struct gsm_bts;

int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type type);
unsigned uarfcn_size(const uint16_t *u, const uint16_t *sc, size_t u_len);
unsigned earfcn_size(const struct osmo_earfcn_si2q *e);
unsigned range1024_p(unsigned n);
unsigned range512_q(unsigned m);
bool si2q_size_check(const struct gsm_bts *bts);
int bts_uarfcn_del(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble);
int bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble,
		   bool diversity);
#endif
