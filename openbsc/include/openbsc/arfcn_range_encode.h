#ifndef ARFCN_RANGE_ENCODE_H
#define ARFCN_RANGE_ENCODE_H

#include <stdint.h>

enum gsm48_range {
	ARFCN_RANGE_INVALID	= -1,
	ARFCN_RANGE_128		= 127,
	ARFCN_RANGE_256		= 255,
	ARFCN_RANGE_512		= 511,
	ARFCN_RANGE_1024	= 1023,
};

#define RANGE_ENC_MAX_ARFCNS	29

int range_enc_determine_range(const int *arfcns, int size, int *f0_out);
int range_enc_arfcns(enum gsm48_range rng, const int *arfcns, int sze, int *out, int idx);
int range_enc_find_index(enum gsm48_range rng, const int *arfcns, int size);
int range_enc_filter_arfcns(int *arfcns, const int sze, const int f0, int *f0_included);

int range_enc_range128(uint8_t *chan_list, int f0, int *w);
int range_enc_range256(uint8_t *chan_list, int f0, int *w);
int range_enc_range512(uint8_t *chan_list, int f0, int *w);
int range_enc_range1024(uint8_t *chan_list, int f0, int f0_incl, int *w);

#endif
