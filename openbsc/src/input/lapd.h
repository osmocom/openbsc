
#include <stdint.h>

typedef enum {
	LAPD_MPH_NONE	= 0,

	LAPD_MPH_ACTIVATE_IND,
	LAPD_MPH_DEACTIVATE_IND,

	LAPD_DL_DATA_IND,

} lapd_mph_type;

extern uint8_t *lapd_receive(uint8_t *data, int len, int *ilen, lapd_mph_type *prim, void *cbdata);

extern void (*lapd_transmit_cb)(uint8_t *data, int len, void *cbdata);

extern void lapd_transmit(int tei, uint8_t *data, int len, void *cbdata);

