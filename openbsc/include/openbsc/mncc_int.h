#ifndef _MNCC_INT_H
#define _MNCC_INT_H

#include <stdint.h>

struct mncc_int {
	uint8_t def_codec[2];
};

extern struct mncc_int mncc_int;

#endif
