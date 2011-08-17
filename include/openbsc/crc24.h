#ifndef _CRC24_H
#define _CRC24_H

#include <stdint.h>

#define INIT_CRC24	0xffffff

uint32_t crc24_calc(uint32_t fcs, uint8_t *cp, unsigned int len);

#endif
