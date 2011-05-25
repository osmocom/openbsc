#ifndef _CRC24_H
#define _CRC24_H

#define INIT_CRC24	0xffffff

u_int32_t crc24_calc(u_int32_t fcs, u_int8_t *cp, unsigned int len);

#endif
