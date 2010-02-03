/*
 * COMP128 header
 *
 * See comp128.c for details
 */

#ifndef __COMP128_H__
#define __COMP128_H__

#include <sys/types.h>

/*
 * Performs the COMP128 algorithm (used as A3/A8)
 * ki    : u_int8_t [16]
 * srand : u_int8_t [16]
 * sres  : u_int8_t [4]
 * kc    : u_int8_t [8]
 */
void comp128(u_int8_t *ki, u_int8_t *srand, u_int8_t *sres, u_int8_t *kc);

#endif /* __COMP128_H__ */

