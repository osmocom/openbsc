/* OpenBSC kitchen sink */

#pragma once

#include <stdint.h>
#include <stdlib.h>

/* Compare count bytes of exp to rel. Return 0 if they are identical, 1
 * otherwise. Do not return a mismatch on the first mismatching byte,
 * but always compare all bytes, regardless. The idea is that the amount of
 * matching bytes cannot be inferred from the time the comparison took.*/
int constant_time_cmp(const uint8_t *exp, const uint8_t *rel, const int count);

/* This is like osmo_load64be_ext, except that if data_len is less than
 * sizeof(uint64_t), the data is interpreted as the least significant bytes
 * (osmo_load64be_ext loads them as the most significant bytes into the
 * returned uint64_t). In this way, any integer size up to 64 bits can be
 * decoded conveniently by using sizeof(), without the need to call specific
 * numbered functions (osmo_load16, 32, ...). */
uint64_t decode_big_endian(const uint8_t *data, size_t data_len);

/* This is like osmo_store64be_ext, except that this returns a static buffer of
 * the result (for convenience, but not threadsafe). If data_len is less than
 * sizeof(uint64_t), only the least significant bytes of value are encoded. */
uint8_t *encode_big_endian(uint64_t value, size_t data_len);

