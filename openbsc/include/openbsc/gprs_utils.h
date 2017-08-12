/* GPRS utility functions */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2014 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include <stdint.h>
#include <sys/types.h>

struct msgb;
struct gprs_ra_id;

struct msgb *gprs_msgb_copy(const struct msgb *msg, const char *name);
int gprs_msgb_resize_area(struct msgb *msg, uint8_t *area,
			    size_t old_size, size_t new_size);
int gprs_str_to_apn(uint8_t *apn_enc, size_t max_len, const char *str);

/* GSM 04.08, 10.5.7.3 GPRS Timer */
int gprs_tmr_to_secs(uint8_t tmr);
uint8_t gprs_secs_to_tmr_floor(int secs);

int gprs_is_mi_tmsi(const uint8_t *value, size_t value_len);
int gprs_is_mi_imsi(const uint8_t *value, size_t value_len);
int gprs_parse_mi_tmsi(const uint8_t *value, size_t value_len, uint32_t *tmsi);
void gprs_parse_tmsi(const uint8_t *value, uint32_t *tmsi);

int gprs_ra_id_equals(const struct gprs_ra_id *id1, const struct gprs_ra_id *id2);
