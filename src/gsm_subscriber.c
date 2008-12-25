/* Dummy implementation of a subscriber database, roghly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include <openbsc/gsm_subscriber.h>

static struct gsm_subscriber subscr = {
	.name = "Test User 1",
	.tmsi = { 0x22, 0x33, 0x44, 0x55 },
};

struct gsm_subscriber *subscr_get_by_tmsi(u_int8_t *tmsi)
{
	return &subscr;
}
struct gsm_subscriber *subscr_get_by_imsi(u_int8_t *imsi)
{
	return &subscr;
}

int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts)
{
	return 0;
}
