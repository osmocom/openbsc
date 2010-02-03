/*
 * ubx.c
 *
 * Implementation of generic UBX helpers
 *
 *
 * Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>

#include "ubx.h"


static void
ubx_checksum(uint8_t *data, int len, uint8_t *cksum)
{
	int i;
	uint8_t ck0 = 0, ck1 = 0;
	for (i=0; i<len; i++) {
		ck0 += data[i];
		ck1 += ck0;
	}
	cksum[0] = ck0;
	cksum[1] = ck1;
}


static ubx_msg_handler_t
ubx_find_handler(struct ubx_dispatch_entry *dt, uint8_t msg_class, uint8_t msg_id)
{
	while (dt->handler) {
		if ((dt->msg_class == msg_class) && (dt->msg_id == msg_id))
			return dt->handler;
		dt++;
	}
	return NULL;
}


int
ubx_msg_dispatch(struct ubx_dispatch_entry *dt,
                 void *msg, int len, void *userdata)
{
	struct ubx_hdr *hdr = msg;
	uint8_t cksum[2], *cksum_ptr;
	ubx_msg_handler_t h;

	if ((hdr->sync[0] != UBX_SYNC0) || (hdr->sync[1] != UBX_SYNC1)) {
		fprintf(stderr, "[!] Invalid sync bytes\n");
		return -1;
	}

	ubx_checksum(msg + 2, sizeof(struct ubx_hdr) + hdr->payload_len - 2, cksum);
	cksum_ptr = msg + (sizeof(struct ubx_hdr) + hdr->payload_len);
	if ((cksum_ptr[0] != cksum[0]) || (cksum_ptr[1] != cksum[1])) {
		fprintf(stderr, "[!] Invalid checksum\n");
		return -1;
	}

	h = ubx_find_handler(dt, hdr->msg_class, hdr->msg_id);
	if (h)
		h(hdr, msg + sizeof(struct ubx_hdr), hdr->payload_len, userdata);

	return sizeof(struct ubx_hdr) + hdr->payload_len + 2;
}

