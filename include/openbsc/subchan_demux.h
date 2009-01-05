#ifndef _SUBCH_DEMUX_H
#define _SUBCH_DEMUX_H
/* A E1 sub-channel demultiplexer with TRAU frame sync */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <sys/types.h>

#define NR_SUBCH	4
#define TRAU_FRAME_SIZE	40
#define TRAU_FRAME_BITS	(TRAU_FRAME_SIZE*8)

struct subch {
	u_int8_t out_bitbuf[TRAU_FRAME_BITS];
	u_int8_t out_idx; /* next bit to be written in out_bitbuf */
};

struct subch_demux {
	u_int8_t chan_activ;
	struct subch subch[NR_SUBCH];
	int (*out_cb)(struct subch_demux *dmx, int ch, u_int8_t *data, int len,
		      void *);
	void *data;
};

int subch_demux_in(struct subch_demux *dmx, u_int8_t *data, int len);
int subch_demux_activate(struct subch_demux *dmx, int subch);
int subch_demux_deactivate(struct subch_demux *dmx, int subch);
#endif /* _SUBCH_DEMUX_H */
