/* Simple TRAU frame reflector to route voice calls */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

/* The "TRAU mux map" defines which particular 16kbit sub-slot (in which E1
 * timeslot on which E1 interface) should be directly muxed to which other 
 * sub-slot.  Entries in the mux map are always bi-directional. 
 *
 * The idea of all this is to directly switch voice channels in the BSC
 * from one phone to another.  We do this right now since we don't support
 * any external interface for voice channels, and in the future as an
 * optimization to routing them externally.
 */

#include <stdint.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mncc.h>

struct decoded_trau_frame;

/* map a TRAU mux map entry */
int trau_mux_map(const struct gsm_e1_subslot *src,
		 const struct gsm_e1_subslot *dst);
int trau_mux_map_lchan(const struct gsm_lchan *src,	
			const struct gsm_lchan *dst);

/* unmap a TRAU mux map entry */
int trau_mux_unmap(const struct gsm_e1_subslot *ss, uint32_t callref);

/* we get called by subchan_demux */
int trau_mux_input(struct gsm_e1_subslot *src_e1_ss,
		   const uint8_t *trau_bits, int num_bits);

/* add a trau receiver */
int trau_recv_lchan(struct gsm_lchan *lchan, uint32_t callref);

/* send trau from application */
int trau_send_frame(struct gsm_lchan *lchan, struct gsm_data_frame *frame);

/* switch trau muxer to new lchan */
int switch_trau_mux(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan);

/* callback invoked if we receive TRAU frames */
int subch_cb(struct subch_demux *dmx, int ch, uint8_t *data, int len, void *_priv);

/* TRAU frame transcoding */
struct msgb *trau_decode_fr(uint32_t callref,
	const struct decoded_trau_frame *tf);
struct msgb *trau_decode_efr(uint32_t callref,
	const struct decoded_trau_frame *tf);
void trau_encode_fr(struct decoded_trau_frame *tf,
	const unsigned char *data);
void trau_encode_efr(struct decoded_trau_frame *tf,
	const unsigned char *data);
