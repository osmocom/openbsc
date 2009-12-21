/* Simple TRAU frame reflector to route voice calls */

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

/* The "TRAU mux map" defines which particular 16kbit sub-slot (in which E1
 * timeslot on which E1 interface) should be directly muxed to which other 
 * sub-slot.  Entries in the mux map are always bi-directional. 
 *
 * The idea of all this is to directly switch voice channels in the BSC
 * from one phone to another.  We do this right now since we don't support
 * any external interface for voice channels, and in the future as an
 * optimization to routing them externally.
 */

/* map a TRAU mux map entry */
int trau_mux_map(const struct gsm_e1_subslot *src,
		 const struct gsm_e1_subslot *dst);
int trau_mux_map_lchan(const struct gsm_lchan *src,	
			const struct gsm_lchan *dst);

/* unmap a TRAU mux map entry */
int trau_mux_unmap(const struct gsm_e1_subslot *ss, u_int32_t callref);

/* we get called by subchan_demux */
int trau_mux_input(struct gsm_e1_subslot *src_e1_ss,
		   const u_int8_t *trau_bits, int num_bits);

/* add a trau receiver */
int trau_recv_lchan(struct gsm_lchan *lchan, u_int32_t callref);

/* send trau from application */
int trau_send_frame(struct gsm_lchan *lchan, struct gsm_data_frame *frame);
