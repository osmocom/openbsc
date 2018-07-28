/*
 * (C) 2014 by On-Waves
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
#ifndef OPENBSC_MGCP_TRANSCODE_H
#define OPENBSC_MGCP_TRANSCODE_H

#include "bscconfig.h"

#if HAVE_GSM_H
#include <gsm.h>
#elif HAVE_GSM_GSM_H
#include <gsm/gsm.h>
#endif
#ifdef HAVE_BCG729
#include <bcg729/decoder.h>
#include <bcg729/encoder.h>
#endif

enum audio_format {
	AF_INVALID,
	AF_S16,
	AF_L16,
	AF_GSM,
	AF_G729,
	AF_PCMA,
	AF_PCMU
};


struct mgcp_process_rtp_state {
	/* decoding */
	enum audio_format src_fmt;
	union {
		gsm gsm_handle;
#ifdef HAVE_BCG729
		bcg729DecoderChannelContextStruct *g729_dec;
#endif
	} src;
	size_t src_frame_size;
	size_t src_samples_per_frame;

	/* processing */

	/* encoding */
	enum audio_format dst_fmt;
	union {
		gsm gsm_handle;
#ifdef HAVE_BCG729
		bcg729EncoderChannelContextStruct *g729_enc;
#endif
	} dst;
	size_t dst_frame_size;
	size_t dst_samples_per_frame;
	int dst_packet_duration;

	int is_running;
	uint16_t next_seq;
	uint32_t next_time;
	int16_t samples[10*160];
	size_t sample_cnt;
	size_t sample_offs;
};


int mgcp_transcoding_setup(struct mgcp_endpoint *endp,
			   struct mgcp_rtp_end *dst_end,
			   struct mgcp_rtp_end *src_end);

void mgcp_transcoding_net_downlink_format(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**audio_name,
					  const char**fmtp_extra);

int mgcp_transcoding_process_rtp(struct mgcp_endpoint *endp,
				 struct mgcp_rtp_end *dst_end,
				 char *data, int *len, int buf_size);

int mgcp_transcoding_get_frame_size(void *state_, int nsamples, int dst);
#endif /* OPENBSC_MGCP_TRANSCODE_H */
