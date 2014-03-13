/*
 * (C) 2014 by Sysmocom s.f.m.c. GmbH
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bscconfig.h"

#include "g711common.h"
#include <gsm.h>
#ifdef HAVE_BCG729
#include <bcg729/decoder.h>
#include <bcg729/encoder.h>
#endif

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/core/talloc.h>

enum audio_format {
	AF_INVALID,
	AF_S16,
	AF_L16,
	AF_GSM,
	AF_G729,
	AF_PCMA
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
};

static enum audio_format get_audio_format(const struct mgcp_rtp_end *rtp_end)
{
	if (rtp_end->subtype_name) {
		if (!strcmp("GSM", rtp_end->subtype_name))
			return AF_GSM;
		if (!strcmp("PCMA", rtp_end->subtype_name))
			return AF_PCMA;
#ifdef HAVE_BCG729
		if (!strcmp("G729", rtp_end->subtype_name))
			return AF_G729;
#endif
		if (!strcmp("L16", rtp_end->subtype_name))
			return AF_L16;
	}

	switch (rtp_end->payload_type) {
	case 3 /* GSM */:
		return AF_GSM;
	case 8 /* PCMA */:
		return AF_PCMA;
#ifdef HAVE_BCG729
	case 18 /* G.729 */:
		return AF_G729;
#endif
	case 11 /* L16 */:
		return AF_L16;
	default:
		return AF_INVALID;
	}
}

static void l16_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2) {
		buf[0] = sample[0] >> 8;
		buf[1] = sample[0] & 0xff;
	}
}

static void l16_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2)
		sample[0] = ((short)buf[0] << 8) | buf[1];
}

static void alaw_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n)
		*(buf++) = s16_to_alaw(*(sample++));
}

static void alaw_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n)
		*(sample++) = alaw_to_s16(*(buf++));
}

static int processing_state_destructor(struct mgcp_process_rtp_state *state)
{
	switch (state->src_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->src.gsm_handle);
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		if (state->src.g729_dec)
			closeBcg729DecoderChannel(state->src.g729_dec);
		break;
#endif
	default:
		break;
	}
	switch (state->dst_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->dst.gsm_handle);
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		if (state->dst.g729_enc)
			closeBcg729EncoderChannel(state->dst.g729_enc);
		break;
#endif
	default:
		break;
	}
	return 0;
}

int mgcp_transcoding_setup(struct mgcp_endpoint *endp,
			   struct mgcp_rtp_end *dst_end,
			   struct mgcp_rtp_end *src_end)
{
	struct mgcp_process_rtp_state *state;
	enum audio_format src_fmt, dst_fmt;

	/* cleanup first */
	if (dst_end->rtp_process_data) {
		talloc_free(dst_end->rtp_process_data);
		dst_end->rtp_process_data = NULL;
	}

	if (!src_end)
		return 0;

	src_fmt = get_audio_format(src_end);
	dst_fmt = get_audio_format(dst_end);

	LOGP(DMGCP, LOGL_ERROR,
	     "Checking transcoding: %s (%d) -> %s (%d)\n",
	     src_end->subtype_name, src_end->payload_type,
	     dst_end->subtype_name, dst_end->payload_type);

	if (src_fmt == AF_INVALID || dst_fmt == AF_INVALID) {
		if (!src_end->subtype_name || !dst_end->subtype_name)
			/* Not enough info, do nothing */
			return 0;

		if (strcmp(src_end->subtype_name, dst_end->subtype_name) == 0)
			/* Nothing to do */
			return 0;

		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: %s codec not supported (%s -> %s).\n",
		     src_fmt != AF_INVALID ? "destination" : "source",
		     src_end->audio_name, dst_end->audio_name);
		return -EINVAL;
	}

	if (src_end->rate && dst_end->rate && src_end->rate != dst_end->rate) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: rate conversion (%d -> %d) not supported.\n",
		     src_end->rate, dst_end->rate);
		return -EINVAL;
	}

	state = talloc_zero(endp->tcfg->cfg, struct mgcp_process_rtp_state);
	talloc_set_destructor(state, processing_state_destructor);
	dst_end->rtp_process_data = state;

	state->src_fmt = src_fmt;

	switch (state->src_fmt) {
	case AF_L16:
	case AF_S16:
		state->src_frame_size = 80 * sizeof(short);
		state->src_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->src_frame_size = sizeof(gsm_frame);
		state->src_samples_per_frame = 160;
		state->src.gsm_handle = gsm_create();
		if (!state->src.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM decoder.\n");
			return -EINVAL;
		}
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		state->src_frame_size = 10;
		state->src_samples_per_frame = 80;
		state->src.g729_dec = initBcg729DecoderChannel();
		if (!state->src.g729_dec) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
#endif
	case AF_PCMA:
		state->src_frame_size = 80;
		state->src_samples_per_frame = 80;
		break;
	default:
		break;
	}

	state->dst_fmt = dst_fmt;

	switch (state->dst_fmt) {
	case AF_L16:
	case AF_S16:
		state->dst_frame_size = 80*sizeof(short);
		state->dst_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->dst_frame_size = sizeof(gsm_frame);
		state->dst_samples_per_frame = 160;
		state->dst.gsm_handle = gsm_create();
		if (!state->dst.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM encoder.\n");
			return -EINVAL;
		}
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		state->dst_frame_size = 10;
		state->dst_samples_per_frame = 80;
		state->dst.g729_enc = initBcg729EncoderChannel();
		if (!state->dst.g729_enc) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
#endif
	case AF_PCMA:
		state->dst_frame_size = 80;
		state->dst_samples_per_frame = 80;
		break;
	default:
		break;
	}

	LOGP(DMGCP, LOGL_INFO,
	     "Initialized RTP processing on: 0x%x "
	     "conv: %d (%d, %d, %s) -> %d (%d, %d, %s)\n",
	     ENDPOINT_NUMBER(endp),
	     src_fmt, src_end->payload_type, src_end->rate, src_end->fmtp_extra,
	     dst_fmt, dst_end->payload_type, dst_end->rate, dst_end->fmtp_extra);

	return 0;
}

void mgcp_transcoding_net_downlink_format(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**audio_name,
					  const char**fmtp_extra)
{
	struct mgcp_process_rtp_state *state = endp->net_end.rtp_process_data;
	if (!state || endp->net_end.payload_type < 0) {
		*payload_type = endp->bts_end.payload_type;
		*audio_name = endp->bts_end.audio_name;
		*fmtp_extra = endp->bts_end.fmtp_extra;
		return;
	}

	*payload_type = endp->net_end.payload_type;
	*fmtp_extra = endp->net_end.fmtp_extra;
	*audio_name = endp->net_end.audio_name;
}


int mgcp_transcoding_process_rtp(struct mgcp_endpoint *endp,
				 struct mgcp_rtp_end *dst_end,
				 char *data, int *len, int buf_size)
{
	struct mgcp_process_rtp_state *state = dst_end->rtp_process_data;
	size_t rtp_hdr_size = 12;
	char *payload_data = data + rtp_hdr_size;
	int payload_len = *len - rtp_hdr_size;
	size_t sample_cnt = 0;
	size_t sample_idx;
	int16_t samples[10*160];
	uint8_t *src = (uint8_t *)payload_data;
	uint8_t *dst = (uint8_t *)payload_data;
	size_t nbytes = payload_len;
	size_t frame_remainder;

	if (!state)
		return 0;

	if (state->src_fmt == state->dst_fmt)
		return 0;

	/* TODO: check payload type (-> G.711 comfort noise) */

	/* Decode src into samples */
	while (nbytes >= state->src_frame_size) {
		if (sample_cnt + state->src_samples_per_frame > ARRAY_SIZE(samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small: %d > %d.\n",
			     sample_cnt + state->src_samples_per_frame,
			     ARRAY_SIZE(samples));
			return -ENOSPC;
		}
		switch (state->src_fmt) {
		case AF_GSM:
			if (gsm_decode(state->src.gsm_handle,
				       (gsm_byte *)src, samples + sample_cnt) < 0) {
				LOGP(DMGCP, LOGL_ERROR,
				     "Failed to decode GSM.\n");
				return -EINVAL;
			}
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Decoder(state->src.g729_dec, src, 0, samples + sample_cnt);
			break;
#endif
		case AF_PCMA:
			alaw_decode(src, samples + sample_cnt,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(samples + sample_cnt, src,
				state->src_frame_size);
			break;
		case AF_L16:
			l16_decode(src, samples + sample_cnt,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		src        += state->src_frame_size;
		nbytes     -= state->src_frame_size;
		sample_cnt += state->src_samples_per_frame;
	}

	/* Add silence if necessary */
	frame_remainder = sample_cnt % state->dst_samples_per_frame;
	if (frame_remainder) {
		size_t silence = state->dst_samples_per_frame - frame_remainder;
		if (sample_cnt + silence > ARRAY_SIZE(samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small for silence: %d > %d.\n",
			     sample_cnt + silence,
			     ARRAY_SIZE(samples));
			return -ENOSPC;
		}

		while (silence > 0) {
			samples[sample_cnt] = 0;
			sample_cnt += 1;
			silence -= 1;
		}
	}

	/* Encode samples into dst */
	sample_idx = 0;
	nbytes = 0;
	while (sample_idx + state->dst_samples_per_frame <= sample_cnt) {
		if (nbytes + state->dst_frame_size > buf_size) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Encoding (RTP) buffer too small: %d > %d.\n",
			     nbytes + state->dst_frame_size, buf_size);
			return -ENOSPC;
		}
		switch (state->dst_fmt) {
		case AF_GSM:
			gsm_encode(state->dst.gsm_handle,
				   samples + sample_idx, dst);
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Encoder(state->dst.g729_enc,
				      samples + sample_idx, dst);
			break;
#endif
		case AF_PCMA:
			alaw_encode(samples + sample_idx, dst,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(dst, samples + sample_idx, state->dst_frame_size);
			break;
		case AF_L16:
			l16_encode(samples + sample_idx, dst,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		dst        += state->dst_frame_size;
		nbytes     += state->dst_frame_size;
		sample_idx += state->dst_samples_per_frame;
	}

	*len = rtp_hdr_size + nbytes;
	/* Patch payload type */
	data[1] = (data[1] & 0x80) | (dst_end->payload_type & 0x7f);

	return 0;
}
