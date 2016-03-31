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

#include <stdlib.h>
#include <string.h>
#include <errno.h>


#include "g711common.h"

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/mgcp_transcode.h>

#include <osmocom/core/talloc.h>
#include <osmocom/netif/rtp.h>

int mgcp_transcoding_get_frame_size(void *state_, int nsamples, int dst)
{
	struct mgcp_process_rtp_state *state = state_;
	if (dst)
		return (nsamples >= 0 ?
			nsamples / state->dst_samples_per_frame :
			1) * state->dst_frame_size;
	else
		return (nsamples >= 0 ?
			nsamples / state->src_samples_per_frame :
			1) * state->src_frame_size;
}

static enum audio_format get_audio_format(const struct mgcp_rtp_codec *codec)
{
	if (codec->subtype_name) {
		if (!strcasecmp("GSM", codec->subtype_name))
			return AF_GSM;
		if (!strcasecmp("PCMA", codec->subtype_name))
			return AF_PCMA;
		if (!strcasecmp("PCMU", codec->subtype_name))
			return AF_PCMU;
#ifdef HAVE_BCG729
		if (!strcasecmp("G729", codec->subtype_name))
			return AF_G729;
#endif
		if (!strcasecmp("L16", codec->subtype_name))
			return AF_L16;
	}

	switch (codec->payload_type) {
	case 0 /* PCMU */:
		return AF_PCMU;
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

static void ulaw_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n)
		*(buf++) = s16_to_ulaw(*(sample++));
}

static void ulaw_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n)
		*(sample++) = ulaw_to_s16(*(buf++));
}

static int processing_state_destructor(struct mgcp_process_rtp_state *state)
{
	switch (state->src_fmt) {
	case AF_GSM:
		if (state->src.gsm_handle)
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
	const struct mgcp_rtp_codec *dst_codec = &dst_end->codec;

	/* cleanup first */
	if (dst_end->rtp_process_data) {
		talloc_free(dst_end->rtp_process_data);
		dst_end->rtp_process_data = NULL;
	}

	if (!src_end)
		return 0;

	const struct mgcp_rtp_codec *src_codec = &src_end->codec;

	if (endp->tcfg->no_audio_transcoding) {
		LOGP(DMGCP, LOGL_NOTICE,
			"Transcoding disabled on endpoint 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	src_fmt = get_audio_format(src_codec);
	dst_fmt = get_audio_format(dst_codec);

	LOGP(DMGCP, LOGL_ERROR,
	     "Checking transcoding: %s (%d) -> %s (%d)\n",
	     src_codec->subtype_name, src_codec->payload_type,
	     dst_codec->subtype_name, dst_codec->payload_type);

	if (src_fmt == AF_INVALID || dst_fmt == AF_INVALID) {
		if (!src_codec->subtype_name || !dst_codec->subtype_name)
			/* Not enough info, do nothing */
			return 0;

		if (strcasecmp(src_codec->subtype_name, dst_codec->subtype_name) == 0)
			/* Nothing to do */
			return 0;

		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: %s codec not supported (%s -> %s).\n",
		     src_fmt != AF_INVALID ? "destination" : "source",
		     src_codec->audio_name, dst_codec->audio_name);
		return -EINVAL;
	}

	if (src_codec->rate && dst_codec->rate && src_codec->rate != dst_codec->rate) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: rate conversion (%d -> %d) not supported.\n",
		     src_codec->rate, dst_codec->rate);
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
	case AF_PCMU:
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
	case AF_PCMU:
	case AF_PCMA:
		state->dst_frame_size = 80;
		state->dst_samples_per_frame = 80;
		break;
	default:
		break;
	}

	if (dst_end->force_output_ptime)
		state->dst_packet_duration = mgcp_rtp_packet_duration(endp, dst_end);

	LOGP(DMGCP, LOGL_INFO,
	     "Initialized RTP processing on: 0x%x "
	     "conv: %d (%d, %d, %s) -> %d (%d, %d, %s)\n",
	     ENDPOINT_NUMBER(endp),
	     src_fmt, src_codec->payload_type, src_codec->rate, src_end->fmtp_extra,
	     dst_fmt, dst_codec->payload_type, dst_codec->rate, dst_end->fmtp_extra);

	return 0;
}

void mgcp_transcoding_net_downlink_format(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**audio_name,
					  const char**fmtp_extra)
{
	struct mgcp_process_rtp_state *state = endp->net_end.rtp_process_data;
	struct mgcp_rtp_codec *net_codec = &endp->net_end.codec;
	struct mgcp_rtp_codec *bts_codec = &endp->bts_end.codec;

	if (!state || net_codec->payload_type < 0) {
		*payload_type = bts_codec->payload_type;
		*audio_name = bts_codec->audio_name;
		*fmtp_extra = endp->bts_end.fmtp_extra;
		return;
	}

	*payload_type = net_codec->payload_type;
	*audio_name = net_codec->audio_name;
	*fmtp_extra = endp->net_end.fmtp_extra;
}

static int decode_audio(struct mgcp_process_rtp_state *state,
			uint8_t **src, size_t *nbytes)
{
	while (*nbytes >= state->src_frame_size) {
		if (state->sample_cnt + state->src_samples_per_frame > ARRAY_SIZE(state->samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small: %zu > %zu.\n",
			     state->sample_cnt + state->src_samples_per_frame,
			     ARRAY_SIZE(state->samples));
			return -ENOSPC;
		}
		switch (state->src_fmt) {
		case AF_GSM:
			if (gsm_decode(state->src.gsm_handle,
				       (gsm_byte *)*src, state->samples + state->sample_cnt) < 0) {
				LOGP(DMGCP, LOGL_ERROR,
				     "Failed to decode GSM.\n");
				return -EINVAL;
			}
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Decoder(state->src.g729_dec, *src, 0, state->samples + state->sample_cnt);
			break;
#endif
		case AF_PCMU:
			ulaw_decode(*src, state->samples + state->sample_cnt,
				    state->src_samples_per_frame);
			break;
		case AF_PCMA:
			alaw_decode(*src, state->samples + state->sample_cnt,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(state->samples + state->sample_cnt, *src,
				state->src_frame_size);
			break;
		case AF_L16:
			l16_decode(*src, state->samples + state->sample_cnt,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		*src        += state->src_frame_size;
		*nbytes     -= state->src_frame_size;
		state->sample_cnt += state->src_samples_per_frame;
	}
	return 0;
}

static int encode_audio(struct mgcp_process_rtp_state *state,
			uint8_t *dst, size_t buf_size, size_t max_samples)
{
	int nbytes = 0;
	size_t nsamples = 0;
	/* Encode samples into dst */
	while (nsamples + state->dst_samples_per_frame <= max_samples) {
		if (nbytes + state->dst_frame_size > buf_size) {
			if (nbytes > 0)
				break;

			/* Not even one frame fits into the buffer */
			LOGP(DMGCP, LOGL_INFO,
			     "Encoding (RTP) buffer too small: %zu > %zu.\n",
			     nbytes + state->dst_frame_size, buf_size);
			return -ENOSPC;
		}
		switch (state->dst_fmt) {
		case AF_GSM:
			gsm_encode(state->dst.gsm_handle,
				   state->samples + state->sample_offs, dst);
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Encoder(state->dst.g729_enc,
				      state->samples + state->sample_offs, dst);
			break;
#endif
		case AF_PCMU:
			ulaw_encode(state->samples + state->sample_offs, dst,
				    state->src_samples_per_frame);
			break;
		case AF_PCMA:
			alaw_encode(state->samples + state->sample_offs, dst,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(dst, state->samples + state->sample_offs,
				state->dst_frame_size);
			break;
		case AF_L16:
			l16_encode(state->samples + state->sample_offs, dst,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		dst        += state->dst_frame_size;
		nbytes     += state->dst_frame_size;
		state->sample_offs += state->dst_samples_per_frame;
		nsamples   += state->dst_samples_per_frame;
	}
	state->sample_cnt -= nsamples;
	return nbytes;
}

static struct mgcp_rtp_end *source_for_dest(struct mgcp_endpoint *endp,
					struct mgcp_rtp_end *dst_end)
{
	if (&endp->bts_end == dst_end)
		return &endp->net_end;
	else if (&endp->net_end == dst_end)
		return &endp->bts_end;
	OSMO_ASSERT(0);
}

/*
 * With some modems we get offered multiple codecs
 * and we have selected one of them. It might not
 * be the right one and we need to detect this with
 * the first audio packets. One difficulty is that
 * we patch the rtp payload type in place, so we
 * need to discuss this.
 */
struct mgcp_process_rtp_state *check_transcode_state(
				struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
				struct rtp_hdr *rtp_hdr)
{
	struct mgcp_rtp_end *src_end;

	/* Only deal with messages from net to bts */
	if (&endp->bts_end != dst_end)
		goto done;

	src_end = source_for_dest(endp, dst_end);

	/* Already patched */
	if (rtp_hdr->payload_type == dst_end->codec.payload_type)
		goto done;
	/* The payload we expect */
	if (rtp_hdr->payload_type == src_end->codec.payload_type)
		goto done;
	/* The matching alternate payload type? Then switch */
	if (rtp_hdr->payload_type == src_end->alt_codec.payload_type) {
		struct mgcp_config *cfg = endp->cfg;
		struct mgcp_rtp_codec tmp_codec = src_end->alt_codec;
		src_end->alt_codec = src_end->codec;
		src_end->codec = tmp_codec;
		cfg->setup_rtp_processing_cb(endp, &endp->net_end, &endp->bts_end);
		cfg->setup_rtp_processing_cb(endp, &endp->bts_end, &endp->net_end);
	}

done:
	return dst_end->rtp_process_data;
}

int mgcp_transcoding_process_rtp(struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
			     char *data, int *len, int buf_size)
{
	struct mgcp_process_rtp_state *state;
	const size_t rtp_hdr_size = sizeof(struct rtp_hdr);
	struct rtp_hdr *rtp_hdr = (struct rtp_hdr *) data;
	char *payload_data = (char *) &rtp_hdr->data[0];
	int payload_len = *len - rtp_hdr_size;
	uint8_t *src = (uint8_t *)payload_data;
	uint8_t *dst = (uint8_t *)payload_data;
	size_t nbytes = payload_len;
	size_t nsamples;
	size_t max_samples;
	uint32_t ts_no;
	int rc;

	state = check_transcode_state(endp, dst_end, rtp_hdr);
	if (!state)
		return 0;

	if (state->src_fmt == state->dst_fmt) {
		if (!state->dst_packet_duration)
			return 0;

		/* TODO: repackage without transcoding */
	}

	/* If the remaining samples do not fit into a fixed ptime,
	 * a) discard them, if the next packet is much later
	 * b) add silence and * send it, if the current packet is not
	 *    yet too late
	 * c) append the sample data, if the timestamp matches exactly
	 */

	/* TODO: check payload type (-> G.711 comfort noise) */

	if (payload_len > 0) {
		ts_no = ntohl(rtp_hdr->timestamp);
		if (!state->is_running) {
			state->next_seq = ntohs(rtp_hdr->sequence);
			state->next_time = ts_no;
			state->is_running = 1;
		}


		if (state->sample_cnt > 0) {
			int32_t delta = ts_no - state->next_time;
			/* TODO: check sequence? reordering? packet loss? */

			if (delta > state->sample_cnt) {
				/* There is a time gap between the last packet
				 * and the current one. Just discard the
				 * partial data that is left in the buffer.
				 * TODO: This can be improved by adding silence
				 * instead if the delta is small enough.
				 */
				LOGP(DMGCP, LOGL_NOTICE,
					"0x%x dropping sample buffer due delta=%d sample_cnt=%zu\n",
					ENDPOINT_NUMBER(endp), delta, state->sample_cnt);
				state->sample_cnt = 0;
				state->next_time = ts_no;
			} else if (delta < 0) {
				LOGP(DMGCP, LOGL_NOTICE,
				     "RTP time jumps backwards, delta = %d, "
				     "discarding buffered samples\n",
				     delta);
				state->sample_cnt = 0;
				state->sample_offs = 0;
				return -EAGAIN;
			}

			/* Make sure the samples start without offset */
			if (state->sample_offs && state->sample_cnt)
				memmove(&state->samples[0],
					&state->samples[state->sample_offs],
					state->sample_cnt *
					sizeof(state->samples[0]));
		}

		state->sample_offs = 0;

		/* Append decoded audio to samples */
		decode_audio(state, &src, &nbytes);

		if (nbytes > 0)
			LOGP(DMGCP, LOGL_NOTICE,
			     "Skipped audio frame in RTP packet: %zu octets\n",
			     nbytes);
	} else
		ts_no = state->next_time;

	if (state->sample_cnt < state->dst_packet_duration)
		return -EAGAIN;

	max_samples =
		state->dst_packet_duration ?
		state->dst_packet_duration : state->sample_cnt;

	nsamples = state->sample_cnt;

	rc = encode_audio(state, dst, buf_size, max_samples);
	/*
	 * There were no samples to encode?
	 * TODO: how does this work for comfort noise?
	 */
	if (rc == 0)
		return -ENOMSG;
	/* Any other error during the encoding */
	if (rc < 0)
		return rc;

	nsamples -= state->sample_cnt;

	*len = rtp_hdr_size + rc;
	rtp_hdr->sequence = htons(state->next_seq);
	rtp_hdr->timestamp = htonl(ts_no);

	state->next_seq += 1;
	state->next_time = ts_no + nsamples;

	/*
	 * XXX: At this point we should always have consumed
	 * samples. So doing OSMO_ASSERT(nsamples > 0) and returning
	 * rtp_hdr_size should be fine.
	 */
	return nsamples ? rtp_hdr_size : 0;
}
