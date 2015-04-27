#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdint.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/application.h>

#include <osmocom/netif/rtp.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include "bscconfig.h"
#ifndef BUILD_MGCP_TRANSCODING
#error "Requires MGCP transcoding enabled (see --enable-mgcp-transcoding)"
#endif

#include "openbsc/mgcp_transcode.h"

uint8_t *audio_frame_l16[] = {
};

struct rtp_packets {
	float t;
	int len;
	char *data;
};

struct rtp_packets audio_packets_l16[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 332,
		"\x80\x0B\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
		"\x00\x00\x40\x13\x5A\x9E\x40\x13\x00\x00\xBF\xED\xA5\x62\xBF\xED"
	},
};

struct rtp_packets audio_packets_gsm[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 45,
		"\x80\x03\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xD4\x7C\xE3\xE9\x62\x50\x39\xF0\xF8\xB4\x68\xEA\x6C\x0E\x81\x1B"
		"\x56\x2A\xD5\xBC\x69\x9C\xD1\xF0\x66\x7A\xEC\x49\x7A\x33\x3D\x0A"
		"\xDE"
	},
};

struct rtp_packets audio_packets_gsm_invalid_size[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 41,
		"\x80\x03\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xD4\x7C\xE3\xE9\x62\x50\x39\xF0\xF8\xB4\x68\xEA\x6C\x0E\x81\x1B"
		"\x56\x2A\xD5\xBC\x69\x9C\xD1\xF0\x66\x7A\xEC\x49\x7A\x33\x3D\x0A"
		"\xDE"
	},
};

struct rtp_packets audio_packets_gsm_invalid_data[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 45,
		"\x80\x03\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
		"\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
		"\xEE"
	},
};

struct rtp_packets audio_packets_gsm_invalid_ptype[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 45,
		"\x80\x08\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xD4\x7C\xE3\xE9\x62\x50\x39\xF0\xF8\xB4\x68\xEA\x6C\x0E\x81\x1B"
		"\x56\x2A\xD5\xBC\x69\x9C\xD1\xF0\x66\x7A\xEC\x49\x7A\x33\x3D\x0A"
		"\xDE"
	},
};

struct rtp_packets audio_packets_g729[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 32,
		"\x80\x12\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xAF\xC2\x81\x40\x00\xFA\xCE\xA4\x21\x7C\xC5\xC3\x4F\xA5\x98\xF5"
		"\xB2\x95\xC4\xAD"
	},
};

struct rtp_packets audio_packets_pcma[] = {
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 172,
		"\x80\x08\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
		"\xD5\xA5\xA3\xA5\xD5\x25\x23\x25\xD5\xA5\xA3\xA5\xD5\x25\x23\x25"
	},
	/* RTP: SeqNo=26527, TS=232640 */
	{0.020000, 92,
		"\x80\x08\x67\x9f\x00\x03\x8c\xc0\x04\xaa\x67\x9f\xd5\xd5\xd5\xd5"
		"\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5"
		"\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5"
		"\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5"
		"\xd5\xd5\xd5\xd5\xd5\xd5\x55\x55\xd5\xd5\x55\x55\xd5\xd5\x55\x55"
		"\xd5\xd5\xd5\x55\x55\xd5\xd5\xd5\x55\x55\xd5\xd5"
	},
	/* RTP: SeqNo=26528, TS=232720 */
	{0.020000, 92,
		"\x80\x08\x67\xa0\x00\x03\x8d\x10\x04\xaa\x67\x9f\x55\xd5\xd5\x55"
		"\xd5\x55\xd5\xd5\xd5\x55\xd5\x55\xd5\xd5\x55\xd5\x55\xd5\x55\xd5"
		"\x55\x55\xd5\x55\xd5\xd5\x55\x55\x55\x55\x55\xd5\xd5\x55\xd5\xd5"
		"\xd5\x55\xd5\xd5\xd5\x55\x54\x55\xd5\xd5\x55\xd5\xd5\xd5\xd5\x55"
		"\x54\x55\xd5\x55\xd5\x55\x55\x55\x55\x55\xd5\xd5\xd5\xd5\xd5\xd4"
		"\xd5\x54\x55\xd5\xd4\xd5\x54\xd5\x55\xd5\xd5\xd5"
	},
};



static int audio_name_to_type(const char *name)
{
	if (!strcasecmp(name, "gsm"))
		return 3;
#ifdef HAVE_BCG729
	else if (!strcasecmp(name, "g729"))
		return 18;
#endif
	else if (!strcasecmp(name, "pcma"))
		return 8;
	else if (!strcasecmp(name, "l16"))
		return 11;
	return -1;
}

int mgcp_get_trans_frame_size(void *state_, int nsamples, int dst);

static int given_configured_endpoint(int in_samples, int out_samples,
				const char *srcfmt, const char *dstfmt,
				void **out_ctx, struct mgcp_endpoint **out_endp)
{
	int rc;
	struct mgcp_rtp_end *dst_end;
	struct mgcp_rtp_end *src_end;
	struct mgcp_config *cfg;
	struct mgcp_trunk_config *tcfg;
	struct mgcp_endpoint *endp;

	cfg = mgcp_config_alloc();
	tcfg = talloc_zero(cfg, struct mgcp_trunk_config);
	endp = talloc_zero(tcfg, struct mgcp_endpoint);

	cfg->setup_rtp_processing_cb = mgcp_transcoding_setup;
	cfg->rtp_processing_cb = mgcp_transcoding_process_rtp;
	cfg->get_net_downlink_format_cb = mgcp_transcoding_net_downlink_format;

	tcfg->endpoints = endp;
	tcfg->number_endpoints = 1;
	tcfg->cfg = cfg;
	endp->tcfg = tcfg;
	endp->cfg = cfg;
	mgcp_initialize_endp(endp);

	dst_end = &endp->bts_end;
	dst_end->codec.payload_type = audio_name_to_type(dstfmt);

	src_end = &endp->net_end;
	src_end->codec.payload_type = audio_name_to_type(srcfmt);

	if (out_samples) {
		dst_end->codec.frame_duration_den = dst_end->codec.rate;
		dst_end->codec.frame_duration_num = out_samples;
		dst_end->frames_per_packet = 1;
		dst_end->force_output_ptime = 1;
	}

	rc = mgcp_transcoding_setup(endp, dst_end, src_end);
	if (rc < 0) {
		printf("setup failed: %s", strerror(-rc));
		abort();
	}

	*out_ctx = cfg;
	*out_endp = endp;
	return 0;
}


static int transcode_test(const char *srcfmt, const char *dstfmt,
			  uint8_t *src_pkts, size_t src_pkt_size)
{
	char buf[4096] = {0x80, 0};
	void *ctx;

	struct mgcp_rtp_end *dst_end;
	struct mgcp_process_rtp_state *state;
	struct mgcp_endpoint *endp;
	int in_size;
	const int in_samples = 160;
	int len, cont;

	printf("== Transcoding test ==\n");
	printf("converting %s -> %s\n", srcfmt, dstfmt);

	given_configured_endpoint(in_samples, 0, srcfmt, dstfmt, &ctx, &endp);

	dst_end = &endp->bts_end;
	state = dst_end->rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, in_samples, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	memcpy(buf, src_pkts, src_pkt_size);

	len = src_pkt_size;

	cont = mgcp_transcoding_process_rtp(endp, dst_end,
					    buf, &len, sizeof(buf));
	if (cont < 0) {
		printf("Nothing encoded due: %s\n", strerror(-cont));
		talloc_free(ctx);
		return -1;
	}

	if (len < 24) {
		printf("encoded: %s\n", osmo_hexdump((unsigned char *)buf, len));
	} else {
		const char *str = osmo_hexdump((unsigned char *)buf, len);
		int i = 0;
		const int prefix = 4;
		const int cutlen = 48;
		int nchars = 0;

		printf("encoded:\n");
		do {
			nchars = printf("%*s%-.*s", prefix, "", cutlen, str + i);
			i += nchars - prefix;
			printf("\n");
		} while (nchars - prefix >= cutlen);
	}
	printf("counted: %d\n", cont);
	talloc_free(ctx);
	return 0;
}

static void test_rtp_seq_state(void)
{
	char buf[4096];
	int len;
	int cont;
	void *ctx;
	struct mgcp_endpoint *endp;
	struct mgcp_process_rtp_state *state;
	struct rtp_hdr *hdr;
	uint32_t ts_no;
	uint16_t seq_no;

	given_configured_endpoint(160, 0, "pcma", "l16", &ctx, &endp);
	state = endp->bts_end.rtp_process_data;
	OSMO_ASSERT(!state->is_running);
	OSMO_ASSERT(state->next_seq == 0);
	OSMO_ASSERT(state->next_time == 0);

	/* initialize packet */
	len = audio_packets_pcma[0].len;
	memcpy(buf, audio_packets_pcma[0].data, len);
	cont = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, len);
	OSMO_ASSERT(cont >= 0);
	OSMO_ASSERT(state->is_running);
	OSMO_ASSERT(state->next_seq == 2);
	OSMO_ASSERT(state->next_time == 240);

	/* verify that the right timestamp was written */
	OSMO_ASSERT(len == audio_packets_pcma[0].len);
	hdr = (struct rtp_hdr *) &buf[0];

	memcpy(&ts_no, &hdr->timestamp, sizeof(ts_no));
	OSMO_ASSERT(htonl(ts_no) == 160);
	memcpy(&seq_no, &hdr->sequence, sizeof(seq_no));
	OSMO_ASSERT(htons(seq_no) == 1);
	/* Check the right sequence number is written */
	state->next_seq = 1234;
	len = audio_packets_pcma[0].len;
	memcpy(buf, audio_packets_pcma[0].data, len);
	cont = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, len);
	OSMO_ASSERT(cont >= 0);
	OSMO_ASSERT(len == audio_packets_pcma[0].len);
	hdr = (struct rtp_hdr *) &buf[0];

	memcpy(&seq_no, &hdr->sequence, sizeof(seq_no));
	OSMO_ASSERT(htons(seq_no) == 1234);

	talloc_free(ctx);
}

static void test_transcode_result(void)
{
	char buf[4096];
	int len, res;
	void *ctx;
	struct mgcp_endpoint *endp;
	struct mgcp_process_rtp_state *state;

	{
		/* from GSM to PCMA and same ptime */
		given_configured_endpoint(160, 0, "gsm", "pcma", &ctx, &endp);
		state = endp->bts_end.rtp_process_data;

		/* result */
		len = audio_packets_gsm[0].len;
		memcpy(buf, audio_packets_gsm[0].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == sizeof(struct rtp_hdr));
		OSMO_ASSERT(state->sample_cnt == 0);

		len = res;
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == -ENOMSG);

		talloc_free(ctx);
	}

	{
		/* from GSM to PCMA and same ptime */
		given_configured_endpoint(160, 160, "gsm", "pcma", &ctx, &endp);
		state = endp->bts_end.rtp_process_data;

		/* result */
		len = audio_packets_gsm[0].len;
		memcpy(buf, audio_packets_gsm[0].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == sizeof(struct rtp_hdr));
		OSMO_ASSERT(state->sample_cnt == 0);

		len = res;
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == -EAGAIN);

		talloc_free(ctx);
	}

	{
		/* from PCMA to GSM and wrong different ptime */
		given_configured_endpoint(80, 160, "pcma", "gsm", &ctx, &endp);
		state = endp->bts_end.rtp_process_data;

		/* Add the first sample */
		len = audio_packets_pcma[1].len;
		memcpy(buf, audio_packets_pcma[1].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(state->sample_cnt == 80);
		OSMO_ASSERT(state->next_time == 232640);
		OSMO_ASSERT(res < 0);

		/* Add the second sample and it should be consumable */
		len = audio_packets_pcma[2].len;
		memcpy(buf, audio_packets_pcma[2].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(state->sample_cnt == 0);
		OSMO_ASSERT(state->next_time == 232640 + 80 + 160);
		OSMO_ASSERT(res == sizeof(struct rtp_hdr));

		talloc_free(ctx);
	}

	{
		/* from PCMA to GSM with a big time jump */
		struct rtp_hdr *hdr;
		uint32_t ts;

		given_configured_endpoint(80, 160, "pcma", "gsm", &ctx, &endp);
		state = endp->bts_end.rtp_process_data;

		/* Add the first sample */
		len = audio_packets_pcma[1].len;
		memcpy(buf, audio_packets_pcma[1].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(state->sample_cnt == 80);
		OSMO_ASSERT(state->next_time == 232640);
		OSMO_ASSERT(state->next_seq == 26527);
		OSMO_ASSERT(res < 0);

		/* Add a skip to the packet to force a 'resync' */
		len = audio_packets_pcma[2].len;
		memcpy(buf, audio_packets_pcma[2].data, len);
		hdr = (struct rtp_hdr *) &buf[0];
		/* jump the time and add alignment error */
		ts = ntohl(hdr->timestamp) + 123 * 80 + 2;
		hdr->timestamp = htonl(ts);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res < 0);
		OSMO_ASSERT(state->sample_cnt == 80);
		OSMO_ASSERT(state->next_time == ts);
		OSMO_ASSERT(state->next_seq == 26527);
		/* TODO: this can create alignment errors */


		/* Now attempt to consume 160 samples */
		len = audio_packets_pcma[2].len;
		memcpy(buf, audio_packets_pcma[2].data, len);
		hdr = (struct rtp_hdr *) &buf[0];
		ts += 80;
		hdr->timestamp = htonl(ts);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == 12);
		OSMO_ASSERT(state->sample_cnt == 0);
		OSMO_ASSERT(state->next_time == ts + 160);
		OSMO_ASSERT(state->next_seq == 26528);

		talloc_free(ctx);
	}
}

static void test_transcode_change(void)
{
	char buf[4096] = {0x80, 0};
	void *ctx;

	struct mgcp_endpoint *endp;
	struct mgcp_process_rtp_state *state;
	struct rtp_hdr *hdr;

	int len, res;

	{
		/* from GSM to PCMA and same ptime */
		printf("Testing Initial L16->GSM, PCMA->GSM\n");
		given_configured_endpoint(160, 0, "l16", "gsm", &ctx, &endp);
		endp->net_end.alt_codec = endp->net_end.codec;
		endp->net_end.alt_codec.payload_type = audio_name_to_type("pcma");
		state = endp->bts_end.rtp_process_data;

		/* initial transcoding work */
		OSMO_ASSERT(state->src_fmt == AF_L16);
		OSMO_ASSERT(state->dst_fmt == AF_GSM);
		OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 8);
		OSMO_ASSERT(endp->net_end.codec.payload_type == 11);

		/* result */
		len = audio_packets_pcma[0].len;
		memcpy(buf, audio_packets_pcma[0].data, len);
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		state = endp->bts_end.rtp_process_data;
		OSMO_ASSERT(res == sizeof(struct rtp_hdr));
		OSMO_ASSERT(state->sample_cnt == 0);
		OSMO_ASSERT(state->src_fmt == AF_PCMA);
		OSMO_ASSERT(state->dst_fmt == AF_GSM);
		OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 11);
		OSMO_ASSERT(endp->net_end.codec.payload_type == 8);

		len = res;
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(res == -ENOMSG);
		OSMO_ASSERT(state == endp->bts_end.rtp_process_data);


		/* now check that comfort noise doesn't change anything */
		len = audio_packets_pcma[1].len;
		memcpy(buf, audio_packets_pcma[1].data, len);
		hdr = (struct rtp_hdr *) buf;
		hdr->payload_type = 12;
		res = mgcp_transcoding_process_rtp(endp, &endp->bts_end, buf, &len, ARRAY_SIZE(buf));
		OSMO_ASSERT(state == endp->bts_end.rtp_process_data);
		OSMO_ASSERT(state->sample_cnt == 80);
		OSMO_ASSERT(state->src_fmt == AF_PCMA);
		OSMO_ASSERT(state->dst_fmt == AF_GSM);
		OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 11);
		OSMO_ASSERT(endp->net_end.codec.payload_type == 8);

		talloc_free(ctx);
	}
}

static int test_repacking(int in_samples, int out_samples, int no_transcode)
{
	char buf[4096] = {0x80, 0};
	int cc;
	struct mgcp_endpoint *endp;
	void *ctx;

	struct mgcp_process_rtp_state *state;
	int in_cnt;
	int out_size;
	int in_size;
	uint32_t ts = 0;
	uint16_t seq = 0;
	const char *srcfmt = "pcma";
	const char *dstfmt = no_transcode ? "pcma" : "l16";

	printf("== Transcoding test ==\n");
	printf("converting %s -> %s\n", srcfmt, dstfmt);

	given_configured_endpoint(in_samples, out_samples, srcfmt, dstfmt, &ctx, &endp);

	state = endp->bts_end.rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, in_samples, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	out_size = mgcp_transcoding_get_frame_size(state, -1, 1);
	OSMO_ASSERT(sizeof(buf) >= out_size + 12);

	buf[1] = endp->net_end.codec.payload_type;
	*(uint16_t*)(buf+2) = htons(1);
	*(uint32_t*)(buf+4) = htonl(0);
	*(uint32_t*)(buf+8) = htonl(0xaabbccdd);

	for (in_cnt = 0; in_cnt < 16; in_cnt++) {
		int cont;
		int len;

		/* fake PCMA data */
		printf("generating %d %s input samples\n", in_samples, srcfmt);
		for (cc = 0; cc < in_samples; cc++)
			buf[12+cc] = cc;

		*(uint16_t*)(buf+2) = htonl(seq);
		*(uint32_t*)(buf+4) = htonl(ts);

		seq += 1;
		ts += in_samples;

		cc += 12; /* include RTP header */

		len = cc;

		do {
			cont = mgcp_transcoding_process_rtp(endp, &endp->bts_end,
							    buf, &len, sizeof(buf));
			if (cont == -EAGAIN) {
				fprintf(stderr, "Got EAGAIN\n");
				break;
			}

			if (cont < 0) {
				printf("processing failed: %s", strerror(-cont));
				abort();
			}

			len -= 12; /* ignore RTP header */

			printf("got %d %s output frames (%d octets) count=%d\n",
			       len / out_size, dstfmt, len, cont);

			len = cont;
		} while (len > 0);
	}

	talloc_free(ctx);
	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	osmo_init_logging(&log_info);

	printf("=== Transcoding Good Cases ===\n");

	transcode_test("l16", "l16",
		       (uint8_t *)audio_packets_l16[0].data,
		       audio_packets_l16[0].len);
	transcode_test("l16", "gsm",
		       (uint8_t *)audio_packets_l16[0].data,
		       audio_packets_l16[0].len);
	transcode_test("l16", "pcma",
		       (uint8_t *)audio_packets_l16[0].data,
		       audio_packets_l16[0].len);
	transcode_test("gsm", "l16",
		       (uint8_t *)audio_packets_gsm[0].data,
		       audio_packets_gsm[0].len);
	transcode_test("gsm", "gsm",
		       (uint8_t *)audio_packets_gsm[0].data,
		       audio_packets_gsm[0].len);
	transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm[0].data,
		       audio_packets_gsm[0].len);
	transcode_test("pcma", "l16",
		       (uint8_t *)audio_packets_pcma[0].data,
		       audio_packets_pcma[0].len);
	transcode_test("pcma", "gsm",
		       (uint8_t *)audio_packets_pcma[0].data,
		       audio_packets_pcma[0].len);
	transcode_test("pcma", "pcma",
		       (uint8_t *)audio_packets_pcma[0].data,
		       audio_packets_pcma[0].len);

	printf("=== Transcoding Bad Cases ===\n");

	printf("Invalid size:\n");
	rc = transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_size[0].data,
		       audio_packets_gsm_invalid_size[0].len);
	OSMO_ASSERT(rc < 0);

	printf("Invalid data:\n");
	rc = transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_data[0].data,
		       audio_packets_gsm_invalid_data[0].len);
	OSMO_ASSERT(rc < 0);

	printf("Invalid payload type:\n");
	rc = transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_ptype[0].data,
		       audio_packets_gsm_invalid_ptype[0].len);
	OSMO_ASSERT(rc == 0);

	printf("=== Repacking ===\n");

	test_repacking(160, 160, 0);
	test_repacking(160, 160, 1);
	test_repacking(160, 80, 0);
	test_repacking(160, 80, 1);
	test_repacking(160, 320, 0);
	test_repacking(160, 320, 1);
	test_repacking(160, 240, 0);
	test_repacking(160, 240, 1);
	test_repacking(160, 100, 0);
	test_repacking(160, 100, 1);
	test_rtp_seq_state();
	test_transcode_result();
	test_transcode_change();

	return 0;
}

