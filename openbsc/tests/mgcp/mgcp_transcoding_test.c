#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/rtp.h>
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

static int transcode_test(const char *srcfmt, const char *dstfmt,
			  uint8_t *src_pkts, size_t src_pkt_size)
{
	char buf[4096] = {0x80, 0};
	int rc;
	struct mgcp_rtp_end *dst_end;
	struct mgcp_rtp_end *src_end;
	struct mgcp_trunk_config tcfg = {{0}};
	struct mgcp_endpoint endp = {0};
	struct mgcp_process_rtp_state *state;
	int in_size;
	int in_samples = 160;
	int len, cont;
	struct rtp_hdr *rtp;
	uint32_t exp_ts;
	uint16_t exp_seq;

	printf("== Transcoding test ==\n");
	printf("converting %s -> %s\n", srcfmt, dstfmt);

	tcfg.endpoints = &endp;
	tcfg.number_endpoints = 1;
	endp.tcfg = &tcfg;
	mgcp_free_endp(&endp);

	dst_end = &endp.bts_end;
	src_end = &endp.net_end;

	src_end->payload_type = audio_name_to_type(srcfmt);
	dst_end->payload_type = audio_name_to_type(dstfmt);

	rc = mgcp_transcoding_setup(&endp, dst_end, src_end);
	if (rc < 0)
		errx(1, "setup failed: %s", strerror(-rc));

	state = dst_end->rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, in_samples, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	memcpy(buf, src_pkts, src_pkt_size);

	rtp = (struct rtp_hdr *)buf;
	OSMO_ASSERT(rtp_header_len(rtp) == 12);
	exp_ts = rtp_timestamp(rtp);
	exp_seq = rtp_sequence(rtp);

	len = src_pkt_size;

	cont = mgcp_transcoding_process_rtp(&endp, dst_end,
					    buf, &len, sizeof(buf));
	if (cont < 0)
		errx(1, "processing failed: %s", strerror(-cont));

	if (exp_ts != rtp_timestamp(rtp) || exp_seq != rtp_sequence(rtp))
		printf("RTP header fields differ: "
		       "TS %u (expected %u), SEQ %u (expected %u)\n",
		       rtp_timestamp(rtp), exp_ts,
		       rtp_sequence(rtp), exp_seq);

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
	return 0;
}

static int test_repacking(int in_samples, int out_samples, int no_transcode)
{
	char buf[4096] = {0x80, 0};
	int cc, rc;
	struct mgcp_rtp_end *dst_end;
	struct mgcp_rtp_end *src_end;
	struct mgcp_config *cfg;
	struct mgcp_trunk_config tcfg = {{0}};
	struct mgcp_endpoint endp = {0};
	struct mgcp_process_rtp_state *state;
	int in_cnt;
	int out_size;
	int in_size;
	uint32_t ts = 0;
	uint16_t seq = 0;
	uint32_t exp_ts = 0;
	uint16_t exp_seq = 0;
	const char *srcfmt = "pcma";
	const char *dstfmt = no_transcode ? "pcma" : "l16";
	struct rtp_hdr *rtp;
	int exp_undefined = 1;

	cfg = mgcp_config_alloc();

	tcfg.endpoints = &endp;
	tcfg.number_endpoints = 1;
	tcfg.cfg = cfg;
	endp.tcfg = &tcfg;
	endp.cfg = cfg;
	mgcp_free_endp(&endp);

	dst_end = &endp.bts_end;
	src_end = &endp.net_end;

	printf("== Transcoding test ==\n");
	printf("converting %s -> %s\n", srcfmt, dstfmt);

	src_end->payload_type = audio_name_to_type(srcfmt);
	dst_end->payload_type = audio_name_to_type(dstfmt);

	if (out_samples) {
		dst_end->frame_duration_den = dst_end->rate;
		dst_end->frame_duration_num = out_samples;
		dst_end->frames_per_packet = 1;
		dst_end->force_output_ptime = 1;
	}

	rc = mgcp_transcoding_setup(&endp, dst_end, src_end);
	if (rc < 0)
		errx(1, "setup failed: %s", strerror(-rc));

	state = dst_end->rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, in_samples, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	out_size = mgcp_transcoding_get_frame_size(state, -1, 1);
	OSMO_ASSERT(sizeof(buf) >= out_size + 12);

	rtp = (struct rtp_hdr *)buf;
	OSMO_ASSERT(rtp_header_len(rtp) == 12);

	rtp->payload_type = src_end->payload_type;
	rtp_set_sequence(rtp, 1);
	rtp_set_timestamp(rtp, 0);
	rtp_set_ssrc(rtp, 0xaabbccdd);

	for (in_cnt = 0; in_cnt < 16; in_cnt++) {
		int cont;
		int len;

		/* fake PCMA data */
		printf("generating %d %s input samples\n", in_samples, srcfmt);
		for (cc = 0; cc < in_samples; cc++)
			buf[12+cc] = cc;

		rtp_set_sequence(rtp, seq);
		rtp_set_timestamp(rtp, ts);

		seq += 1;
		ts += in_samples;

		cc += 12; /* include RTP header */

		len = cc;

		do {
			cont = mgcp_transcoding_process_rtp(&endp, dst_end,
							    buf, &len, sizeof(buf));
			if (cont == -EAGAIN) {
				fprintf(stderr, "Got EAGAIN\n");
				break;
			}

			if (cont < 0)
				errx(1, "processing failed: %s", strerror(-cont));

			if (exp_undefined) {
				exp_ts = rtp_timestamp(rtp);
				exp_seq = rtp_sequence(rtp);
				exp_undefined = 0;
			} else {
				exp_ts += out_samples;
				exp_seq += 1;
			}

			if (exp_ts != rtp_timestamp(rtp) ||
			    exp_seq != rtp_sequence(rtp))
				printf("RTP header fields differ: "
				       "TS %u (expected %u), SEQ %u (expected %u)\n",
				       rtp_timestamp(rtp), exp_ts,
				       rtp_sequence(rtp), exp_seq);

			len -= 12; /* ignore RTP header */

			printf("got %d %s output frames (%d octets)\n",
			       len / out_size, dstfmt, len);

			len = cont;
		} while (len > 0);
	}
	return 0;
}

int main(int argc, char **argv)
{
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
	transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_size[0].data,
		       audio_packets_gsm_invalid_size[0].len);

	printf("Invalid data:\n");
	transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_data[0].data,
		       audio_packets_gsm_invalid_data[0].len);

	printf("Invalid payload type:\n");
	transcode_test("gsm", "pcma",
		       (uint8_t *)audio_packets_gsm_invalid_ptype[0].data,
		       audio_packets_gsm_invalid_ptype[0].len);

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

	return 0;
}

