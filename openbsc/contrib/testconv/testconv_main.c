#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include "bscconfig.h"
#ifndef BUILD_MGCP_TRANSCODING
#error "Requires MGCP transcoding enabled (see --enable-mgcp-transcoding)"
#endif

#include "openbsc/mgcp_transcode.h"

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

int main(int argc, char **argv)
{
	char buf[4096] = {0x80, 0};
	int cc, rc;
	struct mgcp_rtp_end *dst_end;
	struct mgcp_rtp_end *src_end;
	struct mgcp_trunk_config tcfg = {{0}};
	struct mgcp_endpoint endp = {0};
	struct mgcp_process_rtp_state *state;
	int in_size;
	int in_samples = 160;
	int out_samples = 0;
	uint32_t ts = 0;
	uint16_t seq = 0;

	osmo_init_logging(&log_info);

	tcfg.endpoints = &endp;
	tcfg.number_endpoints = 1;
	endp.tcfg = &tcfg;
	mgcp_initialize_endp(&endp);

	dst_end = &endp.bts_end;
	src_end = &endp.net_end;

	if (argc <= 2)
		errx(1, "Usage: {gsm|g729|pcma|l16} {gsm|g729|pcma|l16} [SPP]");

	if ((src_end->codec.payload_type = audio_name_to_type(argv[1])) == -1)
		errx(1, "invalid input format '%s'", argv[1]);
	if ((dst_end->codec.payload_type = audio_name_to_type(argv[2])) == -1)
		errx(1, "invalid output format '%s'", argv[2]);
	if (argc > 3)
		out_samples = atoi(argv[3]);

	if (out_samples) {
		dst_end->codec.frame_duration_den = dst_end->codec.rate;
		dst_end->codec.frame_duration_num = out_samples;
		dst_end->frames_per_packet = 1;
	}

	rc = mgcp_transcoding_setup(&endp, dst_end, src_end);
	if (rc < 0)
		errx(1, "setup failed: %s", strerror(-rc));

	state = dst_end->rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, in_samples, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	buf[1] = src_end->codec.payload_type;
	*(uint16_t*)(buf+2) = htons(1);
	*(uint32_t*)(buf+4) = htonl(0);
	*(uint32_t*)(buf+8) = htonl(0xaabbccdd);

	while ((cc = read(0, buf + 12, in_size))) {
		int cont;
		int len;

		if (cc != in_size)
			err(1, "read");

		*(uint16_t*)(buf+2) = htonl(seq);
		*(uint32_t*)(buf+4) = htonl(ts);

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

			len -= 12; /* ignore RTP header */

			if (write(1, buf + 12, len) != len)
				err(1, "write");

			len = cont;
		} while (len > 0);
	}
	return 0;
}

