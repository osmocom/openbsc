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

#include "src/osmo-bsc_mgcp/mgcp_transcode.h"

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
	char buf[4096] = {0};
	int cc, rc;
	struct mgcp_rtp_end dst_end = {0};
	struct mgcp_rtp_end src_end = {0};
	struct mgcp_trunk_config tcfg = {{0}};
	struct mgcp_endpoint endp = {0};
	struct mgcp_process_rtp_state *state;
	int in_size;

	osmo_init_logging(&log_info);

	tcfg.endpoints = &endp;
	tcfg.number_endpoints = 1;
	endp.tcfg = &tcfg;

	if (argc <= 2)
		errx(1, "Usage: {gsm|g729|pcma|l16} {gsm|g729|pcma|l16}");

	if ((src_end.payload_type = audio_name_to_type(argv[1])) == -1)
		errx(1, "invalid input format '%s'", argv[1]);
	if ((dst_end.payload_type = audio_name_to_type(argv[2])) == -1)
		errx(1, "invalid output format '%s'", argv[2]);

	rc = mgcp_transcoding_setup(&endp, &dst_end, &src_end);
	if (rc < 0)
		errx(1, "setup failed: %s", strerror(-rc));

	state = dst_end.rtp_process_data;
	OSMO_ASSERT(state != NULL);

	in_size = mgcp_transcoding_get_frame_size(state, 160, 0);
	OSMO_ASSERT(sizeof(buf) >= in_size + 12);

	while ((cc = read(0, buf + 12, in_size))) {
		if (cc != in_size)
			err(1, "read");

		cc += 12; /* include RTP header */

		rc = mgcp_transcoding_process_rtp(&endp, &dst_end,
						  buf, &cc, sizeof(buf));
		if (rc < 0)
			errx(1, "processing failed: %s", strerror(-rc));

		cc -= 12; /* ignore RTP header */
		if (write(1, buf + 12, cc) != cc)
			err(1, "write");
	}
	return 0;
}

