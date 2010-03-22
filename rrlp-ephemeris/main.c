
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "gps.h"
#include "ubx.h"
#include "ubx-parse.h"
#include "rrlp.h"

static int
do_ubx_read(struct gps_assist_data *gps, const char *filename)
{
	int rv, fd, i;
	struct stat st;
	void *buf;

	/* Load file */
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	rv = fstat(fd, &st);
	if (rv < 0) {
		close(fd);
		return -1;
	}

	buf = malloc(st.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	rv = read(fd, buf, st.st_size);
	if (rv != st.st_size) {
		free(buf);
		close(fd);
		return -1;
	}

	/* Parse each message */
	for (i=0; i<st.st_size;) {
		int rv;
		rv = ubx_msg_dispatch(ubx_parse_dt, buf + i, st.st_size - i, gps);
		if (rv < 0)
			i++;	/* Invalid message: try one byte later */
		else
			i += rv;
	}

	/* Done */
	free(buf);
	close(fd);

	return 0;
}

static int
do_rrlp(struct gps_assist_data *gps)
{
	struct rrlp_assist_req ar;
	void *pdus[64];
	int len[64];
	int i, rv;

	char *test = "\x28\x00\x80\x10\x01\x32\x00\x19\x4F\x07\x15\x04";

	rrlp_decode_assistance_request(&ar, test, 12);
	printf("%08x %016llx\n", ar.req_elems, (long long unsigned) ar.eph_svs);

	ar.req_elems = -1;
	ar.eph_svs = -1LL;
	rv = rrlp_gps_assist_pdus(gps, &ar, pdus, len, 64);
	printf("%d\n", rv);
	for (i=0; i<rv; i++) {
		printf("%p %d\n", pdus[i], len[i]);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct gps_assist_data gps;
	int rv;

	memset(&gps, 0x00, sizeof(gps));

	rv = do_ubx_read(&gps, "data.ubx");
	
	rv = do_rrlp(&gps);

	return 0;
}

