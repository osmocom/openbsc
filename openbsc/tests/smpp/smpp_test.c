/*
 * (C) 2013 by Holger Hans Peter Freyther
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
#include <stdio.h>

#include <openbsc/debug.h>

#include <osmocom/core/application.h>
#include <osmocom/core/backtrace.h>

#include "smpp_smsc.h"

struct coding_test {
	uint8_t dcs;
	uint8_t coding;
	int	mode;
	int	res;
};

static struct coding_test codecs[] = {
	{ .dcs = 0xf6		, .coding = 0x02, .mode = MODE_8BIT,	.res = 0  },
	{ .dcs = 0xf2		, .coding = 0x01, .mode = MODE_7BIT,	.res = 0  },
	{ .dcs = 0x02		, .coding = 0x01, .mode = MODE_7BIT,	.res = 0  },
	{ .dcs = 0x06		, .coding = 0x02, .mode = MODE_8BIT,	.res = 0  },
	{ .dcs = 0x0A		, .coding = 0x08, .mode = MODE_8BIT,	.res = 0  },
	{ .dcs = 0x0E		, .coding = 0xFF, .mode = 0xFF,		.res = -1 },
	{ .dcs = 0xE0		, .coding = 0xFF, .mode = 0xFF,		.res = -1 },
};

static void test_coding_scheme(void)
{
	int i;
	printf("Testing coding scheme support\n");

	for (i = 0; i < ARRAY_SIZE(codecs); ++i) {
		uint8_t coding;
		int mode, res;

		res = smpp_determine_scheme(codecs[i].dcs, &coding, &mode);
		OSMO_ASSERT(res == codecs[i].res);
		if (res != -1) {
			OSMO_ASSERT(mode == codecs[i].mode);
			OSMO_ASSERT(coding == codecs[i].coding);
		}
	}
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	test_coding_scheme();
	return EXIT_SUCCESS;
}
