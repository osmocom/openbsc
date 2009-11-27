/* Debugging/Logging support code */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openbsc/debug.h>

unsigned int debug_mask = 0xffffffff & ~(DMI|DMIB|DMEAS);

struct debug_info {
	const char *name;
	const char *color;
	const char *description;
	int number;
};

#define DEBUG_CATEGORY(NUMBER, NAME, COLOR, DESCRIPTION) \
	{ .name = NAME, .color = COLOR, .description = DESCRIPTION, .number = NUMBER },

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))

static const struct debug_info debug_info[] = {
	DEBUG_CATEGORY(DRLL,  "DRLL", "\033[1;31m", "")
	DEBUG_CATEGORY(DCC,   "DCC",  "\033[1;32m", "")
	DEBUG_CATEGORY(DMM,   "DMM",  "\033[1;33m", "")
	DEBUG_CATEGORY(DRR,   "DRR",  "\033[1;34m", "")
	DEBUG_CATEGORY(DRSL,  "DRSL", "\033[1;35m", "")
	DEBUG_CATEGORY(DNM,   "DNM",  "\033[1;36m", "")
	DEBUG_CATEGORY(DSMS,  "DSMS", "\033[1;37m", "")
	DEBUG_CATEGORY(DPAG,  "DPAG", "\033[1;38m", "")
	DEBUG_CATEGORY(DMNCC, "DMNCC","\033[1;39m", "")
	DEBUG_CATEGORY(DINP,  "DINP", "", "")
	DEBUG_CATEGORY(DMI,  "DMI", "", "")
	DEBUG_CATEGORY(DMIB,  "DMIB", "", "")
	DEBUG_CATEGORY(DMUX,  "DMUX", "", "")
	DEBUG_CATEGORY(DMEAS,  "DMEAS", "", "")
	DEBUG_CATEGORY(DSCCP, "DSCCP", "", "")
	DEBUG_CATEGORY(DMSC, "DMSC", "", "")
	DEBUG_CATEGORY(DMGCP, "DMGCP", "", "")
};

static int use_color = 1;

void debug_use_color(int color)
{
	use_color = color;
}

static int print_timestamp = 0;

void debug_timestamp(int enable)
{
	print_timestamp = enable;
}


/*
 * Parse the category mask.
 * category1:category2:category3
 */
void debug_parse_category_mask(const char *_mask)
{
	unsigned int new_mask = 0;
	int i = 0;
	char *mask = strdup(_mask);
	char *category_token = NULL;

	category_token = strtok(mask, ":");
	do {
		for (i = 0; i < ARRAY_SIZE(debug_info); ++i) {
			if (strcasecmp(debug_info[i].name, category_token) == 0)
				new_mask |= debug_info[i].number;
		}
	} while ((category_token = strtok(NULL, ":")));


	free(mask);
	debug_mask = new_mask;
}

const char* color(int subsys)
{
	int i = 0;

	for (i = 0; use_color && i < ARRAY_SIZE(debug_info); ++i) {
		if (debug_info[i].number == subsys)
			return debug_info[i].color;
	}

	return "";
}

void debugp(unsigned int subsys, char *file, int line, int cont, const char *format, ...)
{
	va_list ap;
	FILE *outfd = stderr;

	if (!(debug_mask & subsys))
		return;

	va_start(ap, format);

	fprintf(outfd, "%s", color(subsys));

	if (!cont) {
		if (print_timestamp) {
			char *timestr;
			time_t tm;
			tm = time(NULL);
			timestr = ctime(&tm);
			timestr[strlen(timestr)-1] = '\0';
			fprintf(outfd, "%s ", timestr);
		}
		fprintf(outfd, "<%4.4x> %s:%d ", subsys, file, line);
	}
	vfprintf(outfd, format, ap);
	fprintf(outfd, "\033[0;m");

	va_end(ap);

	fflush(outfd);
}

static char hexd_buff[4096];

char *hexdump(const unsigned char *buf, int len)
{
	int i;
	char *cur = hexd_buff;

	hexd_buff[0] = 0;
	for (i = 0; i < len; i++) {
		int len_remain = sizeof(hexd_buff) - (cur - hexd_buff);
		int rc = snprintf(cur, len_remain, "%02x ", buf[i]);
		if (rc <= 0)
			break;
		cur += rc;
	}
	hexd_buff[sizeof(hexd_buff)-1] = 0;
	return hexd_buff;
}

