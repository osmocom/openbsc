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

static unsigned int debug_mask = 0xffffffff & ~DMI;

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
	DEBUG_CATEGORY(DRLL,  "DRLL", "", "")
	DEBUG_CATEGORY(DCC,   "DCC",  "", "")
	DEBUG_CATEGORY(DNM,   "DMM",  "", "")
	DEBUG_CATEGORY(DRR,   "DRR",  "", "")
	DEBUG_CATEGORY(DRSL,  "DRSSL","", "")
	DEBUG_CATEGORY(DNM,   "DNM",  "", "")
};

/*
 * Parse the category mask.
 * category1:category2:category3
 */
void parse_category_mask(const char *_mask)
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
	} while (category_token = strtok(NULL, ":"));


	free(mask);
	debug_mask = new_mask;
}

void debugp(unsigned int subsys, char *file, int line, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd = stderr;

	if (!(debug_mask & subsys))
		return;

	va_start(ap, format);

	tm = time(NULL);
	timestr = ctime(&tm);
	timestr[strlen(timestr)-1] = '\0';
	fprintf(outfd, "%s <%4.4x> %s:%d ", timestr, subsys, file, line);
	vfprintf(outfd, format, ap);

	va_end(ap);

	fflush(outfd);
}

