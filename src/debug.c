/* Debugging/Logging support code */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openbsc/debug.h>

static unsigned int debug_mask = 0xffffffff & ~DMI;

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

