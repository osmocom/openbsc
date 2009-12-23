/* Routines for parsing an ipacces SDP firmware file */

/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



static void analyze_file(int fd)
{
	char buf[4096];
	int rc;

	rc = read(fd, buf, 4);
	if (rc <= 0) {
		fprintf(stderr, "Not enough space for the header.\n");
		return;
	}

	if (strcmp(buf, " SDP") != 0) {
		fprintf(stderr, "Wrong magic number at the beginning of the file.\n");
		return;
	}

	printf("Printing header information:\n");
}

int main(int argc, char** argv)
{
	int i, fd;

	for (i = 1; i < argc; ++i) {
		printf("Opening possible firmware '%s'\n", argv[i]);
		fd = open(argv[i], O_RDONLY);
		if (!fd) {
			perror("nada");
			continue;
		}

		analyze_file(fd);
	}

	return EXIT_SUCCESS;
}
