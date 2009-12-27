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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct sdp_firmware {
	char magic[4];
	char more_magic[4];
	unsigned int header_length;
	unsigned int file_length;
	char sw_part[20];
	char text1[122];
	u_int8_t no_idea_1[4];
	char text2[64];
	char time[8];
	u_int8_t no_idea_2[4];
	char date[8];
	u_int8_t no_idea_3[6];
	/* stuff i don't know */
} __attribute__((packed));

/* more magic, the second "int" in the header */
static char more_magic[] = { 0x10, 0x02, 0x00, 0x0 };


static void analyze_file(int fd)
{
	struct sdp_firmware *firmware_header;
	struct stat stat;
	char buf[4096];
	int rc;

	rc = read(fd, buf, sizeof(*firmware_header));
	if (rc < 0) {
		perror("can not read header");
		return;
	}

	firmware_header = (struct sdp_firmware *) &buf[0];
	if (strncmp(firmware_header->magic, " SDP", 4) != 0) {
		fprintf(stderr, "Wrong magic.\n");
		return;
	}

	if (memcmp(firmware_header->more_magic, more_magic, 4) != 0) {
		fprintf(stderr, "Wrong more magic.\n");
		return;
	}

	printf("Printing header information:\n");
	printf("header_length: %u\n", ntohl(firmware_header->header_length));
	printf("file_length: %u\n", ntohl(firmware_header->file_length));
	printf("sw_part: %.20s\n", firmware_header->sw_part);
	printf("text1: %.122s\n", firmware_header->text1);
	printf("text2: %.64s\n", firmware_header->text2);
	printf("time: %.8s\n", firmware_header->time);
	printf("date: %.8s\n", firmware_header->date);

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		return;
	}

	if (ntohl(firmware_header->file_length) != stat.st_size) {
		fprintf(stderr, "The filesize and the header do not match.\n");
		return;
	}
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
