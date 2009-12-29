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

#include <openbsc/debug.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PART_LENGTH 138

struct sdp_firmware_start {
	char magic[4];
	char more_magic[2];
	u_int16_t more_more_magic;
} __attribute__((packed));

struct sdp_firmware {
	u_int32_t header_length;
	u_int32_t file_length;
	char sw_part[20];
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char text3[20];
	u_int8_t dummy[2];
	u_int16_t part_length;
	/* stuff i don't know */
} __attribute__((packed));

struct sdp_header_entry {
	u_int16_t something1;
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char text3[20];
	u_int32_t length;
	u_int32_t addr1;
	u_int32_t addr2;
	u_int32_t start;
} __attribute__((packed));

static_assert(sizeof(struct sdp_header_entry) == 138, right_entry);
static_assert(sizeof(struct sdp_firmware_start) + sizeof(struct sdp_firmware) == 160, _right_header_length);

/* more magic, the second "int" in the header */
static char more_magic[] = { 0x10, 0x02 };

static void analyze_file(int fd, const unsigned int st_size, const unsigned int base_offset)
{
	struct sdp_firmware_start *firmware_start;
	struct sdp_firmware *firmware_header = 0;
	char buf[4096];
	int rc, i;
	unsigned int start_offset = 0;

	rc = read(fd, buf, sizeof(*firmware_start));
	if (rc < 0) {
		perror("Can not read header start.");
		return;
	}

	firmware_start = (struct sdp_firmware_start *) &buf[0];
	if (strncmp(firmware_start->magic, " SDP", 4) != 0) {
		fprintf(stderr, "Wrong magic.\n");
		return;
	}

	start_offset = sizeof(*firmware_start);
	if (memcmp(firmware_start->more_magic, more_magic, 2) == 0) {
		rc = read(fd, &buf[start_offset], sizeof(*firmware_header));
		if (rc != sizeof(*firmware_header)) {
			perror("Can not read header.");
			return;
		}
		firmware_header = (struct sdp_firmware *) &buf[start_offset];
		start_offset += sizeof(*firmware_header);
	} else {
		fprintf(stderr, "Wrong more magic. Got: 0x%x %x %x %x\n",
			firmware_start->more_magic[0] & 0xff, firmware_start->more_magic[1] & 0xff,
			firmware_start->more_magic[2] & 0xff, firmware_start->more_magic[3] & 0xff);
		return;
	}


	if (!firmware_header)
		return;

	printf("Printing header information:\n");
	printf("more_more_magic: 0x%x\n", ntohs(firmware_start->more_more_magic));
	printf("header_length: %u\n", ntohl(firmware_header->header_length));
	printf("file_length: %u\n", ntohl(firmware_header->file_length));
	printf("sw_part: %.20s\n", firmware_header->sw_part);
	printf("text1: %.64s\n", firmware_header->text1);
	printf("time: %.12s\n", firmware_header->time);
	printf("date: %.14s\n", firmware_header->date);
	printf("text2: %.10s\n", firmware_header->text2);
	printf("text3: %.20s\n", firmware_header->text3);
	if (ntohl(firmware_header->file_length) != st_size) {
		fprintf(stderr, "The filesize and the header do not match.\n");
		return;
	}

	/* this semantic appears to be only the case for 0x0000 */
	if (firmware_start->more_more_magic != 0)
		return;

	printf("items: %u (rest %u)\n", ntohs(firmware_header->part_length) / PART_LENGTH,
		ntohs(firmware_header->part_length) % PART_LENGTH);

	if (ntohs(firmware_header->part_length) % PART_LENGTH != 0) {
		fprintf(stderr, "The part length seems to be wrong.\n");
		return;
	}

	/* look into each firmware now */
	for (i = 0; i < ntohs(firmware_header->part_length) / PART_LENGTH; ++i) {
		struct sdp_header_entry entry;
		unsigned int offset = start_offset + base_offset;
		offset += i * 138;

		if (lseek(fd, offset, SEEK_SET) != offset) {
			fprintf(stderr, "Can not seek to the offset: %u.\n", offset);
			return;
		}

		rc = read(fd, &entry, sizeof(entry));
		if (rc != sizeof(entry)) {
			fprintf(stderr, "Can not read the header entry.\n");
			return;
		}

		printf("Header Entry: %d\n", i);
		printf("\tsomething1: %u\n", ntohs(entry.something1));
		printf("\ttext1: %.64s\n", entry.text1);
		printf("\ttime: %.12s\n", entry.time);
		printf("\tdate: %.14s\n", entry.date);
		printf("\ttext2: %.10s\n", entry.text2);
		printf("\ttext3: %.20s\n", entry.text3);
		printf("\taddr1: 0x%x\n", entry.addr1);
		printf("\taddr2: 0x%x\n", entry.addr2);
		printf("\tstart: 0x%x\n", ntohl(entry.start));
		printf("\tlength: 0x%x\n", ntohl(entry.length));

		/* now we need to find the SDP file... */
		offset = ntohl(entry.start) + 4 + base_offset;
		if (lseek(fd, offset, SEEK_SET) != offset) {
			perror("can't seek to sdp");
			return;
		}

		printf("------> parsing\n");
		analyze_file(fd, ntohl(entry.length), offset);
		printf("<------ parsing\n");
	}
}

int main(int argc, char** argv)
{
	int i, fd;
	struct stat stat;

	for (i = 1; i < argc; ++i) {
		printf("Opening possible firmware '%s'\n", argv[i]);
		fd = open(argv[i], O_RDONLY);
		if (!fd) {
			perror("nada");
			continue;
		}

		/* verify the file */
		if (fstat(fd, &stat) == -1) {
			perror("Can not stat the file");
			return EXIT_FAILURE;
		}

		analyze_file(fd, stat.st_size, 0);
	}

	return EXIT_SUCCESS;
}
