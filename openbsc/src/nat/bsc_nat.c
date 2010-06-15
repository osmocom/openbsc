/* BSC Multiplexer/NAT */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by on-waves.com
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/debug.h>

static const char *config_file = "openbsc.cfg";
static char *msc_address = "127.0.0.1";
static struct in_addr local_addr;

static void print_usage()
{
	printf("Usage: bsc_nat\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -m --msc=IP. The address of the MSC.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"msc", 1, 0, 'm'},
			{"local", 1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sTPc:m:l:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			debug_use_color(0);
			break;
		case 'd':
			debug_parse_category_mask(optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			debug_timestamp(1);
			break;
		case 'm':
			msc_address = strdup(optarg);
			break;
		case 'l':
			inet_aton(optarg, &local_addr);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

int main(int argc, char** argv)
{
	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	return 0;
}
