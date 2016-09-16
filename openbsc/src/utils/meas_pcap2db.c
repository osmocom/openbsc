/* read PCAP file with meas_feed data and write it to sqlite3 database */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/gsm_utils.h>

#include <openbsc/meas_feed.h>

#include <pcap/pcap.h>

#include "meas_db.h"

static struct meas_db_state *db;

static void handle_mfm(const struct pcap_pkthdr *h,
		       const struct meas_feed_meas *mfm)
{
	const char *scenario;

	if (strlen(mfm->scenario))
		scenario = mfm->scenario;
	else
		scenario = NULL;

	meas_db_insert(db, mfm->imsi, mfm->name, h->ts.tv_sec,
			scenario, &mfm->mr);
}

static void pcap_cb(u_char *user, const struct pcap_pkthdr *h,
		   const u_char *bytes)
{
	const char *cur = bytes;
	const struct iphdr *ip;
	const struct udphdr *udp;
	const struct meas_feed_meas *mfm;
	uint16_t udplen;

	if (h->caplen < 14+20+8)
		return;

	/* Check if there is IPv4 in the Ethernet */
	if (cur[12] != 0x08 || cur[13] != 0x00)
		return;

	cur += 14;	/* ethernet header */
	ip = (struct iphdr *) cur;

	if (ip->version != 4)
		return;
	cur += ip->ihl * 4;

	if (ip->protocol != IPPROTO_UDP)
		return;

	udp = (struct udphdr *) cur;

	if (udp->dest != htons(8888))
		return;

	udplen = ntohs(udp->len);
	if (udplen != sizeof(*udp) + sizeof(*mfm))
		return;
	cur += sizeof(*udp);

	mfm = (const struct meas_feed_meas *) cur;

	handle_mfm(h, mfm);
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE+1];
	char *pcap_fname, *db_fname;
	pcap_t *pc;
	int rc;

	if (argc < 3) {
		fprintf(stderr, "You need to specify PCAP and database file\n");
		exit(2);
	}

	pcap_fname = argv[1];
	db_fname = argv[2];

	pc = pcap_open_offline(pcap_fname, errbuf);
	if (!pc) {
		fprintf(stderr, "Cannot open %s: %s\n", pcap_fname, errbuf);
		exit(1);
	}

	db = meas_db_open(NULL, db_fname);
	if (!db)
		exit(0);

	rc = meas_db_begin(db);
	if (rc < 0) {
		fprintf(stderr, "Error during BEGIN\n");
		exit(1);
	}

	pcap_loop(pc, 0 , pcap_cb, NULL);

	meas_db_commit(db);

	exit(0);
}
