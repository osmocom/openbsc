/* ip.access nanoBTS configuration tool */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>
#include <openbsc/gsm_data.h>

static int udp_sock(const char *ifname)
{
	int fd, rc, bc = 1;
	struct sockaddr_in sa;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	if (ifname) {
#ifdef __FreeBSD__
		rc = setsockopt(fd, SOL_SOCKET, IP_RECVIF, ifname,
				strlen(ifname));
#else
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen(ifname));
#endif
		if (rc < 0)
			goto err;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	sa.sin_addr.s_addr = INADDR_ANY;

	rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;

	rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bc, sizeof(bc));
	if (rc < 0)
		goto err;

#if 0
	/* we cannot bind, since the response packets don't come from
	 * the broadcast address */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	inet_aton("255.255.255.255", &sa.sin_addr);

	rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;
#endif
	return fd;

err:
	close(fd);
	return rc;
}

const unsigned char find_pkt[] = { 0x00, 0x0b+8, IPAC_PROTO_IPACCESS, 0x00,
				IPAC_MSGT_ID_GET,
					0x01, IPAC_IDTAG_MACADDR,
					0x01, IPAC_IDTAG_IPADDR,
					0x01, IPAC_IDTAG_UNIT,
					0x01, IPAC_IDTAG_LOCATION1,
					0x01, IPAC_IDTAG_LOCATION2,
					0x01, IPAC_IDTAG_EQUIPVERS,
					0x01, IPAC_IDTAG_SWVERSION,
					0x01, IPAC_IDTAG_UNITNAME,
					0x01, IPAC_IDTAG_SERNR,
				};


static int bcast_find(int fd)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	inet_aton("255.255.255.255", &sa.sin_addr);

	return sendto(fd, find_pkt, sizeof(find_pkt), 0, (struct sockaddr *) &sa, sizeof(sa));
}

static int parse_response(unsigned char *buf, int len)
{
	uint8_t t_len;
	uint8_t t_tag;
	uint8_t *cur = buf;

	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;
		
		printf("%s='%s'  ", ipa_ccm_idtag_name(t_tag), cur);

		cur += t_len;
	}
	printf("\n");
	return 0;
}

static int read_response(int fd)
{
	unsigned char buf[255];
	struct sockaddr_in sa;
	int len;
	socklen_t sa_len = sizeof(sa);

	len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &sa_len);
	if (len < 0)
		return len;

	/* 2 bytes length, 1 byte protocol */
	if (buf[2] != IPAC_PROTO_IPACCESS)
		return 0;

	if (buf[4] != IPAC_MSGT_ID_RESP)
		return 0;

	return parse_response(buf+6, len-6);
}

static int bfd_cb(struct osmo_fd *bfd, unsigned int flags)
{
	if (flags & BSC_FD_READ)
		return read_response(bfd->fd);
	if (flags & BSC_FD_WRITE) {
		bfd->when &= ~BSC_FD_WRITE;
		return bcast_find(bfd->fd);
	}
	return 0;
}

static struct osmo_timer_list timer;

static void timer_cb(void *_data)
{
	struct osmo_fd *bfd = _data;

	bfd->when |= BSC_FD_WRITE;

	osmo_timer_schedule(&timer, 5, 0);
}

int main(int argc, char **argv)
{
	struct osmo_fd bfd;
	char *ifname = NULL;
	int rc;

	printf("abisip-find (C) 2009 by Harald Welte\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	if (argc < 2) {
		fprintf(stdout, "you might need to specify the outgoing\n"
			" network interface, e.g. ``%s eth0''\n", argv[0]);
	} else {
		ifname = argv[1];
	}

	bfd.cb = bfd_cb;
	bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	bfd.fd = udp_sock(ifname);
	if (bfd.fd < 0) {
		perror("Cannot create local socket for broadcast udp");
		exit(1);
	}

	rc = osmo_fd_register(&bfd);
	if (rc < 0) {
		fprintf(stderr, "Cannot register FD\n");
		exit(1);
	}

	osmo_timer_setup(&timer, timer_cb, &bfd);
	osmo_timer_schedule(&timer, 5, 0);

	printf("Trying to find ip.access BTS by broadcast UDP...\n");

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

