/* isdnsync.c
 *
 * Author       Andreas Eversberg <jolly@eversberg.eu>
 *
 * All rights reserved
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include "mISDNif.h"
#define MISDN_OLD_AF_COMPATIBILITY
#define AF_COMPATIBILITY_FUNC
#include "compat_af_isdn.h"

int card = 0;
int sock = -1;

int mISDN_open(void)
{
	int			fd, ret;
	struct mISDN_devinfo	devinfo;
	struct sockaddr_mISDN	l2addr;

	fd = socket(PF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (fd < 0) {
		fprintf(stderr, "could not open socket (%s)\n", strerror(errno));
		return fd;
	}
	devinfo.id = card;
	ret = ioctl(fd, IMGETDEVINFO, &devinfo);
	if (ret < 0) {
		fprintf(stderr,"could not send IOCTL IMGETCOUNT (%s)\n", strerror(errno));
		close(fd);
		return ret;
	}
	close(fd);
	if (!(devinfo.Dprotocols & (1 << ISDN_P_TE_S0))
	 && !(devinfo.Dprotocols & (1 << ISDN_P_TE_E1))) {
		fprintf(stderr,"Interface does not support TE mode (%s)\n", strerror(errno));
		return ret;
	}
	fd = socket(PF_ISDN, SOCK_DGRAM, ISDN_P_LAPD_TE);
	if (fd < 0) {
		fprintf(stderr,"could not open ISDN_P_LAPD_TE socket (%s)\n", strerror(errno));
		return fd;
	}
	l2addr.family = AF_ISDN;
	l2addr.dev = card;
	l2addr.channel = 0;
	l2addr.sapi = 0;
	l2addr.tei = 0;
	ret = bind(fd, (struct sockaddr *)&l2addr, sizeof(l2addr));
	if (ret < 0) {
		fprintf(stderr,"could not bind socket for card %d (%s)\n", card, strerror(errno));
		close(fd);
		return ret;
	}
	sock = fd;

	return sock;
}


void mISDN_handle(void)
{
	int ret;
	fd_set rfd;
	struct timeval tv;
	struct sockaddr_mISDN addr;
	socklen_t alen;
	unsigned char buffer[2048];
	struct mISDNhead *hh = (struct mISDNhead *)buffer;
	int l1 = 0, l2 = 0, tei = 0;

	while(1) {
again:
		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		ret = select(sock+1, &rfd, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "%s aborted: %s\n", __FUNCTION__, strerror(errno));
			break;
		}
		if (FD_ISSET(sock, &rfd)) {
			alen = sizeof(addr);
			ret = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &alen);
			if (ret < 0) {
				fprintf(stderr, "%s read socket error %s\n", __FUNCTION__, strerror(errno));
			} else if (ret < MISDN_HEADER_LEN) {
					fprintf(stderr, "%s read socket shor frame\n", __FUNCTION__);
			} else {
				switch(hh->prim) {
					case MPH_ACTIVATE_IND:
					case PH_ACTIVATE_IND:
						if (!l1) {
							printf("PH_ACTIVATE\n");
							printf("*** Sync available from interface :-)\n");
							l1 = 1;
						}
						goto again;
					break;
					case MPH_DEACTIVATE_IND:
					case PH_DEACTIVATE_IND:
						if (l1) {
							printf("PH_DEACTIVATE\n");
							printf("*** Lost sync on interface        :-(\n");
							l1 = 0;
						}
						goto again;
					break;
					case DL_ESTABLISH_IND:
					case DL_ESTABLISH_CNF:
						printf("DL_ESTABLISH\n");
						l2 = 1;
						goto again;
					break;
					case DL_RELEASE_IND:
					case DL_RELEASE_CNF:
						printf("DL_RELEASE\n");
						l2 = 0;
						goto again;
					break;
					case DL_INFORMATION_IND:
						printf("DL_INFORMATION (tei %d sapi %d)\n", addr.tei, addr.sapi);
						tei = 1;
					break;
					default:
//						printf("prim %x\n", hh->prim);
						goto again;
				}
			}
		}
		if (tei && !l2) {
			hh->prim = DL_ESTABLISH_REQ;
			printf("-> activating layer 2\n");
			sendto(sock, buffer, MISDN_HEADER_LEN, 0, (struct sockaddr *) &addr, alen);
		}
	}
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc <= 1)
	{
		printf("Usage: %s <card>\n\n", argv[0]);
		printf("Opens given card number in TE-mode PTP and tries to keep layer 2 established.\n");
		printf("This keeps layer 1 activated to retrieve a steady sync signal from network.\n");
		return(0);
	}

	card = atoi(argv[1]);

	init_af_isdn();

	if ((ret = mISDN_open() < 0))
		return(ret);

	mISDN_handle();

	close(sock);

	return 0;
}
