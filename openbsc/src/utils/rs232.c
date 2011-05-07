/* OpenBSC BS-11 T-Link interface using POSIX serial port */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/rs232.h>

/* adaption layer from GSM 08.59 + 12.21 to RS232 */

struct serial_handle {
	struct osmo_fd fd;
	struct llist_head tx_queue;

	struct msgb *rx_msg;
	unsigned int rxmsg_bytes_missing;

	unsigned int delay_ms;
	struct gsm_bts *bts;
};

/* FIXME: this needs to go */
static struct serial_handle _ser_handle, *ser_handle = &_ser_handle;

#define LAPD_HDR_LEN	10

static int handle_ser_write(struct osmo_fd *bfd);

/* callback from abis_nm */
int _abis_nm_sendmsg(struct msgb *msg, int to_trx_oml)
{
	struct serial_handle *sh = ser_handle;
	uint8_t *lapd;
	unsigned int len;

	msg->l2h = msg->data;

	/* prepend LAPD header */
	lapd = msgb_push(msg, LAPD_HDR_LEN);

	len = msg->len - 2;

	lapd[0] = (len >> 8) & 0xff;
	lapd[1] = len & 0xff; /* length of bytes startign at lapd[2] */
	lapd[2] = 0x00;
	lapd[3] = 0x07;
	lapd[4] = 0x01;
	lapd[5] = 0x3e;
	lapd[6] = 0x00;
	lapd[7] = 0x00;
	lapd[8] = msg->len - 10; /* length of bytes starting at lapd[10] */
	lapd[9] = lapd[8] ^ 0x38;

	msgb_enqueue(&sh->tx_queue, msg);
	sh->fd.when |= BSC_FD_WRITE;

	/* we try to immediately send */
	handle_ser_write(&sh->fd);

	return 0;
}

/* select.c callback in case we can write to the RS232 */
static int handle_ser_write(struct osmo_fd *bfd)
{
	struct serial_handle *sh = bfd->data;
	struct msgb *msg;
	int written;

	msg = msgb_dequeue(&sh->tx_queue);
	if (!msg) {
		bfd->when &= ~BSC_FD_WRITE;
		return 0;
	}

	DEBUGP(DMI, "RS232 TX: %s\n", osmo_hexdump(msg->data, msg->len));

	/* send over serial line */
	written = write(bfd->fd, msg->data, msg->len);
	if (written < msg->len) {
		perror("short write:");
		msgb_free(msg);
		return -1;
	}

	msgb_free(msg);
	usleep(sh->delay_ms*1000);

	return 0;
}

#define SERIAL_ALLOC_SIZE	300

/* select.c callback in case we can read from the RS232 */
static int handle_ser_read(struct osmo_fd *bfd)
{
	struct serial_handle *sh = bfd->data;
	struct msgb *msg;
	int rc = 0;

	if (!sh->rx_msg) {
		sh->rx_msg = msgb_alloc(SERIAL_ALLOC_SIZE, "RS232 Rx");
		sh->rx_msg->l2h = NULL;
		sh->rx_msg->trx = sh->bts->c0;
	}
	msg = sh->rx_msg;

	/* first read two byes to obtain length */
	if (msg->len < 2) {
		rc = read(sh->fd.fd, msg->tail, 2 - msg->len);
		if (rc < 0) {
			perror("ERROR reading from serial port");
			msgb_free(msg);
			return rc;
		}
		msgb_put(msg, rc);

		if (msg->len >= 2) {
			/* parse LAPD payload length */
			if (msg->data[0] != 0)
				fprintf(stderr, "Suspicious header byte 0: 0x%02x\n",
					msg->data[0]);

			sh->rxmsg_bytes_missing = msg->data[0] << 8;
			sh->rxmsg_bytes_missing += msg->data[1];

			if (sh->rxmsg_bytes_missing < LAPD_HDR_LEN -2)
				fprintf(stderr, "Invalid length in hdr: %u\n",
					sh->rxmsg_bytes_missing);
		}
	} else {
		/* try to read as many of the missing bytes as are available */
		rc = read(sh->fd.fd, msg->tail, sh->rxmsg_bytes_missing);
		if (rc < 0) {
			perror("ERROR reading from serial port");
			msgb_free(msg);
			return rc;
		}
		msgb_put(msg, rc);
		sh->rxmsg_bytes_missing -= rc;

		if (sh->rxmsg_bytes_missing == 0) {
			/* we have one complete message now */
			sh->rx_msg = NULL;

			if (msg->len > LAPD_HDR_LEN)
				msg->l2h = msg->data + LAPD_HDR_LEN;

			DEBUGP(DMI, "RS232 RX: %s\n", osmo_hexdump(msg->data, msg->len));
			rc = handle_serial_msg(msg);
		}
	}

	return rc;
}

/* select.c callback */
static int serial_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & BSC_FD_READ)
		rc = handle_ser_read(bfd);

	if (rc < 0)
		return rc;

	if (what & BSC_FD_WRITE)
		rc = handle_ser_write(bfd);

	return rc;
}

int rs232_setup(const char *serial_port, unsigned int delay_ms,
		struct gsm_bts *bts)
{
	int rc, serial_fd;
	struct termios tio;

	serial_fd = open(serial_port, O_RDWR);
	if (serial_fd < 0) {
		perror("cannot open serial port:");
		return serial_fd;
	}

	/* set baudrate */
	rc = tcgetattr(serial_fd, &tio);
	if (rc < 0) {
		perror("tcgetattr()");
		return rc;
	}
	cfsetispeed(&tio, B19200);
	cfsetospeed(&tio, B19200);
	tio.c_cflag |=  (CREAD | CLOCAL | CS8);
	tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE | CRTSCTS);
	tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	tio.c_iflag |=  (INPCK | ISTRIP);
	tio.c_iflag &= ~(ISTRIP | IXON | IXOFF | IGNBRK | INLCR | ICRNL | IGNCR);
	tio.c_oflag &= ~(OPOST);
	rc = tcsetattr(serial_fd, TCSADRAIN, &tio);
	if (rc < 0) {
		perror("tcsetattr()");
		return rc;
	}

	INIT_LLIST_HEAD(&ser_handle->tx_queue);
	ser_handle->fd.fd = serial_fd;
	ser_handle->fd.when = BSC_FD_READ;
	ser_handle->fd.cb = serial_fd_cb;
	ser_handle->fd.data = ser_handle;
	ser_handle->delay_ms = delay_ms;
	ser_handle->bts = bts;
	rc = osmo_fd_register(&ser_handle->fd);
	if (rc < 0) {
		fprintf(stderr, "could not register FD: %s\n",
			strerror(rc));
		return rc;
	}

	return 0;
}
