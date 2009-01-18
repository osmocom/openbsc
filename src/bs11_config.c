/* Siemens BS-11 microBTS configuration tool */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This software is based on ideas (but not code) of BS11Config 
 * (C) 2009 by Dieter Spaar <spaar@mirider.augusta.de>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>

static const u_int8_t obj_li_attr[] = { 
	0xa0, 0x09, 0x00,
	0xab, 0x00, 
	0xac, 0x00,
};
static const u_int8_t obj_bbsig0_attr[] = {
	0x3d, 0x02, 0x00, 0x00,
	0x3f, 0x01, 0x00,
};
static const u_int8_t obj_pa0_attr[] = {
	NM_ATT_BS11_TXPWR, 0x01, BS11_TRX_POWER_30mW,
};
static const char *trx1_password = "1111111111";
#define TEI_OML	25

/* create all objects for an initial configuration */
static int create_objects(struct gsm_bts *bts, int trx1)
{
	abis_nm_bs11_factory_logon(bts, 1);
	abis_nm_bs11_create_object(bts, BS11_OBJ_LI, 0, sizeof(obj_li_attr),
				   obj_li_attr);
	abis_nm_bs11_create_object(bts, BS11_OBJ_GPSU, 0, 0, NULL);
	abis_nm_bs11_create_object(bts, BS11_OBJ_ALCO, 0, 0, NULL);
	abis_nm_bs11_create_object(bts, BS11_OBJ_BBSIG, 0,
				   sizeof(obj_bbsig0_attr), obj_bbsig0_attr);
	abis_nm_bs11_create_object(bts, BS11_OBJ_PA, 0,
				   sizeof(obj_pa0_attr), obj_pa0_attr);
	if (trx1) {
		u_int8_t bbsig1_attr[sizeof(obj_bbsig0_attr)+12];
		u_int8_t *cur = bbsig1_attr;
		
		abis_nm_bs11_set_trx1_pw(bts, trx1_password);

		cur = tlv_put(cur, NM_ATT_BS11_PASSWORD, 10,
			      (u_int8_t *)trx1_password);
		memcpy(cur, obj_bbsig0_attr, sizeof(obj_bbsig0_attr));
		abis_nm_bs11_create_object(bts, BS11_OBJ_BBSIG, 1,
					   sizeof(bbsig1_attr), bbsig1_attr);

		abis_nm_bs11_create_object(bts, BS11_OBJ_PA, 1,
					   sizeof(obj_pa0_attr), obj_pa0_attr);
	}

	abis_nm_bs11_create_envaBTSE(bts, 0);
	abis_nm_bs11_create_envaBTSE(bts, 1);
	abis_nm_bs11_create_envaBTSE(bts, 2);
	abis_nm_bs11_create_envaBTSE(bts, 3);

	abis_nm_bs11_conn_oml(bts, 0, 1, 0xff);
	abis_nm_bs11_set_oml_tei(bts, TEI_OML);

	abis_nm_bs11_set_trx_power(&bts->trx[0], BS11_TRX_POWER_30mW);

	if (trx1)
		abis_nm_bs11_set_trx_power(&bts->trx[1], BS11_TRX_POWER_30mW);

	abis_nm_bs11_factory_logon(bts, 0);
	
	return 0;
}

static char *serial_port = "/dev/ttyUSB0";
static char *fname_safety = "BTSBMC76.SWI";
static char *fname_software = "HS011106.SWL";
static int serial_fd = -1;
static int have_trx1 = 0;
static struct gsm_bts *g_bts;

/* adaption layer from GSM 08.59 + 12.21 to RS232 */

#define LAPD_HDR_LEN	10

/* callback from abis_nm */
int _abis_nm_sendmsg(struct msgb *msg)
{
	int written;
	u_int8_t *lapd;

	msg->l2h = msg->data;

	/* prepend LAPD header */
	lapd = msgb_push(msg, LAPD_HDR_LEN);

	lapd[0] = 0x00;
	lapd[1] = msg->len - 2; /* length of bytes startign at lapd[2] */
	lapd[2] = 0x00;
	lapd[3] = 0x07;
	lapd[4] = 0x01;
	lapd[5] = 0x3e;
	lapd[6] = 0x00;
	lapd[7] = 0x00;
	lapd[8] = msg->len - 10; /* length of bytes starting at lapd[10] */
	lapd[9] = lapd[8] ^ 0x38;

	fprintf(stdout, "TX: ");
	hexdump(msg->data, msg->len);

	/* send over serial line */
	written = write(serial_fd, msg->data, msg->len);
	if (written < msg->len) {
		perror("short write:");
		msgb_free(msg);
		return -1;
	}

	msgb_free(msg);

	return 0;
}

#define SERIAL_ALLOC_SIZE	300

/* receive an entire message from the serial port */
static struct msgb *serial_read_msg(void)
{
	struct msgb *msg = msgb_alloc(SERIAL_ALLOC_SIZE);
	int rc;

	if (!msg)
		return NULL;

	/* first read two byes to obtain length */
	while (msg->len < 2) {
		rc = read(serial_fd, msg->tail, 2 - msg->len);
		if (rc < 0) {
			perror("reading from serial port");
			msgb_free(msg);
			return NULL;
		}
		msgb_put(msg, rc);
	}
	if (msg->data[0] != 0)
		fprintf(stderr, "Invalid header byte 0: 0x%02x\n",
			msg->data[0]);

	/* second byte is LAPD payload length */
	if (msg->data[1] < LAPD_HDR_LEN + sizeof(struct abis_om_fom_hdr) +
			   sizeof(struct abis_om_hdr))
		fprintf(stderr, "Invalied header byte 1(len): %u\n",
			msg->data[1]);

	while (msg->len < 2 + msg->data[1]) {
		rc = read(serial_fd, msg->tail, 2 + msg->data[1] - msg->len);
		if (rc < 0) {
			perror("reading from serial port");
			msgb_free(msg);
			return NULL;
		}
		msgb_put(msg, rc);
	}

	msg->l2h = msg->data + LAPD_HDR_LEN;

	fprintf(stdout, "RX: ");
	hexdump(msg->l2h, msg->len - (msg->l2h - msg->data));

	return msg;
}

static int file_is_readable(const char *fname)
{
	int rc;
	struct stat st;

	rc = stat(fname, &st);
	if (rc < 0)
		return 0;

	if (S_ISREG(st.st_mode) && (st.st_mode & S_IRUSR))
		return 1;

	return 0;
}


static int handle_state_resp(u_int8_t state)
{
	printf("STATE: ");
	switch (state) {
	case BS11_STATE_WARM_UP:
		printf("Warm Up...\n");
		sleep(5);
		break;
	case BS11_STATE_LOAD_SMU_SAFETY:
		printf("Load SMU Safety...\n");
		sleep(5);
		break;
	case BS11_STATE_SOFTWARE_RQD:
		printf("Software required...\n");
		/* send safety load */
		if (file_is_readable(fname_safety))
			abis_nm_software_load(g_bts, fname_safety, 8);
		else
			fprintf(stderr, "No valid Safety Load file\n");
		break;
	case BS11_STATE_WAIT_MIN_CFG:
	case BS11_STATE_WAIT_MIN_CFG_2:
		printf("Wait minimal config...\n");
		create_objects(g_bts, have_trx1);
		break;
	case BS11_STATE_MAINTENANCE:
		printf("Maintenance...\n");
		/* send software (FIXME: over A-bis?) */
		if (file_is_readable(fname_software))
			abis_nm_software_load(g_bts, fname_software, 8);
		else
			fprintf(stderr, "No valid Software file\n");
		break;
	case BS11_STATE_NORMAL:
		printf("Normal...\n");
		return 1;
	default:
		printf("Unknown state 0x%02u\n", state);
		sleep(5);
		break;
	}
	return 0;
}

static void print_banner(void)
{
	printf("bs11_config (C) 2009 by Harald Welte and Dieter Spaar\n");
	printf("THIS SOFTWARE IS FREE SOFTWARE WIH NO WARRANTY\n\n");
}

static void print_help(void)
{
	printf("Supported arguments:\n");
	printf("\t--help\t\t\t-h\tPrint this help text\n");
	printf("\t--port /dev/ttyXXX\t-p\tSpecify serial port\n");
	printf("\t--with-trx1\t\t-t\tAssume the BS-11 has 2 TRX\n");
	printf("\t--software file\t\t-s\tSpecify Software file\n");
	printf("\t--safety file\t\t-s\tSpecify Safety Load file\n");
}

static void handle_options(int argc, char **argv)
{
	print_banner();

	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "port", 1, 0, 'p' },
			{ "with-trx1", 0, 0, 't' },
			{ "software", 1, 0, 's' },
			{ "safety", 1, 0, 'S' },
		};

		c = getopt_long(argc, argv, "hp:s:S:t",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
		case 'p':
			serial_port = optarg;
			break;
		case 't':
			have_trx1 = 1;
			break;
		case 's':
			fname_software = optarg;
			break;
		case 'S':
			fname_safety = optarg;
			break;
		default:
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct gsm_network *gsmnet;

	handle_options(argc, argv);

	serial_fd = open(serial_port, O_RDWR);
	if (serial_fd < 0) {
		perror("cannot open serial port:");
		exit(1);
	}

	/* FIXME: set baudrate */

	gsmnet = gsm_network_init(1, 1, 1);
	if (!gsmnet) {
		fprintf(stderr, "Unable to allocate gsm network\n");
		exit(1);
	}
	g_bts = &gsmnet->bts[0];

	abis_nm_bs11_factory_logon(g_bts, 1);

	while (1) {
		struct msgb *rx_msg;
		struct abis_om_hdr *oh;
		struct abis_om_fom_hdr *foh;
		int rc = -1;

		rx_msg = serial_read_msg();

		oh = (struct abis_om_hdr *) msgb_l2(rx_msg);
		foh = (struct abis_om_fom_hdr *) oh->data;
		switch (foh->msg_type) {
		case NM_MT_BS11_GET_STATE_ACK:
			rc = handle_state_resp(foh->data[2]);
			break;
		default:
			rc = abis_nm_rcvmsg(rx_msg);
		}
		if (rc < 0) {
			perror("in main loop");
			break;
		}
		if (rc == 1)
			break;
	}

	abis_nm_bs11_factory_logon(g_bts, 0);

	close(serial_fd);
	exit(0);
}
