/* Radio Resource LCS (Location) Protocol, GMS TS 04.31 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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



#include <openbsc/gsm_04_08.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>

/* ----------------------------------------------- */

/* TODO: move in a separate file  ? */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 

#define RRLP_SERV_PORT	7890
#define RRLP_SERV_IP	"127.0.0.2" /* TODO: from config file */

#define MAX_RRLP_DATA	256

/* Server cmds */

#define RRLP_CMD_MS_DATA		1 /* data from MS */
#define RRLP_CMD_MS_DATA_SLOW	2 /* data from MS, slow channel */

/* Server response */

#define RRLP_RSP_ASSIST_DATA	1 /* assitance data, send to MS */
#define RRLP_RSP_RRLP_ERROR		2 /* RRLP error */
#define RRLP_RSP_RRLP_POSITION	3 /* RRLP position */
#define RRLP_RSP_ERROR			4 /* something went wrong */

/* TODO: adjust error messages, use logging */

static int rrlp_serv_cmd(struct gsm_subscriber_connection *conn, 
	uint8_t cmd, uint8_t *data, int len_data,
	uint8_t *cmd_reply, uint8_t *reply, int *len_reply)
{
	static int fd = -1;
	static struct sockaddr_in sa;
	int len;
	uint8_t buf[2 + 1 + 8 + MAX_RRLP_DATA]; /* len, cmd, subscriber ID, data */
	int len_pkt, offs;
	int rc;
	long long unsigned int id;
	struct sockaddr_in from;
	int from_len;
	fd_set readset;
	struct timeval tv;

	if(len_data > MAX_RRLP_DATA) {
		fprintf(stderr, "len_data > MAX_RRLP_DATA: %d\n", len_data);
		return -1;
	}
	if(fd == -1) {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(fd < 0) {
			fprintf(stderr, "socket() failed: (%d) %s\n", fd, strerror(errno));
			return -1;
		}
			
		sa.sin_family = AF_INET;
		sa.sin_port = htons(RRLP_SERV_PORT);
		if(inet_aton(RRLP_SERV_IP, &sa.sin_addr) != 1) {
			fprintf(stderr, "inet_aton() failed: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			return -1;
		}

		rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
		if(rc < 0) {
			fprintf(stderr, "connect() failed: (%d) %s\n", rc, strerror(errno));
			close(fd);
			fd = -1;
			return -1;
		}			
	}
	
	/* we are now connected */
	
	id = conn->subscr->id;
	
	/* build cmd packet */
	
	len_pkt = 2 + 1 + 8 + len_data;
	buf[0] = len_pkt & 0xFF;
	buf[1] = (len_pkt >> 8) & 0xFF;
	
	buf[2] = cmd;
	
	buf[3] = id & 0xFF;
	buf[4] = (id >> 8) & 0xFF;
	buf[5] = (id >> 16) & 0xFF;
	buf[6] = (id >> 24) & 0xFF;
	buf[7] = (id >> 32) & 0xFF;
	buf[8] = (id >> 40) & 0xFF;
	buf[9] = (id >> 48) & 0xFF;
	buf[10] = (id >> 56) & 0xFF;	
	/* data */
	memcpy(&buf[11], data, len_data);
	
	/* send cmd */
	
	len = sendto(fd, buf, len_pkt, 0, (struct sockaddr*)&sa, sizeof(sa));
	if(len < 0) {
		fprintf(stderr, "sendto() failed: (%d) %s\n", len, strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}		
	if(len != len_pkt) {
		fprintf(stderr, "sendto: len != len_pkt: %d %d\n", len, len_pkt);
		close(fd);
		fd = -1;
		return -1;
	}					
	
	/* wait at most 500 ms for a reply */
	
	FD_ZERO(&readset);
	FD_SET(fd, &readset);
	tv.tv_sec = 0;
	tv.tv_usec = 500 * 1000;
		
	/* this creates another UDP socket on Cygwin !? */
	rc = select(fd + 1, &readset, NULL, NULL, &tv);
	if(rc < 0) {
		fprintf(stderr, "select() failed: (%d) %s\n", rc, strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}
		
	if(!FD_ISSET(fd, &readset)) {
		fprintf(stderr, "timeout select()\n");
		close(fd);
		fd = -1;
		return -1;
	}
	
	/* read packet */
   	from_len = sizeof(from);
	len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &from_len);
	if(len < 0) {
		fprintf(stderr, "recvfrom() failed: (%d) %s\n", len, strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}		
	if(len < 2) {
		fprintf(stderr, "len < 2: %d\n", len);
		close(fd);
		fd = -1;
		return -1;
	}		
	len_pkt = buf[0] + (buf[1] << 8);
	if(len_pkt < 2 + 1) {
		fprintf(stderr, "len_pkt < 2 + 1: %d\n", len_pkt);
		close(fd);
		fd = -1;
		return -1;
	}		
	if(len != len_pkt) {
		fprintf(stderr, "recvfrom: len != len_pkt: %d %d\n", len, len_pkt);
		close(fd);
		fd = -1;
		return -1;
	}		
	len_pkt -= 2;
	offs = 2;

#if 0 /* dump packet */
	{
		int i;
		for(i = 0; i < len_pkt; i++)
			printf("%02X ", buf[offs + i]);
		printf("\n");
	}
#endif		

	/* process packet */

	*len_reply = len_pkt - 1;
	*cmd_reply = buf[offs];
	memcpy(reply, &buf[offs + 1], *len_reply);
	
	return 0;
}

/* ----------------------------------------------- */

int send_rrlp_req(struct gsm_subscriber_connection *conn);

/* TODO: adjust error messages, use logging */

int handle_rrlp(struct gsm_subscriber_connection *conn, uint8_t *data, int len)
{
	struct gsm_network *net = conn->bts->network;
	int rc;
	uint8_t cmd_reply; 
	uint8_t reply[MAX_RRLP_DATA];
	int len_reply;
	uint8_t cmd; 
	
	if (net->rrlp.mode == RRLP_MODE_NONE)
		return 0;
		
	if(len > MAX_RRLP_DATA) {
		fprintf(stderr, "too many data for handle_rrlp (%d)\n", len);
		return -1;
	}
			
	/* TODO: decide if channel is slow (SDCCH), for slow channels 
	   only short assistance data should be sent */	
	   
	if(1)
		cmd = RRLP_CMD_MS_DATA;
	else
		cmd = RRLP_CMD_MS_DATA_SLOW;
		
	rc = rrlp_serv_cmd(conn, cmd, data, len, &cmd_reply, reply, &len_reply);
	if(rc != 0) {
		fprintf(stderr, "rrlp_serv_cmd failed (%d)\n", rc);
		return rc;
	}
	
	if(cmd_reply == RRLP_RSP_ERROR) {
		printf("RRLP Server error (general): %s\n", reply);
		return 0;
	}

	if(cmd_reply == RRLP_RSP_RRLP_ERROR) {
		printf("RRLP Server error (RRLP): %s\n", reply);
		return 0;
	}
	
	if(cmd_reply == RRLP_RSP_RRLP_POSITION) {
		long latitude;
		long longitude;
		long altitude;
		
		if(len_reply != 12) {
			fprintf(stderr, "invalid RRLP position length (%d)\n", len_reply);
			return -1;
		}
				
		latitude  = reply[0] + (reply[1] << 8) + (reply[2] << 16) + (reply[3] << 24);
		longitude = reply[4] + (reply[5] << 8) + (reply[6] << 16) + (reply[7] << 24);
		altitude  = reply[8] + (reply[9] << 8) + (reply[10] << 16) + (reply[11] << 24);
		
		/* TODO: do something useful with the position */
		
		printf("RRLP Server position: ");
		printf("latitude = %f ", ((double)latitude * 90.0) / 0x800000L);
		printf("longitude = %f ", ((double)longitude * 360.0) / 0x1000000L);
		printf("altitude = %ld\n", altitude);		
		
		return 0;
	}
	
	if(cmd_reply == RRLP_RSP_ASSIST_DATA) {
		printf("Assistance data, len %d\n", len_reply);
		
		/* 
		  If there are assistance data, send them. If there are no more,
		  repeat the measurement request 
		*/
		 
		if(len_reply)
			return gsm48_send_rr_app_info(conn, 0x00, len_reply, reply);
		else
			send_rrlp_req(conn);		
	}
	
	return 0;
}

/* RRLP msPositionReq, nsBased,
 *	Accuracy=60, Method=gps, ResponseTime=2, oneSet */
static const uint8_t ms_based_pos_req[] = { 0x40, 0x01, 0x78, 0xa8 };

/* RRLP msPositionReq, msBasedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ms_pref_pos_req[]  = { 0x40, 0x02, 0x79, 0x50 };

/* RRLP msPositionReq, msAssistedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ass_pref_pos_req[] = { 0x40, 0x03, 0x79, 0x50 };

int send_rrlp_req(struct gsm_subscriber_connection *conn)
{
	struct gsm_network *net = conn->bts->network;
	const uint8_t *req;

	switch (net->rrlp.mode) {
	case RRLP_MODE_MS_BASED:
		req = ms_based_pos_req;
		break;
	case RRLP_MODE_MS_PREF:
		req = ms_pref_pos_req;
		break;
	case RRLP_MODE_ASS_PREF:
		req = ass_pref_pos_req;
		break;
	case RRLP_MODE_NONE:
	default:
		return 0;
	}

	return gsm48_send_rr_app_info(conn, 0x00,
				      sizeof(ms_based_pos_req), req);
}

static int subscr_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr;
	struct gsm_subscriber_connection *conn;

	switch (signal) {
	case S_SUBSCR_ATTACHED:
		/* A subscriber has attached. */
		subscr = signal_data;
		conn = connection_for_subscr(subscr);
		if (!conn)
			break;
		if (conn->bts->network->rrlp.on_attach)
			send_rrlp_req(conn);
		break;
	}
	return 0;
}

static int paging_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct paging_signal_data *psig_data = signal_data;

	switch (signal) {
	case S_PAGING_SUCCEEDED:
		/* A subscriber has attached. */
		if (psig_data->conn->bts->network->rrlp.on_paging)
			send_rrlp_req(psig_data->conn);
		break;
	case S_PAGING_EXPIRED:
		break;
	}
	return 0;
}

void on_dso_load_rrlp(void)
{
	osmo_signal_register_handler(SS_SUBSCR, subscr_sig_cb, NULL);
	osmo_signal_register_handler(SS_PAGING, paging_sig_cb, NULL);
}
