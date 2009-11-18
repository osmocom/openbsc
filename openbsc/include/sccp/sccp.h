/*
 * SCCP management code
 *
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
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

#ifndef SCCP_H
#define SCCP_H

#include <stdlib.h>

#include <sys/socket.h>

#include <openbsc/msgb.h>

#include "sccp_types.h"

struct sccp_system;

enum {
	SCCP_CONNECTION_STATE_NONE,
	SCCP_CONNECTION_STATE_REQUEST,
	SCCP_CONNECTION_STATE_CONFIRM,
	SCCP_CONNECTION_STATE_ESTABLISHED,
	SCCP_CONNECTION_STATE_RELEASE,
	SCCP_CONNECTION_STATE_RELEASE_COMPLETE,
	SCCP_CONNECTION_STATE_REFUSED,
	SCCP_CONNECTION_STATE_SETUP_ERROR,
};

struct sockaddr_sccp {
	sa_family_t	sccp_family;		/* AF_SCCP in the future??? */
	u_int8_t	sccp_ssn;		/* subssystem number for routing */

	/* TODO fill in address indicator... if that is ever needed */

	/* not sure about these */
	/* u_int8_t    sccp_class; */
};

/*
 * parsed structure of an address
 */
struct sccp_address {
	struct sccp_called_party_address    address;
	u_int8_t			    ssn;
	u_int8_t			    poi[2];
};

struct sccp_optional_data {
	u_int8_t			    data_len;
	u_int8_t			    data_start;
};

struct sccp_connection {
	/* public */
	void *data_ctx;
	void (*data_cb)(struct sccp_connection *conn, struct msgb *msg, unsigned int len);

	void *state_ctx;
	void (*state_cb)(struct sccp_connection *, int old_state);

	struct sccp_source_reference source_local_reference;
	struct sccp_source_reference destination_local_reference;

	int connection_state;

	/* private */
	/* list of active connections */
	struct llist_head list;
	struct sccp_system *system;
	int incoming;
};

/**
 * system functionality to implement on top of any other transport layer:
 *   call sccp_system_incoming for incoming data (from the network)
 *   sccp will call outgoing whenever outgoing data exists
 */
int sccp_system_init(int (*outgoing)(struct msgb *data, void *ctx), void *context);
int sccp_system_incoming(struct msgb *data);

/**
 * Send data on an existing connection
 */
int sccp_connection_write(struct sccp_connection *connection, struct msgb *data);
int sccp_connection_send_it(struct sccp_connection *connection);
int sccp_connection_close(struct sccp_connection *connection, int cause);
int sccp_connection_free(struct sccp_connection *connection);

/**
 * Create a new socket. Set your callbacks and then call bind to open
 * the connection.
 */
struct sccp_connection *sccp_connection_socket(void);

/**
 * Open the connection and send additional data
 */
int sccp_connection_connect(struct sccp_connection *conn,
			    const struct sockaddr_sccp *sccp_called,
			    struct msgb *data);

/**
 * mostly for testing purposes only. Set the accept callback.
 * TODO: add true routing information... in analogy to socket, bind, accept
 */
int sccp_connection_set_incoming(const struct sockaddr_sccp *sock,
				 int (*accept_cb)(struct sccp_connection *connection, void *data),
				 void *user_data);

/**
 * Send data in terms of unit data. A fixed address indicator will be used.
 */
int sccp_write(struct msgb *data,
	       const struct sockaddr_sccp *sock_sender,
	       const struct sockaddr_sccp *sock_target, int class);
int sccp_set_read(const struct sockaddr_sccp *sock,
		  int (*read_cb)(struct msgb *msgb, unsigned int, void *user_data),
		  void *user_data);

/* generic sock addresses */
extern const struct sockaddr_sccp sccp_ssn_bssap;

/* helpers */
u_int32_t sccp_src_ref_to_int(struct sccp_source_reference *ref);
struct sccp_source_reference sccp_src_ref_from_int(u_int32_t);

#endif
