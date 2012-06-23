#ifndef _GANC_DATA_H
#define _GANC_DATA_H

#include <osmocom/core/linuxlist.h>
#include "conn.h"

struct gan_peer {
	struct llist_head list;
	struct osmo_conn *conn;
};

#endif
