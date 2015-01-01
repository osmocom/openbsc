#ifndef _OPENBSC_MEAS_FEED_H
#define _OPENBSC_MEAS_FEED_H

#include <stdint.h>

#include <openbsc/meas_rep.h>

struct meas_feed_hdr {
	uint8_t msg_type;
	uint8_t reserved;
	uint16_t version;
};

struct meas_feed_meas {
	struct meas_feed_hdr hdr;
	char imsi[15+1];
	char name[31+1];
	char scenario[31+1];
	struct gsm_meas_rep mr;
};

enum meas_feed_msgtype {
	MEAS_FEED_MEAS		= 0,
};

#define MEAS_FEED_VERSION	0


#endif
