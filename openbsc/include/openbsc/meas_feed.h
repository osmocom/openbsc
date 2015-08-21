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
	/* The logical channel type, enum gsm_chan_t */
	uint8_t lchan_type;
	/* The physical channel type, enum gsm_phys_chan_config */
	uint8_t pchan_type;
	/* number of ths BTS in network */
	uint8_t bts_nr;
	/* number of this TRX in the BTS */
	uint8_t trx_nr;
	/* number of this timeslot at the TRX */
	uint8_t ts_nr;
	/* The logical subslot number in the TS */
	uint8_t ss_nr;
};

enum meas_feed_msgtype {
	MEAS_FEED_MEAS		= 0,
};

#define MEAS_FEED_VERSION	1


#endif
