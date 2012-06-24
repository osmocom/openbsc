#ifndef _GANC_DATA_H
#define _GANC_DATA_H

#include <osmocom/core/linuxlist.h>
#include "conn.h"

struct ganc_bts;

enum ganc_net_timer {
	T3212,
	TU3901,
	TU3902,
	TU3903,
	TU3904,
	TU3905,
	TU3906,
	TU3907,
	TU3908,
	//TU3909,
	TU3910,
	TU3920,
	TU4001,
	TU4002,
	TU4003,
	_NUM_GANC_TIMER
};

enum ganc_state {
	GA_S_CSR_IDLE,
	GA_S_CSR_DEDICATED,
};

struct gan_peer {
	struct llist_head list;		/* list of all peers */
	struct osmo_conn *conn;		/* TCP connection */
	struct ganc_bts *bts;		/* BTS to which we belong */

	uint8_t gan_release;		/* UMA/GAN release version */
	enum ganc_state csr_state;
	char imsi[16+1];
	uint8_t gan_classmark[2];
	uint8_t cm2[3];
	struct {
		unsigned int len;
		uint8_t *val;
	} cm3;
};

struct ganc_net {
	uint8_t country_code;
	uint8_t network_code;

	uint16_t timer[_NUM_GANC_TIMER];

	int emergency_gan_preferred;

	struct {
		int mode;
	} gprs;
};

struct ganc_bts {
	struct ganc_net *net;
	uint16_t location_area_code;
	uint16_t routing_area_code;
	uint16_t cell_identity;
	uint8_t bsic;
	uint16_t arfcn;
};

void ganc_net_init(struct ganc_net *net);
void ganc_bts_init(struct ganc_bts *bts, struct ganc_net *net);

extern struct ganc_bts *g_ganc_bts;

#endif
