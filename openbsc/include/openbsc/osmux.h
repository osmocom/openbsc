#ifndef _OPENBSC_OSMUX_H_
#define _OPENBSC_OSMUX_H_

#include <osmocom/netif/osmux.h>

enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

struct osmux {
	struct osmux_out_handle out;
};

int osmux_init(int role, struct mgcp_config *cfg);

int osmux_xfrm_to_rtp(struct mgcp_endpoint *endp, int type, char *buf, int rc);
int osmux_xfrm_to_osmux(int type, char *buf, int rc, struct mgcp_endpoint *endp);

int osmux_change_cb(struct mgcp_trunk_config *cfg, int endpoint, int state);

#endif
