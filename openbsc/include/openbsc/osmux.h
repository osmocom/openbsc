#ifndef _OPENBSC_OSMUX_H_
#define _OPENBSC_OSMUX_H_

#include <osmocom/netif/osmux.h>

enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

int osmux_init(int role, struct mgcp_config *cfg);
int osmux_enable_endpoint(struct mgcp_endpoint *endp, int role);

int osmux_xfrm_to_rtp(struct mgcp_endpoint *endp, int type, char *buf, int rc);
int osmux_xfrm_to_osmux(int type, char *buf, int rc, struct mgcp_endpoint *endp);

int osmux_send_dummy(struct mgcp_endpoint *endp);

#endif
