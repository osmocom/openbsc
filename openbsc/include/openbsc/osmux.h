#ifndef _OPENBSC_OSMUX_H_
#define _OPENBSC_OSMUX_H_

#include <osmocom/netif/osmux.h>

#define OSMUX_PORT	1984

enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

int osmux_init(int role, struct mgcp_config *cfg);
int osmux_enable_endpoint(struct mgcp_endpoint *endp, int role,
			  struct in_addr *addr, uint16_t port);
void osmux_disable_endpoint(struct mgcp_endpoint *endp);

int osmux_xfrm_to_rtp(struct mgcp_endpoint *endp, int type, char *buf, int rc);
int osmux_xfrm_to_osmux(int type, char *buf, int rc, struct mgcp_endpoint *endp);

int osmux_send_dummy(struct mgcp_endpoint *endp);

int osmux_get_cid(void);
void osmux_put_cid(uint8_t osmux_cid);

enum osmux_state {
	OSMUX_STATE_DISABLED = 0,
	OSMUX_STATE_ACTIVATING,
	OSMUX_STATE_ENABLED,
};

#endif
