#ifndef _REG_PROXY_H
#define _REG_PROXY_H

#include <openbsc/sup_server.h>
#include <openbsc/sip_client.h>
#include <osip2/osip.h>
void *tall_reg_ctx;

struct reg_proxy {
	struct gsm_sup_server *sup_server;
	struct sip_client *sip_client;
	osip_t *osip;
};

#endif /* _REG_PROXY_H */
