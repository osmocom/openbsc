#ifndef _BSC_SOCKET_H
#define _BSC_SOCKET_H

#include <osmocom/core/select.h>

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

int make_sock(struct osmo_fd *bfd, int proto,
	      uint32_t ip, uint16_t port, int priv_nr,
	      int (*cb)(struct osmo_fd *fd, unsigned int what), void *data);

#endif /* _BSC_SOCKET_H */
