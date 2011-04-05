#ifndef _BSC_SOCKET_H
#define _BSC_SOCKET_H

#include <sys/types.h>
#include <osmocom/core/select.h>

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

int make_sock(struct bsc_fd *bfd, int proto,
	      u_int32_t ip, u_int16_t port, int priv_nr,
	      int (*cb)(struct bsc_fd *fd, unsigned int what), void *data);

#endif /* _BSC_SOCKET_H */
