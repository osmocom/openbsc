#ifndef _BSC_SOCKET_H
#define _BSC_SOCKET_H

#include <sys/types.h>
#include <osmocore/select.h>

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

int make_sock(struct bsc_fd *bfd, int proto, u_int16_t port,
	      int (*cb)(struct bsc_fd *fd, unsigned int what));

#endif /* _BSC_SOCKET_H */
