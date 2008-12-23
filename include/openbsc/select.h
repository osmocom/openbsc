#ifndef _BSC_SELECT_H
#define _BSC_SELECT_H

#define BSC_FD_READ	0x0001
#define BSC_FD_WRITE	0x0002
#define BSC_FD_EXCEPT	0x0004

struct bsc_fd {
	struct llist_head list;
	int fd;
	unsigned int when;
	int (*cb)(struct bsc_fd *fd, unsigned int what);
	void *data;
	unsigned int priv_nr;
};

#endif /* _BSC_SELECT_H */
