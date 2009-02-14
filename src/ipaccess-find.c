
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <openbsc/select.h>
#include <openbsc/timer.h>

static int udp_sock(void)
{
	int fd, rc, bc = 1;
	struct sockaddr_in sa;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	sa.sin_addr.s_addr = INADDR_ANY;
	inet_aton("192.168.100.11", &sa.sin_addr);

	rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;

	rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bc, sizeof(bc));
	if (rc < 0)
		goto err;

#if 0
	rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;
#endif		
	return fd;

err:
	close(fd);
	return rc;
}

const unsigned char find_pkt[] = { 0x00, 0x0b, 0xfe, 0x00, 0x04, 0x01, 0x06, 0x01, 0x07, 0x01, 0x02, 0x01, 0x03, 0x01, 0x08 };


static int bcast_find(int fd)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(3006);
	inet_aton("255.255.255.255", &sa.sin_addr);

	return sendto(fd, find_pkt, sizeof(find_pkt), 0, (struct sockaddr *) &sa, sizeof(sa));
}

static int parse_response(unsigned char *buf, int len)
{
	u_int8_t t_len;
	u_int8_t t_tag;
	u_int8_t *cur = buf;

	cur += 6;
	
	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;
		
		printf("tag=0x%02x, val='%s'  ", t_tag, cur);

		cur += t_len;
	}
	printf("\n");
	return 0;
}

static int read_response(int fd)
{
	unsigned char buf[255];
	struct sockaddr_in sa;
	int len;
	socklen_t sa_len = sizeof(sa);

	len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &sa_len);
	if (len < 0)
		return len;

	return parse_response(buf, len);
}

static int bfd_cb(struct bsc_fd *bfd, unsigned int flags)
{
	if (flags & BSC_FD_READ)
		return read_response(bfd->fd);
	if (flags & BSC_FD_WRITE) {
		bfd->when &= ~BSC_FD_WRITE;
		return bcast_find(bfd->fd);
	}
	return 0;
}

static struct timer_list timer;

static void timer_cb(void *_data)
{
	struct bsc_fd *bfd = _data;

	bfd->when |= BSC_FD_WRITE;

	schedule_timer(&timer, 5, 0);
}

int main(int argc, char **argv)
{
	struct bsc_fd bfd;
	int rc;

	printf("ipaccess-find (C) 2009 by Harald Welte\n");
	printf("This is FREE SOFTWARE with ABSOLUTELY NO WARRANTY\n\n");

	bfd.cb = bfd_cb;
	bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	bfd.fd = udp_sock();
	if (bfd.fd < 0)
		exit(2);

	bsc_register_fd(&bfd);

	timer.cb = timer_cb;
	timer.data = &bfd;

	schedule_timer(&timer, 5, 0);

	printf("Trying to find ip.access BTS by broadcast UDP...\n");

	while (1) {
		rc = bsc_select_main();
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

