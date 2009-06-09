
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <openbsc/select.h>
#include <openbsc/timer.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>

static const char *idtag_names[] = {
	[IPAC_IDTAG_SERNR]	= "Serial Number",
	[IPAC_IDTAG_UNITNAME]	= "Unit Name",
	[IPAC_IDTAG_LOCATION1]	= "Location 1",
	[IPAC_IDTAG_LOCATION2]	= "Location 2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equipment Version",
	[IPAC_IDTAG_SWVERSION]	= "Software Version",
	[IPAC_IDTAG_IPADDR]	= "IP Address",
	[IPAC_IDTAG_MACADDR]	= "MAC Address",
	[IPAC_IDTAG_UNIT]	= "Unit ID",
};

static const char *ipac_idtag_name(int tag)
{
	if (tag >= ARRAY_SIZE(idtag_names))
		return "unknown";

	return idtag_names[tag];
}

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

const unsigned char find_pkt[] = { 0x00, 0x0b+8, IPAC_PROTO_IPACCESS, 0x00, 
				IPAC_MSGT_ID_GET,
					0x01, IPAC_IDTAG_MACADDR,
					0x01, IPAC_IDTAG_IPADDR,
					0x01, IPAC_IDTAG_UNIT,
					0x01, IPAC_IDTAG_LOCATION1,
					0x01, IPAC_IDTAG_LOCATION2,
					0x01, IPAC_IDTAG_EQUIPVERS,
					0x01, IPAC_IDTAG_SWVERSION,
					0x01, IPAC_IDTAG_UNITNAME,
					0x01, IPAC_IDTAG_SERNR,
				};


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

	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;
		
		printf("%s='%s'  ", ipac_idtag_name(t_tag), cur);

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

	return parse_response(buf+6, len-6);
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

	bsc_schedule_timer(&timer, 5, 0);
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

	bsc_schedule_timer(&timer, 5, 0);

	printf("Trying to find ip.access BTS by broadcast UDP...\n");

	while (1) {
		rc = bsc_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}

