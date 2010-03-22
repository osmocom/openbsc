#ifndef _IPACCESS_H
#define _IPACCESS_H

#include "e1_input.h"
#include <osmocore/linuxlist.h>

#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

struct ipaccess_head {
	u_int16_t len;	/* network byte order */
	u_int8_t proto;
	u_int8_t data[0];
} __attribute__ ((packed));

enum ipaccess_proto {
	IPAC_PROTO_RSL		= 0x00,
	IPAC_PROTO_IPACCESS	= 0xfe,
	IPAC_PROTO_SCCP		= 0xfd,
	IPAC_PROTO_OML		= 0xff,
};

enum ipaccess_msgtype {
	IPAC_MSGT_PING		= 0x00,
	IPAC_MSGT_PONG		= 0x01,
	IPAC_MSGT_ID_GET	= 0x04,
	IPAC_MSGT_ID_RESP	= 0x05,
	IPAC_MSGT_ID_ACK	= 0x06,
};

enum ipaccess_id_tags {
	IPAC_IDTAG_SERNR		= 0x00,
	IPAC_IDTAG_UNITNAME		= 0x01,
	IPAC_IDTAG_LOCATION1		= 0x02,
	IPAC_IDTAG_LOCATION2		= 0x03,
	IPAC_IDTAG_EQUIPVERS		= 0x04,
	IPAC_IDTAG_SWVERSION		= 0x05,
	IPAC_IDTAG_IPADDR		= 0x06,
	IPAC_IDTAG_MACADDR		= 0x07,
	IPAC_IDTAG_UNIT			= 0x08,
};

int ipaccess_connect(struct e1inp_line *line, struct sockaddr_in *sa);

/*
 * methods for parsing and sending a message
 */
int ipaccess_rcvmsg_base(struct msgb *msg, struct bsc_fd *bfd);
struct msgb *ipaccess_read_msg(struct bsc_fd *bfd, int *error);
void ipaccess_prepend_header(struct msgb *msg, int proto);
int ipaccess_send_id_ack(int fd);
int ipaccess_send_id_req(int fd);

int ipaccess_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len);


/*
 * Firmware specific header
 */
struct sdp_firmware {
	char magic[4];
	char more_magic[2];
	u_int16_t more_more_magic;
	u_int32_t header_length;
	u_int32_t file_length;
	char sw_part[20];
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char version[20];
	u_int16_t table_offset;
	/* stuff i don't know */
} __attribute__((packed));

struct sdp_header_entry {
	u_int16_t something1;
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char version[20];
	u_int32_t length;
	u_int32_t addr1;
	u_int32_t addr2;
	u_int32_t start;
} __attribute__((packed));

struct sdp_header_item {
	struct sdp_header_entry header_entry;
	struct llist_head entry;
};

struct sdp_header {
	struct sdp_firmware firmware_info;

	/* for more_magic a list of sdp_header_entry_list */
	struct llist_head header_list;

	/* the entry of the sdp_header */
	struct llist_head entry;
};

int ipaccess_analyze_file(int fd, const unsigned int st_size, const unsigned base_offset, struct llist_head *list);

#endif /* _IPACCESS_H */
