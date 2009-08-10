#ifndef _IPACCESS_H
#define _IPACCESS_H

struct ipaccess_head {
	u_int8_t zero;
	u_int8_t len;
	u_int8_t proto;
	u_int8_t data[0];
} __attribute__ ((packed));

enum ipaccess_proto {
	IPAC_PROTO_RSL		= 0x00,
	IPAC_PROTO_IPACCESS	= 0xfe,
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

#endif /* _IPACCESS_H */
