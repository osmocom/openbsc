#ifndef OPENSC_RTP_RFC_H
#define OPENSC_RTP_RFC_H

#include <stdint.h>
#include <unistd.h>

/* attempt to determine byte order */
#include <sys/param.h>
#include <limits.h>

#ifndef __BYTE_ORDER
#error "__BYTE_ORDER should be defined by someone"
#endif

#define RTP_VERSION	2

#define RTCP_TYPE_SDES	202
#define RTCP_IE_CNAME	1

/* according to RFC 1889 */
struct rtcp_hdr {
	uint8_t byte0;
	uint8_t type;
	uint16_t length;
} __attribute__((packed));

/* according to rtp_proxy.c RFC 3550 */
struct rtp_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t  csrc_count:4,
		  extension:1,
		  padding:1,
		  version:2;
	uint8_t  payload_type:7,
		  marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t  version:2,
		  padding:1,
		  extension:1,
		  csrc_count:4;
	uint8_t  marker:1,
		  payload_type:7;
#endif
	uint16_t sequence;
	uint32_t timestamp;
	uint32_t ssrc;
} __attribute__((packed));


#endif
