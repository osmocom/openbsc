/* RTP: A Transport Protocol for Real-Time Applications: RFC 3550 */

/*
 * (C) 2009-2013 by Harald Welte <laforge@gnumonks.org>
 * (C) 2014 by On-Waves
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <endian.h>
#include <stdint.h>

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
	uint16_t sequence_be;
	uint32_t timestamp_be;
	uint32_t ssrc_be;
	uint8_t data[0];
} __attribute__((packed));

inline size_t rtp_header_len(const struct rtp_hdr *rtp)
{
	size_t len = sizeof(struct rtp_hdr);

#if 0
	/* TODO: Just fail if csrc or extension present, reenable when test
	 * cases are present */
	len += rtp->csrc_count * 4;
	if (rtp->extension)
		len += 4 + 4 * ntohs(*(uint16_t *)(rtp->data + 2));
#endif

	return len;
}

/* TODO: Payload length computation (consider padding) */

inline uint16_t rtp_sequence(const struct rtp_hdr *rtp)
{
	return ntohs(rtp->sequence_be);
}

inline void rtp_set_sequence(struct rtp_hdr *rtp, uint16_t seq)
{
	rtp->sequence_be = htons(seq);
}

inline uint32_t rtp_ssrc(const struct rtp_hdr *rtp)
{
	return ntohl(rtp->ssrc_be);
}

inline void rtp_set_ssrc(struct rtp_hdr *rtp, uint32_t ssrc)
{
	rtp->ssrc_be = htonl(ssrc);
}

inline uint32_t rtp_timestamp(const struct rtp_hdr *rtp)
{
	return ntohl(rtp->timestamp_be);
}

inline void rtp_set_timestamp(struct rtp_hdr *rtp, uint32_t timestamp)
{
	rtp->timestamp_be = htonl(timestamp);
}
