/*
 * ubx.h
 *
 * Header for UBX related stuff
 *
 *
 * Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __UBX_H__
#define __UBX_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Constants used in UBX */

	/* Sync bytes (two first bytes of each message) */
#define UBX_SYNC0		0xb5
#define UBX_SYNC1		0x62

	/* UBX messages classes */
#define UBX_CLASS_NAV		0x01
#define UBX_CLASS_RXM		0x02
#define UBX_CLASS_INF		0x04
#define UBX_CLASS_ACK		0x05
#define UBX_CLASS_CFG		0x06
#define UBX_CLASS_UPD		0x09
#define UBX_CLASS_MON		0x0a
#define UBX_CLASS_AID		0x0b
#define UBX_CLASS_TIM		0x0d

	/* UBX messages type ID (by class) */
#define UBX_NAV_POSECEF		0x01
#define UBX_NAV_POSLLH		0x02
#define UBX_NAV_STATUS		0x03
#define UBX_NAV_DOP		0x04
#define UBX_NAV_SOL		0x06
#define UBX_NAV_POSUTM		0x08
#define UBX_NAV_VELECEF		0x11
#define UBX_NAV_VELNED		0x12
#define UBX_NAV_TIMEGPS		0x20
#define UBX_NAV_TIMEUTC		0x21
#define UBX_NAV_CLOCK		0x22
#define UBX_NAV_SVINFO		0x30
#define UBX_NAV_DGPS		0x31
#define UBX_NAV_SBAS		0x32
#define UBX_NAV_EKFSTATUS	0x40

#define UBX_RXM_RAW		0x10
#define UBX_RXM_SFRB		0x11
#define UBX_RXM_SVSI		0x20
#define UBX_RXM_SVSI_GPS	0x20
#define UBX_RXM_ALM		0x30
#define UBX_RXM_EPH		0x31
#define UBX_RXM_POSREQ		0x40

#define UBX_INF_ERROR		0x00
#define UBX_INF_WARNING		0x01
#define UBX_INF_NOTICE		0x02
#define UBX_INF_TEST		0x03
#define UBX_INF_DEBUG		0x04
#define UBX_INF_USER		0x07

#define UBX_ACK_NAK		0x00
#define UBX_ACK_ACK		0x01

#define UBX_CFG_PRT		0x00
#define UBX_CFG_USB		0x1b
#define UBX_CFG_MSG		0x01
#define UBX_CFG_NMEA		0x17
#define UBX_CFG_RATE		0x08
#define UBX_CFG_CFG		0x09
#define UBX_CFG_TP		0x07
#define UBX_CFG_NAV2		0x1a
#define UBX_CFG_DAT		0x06
#define UBX_CFG_INF		0x02
#define UBX_CFG_RST		0x04
#define UBX_CFG_RXM		0x11
#define UBX_CFG_ANT		0x13
#define UBX_CFG_FXN		0x0e
#define UBX_CFG_SBAS		0x16
#define UBX_CFG_LIC		0x80
#define UBX_CFG_TM		0x10
#define UBX_CFG_TM2		0x19
#define UBX_CFG_TMODE		0x1d
#define UBX_CFG_EKF		0x12

#define UBX_UPD_DOWNL		0x01
#define UBX_UPD_UPLOAD		0x02
#define UBX_UPD_EXEC		0x03
#define UBX_UPD_MEMCPY		0x04

#define UBX_MON_SCHD		0x01
#define UBX_MON_IO		0x02
#define UBX_MON_IPC		0x03
#define UBX_MON_VER		0x04
#define UBX_MON_EXCEPT		0x05
#define UBX_MON_MSGPP		0x06
#define UBX_MON_RXBUF		0x07
#define UBX_MON_TXBUF		0x08
#define UBX_MON_HW		0x09
#define UBX_MON_USB		0x0a

#define UBX_AID_REQ		0x00
#define UBX_AID_INI		0x01
#define UBX_AID_HUI		0x02
#define UBX_AID_DATA		0x10
#define UBX_AID_ALM		0x30
#define UBX_AID_EPH		0x31

#define UBX_TIM_TP		0x01
#define UBX_TIM_TM		0x02
#define UBX_TIM_TM2		0x03
#define UBX_TIM_SVIN		0x04


/* Header */
struct ubx_hdr {
        uint8_t  sync[2];
        uint8_t  msg_class;
        uint8_t  msg_id;
        uint16_t payload_len;
} __attribute__((packed));


/* Payload formats (some of them) */
struct ubx_nav_posllh {
	uint32_t itow;
	int32_t  lon;	/* scaling 1e-7 */
	int32_t  lat;	/* scaling 1e-7 */
	int32_t  height;/* mm */
	int32_t  hsl;	/* mm */
	uint32_t hacc;	/* mm */
	uint32_t vacc;	/* mm */
} __attribute__((packed));

struct ubx_aid_ini {
	int32_t  x;
	int32_t  y;
	int32_t  z;
	uint32_t posacc;
	uint16_t tm_cfg;
	uint16_t wn;
	uint32_t tow;
	int32_t  tow_ns;
	uint32_t tacc_ms;
	uint32_t tacc_ns;
	int32_t  clkd;
	uint32_t clkdacc;
	uint32_t flags;
} __attribute__((packed));

struct ubx_aid_hui {
	uint32_t health;
	double   utc_a1;
	double   utc_a0;
	int32_t  utc_tot;
	int16_t  utc_wnt;
	int16_t  utc_ls;
	int16_t  utc_wnf;
	int16_t  utc_dn;
	int16_t  utc_lsf;
	int16_t  utc_spare;
	float    klob_a0;
	float    klob_a1;
	float    klob_a2;
	float    klob_a3;
	float    klob_b0;
	float    klob_b1;
	float    klob_b2;
	float    klob_b3;
	uint32_t flags;
} __attribute__((packed));

struct ubx_aid_alm {
	uint32_t sv_id;
	uint32_t gps_week;
	uint32_t alm_words[8];	/* Present only if 'gps_week' != 0 */
} __attribute__((packed));

struct ubx_aid_eph {
	uint32_t sv_id;
	uint32_t present;
	uint32_t eph_words[24];	/* Present only if 'present' != 0 */
} __attribute__((packed));


/* Message handler */
typedef void (*ubx_msg_handler_t)(
	struct ubx_hdr *hdr, void *payload, int payload_len, void *userdata);

struct ubx_dispatch_entry {
	uint8_t msg_class;
	uint8_t msg_id;
	ubx_msg_handler_t handler;
};

#define UBX_DISPATCH(kls,id,hdl) {		\
	.msg_class = UBX_CLASS_ ## kls ,	\
	.msg_id = UBX_ ## kls ## _ ## id,	\
	.handler = (hdl),			\
}


/* Methods */
int ubx_msg_dispatch(struct ubx_dispatch_entry *dt,
                     void *msg, int len, void *userdata);


#ifdef __cplusplus
}
#endif

#endif /* __UBX_H__ */

