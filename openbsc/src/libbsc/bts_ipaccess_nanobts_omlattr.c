/* ip.access nanoBTS specific code, OML attribute table generator */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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
 */

#include <arpa/inet.h>
#include <osmocom/core/msgb.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>

static void patch_16(uint8_t *data, const uint16_t val)
{
	memcpy(data, &val, sizeof(val));
}

static void patch_32(uint8_t *data, const uint32_t val)
{
	memcpy(data, &val, sizeof(val));
}

struct msgb *nanobts_attr_bts_get(struct gsm_bts *bts)
{
	struct msgb *msgb;
	uint8_t buf[256];
	int rlt;
	msgb = msgb_alloc(1024, "nanobts_attr_bts");

	memcpy(buf, "\x55\x5b\x61\x67\x6d\x73", 6);
	msgb_tv_fixed_put(msgb, NM_ATT_INTERF_BOUND, 6, buf);

	/* interference avg. period in numbers of SACCH multifr */
	msgb_tv_put(msgb, NM_ATT_INTAVE_PARAM, 0x06);

	rlt = gsm_bts_get_radio_link_timeout(bts);
	if (rlt == -1) {
		/* Osmocom extension: Use infinite radio link timeout */
		buf[0] = 0xFF;
		buf[1] = 0x00;
	} else {
		/* conn fail based on SACCH error rate */
		buf[0] = 0x01;
		buf[1] = rlt;
	}
	msgb_tl16v_put(msgb, NM_ATT_CONN_FAIL_CRIT, 2, buf);

	memcpy(buf, "\x1e\x24\x24\xa8\x34\x21\xa8", 7);
	msgb_tv_fixed_put(msgb, NM_ATT_T200, 7, buf);

	msgb_tv_put(msgb, NM_ATT_MAX_TA, 0x3f);

	/* seconds */
	memcpy(buf, "\x00\x01\x0a", 3);
	msgb_tv_fixed_put(msgb, NM_ATT_OVERL_PERIOD, 3, buf);

	/* percent */
	msgb_tv_put(msgb, NM_ATT_CCCH_L_T, 10);

	/* seconds */
	msgb_tv_put(msgb, NM_ATT_CCCH_L_I_P, 1);

	/* busy threshold in - dBm */
	buf[0] = 10;
	if (bts->rach_b_thresh != -1)
		buf[0] = bts->rach_b_thresh & 0xff;
	msgb_tv_put(msgb, NM_ATT_RACH_B_THRESH, buf[0]);

	/* rach load averaging 1000 slots */
	buf[0] = 0x03;
	buf[1] = 0xe8;
	if (bts->rach_ldavg_slots != -1) {
		buf[0] = (bts->rach_ldavg_slots >> 8) & 0x0f;
		buf[1] = bts->rach_ldavg_slots & 0xff;
	}
	msgb_tv_fixed_put(msgb, NM_ATT_LDAVG_SLOTS, 2, buf);

	/* miliseconds */
	msgb_tv_put(msgb, NM_ATT_BTS_AIR_TIMER, 128);

	/* 10 retransmissions of physical config */
	msgb_tv_put(msgb, NM_ATT_NY1, 10);

	buf[0] = (bts->c0->arfcn >> 8) & 0x0f;
	buf[1] = bts->c0->arfcn & 0xff;
	msgb_tv_fixed_put(msgb, NM_ATT_BCCH_ARFCN, 2, buf);

	msgb_tv_put(msgb, NM_ATT_BSIC, bts->bsic);

	abis_nm_ipaccess_cgi(buf, bts);
	msgb_tl16v_put(msgb, NM_ATT_IPACC_CGI, 7, buf);

	return msgb;
}

struct msgb *nanobts_attr_nse_get(struct gsm_bts *bts)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");

	/* NSEI 925 */
	buf[0] = bts->gprs.nse.nsei >> 8;
	buf[1] = bts->gprs.nse.nsei & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NSEI, 2, buf);

	/* all timers in seconds */
	OSMO_ASSERT(ARRAY_SIZE(bts->gprs.nse.timer) < sizeof(buf));
	memcpy(buf, bts->gprs.nse.timer, ARRAY_SIZE(bts->gprs.nse.timer));
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NS_CFG, 7, buf);

	/* all timers in seconds */
	buf[0] = 3;	/* blockimg timer (T1) */
	buf[1] = 3;	/* blocking retries */
	buf[2] = 3;	/* unblocking retries */
	buf[3] = 3;	/* reset timer (T2) */
	buf[4] = 3;	/* reset retries */
	buf[5] = 10;	/* suspend timer (T3) in 100ms */
	buf[6] = 3;	/* suspend retries */
	buf[7] = 10;	/* resume timer (T4) in 100ms */
	buf[8] = 3;	/* resume retries */
	buf[9] = 10;	/* capability update timer (T5) */
	buf[10] = 3;	/* capability update retries */

	OSMO_ASSERT(ARRAY_SIZE(bts->gprs.cell.timer) < sizeof(buf));
	memcpy(buf, bts->gprs.cell.timer, ARRAY_SIZE(bts->gprs.cell.timer));
	msgb_tl16v_put(msgb, NM_ATT_IPACC_BSSGP_CFG, 11, buf);

	return msgb;
}

struct msgb *nanobts_attr_cell_get(struct gsm_bts *bts)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");

	/* routing area code */
	buf[0] = bts->gprs.rac;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RAC, 1, buf);

	buf[0] = 5;	/* repeat time (50ms) */
	buf[1] = 3;	/* repeat count */
	msgb_tl16v_put(msgb, NM_ATT_IPACC_GPRS_PAGING_CFG, 2, buf);

	/* BVCI 925 */
	buf[0] = bts->gprs.cell.bvci >> 8;
	buf[1] = bts->gprs.cell.bvci & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_BVCI, 2, buf);

	/* all timers in seconds, unless otherwise stated */
	buf[0] = 20;	/* T3142 */
	buf[1] = 5;	/* T3169 */
	buf[2] = 5;	/* T3191 */
	buf[3] = 160;	/* T3193 (units of 10ms) */
	buf[4] = 5;	/* T3195 */
	buf[5] = 10;	/* N3101 */
	buf[6] = 4;	/* N3103 */
	buf[7] = 8;	/* N3105 */
	buf[8] = 15;	/* RLC CV countdown */
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG, 9, buf);

	if (bts->gprs.mode == BTS_GPRS_EGPRS) {
		buf[0] = 0x8f;
		buf[1] = 0xff;
	} else {
		buf[0] = 0x0f;
		buf[1] = 0x00;
	}
	msgb_tl16v_put(msgb, NM_ATT_IPACC_CODING_SCHEMES, 2, buf);

	buf[0] = 0;	/* T downlink TBF extension (0..500, high byte) */
	buf[1] = 250;	/* T downlink TBF extension (0..500, low byte) */
	buf[2] = 0;	/* T uplink TBF extension (0..500, high byte) */
	buf[3] = 250;	/* T uplink TBF extension (0..500, low byte) */
	buf[4] = 2;	/* CS2 */
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG_2, 5, buf);

#if 0
	/* EDGE model only, breaks older models.
	 * Should inquire the BTS capabilities */
	buf[0] = 2;		/* MCS2 */
	msgb_tl16v_put(msgb, NM_ATT_IPACC_RLC_CFG_3, 1, buf);
#endif

	return msgb;
}

struct msgb *nanobts_attr_nscv_get(struct gsm_bts *bts)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");

	/* 925 */
	buf[0] = bts->gprs.nsvc[0].nsvci >> 8;
	buf[1] = bts->gprs.nsvc[0].nsvci & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NSVCI, 2, buf);

	/* remote udp port */
	patch_16(&buf[0], htons(bts->gprs.nsvc[0].remote_port));
	/* remote ip address */
	patch_32(&buf[2], htonl(bts->gprs.nsvc[0].remote_ip));
	/* local udp port */
	patch_16(&buf[6], htons(bts->gprs.nsvc[0].local_port));
	msgb_tl16v_put(msgb, NM_ATT_IPACC_NS_LINK_CFG, 8, buf);

	return msgb;
}

struct msgb *nanobts_attr_radio_get(struct gsm_bts *bts,
				    struct gsm_bts_trx *trx)
{
	struct msgb *msgb;
	uint8_t buf[256];
	msgb = msgb_alloc(1024, "nanobts_attr_bts");

	/* number of -2dB reduction steps / Pn */
	msgb_tv_put(msgb, NM_ATT_RF_MAXPOWR_R, trx->max_power_red / 2);

	buf[0] = trx->arfcn >> 8;
	buf[1] = trx->arfcn & 0xff;
	msgb_tl16v_put(msgb, NM_ATT_ARFCN_LIST, 2, buf);

	return msgb;
}
