/* ip.access nanoBTS network listen mode */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/rxlev_stat.h>
#include <osmocom/gsm/gsm48_ie.h>

#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <osmocom/abis/e1_input.h>

#define WHITELIST_MAX_SIZE ((NUM_ARFCNS*2)+2+1)

int ipac_rxlevstat2whitelist(uint16_t *buf, const struct rxlev_stats *st, uint8_t min_rxlev,
			     uint16_t max_num_arfcns)
{
	int i;
	unsigned int num_arfcn = 0;

	for (i = NUM_RXLEVS-1; i >= min_rxlev; i--) {
		int16_t arfcn = -1;

		while ((arfcn = rxlev_stat_get_next(st, i, arfcn)) >= 0) {
			*buf++ = htons(arfcn);
			num_arfcn++;

		}

		if (num_arfcn > max_num_arfcns)
			break;
	}

	return num_arfcn;
}

enum ipac_test_state {
	IPAC_TEST_S_IDLE,
	IPAC_TEST_S_RQD,
	IPAC_TEST_S_EXEC,
	IPAC_TEST_S_PARTIAL,
};

int ipac_nwl_test_start(struct gsm_bts_trx *trx, uint8_t testnr,
			const uint8_t *phys_conf, unsigned int phys_conf_len)
{
	struct msgb *msg;

	if (trx->ipaccess.test_state != IPAC_TEST_S_IDLE) {
		fprintf(stderr, "Cannot start test in state %u\n", trx->ipaccess.test_state);
		return -EINVAL;
	}

	switch (testnr) {
	case NM_IPACC_TESTNO_CHAN_USAGE:
	case NM_IPACC_TESTNO_BCCH_CHAN_USAGE:
		rxlev_stat_reset(&trx->ipaccess.rxlev_stat);
		break;
	}

	msg = msgb_alloc_headroom(phys_conf_len+256, 128, "OML");

	if (phys_conf && phys_conf_len) {
		uint8_t *payload;
		/* first put the phys conf header */
		msgb_tv16_put(msg, NM_ATT_PHYS_CONF, phys_conf_len);
		payload = msgb_put(msg, phys_conf_len);
		memcpy(payload, phys_conf, phys_conf_len);
	}

	abis_nm_perform_test(trx->bts, NM_OC_RADIO_CARRIER, 0, trx->nr, 0xff,
			     testnr, 1, msg);
	trx->ipaccess.test_nr = testnr;

	/* FIXME: start safety timer until when test is supposed to complete */

	return 0;
}

static uint16_t last_arfcn;
static struct gsm_sysinfo_freq nwl_si_freq[1024];
#define FREQ_TYPE_NCELL_2	0x04 /* sub channel of SI 2 */
#define FREQ_TYPE_NCELL_2bis	0x08 /* sub channel of SI 2bis */
#define FREQ_TYPE_NCELL_2ter	0x10 /* sub channel of SI 2ter */

struct ipacc_ferr_elem {
	int16_t freq_err;
	uint8_t freq_qual;
	uint8_t arfcn;
} __attribute__((packed));

struct ipacc_cusage_elem {
	uint16_t arfcn:10,
		  rxlev:6;
} __attribute__ ((packed));

static int test_rep(void *_msg)
{
	struct msgb *msg = _msg;
	struct abis_om_fom_hdr *foh = msgb_l3(msg);
	uint16_t test_rep_len, ferr_list_len;
	struct ipacc_ferr_elem *ife;
	struct ipac_bcch_info binfo;
	struct e1inp_sign_link *sign_link = (struct e1inp_sign_link *)msg->dst;
	int i, rc;

	DEBUGP(DNM, "TEST REPORT: ");

	if (foh->data[0] != NM_ATT_TEST_NO ||
	    foh->data[2] != NM_ATT_TEST_REPORT)
		return -EINVAL;

	DEBUGPC(DNM, "test_no=0x%02x ", foh->data[1]);
	/* data[2] == NM_ATT_TEST_REPORT */
	/* data[3..4]: test_rep_len */
	memcpy(&test_rep_len, &foh->data[3], sizeof(uint16_t));
	test_rep_len = ntohs(test_rep_len);
	/* data[5]: ip.access test result */
	DEBUGPC(DNM, "tst_res=%s\n", ipacc_testres_name(foh->data[5]));

	/* data[6]: ip.access nested IE. 3 == freq_err_list */
	switch (foh->data[6]) {
	case NM_IPAC_EIE_FREQ_ERR_LIST:
		/* data[7..8]: length of ferr_list */
		memcpy(&ferr_list_len, &foh->data[7], sizeof(uint16_t));
		ferr_list_len = ntohs(ferr_list_len);

		/* data[9...]: frequency error list elements */
		for (i = 0; i < ferr_list_len; i+= sizeof(*ife)) {
			ife = (struct ipacc_ferr_elem *) (foh->data + 9 + i);
			DEBUGP(DNM, "==> ARFCN %4u, Frequency Error %6hd\n",
			ife->arfcn, ntohs(ife->freq_err));
		}
		break;
	case NM_IPAC_EIE_CHAN_USE_LIST:
		/* data[7..8]: length of ferr_list */
		memcpy(&ferr_list_len, &foh->data[7], sizeof(uint16_t));
		ferr_list_len = ntohs(ferr_list_len);

		/* data[9...]: channel usage list elements */
		for (i = 0; i < ferr_list_len; i+= 2) {
			uint16_t *cu_ptr = (uint16_t *)(foh->data + 9 + i);
			uint16_t cu = ntohs(*cu_ptr);
			uint16_t arfcn = cu & 0x3ff;
			uint8_t rxlev = cu >> 10;
			DEBUGP(DNM, "==> ARFCN %4u, RxLev %2u\n", arfcn, rxlev);
			rxlev_stat_input(&sign_link->trx->ipaccess.rxlev_stat,
					 arfcn, rxlev);
		}
		break;
	case NM_IPAC_EIE_BCCH_INFO_TYPE:
		break;
	case NM_IPAC_EIE_BCCH_INFO:
		rc = ipac_parse_bcch_info(&binfo, foh->data+6);
		if (rc < 0) {
			DEBUGP(DNM, "BCCH Info parsing failed\n");
			break;
		}
		DEBUGP(DNM, "==> ARFCN %u, RxLev %2u, RxQual %2u: %3d-%d, LAC %d CI %d BSIC %u\n",
			binfo.arfcn, binfo.rx_lev, binfo.rx_qual,
			binfo.cgi.mcc, binfo.cgi.mnc,
			binfo.cgi.lac, binfo.cgi.ci, binfo.bsic);

		if (binfo.arfcn != last_arfcn) {
			/* report is on a new arfcn, need to clear channel list */
			memset(nwl_si_freq, 0, sizeof(nwl_si_freq));
			last_arfcn = binfo.arfcn;
		}
		if (binfo.info_type & IPAC_BINF_NEIGH_BA_SI2) {
			DEBUGP(DNM, "BA SI2: %s\n", osmo_hexdump(binfo.ba_list_si2, sizeof(binfo.ba_list_si2)));
			gsm48_decode_freq_list(nwl_si_freq, binfo.ba_list_si2, sizeof(binfo.ba_list_si2),
						0x8c, FREQ_TYPE_NCELL_2);
		}
		if (binfo.info_type & IPAC_BINF_NEIGH_BA_SI2bis) {
			DEBUGP(DNM, "BA SI2bis: %s\n", osmo_hexdump(binfo.ba_list_si2bis, sizeof(binfo.ba_list_si2bis)));
			gsm48_decode_freq_list(nwl_si_freq, binfo.ba_list_si2bis, sizeof(binfo.ba_list_si2bis),
						0x8e, FREQ_TYPE_NCELL_2bis);
		}
		if (binfo.info_type & IPAC_BINF_NEIGH_BA_SI2ter) {
			DEBUGP(DNM, "BA SI2ter: %s\n", osmo_hexdump(binfo.ba_list_si2ter, sizeof(binfo.ba_list_si2ter)));
			gsm48_decode_freq_list(nwl_si_freq, binfo.ba_list_si2ter, sizeof(binfo.ba_list_si2ter),
						0x8e, FREQ_TYPE_NCELL_2ter);
		}
		for (i = 0; i < ARRAY_SIZE(nwl_si_freq); i++) {
			if (nwl_si_freq[i].mask)
				DEBUGP(DNM, "Neighbor Cell on ARFCN %u\n", i);
		}
		break;
	default:
		break;
	}

	switch (foh->data[5]) {
	case NM_IPACC_TESTRES_SUCCESS:
	case NM_IPACC_TESTRES_STOPPED:
	case NM_IPACC_TESTRES_TIMEOUT:
	case NM_IPACC_TESTRES_NO_CHANS:
		sign_link->trx->ipaccess.test_state = IPAC_TEST_S_IDLE;
		/* Send signal to notify higher layers of test completion */
		DEBUGP(DNM, "dispatching S_IPAC_NWL_COMPLETE signal\n");
		osmo_signal_dispatch(SS_IPAC_NWL, S_IPAC_NWL_COMPLETE,
					sign_link->trx);
		break;
	case NM_IPACC_TESTRES_PARTIAL:
		sign_link->trx->ipaccess.test_state = IPAC_TEST_S_PARTIAL;
		break;
	}

	return 0;
}

static int nwl_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	switch (signal) {
	case S_NM_TEST_REP:
		return test_rep(signal_data);
	default:
		break;
	}

	return 0;
}

void ipac_nwl_init(void)
{
	osmo_signal_register_handler(SS_NM, nwl_sig_cb, NULL);
}
