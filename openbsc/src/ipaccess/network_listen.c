/* ip.access nanoBTS network listen mode */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <osmocore/talloc.h>
#include <osmocore/timer.h>

#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>

enum ipac_test_state {
	IPAC_TEST_S_IDLE,
	IPAC_TEST_S_RQD,
	IPAC_TEST_S_EXEC,
	IPAC_TEST_S_PARTIAL,
};

int ipac_nwl_test_start(struct gsm_bts_trx *trx, uint8_t testnr)
{
	const uint8_t phys_config[] = { 0x02, 0x0a, 0x00, 0x01, 0x02 };

	if (trx->ipaccess.test_state != IPAC_TEST_S_IDLE) {
		fprintf(stderr, "Cannot start test in state %u\n", trx->ipaccess.test_state);
		return -EINVAL;
	}

	abis_nm_perform_test(trx->bts, 2, 0, trx->nr, 0xff, testnr, 1,
			     phys_config, sizeof(phys_config));

	/* FIXME: start safety timer until when test is supposed to complete */

	return 0;
}

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
	int i, rc;

	DEBUGP(DNM, "TEST REPORT: ");

	if (foh->data[0] != NM_ATT_TEST_NO ||
	    foh->data[2] != NM_ATT_TEST_REPORT)
		return -EINVAL;

	DEBUGPC(DNM, "test_no=0x%02x ", foh->data[1]);
	/* data[2] == NM_ATT_TEST_REPORT */
	/* data[3..4]: test_rep_len */
	test_rep_len = ntohs(*(uint16_t *) &foh->data[3]);
	/* data[5]: ip.access test result */
	DEBUGPC(DNM, "tst_res=%s\n", ipacc_testres_name(foh->data[5]));

	/* data[6]: ip.access nested IE. 3 == freq_err_list */
	switch (foh->data[6]) {
	case NM_IPAC_EIE_FREQ_ERR_LIST:
		/* data[7..8]: length of ferr_list */
		ferr_list_len = ntohs(*(uint16_t *) &foh->data[7]);

		/* data[9...]: frequency error list elements */
		for (i = 0; i < ferr_list_len; i+= sizeof(*ife)) {
			ife = (struct ipacc_ferr_elem *) (foh->data + 9 + i);
			DEBUGP(DNM, "==> ARFCN %4u, Frequency Error %6hd\n",
			ife->arfcn, ntohs(ife->freq_err));
		}
		break;
	case NM_IPAC_EIE_CHAN_USE_LIST:
		/* data[7..8]: length of ferr_list */
		ferr_list_len = ntohs(*(uint16_t *) &foh->data[7]);

		/* data[9...]: channel usage list elements */
		for (i = 0; i < ferr_list_len; i+= 2) {
			uint16_t *cu_ptr = (uint16_t *)(foh->data + 9 + i);
			uint16_t cu = ntohs(*cu_ptr);
			DEBUGP(DNM, "==> ARFCN %4u, RxLev %2u\n",
				cu & 0x3ff, cu >> 10);
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
		DEBUGP(DNM, "==> ARFCN %u, RxLev %2u, RxQual %2u: %3d-%d, LAC %d CI %d\n",
			binfo.arfcn, binfo.rx_lev, binfo.rx_qual,
			binfo.cgi.mcc, binfo.cgi.mnc,
			binfo.cgi.lac, binfo.cgi.ci);
		break;
	default:
		break;
	}

	switch (foh->data[5]) {
	case NM_IPACC_TESTRES_SUCCESS:
	case NM_IPACC_TESTRES_STOPPED:
	case NM_IPACC_TESTRES_TIMEOUT:
	case NM_IPACC_TESTRES_NO_CHANS:
		msg->trx->ipaccess.test_state = IPAC_TEST_S_IDLE;
		/* Send signal to notify higher layers of test completion */
		dispatch_signal(SS_IPAC_NWL, S_IPAC_NWL_COMPLETE, msg->trx);
		break;
	case NM_IPACC_TESTRES_PARTIAL:
		msg->trx->ipaccess.test_state = IPAC_TEST_S_PARTIAL;
		break;
	}

	return 0;
}

static int nwl_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	struct ipacc_ack_signal_data *ipacc_data;

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
	register_signal_handler(SS_NM, nwl_sig_cb, NULL);
}
