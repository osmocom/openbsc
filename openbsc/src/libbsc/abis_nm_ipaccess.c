/* GSM Network Management (OML) messages on the A-bis interface 
 * Extensions for the ip.access A-bis over IP protocol*/

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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

/* A list of all the 'embedded' attributes of ip.access */
enum ipa_embedded_att {
	IPA_ATT_ARFCN_WHITELIST		= 0x01,
	IPA_ATT_ARFCN_BLACKLIST		= 0x02,
	IPA_ATT_FREQ_ERR_LIST		= 0x03,
	IPA_ATT_CHAN_USAGE_LIST		= 0x04,
	IPA_ATT_BCCH_INF_TYPE		= 0x05,
	IPA_ATT_BCCH_INF		= 0x06,
	IPA_ATT_CONFIG			= 0x07,
	IPA_ATT_RESULT_DETAILS		= 0x08,
	IPA_ATT_RXLEV_THRESH		= 0x09,
	IPA_ATT_FREQ_SYNC_OPT		= 0x0a,
	IPA_ATT_MAC_ADDR		= 0x0b,
	IPA_ATT_HW_SW_COMPAT_NR		= 0x0c,
	IPA_ATT_MANUF_SER_NR		= 0x0d,
	IPA_ATT_OEM_ID			= 0x0e,
	IPA_ATT_DATETIME_MANUF		= 0x0f,
	IPA_ATT_DATETIME_CALIB		= 0x10,
	IPA_ATT_BEACON_INF		= 0x11,
	IPA_ATT_FREQ_ERR		= 0x12,
	IPA_ATT_SNMP_COMM_STRING	= 0x13,
	IPA_ATT_SNMP_TRAP_ADDR		= 0x14,
	IPA_ATT_SNMP_TRAP_PORT		= 0x15,
	IPA_ATT_SNMP_MAN_ADDR		= 0x16,
	IPA_ATT_SNMP_SYS_CONTACT	= 0x17,
	IPA_ATT_FACTORY_ID		= 0x18,
	IPA_ATT_FACTORY_SERIAL		= 0x19,
	IPA_ATT_LOGGED_EVT_IND		= 0x1a,
	IPA_ATT_LOCAL_ADD_TEXT		= 0x1b,
	IPA_ATT_FREQ_BANDS		= 0x1c,
	IPA_ATT_MAX_TA			= 0x1d,
	IPA_ATT_CIPH_ALG		= 0x1e,
	IPA_ATT_CHAN_TYPES		= 0x1f,
	IPA_ATT_CHAN_MODES		= 0x20,
	IPA_ATT_GPRS_CODING_SCHEMES	= 0x21,
	IPA_ATT_RTP_FEATURES		= 0x22,
	IPA_ATT_RSL_FEATURES		= 0x23,
	IPA_ATT_BTS_HW_CLASS		= 0x24,
	IPA_ATT_BTS_ID			= 0x25,
	IPA_ATT_BCAST_L2_MSG		= 0x26,
};

/* append an ip.access channel list to the given msgb */
static int ipa_chan_list_append(struct msgb *msg, uint8_t ie,
				uint16_t *arfcns, int arfcn_count)
{
	int i;
	uint8_t *u8;
	uint16_t *u16;

	/* tag */
	u8 = msgb_push(msg, 1);
	*u8 = ie;

	/* length in octets */
	u16 = msgb_push(msg, 2);
	*u16 = htons(arfcn_count * 2);

	for (i = 0; i < arfcn_count; i++) {
		u16 = msgb_push(msg, 2);
		*u16 = htons(arfcns[i]);
	}

	return 0;
}
