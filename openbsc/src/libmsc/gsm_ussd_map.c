/* GSM USSD external MAP interface */

/* (C) 2015 by Sergey Kostanbaev <sergey.kostanbaev@gmail.com>
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

#include <openbsc/gsm_ussd_map.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/gprs_gsup_messages.h>
#include <openbsc/gprs_gsup_client.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/ussd.h>


int ussd_map_tx_message(struct gsm_network* net,
			struct ss_header *req,
			const char* extension,
			uint32_t ref,
			const uint8_t* component_data)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	subscr_uss_message(msg, req, extension, ref, component_data);

	return gprs_gsup_client_send(net->ussd_sup_client, msg);
}


static int ussd_map_rx_message_int(struct gsm_network *net, const uint8_t* data, size_t len)
{
	char extension[32] = {0};
	uint32_t ref;
	struct ss_header ss;
	memset(&ss, 0, sizeof(ss));

	if (rx_uss_message_parse(data, len, &ss, &ref, extension, sizeof(extension))) {
		LOGP(DSS, LOGL_ERROR, "Can't parse SUP MAP SS message\n");
		return -1;
	}

	LOGP(DSS, LOGL_ERROR, "Got type=0x%02x len=%d\n",
	     ss.message_type, ss.component_length);

	return on_ussd_response(net, ref, &ss, data + ss.component_offset, extension);
}

static int ussd_map_rx_message(struct gprs_gsup_client *sup_client, struct msgb *msg)
{
	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	struct gsm_network *gsmnet = (struct gsm_network *)sup_client->data;

	if (*data != GPRS_GSUP_MSGT_USSD_MAP) {
		return -1;
	}

	return ussd_map_rx_message_int(gsmnet, data, data_len);
}

int ussd_map_read_cb(struct gprs_gsup_client *sup_client, struct msgb *msg)
{
	int rc;

	rc = ussd_map_rx_message(sup_client, msg);
	msgb_free(msg);
	if (rc < 0)
		return -1;

	return rc;
}
