/* GPRS utility functions */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2014 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
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
#include <openbsc/gprs_utils.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gprs/gprs_ns.h>

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>

#include <string.h>

/* FIXME: this needs to go to libosmocore/msgb.c */
struct msgb *gprs_msgb_copy(const struct msgb *msg, const char *name)
{
	struct libgb_msgb_cb *old_cb, *new_cb;
	struct msgb *new_msg;

	new_msg = msgb_alloc(msg->data_len, name);
	if (!new_msg)
		return NULL;

	/* copy data */
	memcpy(new_msg->_data, msg->_data, new_msg->data_len);

	/* copy header */
	new_msg->len = msg->len;
	new_msg->data += msg->data - msg->_data;
	new_msg->head += msg->head - msg->_data;
	new_msg->tail += msg->tail - msg->_data;

	if (msg->l1h)
		new_msg->l1h = new_msg->_data + (msg->l1h - msg->_data);
	if (msg->l2h)
		new_msg->l2h = new_msg->_data + (msg->l2h - msg->_data);
	if (msg->l3h)
		new_msg->l3h = new_msg->_data + (msg->l3h - msg->_data);
	if (msg->l4h)
		new_msg->l4h = new_msg->_data + (msg->l4h - msg->_data);

	/* copy GB specific data */
	old_cb = LIBGB_MSGB_CB(msg);
	new_cb = LIBGB_MSGB_CB(new_msg);

	if (old_cb->bssgph)
		new_cb->bssgph = new_msg->_data + (old_cb->bssgph - msg->_data);
	if (old_cb->llch)
		new_cb->llch = new_msg->_data + (old_cb->llch - msg->_data);

	/* bssgp_cell_id is a pointer into the old msgb, so we need to make
	 * it a pointer into the new msgb */
	if (old_cb->bssgp_cell_id)
		new_cb->bssgp_cell_id = new_msg->_data +
			(old_cb->bssgp_cell_id - msg->_data);
	new_cb->nsei = old_cb->nsei;
	new_cb->bvci = old_cb->bvci;
	new_cb->tlli = old_cb->tlli;

	return new_msg;
}

/* TODO: Move this to libosmocore/msgb.c */
int gprs_msgb_resize_area(struct msgb *msg, uint8_t *area,
			    size_t old_size, size_t new_size)
{
	int rc;
	uint8_t *rest = area + old_size;
	int rest_len = msg->len - old_size - (area - msg->data);
	int delta_size = (int)new_size - (int)old_size;

	if (delta_size == 0)
		return 0;

	if (delta_size > 0) {
		rc = msgb_trim(msg, msg->len + delta_size);
		if (rc < 0)
			return rc;
	}

	memmove(area + new_size, area + old_size, rest_len);

	if (msg->l1h >= rest)
		msg->l1h += delta_size;
	if (msg->l2h >= rest)
		msg->l2h += delta_size;
	if (msg->l3h >= rest)
		msg->l3h += delta_size;
	if (msg->l4h >= rest)
		msg->l4h += delta_size;

	if (delta_size < 0)
		msgb_trim(msg, msg->len + delta_size);

	return 0;
}

/* TODO: Move these conversion functions to a utils file. */
/* TODO: consolidate with gprs_apn2str(). */
/** memmove apn_enc to out_str, replacing the length octets in apn_enc with '.'
 * (omitting the first one) and terminating with a '\0'.
 * out_str needs to have rest_chars amount of bytes or 1 whatever is bigger.
 */
char * gprs_apn_to_str(char *out_str, const uint8_t *apn_enc, size_t rest_chars)
{
	char *str = out_str;

	while (rest_chars > 0 && apn_enc[0]) {
		size_t label_size = apn_enc[0];
		if (label_size + 1 > rest_chars)
			return NULL;

		memmove(str, apn_enc + 1, label_size);
		str += label_size;
		rest_chars -= label_size + 1;
		apn_enc += label_size + 1;

		if (rest_chars)
			*(str++) = '.';
	}
	str[0] = '\0';

	return out_str;
}

int gprs_str_to_apn(uint8_t *apn_enc, size_t max_len, const char *str)
{
	uint8_t *last_len_field;
	int len;

	/* Can we even write the length field to the output? */
	if (max_len == 0)
		return -1;

	/* Remember where we need to put the length once we know it */
	last_len_field = apn_enc;
	len = 1;
	apn_enc += 1;

	while (str[0]) {
		if (len >= max_len)
			return -1;

		if (str[0] == '.') {
			*last_len_field = (apn_enc - last_len_field) - 1;
			last_len_field = apn_enc;
		} else {
			*apn_enc = str[0];
		}
		apn_enc += 1;
		str += 1;
		len += 1;
	}

	*last_len_field = (apn_enc - last_len_field) - 1;

	return len;
}

/* GSM 04.08, 10.5.7.3 GPRS Timer */
int gprs_tmr_to_secs(uint8_t tmr)
{
	switch (tmr & GPRS_TMR_UNIT_MASK) {
	case GPRS_TMR_2SECONDS:
		return 2 * (tmr & GPRS_TMR_FACT_MASK);
	default:
	case GPRS_TMR_MINUTE:
		return 60 * (tmr & GPRS_TMR_FACT_MASK);
	case GPRS_TMR_6MINUTE:
		return 360 * (tmr & GPRS_TMR_FACT_MASK);
	case GPRS_TMR_DEACTIVATED:
		return -1;
	}
}

/* This functions returns a tmr value such that
 *   - f is monotonic
 *   - f(s) <= s
 *   - f(s) == s if a tmr exists with s = gprs_tmr_to_secs(tmr)
 *   - the best possible resolution is used
 * where
 *   f(s) = gprs_tmr_to_secs(gprs_secs_to_tmr_floor(s))
 */
uint8_t gprs_secs_to_tmr_floor(int secs)
{
	if (secs < 0)
		return GPRS_TMR_DEACTIVATED;
	if (secs < 2 * 32)
		return GPRS_TMR_2SECONDS | (secs / 2);
	if (secs < 60 * 2)
		/* Ensure monotonicity */
		return GPRS_TMR_2SECONDS | GPRS_TMR_FACT_MASK;
	if (secs < 60 * 32)
		return GPRS_TMR_MINUTE | (secs / 60);
	if (secs < 360 * 6)
		/* Ensure monotonicity */
		return GPRS_TMR_MINUTE | GPRS_TMR_FACT_MASK;
	if (secs < 360 * 32)
		return GPRS_TMR_6MINUTE | (secs / 360);

	return GPRS_TMR_6MINUTE | GPRS_TMR_FACT_MASK;
}

/* GSM 04.08, 10.5.1.4 */
int gprs_is_mi_tmsi(const uint8_t *value, size_t value_len)
{
	if (value_len != GSM48_TMSI_LEN)
		return 0;

	if (!value || (value[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_TMSI)
		return 0;

	return 1;
}

/* GSM 04.08, 10.5.1.4 */
int gprs_is_mi_imsi(const uint8_t *value, size_t value_len)
{
	if (value_len == 0)
		return 0;

	if (!value || (value[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI)
		return 0;

	return 1;
}

int gprs_parse_mi_tmsi(const uint8_t *value, size_t value_len, uint32_t *tmsi)
{
	uint32_t tmsi_be;

	if (!gprs_is_mi_tmsi(value, value_len))
		return 0;

	memcpy(&tmsi_be, value + 1, sizeof(tmsi_be));

	*tmsi = ntohl(tmsi_be);
	return 1;
}

void gprs_parse_tmsi(const uint8_t *value, uint32_t *tmsi)
{
	uint32_t tmsi_be;

	memcpy(&tmsi_be, value, sizeof(tmsi_be));

	*tmsi = ntohl(tmsi_be);
}

int gprs_ra_id_equals(const struct gprs_ra_id *id1,
			const struct gprs_ra_id *id2)
{
	return (id1->mcc == id2->mcc && id1->mnc == id2->mnc &&
		id1->lac == id2->lac && id1->rac == id2->rac);
}
