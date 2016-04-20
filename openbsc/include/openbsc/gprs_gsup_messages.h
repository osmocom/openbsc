/* GPRS Subscriber Update Protocol message encoder/decoder */

/* (C) 2014 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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

#include <stdint.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/gsm_data.h>
/* Needed for GSM_IMSI_LENGTH: */
#include <openbsc/gsm_subscriber.h>

#define GPRS_GSUP_MAX_NUM_PDP_INFO		10 /* GSM 09.02 limits this to 50 */
#define GPRS_GSUP_MAX_NUM_AUTH_INFO		5
#define GPRS_GSUP_MAX_MSISDN_LEN		9

#define GPRS_GSUP_PDP_TYPE_SIZE			2

enum gprs_gsup_iei {
	GPRS_GSUP_IMSI_IE			= 0x01,
	GPRS_GSUP_CAUSE_IE			= 0x02,
	GPRS_GSUP_AUTH_TUPLE_IE			= 0x03,
	GPRS_GSUP_PDP_INFO_COMPL_IE		= 0x04,
	GPRS_GSUP_PDP_INFO_IE			= 0x05,
	GPRS_GSUP_CANCEL_TYPE_IE		= 0x06,
	GPRS_GSUP_FREEZE_PTMSI_IE		= 0x07,
	GPRS_GSUP_MSISDN_IE			= 0x08,
	GPRS_GSUP_HLR_NUMBER_IE			= 0x09,
	GPRS_GSUP_PDP_CONTEXT_ID_IE		= 0x10,
	GPRS_GSUP_PDP_TYPE_IE			= 0x11,
	GPRS_GSUP_ACCESS_POINT_NAME_IE		= 0x12,
	GPRS_GSUP_PDP_QOS_IE			= 0x13,
	GPRS_GSUP_RAND_IE			= 0x20,
	GPRS_GSUP_SRES_IE			= 0x21,
	GPRS_GSUP_KC_IE				= 0x22
};

enum gprs_gsup_message_type {
	GPRS_GSUP_MSGT_UPDATE_LOCATION_REQUEST	= 0b00000100,
	GPRS_GSUP_MSGT_UPDATE_LOCATION_ERROR	= 0b00000101,
	GPRS_GSUP_MSGT_UPDATE_LOCATION_RESULT	= 0b00000110,

	GPRS_GSUP_MSGT_SEND_AUTH_INFO_REQUEST	= 0b00001000,
	GPRS_GSUP_MSGT_SEND_AUTH_INFO_ERROR	= 0b00001001,
	GPRS_GSUP_MSGT_SEND_AUTH_INFO_RESULT	= 0b00001010,

	GPRS_GSUP_MSGT_PURGE_MS_REQUEST		= 0b00001100,
	GPRS_GSUP_MSGT_PURGE_MS_ERROR		= 0b00001101,
	GPRS_GSUP_MSGT_PURGE_MS_RESULT		= 0b00001110,

	GPRS_GSUP_MSGT_INSERT_DATA_REQUEST	= 0b00010000,
	GPRS_GSUP_MSGT_INSERT_DATA_ERROR	= 0b00010001,
	GPRS_GSUP_MSGT_INSERT_DATA_RESULT	= 0b00010010,

	GPRS_GSUP_MSGT_DELETE_DATA_REQUEST	= 0b00010100,
	GPRS_GSUP_MSGT_DELETE_DATA_ERROR	= 0b00010101,
	GPRS_GSUP_MSGT_DELETE_DATA_RESULT	= 0b00010110,

	GPRS_GSUP_MSGT_LOCATION_CANCEL_REQUEST	= 0b00011100,
	GPRS_GSUP_MSGT_LOCATION_CANCEL_ERROR	= 0b00011101,
	GPRS_GSUP_MSGT_LOCATION_CANCEL_RESULT	= 0b00011110,
};

#define GPRS_GSUP_IS_MSGT_REQUEST(msgt) (((msgt) & 0b00000011) == 0b00)
#define GPRS_GSUP_IS_MSGT_ERROR(msgt)   (((msgt) & 0b00000011) == 0b01)
#define GPRS_GSUP_TO_MSGT_ERROR(msgt)   (((msgt) & 0b11111100) | 0b01)

enum gprs_gsup_cancel_type {
	GPRS_GSUP_CANCEL_TYPE_UPDATE		= 1, /* on wire: 0 */
	GPRS_GSUP_CANCEL_TYPE_WITHDRAW		= 2, /* on wire: 1 */
};

struct gprs_gsup_pdp_info {
	unsigned int			context_id;
	int				have_info;
	uint16_t			pdp_type;
	const uint8_t			*apn_enc;
	size_t				apn_enc_len;
	const uint8_t			*qos_enc;
	size_t				qos_enc_len;
};

struct gprs_gsup_message {
	enum gprs_gsup_message_type	message_type;
	char				imsi[GSM_IMSI_LENGTH];
	enum gsm48_gmm_cause		cause;
	enum gprs_gsup_cancel_type	cancel_type;
	int				pdp_info_compl;
	int				freeze_ptmsi;
	struct osmo_auth_vector		auth_vectors[GPRS_GSUP_MAX_NUM_AUTH_INFO];
	size_t				num_auth_vectors;
	struct gprs_gsup_pdp_info	pdp_infos[GPRS_GSUP_MAX_NUM_PDP_INFO];
	size_t				num_pdp_infos;
	const uint8_t			*msisdn_enc;
	size_t				msisdn_enc_len;
	const uint8_t			*hlr_enc;
	size_t				hlr_enc_len;
};

int gprs_gsup_decode(const uint8_t *data, size_t data_len,
		     struct gprs_gsup_message *gsup_msg);
void gprs_gsup_encode(struct msgb *msg, const struct gprs_gsup_message *gsup_msg);
