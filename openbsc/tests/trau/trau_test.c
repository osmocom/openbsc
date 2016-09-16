/* (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/abis/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <osmocom/core/msgb.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void test_trau_fr_efr(unsigned char *data)
{
	struct decoded_trau_frame tf;
	struct msgb *msg;
	struct gsm_data_frame *frame;

	printf("Testing TRAU FR transcoding.\n");
	data[0] = 0xd0;
	trau_encode_fr(&tf, data);
	tf.c_bits[11] = 0; /* clear BFI */
	msg = trau_decode_fr(1, &tf);
	OSMO_ASSERT(msg != NULL);
	frame = (struct gsm_data_frame *)msg->data;
	OSMO_ASSERT(frame->msg_type == GSM_TCHF_FRAME);
	OSMO_ASSERT(!memcmp(frame->data, data, 33));
	msgb_free(msg);

	printf("Testing TRAU EFR transcoding.\n");
	data[0] = 0xc0;
	trau_encode_efr(&tf, data);
	OSMO_ASSERT(tf.d_bits[0] == 1); /* spare bit must be 1 */
	tf.c_bits[11] = 0; /* clear BFI */
	msg = trau_decode_efr(1, &tf);
	OSMO_ASSERT(msg != NULL);
	frame = (struct gsm_data_frame *)msg->data;
	OSMO_ASSERT(frame->msg_type == GSM_TCHF_FRAME_EFR);
	OSMO_ASSERT(!memcmp(frame->data, data, 31));

	printf("Testing TRAU EFR decoding with CRC error.\n");
	tf.d_bits[0] = 0; /* spare bit must be included */
	msg = trau_decode_efr(1, &tf);
	OSMO_ASSERT(msg != NULL);
	frame = (struct gsm_data_frame *)msg->data;
	OSMO_ASSERT(frame->msg_type == GSM_BAD_FRAME);
	msgb_free(msg);
}

int main()
{
	unsigned char data[33];
	int i;

	msgb_talloc_ctx_init(NULL, 0);

	memset(data, 0x00, sizeof(data));
	test_trau_fr_efr(data);
	memset(data, 0xff, sizeof(data));
	test_trau_fr_efr(data);
	srandom(42);
	for (i = 0; i < sizeof(data); i++)
		data[i] = random();
	test_trau_fr_efr(data);
	printf("Done\n");
	return 0;
}

/* stubs */
void vty_out() {}
