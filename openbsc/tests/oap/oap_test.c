/* Test Osmocom Authentication Protocol */
/*
 * (C) 2015 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/core/application.h>

#include <openbsc/debug.h>

#include <openbsc/oap.h>
#include <openbsc/oap_messages.h>

#include <stdio.h>
#include <string.h>

static void test_oap_api(void)
{
	printf("Testing OAP API\n  - Config parsing\n");

	struct oap_config _config;
	struct oap_config *config = &_config;

	struct oap_state _state;
	struct oap_state *state = &_state;

	memset(config, 0, sizeof(*config));
	memset(state, 0, sizeof(*state));

	OSMO_ASSERT(osmo_hexparse("0102030405060708090a0b0c0d0e0f10", config->secret_k, 16) == 16);
	OSMO_ASSERT(osmo_hexparse("1112131415161718191a1b1c1d1e1f20", config->secret_opc, 16) == 16);

	/* make sure filling with zeros means uninitialized */
	OSMO_ASSERT(state->state == OAP_UNINITIALIZED);

	/* invalid client_id and shared secret */
	config->client_id = 0;
	config->secret_k_present = 0;
	config->secret_opc_present = 0;
	OSMO_ASSERT( oap_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OAP_DISABLED);

	/* reset state */
	memset(state, 0, sizeof(*state));

	/* only client_id is invalid */
	config->client_id = 0;
	config->secret_k_present = 1;
	config->secret_opc_present = 1;
	OSMO_ASSERT( oap_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OAP_DISABLED);

	memset(state, 0, sizeof(*state));

	/* valid id, but omitted shared_secret (1/2) */
	config->client_id = 12345;
	config->secret_k_present = 0;
	config->secret_opc_present = 1;
	OSMO_ASSERT( oap_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OAP_DISABLED);

	memset(state, 0, sizeof(*state));

	/* valid id, but omitted shared_secret (2/2) */
	config->client_id = 12345;
	config->secret_k_present = 1;
	config->secret_opc_present = 0;
	OSMO_ASSERT( oap_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OAP_DISABLED);

	memset(state, 0, sizeof(*state));


	/* mint configuration */
	config->client_id = 12345;
	config->secret_k_present = 1;
	config->secret_opc_present = 1;
	/*config->secret_* buffers are still set from the top */
	OSMO_ASSERT( oap_init(config, state) == 0 );
	OSMO_ASSERT(state->state == OAP_INITIALIZED);

	printf("  - AUTN failures\n");

	struct osmo_oap_message oap_rx;
	struct osmo_oap_message oap_tx;
	struct msgb *msg_rx;
	struct msgb *msg_tx;

	memset(&oap_rx, 0, sizeof(oap_rx));

	/* Missing challenge data */
	oap_rx.message_type = OAP_MSGT_CHALLENGE_REQUEST;
	oap_rx.rand_present = 0;
	oap_rx.autn_present = 0;
	msg_rx = oap_encoded(&oap_rx);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	/* AUTN missing */
	osmo_hexparse("0102030405060708090a0b0c0d0e0f10",
		      oap_rx.rand, 16);
	oap_rx.rand_present = 1;
	msg_rx = oap_encoded(&oap_rx);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	/* RAND missing */
	oap_rx.rand_present = 0;
	osmo_hexparse("cec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	oap_rx.autn_present = 1;
	msg_rx = oap_encoded(&oap_rx);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	/* wrong autn (by one bit) */
	osmo_hexparse("0102030405060708090a0b0c0d0e0f10",
		      oap_rx.rand, 16);
	osmo_hexparse("dec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	oap_rx.rand_present = 1;
	oap_rx.autn_present = 1;
	msg_rx = oap_encoded(&oap_rx);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -2);
	msgb_free(msg_rx);
	OSMO_ASSERT(!msg_tx);

	/* all data correct */
	osmo_hexparse("cec4e3848a33000086781158ca40f136",
		      oap_rx.autn, 16);
	msg_rx = oap_encoded(&oap_rx);

	/* but refuse to evaluate in uninitialized state */
	OSMO_ASSERT(state->state == OAP_INITIALIZED);

	state->state = OAP_UNINITIALIZED;
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -1);
	OSMO_ASSERT(!msg_tx);

	state->state = OAP_DISABLED;
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -1);
	OSMO_ASSERT(!msg_tx);

	state->state = OAP_INITIALIZED;

	/* now everything is correct */
	printf("  - AUTN success\n");
	/* a successful return value here indicates correct autn */
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == 0);
	msgb_free(msg_rx);

	/* Expect the challenge response in msg_tx */
	OSMO_ASSERT(msg_tx);
	OSMO_ASSERT(osmo_oap_decode(&oap_tx, msg_tx->data, msg_tx->len) == 0);
	OSMO_ASSERT(oap_tx.message_type == OAP_MSGT_CHALLENGE_RESULT);
	OSMO_ASSERT(strcmp("e2d05b598c61d9ba",
			   osmo_hexdump_nospc(oap_tx.xres, sizeof(oap_tx.xres)))
		    == 0);
	OSMO_ASSERT(state->state == OAP_SENT_CHALLENGE_RESULT);
	msgb_free(msg_tx);
	msg_tx = 0;

	struct oap_state saved_state = _state;

	printf("  - Registration failure\n");

	memset(&oap_rx, 0, sizeof(oap_rx));
	oap_rx.message_type = OAP_MSGT_REGISTER_ERROR;
	oap_rx.cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
	msg_rx = oap_encoded(&oap_rx);

	/* Receive registration error for the first time. */
	OSMO_ASSERT(state->registration_failures == 0);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == 0);
	OSMO_ASSERT(state->registration_failures == 1);
	OSMO_ASSERT(msg_tx);
	OSMO_ASSERT(osmo_oap_decode(&oap_tx, msg_tx->data, msg_tx->len) == 0);
	OSMO_ASSERT(oap_tx.message_type == OAP_MSGT_REGISTER_REQUEST);
	OSMO_ASSERT(state->state == OAP_REQUESTED_CHALLENGE);
	msgb_free(msg_tx);
	msg_tx = 0;

	/* Receive registration error for the Nth time. */
	state->registration_failures = 999;
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == -11);
	OSMO_ASSERT(!msg_tx);
	OSMO_ASSERT(state->state == OAP_INITIALIZED);
	msgb_free(msg_tx);
	msg_tx = 0;

	msgb_free(msg_rx);

	printf("  - Registration success\n");

	_state = saved_state;
	memset(&oap_rx, 0, sizeof(oap_rx));
	oap_rx.message_type = OAP_MSGT_REGISTER_RESULT;
	msg_rx = oap_encoded(&oap_rx);
	OSMO_ASSERT(oap_handle(state, msg_rx, &msg_tx) == 0);
	OSMO_ASSERT(!msg_tx);
	OSMO_ASSERT(state->state == OAP_REGISTERED);
	msgb_free(msg_rx);
}

static struct log_info_cat gprs_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);

	test_oap_api();
	printf("Done\n");

	return 0;
}

