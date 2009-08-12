/* SMS based token authentication for ad-hoc GSM networks */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/signal.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_subscriber.h>

#define TOKEN_SMS_TEXT "HAR 2009 GSM.  Please visit http://127.0.0.1/ to register"

static int token_subscr_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr = signal_data;
	struct gsm_sms *sms;

	if (subscr->net->auth_policy != GSM_AUTH_POLICY_TOKEN)
		return 0;

	switch (signal) {
	case S_SUBSCR_FIRST_CONTACT:
		/* we've seen this subscriber for the first time. */
		sms = sms_from_text(subscr, TOKEN_SMS_TEXT);
		if (!sms)
			return -ENOMEM;
		gsm411_send_sms_subscr(subscr, sms);
		break;
	}

	return 0;
}

static int token_sms_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_sms *sms = signal_data;
	struct gsm_lchan *lchan;
	u_int16_t rand[16];

	if (signal != S_SMS_DELIVERED)
		return 0;

	/* these are not the droids we've been looking for */
	if (!sms->receiver ||
	    !(sms->receiver->flags & GSM_SUBSCRIBER_FIRST_CONTACT))
		return 0;

	if (sms->receiver->net->auth_policy != GSM_AUTH_POLICY_TOKEN)
		return 0;

	lchan = lchan_for_subscr(sms->receiver);
	if (lchan) {
		/* kick the subscriber off the network */
		gsm48_tx_mm_auth_req(lchan, rand);
		gsm48_tx_mm_auth_rej(lchan);
		/* close the channel */
		//gsm48_send_rr_Release(lchan);
		lchan_free(lchan);
	}

	/* make sure we don't allow him in again unless he clicks the web UI */
	sms->receiver->authorized = 0;
	db_sync_subscriber(sms->receiver);

	return 0;
}

static __attribute__((constructor)) void on_dso_load_token(void)
{
	register_signal_handler(SS_SUBSCR, token_subscr_cb, NULL);
	register_signal_handler(SS_SMS, token_sms_cb, NULL);
}
