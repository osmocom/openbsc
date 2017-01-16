/* Authentication related functions */

/*
 * (C) 2010 by Sylvain Munaut <tnt@246tNt.com>
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

#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/auth.h>
#include <openbsc/gsm_data.h>

#include <osmocom/gsm/comp128.h>
#include <osmocom/core/utils.h>

#include <openssl/rand.h>

#include <stdlib.h>

const struct value_string auth_action_names[] = {
	OSMO_VALUE_STRING(AUTH_ERROR),
	OSMO_VALUE_STRING(AUTH_NOT_AVAIL),
	OSMO_VALUE_STRING(AUTH_DO_AUTH_THEN_CIPH),
	OSMO_VALUE_STRING(AUTH_DO_CIPH),
	OSMO_VALUE_STRING(AUTH_DO_AUTH),
	{ 0, NULL }
};

static int
_use_xor(struct gsm_auth_info *ainfo, struct gsm_auth_tuple *atuple)
{
	int i, l = ainfo->a3a8_ki_len;

	if ((l > A38_XOR_MAX_KEY_LEN) || (l < A38_XOR_MIN_KEY_LEN)) {
		LOGP(DMM, LOGL_ERROR, "Invalid XOR key (len=%d) %s\n",
			ainfo->a3a8_ki_len,
			osmo_hexdump(ainfo->a3a8_ki, ainfo->a3a8_ki_len));
		return -1;
	}

	for (i=0; i<4; i++)
		atuple->vec.sres[i] = atuple->vec.rand[i] ^ ainfo->a3a8_ki[i];
	for (i=4; i<12; i++)
		atuple->vec.kc[i-4] = atuple->vec.rand[i] ^ ainfo->a3a8_ki[i];

	return 0;
}

static int
_use_comp128_v1(struct gsm_auth_info *ainfo, struct gsm_auth_tuple *atuple)
{
	if (ainfo->a3a8_ki_len != A38_COMP128_KEY_LEN) {
		LOGP(DMM, LOGL_ERROR, "Invalid COMP128v1 key (len=%d) %s\n",
			ainfo->a3a8_ki_len,
			osmo_hexdump(ainfo->a3a8_ki, ainfo->a3a8_ki_len));
		return -1;
	}

	comp128(ainfo->a3a8_ki, atuple->vec.rand, atuple->vec.sres, atuple->vec.kc);

	return 0;
}

/* Return values 
 *  -1 -> Internal error
 *   0 -> Not available
 *   1 -> Tuple returned, need to do auth, then enable cipher
 *   2 -> Tuple returned, need to enable cipher
 */
int auth_get_tuple_for_subscr(struct gsm_auth_tuple *atuple,
                              struct gsm_subscriber *subscr, int key_seq)
{
	struct gsm_auth_info ainfo;
	int rc;

	/* Get subscriber info (if any) */
	rc = db_get_authinfo_for_subscr(&ainfo, subscr);
	if (rc < 0) {
		LOGP(DMM, LOGL_NOTICE,
		     "No retrievable Ki for subscriber %s, skipping auth\n",
		     subscr_name(subscr));
		return rc == -ENOENT ? AUTH_NOT_AVAIL : AUTH_ERROR;
	}

	/* If possible, re-use the last tuple and skip auth */
	rc = db_get_lastauthtuple_for_subscr(atuple, subscr);
	if ((rc == 0) &&
	    (key_seq != GSM_KEY_SEQ_INVAL) &&
	    (key_seq == atuple->key_seq) &&
	    (atuple->use_count < 3))
	{
		atuple->use_count++;
		db_sync_lastauthtuple_for_subscr(atuple, subscr);
		DEBUGP(DMM, "Auth tuple use < 3, just doing ciphering\n");
		return AUTH_DO_CIPH;
	}

	/* Generate a new one */
	if (rc != 0) {
		/* If db_get_lastauthtuple_for_subscr() returned nothing, make
		 * sure the atuple memory is initialized to zero and thus start
		 * off with key_seq = 0. */
		memset(atuple, 0, sizeof(*atuple));
	} else {
		/* If db_get_lastauthtuple_for_subscr() returned a previous
		 * tuple, use the next key_seq. */
		atuple->key_seq = (atuple->key_seq + 1) % 7;
	}
	atuple->use_count = 1;

	if (RAND_bytes(atuple->vec.rand, sizeof(atuple->vec.rand)) != 1) {
		LOGP(DMM, LOGL_NOTICE, "RAND_bytes failed, can't generate new auth tuple\n");
		return AUTH_ERROR;
	}

	switch (ainfo.auth_algo) {
	case AUTH_ALGO_NONE:
		DEBUGP(DMM, "No authentication for subscriber\n");
		return AUTH_NOT_AVAIL;

	case AUTH_ALGO_XOR:
		if (_use_xor(&ainfo, atuple))
			return AUTH_NOT_AVAIL;
		break;

	case AUTH_ALGO_COMP128v1:
		if (_use_comp128_v1(&ainfo, atuple))
			return AUTH_NOT_AVAIL;
		break;

	default:
		DEBUGP(DMM, "Unsupported auth type algo_id=%d\n",
			ainfo.auth_algo);
		return AUTH_NOT_AVAIL;
	}

        db_sync_lastauthtuple_for_subscr(atuple, subscr);

	DEBUGP(DMM, "Need to do authentication and ciphering\n");
	return AUTH_DO_AUTH_THEN_CIPH;
}

