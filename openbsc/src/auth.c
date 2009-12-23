/* Authentication related functions */

/*
 * (C) 2010 by Sylvain Munaut <tnt@246tNt.com>
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

#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>

#include <osmocore/comp128.h>

#include <stdlib.h>


static int
_use_comp128_v1(struct gsm_auth_info *ainfo, struct gsm_auth_tuple *atuple)
{
	if (ainfo->a3a8_ki_len != A38_COMP128_KEY_LEN) {
		DEBUGP(DMM, "Invalid COMP128v1 key (len=%d) %s",
			ainfo->a3a8_ki_len,
			hexdump(ainfo->a3a8_ki, ainfo->a3a8_ki_len));
		return -1;
	}

	comp128(ainfo->a3a8_ki, atuple->rand, atuple->sres, atuple->kc);

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
	int i, rc;

	/* Get subscriber info (if any) */
	rc = db_get_authinfo_for_subscr(&ainfo, subscr);
	if (rc < 0) {
		DEBUGP(DMM, "No retrievable Ki for subscriber, skipping auth");
		return rc == -ENOENT ? 0 : -1;
	}

	/* If possible, re-use the last tuple and skip auth */
	rc = db_get_lastauthtuple_for_subscr(atuple, subscr);
	if ((rc == 0) &&
	    (atuple->key_seq != GSM_KEY_SEQ_INVAL) &&
	    (atuple->use_count < 3))
	{
		atuple->use_count++;
		db_sync_lastauthtuple_for_subscr(atuple, subscr);
		return 2;
	}

	/* Generate a new one */
	atuple->use_count = 1;
	atuple->key_seq = (atuple->key_seq + 1) % 7;
        for (i=0; i<sizeof(atuple->rand); i++)
                atuple->rand[i] = random() & 0xff;

	switch (ainfo.auth_algo) {
		case AUTH_ALGO_NONE:
			return 0;

		case AUTH_ALGO_COMP128v1:
			if (_use_comp128_v1(&ainfo, atuple))
				return 0;
			break;

		default:
			DEBUGP(DMM, "Unsupported auth type algo_id=%d\n",
				ainfo.auth_algo);
			return 0;
	}

        db_sync_lastauthtuple_for_subscr(atuple, subscr);

	return 1;
}

