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
