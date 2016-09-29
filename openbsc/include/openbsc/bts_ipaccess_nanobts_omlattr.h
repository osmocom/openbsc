/* OML attribute table generator for ipaccess nanobts */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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
 */

#pragma once

#include <stdint.h>
#include <osmocom/core/msgb.h>

struct msgb *nanobts_attr_bts_get(struct gsm_bts *bts);
struct msgb *nanobts_attr_nse_get(struct gsm_bts *bts);
struct msgb *nanobts_attr_cell_get(struct gsm_bts *bts);
struct msgb *nanobts_attr_nscv_get(struct gsm_bts *bts);
struct msgb *nanobts_attr_radio_get(struct gsm_bts *bts,
				    struct gsm_bts_trx *trx);
