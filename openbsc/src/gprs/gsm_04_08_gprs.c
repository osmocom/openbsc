/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010      by On-Waves
 * (C) 2014-2015 by Sysmocom s.f.m.c. GmbH
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

/* TODO: Move this to osmocom/gsm/protocol/gsm_04_08_gprs.h ? */

#include <openbsc/gsm_04_08_gprs.h>

#include <osmocom/core/utils.h>

const struct value_string gprs_service_t_strs_[] = {
	{ GPRS_SERVICE_T_SIGNALLING,	"signalling" },
	{ GPRS_SERVICE_T_DATA,		"data" },
	{ GPRS_SERVICE_T_PAGING_RESP,	"paging response" },
	{ GPRS_SERVICE_T_MBMS_MC_SERV,	"MBMS multicast service" },
	{ GPRS_SERVICE_T_MBMS_BC_SERV,	"MBMS broadcast service" },
	{ 0, NULL }
};

const struct value_string *gprs_service_t_strs = gprs_service_t_strs_;
