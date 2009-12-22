/*
 * ubx-parse.h
 *
 * Header for parsing code converting UBX messages to GPS assist data
 *
 *
 * Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __UBX_PARSE_H__
#define __UBX_PARSE_H__


#include "gps.h"
#include "ubx.h"


#ifdef __cplusplus
extern "C" {
#endif


/* Dispatch table */
extern struct ubx_dispatch_entry ubx_parse_dt[];


#ifdef __cplusplus
}
#endif

#endif /* __UBX_PARSE_H__ */

