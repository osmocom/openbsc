/* 
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef OPENBSCDEFINES_H
#define OPENBSCDEFINES_H

#ifdef BUILDING_ON_WINDOWS
    #ifdef BUILDING_OPENBSC
        #define BSC_API __declspec(dllexport)
    #else
        #define BSC_API __declspec(dllimport)
    #endif
#else
    #define BSC_API __attribute__((visibility("default")))
#endif

#endif
