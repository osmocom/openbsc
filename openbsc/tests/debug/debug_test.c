/* simple test for the debug interface */
/*
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/debug.h>


int main(int argc, char** argv)
{
	struct debug_target *stderr_target;

	debug_init();
	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);
	debug_set_all_filter(stderr_target, 1);

	debug_parse_category_mask(stderr_target, "DRLL");
	DEBUGP(DCC, "You should not see this\n");

	debug_parse_category_mask(stderr_target, "DRLL:DCC");
	DEBUGP(DRLL, "You should see this\n");
	DEBUGP(DCC, "You should see this\n");
	DEBUGP(DMM, "You should not see this\n");
}
