/* simple test for the debug interface */
/*
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/debug.h>


int main(int argc, char **argv)
{
	struct log_target *stderr_target;

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	log_parse_category_mask(stderr_target, "DRLL");
	DEBUGP(DCC, "You should not see this\n");

	log_parse_category_mask(stderr_target, "DRLL:DCC");
	DEBUGP(DRLL, "You should see this\n");
	DEBUGP(DCC, "You should see this\n");
	DEBUGP(DMM, "You should not see this\n");

	return 0;
}
