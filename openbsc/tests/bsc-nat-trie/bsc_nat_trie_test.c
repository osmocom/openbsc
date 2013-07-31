/*
 * (C) 2013 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/nat_rewrite_trie.h>
#include <openbsc/debug.h>

#include <osmocom/core/application.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <string.h>

int main(int argc, char **argv)
{
	struct nat_rewrite *trie;

	osmo_init_logging(&log_info);

	printf("Testing the trie\n");

	trie = nat_rewrite_parse(NULL, "prefixes.csv");
	OSMO_ASSERT(trie);

	/* verify that it has been parsed */
	OSMO_ASSERT(trie->prefixes == 17);
	printf("Dumping the internal trie\n");
	nat_rewrite_dump(trie);

	/* now do the matching... */
	OSMO_ASSERT(!nat_rewrite_lookup(trie, ""));
	OSMO_ASSERT(!nat_rewrite_lookup(trie, "2"));

	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "1")->rewrite, "1") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "12")->rewrite, "2") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "123")->rewrite, "3") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "1234")->rewrite, "4") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "12345")->rewrite, "5") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "123456")->rewrite, "6") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "1234567")->rewrite, "7") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "12345678")->rewrite, "8") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "123456789")->rewrite, "9") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "1234567890")->rewrite, "10") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "13")->rewrite, "11") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "14")->rewrite, "12") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "15")->rewrite, "13") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "16")->rewrite, "14") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "823455")->rewrite, "15") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "82")->rewrite, "16") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "+49123445")->rewrite, "17") == 0);

	/* match a prefix */
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "121")->rewrite, "2") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "1292323")->rewrite, "2") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "12345678901")->rewrite, "10") == 0);
	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "160")->rewrite, "14") == 0);

	OSMO_ASSERT(strcmp(nat_rewrite_lookup(trie, "12345678901123452123123")->rewrite, "10") == 0);

	/* invalid input */
	OSMO_ASSERT(!nat_rewrite_lookup(trie, "12abc"));

	talloc_free(trie);

	trie = nat_rewrite_parse(NULL, "does_not_exist.csv");
	OSMO_ASSERT(!trie);

	printf("Done with the tests.\n");
	return 0;
}
