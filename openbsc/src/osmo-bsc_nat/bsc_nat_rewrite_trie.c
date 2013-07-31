/* Handling for loading a re-write file/database */
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
#include <openbsc/vty.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define CHECK_IS_DIGIT_OR_FAIL(prefix, pos)						\
	if (!isdigit(prefix[pos]) && prefix[pos] != '+') {				\
			LOGP(DNAT, LOGL_ERROR,						\
				"Prefix(%s) contains non ascii text at(%d=%c)\n",	\
				prefix, pos, prefix[pos]);				\
			goto fail;							\
	}
#define TO_INT(c) \
	((c) == '+' ? 10 : ((c - '0') % 10))

static void insert_rewrite_node(struct nat_rewrite_rule *rule, struct nat_rewrite *root)
{
	struct nat_rewrite_rule *new = &root->rule;

	const size_t len = strlen(rule->prefix);
	int i;

	if (len == 0) {
		LOGP(DNAT, LOGL_ERROR, "An empty prefix does not make sense.\n");
		goto fail;
	}

	for (i = 0; i < len - 1; ++i) {
		int pos;

		/* check if the input is valid */
		CHECK_IS_DIGIT_OR_FAIL(rule->prefix, i);

		/* check if the next node is already valid */
		pos = TO_INT(rule->prefix[i]);
		if (!new->rules[pos]) {
			new->rules[pos] = talloc_zero(root, struct nat_rewrite_rule);
			if (!new->rules[pos]) {
				LOGP(DNAT, LOGL_ERROR,
					"Failed to allocate memory.\n");
				goto fail;
			}

			new->rules[pos]->empty = 1;
		}

		/* we continue here */
		new = new->rules[pos];
	}

	/* new now points to the place where we want to add it */
	int pos;

	/* check if the input is valid */
	CHECK_IS_DIGIT_OR_FAIL(rule->prefix, (len - 1));

	/* check if the next node is already valid */
	pos = TO_INT(rule->prefix[len - 1]);
	if (!new->rules[pos])
		new->rules[pos] = rule;
	else if (new->rules[pos]->empty) {
		/* copy over entries */
		new->rules[pos]->empty = 0;
		memcpy(new->rules[pos]->prefix, rule->prefix, sizeof(rule->prefix));
		memcpy(new->rules[pos]->rewrite, rule->rewrite, sizeof(rule->rewrite));
		talloc_free(rule);
	} else {
		LOGP(DNAT, LOGL_ERROR,
			"Prefix(%s) is already installed\n", rule->prefix);
		goto fail;
	}

	root->prefixes += 1;
	return;

fail:
	talloc_free(rule);
	return;
}

static void handle_line(struct nat_rewrite *rewrite, char *line)
{
	char *split;
	struct nat_rewrite_rule *rule;
	size_t size_prefix, size_end, len;


	/* Find the ',' in the line */
	len = strlen(line);
	split = strstr(line, ",");
	if (!split) {
		LOGP(DNAT, LOGL_ERROR, "Line doesn't contain ','\n");
		return;
	}

	/* Check if there is space for the rewrite rule */
	size_prefix = split - line;
	if (len - size_prefix <= 2) {
		LOGP(DNAT, LOGL_ERROR, "No rewrite available.\n");
		return;
	}

	/* Continue after the ',' to the end */
	split = &line[size_prefix + 1];
	size_end = strlen(split) - 1;

	/* Check if both strings can fit into the static array */
	if (size_prefix > sizeof(rule->prefix) - 1) {
		LOGP(DNAT, LOGL_ERROR,
			"Prefix is too long with %zu\n", size_prefix);
		return;
	}

	if (size_end > sizeof(rule->rewrite) - 1) {
		LOGP(DNAT, LOGL_ERROR,
			"Rewrite is too long with %zu on %s\n",
			size_end, &line[size_prefix + 1]);
		return;
	}

	/* Now create the entry and insert it into the trie */
	rule = talloc_zero(rewrite, struct nat_rewrite_rule);
	if (!rule) {
		LOGP(DNAT, LOGL_ERROR, "Can not allocate memory\n");
		return;
	}

	memcpy(rule->prefix, line, size_prefix);
	assert(size_prefix < sizeof(rule->prefix));
	rule->prefix[size_prefix] = '\0';

	memcpy(rule->rewrite, split, size_end);
	assert(size_end < sizeof(rule->rewrite));
	rule->rewrite[size_end] = '\0';

	/* now insert and balance the tree */
	insert_rewrite_node(rule, rewrite);
}

struct nat_rewrite *nat_rewrite_parse(void *ctx, const char *filename)
{
	FILE *file;
	char *line = NULL;
	size_t n = 2342;
	struct nat_rewrite *res;

	file = fopen(filename, "r");
	if (!file)
		return NULL;

	res = talloc_zero(ctx, struct nat_rewrite);
	if (!res) {
		fclose(file);
		return NULL;
	}

	/* mark the root as empty */
	res->rule.empty = 1;

	while (getline(&line, &n, file) != -1) {
		handle_line(res, line);
	}

	free(line);
	fclose(file);
	return res;
}

/**
 * Simple find that tries to do a longest match...
 */
struct nat_rewrite_rule *nat_rewrite_lookup(struct nat_rewrite *rewrite,
					const char *prefix)
{
	struct nat_rewrite_rule *rule = &rewrite->rule;
	struct nat_rewrite_rule *last = NULL;
	const int len = OSMO_MIN(strlen(prefix), (sizeof(rule->prefix) - 1));
	int i;

	for (i = 0; rule && i < len; ++i) {
		int pos;

		CHECK_IS_DIGIT_OR_FAIL(prefix, i);
		pos = TO_INT(prefix[i]);

		rule = rule->rules[pos];
		if (rule && !rule->empty)
			last = rule;
	}

	return last;

fail:
	return NULL;
}

static void nat_rewrite_dump_rec(struct nat_rewrite_rule *rule)
{
	int i;
	if (!rule->empty)
		printf("%s,%s\n", rule->prefix, rule->rewrite);

	for (i = 0; i < ARRAY_SIZE(rule->rules); ++i) {
		if (!rule->rules[i])
			continue;
		nat_rewrite_dump_rec(rule->rules[i]);
	}
}

void nat_rewrite_dump(struct nat_rewrite *rewrite)
{
	nat_rewrite_dump_rec(&rewrite->rule);
}

static void nat_rewrite_dump_rec_vty(struct vty *vty, struct nat_rewrite_rule *rule)
{
	int i;
	if (!rule->empty)
		vty_out(vty, "%s,%s%s", rule->prefix, rule->rewrite, VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(rule->rules); ++i) {
		if (!rule->rules[i])
			continue;
		nat_rewrite_dump_rec_vty(vty, rule->rules[i]);
	}
}

void nat_rewrite_dump_vty(struct vty *vty, struct nat_rewrite *rewrite)
{
	nat_rewrite_dump_rec_vty(vty, &rewrite->rule);
}
