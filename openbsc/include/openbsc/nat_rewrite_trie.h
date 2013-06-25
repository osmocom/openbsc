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
#ifndef NAT_REWRITE_FILE_H
#define NAT_REWRITE_FILE_H

#include <osmocom/core/linuxrbtree.h>

struct vty;

struct nat_rewrite_rule {
	/* For digits 0-9 and + */
	struct nat_rewrite_rule *rules[11];

	char empty;
	char prefix[14];
	char rewrite[6];
};

struct nat_rewrite {
	struct nat_rewrite_rule rule;
	size_t prefixes;
};


struct nat_rewrite *nat_rewrite_parse(void *ctx, const char *filename);
struct nat_rewrite_rule *nat_rewrite_lookup(struct nat_rewrite *, const char *prefix);
void nat_rewrite_dump(struct nat_rewrite *rewr);
void nat_rewrite_dump_vty(struct vty *vty, struct nat_rewrite *rewr);

#endif
