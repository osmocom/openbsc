/* MS authorization and subscriber data handling */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>

void sgsn_auth_init(struct sgsn_instance *sgi)
{
	INIT_LLIST_HEAD(&sgi->cfg.imsi_acl);
}

/* temporary IMSI ACL hack */
struct imsi_acl_entry *sgsn_acl_lookup(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;
	llist_for_each_entry(acl, &cfg->imsi_acl, list) {
		if (!strcmp(imsi, acl->imsi))
			return acl;
	}
	return NULL;
}

int sgsn_acl_add(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	if (sgsn_acl_lookup(imsi, cfg))
		return -EEXIST;

	acl = talloc_zero(NULL, struct imsi_acl_entry);
	if (!acl)
		return -ENOMEM;
	strncpy(acl->imsi, imsi, sizeof(acl->imsi));

	llist_add(&acl->list, &cfg->imsi_acl);

	return 0;
}

int sgsn_acl_del(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	acl = sgsn_acl_lookup(imsi, cfg);
	if (!acl)
		return -ENODEV;

	llist_del(&acl->list);
	talloc_free(acl);

	return 0;
}

