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
#include <openbsc/gprs_gmm.h>

#include <openbsc/debug.h>

const struct value_string auth_state_names[] = {
	{ SGSN_AUTH_ACCEPTED,	"accepted"},
	{ SGSN_AUTH_REJECTED,	"rejected"},
	{ SGSN_AUTH_UNKNOWN,	"unknown"},
	{ 0, NULL }
};

const struct value_string *sgsn_auth_state_names = auth_state_names;

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

enum sgsn_auth_state sgsn_auth_state(struct sgsn_mm_ctx *mmctx,
				     struct sgsn_config *cfg)
{
	char mccmnc[16];
	int check_net = 0;
	int check_acl = 0;

	OSMO_ASSERT(mmctx);

	switch (sgsn->cfg.auth_policy) {
	case SGSN_AUTH_POLICY_OPEN:
		return SGSN_AUTH_ACCEPTED;

	case SGSN_AUTH_POLICY_CLOSED:
		check_net = 1;
		check_acl = 1;
		break;

	case SGSN_AUTH_POLICY_ACL_ONLY:
		check_acl = 1;
		break;
	}

	if (!strlen(mmctx->imsi)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "Missing IMSI, authorization state not known\n");
		return SGSN_AUTH_UNKNOWN;
	}

	if (check_net) {
		/* We simply assume that the IMSI exists, as long as it is part
		 * of 'our' network */
		snprintf(mccmnc, sizeof(mccmnc), "%03d%02d",
			 mmctx->ra.mcc, mmctx->ra.mnc);
		if (strncmp(mccmnc, mmctx->imsi, 5) == 0)
			return SGSN_AUTH_ACCEPTED;
	}

	if (check_acl && sgsn_acl_lookup(mmctx->imsi, &sgsn->cfg))
		return SGSN_AUTH_ACCEPTED;

	return SGSN_AUTH_REJECTED;
}

int sgsn_auth_request(struct sgsn_mm_ctx *mmctx, struct sgsn_config *cfg)
{
	/* TODO: Add remote subscriber update requests here */

	sgsn_auth_update(mmctx, sgsn);

	return 0;
}

void sgsn_auth_update(struct sgsn_mm_ctx *mmctx, struct sgsn_instance *sgi)
{
	enum sgsn_auth_state auth_state;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Updating authorization\n");

	auth_state = sgsn_auth_state(mmctx, &sgi->cfg);
	if (auth_state == SGSN_AUTH_UNKNOWN) {
		/* Reject requests since remote updates are NYI */
		LOGMMCTXP(LOGL_ERROR, mmctx,
			  "Missing information, authorization not possible\n");
		auth_state = SGSN_AUTH_REJECTED;
	}

	if (mmctx->auth_state == auth_state)
		return;

	LOGMMCTXP(LOGL_INFO, mmctx, "Got authorization update: state %s -> %s\n",
		  get_value_string(sgsn_auth_state_names, mmctx->auth_state),
		  get_value_string(sgsn_auth_state_names, auth_state));

	mmctx->auth_state = auth_state;

	switch (auth_state) {
	case SGSN_AUTH_ACCEPTED:
		gsm0408_gprs_access_granted(mmctx);
		break;
	case SGSN_AUTH_REJECTED:
		gsm0408_gprs_access_denied(mmctx);
		break;
	default:
		break;
	}
}
