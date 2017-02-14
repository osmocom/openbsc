/* Test Osmocom SMS queue */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <osmocom/core/application.h>

#include <openbsc/debug.h>
#include <openbsc/vlr.h>

static void *talloc_ctx = NULL;

struct gsm_sms *smsq_take_next_sms(struct gsm_network *net,
				   char *last_msisdn,
				   size_t last_msisdn_buflen);

static void _test_take_next_sms_print(int i,
				      struct gsm_sms *sms,
				      const char *last_msisdn)
{
	printf("#%d: ", i);
	if (sms)
		printf("sending SMS to %s", sms->text);
	else
		printf("no SMS to send");
	printf(" (last_msisdn='%s')\n", last_msisdn? last_msisdn : "NULL");
}

static struct gsm_sms fake_sms = { 0 };

struct {
	const char *msisdn;
	int nr_of_sms;
	int failed_attempts;
	bool vsub_attached;
} fake_sms_db[] = {
	{
		.msisdn = "1111",
		.nr_of_sms = 0,
		.vsub_attached = true,
	},
	{
		.msisdn = "2222",
		.nr_of_sms = 2,
		.failed_attempts = 2,
		.vsub_attached = true,
	},
	{
		.msisdn = "3333",
		.nr_of_sms = 2,
		.failed_attempts = 3,
		.vsub_attached = true,
	},
	{
		.msisdn = "4444",
		.nr_of_sms = 0,
		.vsub_attached = true,
	},
	{
		.msisdn = "5555",
		.nr_of_sms = 2,
		.failed_attempts = 5,
		.vsub_attached = false,
	},
};

/* override, requires '-Wl,--wrap=db_sms_get_next_unsent_rr_msisdn' */
struct gsm_sms *__real_db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
							const char *last_msisdn,
							unsigned int max_failed);
struct gsm_sms *__wrap_db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
							const char *last_msisdn,
							unsigned int max_failed)
{
	static struct vlr_subscr arbitrary_vsub = { .lu_complete = true };
	int i;
	printf("     hitting database: looking for MSISDN > '%s', failed_attempts <= %d\n",
	       last_msisdn, max_failed);

	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		if (!fake_sms_db[i].nr_of_sms)
			continue;
		if (strcmp(fake_sms_db[i].msisdn, last_msisdn) <= 0)
			continue;
		if (fake_sms_db[i].failed_attempts > max_failed)
			continue;
		osmo_strlcpy(fake_sms.dst.addr, fake_sms_db[i].msisdn,
			     sizeof(fake_sms.dst.addr));
		fake_sms.receiver = fake_sms_db[i].vsub_attached? &arbitrary_vsub : NULL;
		osmo_strlcpy(fake_sms.text, fake_sms_db[i].msisdn, sizeof(fake_sms.text));
		if (fake_sms_db[i].vsub_attached)
			fake_sms_db[i].nr_of_sms --;
		return &fake_sms;
	}
	return NULL;
}

void show_fake_sms_db()
{
	int i;
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		printf("  %s%s has %u SMS pending, %u failed attempts\n",
		       fake_sms_db[i].msisdn,
		       fake_sms_db[i].vsub_attached ? "" : " (NOT attached)",
		       fake_sms_db[i].nr_of_sms,
		       fake_sms_db[i].failed_attempts);
	}
	printf("-->\n");
}

static void test_next_sms()
{
	int i;
	char last_msisdn[GSM_EXTENSION_LENGTH+1] = "";

	printf("Testing smsq_take_next_sms()\n");

	printf("\n- vsub 2, 3 and 5 each have 2 SMS pending, but 5 is not attached\n");
	last_msisdn[0] = '\0';
	show_fake_sms_db();
	for (i = 0; i < 7; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(i >= 4 || sms);
	}

	printf("\n- SMS are pending at various nr failed attempts (cutoff at >= 10)\n");
	last_msisdn[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = true;
		fake_sms_db[i].nr_of_sms = 1 + i;
		fake_sms_db[i].failed_attempts = i*5;

	}
	show_fake_sms_db();
	for (i = 0; i < 7; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(i >= 2 || sms);
	}

	printf("\n- iterate the SMS DB at most once\n");
	osmo_strlcpy(last_msisdn, "2345", sizeof(last_msisdn));
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = false;
		fake_sms_db[i].nr_of_sms = 1;
		fake_sms_db[i].failed_attempts = 0;
	}
	show_fake_sms_db();
	for (i = 0; i < 3; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(!sms);
	}

	printf("\n- there are no SMS in the DB\n");
	last_msisdn[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(fake_sms_db); i++) {
		fake_sms_db[i].vsub_attached = true;
		fake_sms_db[i].nr_of_sms = 0;
		fake_sms_db[i].failed_attempts = 0;
	}
	show_fake_sms_db();
	for (i = 0; i < 3; i++) {
		struct gsm_sms *sms = smsq_take_next_sms(NULL, last_msisdn, sizeof(last_msisdn));
		_test_take_next_sms_print(i, sms, last_msisdn);
		OSMO_ASSERT(!sms);
	}
}


static struct log_info_cat sms_queue_test_categories[] = {
};

static struct log_info info = {
	.cat = sms_queue_test_categories,
	.num_cat = ARRAY_SIZE(sms_queue_test_categories),
};

int main(int argc, char **argv)
{
	talloc_ctx = talloc_named_const(NULL, 1, "sms_queue_test");
	msgb_talloc_ctx_init(talloc_ctx, 0);
	osmo_init_logging(&info);

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_parse_category_mask(osmo_stderr_target, "DLOAP,1");

	test_next_sms();
	printf("Done\n");

	return 0;
}
