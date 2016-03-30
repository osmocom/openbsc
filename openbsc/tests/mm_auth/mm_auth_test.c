#include <stdbool.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/auth.h>

/* override, requires '-Wl,--wrap=db_get_authinfo_for_subscr' */
int __real_db_get_authinfo_for_subscr(struct gsm_auth_info *ainfo,
				      struct gsm_subscriber *subscr);

int test_get_authinfo_rc = 0;
struct gsm_auth_info test_auth_info = {0};
struct gsm_auth_info default_auth_info = {
	.auth_algo = AUTH_ALGO_COMP128v1,
	.a3a8_ki_len = 16,
	.a3a8_ki = { 0 }
};

int __wrap_db_get_authinfo_for_subscr(struct gsm_auth_info *ainfo,
				      struct gsm_subscriber *subscr)
{
	*ainfo = test_auth_info;
	printf("wrapped: db_get_authinfo_for_subscr(): rc = %d\n", test_get_authinfo_rc);
	return test_get_authinfo_rc;
}

/* override, requires '-Wl,--wrap=db_get_lastauthtuple_for_subscr' */
int __real_db_get_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
					   struct gsm_subscriber *subscr);

int test_get_lastauthtuple_rc = 0;
struct gsm_auth_tuple test_last_auth_tuple = { 0 };
struct gsm_auth_tuple default_auth_tuple = { 0 };

int __wrap_db_get_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
					   struct gsm_subscriber *subscr)
{
	*atuple = test_last_auth_tuple;
	printf("wrapped: db_get_lastauthtuple_for_subscr(): rc = %d\n", test_get_lastauthtuple_rc);
	return test_get_lastauthtuple_rc;
}

/* override, requires '-Wl,--wrap=db_sync_lastauthtuple_for_subscr' */
int __real_db_sync_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
					    struct gsm_subscriber *subscr);
int test_sync_lastauthtuple_rc = 0;
int __wrap_db_sync_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
					    struct gsm_subscriber *subscr)
{
	test_last_auth_tuple = *atuple;
	printf("wrapped: db_sync_lastauthtuple_for_subscr(): rc = %d\n", test_sync_lastauthtuple_rc);
	return test_sync_lastauthtuple_rc;
}

int auth_get_tuple_for_subscr_verbose(struct gsm_auth_tuple *atuple,
				      struct gsm_subscriber *subscr,
				      int key_seq)
{
	int auth_action;
	auth_action = auth_get_tuple_for_subscr(atuple, subscr, key_seq);
	printf("auth_get_tuple_for_subscr(key_seq=%d) --> auth_action == %s\n",
	       key_seq, auth_action_str(auth_action));
	return auth_action;
}

/* override libssl RAND_bytes() to get testable crypto results */
int RAND_bytes(uint8_t *rand, int len)
{
	memset(rand, 23, len);
	return 1;
}

static void test_error()
{
	int auth_action;

	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq = 0;

	printf("\n* test_error()\n");

	/* any error (except -ENOENT) */
	test_get_authinfo_rc = -EIO;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == -1);
}

static void test_auth_not_avail()
{
	int auth_action;

	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq = 0;

	printf("\n* test_auth_not_avail()\n");

	/* no entry */
	test_get_authinfo_rc = -ENOENT;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_NOT_AVAIL);
}

int main(void)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	test_error();
	test_auth_not_avail();
	return 0;
}
