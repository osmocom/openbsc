#include <stdbool.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/auth.h>

#define min(A,B) ((A)>(B)? (B) : (A))

static char *auth_tuple_str(struct gsm_auth_tuple *atuple)
{
	static char buf[256];
	char *pos = buf;
	int len = sizeof(buf);
	int l;

#define print2buf(FMT, args...) do {\
		l = snprintf(pos, len, FMT, ## args); \
		pos += l;\
		len -= l;\
	} while (0)

	print2buf("gsm_auth_tuple {\n");
	print2buf("  .use_count = %d\n", atuple->use_count);
	print2buf("  .key_seq = %d\n", atuple->key_seq);
	print2buf("  .rand = %s\n", osmo_hexdump(atuple->vec.rand, sizeof(atuple->vec.rand)));
	print2buf("  .sres = %s\n", osmo_hexdump(atuple->vec.sres, sizeof(atuple->vec.sres)));
	print2buf("  .kc = %s\n", osmo_hexdump(atuple->vec.kc, sizeof(atuple->vec.kc)));
	print2buf("}\n");
#undef print2buf

	return buf;
}

static bool auth_tuple_is(struct gsm_auth_tuple *atuple,
			  const char *expect_str)
{
	int l, l1, l2;
	int i;
	char *tuple_str = auth_tuple_str(atuple);
	bool same = (strcmp(expect_str, tuple_str) == 0);
	if (!same) {
		l1 = strlen(expect_str);
		l2 = strlen(tuple_str);
		printf("Expected %d:\n%s\nGot %d:\n%s\n",
		       l1, expect_str, l2, tuple_str);
		l = min(l1, l2);
		for (i = 0; i < l; i++) {
			if (expect_str[i] != tuple_str[i]) {
				printf("Difference at pos %d"
				       " (%c 0x%0x != %c 0x%0x)\n",
				       i, expect_str[i], expect_str[i],
				       tuple_str[i], tuple_str[i]);
				break;
			}
		}
	}
	return same;
}

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
	OSMO_ASSERT(auth_action == AUTH_ERROR);
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

static void test_auth_then_ciph1()
{
	int auth_action;

	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq;

	printf("\n* test_auth_then_ciph1()\n");

	/* Ki entry, but no auth tuple negotiated yet */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = -ENOENT;
	key_seq = 0;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_AUTH_THEN_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 1\n"
		"  .key_seq = 0\n"
		"  .rand = 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 \n"
		"  .sres = a1 ab c6 90 \n"
		"  .kc = 0f 27 ed f3 ac 97 ac 00 \n"
		"}\n"
		));

	/* With a different last saved key_seq stored in the out-arg of
	 * db_get_lastauthtuple_for_subscr() by coincidence, expect absolutely
	 * the same as above. */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_last_auth_tuple.key_seq = 3;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = -ENOENT;
	key_seq = 0;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_AUTH_THEN_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 1\n"
		"  .key_seq = 0\n"
		"  .rand = 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 \n"
		"  .sres = a1 ab c6 90 \n"
		"  .kc = 0f 27 ed f3 ac 97 ac 00 \n"
		"}\n"
		));
}

static void test_auth_then_ciph2()
{
	int auth_action;

	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq;

	printf("\n* test_auth_then_ciph2()\n");

	/* Ki entry, auth tuple negotiated, but invalid incoming key_seq */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_last_auth_tuple.key_seq = 2;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = 0;
	key_seq = GSM_KEY_SEQ_INVAL;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_AUTH_THEN_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 1\n"
		"  .key_seq = 3\n"
		"  .rand = 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 \n"
		"  .sres = a1 ab c6 90 \n"
		"  .kc = 0f 27 ed f3 ac 97 ac 00 \n"
		"}\n"
		));

	/* Change the last saved key_seq, expect last_auth_tuple.key_seq + 1 */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_last_auth_tuple.key_seq = 3;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = 0;
	key_seq = GSM_KEY_SEQ_INVAL;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_AUTH_THEN_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 1\n"
		"  .key_seq = 4\n"
		"  .rand = 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 \n"
		"  .sres = a1 ab c6 90 \n"
		"  .kc = 0f 27 ed f3 ac 97 ac 00 \n"
		"}\n"
		));
}

static void test_auth_reuse()
{
	int auth_action;
	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq;

	printf("\n* test_auth_reuse()\n");

	/* Ki entry, auth tuple negotiated, valid+matching incoming key_seq */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_last_auth_tuple.key_seq = key_seq = 3;
	test_last_auth_tuple.use_count = 1;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = 0;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 2\n"
		"  .key_seq = 3\n"
		"  .rand = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \n"
		"  .sres = 00 00 00 00 \n"
		"  .kc = 00 00 00 00 00 00 00 00 \n"
		"}\n"
		));
}

static void test_auth_reuse_key_seq_mismatch()
{
	int auth_action;
	struct gsm_auth_tuple atuple = {0};
	struct gsm_subscriber subscr = {0};
	int key_seq;

	printf("\n* test_auth_reuse_key_seq_mismatch()\n");

	/* Ki entry, auth tuple negotiated, valid+matching incoming key_seq */
	test_auth_info = default_auth_info;
	test_last_auth_tuple = default_auth_tuple;
	test_last_auth_tuple.key_seq = 3;
	key_seq = 4;
	test_last_auth_tuple.use_count = 1;
	test_get_authinfo_rc = 0;
	test_get_lastauthtuple_rc = 0;
	auth_action = auth_get_tuple_for_subscr_verbose(&atuple, &subscr,
							key_seq);
	OSMO_ASSERT(auth_action == AUTH_DO_AUTH_THEN_CIPH);
	OSMO_ASSERT(auth_tuple_is(&atuple,
		"gsm_auth_tuple {\n"
		"  .use_count = 1\n"
		"  .key_seq = 4\n"
		"  .rand = 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 17 \n"
		"  .sres = a1 ab c6 90 \n"
		"  .kc = 0f 27 ed f3 ac 97 ac 00 \n"
		"}\n"
		));
}

int main(void)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	test_error();
	test_auth_not_avail();
	test_auth_then_ciph1();
	test_auth_then_ciph2();
	test_auth_reuse();
	test_auth_reuse_key_seq_mismatch();
	return 0;
}
