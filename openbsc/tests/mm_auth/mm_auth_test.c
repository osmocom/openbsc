#include <stdbool.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/auth.h>

#define min(A,B) ((A)>(B)? (B) : (A))

#if 0
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
#endif

int test_get_authinfo_rc = 0;
struct gsm_auth_info test_auth_info = {0};
struct gsm_auth_info default_auth_info = {
	.auth_algo = AUTH_ALGO_COMP128v1,
	.a3a8_ki_len = 16,
	.a3a8_ki = { 0 }
};


int main(void)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	printf("Nothing being tested!\n");

	/* TODO auth_get_tuple_for_subscr() no longer exists ... test auth somehow?? */
	return 0;
}
