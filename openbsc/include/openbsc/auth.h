#ifndef _AUTH_H
#define _AUTH_H

#include <osmocom/core/utils.h>

struct gsm_auth_tuple;
struct gsm_subscriber;

enum auth_action {
	AUTH_ERROR		= -1,	/* Internal error */
	AUTH_NOT_AVAIL		= 0,	/* No auth tuple available */
	AUTH_DO_AUTH_THEN_CIPH	= 1,	/* Firsth authenticate, then cipher */
	AUTH_DO_CIPH		= 2,	/* Only ciphering */
	AUTH_DO_AUTH		= 3,	/* Only authentication, no ciphering */
};

extern const struct value_string auth_action_names[];
static inline const char *auth_action_str(enum auth_action a)
{
	return get_value_string(auth_action_names, a);
}

int auth_get_tuple_for_subscr(struct gsm_auth_tuple *atuple,
                              struct gsm_subscriber *subscr, int key_seq);

#endif /* _AUTH_H */
