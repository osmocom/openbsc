#ifndef _AUTH_H
#define _AUTH_H

struct gsm_auth_tuple;
struct gsm_subscriber;

enum auth_action {
	AUTH_NOT_AVAIL		= 0,	/* No auth tuple available */
	AUTH_DO_AUTH_THAN_CIPH	= 1,	/* Firsth authenticate, then cipher */
	AUTH_DO_CIPH		= 2,	/* Only ciphering */
	AUTH_DO_AUTH		= 3,	/* Only authentication, no ciphering */
};

int auth_get_tuple_for_subscr(struct gsm_auth_tuple *atuple,
                              struct gsm_subscriber *subscr, int key_seq);

#endif /* _AUTH_H */
