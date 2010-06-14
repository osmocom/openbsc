#ifndef _AUTH_H
#define _AUTH_H

struct gsm_auth_tuple;
struct gsm_subscriber;

int auth_get_tuple_for_subscr(struct gsm_auth_tuple *atuple,
                              struct gsm_subscriber *subscr, int key_seq);

#endif /* _AUTH_H */
