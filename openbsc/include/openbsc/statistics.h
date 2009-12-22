#ifndef _STATISTICS_H
#define _STATISTICS_H

struct counter {
	struct llist_head list;
	const char *name;
	const char *description;
	unsigned long value;
};

static inline void counter_inc(struct counter *ctr)
{
	ctr->value++;
}

static inline unsigned long counter_get(struct counter *ctr)
{
	return ctr->value;
}

static inline void counter_reset(struct counter *ctr)
{
	ctr->value = 0;
}

struct counter *counter_alloc(const char *name);
void counter_free(struct counter *ctr);
int counters_store_db(void);

#endif /* _STATISTICS_H */
