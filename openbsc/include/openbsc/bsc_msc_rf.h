#ifndef BSC_MSC_RF
#define BSC_MSC_RF

#include <osmocore/write_queue.h>

struct gsm_network;

struct bsc_msc_rf {
	/* the value of signal.h */
	int policy;
	struct bsc_fd listen;
	struct gsm_network *gsm_network;
};

struct bsc_msc_rf_conn {
	struct write_queue queue;
	struct bsc_msc_rf *rf;
};

struct bsc_msc_rf *bsc_msc_rf_create(const char *path, struct gsm_network *net);

#endif
