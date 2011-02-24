#ifndef OSMO_BSC_RF
#define OSMO_BSC_RF

#include <osmocore/write_queue.h>
#include <osmocore/timer.h>

struct gsm_network;

struct osmo_bsc_rf {
	/* the value of signal.h */
	int policy;
	struct bsc_fd listen;
	struct gsm_network *gsm_network;

	const char *last_state_command;

	/* verify that RF is up as it should be */
	struct timer_list rf_check;

	/* some handling for the automatic grace switch */
	struct timer_list grace_timeout;
};

struct osmo_bsc_rf_conn {
	struct write_queue queue;
	struct osmo_bsc_rf *rf;
};

struct osmo_bsc_rf *osmo_bsc_rf_create(const char *path, struct gsm_network *net);

#endif
