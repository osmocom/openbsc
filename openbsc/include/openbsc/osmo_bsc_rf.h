#ifndef OSMO_BSC_RF
#define OSMO_BSC_RF

#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>

struct gsm_network;

struct osmo_bsc_rf {
	/* the value of signal.h */
	int policy;
	struct bsc_fd listen;
	struct gsm_network *gsm_network;

	const char *last_state_command;

	/* delay the command */
	char last_request;
	struct osmo_timer_list delay_cmd;

	/* verify that RF is up as it should be */
	struct osmo_timer_list rf_check;

	/* some handling for the automatic grace switch */
	struct osmo_timer_list grace_timeout;
};

struct osmo_bsc_rf_conn {
	struct write_queue queue;
	struct osmo_bsc_rf *rf;
};

struct osmo_bsc_rf *osmo_bsc_rf_create(const char *path, struct gsm_network *net);

#endif
