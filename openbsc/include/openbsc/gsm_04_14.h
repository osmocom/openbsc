#pragma once

#include <osmocom/gsm/protocol/gsm_04_14.h>

int gsm0414_tx_close_tch_loop_cmd(struct gsm_subscriber_connection *conn,
				  enum gsm414_tch_loop_mode loop_mode);
int gsm0414_tx_open_loop_cmd(struct gsm_subscriber_connection *conn);
int gsm0414_tx_act_emmi_cmd(struct gsm_subscriber_connection *conn);
int gsm0414_tx_test_interface(struct gsm_subscriber_connection *conn,
			      uint8_t tested_devs);
int gsm0414_tx_reset_ms_pos_store(struct gsm_subscriber_connection *conn,
				  uint8_t technology);

int gsm0414_rcv_test(struct gsm_subscriber_connection *conn,
		     struct msgb *msg);
