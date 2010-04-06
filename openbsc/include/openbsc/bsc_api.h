/* GSM 08.08 like API for OpenBSC */

#include "gsm_data.h"


int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg, int link_id);
