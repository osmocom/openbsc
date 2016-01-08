#pragma once

struct msgb;
struct gprs_ra_id;

typedef int (* iu_recv_cb_t )(struct msgb *msg, struct gprs_ra_id *ra_id,
			      uint16_t *sai);

int iu_tx(struct msgb *msg, uint8_t sapi);
