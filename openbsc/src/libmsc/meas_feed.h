#ifndef _INT_MEAS_FEED_H
#define _INT_MEAS_FEED_H

#include <stdint.h>

int meas_feed_cfg_set(const char *dst_host, uint16_t dst_port);
void meas_feed_cfg_get(char **host, uint16_t *port);

void meas_feed_scenario_set(const char *name);
const char *meas_feed_scenario_get(void);

#endif  /* _INT_MEAS_FEED_H */
