#ifndef _BSS_H_
#define _BSS_H_

#include <openbsc/gsm_data.h>

struct msgb;

/* start and stop network */
extern int bsc_network_alloc(mncc_recv_cb_t mncc_recv);
extern int bsc_network_configure(const char *cfg_file);
extern int bsc_shutdown_net(struct gsm_network *net);

/* register all supported BTS */
extern int bts_init(void);
extern int bts_model_bs11_init(void);
extern int bts_model_rbs2k_init(void);
extern int bts_model_nanobts_init(void);
extern int bts_model_nokia_site_init(void);
extern int bts_model_sysmobts_init(void);
#endif
