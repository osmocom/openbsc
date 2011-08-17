#ifndef _SYSTEM_INFO_H
#define _SYSTEM_INFO_H

#include <osmocom/gsm/sysinfo.h>

struct gsm_bts;

int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type type);

#endif
