#ifndef _SYSTEM_INFO_H
#define _SYSTEM_INFO_H

#include <osmocore/utils.h>

#define GSM_MACBLOCK_LEN 		23

enum osmo_sysinfo_type {
	SYSINFO_TYPE_NONE,
	SYSINFO_TYPE_1,
	SYSINFO_TYPE_2,
	SYSINFO_TYPE_3,
	SYSINFO_TYPE_4,
	SYSINFO_TYPE_5,
	SYSINFO_TYPE_6,
	SYSINFO_TYPE_7,
	SYSINFO_TYPE_8,
	SYSINFO_TYPE_9,
	SYSINFO_TYPE_10,
	SYSINFO_TYPE_13,
	SYSINFO_TYPE_16,
	SYSINFO_TYPE_17,
	SYSINFO_TYPE_18,
	SYSINFO_TYPE_19,
	SYSINFO_TYPE_20,
	SYSINFO_TYPE_2bis,
	SYSINFO_TYPE_2ter,
	SYSINFO_TYPE_2quater,
	SYSINFO_TYPE_5bis,
	SYSINFO_TYPE_5ter,
	/* FIXME all the various bis and ter */
	_MAX_SYSINFO_TYPE
};

typedef u_int8_t sysinfo_buf_t[GSM_MACBLOCK_LEN];

const struct value_string osmo_sitype_strs[_MAX_SYSINFO_TYPE];
uint8_t gsm_sitype2rsl(enum osmo_sysinfo_type si_type);
const char *gsm_sitype_name(enum osmo_sysinfo_type si_type);
int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type type);

#endif
