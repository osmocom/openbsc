#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

enum gbproxy_patch_mode {
	GBPROX_PATCH_DEFAULT,
	GBPROX_PATCH_BSSGP,		/*!< BSGGP messages only */
	GBPROX_PATCH_LLC_ATTACH_REQ,	/*!< BSSGP and Attach Request */
	GBPROX_PATCH_LLC_ATTACH,	/*!< BSSGP and Attach Request/Response */
	GBPROX_PATCH_LLC_GMM,		/*!< BSSGP and all GMM msgs */
	GBPROX_PATCH_LLC_GSM,		/*!< BSSGP and all GMM and GSM msgs */
	GBPROX_PATCH_LLC,		/*!< BSSGP and all supported LLC msgs */
};

struct gbproxy_config {
	/* parsed from config file */
	uint16_t nsip_sgsn_nsei;

	/* misc */
	struct gprs_ns_inst *nsi;

	/* force mcc/mnc */
	int core_mnc;
	int core_mcc;
	uint8_t* core_apn;
	size_t core_apn_size;
	char * match_re;
	enum gbproxy_patch_mode patch_mode;
	int tlli_max_age;
	int tlli_max_len;
};

extern struct gbproxy_config gbcfg;
extern struct cmd_element show_gbproxy_cmd;
extern struct cmd_element delete_gb_bvci_cmd;
extern struct cmd_element delete_gb_nsei_cmd;

/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);


/* gb_proxy.c */

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);

/* Reset all persistent NS-VC's */
int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi);

int gbprox_dump_global(FILE *stream, int indent, int verbose);
int gbprox_dump_peers(FILE *stream, int indent, int verbose);
void gbprox_reset();

char *gbprox_apn_to_str(char *str, const uint8_t *apn_enc, size_t max_chars);
int gbprox_str_to_apn(uint8_t *apn_enc, const char *str, size_t max_chars);

int gbprox_set_patch_filter(const char *filter, const char **err_msg);
#endif
