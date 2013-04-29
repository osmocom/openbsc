#ifndef _IPACCESS_H
#define _IPACCESS_H

#include <osmocom/abis/e1_input.h>
#include "gsm_subscriber.h"
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/ipaccess.h>

struct ipac_msgt_sccp_state {
	uint8_t	src_ref[3];
	uint8_t	dst_ref[3];
	uint8_t trans_id;
	uint8_t invoke_id;
	char	imsi[GSM_IMSI_LENGTH];
	uint8_t data[0];
} __attribute__((packed));

/*
 * @add_remove 0 for remove, 1 for add, 3 to asK
 * @nr_lacs Number of extra lacs inside this package
 * @lac One lac entry
 */
struct ipac_ext_lac_cmd {
	uint8_t add_remove;
	uint8_t nr_extra_lacs;
	uint16_t lac;
	uint8_t data[0];
} __attribute__((packed));

/*
 * methods for parsing and sending a message
 */
int ipaccess_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd);
void ipaccess_prepend_header(struct msgb *msg, int proto);
void ipaccess_prepend_header_ext(struct msgb *msg, int proto);
int ipaccess_send_pong(int fd);
int ipaccess_send_id_ack(int fd);
int ipaccess_send_id_req(int fd);

const char *ipaccess_idtag_name(uint8_t tag);
int ipaccess_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len);
int ipaccess_parse_unitid(const char *str, uint16_t *site_id, uint16_t *bts_id, uint16_t *trx_id);

int ipaccess_drop_oml(struct gsm_bts *bts);
int ipaccess_drop_rsl(struct gsm_bts_trx *trx);

struct sdp_header_item {
	struct sdp_header_entry header_entry;
	struct llist_head entry;
	off_t absolute_offset;
};

struct sdp_header {
	struct sdp_firmware firmware_info;

	/* for more_magic a list of sdp_header_entry_list */
	struct llist_head header_list;

	/* the entry of the sdp_header */
	struct llist_head entry;
};

int ipaccess_analyze_file(int fd, const unsigned int st_size, const unsigned base_offset, struct llist_head *list);

#endif /* _IPACCESS_H */
