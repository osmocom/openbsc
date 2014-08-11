/* test routines for gbproxy
 * send NS messages to the gbproxy and dumps what happens
 * (C) 2013 by sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
 */

#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/gb_proxy.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/debug.h>

#define REMOTE_BSS_ADDR 0x01020304
#define REMOTE_SGSN_ADDR 0x05060708

#define SGSN_NSEI 0x0100

struct gbproxy_config gbcfg = {0};

static int dump_global(FILE *stream, int indent)
{
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sGbproxy global:\n", indent, "");
	if (rc < 0)
		return rc;

	desc = gbcfg.ctrg->desc;

	for (i = 0; i < desc->num_ctr; i++) {
		struct rate_ctr *ctr = &gbcfg.ctrg->ctr[i];
		if (ctr->current) {
			rc = fprintf(stream, "%*s    %s: %llu\n",
				     indent, "",
				     desc->ctr_desc[i].description,
				     (long long)ctr->current);

			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

static int dump_peers(FILE *stream, int indent, time_t now,
		      struct gbproxy_config *cfg)
{
	struct gbproxy_peer *peer;
	struct gprs_ra_id raid;
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sPeers:\n", indent, "");
	if (rc < 0)
		return rc;

	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		struct gbproxy_tlli_info *tlli_info;
		struct gbproxy_patch_state *state = &peer->patch_state;
		gsm48_parse_ra(&raid, peer->ra);

		rc = fprintf(stream, "%*s  NSEI %u, BVCI %u, %sblocked, "
			     "RAI %u-%u-%u-%u\n",
			     indent, "",
			     peer->nsei, peer->bvci,
			     peer->blocked ? "" : "not ",
			     raid.mcc, raid.mnc, raid.lac, raid.rac);

		if (rc < 0)
			return rc;

		desc = peer->ctrg->desc;

		for (i = 0; i < desc->num_ctr; i++) {
			struct rate_ctr *ctr = &peer->ctrg->ctr[i];
			if (ctr->current) {
				rc = fprintf(stream, "%*s    %s: %llu\n",
					     indent, "",
					     desc->ctr_desc[i].description,
					     (long long)ctr->current);

				if (rc < 0)
					return rc;
			}
		}

		fprintf(stream, "%*s    TLLI-Cache: %d\n",
			indent, "", state->enabled_tllis_count);
		llist_for_each_entry(tlli_info, &state->enabled_tllis, list) {
			char mi_buf[200];
			time_t age = now ? now - tlli_info->timestamp : 0;
			if (tlli_info->mi_data_len > 0) {
				snprintf(mi_buf, sizeof(mi_buf), "(invalid)");
				gsm48_mi_to_string(mi_buf, sizeof(mi_buf),
						   tlli_info->mi_data,
						   tlli_info->mi_data_len);
			} else {
				snprintf(mi_buf, sizeof(mi_buf), "(none)");
			}
			fprintf(stream, "%*s      TLLI %08x",
				     indent, "", tlli_info->tlli);
			if (tlli_info->assigned_tlli)
				fprintf(stream, "/%08x", tlli_info->assigned_tlli);
			rc = fprintf(stream, ", IMSI %s, AGE %d\n",
				     mi_buf, (int)age);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Attach Request */
static const unsigned char bssgp_attach_req[75] = {
	0x01, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x34, 0x01,
	0xc0, 0x01, 0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21,
	0x08, 0x02, 0x05, 0xf4, 0xfb, 0xc5, 0x46, 0x79,
	0x11, 0x22, 0x33, 0x40, 0x50, 0x60, 0x19, 0x18,
	0xb3, 0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60,
	0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80,
	0xba, 0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80, 0x00,
	0x16, 0x6d, 0x01
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Identity Request */
static const unsigned char bssgp_identity_req[] = {
	0x00, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x50, 0x20,
	0x16, 0x82, 0x02, 0x58, 0x0e, 0x89, 0x41, 0xc0,
	0x01, 0x08, 0x15, 0x01, 0xff, 0x6c, 0xba
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Identity Response */
static const unsigned char bssgp_identity_resp[] = {
	0x01, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x11, 0x01,
	0xc0, 0x0d, 0x08, 0x16, 0x08, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0xb7, 0x1b, 0x9a
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Attach Accept */
static const unsigned char bssgp_attach_acc[88] = {
	0x00, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x50, 0x20,
	0x16, 0x82, 0x02, 0x58, 0x13, 0x99, 0x18, 0xb3,
	0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80,
	0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba,
	0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80, 0x00, 0x0a,
	0x82, 0x08, 0x02, 0x0d, 0x88, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x81, 0x00,
	0x0e, 0x9e, 0x41, 0xc0, 0x05, 0x08, 0x02, 0x01,
	0x49, 0x04, 0x21, 0x63, 0x54, 0x40, 0x50, 0x60,
	0x19, 0xcd, 0xd7, 0x08, 0x17, 0x16, 0x18, 0x05,
	0xf4, 0xef, 0xe2, 0xb7, 0x00, 0x42, 0x67, 0x9a
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Attach Complete */
static const unsigned char bssgp_attach_complete[] = {
	0x01, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x08, 0x01,
	0xc0, 0x11, 0x08, 0x03, 0xff, 0xff, 0xff
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - GMM Information */
static const unsigned char bssgp_gmm_information[66] = {
	0x00, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x50, 0x20,
	0x16, 0x82, 0x02, 0x58, 0x13, 0x99, 0x18, 0xb3,
	0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80,
	0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba,
	0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80, 0x00, 0x0a,
	0x82, 0x08, 0x02, 0x0d, 0x88, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x81, 0x00,
	0x0e, 0x88, 0x41, 0xc0, 0x09, 0x08, 0x21, 0x04,
	0xba, 0x3d
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Routing Area Update Request */
static const unsigned char bssgp_ra_upd_req[85] = {
	0x01, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x70, 0x80, 0x00, 0x80, 0x0e, 0x00, 0x3e, 0x01,
	0xc0, 0x15, 0x08, 0x08, 0x10, 0x11, 0x22, 0x33,
	0x40, 0x50, 0x60, 0x1d, 0x19, 0x13, 0x42, 0x33,
	0x57, 0x2b, 0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48,
	0x50, 0xc8, 0x48, 0x02, 0x14, 0x48, 0x50, 0xc8,
	0x48, 0x02, 0x17, 0x49, 0x10, 0xc8, 0x48, 0x02,
	0x00, 0x19, 0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27,
	0x07, 0x04, 0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02,
	0x20, 0x00, 0x96, 0x3e, 0x97
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Routing Area Update Accept */
static const unsigned char bssgp_ra_upd_acc[91] = {
	0x00, 0xbb, 0xc5, 0x46, 0x79, 0x00, 0x50, 0x20,
	0x16, 0x82, 0x02, 0x58, 0x13, 0x9d, 0x19, 0x13,
	0x42, 0x33, 0x57, 0x2b, 0xf7, 0xc8, 0x48, 0x02,
	0x13, 0x48, 0x50, 0xc8, 0x48, 0x02, 0x14, 0x48,
	0x50, 0xc8, 0x48, 0x02, 0x17, 0x49, 0x10, 0xc8,
	0x48, 0x02, 0x00, 0x0a, 0x82, 0x07, 0x04, 0x0d,
	0x88, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x00, 0x81, 0x00, 0x0e, 0x9d, 0x41, 0xc0,
	0x19, 0x08, 0x09, 0x00, 0x49, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0x54, 0xab, 0xb3, 0x18,
	0x05, 0xf4, 0xef, 0xe2, 0xb7, 0x00, 0x17, 0x16,
	0xd7, 0x59, 0x65
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Activate PDP Context Request */
static const unsigned char bssgp_act_pdp_ctx_req[76] = {
	0x01, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x35, 0x01,
	0xc0, 0x0d, 0x0a, 0x41, 0x05, 0x03, 0x0c, 0x00,
	0x00, 0x1f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x01, 0x21, 0x28, 0x03,
	0x02, 0x61, 0x62, 0x27, 0x14, 0x80, 0x80, 0x21,
	0x10, 0x01, 0x00, 0x00, 0x10, 0x81, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x5a, 0xff, 0x02
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Detach Request (MO) */
/* normal detach, power_off = 1 */
static const unsigned char bssgp_detach_po_req[44] = {
	0x01, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x15, 0x01,
	0xc0, 0x19, 0x08, 0x05, 0x09, 0x18, 0x05, 0xf4,
	0xef, 0xe2, 0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97,
	0xcb, 0x84, 0x0c, 0xeb
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Detach Request (MO) */
/* normal detach, power_off = 0 */
static const unsigned char bssgp_detach_req[44] = {
	0x01, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x00, 0x04,
	0x08, 0x88, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
	0x75, 0x30, 0x00, 0x80, 0x0e, 0x00, 0x15, 0x01,
	0xc0, 0x19, 0x08, 0x05, 0x01, 0x18, 0x05, 0xf4,
	0xef, 0xe2, 0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97,
	0xcb, 0x7e, 0xe1, 0x41
};

/* Base Station Subsystem GPRS Protocol: GSM A-I/F DTAP - Detach Accept */
static const unsigned char bssgp_detach_acc[67] = {
	0x00, 0xef, 0xe2, 0xb7, 0x00, 0x00, 0x50, 0x20,
	0x16, 0x82, 0x02, 0x58, 0x13, 0x99, 0x18, 0xb3,
	0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80,
	0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba,
	0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80, 0x00, 0x0a,
	0x82, 0x08, 0x02, 0x0d, 0x88, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x81, 0x00,
	0x0e, 0x89, 0x41, 0xc0, 0x15, 0x08, 0x06, 0x00,
	0xf7, 0x35, 0xf0
};

static int gprs_process_message(struct gprs_ns_inst *nsi, const char *text,
				struct sockaddr_in *peer, const unsigned char* data,
				size_t data_len);

static void send_ns_reset(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr,
			  enum ns_cause cause, uint16_t nsvci, uint16_t nsei)
{
	/* GPRS Network Service, PDU type: NS_RESET,
	 */
	unsigned char msg[12] = {
		0x02, 0x00, 0x81, 0x01, 0x01, 0x82, 0x11, 0x22,
		0x04, 0x82, 0x11, 0x22
	};

	msg[3] = cause;
	msg[6] = nsvci / 256;
	msg[7] = nsvci % 256;
	msg[10] = nsei / 256;
	msg[11] = nsei % 256;

	gprs_process_message(nsi, "RESET", src_addr, msg, sizeof(msg));
}

static void send_ns_reset_ack(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr,
			      uint16_t nsvci, uint16_t nsei)
{
	/* GPRS Network Service, PDU type: NS_RESET_ACK,
	 */
	unsigned char msg[9] = {
		0x03, 0x01, 0x82, 0x11, 0x22,
		0x04, 0x82, 0x11, 0x22
	};

	msg[3] = nsvci / 256;
	msg[4] = nsvci % 256;
	msg[7] = nsei / 256;
	msg[8] = nsei % 256;

	gprs_process_message(nsi, "RESET_ACK", src_addr, msg, sizeof(msg));
}

static void send_ns_alive(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr)
{
	/* GPRS Network Service, PDU type: NS_ALIVE */
	unsigned char msg[1] = {
		0x0a
	};

	gprs_process_message(nsi, "ALIVE", src_addr, msg, sizeof(msg));
}

static void send_ns_alive_ack(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr)
{
	/* GPRS Network Service, PDU type: NS_ALIVE_ACK */
	unsigned char msg[1] = {
		0x0b
	};

	gprs_process_message(nsi, "ALIVE_ACK", src_addr, msg, sizeof(msg));
}

static void send_ns_unblock(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr)
{
	/* GPRS Network Service, PDU type: NS_UNBLOCK */
	unsigned char msg[1] = {
		0x06
	};

	gprs_process_message(nsi, "UNBLOCK", src_addr, msg, sizeof(msg));
}

static void send_ns_unblock_ack(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr)
{
	/* GPRS Network Service, PDU type: NS_UNBLOCK_ACK */
	unsigned char msg[1] = {
		0x07
	};

	gprs_process_message(nsi, "UNBLOCK_ACK", src_addr, msg, sizeof(msg));
}

static void send_ns_unitdata(struct gprs_ns_inst *nsi, const char *text,
			     struct sockaddr_in *src_addr, uint16_t nsbvci,
			     const unsigned char *bssgp_msg, size_t bssgp_msg_size)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA */
	unsigned char msg[4096] = {
		0x00, 0x00, 0x00, 0x00
	};

	OSMO_ASSERT(bssgp_msg_size <= sizeof(msg) - 4);

	msg[2] = nsbvci / 256;
	msg[3] = nsbvci % 256;
	memcpy(msg + 4, bssgp_msg, bssgp_msg_size);

	gprs_process_message(nsi, text ? text : "UNITDATA", src_addr, msg, bssgp_msg_size + 4);
}

static void send_bssgp_reset(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr,
			     uint16_t bvci)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA, BVCI 0
	 * BSSGP RESET */
	unsigned char msg[18] = {
		0x22, 0x04, 0x82, 0x4a,
		0x2e, 0x07, 0x81, 0x08, 0x08, 0x88, 0x11, 0x22,
		0x33, 0x40, 0x50, 0x60, 0x10, 0x00
	};

	msg[3] = bvci / 256;
	msg[4] = bvci % 256;

	send_ns_unitdata(nsi, "BVC_RESET", src_addr, 0, msg, sizeof(msg));
}

static void send_bssgp_reset_ack(struct gprs_ns_inst *nsi,
				 struct sockaddr_in *src_addr, uint16_t bvci)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA, BVCI 0
	 * BSSGP RESET_ACK */
	static unsigned char msg[5] = {
		0x23, 0x04, 0x82, 0x00,
		0x00
	};

	msg[3] = bvci / 256;
	msg[4] = bvci % 256;

	send_ns_unitdata(nsi, "BVC_RESET_ACK", src_addr, 0, msg, sizeof(msg));
}

static void send_bssgp_suspend(struct gprs_ns_inst *nsi,
			       struct sockaddr_in *src_addr,
			       struct gprs_ra_id *raid)
{
	/* Base Station Subsystem GPRS Protocol, BSSGP SUSPEND */
	unsigned char msg[15] = {
		0x0b, 0x1f, 0x84, 0xcc, 0xd1, 0x75, 0x8b, 0x1b,
		0x86, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60
	};

	gsm48_construct_ra(msg + 9, raid);

	send_ns_unitdata(nsi, "BVC_SUSPEND", src_addr, 0, msg, sizeof(msg));
}

static void send_bssgp_suspend_ack(struct gprs_ns_inst *nsi,
				   struct sockaddr_in *src_addr,
				   struct gprs_ra_id *raid)
{
	/* Base Station Subsystem GPRS Protocol, BSSGP SUSPEND ACK */
	unsigned char msg[18] = {
		0x0c, 0x1f, 0x84, 0xcc, 0xd1, 0x75, 0x8b, 0x1b,
		0x86, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60, 0x1d,
		0x81, 0x01
	};

	gsm48_construct_ra(msg + 9, raid);

	send_ns_unitdata(nsi, "BVC_SUSPEND_ACK", src_addr, 0, msg, sizeof(msg));
}

static void setup_ns(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr,
		     uint16_t nsvci, uint16_t nsei)
{
	printf("Setup NS-VC: remote 0x%08x:%d, "
	       "NSVCI 0x%04x(%d), NSEI 0x%04x(%d)\n\n",
	       ntohl(src_addr->sin_addr.s_addr), ntohs(src_addr->sin_port),
	       nsvci, nsvci, nsei, nsei);

	send_ns_reset(nsi, src_addr, NS_CAUSE_OM_INTERVENTION, nsvci, nsei);
	send_ns_alive(nsi, src_addr);
	send_ns_unblock(nsi, src_addr);
	send_ns_alive_ack(nsi, src_addr);
}

static void setup_bssgp(struct gprs_ns_inst *nsi, struct sockaddr_in *src_addr,
		     uint16_t bvci)
{
	printf("Setup BSSGP: remote 0x%08x:%d, "
	       "BVCI 0x%04x(%d)\n\n",
	       ntohl(src_addr->sin_addr.s_addr), ntohs(src_addr->sin_port),
	       bvci, bvci);

	send_bssgp_reset(nsi, src_addr, bvci);
}

static void connect_sgsn(struct gprs_ns_inst *nsi, struct sockaddr_in *sgsn_peer)
{
	gprs_ns_nsip_connect(nsi, sgsn_peer, SGSN_NSEI, SGSN_NSEI+1);
	send_ns_reset_ack(nsi, sgsn_peer, SGSN_NSEI+1, SGSN_NSEI);
	send_ns_alive_ack(nsi, sgsn_peer);
	send_ns_unblock_ack(nsi, sgsn_peer);
	send_ns_alive(nsi, sgsn_peer);
}

static void configure_sgsn_peer(struct sockaddr_in *sgsn_peer)
{
	sgsn_peer->sin_family = AF_INET;
	sgsn_peer->sin_port = htons(32000);
	sgsn_peer->sin_addr.s_addr = htonl(REMOTE_SGSN_ADDR);
}

static void configure_bss_peers(struct sockaddr_in *bss_peers, size_t size)
{
	size_t i;

	for (i = 0; i < size; ++i) {
		bss_peers[i].sin_family = AF_INET;
		bss_peers[i].sin_port = htons((i + 1) * 1111);
		bss_peers[i].sin_addr.s_addr = htonl(REMOTE_BSS_ADDR);
	}
}

int gprs_ns_rcvmsg(struct gprs_ns_inst *nsi, struct msgb *msg,
		   struct sockaddr_in *saddr, enum gprs_ns_ll ll);

/* override */
int gprs_ns_callback(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
			 struct msgb *msg, uint16_t bvci)
{
	printf("CALLBACK, event %d, msg length %d, bvci 0x%04x\n%s\n\n",
			event, msgb_bssgp_len(msg), bvci,
			osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		return gbprox_rcvmsg(&gbcfg, msg, nsvc->nsei, bvci, nsvc->nsvci);
	default:
		break;
	}
	return 0;
}

/* override */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	typedef ssize_t (*sendto_t)(int, const void *, size_t, int,
			const struct sockaddr *, socklen_t);
	static sendto_t real_sendto = NULL;
	uint32_t dest_host = htonl(((struct sockaddr_in *)dest_addr)->sin_addr.s_addr);
	int      dest_port = htons(((struct sockaddr_in *)dest_addr)->sin_port);

	if (!real_sendto)
		real_sendto = dlsym(RTLD_NEXT, "sendto");

	if (dest_host == REMOTE_BSS_ADDR)
		printf("MESSAGE to BSS at 0x%08x:%d, msg length %d\n%s\n\n",
		       dest_host, dest_port,
		       len, osmo_hexdump(buf, len));
	else if (dest_host == REMOTE_SGSN_ADDR)
		printf("MESSAGE to SGSN at 0x%08x:%d, msg length %d\n%s\n\n",
		       dest_host, dest_port,
		       len, osmo_hexdump(buf, len));
	else
		return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

	return len;
}

/* override */
int gprs_ns_sendmsg(struct gprs_ns_inst *nsi, struct msgb *msg)
{
	typedef int (*gprs_ns_sendmsg_t)(struct gprs_ns_inst *nsi, struct msgb *msg);
	static gprs_ns_sendmsg_t real_gprs_ns_sendmsg = NULL;
	uint16_t bvci = msgb_bvci(msg);
	uint16_t nsei = msgb_nsei(msg);

	size_t len = msgb_length(msg);

	if (!real_gprs_ns_sendmsg)
		real_gprs_ns_sendmsg = dlsym(RTLD_NEXT, "gprs_ns_sendmsg");

	if (nsei == SGSN_NSEI)
		printf("NS UNITDATA MESSAGE to SGSN, BVCI 0x%04x, "
		       "msg length %d (%s)\n",
		       bvci, len, __func__);
	else
		printf("NS UNITDATA MESSAGE to BSS, BVCI 0x%04x, "
		       "msg length %d (%s)\n",
		       bvci, len, __func__);

	return real_gprs_ns_sendmsg(nsi, msg);
}

static void dump_rate_ctr_group(FILE *stream, const char *prefix,
			    struct rate_ctr_group *ctrg)
{
	unsigned int i;

	for (i = 0; i < ctrg->desc->num_ctr; i++) {
		struct rate_ctr *ctr = &ctrg->ctr[i];
		if (ctr->current && !strchr(ctrg->desc->ctr_desc[i].name, '.'))
			fprintf(stream, " %s%s: %llu%s",
				prefix, ctrg->desc->ctr_desc[i].description,
				(long long)ctr->current,
				"\n");
	};
}

/* Signal handler for signals from NS layer */
static int test_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data)
{
	struct ns_signal_data *nssd = signal_data;
	int rc;

	if (subsys != SS_L_NS)
		return 0;

	switch (signal) {
	case S_NS_RESET:
		printf("==> got signal NS_RESET, NS-VC 0x%04x/%s\n",
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		break;

	case S_NS_ALIVE_EXP:
		printf("==> got signal NS_ALIVE_EXP, NS-VC 0x%04x/%s\n",
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		break;

	case S_NS_BLOCK:
		printf("==> got signal NS_BLOCK, NS-VC 0x%04x/%s\n",
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		break;

	case S_NS_UNBLOCK:
		printf("==> got signal NS_UNBLOCK, NS-VC 0x%04x/%s\n",
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		break;

	case S_NS_REPLACED:
		printf("==> got signal NS_REPLACED: 0x%04x/%s",
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		printf(" -> 0x%04x/%s\n",
		       nssd->old_nsvc->nsvci,
		       gprs_ns_ll_str(nssd->old_nsvc));
		break;

	default:
		printf("==> got signal %d, NS-VC 0x%04x/%s\n", signal,
		       nssd->nsvc->nsvci,
		       gprs_ns_ll_str(nssd->nsvc));
		break;
	}
	printf("\n");
	rc = gbprox_signal(subsys, signal, handler_data, signal_data);
	return rc;
}

static int gprs_process_message(struct gprs_ns_inst *nsi, const char *text, struct sockaddr_in *peer, const unsigned char* data, size_t data_len)
{
	struct msgb *msg;
	int ret;
	if (data_len > NS_ALLOC_SIZE - NS_ALLOC_HEADROOM) {
		fprintf(stderr, "message too long: %d\n", data_len);
		return -1;
	}

	msg = gprs_ns_msgb_alloc();
	memmove(msg->data, data, data_len);
	msg->l2h = msg->data;
	msgb_put(msg, data_len);

	printf("PROCESSING %s from 0x%08x:%d\n%s\n\n",
	       text, ntohl(peer->sin_addr.s_addr), ntohs(peer->sin_port),
	       osmo_hexdump(data, data_len));

	ret = gprs_ns_rcvmsg(nsi, msg, peer, GPRS_NS_LL_UDP);

	printf("result (%s) = %d\n\n", text, ret);

	msgb_free(msg);

	return ret;
}

static void gprs_dump_nsi(struct gprs_ns_inst *nsi)
{
	struct gprs_nsvc *nsvc;

	printf("Current NS-VCIs:\n");
	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		struct sockaddr_in *peer = &(nsvc->ip.bts_addr);
		printf("    VCI 0x%04x, NSEI 0x%04x, peer 0x%08x:%d%s%s\n",
		       nsvc->nsvci, nsvc->nsei,
		       ntohl(peer->sin_addr.s_addr), ntohs(peer->sin_port),
		       nsvc->state & NSE_S_BLOCKED ? ", blocked" : "",
		       nsvc->state & NSE_S_ALIVE   ? "" : ", dead"
		      );
		dump_rate_ctr_group(stdout, "        ", nsvc->ctrg);
	}
	printf("\n");
}

static void test_gbproxy()
{
	struct gprs_ns_inst *nsi = gprs_ns_instantiate(gprs_ns_callback, NULL);
	struct sockaddr_in bss_peer[4] = {{0},};
	struct sockaddr_in sgsn_peer= {0};

	bssgp_nsi = nsi;
	gbcfg.nsi = bssgp_nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;

	configure_sgsn_peer(&sgsn_peer);
	configure_bss_peers(bss_peer, ARRAY_SIZE(bss_peer));

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, &sgsn_peer);
	gprs_dump_nsi(nsi);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, &bss_peer[0], 0x1001, 0x1000);
	setup_bssgp(nsi, &bss_peer[0], 0x1002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1002);

	printf("--- Initialise BSS 2 ---\n\n");

	setup_ns(nsi, &bss_peer[1], 0x2001, 0x2000);
	setup_bssgp(nsi, &bss_peer[1], 0x2002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x2002);

	printf("--- Move BSS 1 to new port ---\n\n");

	setup_ns(nsi, &bss_peer[2], 0x1001, 0x1000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Move BSS 2 to former BSS 1 port ---\n\n");

	setup_ns(nsi, &bss_peer[0], 0x2001, 0x2000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Move BSS 1 to current BSS 2 port ---\n\n");

	setup_ns(nsi, &bss_peer[0], 0x2001, 0x2000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Move BSS 2 to new port ---\n\n");

	setup_ns(nsi, &bss_peer[3], 0x2001, 0x2000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Move BSS 2 to former BSS 1 port ---\n\n");

	setup_ns(nsi, &bss_peer[2], 0x2001, 0x2000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Move BSS 1 to original BSS 1 port ---\n\n");

	setup_ns(nsi, &bss_peer[0], 0x1001, 0x1000);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Reset BSS 1 with a new BVCI ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], 0x1012);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1012);

	printf("--- Reset BSS 1 with the old BVCI ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], 0x1002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1002);

	printf("--- Reset BSS 1 with the old BVCI again ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], 0x1002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1002);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1012 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1012 ---\n\n");

	send_ns_unitdata(nsi, NULL, &sgsn_peer, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &sgsn_peer, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from BSS 2 to SGSN, BVCI 0x2002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], 0x2002, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 2, BVCI 0x2002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &sgsn_peer, 0x2002, (uint8_t *)"", 0);

	printf("--- Reset BSS 1 with the old BVCI on BSS2's link ---\n\n");

	setup_bssgp(nsi, &bss_peer[2], 0x1002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1002);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, &sgsn_peer, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x10ff (invalid) ---\n\n");

	send_ns_unitdata(nsi, NULL, &sgsn_peer, 0x10ff, (uint8_t *)"", 0);

	dump_global(stdout, 0);

	gbprox_reset(&gbcfg);
	gprs_ns_destroy(nsi);
	nsi = NULL;
}

static void test_gbproxy_ident_changes()
{
	struct gprs_ns_inst *nsi = gprs_ns_instantiate(gprs_ns_callback, NULL);
	struct sockaddr_in bss_peer[1] = {{0},};
	struct sockaddr_in sgsn_peer= {0};
	uint16_t nsei[2] = {0x1000, 0x2000};
	uint16_t nsvci[2] = {0x1001, 0x2001};
	uint16_t bvci[4] = {0x1002, 0x2002, 0x3002, 0x4002};

	bssgp_nsi = nsi;
	gbcfg.nsi = bssgp_nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;

	configure_sgsn_peer(&sgsn_peer);
	configure_bss_peers(bss_peer, ARRAY_SIZE(bss_peer));

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, &sgsn_peer);
	gprs_dump_nsi(nsi);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, &bss_peer[0], nsvci[0], nsei[0]);
	gprs_dump_nsi(nsi);

	printf("--- Setup BVCI 1 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[0]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[0]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Setup BVCI 2 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[1]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[1]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 1 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[0], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[0], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 2 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[1], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[1], (uint8_t *)"", 0);

	printf("--- Change NSEI ---\n\n");

	setup_ns(nsi, &bss_peer[0], nsvci[0], nsei[1]);
	gprs_dump_nsi(nsi);

	printf("--- Setup BVCI 1 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[0]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[0]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Setup BVCI 3 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[2]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[2]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 1 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[0], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[0], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 2 "
	       " (should fail) ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 3 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[2], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[2], (uint8_t *)"", 0);

	printf("--- Change NSVCI ---\n\n");

	setup_ns(nsi, &bss_peer[0], nsvci[1], nsei[1]);
	gprs_dump_nsi(nsi);

	printf("--- Setup BVCI 1 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[0]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[0]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Setup BVCI 4 ---\n\n");

	setup_bssgp(nsi, &bss_peer[0], bvci[3]);
	send_bssgp_reset_ack(nsi, &sgsn_peer, bvci[3]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 1 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[0], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[0], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 2 "
	       " (should fail) ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 3 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[2], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[2], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 4 ---\n\n");

	send_ns_unitdata(nsi, NULL, &bss_peer[0], bvci[3], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, &sgsn_peer, bvci[3], (uint8_t *)"", 0);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	gbprox_reset(&gbcfg);
	gprs_ns_destroy(nsi);
	nsi = NULL;
}

static void test_gbproxy_ra_patching()
{
	struct gprs_ns_inst *nsi = gprs_ns_instantiate(gprs_ns_callback, NULL);
	struct sockaddr_in bss_peer[1] = {{0},};
	struct sockaddr_in sgsn_peer= {0};
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_sgsn =
		{.mcc = 123, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	const char *err_msg = NULL;
	const uint32_t ptmsi = 0xefe2b700;
	const uint32_t local_tlli = 0xefe2b700;
	struct gbproxy_tlli_info *tlli_info;
	struct gbproxy_peer *peer;

	OSMO_ASSERT(local_tlli == gprs_tmsi2tlli(ptmsi, TLLI_LOCAL));

	bssgp_nsi = nsi;
	gbcfg.nsi = bssgp_nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_mcc = 123;
	gbcfg.core_mnc = 456;
	gbcfg.core_apn = talloc_zero_size(NULL, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");

	configure_sgsn_peer(&sgsn_peer);
	configure_bss_peers(bss_peer, ARRAY_SIZE(bss_peer));

	gbcfg.match_re = talloc_strdup(NULL, "^9898|^121314");
	if (gbprox_set_patch_filter(&gbcfg, gbcfg.match_re, &err_msg) != 0) {
		fprintf(stderr, "Failed to compile RE '%s': %s\n",
			gbcfg.match_re, err_msg);
		exit(1);
	}


	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, &sgsn_peer);
	gprs_dump_nsi(nsi);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, &bss_peer[0], 0x1001, 0x1000);
	setup_bssgp(nsi, &bss_peer[0], 0x1002);
	gprs_dump_nsi(nsi);
	dump_peers(stdout, 0, 0, &gbcfg);

	peer = gbprox_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, &sgsn_peer, 0x1002);

	send_bssgp_suspend(nsi, &bss_peer[0], &rai_bss);
	send_bssgp_suspend_ack(nsi, &sgsn_peer, &rai_sgsn);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, "ATTACH REQUEST", &bss_peer[0], 0x1002,
			 bssgp_attach_req, sizeof(bssgp_attach_req));

	send_ns_unitdata(nsi, "IDENT REQUEST", &sgsn_peer, 0x1002,
			 bssgp_identity_req, sizeof(bssgp_identity_req));

	send_ns_unitdata(nsi, "IDENT RESPONSE", &bss_peer[0], 0x1002,
			 bssgp_identity_resp, sizeof(bssgp_identity_resp));

	send_ns_unitdata(nsi, "ATTACH ACCEPT", &sgsn_peer, 0x1002,
			 bssgp_attach_acc, sizeof(bssgp_attach_acc));

	tlli_info = gbprox_find_tlli(peer, local_tlli);
	OSMO_ASSERT(tlli_info);
	OSMO_ASSERT(tlli_info->assigned_tlli == local_tlli);
	OSMO_ASSERT(tlli_info->tlli != local_tlli);
	OSMO_ASSERT(!tlli_info->bss_validated);
	OSMO_ASSERT(!tlli_info->net_validated);

	send_ns_unitdata(nsi, "ATTACH COMPLETE", &bss_peer[0], 0x1002,
			 bssgp_attach_complete, sizeof(bssgp_attach_complete));

	tlli_info = gbprox_find_tlli(peer, local_tlli);
	OSMO_ASSERT(tlli_info);
	OSMO_ASSERT(tlli_info->assigned_tlli == local_tlli);
	OSMO_ASSERT(tlli_info->tlli != local_tlli);
	OSMO_ASSERT(tlli_info->bss_validated);
	OSMO_ASSERT(!tlli_info->net_validated);

	/* Replace APN (1) */
	send_ns_unitdata(nsi, "ACT PDP CTX REQ (REPLACE APN)",
			 &bss_peer[0], 0x1002,
			 bssgp_act_pdp_ctx_req, sizeof(bssgp_act_pdp_ctx_req));

	tlli_info = gbprox_find_tlli(peer, local_tlli);
	OSMO_ASSERT(tlli_info);
	OSMO_ASSERT(tlli_info->assigned_tlli == local_tlli);
	OSMO_ASSERT(tlli_info->tlli != local_tlli);
	OSMO_ASSERT(tlli_info->bss_validated);
	OSMO_ASSERT(!tlli_info->net_validated);

	send_ns_unitdata(nsi, "GMM INFO", &sgsn_peer, 0x1002,
			 bssgp_gmm_information, sizeof(bssgp_gmm_information));

	tlli_info = gbprox_find_tlli(peer, local_tlli);
	OSMO_ASSERT(tlli_info);
	OSMO_ASSERT(tlli_info->assigned_tlli == 0);
	OSMO_ASSERT(tlli_info->tlli == local_tlli);

	/* Replace APN (2) */
	send_ns_unitdata(nsi, "ACT PDP CTX REQ (REPLACE APN)",
			 &bss_peer[0], 0x1002,
			 bssgp_act_pdp_ctx_req, sizeof(bssgp_act_pdp_ctx_req));

	gbcfg.core_apn[0] = 0;
	gbcfg.core_apn_size = 0;

	/* Remove APN */
	send_ns_unitdata(nsi, "ACT PDP CTX REQ (REMOVE APN)",
			 &bss_peer[0], 0x1002,
			 bssgp_act_pdp_ctx_req, sizeof(bssgp_act_pdp_ctx_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach */
	send_ns_unitdata(nsi, "DETACH REQ", &bss_peer[0], 0x1002,
			 bssgp_detach_req, sizeof(bssgp_detach_req));

	send_ns_unitdata(nsi, "DETACH ACC", &sgsn_peer, 0x1002,
			 bssgp_detach_acc, sizeof(bssgp_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- RA update ---\n\n");

	send_ns_unitdata(nsi, "RA UPD REQ", &bss_peer[0], 0x1002,
			 bssgp_ra_upd_req, sizeof(bssgp_ra_upd_req));

	send_ns_unitdata(nsi, "RA UPD ACC", &sgsn_peer, 0x1002,
			 bssgp_ra_upd_acc, sizeof(bssgp_ra_upd_acc));

	/* Remove APN */
	send_ns_unitdata(nsi, "ACT PDP CTX REQ (REMOVE APN)",
			 &bss_peer[0], 0x1002,
			 bssgp_act_pdp_ctx_req, sizeof(bssgp_act_pdp_ctx_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (power off -> no Detach Accept) */
	send_ns_unitdata(nsi, "DETACH REQ (PWR OFF)", &bss_peer[0], 0x1002,
			 bssgp_detach_po_req, sizeof(bssgp_detach_po_req));

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Bad cases ---\n\n");

	printf("TLLI is already detached, shouldn't patch\n");
	send_ns_unitdata(nsi, "ACT PDP CTX REQ", &bss_peer[0], 0x1002,
			 bssgp_act_pdp_ctx_req, sizeof(bssgp_act_pdp_ctx_req));

	printf("Invalid RAI, shouldn't patch\n");
	send_bssgp_suspend_ack(nsi, &sgsn_peer, &rai_unknown);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	gbprox_reset(&gbcfg);
	gprs_ns_destroy(nsi);
	nsi = NULL;
}

/* TODO: Move tlv testing to libosmocore */
int v_fixed_shift(uint8_t **data, size_t *data_len, size_t len, uint8_t **value);
int tv_fixed_match(uint8_t **data, size_t *data_len, uint8_t tag, size_t len,
	     uint8_t **value);
int tlv_match(uint8_t **data, size_t *data_len, uint8_t tag, uint8_t **value,
	      size_t *value_len);
int lv_shift(uint8_t **data, size_t *data_len,
	     uint8_t **value, size_t *value_len);

static void check_tlv_match(uint8_t **data, size_t *data_len,
			    uint8_t tag, size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	int rc;

	rc = tlv_match(data, data_len, tag ^ 1, NULL, NULL);
	OSMO_ASSERT(rc == 0);

	rc = tlv_match(data, data_len, tag, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 2);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tv_fixed_match(uint8_t **data, size_t *data_len,
				 uint8_t tag, size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = tv_fixed_match(data, data_len, tag ^ 1, len, NULL);
	OSMO_ASSERT(rc == 0);

	rc = tv_fixed_match(data, data_len, tag, len, &value);
	OSMO_ASSERT(rc == (int)len + 1);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_v_fixed_shift(uint8_t **data, size_t *data_len,
				size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = v_fixed_shift(data, data_len, len, &value);
	OSMO_ASSERT(rc == (int)len);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_lv_shift(uint8_t **data, size_t *data_len,
			   size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	int rc;

	rc = lv_shift(data, data_len, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 1);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tlv_match_data_len(size_t data_len, uint8_t tag, size_t len,
				     const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	tlv_put(data, tag, len, test_data);
	if (data_len < len + 2) {
		OSMO_ASSERT(-1 == tlv_match(&data, &tmp_data_len,
					    tag, &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= tlv_match(&data, &tmp_data_len,
					   tag, &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void check_tv_fixed_match_data_len(size_t data_len,
					  uint8_t tag, size_t len,
					  const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	tv_fixed_put(data, tag, len, test_data);

	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == tv_fixed_match(&data, &tmp_data_len,
						 tag, len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= tv_fixed_match(&data, &tmp_data_len,
						tag, len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_v_fixed_shift_data_len(size_t data_len,
					 size_t len, const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	memcpy(data, test_data, len);

	if (data_len < len) {
		OSMO_ASSERT(-1 == v_fixed_shift(&data, &tmp_data_len,
						len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= v_fixed_shift(&data, &tmp_data_len,
					       len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_lv_shift_data_len(size_t data_len,
				    size_t len, const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf;

	lv_put(data, len, test_data);
	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == lv_shift(&data, &tmp_data_len,
					   &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= lv_shift(&data, &tmp_data_len,
					  &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void test_tlv_shift_functions()
{
	uint8_t test_data[1024];
	uint8_t buf[1024];
	uint8_t *data_end;
	unsigned i, len;
	uint8_t *data;
	size_t data_len;
	const uint8_t tag = 0x1a;

	printf("Test shift functions\n");

	for (i = 0; i < ARRAY_SIZE(test_data); i++)
		test_data[i] = (uint8_t)i;

	for (len = 0; len < 256; len++) {
		const unsigned iterations = sizeof(buf) / (len + 2) / 4;

		memset(buf, 0xee, sizeof(buf));
		data_end = data = buf;

		for (i = 0; i < iterations; i++) {
			data_end = tlv_put(data_end, tag, len, test_data);
			data_end = tv_fixed_put(data_end, tag, len, test_data);
			/* v_fixed_put */
			memcpy(data_end, test_data, len);
			data_end += len;
			data_end = lv_put(data_end, len, test_data);
		}

		data_len = data_end - data;
		OSMO_ASSERT(data_len <= sizeof(buf));

		for (i = 0; i < iterations; i++) {
			check_tlv_match(&data, &data_len, tag, len, test_data);
			check_tv_fixed_match(&data, &data_len, tag, len, test_data);
			check_v_fixed_shift(&data, &data_len, len, test_data);
			check_lv_shift(&data, &data_len, len, test_data);
		}

		OSMO_ASSERT(data == data_end);

		/* Test at end of data */

		OSMO_ASSERT(-1 == tlv_match(&data, &data_len, tag, NULL, NULL));
		OSMO_ASSERT(-1 == tv_fixed_match(&data, &data_len, tag, len, NULL));
		OSMO_ASSERT((len ? -1 : 0) == v_fixed_shift(&data, &data_len, len, NULL));
		OSMO_ASSERT(-1 == lv_shift(&data, &data_len, NULL, NULL));

		/* Test invalid data_len */
		for (data_len = 0; data_len <= len + 2 + 1; data_len += 1) {
			check_tlv_match_data_len(data_len, tag, len, test_data);
			check_tv_fixed_match_data_len(data_len, tag, len, test_data);
			check_v_fixed_shift_data_len(data_len, len, test_data);
			check_lv_shift_data_len(data_len, len, test_data);
		}
	}
}

static void test_gbproxy_tlli_expire(void)
{
	struct gbproxy_config cfg = {0};
	struct gbproxy_peer *peer;
	const char *err_msg = NULL;
	const uint8_t imsi1[] = { GSM_MI_TYPE_IMSI, 0x23, 0x24, 0x25, 0x26 };
	const uint8_t imsi2[] = { GSM_MI_TYPE_IMSI, 0x26, 0x27, 0x28, 0x29 };
	const uint8_t imsi3[] = { GSM_MI_TYPE_IMSI | 0x10, 0x32, 0x54, 0x76, 0xf8 };
	const uint32_t tlli1 = 1234 | 0xc0000000;
	const uint32_t tlli2 = 5678 | 0xc0000000;
	const uint32_t tlli3 = 3456 | 0xc0000000;
	const char *filter_re = ".*";
	time_t now = 1407479214;

	printf("Test TLLI info expiry\n\n");

	gbproxy_init_config(&cfg);

	if (gbprox_set_patch_filter(&cfg, filter_re, &err_msg) != 0) {
		fprintf(stderr, "gbprox_set_patch_filter: got error: %s\n",
			err_msg);
		OSMO_ASSERT(err_msg == NULL);
	}

	{
		struct gbproxy_tlli_info *tlli_info;

		printf("Test TLLI replacement:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		tlli_info = gbprox_register_tlli(peer, tlli1,
						 imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		/* replace the old entry */
		printf("  Add TLLI 2, IMSI 1 (should replace TLLI 1)\n");
		tlli_info = gbprox_register_tlli(peer, tlli2,
						 imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli2);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli2);
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(!tlli_info);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_tlli_info *tlli_info;

		printf("Test IMSI replacement:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		tlli_info = gbprox_register_tlli(peer, tlli1,
						 imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		/* try to replace the old entry */
		printf("  Add TLLI 1, IMSI 2 (should replace IMSI 1)\n");
		tlli_info = gbprox_register_tlli(peer, tlli1,
						 imsi2, ARRAY_SIZE(imsi2), now);
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!tlli_info);
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli1);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_tlli_info *tlli_info;
		int num_removed;

		printf("Test TLLI expiry, max_len == 1:\n");

		cfg.tlli_max_len = 1;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		gbprox_register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		/* replace the old entry */
		printf("  Add TLLI 2, IMSI 2 (should replace IMSI 1)\n");
		gbprox_register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2), now);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 2);

		num_removed = gbprox_remove_stale_tllis(peer, time(NULL) + 2);
		OSMO_ASSERT(num_removed == 1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!tlli_info);
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(tlli_info);
		OSMO_ASSERT(tlli_info->tlli == tlli2);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		int num_removed;

		printf("Test TLLI expiry, max_age == 1:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 1;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 0);

		printf("  Add TLLI 1, IMSI 1 (should expire after timeout)\n");
		gbprox_register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		printf("  Add TLLI 2, IMSI 2 (should not expire after timeout)\n");
		gbprox_register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2),
				     now + 1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 2);

		num_removed = gbprox_remove_stale_tllis(peer, now + 2);
		OSMO_ASSERT(num_removed == 1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		dump_peers(stdout, 2, now + 2, &cfg);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		int num_removed;

		printf("Test TLLI expiry, max_len == 2, max_age == 1:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 1;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 0);

		printf("  Add TLLI 1, IMSI 1 (should expire)\n");
		gbprox_register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		printf("  Add TLLI 2, IMSI 2 (should expire after timeout)\n");
		gbprox_register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2),
				     now + 1);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 2);

		printf("  Add TLLI 3, IMSI 3 (should not expire after timeout)\n");
		gbprox_register_tlli(peer, tlli3, imsi3, ARRAY_SIZE(imsi3),
				     now + 2);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 3);

		dump_peers(stdout, 2, now + 2, &cfg);

		printf("  Remove stale TLLIs\n");
		num_removed = gbprox_remove_stale_tllis(peer, now + 3);
		OSMO_ASSERT(num_removed == 2);
		OSMO_ASSERT(peer->patch_state.enabled_tllis_count == 1);

		dump_peers(stdout, 2, now + 2, &cfg);

		printf("\n");

		gbproxy_peer_free(peer);
	}
}

static void test_gbproxy_imsi_matching(void)
{
	struct gbproxy_config cfg = {0};
	struct gbproxy_peer *peer;
	const char *err_msg = NULL;
	const uint8_t imsi1[] = { GSM_MI_TYPE_IMSI | 0x10, 0x32, 0x54, 0xf6 };
	const uint8_t imsi2[] = { GSM_MI_TYPE_IMSI | GSM_MI_ODD | 0x10, 0x32, 0x54, 0x76 };
	const uint8_t imsi3_bad[] = { GSM_MI_TYPE_IMSI | 0x10, 0xee, 0x54, 0xff };
	const uint8_t tmsi1[] = { GSM_MI_TYPE_TMSI | 0xf0, 0x11, 0x22, 0x33, 0x44 };
	const uint8_t tmsi2_bad[] = { GSM_MI_TYPE_TMSI | 0xf0, 0x11, 0x22 };
	const uint8_t imei1[] = { GSM_MI_TYPE_IMEI | 0x10, 0x32, 0x54, 0xf6 };
	const uint8_t imei2[] = { GSM_MI_TYPE_IMEI | GSM_MI_ODD | 0x10, 0x32, 0x54, 0x76 };
	const char *filter_re1 = ".*";
	const char *filter_re2 = "^1234";
	const char *filter_re3 = "^4321";
	const char *filter_re4_bad = "^12[";

	printf("=== Test IMSI/TMSI matching ===\n\n");

	gbproxy_init_config(&cfg);
	OSMO_ASSERT(cfg.check_imsi == 0);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re1, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	err_msg = NULL;
	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re4_bad, &err_msg) == -1);
	OSMO_ASSERT(err_msg != NULL);
	OSMO_ASSERT(cfg.check_imsi == 0);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, NULL, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 0);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	gbprox_clear_patch_filter(&cfg);
	OSMO_ASSERT(cfg.check_imsi == 0);

	peer = gbproxy_peer_alloc(&cfg, 20);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	OSMO_ASSERT(gbprox_check_imsi(peer, imsi1, ARRAY_SIZE(imsi1)) == 1);
	OSMO_ASSERT(gbprox_check_imsi(peer, imsi2, ARRAY_SIZE(imsi2)) == 1);
	/* imsi3_bad contains 0xE and 0xF digits, but the conversion function
	 * doesn't complain, so gbprox_check_imsi() doesn't return -1 in this
	 * case. */
	OSMO_ASSERT(gbprox_check_imsi(peer, imsi3_bad, ARRAY_SIZE(imsi3_bad)) == 0);
	OSMO_ASSERT(gbprox_check_imsi(peer, tmsi1, ARRAY_SIZE(tmsi1)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, tmsi2_bad, ARRAY_SIZE(tmsi2_bad)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, imei1, ARRAY_SIZE(imei1)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, imei2, ARRAY_SIZE(imei2)) == -1);

	OSMO_ASSERT(gbprox_set_patch_filter(&cfg, filter_re3, &err_msg) == 0);
	OSMO_ASSERT(cfg.check_imsi == 1);

	OSMO_ASSERT(gbprox_check_imsi(peer, imsi1, ARRAY_SIZE(imsi1)) == 0);
	OSMO_ASSERT(gbprox_check_imsi(peer, imsi2, ARRAY_SIZE(imsi2)) == 0);
	OSMO_ASSERT(gbprox_check_imsi(peer, imsi3_bad, ARRAY_SIZE(imsi3_bad)) == 0);
	OSMO_ASSERT(gbprox_check_imsi(peer, tmsi1, ARRAY_SIZE(tmsi1)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, tmsi2_bad, ARRAY_SIZE(tmsi2_bad)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, imei1, ARRAY_SIZE(imei1)) == -1);
	OSMO_ASSERT(gbprox_check_imsi(peer, imei2, ARRAY_SIZE(imei2)) == -1);

	/* TODO: Check correct length but wrong type with is_mi_tmsi */

	gbproxy_peer_free(peer);
}

static struct log_info_cat gprs_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	osmo_signal_register_handler(SS_L_NS, &test_signal, &gbcfg);

	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_all_filter(osmo_stderr_target, 1);

	rate_ctr_init(NULL);

	setlinebuf(stdout);

	printf("===== GbProxy test START\n");
	gbproxy_init_config(&gbcfg);
	test_tlv_shift_functions();
	test_gbproxy();
	test_gbproxy_ident_changes();
	test_gbproxy_imsi_matching();
	test_gbproxy_ra_patching();
	test_gbproxy_tlli_expire();
	printf("===== GbProxy test END\n\n");

	exit(EXIT_SUCCESS);
}
