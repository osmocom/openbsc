/*
 * Message rewriting functionality
 */
/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <osmocom/sccp/sccp.h>

static char *match_and_rewrite_number(void *ctx, const char *number,
				      const char *imsi,
				      struct llist_head *list)
{
	struct bsc_nat_num_rewr_entry *entry;
	char *new_number = NULL;

	/* need to find a replacement and then fix it */
	llist_for_each_entry(entry, list, list) {
		regmatch_t matches[2];

		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		/* this regexp matches... */
		if (regexec(&entry->num_reg, number, 2, matches, 0) == 0 &&
		    matches[1].rm_eo != -1)
			new_number = talloc_asprintf(ctx, "%s%s",
					entry->replace,
					&number[matches[1].rm_so]);
		if (new_number)
			break;
	}

	return new_number;
}

static char *rewrite_isdn_number(struct bsc_nat *nat, void *ctx, const char *imsi,
				       struct gsm_mncc_number *called)
{
	char int_number[sizeof(called->number) + 2];
	char *number = called->number;

	if (llist_empty(&nat->num_rewr))
		return NULL;

	/* only ISDN plan */
	if (called->plan != 1)
		return NULL;

	/* international, prepend */
	if (called->type == 1) {
		int_number[0] = '+';
		memcpy(&int_number[1], number, strlen(number) + 1);
		number = int_number;
	}

	return match_and_rewrite_number(ctx, number,
					imsi, &nat->num_rewr);
}


/**
 * Rewrite non global numbers... according to rules based on the IMSI
 */
static struct msgb *rewrite_setup(struct bsc_nat *nat, struct msgb *msg,
				  struct bsc_nat_parsed *parsed, const char *imsi,
				  struct gsm48_hdr *hdr48, const uint32_t len)
{
	struct tlv_parsed tp;
	unsigned int payload_len;
	struct gsm_mncc_number called;
	struct msgb *out;
	char *new_number = NULL;
	uint8_t *outptr;
	const uint8_t *msgptr;
	int sec_len;

	/* decode and rewrite the message */
	payload_len = len - sizeof(*hdr48);
	tlv_parse(&tp, &gsm48_att_tlvdef, hdr48->data, payload_len, 0, 0);

	/* no number, well let us ignore it */
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD))
		return NULL;

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	/* check if it looks international and stop */
	new_number = rewrite_isdn_number(nat, msg, imsi, &called);

	if (!new_number) {
		LOGP(DNAT, LOGL_DEBUG, "No IMSI match found, returning message.\n");
		return NULL;
	}

	if (strlen(new_number) > sizeof(called.number)) {
		LOGP(DNAT, LOGL_ERROR, "Number is too long for structure.\n");
		talloc_free(new_number);
		return NULL;
	}

	/*
	 * Need to create a new message now based on the old onew
	 * with a new number. We can sadly not patch this in place
	 * so we will need to regenerate it.
	 */

	out = msgb_alloc_headroom(4096, 128, "changed-setup");
	if (!out) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		talloc_free(new_number);
		return NULL;
	}

	/* copy the header */
	outptr = msgb_put(out, sizeof(*hdr48));
	memcpy(outptr, hdr48, sizeof(*hdr48));

	/* copy everything up to the number */
	sec_len = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 2 - &hdr48->data[0];
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, &hdr48->data[0], sec_len);

	/* create the new number */
	if (strncmp(new_number, "00", 2) == 0) {
		called.type = 1;
		strncpy(called.number, new_number + 2, sizeof(called.number));
	} else {
		/* rewrite international to unknown */
		if (called.type == 1)
			called.type = 0;
		strncpy(called.number, new_number, sizeof(called.number));
	}
	gsm48_encode_called(out, &called);

	/* copy thre rest */
	msgptr = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) +
		 TLVP_LEN(&tp, GSM48_IE_CALLED_BCD);
	sec_len = payload_len - (msgptr - &hdr48->data[0]);
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, msgptr, sec_len);

	talloc_free(new_number);
	return out;
}

/**
 * Find a new SMSC address, returns an allocated string that needs to be
 * freed or is NULL.
 */
static char *find_new_smsc(struct bsc_nat *nat, void *ctx, const char *imsi,
			   const char *smsc_addr, const char *dest_nr)
{
	struct bsc_nat_num_rewr_entry *entry;
	char *new_number = NULL;
	uint8_t dest_match = llist_empty(&nat->tpdest_match);

	/* We will find a new number now */
	llist_for_each_entry(entry, &nat->smsc_rewr, list) {
		regmatch_t matches[2];

		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		/* this regexp matches... */
		if (regexec(&entry->num_reg, smsc_addr, 2, matches, 0) == 0 &&
		    matches[1].rm_eo != -1)
			new_number = talloc_asprintf(ctx, "%s%s",
					entry->replace,
					&smsc_addr[matches[1].rm_so]);
		if (new_number)
			break;
	}

	if (!new_number)
		return NULL;

	/*
	 * now match the number against another list
	 */
	llist_for_each_entry(entry, &nat->tpdest_match, list) {
		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		if (regexec(&entry->num_reg, dest_nr, 0, NULL, 0) == 0) {
			dest_match = 1;
			break;
		}
	}

	if (!dest_match) {
		talloc_free(new_number);
		return NULL;
	}

	return new_number;
}

/**
 * Clear the TP-SRR from the TPDU header
 */
static uint8_t sms_new_tpdu_hdr(struct bsc_nat *nat, const char *imsi,
				const char *dest_nr, uint8_t hdr)
{
	struct bsc_nat_num_rewr_entry *entry;

	/* We will find a new number now */
	llist_for_each_entry(entry, &nat->sms_clear_tp_srr, list) {
		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;
		if (regexec(&entry->num_reg, dest_nr, 0, NULL, 0) != 0)
			continue;

		/* matched phone number and imsi */
		return hdr & ~0x20;
	}

	return hdr;
}

/**
 * Check if we need to rewrite the number. For this SMS.
 */
static char *sms_new_dest_nr(struct bsc_nat *nat, void *ctx,
			     const char *imsi, const char *dest_nr)
{
	return match_and_rewrite_number(ctx, dest_nr, imsi,
					&nat->sms_num_rewr);
}

/**
 * This is a helper for GSM 04.11 8.2.5.2 Destination address element
 */
void sms_encode_addr_element(struct msgb *out, const char *new_number,
			     int format, int tp_data)
{
	uint8_t new_addr_len;
	uint8_t new_addr[26];

	/*
	 * Copy the new number. We let libosmocore encode it, then set
	 * the extension followed after the length. Depending on if
	 * we want to write RP we will let the TLV code add the
	 * length for us or we need to use strlen... This is not very clear
	 * as of 03.40 and 04.11.
	 */
	new_addr_len = gsm48_encode_bcd_number(new_addr, ARRAY_SIZE(new_addr),
					       1, new_number);
	new_addr[1] = format;
	if (tp_data) {
		uint8_t *data = msgb_put(out, new_addr_len);
		memcpy(data, new_addr, new_addr_len);
		data[0] = strlen(new_number);
	} else {
		msgb_lv_put(out, new_addr_len - 1, new_addr + 1);
	}
}

static struct msgb *sms_create_new(uint8_t type, uint8_t ref,
				   struct gsm48_hdr *old_hdr48,
				   const uint8_t *orig_addr_ptr,
				   int orig_addr_len, const char *new_number,
				   const uint8_t *data_ptr, int data_len,
				   uint8_t tpdu_first_byte,
				   const int old_dest_len, const char *new_dest_nr)
{
	struct gsm48_hdr *new_hdr48;
	struct msgb *out;

	/*
	 * We need to re-create the patched structure. This is why we have
	 * saved the above pointers.
	 */
	out = msgb_alloc_headroom(4096, 128, "changed-smsc");
	if (!out) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	out->l2h = out->data;
	msgb_v_put(out, GSM411_MT_RP_DATA_MO);
	msgb_v_put(out, ref);
	msgb_lv_put(out, orig_addr_len, orig_addr_ptr);

	sms_encode_addr_element(out, new_number, 0x91, 0);


	/* Patch the TPDU from here on */

	/**
	 * Do we need to put a new TP-Destination-Address (TP-DA) here or
	 * can we copy the old thing? For the TP-DA we need to find out the
	 * new size.
	 */
	if (new_dest_nr) {
		uint8_t *data, *new_size;

		/* reserve the size and write the header */
		new_size = msgb_put(out, 1);
		out->l3h = new_size + 1;
		msgb_v_put(out, tpdu_first_byte);
		msgb_v_put(out, data_ptr[1]);

		/* encode the new number and put it */
		if (strncmp(new_dest_nr, "00", 2) == 0)
			sms_encode_addr_element(out, new_dest_nr + 2, 0x91, 1);
		else
			sms_encode_addr_element(out, new_dest_nr, 0x81, 1);

		/* Copy the rest after the TP-DS */
		data = msgb_put(out, data_len - 2 - 1 - old_dest_len);
		memcpy(data, &data_ptr[2 + 1 + old_dest_len], data_len - 2 - 1 - old_dest_len);

		/* fill in the new size */
		new_size[0] = msgb_l3len(out);
	} else {
		msgb_v_put(out, data_len);
		msgb_tv_fixed_put(out, tpdu_first_byte, data_len - 1, &data_ptr[1]);
	}

	/* prepend GSM 04.08 header */
	new_hdr48 = (struct gsm48_hdr *) msgb_push(out, sizeof(*new_hdr48) + 1);
	memcpy(new_hdr48, old_hdr48, sizeof(*old_hdr48));
	new_hdr48->data[0] = msgb_l2len(out);

	return out;
}

/**
 * Parse the SMS and check if it needs to be rewritten
 */
static struct msgb *rewrite_sms(struct bsc_nat *nat, struct msgb *msg,
				struct bsc_nat_parsed *parsed, const char *imsi,
				struct gsm48_hdr *hdr48, const uint32_t len)
{
	unsigned int payload_len;
	unsigned int cp_len;

	uint8_t ref;
	uint8_t orig_addr_len, *orig_addr_ptr;
	uint8_t dest_addr_len, *dest_addr_ptr;
	uint8_t data_len, *data_ptr;
	char smsc_addr[30];


	uint8_t dest_len, orig_dest_len;
	char _dest_nr[30];
	char *dest_nr;
	char *new_dest_nr;

	char *new_number = NULL;
	uint8_t tpdu_hdr;
	struct msgb *out;

	payload_len = len - sizeof(*hdr48);
	if (payload_len < 1) {
		LOGP(DNAT, LOGL_ERROR, "SMS too short for things. %d\n", payload_len);
		return NULL;
	}

	cp_len = hdr48->data[0];
	if (payload_len + 1 < cp_len) {
		LOGP(DNAT, LOGL_ERROR, "SMS RPDU can not fit in: %d %d\n", cp_len, payload_len);
		return NULL;
	}

	if (hdr48->data[1] != GSM411_MT_RP_DATA_MO)
		return NULL;

	if (cp_len < 5) {
		LOGP(DNAT, LOGL_ERROR, "RD-DATA can not fit in the CP len: %d\n", cp_len);
		return NULL;
	}

	/* RP */
	ref = hdr48->data[2];
	orig_addr_len = hdr48->data[3];
	orig_addr_ptr = &hdr48->data[4];

	/* the +1 is for checking if the following element has some space */
	if (cp_len < 3 + orig_addr_len + 1) {
		LOGP(DNAT, LOGL_ERROR, "RP-Originator addr does not fit: %d\n", orig_addr_len);
		return NULL;
	}

	dest_addr_len = hdr48->data[3 + orig_addr_len + 1];
	dest_addr_ptr = &hdr48->data[3 + orig_addr_len + 2];

	if (cp_len < 3 + orig_addr_len + 1 + dest_addr_len + 1) {
		LOGP(DNAT, LOGL_ERROR, "RP-Destination addr does not fit: %d\n", dest_addr_len);
		return NULL;
	}
	gsm48_decode_bcd_number(smsc_addr, ARRAY_SIZE(smsc_addr), dest_addr_ptr - 1, 1);

	data_len = hdr48->data[3 + orig_addr_len + 1 + dest_addr_len + 1];
	data_ptr = &hdr48->data[3 + orig_addr_len + 1 + dest_addr_len + 2];

	if (cp_len < 3 + orig_addr_len + 1 + dest_addr_len + 1 + data_len) {
		LOGP(DNAT, LOGL_ERROR, "RP-Data does not fit: %d\n", data_len);
		return NULL;
	}

	if (data_len < 3) {
		LOGP(DNAT, LOGL_ERROR, "SMS-SUBMIT is too short.\n");
		return NULL;
	}

	/* TP-PDU starts here */
	if ((data_ptr[0] & 0x03) != GSM340_SMS_SUBMIT_MS2SC)
		return NULL;

	/*
	 * look into the phone number. The length is in semi-octets, we will
	 * need to add the byte for the number type as well.
	 */
	orig_dest_len = data_ptr[2];
	dest_len = ((orig_dest_len + 1) / 2) + 1;
	if (data_len < dest_len + 3 || dest_len < 2) {
		LOGP(DNAT, LOGL_ERROR, "SMS-SUBMIT can not have TP-DestAddr.\n");
		return NULL;
	}

	if ((data_ptr[3] & 0x80) == 0) {
		LOGP(DNAT, LOGL_ERROR, "TP-DestAddr has extension. Not handled.\n");
		return NULL;
	}

	if ((data_ptr[3] & 0x0F) == 0) {
		LOGP(DNAT, LOGL_ERROR, "TP-DestAddr is of unknown type.\n");
		return NULL;
	}

	/**
	 * Besides of what I think I read in GSM 03.40 and 04.11 the TP-DA
	 * contains the semi-octets as length (strlen), change it to the
	 * the number of bytes, but then change it back.
	 */
	data_ptr[2] = dest_len;
	gsm48_decode_bcd_number(_dest_nr + 2, ARRAY_SIZE(_dest_nr) - 2,
				&data_ptr[2], 1);
	data_ptr[2] = orig_dest_len;
	if ((data_ptr[3] & 0x70) == 0x10) {
		_dest_nr[0] = _dest_nr[1] = '0';
		dest_nr = &_dest_nr[0];
	} else {
		dest_nr = &_dest_nr[2];
	}

	/**
	 * Call functions to rewrite the data
	 */
	tpdu_hdr = sms_new_tpdu_hdr(nat, imsi, dest_nr, data_ptr[0]);
	new_number = find_new_smsc(nat, msg, imsi, smsc_addr, dest_nr);
	new_dest_nr = sms_new_dest_nr(nat, msg, imsi, dest_nr);

	if (tpdu_hdr == data_ptr[0] && !new_number && !new_dest_nr)
		return NULL;

	out = sms_create_new(GSM411_MT_RP_DATA_MO, ref, hdr48,
			orig_addr_ptr, orig_addr_len,
			new_number ? new_number : smsc_addr,
			data_ptr, data_len, tpdu_hdr,
			dest_len, new_dest_nr);
	talloc_free(new_number);
	talloc_free(new_dest_nr);
	return out;
}

struct msgb *bsc_nat_rewrite_msg(struct bsc_nat *nat, struct msgb *msg, struct bsc_nat_parsed *parsed, const char *imsi)
{
	struct gsm48_hdr *hdr48;
	uint32_t len;
	uint8_t msg_type, proto;
	struct msgb *new_msg = NULL, *sccp;
	uint8_t link_id;

	if (!imsi || strlen(imsi) < 5)
		return msg;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return msg;
	if (!parsed->dest_local_ref)
		return msg;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return msg;

	link_id = msg->l3h[1];
	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;

	if (proto == GSM48_PDISC_CC && msg_type == GSM48_MT_CC_SETUP)
		new_msg = rewrite_setup(nat, msg, parsed, imsi, hdr48, len);
	else if (proto == GSM48_PDISC_SMS && msg_type == GSM411_MT_CP_DATA)
		new_msg = rewrite_sms(nat, msg, parsed, imsi, hdr48, len);

	if (!new_msg)
		return msg;

	/* wrap with DTAP, SCCP, then IPA. TODO: Stop copying */
	gsm0808_prepend_dtap_header(new_msg, link_id);
	sccp = sccp_create_dt1(parsed->dest_local_ref, new_msg->data, new_msg->len);
	talloc_free(new_msg);

	if (!sccp) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return msg;
	}

	ipaccess_prepend_header(sccp, IPAC_PROTO_SCCP);

	/* the parsed hangs off from msg but it needs to survive */
	talloc_steal(sccp, parsed);
	msgb_free(msg);
	return sccp;
}

static void num_rewr_free_data(struct bsc_nat_num_rewr_entry *entry)
{
	regfree(&entry->msisdn_reg);
	regfree(&entry->num_reg);
	talloc_free(entry->replace);
}

void bsc_nat_num_rewr_entry_adapt(void *ctx, struct llist_head *head,
				  const struct osmo_config_list *list)
{
	struct bsc_nat_num_rewr_entry *entry, *tmp;
	struct osmo_config_entry *cfg_entry;

	/* free the old data */
	llist_for_each_entry_safe(entry, tmp, head, list) {
		num_rewr_free_data(entry);
		llist_del(&entry->list);
		talloc_free(entry);
	}


	if (!list)
		return;

	llist_for_each_entry(cfg_entry, &list->entry, list) {
		char *regexp;
		if (cfg_entry->text[0] == '+') {
			LOGP(DNAT, LOGL_ERROR,
				"Plus is not allowed in the number\n");
			continue;
		}

		entry = talloc_zero(ctx, struct bsc_nat_num_rewr_entry);
		if (!entry) {
			LOGP(DNAT, LOGL_ERROR,
				"Allocation of the num_rewr entry failed.\n");
			continue;
		}

		entry->replace = talloc_strdup(entry, cfg_entry->text);
		if (!entry->replace) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to copy the replacement text.\n");
			talloc_free(entry);
			continue;
		}

		/* we will now build a regexp string */
		if (cfg_entry->mcc[0] == '^') {
			regexp = talloc_strdup(entry, cfg_entry->mcc);
		} else {
			regexp = talloc_asprintf(entry, "^%s%s",
					cfg_entry->mcc[0] == '*' ?
						"[0-9][0-9][0-9]" : cfg_entry->mcc,
					cfg_entry->mnc[0] == '*' ?
						"[0-9][0-9]" : cfg_entry->mnc);
		}

		if (!regexp) {
			LOGP(DNAT, LOGL_ERROR, "Failed to create a regexp string.\n");
			talloc_free(entry);
			continue;
		}

		if (regcomp(&entry->msisdn_reg, regexp, 0) != 0) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to compile regexp '%s'\n", regexp);
			talloc_free(regexp);
			talloc_free(entry);
			continue;
		}

		talloc_free(regexp);
		if (regcomp(&entry->num_reg, cfg_entry->option, REG_EXTENDED) != 0) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to compile regexp '%s'\n", cfg_entry->option);
			regfree(&entry->msisdn_reg);
			talloc_free(entry);
			continue;
		}

		/* we have copied the number */
		llist_add_tail(&entry->list, head);
	}
}
