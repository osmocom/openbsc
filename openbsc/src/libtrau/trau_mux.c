/* Simple TRAU frame reflector to route voice calls */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openbsc/gsm_data.h>
#include <osmocom/abis/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <osmocom/abis/subchan_demux.h>
#include <osmocom/abis/e1_input.h>
#include <openbsc/debug.h>
#include <osmocom/core/talloc.h>
#include <openbsc/trau_upqueue.h>
#include <osmocom/core/crcgen.h>
#include <openbsc/transaction.h>

/* this corresponds to the bit-lengths of the individual codec
 * parameters as indicated in Table 1.1 of TS 06.10 */
static const uint8_t gsm_fr_map[] = {
	6, 6, 5, 5, 4, 4, 3, 3,
	7, 2, 2, 6, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 7, 2, 2, 6, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 7, 2, 2, 6, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 7, 2, 2, 6, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3
};


/*
 * EFR TRAU parity
 *
 * g(x) = x^3 + x^1 + 1
 */
static const struct osmo_crc8gen_code gsm0860_efr_crc3 = {
	.bits = 3,
	.poly = 0x3,
	.init = 0x0,
	.remainder = 0x7,
};

/* EFR parity bits */
static inline void efr_parity_bits_1(ubit_t *check_bits, const ubit_t *d_bits)
{
	memcpy(check_bits + 0 , d_bits + 0, 22);
	memcpy(check_bits + 22 , d_bits + 24, 3);
	check_bits[25] = d_bits[28];
}

static inline void efr_parity_bits_2(ubit_t *check_bits, const ubit_t *d_bits)
{
	memcpy(check_bits + 0 , d_bits + 42, 10);
	memcpy(check_bits + 10 , d_bits + 90, 2);
}

static inline void efr_parity_bits_3(ubit_t *check_bits, const ubit_t *d_bits)
{
	memcpy(check_bits + 0 , d_bits + 98, 5);
	check_bits[5] = d_bits[104];
	memcpy(check_bits + 6 , d_bits + 143, 2);
}

static inline void efr_parity_bits_4(ubit_t *check_bits, const ubit_t *d_bits)
{
	memcpy(check_bits + 0 , d_bits + 151, 10);
	memcpy(check_bits + 10 , d_bits + 199, 2);
}

static inline void efr_parity_bits_5(ubit_t *check_bits, const ubit_t *d_bits)
{
	memcpy(check_bits + 0 , d_bits + 207, 5);
	check_bits[5] = d_bits[213];
	memcpy(check_bits + 6 , d_bits + 252, 2);
}

struct map_entry {
	struct llist_head list;
	struct gsm_e1_subslot src, dst;
};

struct upqueue_entry {
	struct llist_head list;
	struct gsm_network *net;
	struct gsm_e1_subslot src;
	uint32_t callref;
};

static LLIST_HEAD(ss_map);
static LLIST_HEAD(ss_upqueue);

void *tall_map_ctx, *tall_upq_ctx;

/* map one particular subslot to another subslot */
int trau_mux_map(const struct gsm_e1_subslot *src,
		 const struct gsm_e1_subslot *dst)
{
	struct map_entry *me;

	me = talloc(tall_map_ctx, struct map_entry);
	if (!me) {
		LOGP(DLMIB, LOGL_FATAL, "Out of memory\n");
		return -ENOMEM;
	}

	DEBUGP(DCC, "Setting up TRAU mux map between (e1=%u,ts=%u,ss=%u) "
		"and (e1=%u,ts=%u,ss=%u)\n",
		src->e1_nr, src->e1_ts, src->e1_ts_ss,
		dst->e1_nr, dst->e1_ts, dst->e1_ts_ss);

	/* make sure to get rid of any stale old mappings */
	trau_mux_unmap(src, 0);
	trau_mux_unmap(dst, 0);

	memcpy(&me->src, src, sizeof(me->src));
	memcpy(&me->dst, dst, sizeof(me->dst));
	llist_add(&me->list, &ss_map);

	return 0;
}

int trau_mux_map_lchan(const struct gsm_lchan *src,	
			const struct gsm_lchan *dst)
{
	struct gsm_e1_subslot *src_ss, *dst_ss;

	src_ss = &src->ts->e1_link;
	dst_ss = &dst->ts->e1_link;

	return trau_mux_map(src_ss, dst_ss);
}


/* unmap one particular subslot from another subslot */
int trau_mux_unmap(const struct gsm_e1_subslot *ss, uint32_t callref)
{
	struct map_entry *me, *me2;
	struct upqueue_entry *ue, *ue2;

	if (ss)
		llist_for_each_entry_safe(me, me2, &ss_map, list) {
			if (!memcmp(&me->src, ss, sizeof(*ss)) ||
			    !memcmp(&me->dst, ss, sizeof(*ss))) {
				llist_del(&me->list);
				return 0;
			}
		}
	llist_for_each_entry_safe(ue, ue2, &ss_upqueue, list) {
		if (ue->callref == callref) {
			llist_del(&ue->list);
			return 0;
		}
		if (ss && !memcmp(&ue->src, ss, sizeof(*ss))) {
			llist_del(&ue->list);
			return 0;
		}
	}
	return -ENOENT;
}

/* look-up an enty in the TRAU mux map */
static struct gsm_e1_subslot *
lookup_trau_mux_map(const struct gsm_e1_subslot *src)
{
	struct map_entry *me;

	llist_for_each_entry(me, &ss_map, list) {
		if (!memcmp(&me->src, src, sizeof(*src)))
			return &me->dst;
		if (!memcmp(&me->dst, src, sizeof(*src)))
			return &me->src;
	}
	return NULL;
}

/* look-up an enty in the TRAU upqueue */
struct upqueue_entry *
lookup_trau_upqueue(const struct gsm_e1_subslot *src)
{
	struct upqueue_entry *ue;

	llist_for_each_entry(ue, &ss_upqueue, list) {
		if (!memcmp(&ue->src, src, sizeof(*src)))
			return ue;
	}
	return NULL;
}

static const uint8_t c_bits_check_fr[] = { 0, 0, 0, 1, 0 };
static const uint8_t c_bits_check_efr[] = { 1, 1, 0, 1, 0 };

struct msgb *trau_decode_fr(uint32_t callref,
	const struct decoded_trau_frame *tf)
{
	struct msgb *msg;
	struct gsm_data_frame *frame;
	unsigned char *data;
	int i, j, k, l, o;

	msg = msgb_alloc(sizeof(struct gsm_data_frame) + 33,
				 "GSM-DATA");
	if (!msg)
		return NULL;

	frame = (struct gsm_data_frame *)msg->data;
	memset(frame, 0, sizeof(struct gsm_data_frame));
	data = frame->data;
	data[0] = 0xd << 4;
	/* reassemble d-bits */
	i = 0; /* counts bits */
	j = 4; /* counts output bits */
	k = gsm_fr_map[0]-1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset input bits */
	while (i < 260) {
		data[j/8] |= (tf->d_bits[k+o] << (7-(j%8)));
		/* to avoid out-of-bounds access in gsm_fr_map[++l] */
		if (i == 259)
			break;
		if (--k < 0) {
			o += gsm_fr_map[l];
			k = gsm_fr_map[++l]-1;
		}
		i++;
		j++;
	}
	if (tf->c_bits[11]) /* BFI */
		frame->msg_type = GSM_BAD_FRAME;
	else
		frame->msg_type = GSM_TCHF_FRAME;
	frame->callref = callref;
	msgb_put(msg, sizeof(struct gsm_data_frame) + 33);

	return msg;
}

struct msgb *trau_decode_efr(uint32_t callref,
	const struct decoded_trau_frame *tf)
{
	struct msgb *msg;
	struct gsm_data_frame *frame;
	unsigned char *data;
	int i, j, rc;
	ubit_t check_bits[26];

	msg = msgb_alloc(sizeof(struct gsm_data_frame) + 31,
				 "GSM-DATA");
	if (!msg)
		return NULL;

	frame = (struct gsm_data_frame *)msg->data;
	memset(frame, 0, sizeof(struct gsm_data_frame));
	frame->msg_type = GSM_TCHF_FRAME_EFR;
	frame->callref = callref;
	msgb_put(msg, sizeof(struct gsm_data_frame) + 31);

	if (tf->c_bits[11]) /* BFI */
		goto bad_frame;

	data = frame->data;
	data[0] = 0xc << 4;
	/* reassemble d-bits */
	for (i = 1, j = 4; i < 39; i++, j++)
		data[j/8] |= (tf->d_bits[i] << (7-(j%8)));
	efr_parity_bits_1(check_bits, tf->d_bits);
	rc = osmo_crc8gen_check_bits(&gsm0860_efr_crc3, check_bits, 26,
			tf->d_bits + 39);
	if (rc)
		goto bad_frame;
	for (i = 42, j = 42; i < 95; i++, j++)
		data[j/8] |= (tf->d_bits[i] << (7-(j%8)));
	efr_parity_bits_2(check_bits, tf->d_bits);
	rc = osmo_crc8gen_check_bits(&gsm0860_efr_crc3, check_bits, 12,
			tf->d_bits + 95);
	if (rc)
		goto bad_frame;
	for (i = 98, j = 95; i < 148; i++, j++)
		data[j/8] |= (tf->d_bits[i] << (7-(j%8)));
	efr_parity_bits_3(check_bits, tf->d_bits);
	rc = osmo_crc8gen_check_bits(&gsm0860_efr_crc3, check_bits, 8,
			tf->d_bits + 148);
	if (rc)
		goto bad_frame;
	for (i = 151, j = 145; i < 204; i++, j++)
		data[j/8] |= (tf->d_bits[i] << (7-(j%8)));
	efr_parity_bits_4(check_bits, tf->d_bits);
	rc = osmo_crc8gen_check_bits(&gsm0860_efr_crc3, check_bits, 12,
			tf->d_bits + 204);
	if (rc)
		goto bad_frame;
	for (i = 207, j = 198; i < 257; i++, j++)
		data[j/8] |= (tf->d_bits[i] << (7-(j%8)));
	efr_parity_bits_5(check_bits, tf->d_bits);
	rc = osmo_crc8gen_check_bits(&gsm0860_efr_crc3, check_bits, 8,
			tf->d_bits + 257);
	if (rc)
		goto bad_frame;

	return msg;

bad_frame:
	frame->msg_type = GSM_BAD_FRAME;

	return msg;
}

/* we get called by subchan_demux */
int trau_mux_input(struct gsm_e1_subslot *src_e1_ss,
		   const uint8_t *trau_bits, int num_bits)
{
	struct decoded_trau_frame tf;
	uint8_t trau_bits_out[TRAU_FRAME_BITS];
	struct gsm_e1_subslot *dst_e1_ss = lookup_trau_mux_map(src_e1_ss);
	struct subch_mux *mx;
	struct upqueue_entry *ue;
	int rc;

	/* decode TRAU, change it to downlink, re-encode */
	rc = decode_trau_frame(&tf, trau_bits);
	if (rc)
		return rc;

	if (!dst_e1_ss) {
		struct msgb *msg = NULL;
		/* frame shall be sent to upqueue */
		if (!(ue = lookup_trau_upqueue(src_e1_ss)))
			return -EINVAL;
		if (!ue->callref)
			return -EINVAL;
		if (!memcmp(tf.c_bits, c_bits_check_fr, 5))
			msg = trau_decode_fr(ue->callref, &tf);
		else if (!memcmp(tf.c_bits, c_bits_check_efr, 5))
			msg = trau_decode_efr(ue->callref, &tf);
		else {
			DEBUGPC(DLMUX, "illegal trau (C1-C5) %s\n",
				osmo_hexdump(tf.c_bits, 5));
			DEBUGPC(DLMUX, "test trau (C1-C5) %s\n",
				osmo_hexdump(c_bits_check_efr, 5));
			return -EINVAL;
		}
		if (!msg)
			return -ENOMEM;
		trau_tx_to_mncc(ue->net, msg);

		return 0;
	}

	mx = e1inp_get_mux(dst_e1_ss->e1_nr, dst_e1_ss->e1_ts);
	if (!mx)
		return -EINVAL;

	trau_frame_up2down(&tf);
	encode_trau_frame(trau_bits_out, &tf);

	/* and send it to the muxer */
	return subchan_mux_enqueue(mx, dst_e1_ss->e1_ts_ss, trau_bits_out,
				   TRAU_FRAME_BITS);
}

/* callback when a TRAU frame was received */
int subch_cb(struct subch_demux *dmx, int ch, uint8_t *data, int len,
	     void *_priv)
{
	struct e1inp_ts *e1i_ts = _priv;
	struct gsm_e1_subslot src_ss;

	src_ss.e1_nr = e1i_ts->line->num;
	src_ss.e1_ts = e1i_ts->num;
	src_ss.e1_ts_ss = ch;

	return trau_mux_input(&src_ss, data, len);
}

/* add receiver instance for lchan and callref */
int trau_recv_lchan(struct gsm_lchan *lchan, uint32_t callref)
{
	struct gsm_e1_subslot *src_ss;
	struct upqueue_entry *ue;

	ue = talloc(tall_upq_ctx, struct upqueue_entry);
	if (!ue)
		return -ENOMEM;

	src_ss = &lchan->ts->e1_link;

	DEBUGP(DCC, "Setting up TRAU receiver (e1=%u,ts=%u,ss=%u) "
		"and (callref 0x%x)\n",
		src_ss->e1_nr, src_ss->e1_ts, src_ss->e1_ts_ss,
		callref);

	/* make sure to get rid of any stale old mappings */
	trau_mux_unmap(src_ss, callref);

	memcpy(&ue->src, src_ss, sizeof(ue->src));
	ue->net = lchan->ts->trx->bts->network;
	ue->callref = callref;
	llist_add(&ue->list, &ss_upqueue);

	return 0;
}

void trau_encode_fr(struct decoded_trau_frame *tf,
	const unsigned char *data)
{
	int i, j, k, l, o;

	/* set c-bits and t-bits */
	tf->c_bits[0] = 1;
	tf->c_bits[1] = 1;
	tf->c_bits[2] = 1;
	tf->c_bits[3] = 0;
	tf->c_bits[4] = 0;
	memset(&tf->c_bits[5], 0, 6);
	memset(&tf->c_bits[11], 1, 10);
	memset(&tf->t_bits[0], 1, 4);
	/* reassemble d-bits */
	i = 0; /* counts bits */
	j = 4; /* counts input bits */
	k = gsm_fr_map[0]-1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset output bits */
	while (i < 260) {
		tf->d_bits[k+o] = (data[j/8] >> (7-(j%8))) & 1;
		/* to avoid out-of-bounds access in gsm_fr_map[++l] */
		if (i == 259)
			break;
		if (--k < 0) {
			o += gsm_fr_map[l];
			k = gsm_fr_map[++l]-1;
		}
		i++;
		j++;
	}
}

void trau_encode_efr(struct decoded_trau_frame *tf,
	const unsigned char *data)
{
	int i, j;
	ubit_t check_bits[26];

	/* set c-bits and t-bits */
	tf->c_bits[0] = 1;
	tf->c_bits[1] = 1;
	tf->c_bits[2] = 0;
	tf->c_bits[3] = 1;
	tf->c_bits[4] = 0;
	memset(&tf->c_bits[5], 0, 6);
	memset(&tf->c_bits[11], 1, 10);
	memset(&tf->t_bits[0], 1, 4);
	/* reassemble d-bits */
	tf->d_bits[0] = 1;
	for (i = 1, j = 4; i < 39; i++, j++)
		tf->d_bits[i] = (data[j/8] >> (7-(j%8))) & 1;
	efr_parity_bits_1(check_bits, tf->d_bits);
	osmo_crc8gen_set_bits(&gsm0860_efr_crc3, check_bits, 26,
			tf->d_bits + 39);
	for (i = 42, j = 42; i < 95; i++, j++)
		tf->d_bits[i] = (data[j/8] >> (7-(j%8))) & 1;
	efr_parity_bits_2(check_bits, tf->d_bits);
	osmo_crc8gen_set_bits(&gsm0860_efr_crc3, check_bits, 12,
			tf->d_bits + 95);
	for (i = 98, j = 95; i < 148; i++, j++)
		tf->d_bits[i] = (data[j/8] >> (7-(j%8))) & 1;
	efr_parity_bits_3(check_bits, tf->d_bits);
	osmo_crc8gen_set_bits(&gsm0860_efr_crc3, check_bits, 8,
			tf->d_bits + 148);
	for (i = 151, j = 145; i < 204; i++, j++)
		tf->d_bits[i] = (data[j/8] >> (7-(j%8))) & 1;
	efr_parity_bits_4(check_bits, tf->d_bits);
	osmo_crc8gen_set_bits(&gsm0860_efr_crc3, check_bits, 12,
			tf->d_bits + 204);
	for (i = 207, j = 198; i < 257; i++, j++)
		tf->d_bits[i] = (data[j/8] >> (7-(j%8))) & 1;
	efr_parity_bits_5(check_bits, tf->d_bits);
	osmo_crc8gen_set_bits(&gsm0860_efr_crc3, check_bits, 8,
			tf->d_bits + 257);
}

int trau_send_frame(struct gsm_lchan *lchan, struct gsm_data_frame *frame)
{
	uint8_t trau_bits_out[TRAU_FRAME_BITS];
	struct gsm_e1_subslot *dst_e1_ss = &lchan->ts->e1_link;
	struct subch_mux *mx;
	struct decoded_trau_frame tf;

	mx = e1inp_get_mux(dst_e1_ss->e1_nr, dst_e1_ss->e1_ts);
	if (!mx)
		return -EINVAL;

	switch (frame->msg_type) {
	case GSM_TCHF_FRAME:
		trau_encode_fr(&tf, frame->data);
		break;
	case GSM_TCHF_FRAME_EFR:
		trau_encode_efr(&tf, frame->data);
		break;
	default:
		DEBUGPC(DLMUX, "unsupported message type %d\n",
			frame->msg_type);
		return -EINVAL;
	}

	encode_trau_frame(trau_bits_out, &tf);

	/* and send it to the muxer */
	return subchan_mux_enqueue(mx, dst_e1_ss->e1_ts_ss, trau_bits_out,
				   TRAU_FRAME_BITS);
}

/* switch trau muxer to new lchan */
int switch_trau_mux(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan)
{
	struct gsm_network *net = old_lchan->ts->trx->bts->network;
	struct gsm_trans *trans;

	/* look up transaction with TCH frame receive enabled */
	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->conn && trans->conn->lchan == old_lchan && trans->tch_recv) {
			/* switch */
			trau_recv_lchan(new_lchan, trans->callref);
		}
	}

	return 0;
}
