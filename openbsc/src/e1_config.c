#include <string.h>
#include <errno.h>

#include <netinet/in.h>

#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/misdn.h>
#include <openbsc/ipaccess.h>
#include <openbsc/talloc.h>

#define SAPI_L2ML	0
#define SAPI_OML	62
#define SAPI_RSL	0	/* 63 ? */

/* The e1_reconfig_*() functions below tale the configuration present in the
 * bts/trx/ts data structures and ensure the E1 configuration reflects the
 * timeslot/subslot/TEI configuration */

int e1_reconfig_ts(struct gsm_bts_trx_ts *ts)
{
	struct gsm_e1_subslot *e1_link = &ts->e1_link;
	struct e1inp_line *line;
	struct e1inp_ts *e1_ts;

	printf("e1_reconfig_ts(%u,%u,%u)\n", ts->trx->bts->nr, ts->trx->nr, ts->nr);

	if (!e1_link->e1_ts)
		return 0;

	line = e1inp_line_get_create(e1_link->e1_nr);
	if (!line)
		return -ENOMEM;

	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
		e1_ts = &line->ts[e1_link->e1_ts-1];
		e1inp_ts_config(e1_ts, line, E1INP_TS_TYPE_TRAU);
		subch_demux_activate(&e1_ts->trau.demux, e1_link->e1_ts_ss);
		break;
	default:
		break;
	}

	return 0;
}

int e1_reconfig_trx(struct gsm_bts_trx *trx)
{
	struct gsm_e1_subslot *e1_link = &trx->rsl_e1_link;
	struct e1inp_ts *sign_ts;
	struct e1inp_line *line;
	struct e1inp_sign_link *rsl_link;
	int i;

	if (!e1_link->e1_ts)
		return -EINVAL;

	/* RSL Link */
	line = e1inp_line_get_create(e1_link->e1_nr);
	if (!line)
		return -ENOMEM;
	sign_ts = &line->ts[e1_link->e1_ts-1];
	e1inp_ts_config(sign_ts, line, E1INP_TS_TYPE_SIGN);
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, trx->rsl_tei, SAPI_RSL);
	if (!rsl_link)
		return -ENOMEM;
	if (trx->rsl_link)
		e1inp_sign_link_destroy(trx->rsl_link);
	trx->rsl_link = rsl_link;

	for (i = 0; i < TRX_NR_TS; i++)
		e1_reconfig_ts(&trx->ts[i]);

	return 0;
}

int e1_reconfig_bts(struct gsm_bts *bts)
{
	struct gsm_e1_subslot *e1_link = &bts->oml_e1_link;
	struct e1inp_ts *sign_ts;
	struct e1inp_line *line;
	struct e1inp_sign_link *oml_link;
	struct gsm_bts_trx *trx;

	printf("e1_reconfig_bts(%u)\n", bts->nr);

	if (!e1_link->e1_ts)
		return -EINVAL;

	/* OML link */
	line = e1inp_line_get_create(e1_link->e1_nr);
	if (!line)
		return -ENOMEM;
	sign_ts = &line->ts[e1_link->e1_ts-1];
	e1inp_ts_config(sign_ts, line, E1INP_TS_TYPE_SIGN);
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, bts->oml_tei, SAPI_OML);
	if (!oml_link)
		return -ENOMEM;
	if (bts->oml_link)
		e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = oml_link;

	llist_for_each_entry(trx, &bts->trx_list, list)
		e1_reconfig_trx(trx);

	/* notify E1 input something has changed */
	return e1inp_line_update(line);
}

#if 0
/* do some compiled-in configuration for our BTS/E1 setup */
int e1_config(struct gsm_bts *bts, int cardnr, int release_l2)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts;
	struct e1inp_sign_link *oml_link, *rsl_link;
	struct gsm_bts_trx *trx = bts->c0;
	int base_ts;

	switch (bts->nr) {
	case 0:
		/* First BTS uses E1 TS 01,02,03,04,05 */
		base_ts = HARDCODED_BTS0_TS - 1;
		break;
	case 1:
		/* Second BTS uses E1 TS 06,07,08,09,10 */
		base_ts = HARDCODED_BTS1_TS - 1;
		break;
	case 2:
		/* Third BTS uses E1 TS 11,12,13,14,15 */
		base_ts = HARDCODED_BTS2_TS - 1;
	default:
		return -EINVAL;
	}

	line = talloc_zero(tall_bsc_ctx, struct e1inp_line);
	if (!line)
		return -ENOMEM;

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config(&line->ts[base_ts+1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[base_ts+2-1], line, E1INP_TS_TYPE_TRAU);
	e1inp_ts_config(&line->ts[base_ts+3-1], line, E1INP_TS_TYPE_TRAU);

	/* create signalling links for TS1 */
	sign_ts = &line->ts[base_ts+1-1];
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  trx, TEI_OML, SAPI_OML);
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, TEI_RSL, SAPI_RSL);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	trx->rsl_link = rsl_link;

	/* enable subchannel demuxer on TS2 */
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 1);
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 2);
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 3);

	/* enable subchannel demuxer on TS3 */
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 0);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 1);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 2);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 3);

	trx = gsm_bts_trx_num(bts, 1);
	if (trx) {
		/* create E1 timeslots for TRAU frames of TRX1 */
		e1inp_ts_config(&line->ts[base_ts+4-1], line, E1INP_TS_TYPE_TRAU);
		e1inp_ts_config(&line->ts[base_ts+5-1], line, E1INP_TS_TYPE_TRAU);

		/* create RSL signalling link for TRX1 */
		sign_ts = &line->ts[base_ts+1-1];
		rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, TEI_RSL+1, SAPI_RSL);
		/* create back-links from trx */
		trx->rsl_link = rsl_link;

		/* enable subchannel demuxer on TS2 */
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 0);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 1);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 2);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 3);

		/* enable subchannel demuxer on TS3 */
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 0);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 1);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 2);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 3);
	}

	return mi_setup(cardnr, line, release_l2);
}
#endif

/* configure pseudo E1 line in ip.access style and connect to BTS */
int ia_config_connect(struct gsm_bts *bts, struct sockaddr_in *sin)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts, *rsl_ts;
	struct e1inp_sign_link *oml_link, *rsl_link;

	line = talloc_zero(tall_bsc_ctx, struct e1inp_line);
	if (!line)
		return -ENOMEM;

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config(&line->ts[1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[2-1], line, E1INP_TS_TYPE_SIGN);

	/* create signalling links for TS1 */
	sign_ts = &line->ts[1-1];
	rsl_ts = &line->ts[2-1];
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, 0xff, 0);
	rsl_link = e1inp_sign_link_create(rsl_ts, E1INP_SIGN_RSL,
					  bts->c0, 0, 0);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	bts->c0->rsl_link = rsl_link;

	/* default port at BTS for incoming connections is 3006 */
	if (sin->sin_port == 0)
		sin->sin_port = htons(3006);

	return ipaccess_connect(line, sin);
}
