#include <string.h>
#include <errno.h>

#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/trau_mux.h>

#define SAPI_L2ML	0
#define SAPI_OML	62
#define SAPI_RSL	0	/* 63 ? */

#define TEI_L2ML	127
#define TEI_OML		25
#define TEI_RSL		1

/* do some compiled-in configuration for our BTS/E1 setup */
int e1_config(struct gsm_bts *bts)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts;
	struct e1inp_sign_link *oml_link, *rsl_link;

	line = malloc(sizeof(*line));
	if (!line)
		return -ENOMEM;
	memset(line, 0, sizeof(*line));

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config(&line->ts[1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[2-1], line, E1INP_TS_TYPE_TRAU);
	//e1inp_ts_config(&line->ts[3-1], line, E1INP_TS_TYPE_TRAU);

	/* create signalling links for TS1 */
	sign_ts = &line->ts[1-1];
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, TEI_OML, SAPI_OML);
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  bts->c0, TEI_RSL, SAPI_RSL);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	bts->c0->rsl_link = rsl_link;

	/* configure a static mapping between on-air TS1 and TS2
	 * since we don't yet have code to dynamically switch the
	 * voice channels */
	{
		struct gsm_e1_subslot src_ss, dst_ss;
		src_ss.e1_nr = dst_ss.e1_nr = 0;
		src_ss.e1_ts = dst_ss.e1_ts = 2;
		src_ss.e1_ts_ss = 1; dst_ss.e1_ts_ss = 2;
		trau_mux_map(&src_ss, &dst_ss);

		subch_demux_activate(&line->ts[2-1].trau.demux, 1);
		subch_demux_activate(&line->ts[2-1].trau.demux, 2);
	}
#ifdef HAVE_TRX1
	/* create E1 timeslots for TRAU frames of TRX1 */
	e1inp_ts_config(&line->ts[4-1], line, E1INP_TS_TYPE_TRAU);
	e1inp_ts_config(&line->ts[5-1], line, E1INP_TS_TYPE_TRAU);

	/* create RSL signalling link for TRX1 */
	sign_ts = &line->ts[1-1];
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  &bts->trx[1], TEI_RSL+1, SAPI_RSL);
	/* create back-links from trx */
	bts->trx[1].rsl_link = rsl_link;
#endif

	return mi_setup(0, line, NULL);
}

/* do some compiled-in configuration for our BTS/E1 setup */
int ia_config(struct gsm_bts *bts)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts, *rsl_ts;
	struct e1inp_sign_link *oml_link, *rsl_link;

	line = malloc(sizeof(*line));
	if (!line)
		return -ENOMEM;
	memset(line, 0, sizeof(*line));

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config(&line->ts[1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[2-1], line, E1INP_TS_TYPE_SIGN);

	/* create signalling links for TS1 */
	sign_ts = &line->ts[1-1];
	rsl_ts = &line->ts[2-1];
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, 0, 0xff);
	rsl_link = e1inp_sign_link_create(rsl_ts, E1INP_SIGN_RSL,
					  bts->c0, 0, 0);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	bts->c0->rsl_link = rsl_link;

	return ipaccess_setup(line);
}
