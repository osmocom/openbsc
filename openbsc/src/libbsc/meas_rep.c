/* Measurement Report Processing */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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


#include <openbsc/gsm_data.h>
#include <openbsc/meas_rep.h>

static int get_field(const struct gsm_meas_rep *rep,
		     enum meas_rep_field field)
{
	switch (field) {
	case MEAS_REP_DL_RXLEV_FULL:
		return rep->dl.full.rx_lev;
	case MEAS_REP_DL_RXLEV_SUB:
		return rep->dl.sub.rx_lev;
	case MEAS_REP_DL_RXQUAL_FULL:
		return rep->dl.full.rx_qual;
	case MEAS_REP_DL_RXQUAL_SUB:
		return rep->dl.sub.rx_qual;
	case MEAS_REP_UL_RXLEV_FULL:
		return rep->ul.full.rx_lev;
	case MEAS_REP_UL_RXLEV_SUB:
		return rep->ul.sub.rx_lev;
	case MEAS_REP_UL_RXQUAL_FULL:
		return rep->ul.full.rx_qual;
	case MEAS_REP_UL_RXQUAL_SUB:
		return rep->ul.sub.rx_qual;
	}

	return 0;
}


unsigned int calc_initial_idx(unsigned int array_size,
			      unsigned int meas_rep_idx,
			      unsigned int num_values)
{
	int offs, idx;

	/* from which element do we need to start if we're interested
	 * in an average of 'num' elements */
	offs = meas_rep_idx - num_values;

	if (offs < 0)
		idx = array_size + offs;
	else
		idx = offs;

	return idx;
}

/* obtain an average over the last 'num' fields in the meas reps */
int get_meas_rep_avg(const struct gsm_lchan *lchan,
		     enum meas_rep_field field, unsigned int num)
{
	unsigned int i, idx;
	int avg = 0;

	if (num < 1)
		return 0;

	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
				lchan->meas_rep_idx, num);

	for (i = 0; i < num; i++) {
		int j = (idx+i) % ARRAY_SIZE(lchan->meas_rep);

		avg += get_field(&lchan->meas_rep[j], field);
	}

	return avg / num;
}

/* Check if N out of M last values for FIELD are >= bd */
int meas_rep_n_out_of_m_be(const struct gsm_lchan *lchan,
			enum meas_rep_field field,
			unsigned int n, unsigned int m, int be)
{
	unsigned int i, idx;
	int count = 0;

	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
				lchan->meas_rep_idx, m);

	for (i = 0; i < m; i++) {
		int j = (idx + i) % ARRAY_SIZE(lchan->meas_rep);
		int val = get_field(&lchan->meas_rep[j], field);

		if (val >= be)
			count++;

		if (count >= n)
			return 1;
	}

	return 0;
}
