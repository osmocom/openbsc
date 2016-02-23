/* SNMP-like status interface. Look-up of BTS/TRX
 *
 * (C) 2010-2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2010-2011 by On-Waves
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <errno.h>

#include <osmocom/vty/command.h>
#include <osmocom/ctrl/control_if.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>

extern vector ctrl_node_vec;

/*! \brief control interface lookup function for bsc/bts gsm_data
 * \param[in] data Private data passed to controlif_setup()
 * \param[in] vline Vector of the line holding the command string
 * \param[out] node_type type (CTRL_NODE_) that was determined
 * \param[out] node_data private dta of node that was determined
 * \param i Current index into vline, up to which it is parsed
 */
static int bsc_ctrl_node_lookup(void *data, vector vline, int *node_type,
				void **node_data, int *i)
{
	struct gsm_network *net = data;
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	char *token = vector_slot(vline, *i);
	long num;

	/* TODO: We need to make sure that the following chars are digits
	 * and/or use strtol to check if number conversion was successful
	 * Right now something like net.bts_stats will not work */
	if (!strcmp(token, "bts")) {
		if (*node_type != CTRL_NODE_ROOT || !net)
			goto err_missing;
		(*i)++;
		if (!ctrl_parse_get_num(vline, *i, &num))
			goto err_index;

		bts = gsm_bts_num(net, num);
		if (!bts)
			goto err_missing;
		*node_data = bts;
		*node_type = CTRL_NODE_BTS;
	} else if (!strcmp(token, "trx")) {
		if (*node_type != CTRL_NODE_BTS || !*node_data)
			goto err_missing;
		bts = *node_data;
		(*i)++;
		if (!ctrl_parse_get_num(vline, *i, &num))
			goto err_index;

		trx = gsm_bts_trx_num(bts, num);
		if (!trx)
			goto err_missing;
		*node_data = trx;
		*node_type = CTRL_NODE_TRX;
	} else if (!strcmp(token, "ts")) {
		if (*node_type != CTRL_NODE_TRX || !*node_data)
			goto err_missing;
		trx = *node_data;
		(*i)++;
		if (!ctrl_parse_get_num(vline, *i, &num))
			goto err_index;

		if ((num >= 0) && (num < TRX_NR_TS))
			ts = &trx->ts[num];
		if (!ts)
			goto err_missing;
		*node_data = ts;
		*node_type = CTRL_NODE_TS;
	} else
		return 0;

	return 1;
err_missing:
	return -ENODEV;
err_index:
	return -ERANGE;
}

struct ctrl_handle *bsc_controlif_setup(struct gsm_network *net,
					const char *bind_addr, uint16_t port)
{
	return ctrl_interface_setup_dynip(net, bind_addr, port,
					  bsc_ctrl_node_lookup);
}
