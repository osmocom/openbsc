/* (C) 2017 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

/* Create and start state machine which handles the reset/reset-ack procedure */
void start_reset_fsm(struct bsc_msc_data *msc);

/* Confirm that we sucessfully received a reset acknowlege message */
void reset_ack_confirm(struct bsc_msc_data *msc);

/* Report a failed connection */
void report_conn_fail(struct bsc_msc_data *msc);

/* Report a successful connection */
void report_conn_success(struct bsc_msc_data *msc);

/* Check if we have a connection to a specified msc */
bool sccp_conn_ready(struct bsc_msc_data *msc);
