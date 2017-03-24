/*
 * (C) 2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>

static const uint8_t load_config[] = {
	0x42, 0x12, 0x00, 0x08, 0x31, 0x36, 0x38, 0x64,
	0x34, 0x37, 0x32, 0x00, 0x13, 0x00, 0x0b, 0x76,
	0x32, 0x30, 0x30, 0x62, 0x31, 0x34, 0x33, 0x64,
	0x30, 0x00, 0x42, 0x12, 0x00, 0x08, 0x31, 0x36,
	0x38, 0x64, 0x34, 0x37, 0x32, 0x00, 0x13, 0x00,
	0x0b, 0x76, 0x32, 0x30, 0x30, 0x62, 0x31, 0x34,
	0x33, 0x64, 0x31, 0x00
};

static void test_sw_selection(void)
{
	struct abis_nm_sw_desc descr[8], tmp;
	uint16_t len0, len1;
	int rc, pos;

	rc = abis_nm_get_sw_conf(load_config, ARRAY_SIZE(load_config),
				&descr[0], ARRAY_SIZE(descr));
	if (rc != 2) {
		printf("%s(): FAILED to parse the File Id/File version: %d\n",
		       __func__, rc);
		abort();
	}

	len0 = abis_nm_sw_desc_len(&descr[0], true);
	printf("len: %u\n", len0);
	printf("file_id:  %s\n", osmo_hexdump(descr[0].file_id, descr[0].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(descr[0].file_version, descr[0].file_version_len));

	len1 = abis_nm_sw_desc_len(&descr[1], true);
	printf("len: %u\n", len1);
	printf("file_id:  %s\n", osmo_hexdump(descr[1].file_id, descr[1].file_id_len));
	printf("file_ver: %s\n", osmo_hexdump(descr[1].file_version, descr[1].file_version_len));

	/* start */
	pos = abis_nm_select_newest_sw(descr, rc);
	if (pos != 1) {
		printf("Selected the wrong version: %d\n", pos);
		abort();
	}
	printf("SELECTED: %d\n", pos);

	/* shuffle */
	tmp = descr[0];
	descr[0] = descr[1];
	descr[1] = tmp;
	pos = abis_nm_select_newest_sw(descr, rc);
	if (pos != 0) {
		printf("Selected the wrong version: %d\n", pos);
		abort();
	}
	printf("SELECTED: %d\n", pos);
	printf("%s(): OK\n", __func__);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_sw_selection();

	return EXIT_SUCCESS;
}
