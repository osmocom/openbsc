/* OpenBSC Iu related interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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

#include <stdlib.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>

#include <openbsc/iu.h>

DEFUN(logging_asn_debug,
      logging_asn_debug_cmd,
      "logging asn1-debug (1|0)",
      LOGGING_STR
      "Log ASN.1 debug messages to stderr\n"
      "Log ASN.1 debug messages to stderr\n"
      "Do not log ASN.1 debug messages to stderr\n")
{
	asn_debug = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(logging_asn_xer_print,
      logging_asn_xer_print_cmd,
      "logging asn1-xer-print (1|0)",
      LOGGING_STR
      "Log human readable representations of all ASN.1 messages to stderr\n"
      "Log decoded ASN.1 messages to stderr\n"
      "Do not log decoded ASN.1 messages to stderr\n")
{
	asn1_xer_print = atoi(argv[0]);
	return CMD_SUCCESS;
}

void iu_vty_init(void)
{
	install_element(CFG_LOG_NODE, &logging_asn_debug_cmd);
	install_element(CFG_LOG_NODE, &logging_asn_xer_print_cmd);
}
