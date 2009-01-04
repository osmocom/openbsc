/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
/*
 * I'm lazy and will not introduce lemon to this game. Our telnet
 * interface is matching line based so we can have a pattern that
 * is matching a line and everyone will be happy.
 */

%option never-interactive
%option noyywrap
%option	reentrant

%{
#include <string.h>
#include <openbsc/telnet_interface.h>

extern char *strndup(const char *s, size_t n);
extern void telnet_write_help(int);
extern void telnet_close_client(struct bsc_fd*);
extern void telnet_error_client(int fd);
extern void telnet_page(struct telnet_connection *con, const char *imsi, int page);
extern void telnet_call(struct telnet_connection *con, const char *imsi,
			const char* origin);
extern void telnet_put_channel(struct telnet_connection*, const char *imsi);
extern void telnet_get_channel(struct telnet_connection*, const char *imsi);
extern void telnet_send_gsm_48(struct telnet_connection*);
extern void telnet_send_gsm_11(struct telnet_connection*);
extern void telnet_list_channels(struct telnet_connection*);

static const int PAGE_LEN = 5; /* "page " */
static const int CALL_LEN = 5; /* "call " */
static const int PUT_LEN = 12; /* "put_channel " */
static const int GET_LEN = 12; /* "get_channel " */
static const int NET_LEN = 3;  /* "48 " "11 " */
static const int SHOW_LEN = 5; /* "show " */

#define YY_EXTRA_TYPE struct telnet_connection*

/* the string is null terminated */
static int parse_hex(char *hex)
{
	int byte;
	sscanf(hex, "%x", &byte);
	return byte;
}

#define PREPARE_STRING(len) \
		yytext[yyleng-1] = '\0'; \
                char *str = yytext + len; \
		char *pag = strstr(str, "\r"); \
		if (pag) pag[0] = '\0'; \
		pag = strstr(str, "\n"); \
		if (pag) pag[0] = '\0';

%}

CMD_HELP	"help"
CMD_EXIT	"exit"
CMD_CLOSE	"close"
CMD_PAGE	"page"
CMD_GET_CHANNEL	"get_channel"
CMD_PUT_CHANNEL "put_channel"
CMD_CALL	"call"
CMD_48		"48"
CMD_11		"11"
CMD_SHOW	"show"

LINE_END	\n|\r\n
HEX		[0][x][0-9a-zA-Z][0-9a-zA-Z]

%s  READ_HEX_BYTES

%%
{CMD_HELP}{LINE_END}		{telnet_write_help(yyextra->fd.fd); yyterminate();}
{CMD_EXIT}{LINE_END}		{telnet_close_client(&yyextra->fd); yyterminate();}
{CMD_CLOSE}{LINE_END}		{telnet_close_client(&yyextra->fd); yyterminate();}
{CMD_SHOW}{LINE_END}		{telnet_list_channels(yyextra); yyterminate();}
{CMD_PAGE}[ ][0-9]+{LINE_END} {
				    PREPARE_STRING(PAGE_LEN)
                                    telnet_page(yyextra, str, 0);
				    yyterminate();
				}
{CMD_PAGE}[ ][0-9]+[ ][0-2]{LINE_END} {
				    PREPARE_STRING(PAGE_LEN)
				    char *sp = strstr(str, " ");
				    sp[0] = '\0';
                                    telnet_page(yyextra, str, atoi(sp+1));
				    yyterminate();
				}
{CMD_PUT_CHANNEL}[ ][0-9]+{LINE_END} {
				    PREPARE_STRING(PUT_LEN)
                                    telnet_put_channel(yyextra, str);
				    yyterminate();
				}
{CMD_GET_CHANNEL}[ ][0-9]+{LINE_END} {
				    PREPARE_STRING(GET_LEN)
                                    telnet_get_channel(yyextra, str);
				    yyterminate();
				}
{CMD_CALL}[ ][0-9]+[ ][0-9]+{LINE_END} {
				    PREPARE_STRING(CALL_LEN)
				    char *sp = strstr(str, " ");
				    sp[0] = '\0';
                                    telnet_call(yyextra, str, sp+1);
				    yyterminate();
				}
{CMD_CALL}[ ][0-9]+{LINE_END} {
				    PREPARE_STRING(CALL_LEN)
                                    telnet_call(yyextra, str, NULL);
				    yyterminate();
				}
<READ_HEX_BYTES>{HEX}		{
				    if (yyextra->read >= sizeof(yyextra->commands)) {
					yyterminate();
				    }
				    yytext[yyleng] = '\0';
				    yyextra->commands[yyextra->read++] = parse_hex(yytext+2);
				}
<READ_HEX_BYTES>{LINE_END}	{
				    if (yyextra->command == TELNET_COMMAND_11) {
					telnet_send_gsm_11(yyextra);
				    } else if (yyextra->command == TELNET_COMMAND_48) {
					telnet_send_gsm_48(yyextra);
				    }

				    if (yyextra->imsi) {
					free(yyextra->imsi);
					yyextra->imsi = NULL;
				    }
				    yyterminate();
				}
<INITIAL>{CMD_48}[ ][0-9]+	{
				    BEGIN READ_HEX_BYTES;
				    yyextra->read = 0;
				    yyextra->command = TELNET_COMMAND_48;
				    yytext[yyleng-1] = '\0';
				    yyextra->imsi = strdup(yytext);
				}

<INITIAL>{CMD_11}[ ][0-9]+	{
				    BEGIN READ_HEX_BYTES;
				    yyextra->read = 0;
				    yyextra->command = TELNET_COMMAND_11;
				    yytext[yyleng-1] = '\0';
				    yyextra->imsi = strdup(yytext);
				}



[ \t\r\n]			/* Ommit */
.				{ telnet_error_client(yyextra->fd.fd); yyterminate(); }

%%

void telnet_parse(struct telnet_connection *conn, char *buf)
{
	yyscan_t scanner;
	yylex_init(&scanner);
	yyset_extra(conn, scanner);
	yy_scan_string(buf, scanner);
	yylex(scanner);
	yylex_destroy(scanner);

	if (conn->imsi) {
		free(conn->imsi);
		conn->imsi = NULL;
	}
}

__attribute__((unused)) void telnet_unused(void)
{
	yyunput(0, 0, 0);
	input(0);
}
