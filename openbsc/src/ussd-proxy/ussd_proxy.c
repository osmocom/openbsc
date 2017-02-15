#ifdef HAVE_CONFIG_H
//#include <config.h>
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>

typedef struct context_s context_t;
#define NTA_OUTGOING_MAGIC_T context_t
#define SU_ROOT_MAGIC_T      context_t
#define NUA_MAGIC_T          context_t

typedef struct operation operation_t;
#define NUA_HMAGIC_T         operation_t

#include <sofia-sip/nta.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/su_tag_io.h>
#include <sofia-sip/sl_utils.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/auth_client.h>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/url.h>
#include <sofia-sip/su_log.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm_utils.h>
#include <openbsc/gsm_ussd_map_proto.h>
#include <openbsc/gsm_04_80.h>

#include <iconv.h>

typedef uint32_t sup_tcap_tid_t;


typedef struct isup_connection isup_connection_t;

struct isup_connection {
	context_t      *ctx;

	su_socket_t     isup_conn_socket;
	su_wait_t       isup_conn_event;
	int             isup_register_idx;

	/* osmocom data */

	struct msgb    *pending_msg;
};

typedef enum ss_type {
	TYPE_USSD,
	TYPE_SS_OTHER
} ss_type_t;

struct ussd_session {
	isup_connection_t  *conn;
	sup_tcap_tid_t      ref;

	int                 ms_originated;
	char                extention[32];

	ss_type_t           type;

	uint8_t             ss_code;
	struct ss_request   rigester_msg;
};

struct context_s {
	su_home_t       home[1];
	su_root_t      *root;

	su_socket_t     isup_acc_socket;
	su_wait_t       isup_acc_event;

	nua_t          *nua;

	url_t          *to_url;
	url_t          *self_url;

	su_timer_t     *timer;
	su_duration_t   max_ussd_ses_duration;

	/* iconv data */
	iconv_t*        utf8_to_ucs2;
	iconv_t*        ucs2_to_utf8;

	iconv_t*        utf8_to_latin1;
	iconv_t*        latin1_to_utf8;

	/* Array of isup connections */
	struct isup_connection isup[1];

	/* list of active operations */
	struct llist_head operation_list;
	unsigned operation_count;
	unsigned operations_max;
};


/* Example of operation handle context information structure */
struct operation
{
	struct llist_head list;

	nua_handle_t    *handle;  /* operation handle */
	context_t       *ctx;
	su_time_t        tm_initiated;

	/* protocol specific sessions */
	struct ussd_session ussd;
};

static
int ussd_send_data(operation_t *op, int last, const char* lang, unsigned lang_len,
		   const char* msg, unsigned msg_len);
static
int ussd_send_data_ss(isup_connection_t *conn,
		      uint8_t message_type,
		      const uint8_t *component,
		      uint8_t component_len,
		      uint32_t ref);

static
int ussd_send_reject(isup_connection_t *conn, uint32_t ref, uint8_t invoke_id);

static const char* get_unknown_header(sip_t const *sip, const char *header)
{
	sip_header_t *h = (sip_header_t *)sip->sip_unknown;
	for (; h; h = (sip_header_t *)h->sh_succ) {
		if (strcasecmp(h->sh_unknown->un_name, header) == 0) {
			return h->sh_unknown->un_value;
		}
	}
	return NULL;
}


int sup_server_send(isup_connection_t *conn, struct msgb *msg)
{
	ssize_t sz;

	if (!conn) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_GSUP);
	ipa_msg_push_header(msg, IPAC_PROTO_OSMO);

	LOGP(DLCTRL, LOGL_ERROR,
	     "Sending wire, will send: %s\n", msgb_hexdump(msg));

	// FIXME ugly hack!!!
	// TODO place message in send queue !!!!
	sz = send(conn->isup_conn_socket, msg->data, msg->len, 0);
	msgb_free(msg);

	return ((unsigned)sz == msg->len) ? 0 : -1;
}

static int ussd_parse_xml(const char *xml,
			  unsigned xml_len,
			  const char **lang,
			  unsigned    *lang_len,
			  const char **msg,
			  unsigned    *msg_len)
{
	/* Example of parsing XML
		<?xml version="1.0" encoding="UTF-8"?>
		<ussd-data>
			<language>en</language>
			<ussd-string>Test</ussd-string>
		</ussd-data>
	*/

	// <ussd-data> tag
	char* ussd_data_stag = strstr(xml, "<ussd-data>");
	if (ussd_data_stag == NULL)
		return 0;

	char* ussd_data_etag = strstr(ussd_data_stag, "</ussd-data>");
	if (ussd_data_etag == NULL)
		return 0;

	// <language> tag
	char* ussd_lang_stag = strstr(ussd_data_stag, "<language>");
	if (ussd_lang_stag == NULL)
		return 0;

	char* ussd_lang_etag = strstr(ussd_lang_stag, "</language>");
	if (ussd_lang_etag == NULL)
		return 0;

	// <language> tag
	char* ussd_ussd_stag = strstr(ussd_data_stag, "<ussd-string>");
	if (ussd_ussd_stag == NULL)
		return 0;

	char* ussd_ussd_etag = strstr(ussd_ussd_stag, "</ussd-string>");
	if (ussd_ussd_etag == NULL)
		return 0;

	if (ussd_ussd_etag - xml > xml_len || ussd_lang_etag - xml > xml_len)
		return 0;

	*lang = ussd_lang_stag + strlen("<language>");
	*lang_len = ussd_lang_etag - *lang;

	*msg = ussd_ussd_stag + strlen("<ussd-string>");
	*msg_len = ussd_ussd_etag - *msg;

	return 1;
}

// Operation APIs
static operation_t* operation_find_by_tid(context_t* ctx, sup_tcap_tid_t ref)
{
	operation_t* op;
	llist_for_each_entry(op, &ctx->operation_list, list) {
		if (op->ussd.ref == ref)
			return op;
	}
	return NULL;
}

static operation_t* operation_alloc(context_t* ctx)
{
	operation_t* op;

	if (ctx->operation_count >= ctx->operations_max) {
		fprintf(stderr, "!!! maximum number of active session is reached: %d\n",
			ctx->operation_count);
		return NULL;
	}

	/* create operation context information */
	op = su_zalloc(ctx->home, (sizeof *op));
	if (!op) {
		return NULL;
	}

	op->ctx = ctx;
	op->tm_initiated = su_now();
	INIT_LLIST_HEAD(&op->list);
	llist_add_tail(&op->list, &ctx->operation_list);
	ctx->operation_count++;

	return op;
}

static void operation_destroy(operation_t* op)
{
	/* release operation handle */
	nua_handle_destroy(op->handle);
	op->handle = NULL;

	llist_del(&op->list);
	op->ctx->operation_count--;

	if (op->ussd.type == TYPE_USSD) {
		fprintf(stderr, "--- operation %*.s from %s destroyed (sessions: %d)\n",
			op->ussd.rigester_msg.ussd_text_len,
			op->ussd.rigester_msg.ussd_text,
			op->ussd.extention,
			op->ctx->operation_count);
	} else {
		fprintf(stderr, "--- operation 0x%02x from %s destroyed (sessions: %d)\n",
			op->ussd.ss_code,
			op->ussd.extention,
			op->ctx->operation_count);
	}

	/* release operation context information */
	su_free(op->ctx->home, op);
}

void proxy_r_invite(int           status,
		    char const   *phrase,
		    nua_t        *nua,
		    nua_magic_t  *magic,
		    nua_handle_t *nh,
		    nua_hmagic_t *hmagic,
		    sip_t const  *sip,
		    tagi_t        tags[])
{
	fprintf(stderr, "*** Got reply %d for INVITE\n", status);
	if (status == 200) {
		nua_ack(nh, TAG_END());
	} else if (hmagic->ussd.type == TYPE_USSD) {
		printf("response to USSD INVITE: %03d %s\n", status, phrase);

		ussd_send_reject(hmagic->ussd.conn,
				 hmagic->ussd.ref,
				 hmagic->ussd.rigester_msg.invoke_id);
		operation_destroy(hmagic);
	} else {
		printf("response to SS INVITE: %03d %s\n", status, phrase);

		ussd_send_data_ss(hmagic->ussd.conn,
				  GSM0480_MTYPE_RELEASE_COMPLETE,
				  NULL,
				  0,
				  hmagic->ussd.ref);
		operation_destroy(hmagic);
	}
}

void proxy_i_bye(int           status,
		 char const   *phrase,
		 nua_t        *nua,
		 nua_magic_t  *magic,
		 nua_handle_t *nh,
		 nua_hmagic_t *hmagic,
		 sip_t const  *sip,
		 tagi_t        tags[])
{
	const char* ri;
	int rc;
	// printf("*** call released:\n%s\n", sip->sip_payload->pl_data);

	ri = get_unknown_header(sip, "Recv-Info");
	if (ri && (strcasecmp(ri, "g.3gpp.ussd") == 0)) {
		/* Parse XML */
		const char *language;
		const char *msg;
		unsigned language_len;
		unsigned msg_len;

		if (ussd_parse_xml(sip->sip_payload->pl_data,
				   sip->sip_payload->pl_len,
				   &language, &language_len,
				   &msg, &msg_len)) {
			printf("=== USSD (%.*s): %.*s\n",
			       language_len, language,
			       msg_len, msg);

			/* Send reply back to SUP */
			// TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			rc = ussd_send_data(hmagic, 1, language, language_len,
					    msg, msg_len);
			if (rc == 0) {
				// Normal shutdown
				operation_destroy(hmagic);
				return;
			}

			fprintf(stderr, "*** unable to send to SUP\n");
		} else {
			fprintf(stderr, "*** unable to parse XML\n");
		}
	}

	fprintf(stderr, "*** response BYE with %d satus is malformed, drop session\n",
		status);
	ussd_send_reject(hmagic->ussd.conn,
			 hmagic->ussd.ref,
			 hmagic->ussd.rigester_msg.invoke_id);
	operation_destroy(hmagic);
}

static
uint8_t get_nibble(uint8_t a)
{
	if (a >= '0' && a <= '9')
		return a-'0';
	else if (a >= 'A' && a <= 'F')
		return a-'A' + 10;
	else if (a >= 'a' && a <= 'f')
		return a-'a' + 10;

	fprintf(stderr, "*** Incorrect nibble deteced: %02x\n", a);
	return 0xff;
}

void proxy_i_bye_ss(int           status,
		    char const   *phrase,
		    nua_t        *nua,
		    nua_magic_t  *magic,
		    nua_handle_t *nh,
		    nua_hmagic_t *hmagic,
		    sip_t const  *sip,
		    tagi_t        tags[])
{
	const char* pl_txt = sip->sip_payload->pl_data;
	unsigned pl_txt_len = sip->sip_payload->pl_len;
	uint8_t buffer[256];
	uint8_t buflen = 0;
	int i;

	for (i = 0; i < pl_txt_len && buflen < sizeof(buffer) - 1; ) {
		uint8_t hi_nibble = pl_txt[i++];
		if (hi_nibble == 0xff || i == pl_txt_len)
			break;
		uint8_t lo_nibble = pl_txt[i++];
		if (lo_nibble == 0xff)
			break;

		buffer[buflen++] = (get_nibble(hi_nibble) << 4) |
				    get_nibble(lo_nibble);
	}

	fprintf(stderr, "got bye_ss %d `%.*s` -> %d bytes\n", pl_txt_len, pl_txt_len, pl_txt, buflen);

	if (buflen > 1) {
		/* ASN.1 length can be 1 or 2 bytes ( >2 isn't possible anyway here ) */
		unsigned len =     (buffer[1] < 0x80) ? buffer[1] : ( (buflen > 2) ? buffer[2] : 0xff);
		unsigned len_len = (buffer[1] < 0x80) ? 1         : buffer[1] - 0x80;

		if (len + 1 + len_len != buflen) {
			fprintf(stderr, "*** parsed %d len, but should be %d (%s)",
				buflen, len_len + 1 + len, pl_txt);
		}
	}

	ussd_send_data_ss(hmagic->ussd.conn,
			  GSM0480_MTYPE_RELEASE_COMPLETE,
			  buffer,
			  buflen,
			  hmagic->ussd.ref);
	operation_destroy(hmagic);
}

void proxy_r_bye(int           status,
		 char const   *phrase,
		 nua_t        *nua,
		 nua_magic_t  *magic,
		 nua_handle_t *nh,
		 nua_hmagic_t *hmagic,
		 sip_t const  *sip,
		 tagi_t        tags[])
{
	fprintf(stderr, "*** Got reply %d for BUY\n", status);
	operation_destroy(hmagic);
}

void proxy_i_error(int           status,
		   char const   *phrase,
		   nua_t        *nua,
		   nua_magic_t  *magic,
		   nua_handle_t *nh,
		   nua_hmagic_t *hmagic,
		   sip_t const  *sip,
		   tagi_t        tags[])
{
#if 0
	if (!hmagic) {
		return;
	}

	fprintf(stderr, "*** error in session with %d satus\n",
		status);
	ussd_send_reject(hmagic->ussd.conn,
			 hmagic->ussd.rigester_msg.invoke_id,
			 hmagic->ussd.rigester_msg.opcode);
	operation_destroy(hmagic);
#endif
}

void proxy_info(int           status,
		char const   *phrase,
		nua_t        *nua,
		nua_magic_t  *magic,
		nua_handle_t *nh,
		nua_hmagic_t *hmagic,
		sip_t const  *sip,
		tagi_t        tags[],
		int           response)
{
	const char* ri;
	int rc;

	// Normal ACK is recieved
	if (response == 1 && status == 200)
		return;

	ri = get_unknown_header(sip, "Recv-Info");
	if (ri && (strcasecmp(ri, "g.3gpp.ussd") == 0)) {
		/* Parse XML */
		const char *language;
		const char *msg;
		unsigned language_len;
		unsigned msg_len;

		if (ussd_parse_xml(sip->sip_payload->pl_data,
				   sip->sip_payload->pl_len,
				   &language, &language_len,
				   &msg, &msg_len)) {
			printf("%s USSD (%.*s): %.*s\n",
			       (response) ? ">>>" : "<<<",
			       language_len, language,
			       msg_len, msg);

			if (hmagic == 0) {
				printf("*** unknown session, ignoring");

				// FIXME this function works only with a dialog!
				nua_respond(nh, 481, "INFO with no session", TAG_END());
				return;
			}

			/* Send reply back to SUP */
			// TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			rc = ussd_send_data(hmagic, 0, language, language_len,
					    msg, msg_len);
			if (rc == 0)
				return;

			fprintf(stderr, "*** unable to send to SUP in INFO\n");
		} else {
			fprintf(stderr, "*** unable to parse XML in INFO\n");
		}
	}

	fprintf(stderr, "*** %s INFO with %d satus is malformed, drop session\n",
		response ? "response" : "request",
		status);
	ussd_send_reject(hmagic->ussd.conn,
			 hmagic->ussd.ref,
			 hmagic->ussd.rigester_msg.invoke_id);
	operation_destroy(hmagic);
}

int ussd_create_xml_latin1(context_t* ctx,
			  char *content, size_t max_len,
			  const char* inbuf_latin1, int buf_len)
{
	const char *language = "en";
	char tmpbuf_utf8[2*MAX_LEN_USSD_STRING];
	unsigned tmpbuf_utf8_len;

	char* inbuf = (char*)inbuf_latin1;
	size_t inleft = buf_len;
	char* outbuf = tmpbuf_utf8;
	size_t outleft = sizeof(tmpbuf_utf8);
	size_t s;

	s = iconv(ctx->latin1_to_utf8, &inbuf, &inleft, &outbuf, &outleft);
	if (s == (size_t)-1) {
		LOGP(DLCTRL, LOGL_ERROR, "Unable to encode latin1 into utf8\n");
		return 0;
	}

	tmpbuf_utf8_len = outbuf - tmpbuf_utf8;

	int content_len = snprintf(content, max_len,
				   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				   "<ussd-data>\n"
				   "<language>%s</language>\n"
				   "<ussd-string>%.*s</ussd-string>\n"
				   "</ussd-data>",
				   language,
				   tmpbuf_utf8_len, tmpbuf_utf8);
	if (content_len > max_len) {
		content[max_len - 1] = 0;
		return 0;
	}
	return 1;
}

static int decode_to_latin1(char* outbuf, unsigned size,
			    const uint8_t* msg, unsigned msg_len, uint8_t lang)
{
	if (lang == 0x0f) {
		return gsm_7bit_decode_n_ussd(outbuf, size, msg, msg_len * 8 / 7);
	} else {
		LOGP(DLCTRL, LOGL_ERROR, "Unknown language: 0x%02x\n", lang);
		return 0;
	}
}

/* URL_RESERVED_CHARS in sofia is not strict enough as in RFC3986 */
#define RFC3986_RESERVED_CHARS "!*'();:@&=+$,/?#[]"

int ss_session_open_mo(operation_t *op,
		       isup_connection_t *conn,
		       const uint8_t* component,
		       uint8_t component_len,
		       uint32_t ref,
		       const char* extention)
{
	char buffer[512+1];
	int i;
	context_t* ctx = op->ctx;
	sip_to_t *to = NULL;
	sip_to_t *from = NULL;
	url_t to_url, from_url;
	char* to_url_str;
	char* from_url_str;

	op->ussd.ref = ref;
	op->ussd.conn = conn;
	op->ussd.ms_originated = 1;
	op->ussd.type = TYPE_SS_OTHER;

	strncpy(op->ussd.extention, extention, sizeof(op->ussd.extention));

	for (i = 0; i < component_len; ++i) {
		uint8_t nibble_h = component[i] >> 4;
		uint8_t nibble_l = component[i] & 0xf;

		buffer[2*i    ] = (nibble_h < 10) ? '0' + nibble_h : 'a' + nibble_h - 10;
		buffer[2*i + 1] = (nibble_l < 10) ? '0' + nibble_l : 'a' + nibble_l - 10;
	}
	buffer[2*i] = 0;

	/* Destination address */
	to_url = *ctx->to_url;
	to_url.url_user = "mapss";
	to_url_str = url_as_string(ctx->home, &to_url);
	if (to_url_str == NULL) {
		goto failed_create_handle;
	}
	to = sip_to_create(ctx->home, (url_string_t *)to_url_str);
	su_free(ctx->home, to_url_str);
	if (!to) {
		goto failed_create_handle;
	}

	/* Source address */
	from_url = *ctx->self_url;
	from_url.url_user = extention;
	from_url_str = url_as_string(ctx->home, &from_url);
	if (from_url_str == NULL) {
		goto failed_create_handle;
	}
	from = sip_from_create(ctx->home, (url_string_t *)from_url_str);
	su_free(ctx->home, from_url_str);
	if (!to) {
		goto failed_create_handle;
	}

	/* create operation handle */
	op->handle = nua_handle(ctx->nua,
				op,
				SIPTAG_TO(to),
				SIPTAG_FROM(from),
				NUTAG_M_USERNAME(extention),
				TAG_END());

	su_free(ctx->home, from);
	su_free(ctx->home, to);
	from = NULL;
	to = NULL;

	if (op->handle == NULL) {
		goto failed_create_handle;
	}

	nua_invite(op->handle,
		   SIPTAG_CONTENT_TYPE_STR("application/map-ss-binary"),
		   SIPTAG_PAYLOAD_STR(buffer),
		   TAG_END());
	return 0;

failed_create_handle:
	if (from != NULL)
		su_free(ctx->home, from);
	if (to != NULL)
		su_free(ctx->home, to);

	return -1;
}

int ussd_session_open_mo(operation_t *op,
			 isup_connection_t *conn,
			 struct ss_request* ss,
			 uint32_t ref,
			 const char* extention)
{
	char content[1024];
	char decoded[MAX_LEN_USSD_STRING + 1];
	char escaped_to[512];
	context_t* ctx = op->ctx;
	sip_to_t *to = NULL;
	sip_to_t *from = NULL;
	url_t to_url, from_url;
	char* to_url_str;
	char* from_url_str;

	int decoded_len;

	op->ussd.ref = ref;
	op->ussd.conn = conn;
	op->ussd.ms_originated = 1;
	op->ussd.type = TYPE_USSD;
	op->ussd.rigester_msg = *ss;
	strncpy(op->ussd.extention, extention, sizeof(op->ussd.extention));

	decoded_len = decode_to_latin1(decoded, MAX_LEN_USSD_STRING,
				       op->ussd.rigester_msg.ussd_text,
				       op->ussd.rigester_msg.ussd_text_len,
				       op->ussd.rigester_msg.ussd_text_language);
	if (decoded_len <= 0) {
		goto failed_to_parse_xml;
	}
	decoded[decoded_len] = 0;

	if (!ussd_create_xml_latin1(ctx, content, sizeof(content),
				    decoded, decoded_len)) {
		goto failed_to_parse_xml;
	}


	/* Destination address */
	url_escape(escaped_to, decoded, RFC3986_RESERVED_CHARS);
	to_url = *ctx->to_url;
	to_url.url_user = escaped_to;
	to_url_str = url_as_string(ctx->home, &to_url);
	if (to_url_str == NULL) {
		goto failed_create_handle;
	}

	to = sip_to_create(ctx->home, (url_string_t *)to_url_str);
	su_free(ctx->home, to_url_str);
	if (!to) {
		goto failed_create_handle;
	}

	/* Source address */
	from_url = *ctx->self_url;
	from_url.url_user = extention;
	from_url_str = url_as_string(ctx->home, &from_url);
	if (from_url_str == NULL) {
		goto failed_create_handle;
	}

	from = sip_from_create(ctx->home, (url_string_t *)from_url_str);
	su_free(ctx->home, from_url_str);
	if (!to) {
		goto failed_create_handle;
	}

	/* create operation handle */
	op->handle = nua_handle(ctx->nua,
				op,
				SIPTAG_TO(to),
				SIPTAG_FROM(from),
				NUTAG_M_USERNAME(extention),
				TAG_END());

	su_free(ctx->home, from);
	su_free(ctx->home, to);
	from = NULL;
	to = NULL;

	if (op->handle == NULL) {
		goto failed_create_handle;
	}

	nua_invite(op->handle,
		   SIPTAG_UNKNOWN_STR("Recv-Info: g.3gpp.ussd"),
		   SIPTAG_CONTENT_TYPE_STR("application/vnd.3gpp.ussd+xml"),
		   SIPTAG_PAYLOAD_STR(content),
		   TAG_END());
	return 0;

failed_create_handle:
	if (from != NULL)
		su_free(ctx->home, from);
	if (to != NULL)
		su_free(ctx->home, to);
failed_to_parse_xml:
	fprintf(stderr, "*** open_ussd_session failed!\n");
	return -1;
}

int ussd_session_facility(operation_t *op,
			  struct ss_request* ss,
			  const char* extention)
{
	char content[1024];
	char decoded[MAX_LEN_USSD_STRING + 1];
	int decoded_len;

	decoded_len = decode_to_latin1(decoded, MAX_LEN_USSD_STRING,
				       ss->ussd_text,
				       ss->ussd_text_len,
				       ss->ussd_text_language);
	if (decoded_len <= 0) {
		return -1;
	}
	decoded[decoded_len] = 0;

	if (!ussd_create_xml_latin1(op->ctx, content, sizeof(content),
				    decoded, decoded_len)) {
		return -1;
	}

	nua_info(op->handle,
		   /* other tags as needed ... */
		   SIPTAG_CONTENT_TYPE_STR("application/vnd.3gpp.ussd+xml"),
		   SIPTAG_UNKNOWN_STR("Recv-Info: g.3gpp.ussd"),
		   SIPTAG_PAYLOAD_STR(content),
		   TAG_END());

	return 0;
}

void context_callback(nua_event_t   event,
		      int           status,
		      char const   *phrase,
		      nua_t        *nua,
		      nua_magic_t  *magic,
		      nua_handle_t *nh,
		      nua_hmagic_t *hmagic,
		      sip_t const  *sip,
		      tagi_t        tags[])
{
	fprintf(stderr, "$$$ got event %d: status: %d (%s) : %p\n", event, status, phrase, hmagic);

	switch (event) {
	case nua_i_error:
		proxy_i_error(status, phrase, nua, magic, nh, hmagic, sip, tags);
		break;

	case nua_i_info:
		if (hmagic->ussd.type == TYPE_USSD)
			proxy_info(status, phrase, nua, magic, nh, hmagic, sip, tags, 0);
		break;

	case nua_r_info:
		if (hmagic->ussd.type == TYPE_USSD)
			proxy_info(status, phrase, nua, magic, nh, hmagic, sip, tags, 1);
		break;

	case nua_i_bye:
		if (hmagic->ussd.type == TYPE_USSD)
			proxy_i_bye(status, phrase, nua, magic, nh, hmagic, sip, tags);
		else
			proxy_i_bye_ss(status, phrase, nua, magic, nh, hmagic, sip, tags);
		break;

	case nua_i_invite:
		//app_i_invite(status, phrase, nua, magic, nh, hmagic, sip, tags);
		break;

	case nua_r_invite:
		proxy_r_invite(status, phrase, nua, magic, nh, hmagic, sip, tags);
		break;

	case nua_r_bye:
		proxy_r_bye(status, phrase, nua, magic, nh, hmagic, sip, tags);
		break;

	default:
		/* unknown event -> print out error message */
		if (status > 100) {
			printf("unknown event %d: %03d %s\n",
			       event,
			       status,
			       phrase);
		} else {
			printf("unknown event %d\n", event);
		}
		tl_print(stdout, "", tags);
		break;
	}
}

static int rx_sup_uss_message(isup_connection_t *sup_conn, const uint8_t* data, size_t len)
{
	char extention[32] = {0};
	struct ss_header ss;
	struct ss_request ssreq;
	uint32_t ref;
	operation_t* op;
	int rc;
	context_t *ctx = sup_conn->ctx;
	memset(&ss, 0, sizeof(ss));

	if (rx_uss_message_parse(data, len, &ss, &ref, extention, sizeof(extention))) {
		LOGP(DLCTRL, LOGL_ERROR, "Can't parse uss message\n");
		goto err_bad_packet;
	}

	memset(&ssreq, 0, sizeof(ssreq));
	rc = gsm0480_parse_ss_facility(data + ss.component_offset,
				       ss.component_length,
				       &ssreq);
	if (!rc) {
		LOGP(DLCTRL, LOGL_ERROR, "Can't parse facility message\n");
		goto err_bad_component;
	}

	LOGP(DLCTRL, LOGL_ERROR, "Got ref=%d mtype=0x%02x invoke_id=0x%02x opcode=0x%02x ss_code=0x%02x component_type=0x%02x text=%s\n", ref,
	     ss.message_type, ssreq.invoke_id, ssreq.opcode, ssreq.ss_code, ssreq.component_type, ssreq.ussd_text);

	switch (ss.message_type) {
	case GSM0480_MTYPE_REGISTER:
		if (ssreq.component_type != GSM0480_CTYPE_INVOKE) {
			LOGP(DLCTRL, LOGL_ERROR, "Non-INVOKE component type in REGISTER: 0x%02x\n", ssreq.component_type);
			goto err_send_reject;
		}
		if (ssreq.opcode == GSM0480_OP_CODE_PROCESS_USS_DATA ||
			ssreq.opcode == GSM0480_OP_CODE_USS_NOTIFY ||
			ssreq.opcode == GSM0480_OP_CODE_USS_REQUEST) {

			LOGP(DLCTRL, LOGL_ERROR, "Don't know hot to handle this SS opcode: 0x%02x\n", ssreq.opcode);
			goto err_send_reject;
		}
		/* Create new session */
		op = operation_alloc(ctx);
		if (op == NULL) {
			LOGP(DLCTRL, LOGL_ERROR, "Unable to allocate new session\n");
			goto err_send_reject;
		}

		if (ssreq.opcode == GSM0480_OP_CODE_PROCESS_USS_REQ) {
			LOGP(DLCTRL, LOGL_ERROR, "New session %.*s from %s, active: %d\n",
			     ssreq.ussd_text_len,
			     ssreq.ussd_text,
			     extention,
			     ctx->operation_count);

			op->ussd.ss_code = 0;
			rc = ussd_session_open_mo(op, sup_conn, &ssreq, ref, extention);
			if (rc < 0) {
				operation_destroy(op);
				goto err_send_reject;
			}
		} else {
			LOGP(DLCTRL, LOGL_ERROR, "New session SS 0x%02x from %s, active: %d\n",
			     ssreq.opcode,
			     extention,
			     ctx->operation_count);

			op->ussd.ss_code = ssreq.ss_code;
			op->ussd.rigester_msg = ssreq;
			rc = ss_session_open_mo(op,
						sup_conn,
						data + ss.component_offset,
						ss.component_length,
						ref,
						extention);
			if (rc < 0) {
				operation_destroy(op);
				goto err_send_reject;
			}
		}
		break;

	case GSM0480_MTYPE_FACILITY:
		//Only MS-originated Menu session is supported, so we ignore INVOKE here
		if (ssreq.component_type != GSM0480_CTYPE_RETURN_RESULT &&
				ssreq.component_type != GSM0480_CTYPE_RETURN_ERROR &&
				ssreq.component_type != GSM0480_CTYPE_REJECT) {
			LOGP(DLCTRL, LOGL_ERROR, "Non-{RESULT/RETURN_ERROR/REJECT} component type in FACILITY: 0x%02x\n", ssreq.component_type);
			goto err_send_reject;
		}
		// /////////////////////////////////////////////////
		// TODO handle RETURN_ERROR/REJECT
		if (ssreq.component_type != GSM0480_CTYPE_RETURN_RESULT) {
			LOGP(DLCTRL, LOGL_ERROR, "Component type in FACILITY: 0x%02x is not implemented yet\n", ssreq.component_type);
			goto err_send_reject;
		}
		if (ssreq.opcode != GSM0480_OP_CODE_USS_REQUEST) {
			LOGP(DLCTRL, LOGL_ERROR, "Don't know hot to handle this SS opcode: 0x%02x\n", ssreq.opcode);
			goto err_send_reject;
		}
		op = operation_find_by_tid(ctx, ref);
		if (op == NULL) {
			LOGP(DLCTRL, LOGL_ERROR, "No active session with tid=%d were found\n",
			     ssreq.invoke_id);
			goto err_send_reject;
		}

		// TODO check result!! MO/MT error handling
		rc = ussd_session_facility(op, &ssreq, extention);
		if (rc < 0) {
			operation_destroy(op);
			goto err_send_reject;
		}
		break;

	case GSM0480_MTYPE_RELEASE_COMPLETE:
		op = operation_find_by_tid(ctx, ref);
		if (op == NULL) {
			LOGP(DLCTRL, LOGL_ERROR, "No active session with tid=%d were found for RELEASE_COMPLETE\n",
			     ssreq.invoke_id);
			return 0;
		}

		nua_bye(op->handle, TAG_END());
		break;

	default:
		LOGP(DLCTRL, LOGL_ERROR, "Unknown message type 0x%02x\n", ss.message_type);
		goto err_send_reject;
	}

	return 0;

err_send_reject:
	ussd_send_reject(sup_conn, ref, ssreq.invoke_id);
	return -1;

err_bad_component:
	return ussd_send_data_ss(sup_conn,
				 GSM0480_MTYPE_RELEASE_COMPLETE,
				 NULL,
				 0,
				 ref);
	return -1;

err_bad_packet:
	// Disconnect ?
	return -1;
}

int ussd_send_reject(isup_connection_t *conn, uint32_t ref, uint8_t invoke_id)
{
	uint8_t buffer[2+3+3];

	buffer[0] = GSM0480_CTYPE_REJECT;
	buffer[1] = 3+3;

	buffer[2] = GSM0480_COMPIDTAG_INVOKE_ID;
	buffer[3] = 1;
	buffer[4] = invoke_id;

	buffer[5] = GSM_0480_PROBLEM_CODE_TAG_GENERAL;
	buffer[6] = 1;
	buffer[7] = GSM_0480_GEN_PROB_CODE_UNRECOGNISED;

	return ussd_send_data_ss(conn,
				 GSM0480_MTYPE_RELEASE_COMPLETE,
				 buffer,
				 sizeof(buffer),
				 ref);
}

int ussd_send_data_ss(isup_connection_t *conn,
		      uint8_t message_type,
		      const uint8_t* component,
		      uint8_t component_len,
		      uint32_t ref)
{
	struct msgb *outmsg = msgb_alloc_headroom(4000, 64, __func__);
	struct ss_header hdr;

	hdr.transaction_id = 0;
	hdr.message_type = message_type;
	hdr.component_length = component_len;
	hdr.component_offset = 0;

	subscr_uss_message(outmsg,
			   &hdr,
			   NULL,
			   ref,
			   component);

	LOGP(DLCTRL, LOGL_ERROR,
	     "Sending USS, will send: %s\n", msgb_hexdump(outmsg));

	return sup_server_send(conn, outmsg);
}

int ussd_send_data(operation_t *op, int last, const char* lang, unsigned lang_len,
		   const char* msg, unsigned msg_len)
{
	struct msgb *buf;
	struct ss_request ss;
	int rc;
	uint8_t message_type;

	memset(&ss, 0, sizeof(ss));

	// TODO handle language
	if (msg == NULL) {
		message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
		ss.component_type = GSM0480_CTYPE_REJECT;
		ss.opcode = op->ussd.rigester_msg.opcode;
	} else if (last) {
		message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
		ss.component_type = GSM0480_CTYPE_RETURN_RESULT;
		ss.opcode = op->ussd.rigester_msg.opcode;
	} else {
		message_type = GSM0480_MTYPE_FACILITY;
		ss.component_type = (op->ussd.ms_originated) ? GSM0480_CTYPE_INVOKE
							     : GSM0480_CTYPE_RETURN_RESULT;
		ss.opcode = GSM0480_OP_CODE_USS_REQUEST;
	}

	ss.invoke_id = op->ussd.rigester_msg.invoke_id;

	if (msg) {
		char tmpbuf[MAX_LEN_USSD_STRING + 1];

		char* inbuf = (char*)msg;
		size_t inleft = msg_len;
		char* outbuf = (char*)tmpbuf;
		size_t outleft = sizeof(tmpbuf);
		size_t s;

		// First of all try latin1
		s = iconv(op->ctx->utf8_to_latin1,
			  &inbuf, &inleft,
			  &outbuf, &outleft);
		if (s == (size_t)-1) {
			outbuf = (char*)ss.ussd_text;
			outleft = MAX_ASN1_LEN_USSD_STRING;

			s = iconv(op->ctx->utf8_to_ucs2,
				  &inbuf, &inleft,
				  &outbuf, &outleft);
			if (s == (size_t)-1) {
				perror("can't convert string from utf8");
			}
			// UCS-2 encoding
			ss.ussd_text_language = 0x48;
			ss.ussd_text_len = (uint8_t*)outbuf - ss.ussd_text;

		} else {
			int outlen;
			size_t len = (msg_len > MAX_LEN_USSD_STRING) ?
						MAX_LEN_USSD_STRING : msg_len;
			memcpy(tmpbuf, msg, len);
			tmpbuf[len] = 0;

			gsm_7bit_encode_n_ussd(ss.ussd_text,
					       MAX_ASN1_LEN_USSD_STRING, tmpbuf, &outlen);
			ss.ussd_text_len = outlen;
			ss.ussd_text_language = 0x0f;
		}
	} else {
		ss.ussd_text_len = 0;
		ss.ussd_text_language = 0x0f;
		ss.ussd_text[0] = 0;
	}

	buf = gsm0480_compose_ussd_component(&ss);
	if (!buf) {
		return -1;
	}
	rc = ussd_send_data_ss(op->ussd.conn, message_type,
			       buf->data, msgb_length(buf), op->ussd.ref);
	msgb_free(buf);

	return rc;
}

static void timer_function(su_root_magic_t *magic,
			  su_timer_t *t,
			  su_timer_arg_t *arg)
{
	context_t *cli = (context_t*)arg;
	su_time_t n = su_now();

	operation_t *op, *tmp;
	llist_for_each_entry_safe(op, tmp, &cli->operation_list, list) {
		su_duration_t lasts = su_duration(n, op->tm_initiated);
		if (lasts > cli->max_ussd_ses_duration) {
			if (op->ussd.type == TYPE_USSD) {
				fprintf(stderr, "!!! session %.*s from %s lasted %ld ms, more than thresold %ld ms, destroying\n",
					op->ussd.rigester_msg.ussd_text_len,
					op->ussd.rigester_msg.ussd_text,
					op->ussd.extention,
					lasts,
					cli->max_ussd_ses_duration);


				ussd_send_reject(op->ussd.conn,
						 op->ussd.ref,
						 op->ussd.rigester_msg.invoke_id);
			} else {
				fprintf(stderr, "!!! session 0x%02x from %s lasted %ld ms, more than thresold %ld ms, destroying\n",
					op->ussd.ss_code,
					op->ussd.extention,
					lasts,
					cli->max_ussd_ses_duration);

				ussd_send_data_ss(op->ussd.conn,
						  GSM0480_MTYPE_RELEASE_COMPLETE,
						  NULL,
						  0,
						  op->ussd.ref);
			}
			operation_destroy(op);
		}
	}
}

static int isup_handle_connection(context_t *cli, su_wait_t *w, void *p)
{
	int rc;
	isup_connection_t *conn = (isup_connection_t*)p;

	int events = su_wait_events(w, conn->isup_conn_socket);
	printf("*** connection; event=0x%x\n", events);

	if (events & (SU_WAIT_ERR | SU_WAIT_HUP)) {
		printf("*** connection destroyed\n");
		goto err;
	} else if (events & SU_WAIT_IN) {
		/* Incoming data */

		struct ipaccess_head *iph;
		struct msgb *msg = NULL;
		int ret = ipa_msg_recv_buffered(conn->isup_conn_socket, &msg, &conn->pending_msg);
		if (ret <= 0) {
			if (ret == -EAGAIN)
				return 0;
			if (ret == 0)
				LOGP(DLCTRL, LOGL_INFO, "The control connection was closed\n");
			else
				LOGP(DLCTRL, LOGL_ERROR, "Failed to parse ip access message: %d\n", ret);

			goto err;
		}

		iph = (struct ipaccess_head *) msg->data;
		switch (iph->proto)
		{
		case IPAC_PROTO_IPACCESS:
			if (msg->l2h[0] == IPAC_MSGT_PING) {
				printf("*** got PING\n");
				msg->l2h[0] = IPAC_MSGT_PONG;
				send(conn->isup_conn_socket, msg->data, ntohs(iph->len) + sizeof(struct ipaccess_head), 0);
				msgb_free(msg);
				conn->pending_msg = NULL;
				return 0;
			}

			LOGP(DLCTRL, LOGL_ERROR, "Unknown IPAC_PROTO_IPACCESS msg 0x%x\n", msg->l2h[0]);
			goto err;
		case IPAC_PROTO_OSMO:
			// TODO callback
			if (msg->l2h[1] == OSMO_GSUP_MSGT_USSD_MAP) {
				LOGP(DLCTRL, LOGL_ERROR,
					   "Receive USS: %s\n", msgb_hexdump(msg));

				rc = rx_sup_uss_message(conn, &msg->l2h[1], msgb_l2len(msg) - 1);
				if (rc < 0) {
					/* TODO raise reject !!!!!!! */
					/* release complete */
				}

				msgb_free(msg);
				conn->pending_msg = NULL;
				return 0;
			}

			/* TODO: handle gprs_gsup_decode() for other types */

			LOGP(DLCTRL, LOGL_ERROR, "Unknown IPAC_PROTO_OSMO OSMO_GSUP_MSGT_* 0x%x\n", msg->l2h[1]);
			msgb_free(msg);
			conn->pending_msg = NULL;
			goto err;
		default:
			LOGP(DLCTRL, LOGL_ERROR, "Protocol mismatch. We got 0x%x\n", iph->proto);
			goto err;
		}
	}

	return 0;

err:
	close(conn->isup_conn_socket);
	conn->isup_conn_socket = INVALID_SOCKET;

	su_wait_destroy(w);

	msgb_free(conn->pending_msg);
	conn->pending_msg = NULL;
	//su_root_deregister(cli, cli->isup_register_idx);
	return 0;
}

static int isup_handle_accept(context_t *cli, su_wait_t *w, void *p)
{
	su_sockaddr_t aaddr;
	su_socket_t connection;
	socklen_t len = sizeof(aaddr);
	int rc;

	connection = accept(cli->isup_acc_socket, &aaddr.su_sa, &len);
	if (connection == INVALID_SOCKET) {
		perror("can't accept isup socket");
		return 0;
	}

	printf("*** accepted from %s:%d\n",
	       inet_ntoa(aaddr.su_sin.sin_addr),
	       ntohs(aaddr.su_sin.sin_port));

	/* TODO manage isup connection list, but just now use the single connection */
	isup_connection_t *conn = cli->isup;
	if (conn->isup_conn_socket != INVALID_SOCKET) {
		fprintf(stderr, "--- Can't accept, there's another connection\n");
		su_close(connection);
		return 0;
	}

	conn->ctx = cli;
	conn->isup_conn_socket = connection;
	conn->pending_msg = NULL;

	su_wait_init(&conn->isup_conn_event);
	rc = su_wait_create(&conn->isup_conn_event,
			    conn->isup_conn_socket,
			    SU_WAIT_IN | /*SU_WAIT_OUT | */ SU_WAIT_HUP | SU_WAIT_ERR);

	conn->isup_register_idx = su_root_register(cli->root,
						   &conn->isup_conn_event,
						   isup_handle_connection,
						   conn,
						   0);
	return 0;
}

#define DIPA_USSD_PROXY 0

struct log_info_cat ipa_proxy_test_cat[] = {
	[DIPA_USSD_PROXY] = {
		.name = "DIPA_USSD_PROXY",
		.description = "USSD_PROXY",
		.color = "\033[1;35m",
		.enabled = 1,
		.loglevel = LOGL_DEBUG,
	},
};

const struct log_info ipa_proxy_test_log_info = {
	.filter_fn = NULL,
	.cat = ipa_proxy_test_cat,
	.num_cat = ARRAY_SIZE(ipa_proxy_test_cat),
};


static void Usage(char* progname)
{
	fprintf(stderr, "Usage:\n"
		"%s [options]\n"
		"Options\n"
		"  -p <port>         TCP port to listen incoming SUP connection\n"
		"                           (default: 8184)\n"
		"  -t <url>          Destination SIP URL (default: sip:127.0.0.1:5060)\n"
		"  -u <url>          User agent SIP URL (default: sip:127.0.0.1:5090)\n"
		"  -x <url>          Proxy SIP URL (default: <none>)\n"
		"  -T                Force  using TCP instead trying UDP\n"
		"  -D <secs>         Maximum period of open USSD session (default: 90)\n"
		"  -o <sessions>     Maximum number of concurrent USSD sessions\n"
		"                           (default: 200)\n"
		"  -l <0-9>          sip sofia loglevel, 0 - none; 9 - max\n"
		, progname);
}

int main(int argc, char *argv[])
{
	su_home_t *home;
	context_t context[1] = {{{SU_HOME_INIT(context)}}};
	su_sockaddr_t listen_addr;
	int rc;
	int sup_port = 8184;
	const char* to_str = "sip:127.0.0.1:5060";
	const char* url_str = "sip:127.0.0.1:5090";
	const char* proxy_str = NULL;
	int force_tcp = 0;
	int max_ussd_ses_secs = 90;
	int max_op_limit = 200;
	int sip_loglevel = 1;
	int c;

	while ((c = getopt (argc, argv, "x:p:t:u:D:To:l:L7?")) != -1) {
		switch (c)
		{
		case 'x':
			proxy_str = optarg;
			break;
		case 'p':
			sup_port = atoi(optarg);
			break;
		case 't':
			to_str = optarg;
			break;
		case 'u':
			url_str = optarg;
			break;
		case 'T':
			force_tcp = 1;
			break;
		case 'D':
			max_ussd_ses_secs = atoi(optarg);
			break;
		case 'o':
			max_op_limit = atoi(optarg);
			break;
		case 'l':
			sip_loglevel = atoi(optarg);
			break;
		case 'L':
			fprintf(stderr, " -L is now obsolete, ignored\n");
			break;
		case '7':
			fprintf(stderr, " -7 is now obsolete, ignored\n");
			break;
		case '?':
		default:
			Usage(argv[0]);
			return 2;
		}
	}

	osmo_init_logging(&ipa_proxy_test_log_info);

	su_init();
	su_home_init(home = context->home);

	context->root = su_root_create(context);

	su_log_set_level(NULL, sip_loglevel);

	/* Disable threading */
	su_root_threading(context->root, 0);

	if (!context->root) {
		fprintf(stderr, "Unable to initialize sip-sofia context\n");
		return 1;
	}

	context->utf8_to_latin1=iconv_open("iso8859-1", "utf-8");
	context->latin1_to_utf8=iconv_open("utf-8", "iso8859-1");
	context->utf8_to_ucs2=iconv_open("utf-16be", "utf-8");
	context->ucs2_to_utf8=iconv_open("utf-8", "utf-16be");

	if (context->utf8_to_ucs2 == NULL || context->ucs2_to_utf8 == NULL ||
			context->utf8_to_latin1 == NULL || context->latin1_to_utf8 == NULL) {
		fprintf(stderr, "Unable to initialize iconv\n");
		return 1;
	}

	context->isup_acc_socket = su_socket(AF_INET, SOCK_STREAM, 0);
	if (context->isup_acc_socket == INVALID_SOCKET) {
		perror("unable to create socket\n");
		return 1;
	}
	su_setblocking(context->isup_acc_socket, 0);
	su_setreuseaddr(context->isup_acc_socket, 1);

	context->isup->isup_conn_socket = INVALID_SOCKET;

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.su_sin.sin_family = AF_INET;
	listen_addr.su_sin.sin_addr.s_addr = INADDR_ANY;
	listen_addr.su_sin.sin_port = htons(sup_port);

	rc = bind(context->isup_acc_socket, &listen_addr.su_sa, sizeof(listen_addr.su_sin));
	if (rc < 0) {
		perror("cannot bind socket\n");
		return 2;
	}

	rc = listen(context->isup_acc_socket, 1);
	if (rc < 0) {
		perror("cannot bind socket\n");
		return 2;
	}

	su_wait_init(&context->isup_acc_event);
	su_wait_create(&context->isup_acc_event, context->isup_acc_socket, SU_WAIT_ACCEPT);
	su_root_register(context->root,
			 &context->isup_acc_event,
			 isup_handle_accept,
			 NULL,
			 0);

	context->to_url = url_make(home, to_str);
	context->self_url = url_make(home, url_str);

	if (context->to_url == NULL) {
		fprintf(stderr, "Unable to parse destination URL\n");
		return 1;
	}
	if (context->self_url == NULL) {
		fprintf(stderr, "Unable to parse our (source) URL\n");
		return 1;
	}

	context->nua = nua_create(context->root,
				  context_callback,
				  context,
				  NUTAG_URL(url_str),
				  NUTAG_ENABLEINVITE(1),
				  NUTAG_AUTOALERT(1),
				  NUTAG_SESSION_TIMER(0),
				  NUTAG_AUTOANSWER(0),
				  NUTAG_MEDIA_ENABLE(0),
				  NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, INFO"),
				  TAG_NULL());
	if (context->nua == NULL) {
		fprintf(stderr, "Unable to initialize sip-sofia nua\n");
		return 1;
	}


	if (proxy_str) {
		nua_set_params(context->nua,
			       NUTAG_PROXY(proxy_str),
			       TAG_NULL());
	}

	if (force_tcp) {
		nua_set_params(context->nua,
			       NTATAG_UDP_MTU(10),
			       TAG_NULL());
	}

	INIT_LLIST_HEAD(&context->operation_list);
	context->operation_count = 0;
	context->operations_max = max_op_limit;

	su_timer_t* tm = su_timer_create(su_root_task(context->root), 2000);
	if (tm == NULL) {
		fprintf(stderr, "Unable to initialize sip-sofia timer\n");
		return 1;
	}
	rc = su_timer_run(tm, timer_function, context);
	if (rc < 0) {
		fprintf(stderr, "Unable to start sip-sofia timer\n");
		return 1;
	}
	context->timer = tm;
	context->max_ussd_ses_duration = max_ussd_ses_secs * 1000l;

	su_root_run(context->root);
	nua_destroy(context->nua);

	return 0;
}

