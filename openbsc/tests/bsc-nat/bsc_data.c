/* test data */

/* BSC -> MSC, CR */
static const uint8_t bsc_cr[] = {
0x00, 0x2e, 0xfd,
0x01, 0x00, 0x00, 0x15, 0x02, 0x02, 0x04, 0x02,
0x42, 0xfe, 0x0f, 0x21, 0x00, 0x1f, 0x57, 0x05,
0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x1c, 0xc3,
0x51, 0x17, 0x12, 0x05, 0x08, 0x20, 0x72, 0xf4,
0x90, 0x20, 0x1d, 0x50, 0x08, 0x29, 0x47, 0x80,
0x00, 0x00, 0x00, 0x00, 0x80, 0x00 };

static const uint8_t bsc_cr_patched[] = {
0x00, 0x2e, 0xfd,
0x01, 0x00, 0x00, 0x05, 0x02, 0x02, 0x04, 0x02,
0x42, 0xfe, 0x0f, 0x21, 0x00, 0x1f, 0x57, 0x05,
0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x1c, 0xc3,
0x51, 0x17, 0x12, 0x05, 0x08, 0x20, 0x72, 0xf4,
0x90, 0x20, 0x1d, 0x50, 0x08, 0x29, 0x47, 0x80,
0x00, 0x00, 0x00, 0x00, 0x80, 0x00 };

/* CC, MSC -> BSC */
static const uint8_t msc_cc[] = {
0x00, 0x0a, 0xfd,
0x02, 0x00, 0x00, 0x05, 0x01, 0x1f, 0xe4, 0x02,
0x01, 0x00 };
static const uint8_t msc_cc_patched[] = {
0x00, 0x0a, 0xfd,
0x02, 0x00, 0x00, 0x15, 0x01, 0x1f, 0xe4, 0x02,
0x01, 0x00 };

/* Classmark, BSC -> MSC */
static const uint8_t bsc_dtap[] = {
0x00, 0x17, 0xfd,
0x06, 0x01, 0x1f, 0xe4, 0x00, 0x01, 0x10, 0x00,
0x0e, 0x54, 0x12, 0x03, 0x50, 0x18, 0x93, 0x13,
0x06, 0x60, 0x14, 0x45, 0x00, 0x81, 0x00 };

static const uint8_t bsc_dtap_patched[] = {
0x00, 0x17, 0xfd,
0x06, 0x01, 0x1f, 0xe4, 0x00, 0x01, 0x10, 0x00,
0x0e, 0x54, 0x12, 0x03, 0x50, 0x18, 0x93, 0x13,
0x06, 0x60, 0x14, 0x45, 0x00, 0x81, 0x00 };

/* Clear command, MSC -> BSC */
static const uint8_t msc_dtap[] = {
0x00, 0x0d, 0xfd,
0x06, 0x00, 0x00, 0x05, 0x00, 0x01, 0x06, 0x00,
0x04, 0x20, 0x04, 0x01, 0x09 };
static const uint8_t msc_dtap_patched[] = {
0x00, 0x0d, 0xfd,
0x06, 0x00, 0x00, 0x15, 0x00, 0x01, 0x06, 0x00,
0x04, 0x20, 0x04, 0x01, 0x09 };

/*RLSD, MSC -> BSC */
static const uint8_t msc_rlsd[] = {
0x00, 0x0a, 0xfd,
0x04, 0x00, 0x00, 0x05, 0x01, 0x1f, 0xe4, 0x00,
0x01, 0x00 };
static const uint8_t msc_rlsd_patched[] = {
0x00, 0x0a, 0xfd,
0x04, 0x00, 0x00, 0x15, 0x01, 0x1f, 0xe4, 0x00,
0x01, 0x00 };

/* RLC, BSC -> MSC */
static const uint8_t bsc_rlc[] = {
0x00, 0x07, 0xfd,
0x05, 0x01, 0x1f, 0xe4, 0x00, 0x00, 0x15 };

static const uint8_t bsc_rlc_patched[] = {
0x00, 0x07, 0xfd,
0x05, 0x01, 0x1f, 0xe4, 0x00, 0x00, 0x05 };


/* a paging command */
static const uint8_t paging_by_lac_cmd[] = {
0x00, 0x22, 0xfd, 0x09,
0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x02, 0x00,
0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x12, 0x00,
0x10, 0x52, 0x08, 0x08, 0x29, 0x47, 0x10, 0x02,
0x01, 0x50, 0x02, 0x30, 0x1a, 0x03, 0x05, 0x20,
0x15 };

/* an assignment command */
static const uint8_t ass_cmd[] = {
0x00, 0x12, 0xfd, 0x06,
0x00, 0x00, 0x49, 0x00, 0x01, 0x0b, 0x00, 0x09,
0x01, 0x0b, 0x03, 0x01, 0x0a, 0x11, 0x01, 0x00,
0x01 };

/* identity response */
static const uint8_t id_resp[] = {
0x00, 0x15, 0xfd, 0x06, 0x01, 0x1c, 0xdc,
0x00, 0x01, 0x0e, 0x01, 0x00, 0x0b, 0x05, 0x59,
0x08, 0x29, 0x40, 0x21, 0x03, 0x07, 0x48, 0x66,
0x31
};

/*
 * MGCP messages
 */

/* nothing to patch */
static const char crcx[] = "CRCX 23265295 8@mgw MGCP 1.0\r\nC: 394b0439fb\r\nL: p:20, a:AMR, nt:IN\r\nM: recvonly\r\n";
static const char crcx_patched[] = "CRCX 23265295 1e@mgw MGCP 1.0\r\nC: 394b0439fb\r\nL: p:20, a:AMR, nt:IN\r\nM: recvonly\r\n";


/* patch the ip and port */
static const char crcx_resp[] = "200 23265295\r\nI: 1\r\n\r\nv=0\r\nc=IN IP4 172.16.18.2\r\nm=audio 4002 RTP/AVP 98\r\na=rtpmap:98 AMR/8000\r\n";
static const char crcx_resp_patched[] = "200 23265295\r\nI: 1\r\n\r\nv=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 999 RTP/AVP 98\r\na=rtpmap:98 AMR/8000\r\n";

/* patch the ip and port */
static const char mdcx[] = "MDCX 23330829 8@mgw MGCP 1.0\r\nC: 394b0439fb\r\nI: 1\r\nL: p:20, a:AMR, nt:IN\r\nM: recvonly\r\n\r\nv=0\r\no=- 1049380491 0 IN IP4 172.16.18.2\r\ns=-\r\nc=IN IP4 172.16.18.2\r\nt=0 0\r\nm=audio 4410 RTP/AVP 126\r\na=rtpmap:126 AMR/8000/1\r\na=fmtp:126 mode-set=2;start-mode=0\r\na=ptime:20\r\na=recvonly\r\nm=image 4412 udptl t38\r\na=T38FaxVersion:0\r\na=T38MaxBitRate:14400\r\n";
static const char mdcx_patched[] = "MDCX 23330829 1e@mgw MGCP 1.0\r\nC: 394b0439fb\r\nI: 1\r\nL: p:20, a:AMR, nt:IN\r\nM: recvonly\r\n\r\nv=0\r\no=- 1049380491 0 IN IP4 172.16.18.2\r\ns=-\r\nc=IN IP4 10.0.0.23\r\nt=0 0\r\nm=audio 6666 RTP/AVP 126\r\na=rtpmap:126 AMR/8000/1\r\na=fmtp:126 mode-set=2;start-mode=0\r\na=ptime:20\r\na=recvonly\r\nm=image 4412 udptl t38\r\na=T38FaxVersion:0\r\na=T38MaxBitRate:14400\r\n";


static const char mdcx_resp[] = "200 23330829\r\n\r\nv=0\r\nc=IN IP4 172.16.18.2\r\nm=audio 4002 RTP/AVP 98\r\na=rtpmap:98 AMR/8000\r\n";
static const char mdcx_resp_patched[] = "200 23330829\r\n\r\nv=0\r\nc=IN IP4 10.0.0.23\r\nm=audio 5555 RTP/AVP 98\r\na=rtpmap:98 AMR/8000\r\n";

/* different line ending */
static const char mdcx_resp2[] = "200 33330829\n\nv=0\nc=IN IP4 172.16.18.2\nm=audio 4002 RTP/AVP 98\na=rtpmap:98 AMR/8000\n";
static const char mdcx_resp_patched2[] = "200 33330829\n\nv=0\nc=IN IP4 10.0.0.23\nm=audio 5555 RTP/AVP 98\na=rtpmap:98 AMR/8000\n";

struct mgcp_patch_test {
	const char *orig;
	const char *patch;
	const char *ip;
	const int port;
};

static const struct mgcp_patch_test mgcp_messages[] = {
	{
		.orig = crcx,
		.patch = crcx_patched,
		.ip = "0.0.0.0",
		.port = 2323,
	},
	{
		.orig = crcx_resp,
		.patch = crcx_resp_patched,
		.ip = "10.0.0.1",
		.port = 999,
	},
	{
		.orig = mdcx,
		.patch = mdcx_patched,
		.ip = "10.0.0.23",
		.port = 6666,
	},
	{
		.orig = mdcx_resp,
		.patch = mdcx_resp_patched,
		.ip = "10.0.0.23",
		.port = 5555,
	},
	{
		.orig = mdcx_resp2,
		.patch = mdcx_resp_patched2,
		.ip = "10.0.0.23",
		.port = 5555,
	},
};

/* CC Setup messages */
static const uint8_t cc_setup_national[] = {
	0x00, 0x20, 0xfd, 0x06, 0x01, 0x12,
	0x6d, 0x00, 0x01, 0x19, 0x01, 0x00, 0x16, 0x03,
	0x05, 0x04, 0x06, 0x60, 0x04, 0x02, 0x00, 0x05,
	0x81, 0x5e, 0x06, 0x81, 0x10, 0x27, 0x33, 0x63,
	0x66, 0x15, 0x02, 0x11, 0x01
};

static const uint8_t cc_setup_national_patched[] = {
	0x00, 0x22, 0xfd, 0x06, 0x01, 0x12,
	0x6d, 0x00, 0x01, 0x1b, 0x01, 0x00, 0x18, 0x03,
	0x05, 0x04, 0x06, 0x60, 0x04, 0x02, 0x00, 0x05,
	0x81, 0x5e, 0x08, 0x81, 0x00, 0x94, 0x71, 0x32,
	0x33, 0x66, 0xf6, 0x15, 0x02, 0x11, 0x01
};

static const uint8_t cc_setup_international[] = {
	0x00, 0x22, 0xfd, 0x06, 0x01, 0x13,
	0xe7, 0x00, 0x01, 0x1b, 0x01, 0x00, 0x18, 0x03,
	0x45, 0x04, 0x06, 0x60, 0x04, 0x02, 0x00, 0x05,
	0x81, 0x5e, 0x08, 0x81, 0x00, 0x94, 0x71, 0x33,
	0x63, 0x66, 0x03, 0x15, 0x02, 0x11, 0x01
};
