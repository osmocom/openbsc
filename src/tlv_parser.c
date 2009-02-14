#include <openbsc/tlv.h>

int tlv_parse(struct tlv_parsed *dec, u_int8_t *buf, int buf_len)
{
	u_int8_t tag, len = 1;
	u_int8_t *pos;
	int num_parsed = 0;

	memset(dec, 0, sizeof(*dec));

	for (pos = buf; pos < buf+buf_len; pos += len) {
		tag = *pos;
		/* FIXME: use tables for knwon IEI */
		if (tag & 0x80) {
			/* GSM TS 04.07 11.2.4: Type 1 TV or Type 2 T */
			dec->lv[tag].val = pos;
			dec->lv[tag].len = 0;
			len = 1;
			num_parsed++;
		} else {
			/* GSM TS 04.07 11.2.4: Type 4 TLV */
			if (pos + 1 > buf + buf_len)
				return -1;
			dec->lv[tag].val = pos+2;
			dec->lv[tag].len = *(pos+1);
			len = dec->lv[tag].len + 2;
			if (pos + len > buf + buf_len)
				return -2;
			num_parsed++;
		}
	}
	return num_parsed;
}
