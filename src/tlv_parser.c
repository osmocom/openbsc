#include <stdio.h>
#include <openbsc/tlv.h>

int tlv_dump(struct tlv_parsed *dec)
{
	int i;

	for (i = 0; i <= 0xff; i++) {
		if (!dec->lv[i].val)
			continue;
		printf("T=%02x L=%d\n", i, dec->lv[i].len);
	}
	return 0;
}

int tlv_parse(struct tlv_parsed *dec, const struct tlv_definition *def,
	      const u_int8_t *buf, int buf_len)
{
	u_int8_t tag, len = 1;
	const u_int8_t *pos;
	int num_parsed = 0;

	memset(dec, 0, sizeof(*dec));

	for (pos = buf; pos < buf+buf_len; pos += len) {
		tag = *pos;
		/* FIXME: use tables for knwon IEI */
		switch (def->def[tag].type) {
		case TLV_TYPE_T:
			/* GSM TS 04.07 11.2.4: Type 1 TV or Type 2 T */
			dec->lv[tag].val = pos;
			dec->lv[tag].len = 0;
			len = 1;
			num_parsed++;
			break;
		case TLV_TYPE_TV:
			dec->lv[tag].val = pos+1;
			dec->lv[tag].len = 1;
			len = 2;
			num_parsed++;
			break;
		case TLV_TYPE_FIXED:
			dec->lv[tag].val = pos+1;
			dec->lv[tag].len = def->def[tag].fixed_len;
			len = def->def[tag].fixed_len + 1;
			num_parsed++;
			break;
		case TLV_TYPE_TLV:
			/* GSM TS 04.07 11.2.4: Type 4 TLV */
			if (pos + 1 > buf + buf_len)
				return -1;
			dec->lv[tag].val = pos+2;
			dec->lv[tag].len = *(pos+1);
			len = dec->lv[tag].len + 2;
			if (pos + len > buf + buf_len)
				return -2;
			num_parsed++;
			break;
		case TLV_TYPE_TL16V:
			if (pos + 2 > buf + buf_len)
				return -1;
			dec->lv[tag].val = pos+3;
			dec->lv[tag].len = *(pos+1) << 8 | *(pos+2);
			len = dec->lv[tag].len + 3;
			if (pos + len > buf + buf_len)
				return -2;
			num_parsed++;
			break;
		}
	}
	//tlv_dump(dec);
	return num_parsed;
}

