#include <openbsc/tlv.h>

int tlv_parse(struct tlv_parser *parser, u_int8_t *data, int data_len)
{
	u_int8_t *cur = data;
	memset(parser, 0, sizeof(*parser));

	while (cur +2 <= data + data_len) {
		u_int8_t tag, len;
		u_int8_t *val;

		tag = *cur++;
		len = *cur++;
		val = cur;

		parser->lv[tag].len = len;
		parser->lv[tag].val = val;

		if (cur + len > data + data_len)
			break;

		cur += len;
	}
	return 0;
}
