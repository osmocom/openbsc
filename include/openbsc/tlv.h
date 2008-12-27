#ifndef _TLV_H
#define _TLV_H

#include <sys/types.h>
#include <string.h>

#define TLV_GROSS_LEN(x)	(x+2)
#define TLV16_GROSS_LEN(x)	((2*x)+2)
#define TL16V_GROSS_LEN(x)	(x+3)

static inline u_int8_t *tlv_put(u_int8_t *buf, u_int8_t tag, u_int8_t len,
				const u_int8_t *val)
{
	*buf++ = tag;
	*buf++ = len;
	memcpy(buf, val, len);
	return buf + len;
}

static inline u_int8_t *tlv16_put(u_int8_t *buf, u_int8_t tag, u_int8_t len,
				const u_int16_t *val)
{
	*buf++ = tag;
	*buf++ = len;
	memcpy(buf, val, len*2);
	return buf + len*2;
}

static inline u_int8_t *tl16v_put(u_int8_t *buf, u_int8_t tag, u_int16_t len,
				const u_int8_t *val)
{
	*buf++ = tag;
	*buf++ = len >> 8;
	*buf++ = len & 0xff;
	memcpy(buf, val, len);
	return buf + len*2;
}

static inline u_int8_t *msgb_tlv16_put(struct msgb *msg, u_int8_t tag, u_int8_t len, const u_int16_t *val)
{
	u_int8_t *buf = msgb_put(msg, TLV16_GROSS_LEN(len));
	return tlv16_put(buf, tag, len, val);
}

static inline u_int8_t *msgb_tl16v_put(struct msgb *msg, u_int8_t tag, u_int16_t len,
					const u_int8_t *val)
{
	u_int8_t *buf = msgb_put(msg, TL16V_GROSS_LEN(len));
	return tl16v_put(buf, tag, len, val);
}

static inline u_int8_t *tv_put(u_int8_t *buf, u_int8_t tag, 
				u_int8_t val)
{
	*buf++ = tag;
	*buf++ = val;
	return buf;
}

static inline u_int8_t *tv16_put(u_int8_t *buf, u_int8_t tag, 
				 u_int16_t val)
{
	*buf++ = tag;
	*buf++ = val >> 8;
	*buf++ = val & 0xff;
	return buf;
}

static inline u_int8_t *msgb_tlv_put(struct msgb *msg, u_int8_t tag, u_int8_t len, const u_int8_t *val)
{
	u_int8_t *buf = msgb_put(msg, TLV_GROSS_LEN(len));
	return tlv_put(buf, tag, len, val);
}

static inline u_int8_t *msgb_tv_put(struct msgb *msg, u_int8_t tag, u_int8_t val)
{
	u_int8_t *buf = msgb_put(msg, 2);
	return tv_put(buf, tag, val);
}

static inline u_int8_t *msgb_tv16_put(struct msgb *msg, u_int8_t tag, u_int16_t val)
{
	u_int8_t *buf = msgb_put(msg, 3);
	return tv16_put(buf, tag, val);
}

static inline u_int8_t *msgb_tlv_push(struct msgb *msg, u_int8_t tag, u_int8_t len, const u_int8_t *val)
{
	u_int8_t *buf = msgb_push(msg, TLV_GROSS_LEN(len));
	return tlv_put(buf, tag, len, val);
}

static inline u_int8_t *msgb_tv_push(struct msgb *msg, u_int8_t tag, u_int8_t val)
{
	u_int8_t *buf = msgb_push(msg, 2);
	return tv_put(buf, tag, val);
}

static inline u_int8_t *msgb_tv16_push(struct msgb *msg, u_int8_t tag, u_int16_t val)
{
	u_int8_t *buf = msgb_push(msg, 3);
	return tv16_put(buf, tag, val);
}


#endif /* _TLV_H */
