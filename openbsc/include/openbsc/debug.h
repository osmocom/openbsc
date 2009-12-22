#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG

#define DRLL		0x0001
#define DCC		0x0002
#define DMM		0x0004
#define DRR		0x0008
#define DRSL		0x0010
#define DNM		0x0020

#define DMNCC		0x0080
#define DSMS		0x0100
#define DPAG		0x0200
#define DMEAS		0x0400

#define DMI		0x1000
#define DMIB		0x2000
#define DMUX		0x4000
#define DINP		0x8000

#define DSCCP		0x10000
#define DMSC		0x20000

#define DMGCP		0x40000

#define DHO		0x80000

#ifdef DEBUG
#define DEBUGP(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 0, fmt, ## args)
#define DEBUGPC(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 1, fmt, ## args)
#else
#define DEBUGP(xss, fmt, args...) 
#define DEBUGPC(ss, fmt, args...)
#endif

#define static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1];

char *hexdump(const unsigned char *buf, int len);
void debugp(unsigned int subsys, char *file, int line, int cont, const char *format, ...) __attribute__ ((format (printf, 5, 6)));
void debug_parse_category_mask(const char* mask);
void debug_use_color(int use_color);
void debug_timestamp(int enable);
extern unsigned int debug_mask;

/* new logging interface */
#define LOGP(ss, level, fmt, args...) debugp(ss, __FILE__, __LINE__, 0, fmt, ##args)
#define LOGPC(ss, level, fmt, args...) debugp(ss, __FILE__, __LINE__, 1, fmt, ##args)

/* different levels */
#define LOGL_DEBUG	1	/* debugging information */
#define LOGL_INFO	3
#define LOGL_NOTICE	5	/* abnormal/unexpected condition */
#define LOGL_ERROR	7	/* error condition, requires user action */
#define LOGL_FATAL	8	/* fatal, program aborted */

#endif /* _DEBUG_H */
