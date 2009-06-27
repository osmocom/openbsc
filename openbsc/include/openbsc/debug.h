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

#ifdef DEBUG
#define DEBUGP(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 0, fmt, ## args)
#define DEBUGPC(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, 1, fmt, ## args)
#else
#define DEBUGP(xss, fmt, args...) 
#define DEBUGPC(ss, fmt, args...)
#endif

#define static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1];

char *hexdump(unsigned char *buf, int len);
void debugp(unsigned int subsys, char *file, int line, int cont, const char *format, ...);
void debug_parse_category_mask(const char* mask);
void debug_use_color(int use_color);
void debug_timestamp(int enable);
extern unsigned int debug_mask;

#endif /* _DEBUG_H */
