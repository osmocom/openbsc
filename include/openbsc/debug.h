#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG

#define DRLL		0x0001
#define DCC		0x0002
#define DMM		0x0004
#define DRR		0x0008
#define DRSL		0x0010
#define DNM		0x0020
#define DSMS		0x0100
#define DPAG		0x0200
#define DMI		0x1000
#define DMIB		0x2000

#ifdef DEBUG
#define DEBUGP(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, fmt, ## args)
#else
#define DEBUGP(xss, fmt, args...) 
#endif

#define static_assert(exp, name) typedef int dummy##name [(exp) ? 1 : -1];

void hexdump(unsigned char *buf, int len);
void debugp(unsigned int subsys, char *file, int line, const char *format, ...);
void debug_parse_category_mask(const char* mask);
void debug_use_color(int use_color);
unsigned int debug_mask;

#endif /* _DEBUG_H */
