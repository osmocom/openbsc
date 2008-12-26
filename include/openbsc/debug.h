#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG

#define DRLL		0x0001
#define DCC		0x0002
#define DMM		0x0004
#define DRR		0x0008
#define DRSL		0x0010
#define DNM		0x0020
#define DMI		0x1000

#ifdef DEBUG
#define DEBUGP(ss, fmt, args...) debugp(ss, __FILE__, __LINE__, fmt, ## args)
#else
#define DEBUGP(xss, fmt, args...) 
#endif

void debugp(int subsys, char *file, int line, const char *format, ...);

#endif /* _DEBUG_H */
