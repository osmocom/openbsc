#ifndef _RS232_H
#define _RS232_H

int rs232_setup(const char *serial_port, unsigned int delay_ms,
		struct gsm_bts *bts);

int handle_serial_msg(struct msgb *msg);

#endif /* _RS232_H */
