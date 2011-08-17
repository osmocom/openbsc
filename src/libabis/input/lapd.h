#ifndef OPENBSC_LAPD_H
#define OPENBSC_LAPD_H

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

typedef enum {
	LAPD_MPH_NONE	= 0,

	LAPD_MPH_ACTIVATE_IND,
	LAPD_MPH_DEACTIVATE_IND,

	LAPD_DL_DATA_IND,
	LAPD_DL_UNITDATA_IND,

} lapd_mph_type;

struct lapd_instance {
	struct llist_head list;		/* list of LAPD instances */
	int network_side;

	void (*transmit_cb)(uint8_t *data, int len, void *cbdata);
	void *cbdata;

	struct llist_head tei_list;	/* list of TEI in this LAPD instance */
};

extern uint8_t *lapd_receive(struct lapd_instance *li, uint8_t *data, unsigned int len,
			     int *ilen, lapd_mph_type *prim);

extern void lapd_transmit(struct lapd_instance *li, uint8_t tei, uint8_t sapi,
			  uint8_t *data, unsigned int len);

struct lapd_instance *lapd_instance_alloc(int network_side,
					  void (*tx_cb)(uint8_t *data, int len,
							void *cbdata), void *cbdata);


/* Start a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_start(struct lapd_instance *li, uint8_t tei, uint8_t sapi);

/* Stop a (user-side) SAP for the specified TEI/SAPI on the LAPD instance */
int lapd_sap_stop(struct lapd_instance *li, uint8_t tei, uint8_t sapi);

#endif /* OPENBSC_LAPD_H */
