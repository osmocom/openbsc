
#include "ganc_data.h"


void ganc_bts_init(struct ganc_bts *bts, struct ganc_net *net)
{
	bts->net = net;
	bts->location_area_code = 1;
	bts->routing_area_code = 1;
	bts->cell_identity = 1;
	bts->arfcn = 871;
	bts->bsic = 63;
}

void ganc_net_init(struct ganc_net *net)
{
	net->country_code = 901;
	net->network_code = 70;

	net->timer[TU3901] = 30;	/* seconds */
	net->timer[TU3902] = 30;	/* seconds */
	net->timer[TU3903] = 1;		/* minute */
	net->timer[TU3904] = 30;	/* seconds */
	net->timer[TU3905] = 10;	/* seconds */
	net->timer[TU3906] = 30;	/* seconds */
	net->timer[TU3907] = 30;	/* seconds */
	net->timer[TU3908] = 5;		/* seconds */
	net->timer[TU3910] = 10;
	net->timer[TU3920] = 10;
	net->timer[TU4001] = 10;
	net->timer[TU4002] = 5;		/* seconds */
	net->timer[TU4003] = 5;	
	net->timer[T3212] = 1;		/* 6 minutes */
}
