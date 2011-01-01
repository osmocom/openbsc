
#include <openbsc/linuxlist.h>

struct network_info {
	struct llist_head list;

	u_int16_t mcc;
	u_int16_t mnc;

	struct llist_head bcch_infos;
};

static LLIST_HEAD(bcch_infos);

static LLIST_HEAD(network_infos);

static struct network_info *network_find(u_int16_t mcc, u_int16_t mnc)
{
	struct network_info *ni;

	llist_for_each_head(ni, &network_infos, list) {
		if (ni->mcc == mcc && ni->mnc == mnc)
			return ni;
	}

	return NULL;
}

static struct network_info *network_alloc(u_int16_t mcc, u_int16_t mnc)
{
	struct network_info *ni = talloc_zero(NULL, struct network_info);

	if (!ni)
		return NULL;

	ni->mcc = mcc;
	ni->mnc = mnc;

	llist_add_tail(&ni->list, &network_infos);
	
	return ni;
}

/* here we get handed in the BCCH info structure */
int receive_bcch_info(const struct ipac_bcch_info *binfo)
{
	struct ipac_bcch_info *binfo2;
	struct network_info *ni;

	binfo2 = talloc_zero(NULL, struct ipac_bcch_info);
	if (!binfo2)
		return -ENOMEM;

	memcpy(binfo2, binfo, sizeof(*binfo2));

	ni = network_find(binfo->cgi.mcc, binfo->cgi.mnc);
	if (!ni)
		ni = network_alloc(binfo->cgi.mcc, binfo->cgi.mnc);

	llist_add_tail(&binfo2->list, &ni->bcch_infos);

	return 0;
}


