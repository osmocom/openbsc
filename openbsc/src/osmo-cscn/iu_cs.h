#pragma once

#include <openbsc/iu.h>

int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg, uint8_t link_id);
