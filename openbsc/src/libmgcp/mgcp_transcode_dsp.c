/*
 * (C) 2016 by Holger Hans Peter Freyther
 * (C) 2016 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/mgcp_transcode.h>
#include <openbsc/debug.h>

#include <osmocom/core/write_queue.h>

#include <sysmocom/femtobts/trau.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

static const struct value_string trau_names[] = {
	{ Trau_PrimId_GetCapReq,	"Trau_GetCapReq"	},
	{ Trau_PrimId_GetCapCnf,	"Trau_GetCapCnf"	},
	{ Trau_PrimId_AllocChanReq,	"Trau_AllocChanReq" 	},
	{ Trau_PrimId_AllocChanCnf,	"Trau_AllocChanCnf"	},
	{ Trau_PrimId_FreeChanReq,	"Trau_FreeChanReq"	},
	{ Trau_PrimId_SetupChanReq,	"Trau_SetupChanReq"	},
	{ Trau_PrimId_SetupChanCnf,	"Trau_SetupChan_Cnf"	},
	{ Trau_PrimId_ApplyReq,		"Trau_ApplyReq"		},
	{ Trau_PrimId_ApplyCnf,		"Trau_ApplyCnf"		},
	{ 0,				NULL			},
};

enum {
	STATE_NONE,
	STATE_ALLOCATED,
	STATE_BROKEN,
};

struct dsp_transcode_chan {
	int queue_id;
	int state;
	struct llist_head queue;
};

struct dsp_transcode_mgr {
	/* FDs for DSP->ARM, ARM->DSP of the trau queue */
	struct osmo_wqueue trau_a2d;
	struct osmo_fd trau_d2a;

	/* All the channels for transcoding */
	struct dsp_transcode_chan chans[TRAU_MAX_CHANNEL];	
};

static struct dsp_transcode_mgr g_dsp;

static int trau_arm2dsp_cb(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	rc = write(fd->fd, msg->l2h, msgb_l2len(msg));
	if (rc != msgb_l2len(msg)) {
		LOGP(DMGCP, LOGL_ERROR,
			"Failed to write frame to DSP %d/%d%s\n",
			rc, errno, strerror(errno));
		return -1;
	}
	return 0;
}


static void dispatch_trau(struct dsp_transcode_mgr *mgr, struct Trau_Prim *trau)
{
	switch (trau->id) {
	case Trau_PrimId_AllocChanCnf:
		break;
	//case Trau_PrimId_FreeChanCnf:
	// this doesn't exist but should
	}
}

static int trau_dsp2arm_cb(struct osmo_fd *fd, unsigned int what)
{
	struct Trau_Prim trau;
	int rc;

	if (!(what & BSC_FD_READ)) {
		LOGP(DMGCP, LOGL_ERROR,
			"Activated for not read: %u\n", what);
		return -1;
	}

	rc = read(fd->fd, &trau, sizeof(trua));
	if (rc != sizeof(trau)) {
		LOGP(DMGCP, LOGL_ERROR,
			"Failed to to read trau reply.\n");
		return -1;
	}

	dispatch_trau(&g_dsp, &trau);
	return 0;
}

int mgcp_transcoding_dsp_init(void)
{
	int i;

	memset(&g_dsp, 0, sizeof(g_dsp));
	for (i = 0; i < ARRAY_SIZE(g_dsp.chans); ++i)
		INIT_LLIST_HEAD(&g_dsp.chans[i].queue);	

	osmo_wqueue_init(&g_dsp.trau_a2d, 20);
	g_dsp.trau_a2d.bfd.data = &g_dsp;
	g_dsp.trau_a2d.write_cb = trau_arm2dsp_cb;
	g_dsp.trau_a2d.bfd.fd = open("/dev/msgq/trau_arm2dsp", O_WRONLY);
	if (g_dsp.trau_a2d.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to open arm2dsp queue: %d/%s\n",
			g_dsp.trau_a2d.bfd.fd, strerror(errno));
		return 1;
	}

	g_dsp.trau_d2a.data = &g_dsp;
	g_dsp.trau_d2a.cb = trau_dsp2arm_cb;
	g_dsp.trau_d2a.fd = open("/dev/msgq/trau_dsp2arm", O_RDONLY);
	if (g_dsp.trau_d2a.fd < 0) {
		close(g_dsp.trau_a2d.bfd.fd);
		return 2;
	}

	return 0;
}
