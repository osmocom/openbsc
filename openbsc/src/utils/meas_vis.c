#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <netinet/in.h>

#include <cdk/cdk.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/gsm_utils.h>

#include <openbsc/meas_feed.h>

struct ms_state_uni {
	CDKSLIDER *cdk;
	CDKLABEL *cdk_label;

	time_t last_update;
	char label[32];
	char *_lbl[1];
};


struct ms_state {
	struct llist_head list;

	char name[31+1];
	char imsi[15+1];
	struct gsm_meas_rep mr;

	struct ms_state_uni ul;
	struct ms_state_uni dl;
};

struct state {
	struct osmo_fd udp_ofd;
	struct llist_head ms_list;

	CDKSCREEN *cdkscreen;
	WINDOW *curses_win;

	CDKLABEL *cdk_title;
	char *title;

	CDKLABEL *cdk_header;
	char header[256];
};

static struct state g_st;

struct ms_state *find_ms(const char *imsi)
{
	struct ms_state *ms;

	llist_for_each_entry(ms, &g_st.ms_list, list) {
		if (!strcmp(ms->imsi, imsi))
			return ms;
	}
	return NULL;
}

static struct ms_state *find_alloc_ms(const char *imsi)
{
	struct ms_state *ms;

	ms = find_ms(imsi);
	if (!ms) {
		ms = talloc_zero(NULL, struct ms_state);
		osmo_strlcpy(ms->imsi, imsi, sizeof(ms->imsi));
		ms->ul._lbl[0] = ms->ul.label;
		ms->dl._lbl[0] = ms->dl.label;
		llist_add_tail(&ms->list, &g_st.ms_list);
	}

	return ms;
}

static int handle_meas(struct msgb *msg)
{
	struct meas_feed_meas *mfm = (struct meas_feed_meas *) msgb_data(msg);
	struct ms_state *ms = find_alloc_ms(mfm->imsi);
	time_t now = time(NULL);

	osmo_strlcpy(ms->name, mfm->name, sizeof(ms->name));
	memcpy(&ms->mr, &mfm->mr, sizeof(ms->mr));
	ms->ul.last_update = now;
	if (ms->mr.flags & MEAS_REP_F_DL_VALID)
		ms->dl.last_update = now;

	/* move to head of list */
	llist_del(&ms->list);
	llist_add(&ms->list, &g_st.ms_list);

	return 0;
}

static int handle_msg(struct msgb *msg)
{
	struct meas_feed_hdr *mfh = (struct meas_feed_hdr *) msgb_data(msg);

	if (mfh->version != MEAS_FEED_VERSION)
		return -EINVAL;

	switch (mfh->msg_type) {
	case MEAS_FEED_MEAS:
		handle_meas(msg);
		break;
	default:
		break;
	}

	return 0;
}

static int udp_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;

	if (what & BSC_FD_READ) {
		struct msgb *msg = msgb_alloc(1024, "UDP Rx");

		rc = read(ofd->fd, msgb_data(msg), msgb_tailroom(msg));
		if (rc < 0)
			return rc;
		msgb_put(msg, rc);
		handle_msg(msg);
		msgb_free(msg);
	}

	return 0;
}


static void destroy_dir(struct ms_state_uni *uni)
{
	if (uni->cdk) {
		destroyCDKSlider(uni->cdk);
		uni->cdk = NULL;
	}
	if (uni->cdk_label) {
		destroyCDKLabel(uni->cdk_label);
		uni->cdk_label = NULL;
	}
}

#define DIR_UL	0
#define DIR_DL	1
static const char *dir_str[2] = {
	[DIR_UL]	= "UL",
	[DIR_DL]	= "DL",
};

static int colpair_by_qual(uint8_t rx_qual)
{
	if (rx_qual == 0)
		return 24;
	else if (rx_qual <= 4)
		return 32;
	else
		return 16;
}

static int colpair_by_lev(int rx_lev)
{
	if (rx_lev < -95)
		return 16;
	else if (rx_lev < -80)
		return 32;
	else
		return 24;
}


void write_uni(struct ms_state *ms, struct ms_state_uni *msu,
		struct gsm_rx_lev_qual *lq, int dir, int row)
{

	char label[128];
	time_t now = time(NULL);
	int qual_col = colpair_by_qual(lq->rx_qual);
	int lev_col = colpair_by_lev(rxlev2dbm(lq->rx_lev));
	int color, pwr;

	if (dir == DIR_UL) {
		pwr = ms->mr.ms_l1.pwr;
	} else {
		pwr = ms->mr.bs_power;
	}

	color = A_REVERSE | COLOR_PAIR(lev_col) | ' ';
	snprintf(label, sizeof(label), "%s %s ", ms->imsi, dir_str[dir]);
	msu->cdk = newCDKSlider(g_st.cdkscreen, 0, row, NULL, label, color,
				  COLS-40, rxlev2dbm(lq->rx_lev), -110, -47,
				  1, 2, FALSE, FALSE);
	//IsVisibleObj(ms->ul.cdk) = FALSE;
	snprintf(msu->label, sizeof(msu->label), "</%d>%1d<!%d> %3d %2u %2d %4u",
		 qual_col, lq->rx_qual, qual_col, pwr,
		 ms->mr.ms_l1.ta, ms->mr.ms_timing_offset,
		 now - msu->last_update);
	msu->cdk_label = newCDKLabel(g_st.cdkscreen, RIGHT, row,
					msu->_lbl, 1, FALSE, FALSE);
}

static void update_sliders(void)
{
	int num_vis_sliders = 0;
	struct ms_state *ms;
#define HEADER_LINES 2

	/* remove all sliders */
	llist_for_each_entry(ms, &g_st.ms_list, list) {
		destroy_dir(&ms->ul);
		destroy_dir(&ms->dl);

	}

	llist_for_each_entry(ms, &g_st.ms_list, list) {
		struct gsm_rx_lev_qual *lq;
		unsigned int row = HEADER_LINES + num_vis_sliders*3;

		if (ms->mr.flags & MEAS_REP_F_UL_DTX)
			lq = &ms->mr.ul.sub;
		else
			lq = &ms->mr.ul.full;
		write_uni(ms, &ms->ul, lq, DIR_UL, row);

		if (ms->mr.flags & MEAS_REP_F_DL_DTX)
			lq = &ms->mr.dl.sub;
		else
			lq = &ms->mr.dl.full;
		write_uni(ms, &ms->dl, lq, DIR_DL, row+1);

		num_vis_sliders++;
		if (num_vis_sliders >= LINES/3)
			break;
	}

	refreshCDKScreen(g_st.cdkscreen);

}

const struct value_string col_strs[] = {
	{ COLOR_WHITE,	"white" },
	{ COLOR_RED,	"red" },
	{ COLOR_GREEN,	"green" },
	{ COLOR_YELLOW,	"yellow" },
	{ COLOR_BLUE,	"blue" },
	{ COLOR_MAGENTA,"magenta" },
	{ COLOR_CYAN,	"cyan" },
	{ COLOR_BLACK, 	"black" },
	{ 0, NULL }
};

int main(int argc, char **argv)
{
	int rc;
	char *header[1];
	char *title[1];

	msgb_talloc_ctx_init(NULL, 0);

	printf("sizeof(gsm_meas_rep)=%u\n", sizeof(struct gsm_meas_rep));
	printf("sizeof(meas_feed_meas)=%u\n", sizeof(struct meas_feed_meas));

	INIT_LLIST_HEAD(&g_st.ms_list);
	g_st.curses_win = initscr();
	g_st.cdkscreen = initCDKScreen(g_st.curses_win);
	initCDKColor();

	g_st.title = "OpenBSC link quality monitor";
	title[0] = g_st.title;
	g_st.cdk_title = newCDKLabel(g_st.cdkscreen, CENTER, 0, title, 1, FALSE, FALSE);

	snprintf(g_st.header, sizeof(g_st.header), "Q Pwr TA TO Time");
	header[0] = g_st.header;
	g_st.cdk_header = newCDKLabel(g_st.cdkscreen, RIGHT, 1, header, 1, FALSE, FALSE);

#if 0
	int i;
	for (i = 0; i < 64; i++) {
		short f, b;
		pair_content(i, &f, &b);
		attron(COLOR_PAIR(i));
		printw("%u: %u (%s) ", i, f, get_value_string(col_strs, f));
		printw("%u (%s)\n\r", b, get_value_string(col_strs, b));
	}
	refresh();
	getch();
	exit(0);
#endif

	g_st.udp_ofd.cb = udp_fd_cb;
	rc =  osmo_sock_init_ofd(&g_st.udp_ofd, AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 8888, OSMO_SOCK_F_BIND);
	if (rc < 0)
		exit(1);

	while (1) {
		osmo_select_main(0);
		update_sliders();
	};

	exit(0);
}
