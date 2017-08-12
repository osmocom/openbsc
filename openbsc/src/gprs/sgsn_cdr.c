/* GPRS SGSN CDR dumper */

/* (C) 2015 by Holger Hans Peter Freyther
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

#include <openbsc/sgsn.h>
#include <openbsc/signal.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/debug.h>
#include <osmocom/gsm/apn.h>

#include <openbsc/vty.h>

#include <gtp.h>
#include <pdp.h>

#include <arpa/inet.h>

#include <time.h>

#include <stdio.h>
#include <inttypes.h>

/* TODO...avoid going through a global */
extern struct sgsn_instance *sgsn;

/**
 * The CDR module will generate an entry like:
 *
 * IMSI, # Subscriber IMSI
 * IMEI, # Subscriber IMEI
 * MSISDN, # Subscriber MISDN
 * Charging_Timestamp, # Event start Time
 * Charging_UTC, # Time zone of event start time
 * Duration, # Session DURATION
 * Cell_Id, # CELL_ID
 * Location_Area, # LAC
 * GGSN_ADDR, # GGSN_ADDR
 * SGSN_ADDR, # SGSN_ADDR
 * APNI, # APNI
 * PDP_ADDR, # PDP_ADDR
 * VOL_IN, # VOL_IN in Bytes
 * VOL_OUT, # VOL_OUT in Bytes
 * CAUSE_FOR_TERM, # CAUSE_FOR_TERM
 */


static void maybe_print_header(FILE *cdr_file)
{
	if (ftell(cdr_file) != 0)
		return;

	fprintf(cdr_file, "timestamp,imsi,imei,msisdn,cell_id,lac,hlr,event,pdp_duration,ggsn_addr,sgsn_addr,apni,eua_addr,vol_in,vol_out,charging_id\n");
}

static void cdr_log_mm(struct sgsn_instance *inst, const char *ev,
			struct sgsn_mm_ctx *mmctx)
{
	FILE *cdr_file;
	struct tm tm;
	struct timeval tv;

	if (!inst->cfg.cdr.filename)
		return;

	cdr_file = fopen(inst->cfg.cdr.filename, "a");
	if (!cdr_file) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to open %s\n",
			inst->cfg.cdr.filename);
		return;
	}

	maybe_print_header(cdr_file);
	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);
	fprintf(cdr_file, "%04d%02d%02d%02d%02d%02d%03d,%s,%s,%s,%d,%d,%s,%s\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(int)(tv.tv_usec / 1000),
		mmctx->imsi,
		mmctx->imei,
		mmctx->msisdn,
		mmctx->gb.cell_id,
		mmctx->ra.lac,
		mmctx->hlr,
		ev);

	fclose(cdr_file);
}

static void extract_eua(struct ul66_t *eua, char *eua_addr)
{
	if (eua->l < 2)
		return;

	/* there is no addr for ETSI/PPP */
	if ((eua->v[0] & 0x0F) != 1) {
		strcpy(eua_addr, "ETSI");
		return;
	}

	if (eua->v[1] == 0x21 && eua->l == 6)
		inet_ntop(AF_INET, &eua->v[2], eua_addr, INET_ADDRSTRLEN);
	else if (eua->v[1] == 0x57 && eua->l == 18)
		inet_ntop(AF_INET6, &eua->v[2], eua_addr, INET6_ADDRSTRLEN);
	else {
		/* e.g. both IPv4 and IPv6 */
		strcpy(eua_addr, "Unknown address");
	}
}

static void cdr_log_pdp(struct sgsn_instance *inst, const char *ev,
			struct sgsn_pdp_ctx *pdp)
{
	FILE *cdr_file;
	char apni[(pdp->lib ? pdp->lib->apn_use.l : 0) + 1];
	char ggsn_addr[INET_ADDRSTRLEN + 1];
	char sgsn_addr[INET_ADDRSTRLEN + 1];
	char eua_addr[INET6_ADDRSTRLEN + 1];
	struct tm tm;
	struct timeval tv;
	time_t duration;
	struct timespec tp;

	if (!inst->cfg.cdr.filename)
		return;

	memset(apni, 0, sizeof(apni));
	memset(ggsn_addr, 0, sizeof(ggsn_addr));
	memset(eua_addr, 0, sizeof(eua_addr));


	if (pdp->lib) {
		osmo_apn_to_str(apni, pdp->lib->apn_use.v, pdp->lib->apn_use.l);
		inet_ntop(AF_INET, &pdp->lib->hisaddr0.s_addr, ggsn_addr, sizeof(ggsn_addr));
		extract_eua(&pdp->lib->eua, eua_addr);
	}

	if (pdp->ggsn)
		inet_ntop(AF_INET, &pdp->ggsn->gsn->gsnc.s_addr, sgsn_addr, sizeof(sgsn_addr));

	cdr_file = fopen(inst->cfg.cdr.filename, "a");
	if (!cdr_file) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to open %s\n",
			inst->cfg.cdr.filename);
		return;
	}

	maybe_print_header(cdr_file);

	clock_gettime(CLOCK_MONOTONIC, &tp);
	gettimeofday(&tv, NULL);

	/* convert the timestamp to UTC */
	gmtime_r(&tv.tv_sec, &tm);

	/* Check the duration of the PDP context */
	duration = tp.tv_sec - pdp->cdr_start.tv_sec;

	fprintf(cdr_file,
		"%04d%02d%02d%02d%02d%02d%03d,%s,%s,%s,%d,%d,%s,%s,%ld,%s,%s,%s,%s,%" PRIu64 ",%" PRIu64 ",%u\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(int)(tv.tv_usec / 1000),
		pdp->mm ? pdp->mm->imsi : "N/A",
		pdp->mm ? pdp->mm->imei : "N/A",
		pdp->mm ? pdp->mm->msisdn : "N/A",
		pdp->mm ? pdp->mm->gb.cell_id : -1,
		pdp->mm ? pdp->mm->ra.lac : -1,
		pdp->mm ? pdp->mm->hlr : "N/A",
		ev,
		(unsigned long ) duration,
		ggsn_addr,
		sgsn_addr,
		apni,
		eua_addr,
		pdp->cdr_bytes_in,
		pdp->cdr_bytes_out,
		pdp->cdr_charging_id);
	fclose(cdr_file);
}

static void cdr_pdp_timeout(void *_data)
{
	struct sgsn_pdp_ctx *pdp = _data;
	cdr_log_pdp(sgsn, "pdp-periodic", pdp);
	osmo_timer_schedule(&pdp->cdr_timer, sgsn->cfg.cdr.interval, 0);
}

static int handle_sgsn_sig(unsigned int subsys, unsigned int signal,
			void *handler_data, void *_signal_data)
{
	struct sgsn_signal_data *signal_data = _signal_data;
	struct sgsn_instance *inst = handler_data;

	if (subsys != SS_SGSN)
		return 0;

	switch (signal) {
	case S_SGSN_ATTACH:
		cdr_log_mm(inst, "attach", signal_data->mm);
		break;
	case S_SGSN_UPDATE:
		cdr_log_mm(inst, "update", signal_data->mm);
		break;
	case S_SGSN_DETACH:
		cdr_log_mm(inst, "detach", signal_data->mm);
		break;
	case S_SGSN_MM_FREE:
		cdr_log_mm(inst, "free", signal_data->mm);
		break;
	case S_SGSN_PDP_ACT:
		clock_gettime(CLOCK_MONOTONIC, &signal_data->pdp->cdr_start);
		signal_data->pdp->cdr_charging_id = signal_data->pdp->lib->cid;
		cdr_log_pdp(inst, "pdp-act", signal_data->pdp);
		osmo_timer_setup(&signal_data->pdp->cdr_timer, cdr_pdp_timeout,
				 signal_data->pdp);
		osmo_timer_schedule(&signal_data->pdp->cdr_timer, inst->cfg.cdr.interval, 0);
		break;
	case S_SGSN_PDP_DEACT:
		cdr_log_pdp(inst, "pdp-deact", signal_data->pdp);
		osmo_timer_del(&signal_data->pdp->cdr_timer);
		break;
	case S_SGSN_PDP_TERMINATE:
		cdr_log_pdp(inst, "pdp-terminate", signal_data->pdp);
		osmo_timer_del(&signal_data->pdp->cdr_timer);
		break;
	case S_SGSN_PDP_FREE:
		cdr_log_pdp(inst, "pdp-free", signal_data->pdp);
		osmo_timer_del(&signal_data->pdp->cdr_timer);
		break;
	}

	return 0;
}

int sgsn_cdr_init(struct sgsn_instance *sgsn)
{
	/* register for CDR related events */
	sgsn->cfg.cdr.interval = 10 * 60;
	osmo_signal_register_handler(SS_SGSN, handle_sgsn_sig, sgsn);

	return 0;
}
