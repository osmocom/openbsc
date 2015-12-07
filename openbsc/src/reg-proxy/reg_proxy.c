#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>



#define _GNU_SOURCE
#include <getopt.h>

#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ENABLE_TRACE
#include <osip2/osip.h>

//#define _GNU_SOURCE
//#include <getopt.h>

//#include <openbsc/db.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <openbsc/debug.h>
//#include <osmocom/abis/abis.h>
//#include <osmocom/abis/e1_input.h>
#include <osmocom/core/talloc.h>
#include <openbsc/signal.h>
//#include <openbsc/osmo_msc.h>
//#include <openbsc/osmo_msc_data.h>
//#include <openbsc/sms_queue.h>
//#include <openbsc/vty.h>
//#include <openbsc/bss.h>
//#include <openbsc/mncc.h>
//#include <openbsc/token_auth.h>
//#include <openbsc/handover_decision.h>
//#include <openbsc/rrlp.h>
//#include <osmocom/ctrl/control_if.h>
//#include <osmocom/ctrl/ports.h>
//#include <openbsc/ctrl.h>
//#include <openbsc/osmo_bsc_rf.h>
//#include <openbsc/smpp.h>
#include <openbsc/reg_proxy.h>
#include <openbsc/sup.h>
#include <openbsc/sip.h>

#define DIPA_PROXY_TEST 0

static const char *sip_src_ip = "127.0.0.1";
static const char *sip_dst_ip = "127.0.0.1";
static u_int16_t src_port = 5150;
static u_int16_t dst_port = 5060;
static int expires_time = 3600;

struct log_info_cat ipa_proxy_test_cat[] = {
	[DIPA_PROXY_TEST] = {
		.name = "DLINP_IPA_PROXY_TEST",
		.description = "IPA proxy test",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info ipa_proxy_test_log_info = {
	.filter_fn = NULL,
	.cat = ipa_proxy_test_cat,
	.num_cat = ARRAY_SIZE(ipa_proxy_test_cat),
};


static void print_usage()
{
	printf("Usage: reg-proxy\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -S --sip-src-ip ip-addr Sip client IP address (source).\n");
	printf("  -s --src-port port Sip client port (source).\n");
	printf("  -D --sip-dst-ip ip-addr Sip server IP address (destination).\n");
	printf("  -d --dst-port port Sip server port (destination).\n");
	printf("  -t --expires-time Registration expiry time in seconds.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"sip-src-ip", 1, 0, 'S'},
			{"src-port", 1, 0, 's'},
			{"sip-dst-ip", 1, 0, 'D'},
			{"dst-port", 1, 0, 'd'},
			{"expires-time", 1, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hS:s:D:d:t:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'S':
			sip_src_ip = optarg;
			break;
		case 's':
			src_port = atoi(optarg);
			break;
		case 'D':
			sip_dst_ip = optarg;
			break;
		case 'd':
			dst_port = atoi(optarg);
			break;
		case 't':
			expires_time = atoi(optarg);
			break;
		default:
			/* ignore */
			break;
		}
	}
}


struct reg_proxy *reg_proxy_init()
{
	struct reg_proxy *reg;

	reg = talloc_zero(tall_reg_ctx, struct reg_proxy);
	if (!reg)
		return NULL;
	return reg;
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		//bsc_shutdown_net(bsc_gsmnet);
		//osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_reg_ctx, stderr);
		talloc_report_full(tall_reg_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_reg_ctx, stderr);
		break;
	default:
		break;
	}
}

void printf_trace_func (char *fi, int li, osip_trace_level_t level, char *chfr, va_list ap)
{
    const char* desc = "       ";
    switch(level)
    {
    case OSIP_FATAL:
        desc = " FATAL ";
        break;
    case OSIP_BUG:
        desc = "  BUG  ";
        break;
    case OSIP_ERROR:
        desc = " ERROR ";
        break;
    case OSIP_WARNING:
        desc = "WARNING";
        break;
    case OSIP_INFO1:
        desc = " INFO1 ";
        break;
    case OSIP_INFO2:
        desc = " INFO2 ";
        break;
    case OSIP_INFO3:
        desc = " INFO3 ";
        break;
    case OSIP_INFO4:
        desc = " INFO4 ";
        break;
    default:
        desc = "       ";
    }
    
    printf ("|%s| <%s: %i> | ", desc, fi, li);
    vprintf(chfr, ap);
    printf ("\n");
}


int main(int argc, char **argv)
{
	int rc;
	struct reg_proxy *reg;

	tall_reg_ctx = talloc_named_const(NULL, 1, "reg_proxy");
	//talloc_ctx_init();

	//libosmo_abis_init(tall_reg_ctx);
	osmo_init_logging(&log_info);
	printf("Initializing OSIP\n");
	
	// use custom function
	osip_trace_initialize_func(END_TRACE_LEVEL, &printf_trace_func);


	//osmo_init_logging(&ipa_proxy_test_log_info);

	/* seed the PRNG */
	//srand(time(NULL));

/*
	if (db_init(database_name)) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return -1;
	}
	printf("DB: Database prepared.\n");
*/
	/* parse options */
	handle_options(argc, argv);

	reg = reg_proxy_init();
	if (!reg) {
		LOGP(DSUP, LOGL_FATAL, "Cannot create reg_proxy struck\n");
		exit(2);
	}
	rc = sup_server_init(reg);
	if (rc < 0) {
		LOGP(DSUP, LOGL_FATAL, "Cannot set up subscriber management\n");
		exit(2);
	}

////////////////////////////////

	rc = sip_client_init(reg, sip_src_ip, src_port, sip_dst_ip, dst_port, expires_time);
	if (rc < 0) {
		LOGP(DSUP, LOGL_FATAL, "Cannot set up SIP\n");
		exit(2);
	}




	/* setup the timer */
/*
	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	if (use_db_counter)
		osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

	bsc_gsmnet->subscr_expire_timer.cb = subscr_expire_cb;
	bsc_gsmnet->subscr_expire_timer.data = NULL;
	osmo_timer_schedule(&bsc_gsmnet->subscr_expire_timer, EXPIRE_INTERVAL);
*/
	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

/*
	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}
*/
	printf("Entering Main loop 1\n");
	OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"Check OSIP_TRACE init\n"));

	while (1) {
		log_reset_context();
		osmo_select_main(0); //<-- TIMER handling
		osip_nict_execute(reg->osip);
		osip_timers_nict_execute(reg->osip);

		osip_ict_execute(reg->osip);
		osip_timers_ict_execute(reg->osip);

		osip_nist_execute(reg->osip);
		osip_timers_nist_execute(reg->osip);

		osip_ist_execute(reg->osip);
		osip_timers_ist_execute(reg->osip);

		osip_retransmissions_execute(reg->osip);
	}
}
