/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file radiusd.c
 * @brief Main loop of the radius server.
 *
 * @copyright 2000-2018 The FreeRADIUS server project
 * @copyright 1999,2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman-radius@cqc.com)
 * @copyright 2000 Jeff Carneal (jeff@apex.net)
 * @copyright 2000 Chad Miller (cmiller@surfsouth.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/server/snmp.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/size.h>
#include <freeradius-devel/util/strerror.h>

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/log.h>

#include <freeradius-devel/unlang/base.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>

#ifdef HAVE_CAPABILITY_H
#include <freeradius-devel/util/cap.h>
#endif

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/mman.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#  define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#  define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#ifdef WITH_TLS
#  include <freeradius-devel/tls/version.h>
#endif

char const	*radiusd_version = RADIUSD_VERSION_BUILD("FreeRADIUS");
static pid_t	radius_pid;
static char const	*program = NULL;

/*
 *  Configuration items.
 */

/*
 *	Static functions.
 */
static void usage(int status);

static void sig_fatal (int);
#ifdef SIGHUP
static void sig_hup (int);
#endif

/** Configure talloc debugging features
 *
 * @param[in] config	The main config.
 * @return
 *	- 1 on config conflict.
 *	- 0 on success.
 *	- -1 on error.
 */
static int talloc_config_set(main_config_t *config)
{
	if (config->spawn_workers) {
		if (config->talloc_memory_report) {
			fr_strerror_printf("talloc_memory_report requires single threaded mode (-s | -X)");
			return 1;
		}
		return 0;
	}

	if (!config->talloc_memory_report) {
		talloc_disable_null_tracking();
		return 0;
	}

	talloc_enable_null_tracking();

	return 0;
}


/** Create module and xlat per-thread instances
 *
 */
static int thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el, UNUSED void *uctx)
{
	if (modules_rlm_thread_instantiate(ctx, el) < 0) return -1;

	if (virtual_servers_thread_instantiate(ctx, el) < 0) return -1;

	if (xlat_thread_instantiate(ctx, el) < 0) return -1;
#ifdef WITH_TLS
	if (fr_openssl_thread_init(main_config->openssl_async_pool_init,
				   main_config->openssl_async_pool_max) < 0) return -1;
#endif
	return 0;
}

/** Explicitly cleanup module/xlat resources
 *
 */
static void thread_detach(UNUSED void *uctx)
{
	virtual_servers_thread_detach();

	modules_rlm_thread_detach();

	xlat_thread_detach();
}

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

#define EXIT_WITH_SUCCESS \
do { \
	ret = EXIT_SUCCESS; \
	goto cleanup; \
} while (0)

#define EXIT_WITH_PERROR \
do { \
	fr_perror("%s", program); \
	EXIT_WITH_FAILURE; \
} while (0)

static fr_timer_t *fr_time_sync_ev = NULL;

static void fr_time_sync_event(fr_timer_list_t *tl, UNUSED fr_time_t now, UNUSED void *uctx)
{
	fr_time_delta_t when = fr_time_delta_from_sec(1);

	(void) fr_timer_in(tl, tl, &fr_time_sync_ev, when, false, fr_time_sync_event, NULL);
	(void) fr_time_sync();
}

#ifndef NDEBUG
/** Encourage the server to exit after a period of time
 *
 * @param[in] tl	The main loop.
 * @param[in] now	Current time.  Should be 0, when adding the event.
 * @param[in] uctx	Pointer to a fr_time_delta_t indicating how long
 *			the server should run before exit.
 */
static void fr_exit_after(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	static fr_timer_t *ev;

	fr_time_delta_t	exit_after = *(fr_time_delta_t *)uctx;

	if (fr_time_eq(now, fr_time_wrap(0))) {
		if (fr_timer_in(tl, tl, &ev, exit_after, false, fr_exit_after, uctx) < 0) {
			PERROR("%s: Failed inserting exit event", program);
		}
		return;
	}

	main_loop_signal_raise(RADIUS_SIGNAL_SELF_TERM);
}
#endif

#ifdef HAVE_CAPABILITY_H
#define DUMP_CAPABILITIES(_phase) \
{ \
	char *cap_str; \
	if (fr_cap_set_to_str(talloc_autofree_context(), &cap_str) < 0) { \
		PWARN("Failed retrieving %s capabilities", _phase); \
	} else { \
		INFO("%s capabilities: %s", _phase, cap_str); \
		talloc_free(cap_str); \
	} \
}
#else
#define DUMP_CAPABILITIES(_phase)
#endif

/** Entry point for the daemon
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			status;
	int			c;
	bool			display_version = false;
	bool			radmin = false;
	int			from_child[2] = {-1, -1};
	fr_schedule_t		*sc = NULL;
	int			ret = EXIT_SUCCESS;

	TALLOC_CTX		*global_ctx = NULL;
	main_config_t		*config = NULL;
	bool			talloc_memory_report = false;

	bool			confdir_set = false;

	size_t			pool_size = 0;
	void			*pool_page_start = NULL;
	size_t			pool_page_len = 0;
	bool			do_mprotect;
	int			std_fd[3];

#ifndef NDEBUG
	fr_time_delta_t	exit_after = fr_time_delta_wrap(0);
#endif
	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	/*
	 *	Setup talloc callbacks so we get useful errors
	 */
	(void) fr_talloc_fault_setup();

	/*
	 *	Set some default values
	 */
	program = strrchr(argv[0], FR_DIR_SEP);
	if (!program) {
		program = argv[0];
	} else {
		program++;
	}

	/*
	 * 	We probably don't want to free the talloc global_ctx context
	 * 	directly, so we'll allocate a new context beneath it, and
	 *	free that before any leak reports.
	 */
	{
		char *env;

		/*
		 *	If a FR_GLOBAL_POOL value is provided and
		 *	is of a valid size, we pre-allocate a global
		 *	memory pool, and mprotect() it once we're done
		 *	parsing the global config.
		 *
		 *	This lets us catch stray writes into global
		 *	memory.
		 */
		env = getenv("FR_GLOBAL_POOL");
		if (env) {
			if (fr_size_from_str(&pool_size, &FR_SBUFF_IN_STR(env)) < 0) {
				fr_perror("%s: Invalid pool size string \"%s\"", program, env);
				EXIT_WITH_FAILURE;
			}

			/*
			 *	Pre-allocate a global memory pool for the static
			 *	config to exist in.  We mprotect() this later to
			 *	catch any stray writes.
			 */
			global_ctx = talloc_page_aligned_pool(talloc_autofree_context(),
							      &pool_page_start, &pool_page_len, 0, pool_size);
			do_mprotect = true;
		} else {
	 		global_ctx = talloc_new(talloc_autofree_context());
	 		do_mprotect = false;
		}

		if (!global_ctx) {
			fprintf(stderr, "Failed allocating global context\n");
			EXIT_WITH_FAILURE;
		}
	}

	/*
	 *	Allocate the main config structure.
	 *	It's allocated so we can hang talloced buffers off it.
	 */
	config = main_config_alloc(global_ctx);
	if (!config) {
		fprintf(stderr, "Failed allocating main config");
		EXIT_WITH_FAILURE;
	}

	main_config_name_set_default(config, program, false);

	config->daemonize = true;
	config->spawn_workers = true;

	fr_debug_lvl = 0;
	fr_time_start();

	/*
	 *	Don't put output anywhere until we get told a little
	 *	more.
	 */
	default_log.dst = L_DST_NULL;
	default_log.fd = -1;
	default_log.print_level = true;
	default_log.suppress_secrets = true;

	/*
	 *  Set the panic action and enable other debugging facilities
	 */
	if (fr_fault_setup(global_ctx, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("%s: Failed installing fault handlers... continuing", program);
	}

	/*  Process the options.  */
	while ((c = getopt(argc, argv, "Cd:D:e:fhi:l:Mmn:p:PrsS:tTvxX")) != -1) switch (c) {
		case 'C':
			check_config = true;
			config->spawn_workers = false;
			config->daemonize = false;
			break;

		case 'd':
			main_config_confdir_set(config, optarg);
			confdir_set = true;
			break;

		case 'D':
			main_config_dict_dir_set(config, optarg);
			break;

		case 'e':
			/*
			 *	For non-debug builds, accept '-e', but ignore it.
			 */
#ifndef NDEBUG
			exit_after = fr_time_delta_from_sec(atoi(optarg));
#endif
			break;

		case 'f':
			config->daemonize = false;
			break;

		case 'h':
			usage(EXIT_SUCCESS);
			break;

		case 'l':
			if (strcmp(optarg, "stdout") == 0) goto do_stdout;

			config->log_file = talloc_typed_strdup(global_ctx, optarg);
			default_log.file = talloc_typed_strdup(global_ctx, optarg);
			default_log.dst = L_DST_FILES;
			default_log.fd = open(config->log_file, O_WRONLY | O_APPEND | O_CREAT, 0640);
			if (default_log.fd < 0) {
				fprintf(stderr, "%s: Failed to open log file %s: %s\n",
					program, config->log_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
			break;

		case 'm':
			config->allow_multiple_procs = true;
			break;

		case 'M':
			config->talloc_memory_report = true;
			break;

		case 'n':
			main_config_name_set_default(config, optarg, true);
			break;

		case 'P':	/* Force the PID to be written, even in -f mode */
			config->write_pid = true;
			break;

		case 'r':	/* internal radmin-style control interface */
			config->spawn_workers = false;
			config->daemonize = false;
			radmin = true;
			break;

		case 's':	/* Single process mode */
			config->spawn_workers = false;
			config->daemonize = false;
			break;

		case 'S':	/* Migration support */
#if 0
			if (main_config_parse_option(optarg) < 0) {
				fprintf(stderr, "%s: Unknown configuration option '%s'\n",
					program, optarg);
				EXIT_WITH_FAILURE;
			}
#endif
			break;

		case 't':	/* no child threads */
			config->spawn_workers = false;
			break;

		case 'T':	/* enable timestamps */
			default_log.timestamp = L_TIMESTAMP_ON;
			break;

		case 'v':
			display_version = true;
			break;

		case 'X':
			config->spawn_workers = false;
			config->daemonize = false;
			fr_debug_lvl += 2;

	do_stdout:
			default_log.dst = L_DST_STDOUT;
			default_log.fd = STDOUT_FILENO;
			break;

		case 'x':
			fr_debug_lvl++;
			break;

		default:
			usage(EXIT_FAILURE);
			break;
	}

	if (fr_debug_lvl > 2) default_log.suppress_secrets = false;

	/*
	 *	Allow the configuration directory to be set from an
	 *	environment variable.  This allows tests to change the
	 *	configuration directory without changing the scripts
	 *	being executed.
	 */
	if (!confdir_set) {
		char const *confdir = getenv("FREERADIUS_CONFIG_DIR");

		if (confdir) main_config_confdir_set(config, confdir);
	}

	/*
	 *	We've now got enough information to check to see
	 *	if another process is running with the same config.
	 */
	config->debug_level = fr_debug_lvl;

	/*
	 *  Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		EXIT_WITH_PERROR;
	}

	if (rad_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) EXIT_WITH_FAILURE;

#ifdef WITH_TLS
	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
	if (fr_openssl_version_consistent() < 0) EXIT_WITH_FAILURE;

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 *  Must be called before display_version to ensure relevant engines are loaded.
	 *
	 *  fr_openssl_init() must be called before *ANY* OpenSSL functions are used, which is why
	 *  it's called so early.
	 */
	if (fr_openssl_init() < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *  According to the talloc peeps, no two threads may modify any part of
	 *  a ctx tree with a common root without synchronisation.
	 *
	 *  So we can't run with a null context and threads.
	 */
	if (talloc_config_set(config) != 0) {
		EXIT_WITH_PERROR;
	}

	/*
	 *  Better here, so it doesn't matter whether we get passed -xv or -vx.
	 */
	if (display_version) {
		if (fr_debug_lvl == 0) fr_debug_lvl = 1;
		default_log.dst = L_DST_STDOUT;
		default_log.fd = STDOUT_FILENO;

		INFO("%s - %s", program, radiusd_version);
		dependency_version_print();
		EXIT_WITH_SUCCESS;
	}

	if (fr_debug_lvl) dependency_version_print();

	/*
	 *  Under linux CAP_SYS_PTRACE is usually only available before setuid/setguid,
	 *  so we need to check whether we can attach before calling those functions
	 *  (in main_config_init()).
	 */
	fr_debug_state_store();

	/*
	 *  Write the PID always if we're running as a daemon.
	 */
	if (config->daemonize) config->write_pid = true;

        /*
	 *      Initialize the DL infrastructure, which is used by the
	 *      config file parser.  Note that we pass an empty path
	 *      here, as we haven't yet read the configuration file.
	 */
	modules_init(NULL);

	/*
	 *	Initialise the top level dictionary hashes which hold
	 *	the protocols.
	 */
	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		EXIT_WITH_PERROR;
	}

#ifdef WITH_TLS
	if (fr_tls_dict_init() < 0) {
		EXIT_WITH_PERROR;
	}
#endif

	/*
	 *	Setup the global structures for module lists
	 */
	if (modules_rlm_init() < 0) {
		EXIT_WITH_PERROR;
	}

	if (virtual_servers_init() < 0) {
		EXIT_WITH_PERROR;
	}

	/*
	 *	Load dictionary attributes used
	 *	for requests.
	 */
	if (request_global_init() < 0) {
		EXIT_WITH_PERROR;
	}

	/*
	 *	The radmin functions need to write somewhere.
	 *
	 *	The log functions redirect stdin and stdout to /dev/null, so that exec'd programs can't mangle
	 *	them.  But radmin needs to be able to use them.
	 */
#define RDUP(_x) \
do { \
	if ((std_fd[_x] = dup(_x)) < 0) EXIT_WITH_PERROR; \
	if (fr_cloexec(std_fd[_x]) < 0) EXIT_WITH_PERROR; \
} while (0)

	if (radmin) {
	  	RDUP(STDIN_FILENO);
	  	RDUP(STDOUT_FILENO);
	  	RDUP(STDERR_FILENO);
	}

	/*
	 *  Read the configuration files, BEFORE doing anything else.
	 */
	if (main_config_init(config) < 0) EXIT_WITH_FAILURE;

	if (!config->suppress_secrets) default_log.suppress_secrets = false;

	/*
	 *  Check we're the only process using this config.
	 */
	if (!config->allow_multiple_procs && !check_config) {
		switch (main_config_exclusive_proc(config)) {
		case 0:		/* No other processes running */
			break;

		case -1:	/* Permissions error - fail open */
			PWARN("%s: Process concurrency checks disabled", program);
			break;

		case 1:
		default:	/* All other errors */
			EXIT_WITH_PERROR;
		}
	}

	/*
	 *  Set panic_action from the main config if one wasn't specified in the
	 *  environment.
	 */
	if (config->panic_action && !getenv("PANIC_ACTION") &&
	    (fr_fault_setup(global_ctx, config->panic_action, argv[0]) < 0)) {
		fr_perror("%s: Failed configuring panic action", program);
		EXIT_WITH_FAILURE;
	}

	/*
	 *  This is very useful in figuring out why the panic_action didn't fire.
	 */
	INFO("%s", fr_debug_state_to_msg(fr_debug_state));

	/*
	 *	Track configuration versions.  This lets us know if the configuration changed.
	 */
	if (fr_debug_lvl) {
		uint8_t digest[16];

		cf_md5_final(digest);

		digest[6] &= 0x0f; /* ver is 0b0100 at bits 48:51 */
		digest[6] |= 0x40;
		digest[8] &= ~0xc0; /* var is 0b10 at bits 64:65 */
		digest[8] |= 0x80;

		/*
		 *	UUIDv4 format: 4-2-2-2-6
		 */
		INFO("Configuration version: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		     digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
		     digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
	}

	/*
	 *  Call this again now we've loaded the configuration. Yes I know...
	 */
	if (talloc_config_set(config) < 0) {
		EXIT_WITH_PERROR;
	}

	/*
	 *  Check for vulnerabilities in the version of libssl were linked against.
	 */
#ifdef WITH_TLS
#  ifdef ENABLE_OPENSSL_VERSION_CHECK
	if (fr_openssl_version_check(config->allow_vulnerable_openssl) < 0) EXIT_WITH_FAILURE;
#  endif

	/*
	 *  Toggle FIPS mode
	 */
	if (config->openssl_fips_mode_is_set &&
	    (fr_openssl_fips_mode(config->openssl_fips_mode) < 0)) EXIT_WITH_FAILURE;
#endif

	/*
	 *  The systemd watchdog enablement must be checked before we
	 *  daemonize, but the watchdog notifications can come from any
	 *  process.
	 */
#ifdef HAVE_SYSTEMD_WATCHDOG
	if (!check_config) main_loop_set_sd_watchdog_interval();
#else
	/*
	 *	If the default systemd unit file is used, but the server wasn't
	 *	built with support for systemd, the status returned by systemctl
	 *	will stay permanently as "activating".
	 *
	 *	We detect this condition and warn about it here, using the
	 *	presence of the NOTIFY_SOCKET environmental variable to determine
	 *	whether we're running under systemd.
	 */
	if (getenv("NOTIFY_SOCKET")) INFO("Built without support for systemd watchdog, but running under systemd");
#endif

	/*
	 *	Don't allow radmin when checking the config.
	 */
	if (check_config) radmin = false;

	if (fr_radmin_start(config, radmin, std_fd) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Disconnect from session
	 */
	if (config->daemonize) {
		pid_t pid;
		int devnull;

		DUMP_CAPABILITIES("pre-fork");

		/*
		 *  Really weird things happen if we leave stdin open and call things like
		 *  system() later.
		 */
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			ERROR("Failed opening /dev/null: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
		dup2(devnull, STDIN_FILENO);

		close(devnull);

		if (pipe(from_child) != 0) {
			ERROR("Couldn't open pipe for child status: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}

		pid = fork();
		if (pid < 0) {
			ERROR("Couldn't fork: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}

		/*
		 *  The parent exits, so the child can run in the background.
		 *
		 *  As the child can still encounter an error during initialisation
		 *  we do a blocking read on a pipe between it and the parent.
		 *
		 *  Just before entering the event loop the child will send a success
		 *  or failure message to the parent, via the pipe.
		 */
		if (pid > 0) {
			uint8_t child_ret;
			int stat_loc;

			/* So the pipe is correctly widowed if the child exits */
			close(from_child[1]);

			/*
			 *  The child writes a 0x01 byte on success, and closes
			 *  the pipe on error.
			 */
			if ((read(from_child[0], &child_ret, 1) < 0)) child_ret = 0;

			/* For cleanliness... */
			close(from_child[0]);

			/* Don't turn children into zombies */
			if (child_ret == 0) {
				waitpid(pid, &stat_loc, WNOHANG);
				EXIT_WITH_FAILURE;
			}

#ifdef HAVE_SYSTEMD
			/*
			 *	Update the systemd MAINPID to be our child,
			 *	as the parent is about to exit.
			 */
			sd_notifyf(0, "MAINPID=%lu", (unsigned long)pid);
#endif

			goto cleanup;
		/*
		 *  The child needs to increment the semaphore as the parent
		 *  is going to exit, and it will decrement the semaphore.
		 */
		} else if (pid == 0) {
			if (main_config_exclusive_proc_child(main_config) < 0) {
				PWARN("%s: Failed incrementing exclusive proc semaphore in child", program);
			}
		}

		/* so the pipe is correctly widowed if the parent exits?! */
		close(from_child[0]);
#ifdef HAVE_SETSID
		setsid();
#endif

		DUMP_CAPABILITIES("post-fork");
	} else {
		DUMP_CAPABILITIES("pre-suid-down");
	}

	/*
	 *  Ensure that we're using the CORRECT pid after forking, NOT the one
	 *  we started with.
	 */
	radius_pid = getpid();

	/*
	 *	Initialise the interpreter, registering operations.
	 */
	if (unlang_global_init() < 0) EXIT_WITH_FAILURE;

	if (server_init(config->root_cs, config->confdir, fr_dict_unconst(fr_dict_internal())) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Everything seems to have loaded OK, exit gracefully.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK");
		goto cleanup;
	}

	/*
	 *	Initialise the SNMP stats structures
	 */
	if (fr_snmp_init() < 0) {
		PERROR("Failed initialising SNMP");
		EXIT_WITH_FAILURE;
	}

	/*
	 *  Initialize the global event loop which handles things like
	 *  systemd.
	 *
	 *  This has to be done post-fork in case we're using kqueue, where the
	 *  queue isn't inherited by the child process.
	 */
	if (main_loop_init() < 0) {
		PERROR("Failed initialising main event loop");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Start the network / worker threads.
	 */
	{
		fr_event_list_t *el = NULL;
		fr_schedule_config_t *schedule;

		schedule = talloc_zero(global_ctx, fr_schedule_config_t);
		schedule->max_workers = config->max_workers;
		schedule->max_networks = config->max_networks;
		schedule->stats_interval = config->stats_interval;

		schedule->network.max_outstanding = config->worker.max_requests;
		schedule->worker = config->worker;

		/*
		 *	Single server mode: use the global event list.
		 *	Otherwise, each network thread will create
		 *	its own event list.
		 */
		if (!config->spawn_workers) {
			el = main_loop_event_list();
		}

		/*
		 *	Fix spurious messages
		 */
		fr_strerror_clear();
		sc = fr_schedule_create(NULL, el, &default_log, fr_debug_lvl,
					thread_instantiate, thread_detach, schedule);
		if (!sc) {
			PERROR("Failed starting the scheduler");
			EXIT_WITH_FAILURE;
		}

		/*
		 *	Tell the virtual servers to open their sockets.
		 */
		if (virtual_servers_open(sc) < 0) EXIT_WITH_FAILURE;
	}

	/*
	 *	At this point, no one has any business *ever* going
	 *	back to root uid.
	 */
	rad_suid_down_permanent();

	/*
	 *	Move the current working directory to a place where it
	 *	can't hurt anything.
	 */
	if (main_config->chdir_is_set) {
		if (chdir(main_config->chdir) < 0) {
			ERROR("Failed changing working to %s: %s", main_config->chdir, fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
	}

	DUMP_CAPABILITIES("post-suid-down");

	/*
	 *	Dropping down may change the RLIMIT_CORE value, so
	 *	reset it back to what to should be here.
	 */
	fr_reset_dumpable();

	/*
	 *  If we're debugging, then a CTRL-C will cause the server to die
	 *  immediately.  Use SIGTERM to shut down the server cleanly in
	 *  that case.
	 */
	if (fr_set_signal(SIGINT, sig_fatal) < 0) {
	set_signal_error:
		PERROR("Failed installing signal handler");
		EXIT_WITH_FAILURE;
	}

#ifdef SIGQUIT
	if (fr_set_signal(SIGQUIT, sig_fatal) < 0) goto set_signal_error;
#endif

	/*
	 *  Now that we've set everything up, we can install the signal
	 *  handlers.  Before this, if we get any signal, we don't know
	 *  what to do, so we might as well do the default, and die.
	 */
#ifdef SIGPIPE
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		ERROR("Failed ignoring SIGPIPE: %s", fr_syserror(errno));
		goto cleanup;
	}
#endif

	if (fr_set_signal(SIGHUP, sig_hup) < 0) goto set_signal_error;
	if (fr_set_signal(SIGTERM, sig_fatal) < 0) goto set_signal_error;

	/*
	 *  Write the PID after we've forked, so that we write the correct one.
	 */
	if (config->write_pid) {
		FILE *fp;

		fp = fopen(config->pid_file, "w");
		if (fp != NULL) {
			/*
			 *  @fixme What about following symlinks,
			 *  and having it over-write a normal file?
			 */
			fprintf(fp, "%d\n", (int) radius_pid);
			fclose(fp);
		} else {
			ERROR("Failed creating PID file %s: %s", config->pid_file, fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
	}

	trigger(NULL, NULL, NULL, "server.start", false, NULL);

	/*
	 *  Inform the parent (who should still be waiting) that the rest of
	 *  initialisation went OK, and that it should exit with a 0 status.
	 *  If we don't get this far, then we just close the pipe on exit, and the
	 *  parent gets a read failure.
	 */
	if (config->daemonize) {
		if (write(from_child[1], "\001", 1) < 0) {
			WARN("Failed informing parent of successful start: %s",
			     fr_syserror(errno));
		}
		close(from_child[1]);
	}

	/*
	 *	Clear the libfreeradius error buffer.
	 */
	fr_strerror_clear();

	/*
	 *	Prevent anything from modifying the dictionaries
	 *	they're now immutable.
	 */
	fr_dict_global_ctx_read_only();

	/*
	 *  Protect global memory - If something attempts
	 *  to write to this memory we get a SIGBUS.
	 */
	if (do_mprotect) {
	    	if (mprotect(pool_page_start, pool_page_len, PROT_READ) < 0) {
			PERROR("Protecting global memory failed: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
		DEBUG("Global memory protected");
	}

	fr_time_sync_event(main_loop_event_list()->tl, fr_time(), NULL);
#ifndef NDEBUG
	if (fr_time_delta_ispos(exit_after)) fr_exit_after(main_loop_event_list()->tl, fr_time_wrap(0), &exit_after);
#endif
	/*
	 *  Process requests until HUP or exit.
	 */
	INFO("Ready to process requests");	/* we were actually ready a while ago, but oh well */
	while ((status = main_loop_start()) == 0x80) {
		main_config_hup(config);
	}

	/*
	 *  Ignore the TERM signal: we're about to die.
	 */
	if (unlikely(signal(SIGTERM, SIG_IGN) == SIG_ERR)) {
		ERROR("Failed blocking SIGTERM, we may receive spurious signals: %s",
		      fr_syserror(errno));
	}

	/*
	 *  Unprotect global memory
	 */
	if (do_mprotect) {
		if (mprotect(pool_page_start, pool_page_len,
			     PROT_READ | PROT_WRITE) < 0) {
			PERROR("Unprotecting global memory failed: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
		DEBUG("Global memory unprotected");
	}

	if (status < 0) {
		PERROR("Exiting due to internal error");
		ret = EXIT_FAILURE;
	} else {
		INFO("Exiting normally");
		ret = EXIT_SUCCESS;
	}

	fr_radmin_stop();

	/*
	 *   Fire signal and stop triggers after ignoring SIGTERM, so handlers are
	 *   not killed with the rest of the process group, below.
	 */
	if (status == 2) trigger(NULL, NULL, NULL, "server.signal.term", true, NULL);
	trigger(NULL, NULL, NULL, "server.stop", false, NULL);

	/*
	 *  Stop the scheduler, this signals the network and worker threads
	 *  to exit gracefully.  fr_schedule_destroy only returns once all
	 *  threads have been joined.
	 */
	(void) fr_schedule_destroy(&sc);

	/*
	 *  We're exiting, so we can delete the PID file.
	 *  (If it doesn't exist, we can ignore the error returned by unlink)
	 */
	if (config->daemonize) {
		DEBUG3("Unlinking PID file %s", config->pid_file);
		unlink(config->pid_file);
	}

	/*
	 *  Free memory in an explicit and consistent order
	 *
	 *  We could let everything be freed by the global_ctx
	 *  context, but in some cases there are odd interactions
	 *  with destructors that may cause double frees and
	 *  SEGVs.
	 */
	if (!config->spawn_workers) {
		fr_event_list_t *el;

		el = main_loop_event_list();
		fr_event_loop_exit(el, 1);
	}

	main_loop_free();

	/*
	 *  Send a TERM signal to all associated processes
	 *  (including us, which gets ignored.)
	 *
	 *  This _shouldn't_ be needed, but may help with
	 *  processes created by the exec code or triggers.
	 */
	if (config->spawn_workers) {
		INFO("All threads have exited, sending SIGTERM to remaining children");

		/*
		 *	If pid is negative, but not -1, sig
		 *	shall be sent to all processes
		 *	(excluding an unspecified set of system processes)
		 *	whose process group ID is equal to the absolute value
		 *	of pid, and for which the process has permission
		 *	to send a signal.
		 */
		kill(-getpgid(radius_pid), SIGTERM);
	}

	/*
	 *	Remove the semaphore, allowing other processes
	 *	to start.  We do this before the cleanup label
	 *	as the parent process MUST NOT call this
	 *	function as it exits, otherwise the semaphore
	 *	is removed and there's no exclusivity.
	 */
	main_config_exclusive_proc_done(main_config);

cleanup:
	/*
	 *	This may not have been done earlier if we're
	 *	exiting due to a startup error.
	 */
	(void) fr_schedule_destroy(&sc);

	/*
	 *	Ensure all thread local memory is cleaned up
	 *	before we start cleaning up global resources.
	 *	This is necessary for single threaded mode
	 *	to ensure that thread local resources that
	 *	depend on global resources are freed at the
	 *	appropriate time.
	 */
	fr_atexit_thread_trigger_all();

	server_free();

#ifdef WITH_TLS
	fr_openssl_free();		/* Cleanup any memory alloced by OpenSSL and placed into globals */
#endif

	if (config) talloc_memory_report = config->talloc_memory_report;	/* Grab this before we free the config */

	/*
	 *	Virtual servers need to be freed before modules
	 *	as state entries containing data with module-specific
	 *	destructors may exist.
	 */
	virtual_servers_free();

	/*
	 *	Free modules, this needs to be done explicitly
	 *	because some libraries used by modules use atexit
	 *	handlers registered after ours, and they may deinit
	 *	themselves before we free the modules and cause
	 *	crashes on exit.
	 */
	modules_rlm_free();

#ifdef WITH_TLS
	fr_tls_dict_free();
#endif

	/*
	 *  And now nothing should be left anywhere except the
	 *  parsed configuration items.
	 */
	main_config_free(&config);

	/*
	 *  Cleanup everything else
	 */
	if (talloc_free(global_ctx) < 0) {
#ifndef NDEBUG
		fr_perror("program");
		ret = EXIT_FAILURE;
#endif
	}

	/*
	 *  Anything not cleaned up by the above is allocated in
	 *  the NULL top level context, and is likely leaked memory.
	 */
	if (talloc_memory_report) fr_log_talloc_report(NULL);

	/*
	 *  If we're running under LSAN, try and SUID back up so
	 *  we don't inteferere with the onexit() handler.
	 */
	if (!rad_suid_is_down_permanent() && (fr_get_lsan_state() == 1)) rad_suid_up();
	fr_strerror_clear();	/* clear error buffer */

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}

/*
 *  Display the syntax for starting this program.
 */
static NEVER_RETURNS void usage(int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: %s [options]\n", program);
	fprintf(output, "Options:\n");
	fprintf(output, "  -C            Check configuration and exit.\n");
	fprintf(stderr, "  -d <confdir>  Configuration file directory (defaults to " CONFDIR ").\n");
	fprintf(stderr, "  -D <dictdir>  Set main dictionary directory (defaults to " DICTDIR ").\n");
#ifndef NDEBUG
	fprintf(output, "  -e <seconds>  Exit after the specified number of seconds.  Useful for diagnosing \"crash-on-exit\" issues.\n");
#endif
	fprintf(output, "  -f            Run as a foreground process, not a daemon.\n");
	fprintf(output, "  -h            Print this help message.\n");
	fprintf(output, "  -l <log_file> Logging output will be written to this file.\n");
#ifndef NDEBUG
	fprintf(output, "  -L <size>     When running in memory debug mode, set a hard limit on talloced memory\n");
#endif
	fprintf(output, "  -n <name>     Read ${confdir}/name.conf instead of ${confdir}/%s.conf.\n", program);
	fprintf(output, "  -m            Allow multiple processes reading the same %s.conf to exist simultaneously.\n", program);
#ifndef NDEBUG
	fprintf(output, "  -M            Enable talloc memory debugging, and issue a memory report when the server terminates\n");
#endif
	fprintf(output, "  -P            Always write out PID, even with -f.\n");
	fprintf(output, "  -s            Do not spawn child processes to handle requests (same as -ft).\n");

	/*
	 *	Place-holder in case we need it.  Should be removed before the release.
	 */
//	fprintf(output, "  -S <flag>     Set migration flags to assist with upgrades from version 3.\n");
	fprintf(output, "  -t            Disable threads.\n");
	fprintf(output, "  -T            Prepend timestamps to  log messages.\n");
	fprintf(output, "  -v            Print server version information.\n");
	fprintf(output, "  -X            Turn on full debugging (similar to -tfxxl stdout).\n");
	fprintf(output, "  -x            Turn on additional debugging (-xx gives more debugging).\n");
	fr_exit(status);
}


/*
 *	We got a fatal signal.
 */
static void sig_fatal(int sig)
{
	static int last_sig;

	if (getpid() != radius_pid) _exit(sig);

	/*
	 *	Suppress duplicate signals.
	 *
	 *	For some reason on macOS we get multiple signals
	 *	for the same event (SIGINT).
	 *
	 *	...this also fixes the problem of the user hammering
	 *	Ctrl-C and causing ungraceful exits as we try and
	 *	write out signals to a pipe that's already closed.
	 */
	if (sig == last_sig) return;
	last_sig = sig;

	switch (sig) {
	case SIGTERM:
		main_loop_signal_raise(RADIUS_SIGNAL_SELF_TERM);
		break;

	case SIGINT:
#ifdef SIGQUIT
	case SIGQUIT:
#endif
		main_loop_signal_raise(RADIUS_SIGNAL_SELF_TERM);
		break;

	default:
		fr_exit(sig);
	}
}

#ifdef SIGHUP
/*
 *  We got the hangup signal.
 *  Re-read the configuration files.
 */
static void sig_hup(UNUSED int sig)
{
	reset_signal(SIGHUP, sig_hup);

	main_loop_signal_raise(RADIUS_SIGNAL_SELF_HUP);
}
#endif
