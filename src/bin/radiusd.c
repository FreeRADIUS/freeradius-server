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
 * @copyright 1999,2000 Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000 Alan DeKok <aland@ox.org>
 * @copyright 2000 Alan Curry <pacman-radius@cqc.com>
 * @copyright 2000 Jeff Carneal <jeff@apex.net>
 * @copyright 2000 Chad Miller <cmiller@surfsouth.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/unlang/base.h>

#include <ctype.h>
#include <fcntl.h>
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

char const *radiusd_version = RADIUSD_VERSION_STRING_BUILD("FreeRADIUS");
static pid_t radius_pid;

/*
 *  Configuration items.
 */

/*
 *	Static functions.
 */
static void usage(main_config_t const *config, int status);

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
		if (config->talloc_memory_limit || config->talloc_memory_report) {
			fr_strerror_printf("talloc_memory_limit and talloc_memory_report "
					   "require single threaded mode (-s | -X)");
			return 1;
		}
		return 0;
	}

	if (!config->talloc_memory_limit && !config->talloc_memory_report) {
		talloc_disable_null_tracking();
		return 0;
	}

	talloc_enable_null_tracking();

	if (config->talloc_memory_limit) {
		TALLOC_CTX *null_child = talloc_new(NULL);
		TALLOC_CTX *null_ctx = talloc_parent(null_child);

		talloc_free(null_child);

		if (talloc_set_memlimit(null_ctx, config->talloc_memory_limit) < 0) {
			fr_strerror_printf("Failed applying memory limit");
			return -1;
		}
	}

	return 0;
}


/** Create module and xlat per-thread instances
 *
 */
static int thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el, void *uctx)
{
	CONF_SECTION *root = talloc_get_type_abort(uctx, CONF_SECTION);

	if (modules_thread_instantiate(ctx, root, el) < 0) return -1;
	if (xlat_thread_instantiate(ctx) < 0) return -1;

	return 0;
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

/*
 *	The main guy.
 */
int main(int argc, char *argv[])
{
	int		status;
	int		argval;
	bool		display_version = false;
	bool		radmin = false;
	int		from_child[2] = {-1, -1};
	char		*p;
	fr_schedule_t	*sc = NULL;
	int		ret = EXIT_SUCCESS;

	TALLOC_CTX	*global_ctx = NULL;
	main_config_t	*config = NULL;
	bool		talloc_memory_report = false;

	size_t		pool_size = 0;
	void		*pool_page_start = NULL, *pool_page_end = NULL;
	bool		do_mprotect;

	/*
	 *	Setup talloc callbacks so we get useful errors
	 */
	(void) fr_talloc_fault_setup();

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
			if (fr_size_from_str(&pool_size, env) < 0) {
				fprintf(stderr, "Invalid pool size string \"%s\": %s\n", env, fr_strerror());
				EXIT_WITH_FAILURE;
			}

			/*
			 *	Pre-allocate a global memory pool for the static
			 *	config to exist in.  We mprotect() this later to
			 *	catch any stray writes.
			 */
			global_ctx = talloc_page_aligned_pool(talloc_autofree_context(),
							      &pool_page_start, &pool_page_end, pool_size);
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
	 *	It's allocating so we can hang talloced buffers off it.
	 */
	config = main_config_alloc(global_ctx);
	if (!config) {
		fprintf(stderr, "Failed allocating main config");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Set some default values
	 */
	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config_name_set_default(config, argv[0], false);
	} else {
		main_config_name_set_default(config, p + 1, false);
	}

	config->daemonize = true;
	config->spawn_workers = true;

#ifdef OSFC2
	set_auth_parameters(argc, argv);
#endif

#ifdef WIN32
	{
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
			fprintf(stderr, "%s: Unable to initialize socket library.\n", config->name);
			EXIT_WITH_FAILURE;
		}
	}
#endif

	rad_debug_lvl = 0;
	fr_time_start();

	/*
	 *	Don't put output anywhere until we get told a little
	 *	more.
	 */
	default_log.dst = L_DST_NULL;
	default_log.fd = -1;

	/*
	 *  Set the panic action and enable other debugging facilities
	 */
	if (fr_fault_setup(global_ctx, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("Failed installing fault handlers... continuing");
	}

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Cd:D:fhi:l:L:Mn:p:PrstTvxX")) != EOF) {
		switch (argval) {
		case 'C':
			check_config = true;
			config->spawn_workers = false;
			config->daemonize = false;
			break;

		case 'd':
			main_config_raddb_dir_set(config, optarg);
			break;

		case 'D':
			main_config_dict_dir_set(config, optarg);
			break;

		case 'f':
			config->daemonize = false;
			break;

		case 'h':
			usage(config, EXIT_SUCCESS);
			break;

		case 'l':
			if (strcmp(optarg, "stdout") == 0) goto do_stdout;

			config->log_file = talloc_typed_strdup(global_ctx, optarg);
			default_log.file = talloc_typed_strdup(global_ctx, optarg);
			default_log.dst = L_DST_FILES;
			default_log.fd = open(config->log_file, O_WRONLY | O_APPEND | O_CREAT, 0640);
			if (default_log.fd < 0) {
				fprintf(stderr, "%s: Failed to open log file %s: %s\n",
					config->name, config->log_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
			fr_log_fp = fdopen(default_log.fd, "a");
			break;

		case 'L':
		{
			size_t limit;

			if (fr_size_from_str(&limit, optarg) < 0) {
				fr_perror("%s: Invalid memory limit", config->name);
				EXIT_WITH_FAILURE;
			}

			if ((limit > (((size_t)((1024 * 1024) * 1024)) * 16) || (limit < ((1024 * 1024) * 10)))) {
				fprintf(stderr, "%s: Memory limit must be between 10M-16G\n", config->name);
				EXIT_WITH_FAILURE;
			}

			config->talloc_memory_limit = limit;
		}
			break;

		case 'n':
			main_config_name_set_default(config, optarg, true);
			break;

		case 'M':
			config->talloc_memory_report = true;
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
			rad_debug_lvl += 2;
	do_stdout:
			fr_log_fp = stdout;
			default_log.dst = L_DST_STDOUT;
			default_log.fd = STDOUT_FILENO;
			break;

		case 'x':
			rad_debug_lvl++;
			break;

		default:
			usage(config, EXIT_FAILURE);
			break;
		}
	}

	fr_debug_lvl = req_debug_lvl = config->debug_level = rad_debug_lvl;

	/*
	 *  Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (rad_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (ssl_check_consistency() < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *  According to the talloc peeps, no two threads may modify any part of
	 *  a ctx tree with a common root without synchronisation.
	 *
	 *  So we can't run with a null context and threads.
	 */
	if (talloc_config_set(config) != 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *  Better here, so it doesn't matter whether we get passed -xv or -vx.
	 */
	if (display_version) {
		if (rad_debug_lvl == 0) rad_debug_lvl = 1;
		fr_log_fp = stdout;
		default_log.dst = L_DST_STDOUT;
		default_log.fd = STDOUT_FILENO;

		INFO("%s - %s", config->name, radiusd_version);
		dependency_version_print();
		EXIT_WITH_SUCCESS;
	}

	if (rad_debug_lvl) dependency_version_print();

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
	 *	Initialize the DL infrastructure, which is used by the
	 *	config file parser.
	 */
	dl_loader_init(global_ctx, config->lib_dir);

	/*
	 *	Initialise the top level dictionary hashes which hold
	 *	the protocols.
	 */
	if (fr_dict_global_init(global_ctx, config->dict_dir) < 0) {
		fr_perror("radiusd");
		EXIT_WITH_FAILURE;
	}

	/*
	 *  Read the configuration files, BEFORE doing anything else.
	 */
	if (main_config_init(config) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 *  Must be called before display_version to ensure relevant engines are loaded.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (tls_init() < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *  Set panic_action from the main config if one wasn't specified in the
	 *  environment.
	 */
	if (config->panic_action && !getenv("PANIC_ACTION") &&
	    (fr_fault_setup(global_ctx, config->panic_action, argv[0]) < 0)) {
		fr_perror("radiusd - Failed configuring panic action: %s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *  This is very useful in figuring out why the panic_action didn't fire.
	 */
	INFO("%s", fr_debug_state_to_msg(fr_debug_state));

	/*
	 *  Initialise trigger rate limiting
	 */
	trigger_exec_init(config->root_cs);

	/*
	 *  Call this again now we've loaded the configuration. Yes I know...
	 */
	if (talloc_config_set(config) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *  Check for vulnerabilities in the version of libssl were linked against.
	 */
#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(ENABLE_OPENSSL_VERSION_CHECK)
	if (tls_version_check(config->allow_vulnerable_openssl) < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *  The systemd watchdog enablement must be checked before we
	 *  daemonize, but the notifications can come from any process.
	 */
#ifdef HAVE_SYSTEMD_WATCHDOG
	if (!check_config) {
		uint64_t usec;

		if ((sd_watchdog_enabled(0, &usec) > 0) && (usec > 0)) {
			usec /= 2;
			fr_timeval_from_usec(&sd_watchdog_interval, usec);

			INFO("systemd watchdog interval is %pT secs", &sd_watchdog_interval);
		} else {
			INFO("systemd watchdog is disabled");
		}
	}
#endif

	/*
	 *	Don't allow radmin when checking the config.
	 */
	if (check_config) radmin = false;

	if (fr_radmin_start(config, radmin) < 0) EXIT_WITH_FAILURE;

#ifndef __MINGW32__
	/*
	 *  Disconnect from session
	 */
	if (config->daemonize) {
		pid_t pid;
		int devnull;

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
				exit(EXIT_FAILURE);
			}

#ifdef HAVE_SYSTEMD
			sd_notify(0, "READY=1");
#endif

			exit(EXIT_SUCCESS);
		}

		/* so the pipe is correctly widowed if the parent exits?! */
		close(from_child[0]);
#  ifdef HAVE_SETSID
		setsid();
#  endif
	}
#endif

	/*
	 *  Ensure that we're using the CORRECT pid after forking, NOT the one
	 *  we started with.
	 */
	radius_pid = getpid();

	/*
	 *	Initialise the interpreter, registering operations.
	 */
	if (unlang_init() < 0) EXIT_WITH_FAILURE;

	/*
	 *	Initialize Auth-Type, etc. in the virtual servers
	 *	before loading the modules.  Some modules need those
	 *	to be defined.
	 */
	if (virtual_servers_bootstrap(config->root_cs) < 0) EXIT_WITH_FAILURE;

	/*
	 *	Bootstrap the modules.  This links to them, and runs
	 *	their "bootstrap" routines.
	 *
	 *	After this step, all dynamic attributes, xlats, etc. are defined.
	 */
	if (modules_bootstrap(config->root_cs) < 0) EXIT_WITH_FAILURE;

	/*
	 *	And then load the virtual servers.
	 *
	 *	This function also opens the listeners in each virtual
	 *	server.  These listeners MUST be started before the
	 *	modules.  If there is another server already running,
	 *	we will discover it here and exit BEFORE opening
	 *	connections to back-end DBs.
	 */
	if (virtual_servers_instantiate() < 0) EXIT_WITH_FAILURE;

	/*
	 *	Call the module's initialisation methods.  These create
	 *	connection pools and open connections to external resources.
	 */
	if (modules_instantiate(config->root_cs) < 0) EXIT_WITH_FAILURE;

	/*
	 *	Instantiate "permanent" xlats
	 */
	if (xlat_instantiate() < 0) EXIT_WITH_FAILURE;

	/*
	 *	Instantiate "permanent" paircmps
	 */
	if (paircmp_init() < 0) EXIT_WITH_FAILURE;

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
	 *  systemd, and single-server mode.
	 *
	 *  This has to be done post-fork in case we're using kqueue, where the
	 *  queue isn't inherited by the child process.
	 */
	if (!radius_event_init()) EXIT_WITH_FAILURE;

	/*
	 *  Redirect stderr/stdout as appropriate.
	 */
	if (log_global_init(&default_log, config->daemonize) < 0) EXIT_WITH_FAILURE;

	/*
	 *	Start the network / worker threads.
	 */
	{
		int networks = config->num_networks;
		int workers = config->num_workers;
		fr_event_list_t *el = NULL;

		/*
		 *	Single server mode: use the global event list.
		 *	Otherwise, each network thread will create
		 *	it's own event list.
		 */
		if (!config->spawn_workers) {
			networks = 0;
			workers = 0;
			el = fr_global_event_list();
		}

		sc = fr_schedule_create(NULL, el, &default_log, rad_debug_lvl,
					networks, workers,
					thread_instantiate,
					config->root_cs);
		if (!sc) {
			PERROR("Failed starting the scheduler: %s", fr_strerror());
			EXIT_WITH_FAILURE;
		}

		/*
		 *	Tell the virtual servers to open their sockets.
		 */
		if (virtual_servers_open(sc) < 0) EXIT_WITH_FAILURE;
	}

#ifndef NDEBUG
	{
		size_t size;

		size = talloc_total_size(config->root_cs);

		if (talloc_set_memlimit(config->root_cs, size)) {
			PERROR("Failed setting memory limit for global configuration");
		} else {
			DEBUG3("Memory limit for global configuration is set to %zd bytes", size);
		}
	}
#endif

	/*
	 *  Start the main event loop.
	 */
	if (radius_event_start(config->spawn_workers) < 0) {
		ERROR("Failed starting event loop");
		EXIT_WITH_FAILURE;
	}

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
	signal(SIGPIPE, SIG_IGN);
#endif

	if (fr_set_signal(SIGHUP, sig_hup) < 0) goto set_signal_error;
	if (fr_set_signal(SIGTERM, sig_fatal) < 0) goto set_signal_error;

#ifdef WITH_STATS
	radius_stats_init(0);
#endif

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

	trigger_exec(NULL, NULL, "server.start", false, NULL);

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
	fr_strerror();

	/*
	 *  Protect global memory - If something attempts
	 *  to write to this memory we get a SIGBUS.
	 */
	if (do_mprotect) {
	    	if (mprotect(pool_page_start, (uintptr_t)pool_page_end - (uintptr_t)pool_page_start, PROT_READ) < 0) {
			PERROR("Protecting global memory failed: %s", fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
		DEBUG("Global memory protected");
	}

	/*
	 *  Process requests until HUP or exit.
	 */
	while ((status = radius_event_process()) == 0x80) {
#ifdef WITH_STATS
		radius_stats_init(1);
#endif
		main_config_hup(config);
	}

	/*
	 *  Unprotect global memory
	 */
	if (do_mprotect) {
		if (mprotect(pool_page_start, (uintptr_t)pool_page_end - (uintptr_t)pool_page_start,
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
	 *  Ignore the TERM signal: we're about to die.
	 */
	signal(SIGTERM, SIG_IGN);

	/*
	 *   Fire signal and stop triggers after ignoring SIGTERM, so handlers are
	 *   not killed with the rest of the process group, below.
	 */
	if (status == 2) trigger_exec(NULL, NULL, "server.signal.term", true, NULL);
	trigger_exec(NULL, NULL, "server.stop", false, NULL);

	/*
	 *  Send a TERM signal to all associated processes
	 *  (including us, which gets ignored.)
	 */
#ifndef __MINGW32__
	if (config->spawn_workers) kill(-radius_pid, SIGTERM);
#endif

	/*
	 *  We're exiting, so we can delete the PID file.
	 *  (If it doesn't exist, we can ignore the error returned by unlink)
	 */
	if (config->daemonize) unlink(config->pid_file);

	/*
	 *  Stop the scheduler
	 */
	(void) fr_schedule_destroy(sc);

	/*
	 *  Free memory in an explicit and consistent order
	 *
	 *  We could let everything be freed by the global_ctx
	 *  context, but in some cases there are odd interactions
	 *  with destructors that may cause double frees and
	 *  SEGVs.
	 */
	radius_event_free();		/* Free the requests */

cleanup:
	/*
	 *  Frees request specific logging resources which is OK
	 *  because all the requests will have been stopped.
	 */
	log_global_free();

	/*
	 *  Free xlat instance data, and call any detach methods
	 */
	xlat_instances_free();

	/*
	 *  Detach modules, connection pools, registered xlats
	 *  paircmps / maps.
	 */
	modules_free();

	/*
	 *  The only paircmps remaining are the ones registered
	 *  by the server core.
	 */
	paircmp_free();

	/*
	 *  The only xlats remaining are the ones registered by
	 *  the server core.
	 */
	xlat_free();

	/*
	 *  The only maps remaining are the ones registered by
	 *  the server core.
	 */
	map_proc_free();

	/*
	 *  Free any resources used by the unlang interpreter.
	 */
	unlang_free();

#ifdef HAVE_OPENSSL_CRYPTO_H
	tls_free();		/* Cleanup any memory alloced by OpenSSL and placed into globals */
#endif

	if (config) talloc_memory_report = config->talloc_memory_report;	/* Grab this before we free the config */

	/*
	 *  And now nothing should be left anywhere except the
	 *  parsed configuration items.
	 */
	main_config_free(&config);

	/*
	 *  Cleanup everything else
	 */
	talloc_free(global_ctx);

	/*
	 *  Now we're sure no more triggers can fire, free the
	 *  trigger tree
	 */
	trigger_exec_free();

	/*
	 *  Clean out the main thread's log buffers these would
	 *  be free on exit anyway but this stops them showing
	 *  up in the memory report.
	 */
	fr_strerror_free();

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

	return ret;
}

/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(main_config_t const *config, int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: %s [options]\n", config->name);
	fprintf(output, "Options:\n");
	fprintf(output, "  -C            Check configuration and exit.\n");
	fprintf(stderr, "  -d <raddb>    Set configuration directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>  Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(output, "  -f            Run as a foreground process, not a daemon.\n");
	fprintf(output, "  -h            Print this help message.\n");
	fprintf(output, "  -l <log_file> Logging output will be written to this file.\n");
#ifndef NDEBUG
	fprintf(output, "  -L <size>     When running in memory debug mode, set a hard limit on talloced memory\n");
#endif
	fprintf(output, "  -n <name>     Read raddb/name.conf instead of raddb/radiusd.conf.\n");
#ifndef NDEBUG
	fprintf(output, "  -M            Enable talloc memory debugging, and issue a memory report when the server terminates\n");
#endif
	fprintf(output, "  -P            Always write out PID, even with -f.\n");
	fprintf(output, "  -s            Do not spawn child processes to handle requests (same as -ft).\n");
	fprintf(output, "  -t            Disable threads.\n");
	fprintf(output, "  -T            Prepend timestamps to  log messages.\n");
	fprintf(output, "  -v            Print server version information.\n");
	fprintf(output, "  -X            Turn on full debugging (similar to -tfxxl stdout).\n");
	fprintf(output, "  -x            Turn on additional debugging (-xx gives more debugging).\n");
	exit(status);
}


/*
 *	We got a fatal signal.
 */
static void sig_fatal(int sig)
{
	if (getpid() != radius_pid) _exit(sig);

	switch (sig) {
	case SIGTERM:
		radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
		break;

	case SIGINT:
#ifdef SIGQUIT
	case SIGQUIT:
#endif
		radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
		break;
		/* FALL-THROUGH */

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

	radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
}
#endif
