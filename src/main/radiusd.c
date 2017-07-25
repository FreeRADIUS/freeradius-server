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
 * @copyright 2000-2016 The FreeRADIUS server project
 * @copyright 1999,2000 Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000 Alan DeKok <aland@ox.org>
 * @copyright 2000 Alan Curry <pacman-radius@cqc.com>
 * @copyright 2000 Jeff Carneal <jeff@apex.net>
 * @copyright 2000 Chad Miller <cmiller@surfsouth.com>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/map_proc.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/file.h>

#include <fcntl.h>
#include <ctype.h>

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

/*
 *  Global variables.
 */
char const	*radacct_dir = NULL;
char const	*radlog_dir = NULL;

bool		log_stripped_names;

char const *radiusd_version = RADIUSD_VERSION_STRING_BUILD("FreeRADIUS");
static pid_t radius_pid;

#ifdef HAVE_SYSTEMD_WATCHDOG
struct timeval sd_watchdog_interval;
#endif


/*
 *  Configuration items.
 */

/*
 *	Static functions.
 */
static void usage(int);

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

/*
 *	The main guy.
 */
int main(int argc, char *argv[])
{
	int		rcode = EXIT_SUCCESS;
	int		status;
	int		argval;
	bool		display_version = false;
	int		from_child[2] = {-1, -1};
	char		*p;
	fr_schedule_t	*sc = NULL;

	/*
	 *	Setup talloc callbacks so we get useful errors
	 */
	(void) fr_talloc_fault_setup();

	/*
	 *  We probably don't want to free the talloc autofree context
	 *  directly, so we'll allocate a new context beneath it, and
	 *  free that before any leak reports.
	 */
	TALLOC_CTX *autofree = talloc_init("main");

#ifdef OSFC2
	set_auth_parameters(argc, argv);
#endif

#ifdef WIN32
	{
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
			fprintf(stderr, "%s: Unable to initialize socket library.\n",
				main_config.name);
			exit(EXIT_FAILURE);
		}
	}
#endif

	rad_debug_lvl = 0;
	set_radius_dir(autofree, RADIUS_DIR);
	fr_time_start();

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&main_config, 0, sizeof(main_config));
	main_config.daemonize = true;
	main_config.spawn_workers = true;

	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config.name = argv[0];
	} else {
		main_config.name = p + 1;
	}

	/*
	 *	Don't put output anywhere until we get told a little
	 *	more.
	 */
	default_log.dst = L_DST_NULL;
	default_log.fd = -1;
	main_config.log_file = NULL;

	/*
	 *  Set the panic action and enable other debugging facilities
	 */
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("Failed installing fault handlers... continuing");
	}

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Cd:D:fhi:l:L:Mn:p:PstTvxX")) != EOF) {
		switch (argval) {
		case 'C':
			check_config = true;
			main_config.spawn_workers = false;
			main_config.daemonize = false;
			break;

		case 'd':
			set_radius_dir(autofree, optarg);
			break;

		case 'D':
			main_config.dictionary_dir = talloc_typed_strdup(autofree, optarg);
			break;

		case 'f':
			main_config.daemonize = false;
			break;

		case 'h':
			usage(0);
			break;

		case 'l':
			if (strcmp(optarg, "stdout") == 0) {
				goto do_stdout;
			}

			main_config.log_file = talloc_typed_strdup(autofree, optarg);
			default_log.file = talloc_typed_strdup(autofree, optarg);
			default_log.dst = L_DST_FILES;
			default_log.fd = open(main_config.log_file, O_WRONLY | O_APPEND | O_CREAT, 0640);
			if (default_log.fd < 0) {
				fprintf(stderr, "%s: Failed to open log file %s: %s\n",
					main_config.name, main_config.log_file, fr_syserror(errno));
				exit(EXIT_FAILURE);
			}
			fr_log_fp = fdopen(default_log.fd, "a");
			break;

		case 'L':
		{
			size_t limit;

			if (fr_size_from_str(&limit, optarg) < 0) {
				fprintf(stderr, "%s: Invalid memory limit: %s\n", main_config.name, fr_strerror());
				exit(EXIT_FAILURE);
			}

			if ((limit > (((size_t)((1024 * 1024) * 1024)) * 16) || (limit < ((1024 * 1024) * 10)))) {
				fprintf(stderr, "%s: Memory limit must be between 10M-16G\n", main_config.name);
				exit(EXIT_FAILURE);
			}

			main_config.talloc_memory_limit = limit;
		}
			break;

		case 'n':
			main_config.name = optarg;
			break;

		case 'M':
			main_config.talloc_memory_report = true;
			break;

		case 'P':	/* Force the PID to be written, even in -f mode */
			main_config.write_pid = true;
			break;

		case 's':	/* Single process mode */
			main_config.spawn_workers = false;
			main_config.daemonize = false;
			break;

		case 't':	/* no child threads */
			main_config.spawn_workers = false;
			break;

		case 'T':	/* enable timestamps */
			default_log.timestamp = L_TIMESTAMP_ON;
			break;

		case 'v':
			display_version = true;
			break;

		case 'X':
			main_config.spawn_workers = false;
			main_config.daemonize = false;
			rad_debug_lvl += 2;
			main_config.log_auth = true;
			main_config.log_auth_badpass = true;
			main_config.log_auth_goodpass = true;
	do_stdout:
			fr_log_fp = stdout;
			default_log.dst = L_DST_STDOUT;
			default_log.fd = STDOUT_FILENO;
			break;

		case 'x':
			rad_debug_lvl++;
			break;

		default:
			usage(1);
			break;
		}
	}

	fr_debug_lvl = req_debug_lvl = main_config.debug_level = rad_debug_lvl;

	/*
	 *  Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", main_config.name);
		fr_exit(EXIT_FAILURE);
	}

	if (rad_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) fr_exit(EXIT_FAILURE);

	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (ssl_check_consistency() < 0) fr_exit(EXIT_FAILURE);
#endif

	/*
	 *  According to the talloc peeps, no two threads may modify any part of
	 *  a ctx tree with a common root without synchronisation.
	 *
	 *  So we can't run with a null context and threads.
	 */
	if (talloc_config_set(&main_config) != 0) {
		fr_perror("%s", main_config.name);
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 *  Must be called before display_version to ensure relevant engines are loaded.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (tls_global_init() < 0) fr_exit(EXIT_FAILURE);
#endif

	/*
	 *  Better here, so it doesn't matter whether we get passed -xv or -vx.
	 */
	if (display_version) {
		if (rad_debug_lvl == 0) rad_debug_lvl = 1;
		fr_log_fp = stdout;
		default_log.dst = L_DST_STDOUT;
		default_log.fd = STDOUT_FILENO;

		INFO("%s: %s", main_config.name, radiusd_version);
		version_print();
		exit(EXIT_SUCCESS);
	}

	if (rad_debug_lvl) version_print();

	/*
	 *  Under linux CAP_SYS_PTRACE is usually only available before setuid/setguid,
	 *  so we need to check whether we can attach before calling those functions
	 *  (in main_config_init()).
	 */
	fr_debug_state_store();

	/*
	 *  Write the PID always if we're running as a daemon.
	 */
	if (main_config.daemonize) main_config.write_pid = true;

	/*
	 *  Read the configuration files, BEFORE doing anything else.
	 */
	if (main_config_init() < 0) exit(EXIT_FAILURE);

	/*
	 *  Set panic_action from the main config if one wasn't specified in the
	 *  environment.
	 */
	if (main_config.panic_action && !getenv("PANIC_ACTION") &&
	    (fr_fault_setup(main_config.panic_action, argv[0]) < 0)) {
		fr_perror("Failed configuring panic action: %s", main_config.name);
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *  This is very useful in figuring out why the panic_action didn't fire.
	 */
	INFO("%s", fr_debug_state_to_msg(fr_debug_state));

	/*
	 *  Initialise trigger rate limiting
	 */
	trigger_exec_init(main_config.config);

	/*
	 *  Call this again now we've loaded the configuration. Yes I know...
	 */
	if (talloc_config_set(&main_config) < 0) {
		fr_perror("%s", main_config.name);
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *  Check for vulnerabilities in the version of libssl were linked against.
	 */
#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(ENABLE_OPENSSL_VERSION_CHECK)
	if (tls_global_version_check(main_config.allow_vulnerable_openssl) < 0) exit(EXIT_FAILURE);
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

#ifndef __MINGW32__
	/*
	 *  Disconnect from session
	 */
	if (main_config.daemonize) {
		pid_t pid;
		int devnull;

		/*
		 *  Really weird things happen if we leave stdin open and call things like
		 *  system() later.
		 */
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			ERROR("Failed opening /dev/null: %s", fr_syserror(errno));
			fr_exit(EXIT_FAILURE);
		}
		dup2(devnull, STDIN_FILENO);

		close(devnull);

		if (pipe(from_child) != 0) {
			ERROR("Couldn't open pipe for child status: %s", fr_syserror(errno));
			fr_exit(EXIT_FAILURE);
		}

		pid = fork();
		if (pid < 0) {
			ERROR("Couldn't fork: %s", fr_syserror(errno));
			fr_exit(EXIT_FAILURE);
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
			uint8_t ret = 0;
			int stat_loc;

			/* So the pipe is correctly widowed if the child exits */
			close(from_child[1]);

			/*
			 *  The child writes a 0x01 byte on success, and closes
			 *  the pipe on error.
			 */
			if ((read(from_child[0], &ret, 1) < 0)) {
				ret = 0;
			}

			/* For cleanliness... */
			close(from_child[0]);

			/* Don't turn children into zombies */
			if (!ret) {
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
	 *	Initialize Auth-Type, etc. in the virtual servers
	 *	before loading the modules.  Some modules need those
	 *	to be defined.
	 */
	if (virtual_servers_bootstrap(main_config.config) < 0) exit(EXIT_FAILURE);

	/*
	 *	Bootstrap the modules.  This links to them, and runs
	 *	their "bootstrap" routines.
	 *
	 *	After this step, all dynamic attributes, xlats, etc. are defined.
	 */
	if (modules_bootstrap(main_config.config) < 0) exit(EXIT_FAILURE);

	/*
	 *	Call the module's initialisation methods.  These create
	 *	connection pools and open connections to external resources.
	 */
	if (modules_instantiate(main_config.config) < 0) exit(EXIT_FAILURE);

	/*
	 *	And then load the virtual servers.
	 */
	if (virtual_servers_instantiate(main_config.config) < 0) exit(EXIT_FAILURE);

	/*
	 *	Initialise the SNMP stats structures
	 */
	if (fr_snmp_init() < 0) {
		PERROR("Failed initialising SNMP");
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *  Initialize any event loops just enough so module instantiations can
	 *  add fd/event to them, but do not start them yet.
	 *
	 *  This has to be done post-fork in case we're using kqueue, where the
	 *  queue isn't inherited by the child process.
	 */
	if (!radius_event_init(autofree)) exit(EXIT_FAILURE);

	/*
	 *  Redirect stderr/stdout as appropriate.
	 */
	if (fr_log_init(&default_log, main_config.daemonize) < 0) {
		PERROR("Failed initialising log");
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *	If this isn't just a config check, AND we have new
	 *	async listeners, then we open the sockets.
	 */
	if (!check_config && main_config.namespace) {
		int networks = 1;
		int workers = 4;
		fr_event_list_t *el = NULL;

		if (!main_config.spawn_workers) {
			networks = 0;
			workers = 0;
			el = process_global_event_list(EVENT_CORRAL_MAIN);
		}

		sc = fr_schedule_create(NULL, el, &default_log, networks, workers,
					(fr_schedule_thread_instantiate_t) modules_thread_instantiate,
					main_config.config);
		if (!sc) {
			exit(EXIT_FAILURE);
		}

		if (virtual_servers_open(sc) < 0) exit(EXIT_FAILURE);
	}

	event_loop_started = true;

#ifndef NDEBUG
	{
		size_t size;

		size = talloc_total_size(main_config.config);

		if (talloc_set_memlimit(main_config.config, size)) {
			PERROR("Failed setting memory limit for global configuration");
		} else {
			DEBUG3("Memory limit for global configuration is set to %zd bytes", size);
		}
	}
#endif


	/*
	 *  Start the event loop.
	 */
	if (radius_event_start(main_config.spawn_workers) < 0) {
		ERROR("Failed starting event loop");
		fr_exit(EXIT_FAILURE);
	}

	/*
	 *  If we're debugging, then a CTRL-C will cause the server to die
	 *  immediately.  Use SIGTERM to shut down the server cleanly in
	 *  that case.
	 */
	if (fr_set_signal(SIGINT, sig_fatal) < 0) {
	set_signal_error:
		PERROR("Failed installing signal handler");
		fr_exit(EXIT_FAILURE);
	}

#ifdef SIGQUIT
	if (fr_set_signal(SIGQUIT, sig_fatal) < 0) goto set_signal_error;
#endif

	/*
	 *  Everything seems to have loaded OK, exit gracefully.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK");

		goto cleanup;
	}

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
	if (main_config.write_pid) {
		FILE *fp;

		fp = fopen(main_config.pid_file, "w");
		if (fp != NULL) {
			/*
			 *  @fixme What about following symlinks,
			 *  and having it over-write a normal file?
			 */
			fprintf(fp, "%d\n", (int) radius_pid);
			fclose(fp);
		} else {
			ERROR("Failed creating PID file %s: %s", main_config.pid_file, fr_syserror(errno));
			fr_exit(EXIT_FAILURE);
		}
	}

	trigger_exec(NULL, NULL, "server.start", false, NULL);

	/*
	 *  Inform the parent (who should still be waiting) that the rest of
	 *  initialisation went OK, and that it should exit with a 0 status.
	 *  If we don't get this far, then we just close the pipe on exit, and the
	 *  parent gets a read failure.
	 */
	if (main_config.daemonize) {
		if (write(from_child[1], "\001", 1) < 0) {
			WARN("Failed informing parent of successful start: %s",
			     fr_syserror(errno));
		}
		close(from_child[1]);
	}

	/*
	 *  Clear the libfreeradius error buffer.
	 */
	fr_strerror();

	/*
	 *  Initialise the state rbtree (used to link multiple rounds of challenges).
	 */
	global_state = fr_state_tree_init(autofree, main_config.max_requests * 2, main_config.continuation_timeout);

	/*
	 *  Process requests until HUP or exit.
	 */
	while ((status = radius_event_process()) == 0x80) {
#ifdef WITH_STATS
		radius_stats_init(1);
#endif
		main_config_hup();
	}

	if (status < 0) {
		PERROR("Exiting due to internal error");
		rcode = EXIT_FAILURE;
	} else {
		INFO("Exiting normally");
		rcode = EXIT_SUCCESS;
	}

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
	if (main_config.spawn_workers) kill(-radius_pid, SIGTERM);
#endif

	/*
	 *  We're exiting, so we can delete the PID file.
	 *  (If it doesn't exist, we can ignore the error returned by unlink)
	 */
	if (main_config.daemonize) unlink(main_config.pid_file);

	/*
	 *	Stop the scheduler
	 */
	(void) fr_schedule_destroy(sc);

	/*
	 *	Free memory in an explicit and consistent order
	 *
	 *	We could let everything be freed by the autofree
	 *	context, but in some cases there are odd interactions
	 *	with destructors that may cause double frees and
	 *	SEGVs.
	 */
	radius_event_free();		/* Free the requests */

	talloc_free(global_state);	/* Free state entries */

cleanup:
	/*
	 *	Detach modules, connection pools, registered xlats / paircompares / maps.
	 */
	modules_free();

	/*
	 *	The only xlats remaining are the ones registered by the server core.
	 */
	xlat_free();

	/*
	 *	The only maps remaining are the ones registered by the server core.
	 */
	map_proc_free();

	/*
	 *	And now nothing should be left anywhere except the
	 *	parsed configuration items.
	 */
	main_config_free();

#ifdef WIN32
	WSACleanup();
#endif

#if defined(HAVE_OPENSSL_CRYPTO_H) && OPENSSL_VERSION_NUMBER < 0x10100000L
	tls_global_cleanup();		/* Cleanup any memory alloced by OpenSSL and placed into globals */
#endif

	talloc_free(autofree);		/* Cleanup everything else */

	trigger_exec_free();		/* Now we're sure no more triggers can fire, free the trigger tree */

	/*
	 *  Anything not cleaned up by the above is allocated in the NULL
	 *  top level context, and is likely leaked memory.
	 */
	if (main_config.talloc_memory_report) fr_log_talloc_report(NULL);

	return rcode;
}

/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output, "Usage: %s [options]\n", main_config.name);
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
