/*
 * radiusd.c	Main loop of the radius server.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000-2012  The FreeRADIUS server project
 * Copyright 1999,2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman-radius@cqc.com>
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 * Copyright 2000  Chad Miller <cmiller@surfsouth.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/file.h>

#include <fcntl.h>
#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#	define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#	define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

/*
 *  Global variables.
 */
char const	*radacct_dir = NULL;
char const	*radlog_dir = NULL;

bool		log_stripped_names;

char const *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", for host " HOSTINFO
#ifndef ENABLE_REPRODUCIBLE_BUILDS
", built on " __DATE__ " at " __TIME__
#endif
;

static pid_t radius_pid;

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

/*
 *	The main guy.
 */
int main(int argc, char *argv[])
{
	int rcode = EXIT_SUCCESS;
	int status;
	int argval;
	bool spawn_flag = true;
	bool display_version = false;
	int flag = 0;
	int from_child[2] = {-1, -1};
	char *p;
	fr_state_t *state = NULL;

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

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&main_config, 0, sizeof(main_config));
	main_config.myip.af = AF_UNSPEC;
	main_config.port = 0;
	main_config.daemonize = true;

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

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Cd:D:fhi:l:mMn:p:PstvxX")) != EOF) {

		switch (argval) {
			case 'C':
				check_config = true;
				spawn_flag = false;
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
				main_config.log_file = strdup(optarg);
				default_log.dst = L_DST_FILES;
				default_log.fd = open(main_config.log_file,
							    O_WRONLY | O_APPEND | O_CREAT, 0640);
				if (default_log.fd < 0) {
					fprintf(stderr, "%s: Failed to open log file %s: %s\n",
						main_config.name, main_config.log_file, fr_syserror(errno));
					exit(EXIT_FAILURE);
				}
				fr_log_fp = fdopen(default_log.fd, "a");
				break;

			case 'i':
				if (ip_hton(&main_config.myip, AF_UNSPEC, optarg, false) < 0) {
					fprintf(stderr, "%s: Invalid IP Address or hostname \"%s\"\n",
						main_config.name, optarg);
					exit(EXIT_FAILURE);
				}
				flag |= 1;
				break;

			case 'n':
				main_config.name = optarg;
				break;

			case 'm':
				main_config.debug_memory = true;
				break;

			case 'M':
				main_config.memory_report = true;
				main_config.debug_memory = true;
				break;

			case 'p':
			{
				unsigned long port;

				port = strtoul(optarg, 0, 10);
				if ((port == 0) || (port > UINT16_MAX)) {
					fprintf(stderr, "%s: Invalid port number \"%s\"\n",
						main_config.name, optarg);
					exit(EXIT_FAILURE);
				}

				main_config.port = (uint16_t) port;
				flag |= 2;
			}
				break;

			case 'P':
				/* Force the PID to be written, even in -f mode */
				main_config.write_pid = true;
				break;

			case 's':	/* Single process mode */
				spawn_flag = false;
				main_config.daemonize = false;
				break;

			case 't':	/* no child threads */
				spawn_flag = false;
				break;

			case 'v':
				display_version = true;
				break;

			case 'X':
				spawn_flag = false;
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

	/*
	 *  Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", main_config.name);
		exit(EXIT_FAILURE);
	}

	if (rad_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) exit(EXIT_FAILURE);

	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (ssl_check_consistency() < 0) exit(EXIT_FAILURE);
#endif

	if (flag && (flag != 0x03)) {
		fprintf(stderr, "%s: The options -i and -p cannot be used individually.\n",
			main_config.name);
		exit(EXIT_FAILURE);
	}

	/*
	 *  According to the talloc peeps, no two threads may modify any part of
	 *  a ctx tree with a common root without synchronisation.
	 *
	 *  So we can't run with a null context and threads.
	 */
	if (main_config.memory_report) {
		if (spawn_flag) {
			fprintf(stderr, "%s: The server cannot produce memory reports (-M) in threaded mode\n",
				main_config.name);
			exit(EXIT_FAILURE);
		}
		talloc_enable_null_tracking();
	} else {
		talloc_disable_null_tracking();
	}

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
	fr_store_debug_state();

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	if (tls_global_init(spawn_flag, check_config) < 0) exit(EXIT_FAILURE);
#endif

	/*
	 *  Write the PID always if we're running as a daemon.
	 */
	if (main_config.daemonize) main_config.write_pid = true;

	/*
	 *  Read the configuration files, BEFORE doing anything else.
	 */
	if (main_config_init() < 0) exit(EXIT_FAILURE);

	/*
	 *  This is very useful in figuring out why the panic_action didn't fire.
	 */
	INFO("%s", fr_debug_state_to_msg(fr_debug_state));

	/*
	 *  Check for vulnerabilities in the version of libssl were linked against.
	 */
#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(ENABLE_OPENSSL_VERSION_CHECK)
	if (tls_global_version_check(main_config.allow_vulnerable_openssl) < 0) exit(EXIT_FAILURE);
#endif

	fr_talloc_fault_setup();

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");
		if (!panic_action) panic_action = main_config.panic_action;

		if (panic_action && (fr_fault_setup(panic_action, argv[0]) < 0)) {
			fr_perror("%s", main_config.name);
			exit(EXIT_FAILURE);
		}
	}

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
			exit(EXIT_FAILURE);
		}
		dup2(devnull, STDIN_FILENO);

		close(devnull);

		if (pipe(from_child) != 0) {
			ERROR("Couldn't open pipe for child status: %s", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		pid = fork();
		if (pid < 0) {
			ERROR("Couldn't fork: %s", fr_syserror(errno));
			exit(EXIT_FAILURE);
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
	 *  Initialize any event loops just enough so module instantiations can
	 *  add fd/event to them, but do not start them yet.
	 *
	 *  This has to be done post-fork in case we're using kqueue, where the
	 *  queue isn't inherited by the child process.
	 */
	if (!radius_event_init(autofree)) exit(EXIT_FAILURE);

	/*
	 *   Load the modules
	 */
	if (modules_init(main_config.config) < 0) exit(EXIT_FAILURE);

	/*
	 *  Redirect stderr/stdout as appropriate.
	 */
	if (radlog_init(&default_log, main_config.daemonize) < 0) {
		ERROR("%s", fr_strerror());
		exit(EXIT_FAILURE);
	}

	event_loop_started = true;

	/*
	 *  Start the event loop(s) and threads.
	 */
	radius_event_start(main_config.config, spawn_flag);

	/*
	 *  Now that we've set everything up, we can install the signal
	 *  handlers.  Before this, if we get any signal, we don't know
	 *  what to do, so we might as well do the default, and die.
	 */
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	if ((fr_set_signal(SIGHUP, sig_hup) < 0) ||
	    (fr_set_signal(SIGTERM, sig_fatal) < 0)) {
		ERROR("%s", fr_strerror());
		exit(EXIT_FAILURE);
	}

	/*
	 *  If we're debugging, then a CTRL-C will cause the server to die
	 *  immediately.  Use SIGTERM to shut down the server cleanly in
	 *  that case.
	 */
	if (main_config.debug_memory || (rad_debug_lvl == 0)) {
		if ((fr_set_signal(SIGINT, sig_fatal) < 0)
#ifdef SIGQUIT
		|| (fr_set_signal(SIGQUIT, sig_fatal) < 0)
#endif
		) {
			ERROR("%s", fr_strerror());
			exit(EXIT_FAILURE);
		}
	}

	/*
	 *  Everything seems to have loaded OK, exit gracefully.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK");

		/* for -C -m|-M */
		if (main_config.debug_memory) goto cleanup;

		exit(EXIT_SUCCESS);
	}

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
			exit(EXIT_FAILURE);
		}
	}

	exec_trigger(NULL, NULL, "server.start", false);

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
	state = fr_state_init(NULL);

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
		ERROR("Exiting due to internal error: %s", fr_strerror());
		rcode = EXIT_FAILURE;
	} else {
		INFO("Exiting normally");
	}

	/*
	 *  Ignore the TERM signal: we're about to die.
	 */
	signal(SIGTERM, SIG_IGN);

	/*
	 *   Fire signal and stop triggers after ignoring SIGTERM, so handlers are
	 *   not killed with the rest of the process group, below.
	 */
	if (status == 2) exec_trigger(NULL, NULL, "server.signal.term", true);
	exec_trigger(NULL, NULL, "server.stop", false);

	/*
	 *  Send a TERM signal to all associated processes
	 *  (including us, which gets ignored.)
	 */
#ifndef __MINGW32__
	if (spawn_flag) kill(-radius_pid, SIGTERM);
#endif

	/*
	 *  We're exiting, so we can delete the PID file.
	 *  (If it doesn't exist, we can ignore the error returned by unlink)
	 */
	if (main_config.daemonize) unlink(main_config.pid_file);

	radius_event_free();

cleanup:
	/*
	 *  Detach any modules.
	 */
	modules_free();

	xlat_free();		/* modules may have xlat's */

	fr_state_delete(state);

	/*
	 *  Free the configuration items.
	 */
	main_config_free();

#ifdef WIN32
	WSACleanup();
#endif

#ifdef HAVE_OPENSSL_CRYPTO_H
	tls_global_cleanup();
#endif

	/*
	 *  So we don't see autofreed memory in the talloc report
	 */
	talloc_free(autofree);

	if (main_config.memory_report) {
		INFO("Allocated memory at time of report:");
		fr_log_talloc_report(NULL);
	}

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
	fprintf(output, "  -i <ipaddr>   Listen on ipaddr ONLY.\n");
	fprintf(output, "  -l <log_file> Logging output will be written to this file.\n");
	fprintf(output, "  -m            On SIGINT or SIGQUIT clean up all used memory instead of just exiting.\n");
	fprintf(output, "  -n <name>     Read raddb/name.conf instead of raddb/radiusd.conf.\n");
	fprintf(output, "  -p <port>     Listen on port ONLY.\n");
	fprintf(output, "  -P            Always write out PID, even with -f.\n");
	fprintf(output, "  -s            Do not spawn child processes to handle requests (same as -ft).\n");
	fprintf(output, "  -t            Disable threads.\n");
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
		if (main_config.debug_memory || main_config.memory_report) {
			radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
			break;
		}
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
