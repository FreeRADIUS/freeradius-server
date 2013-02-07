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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/file.h>

#include <fcntl.h>
#include <ctype.h>

#include <signal.h>

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
const char *progname = NULL;
char *radius_dir = NULL;
const char *radacct_dir = NULL;
const char *radlog_dir = NULL;
const char *radlib_dir = NULL;
int log_stripped_names;
int debug_flag = 0;
int check_config = FALSE;

const char *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" RADIUSD_VERSION_COMMIT ")"
#endif
", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

pid_t radius_pid;

static int debug_memory = 0;

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
	int rcode;
	int argval;
	int spawn_flag = TRUE;
	int dont_fork = FALSE;
	int flag = 0;

#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

#ifdef OSFC2
	set_auth_parameters(argc,argv);
#endif

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL)
		progname = argv[0];
	else
		progname++;

#ifdef WIN32
	{
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
		  fprintf(stderr, "%s: Unable to initialize socket library.\n", progname);
			return 1;
		}
	}
#endif

	debug_flag = 0;
	spawn_flag = TRUE;
	radius_dir = strdup(RADIUS_DIR);

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));
	mainconfig.myip.af = AF_UNSPEC;
	mainconfig.port = -1;
	mainconfig.name = "radiusd";

#ifdef HAVE_SIGACTION
	memset(&act, 0, sizeof(act));
	act.sa_flags = 0 ;
	sigemptyset( &act.sa_mask ) ;
#endif

	/*
	 *	Don't put output anywhere until we get told a little
	 *	more.
	 */
	mainconfig.radlog_dest = RADLOG_NULL;
	mainconfig.radlog_fd = -1;
	mainconfig.log_file = NULL;

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Cd:fhi:l:mn:p:stvxX")) != EOF) {

		switch(argval) {
			case 'C':
				check_config = TRUE;
				spawn_flag = FALSE;
				dont_fork = TRUE;
				break;

			case 'd':
				if (radius_dir) free(radius_dir);
				radius_dir = strdup(optarg);
				break;

			case 'f':
				dont_fork = TRUE;
				break;

			case 'h':
				usage(0);
				break;

			case 'l':
				if (strcmp(optarg, "stdout") == 0) {
					goto do_stdout;
				}
				mainconfig.log_file = strdup(optarg);
				mainconfig.radlog_dest = RADLOG_FILES;
				mainconfig.radlog_fd = open(mainconfig.log_file,
							    O_WRONLY | O_APPEND | O_CREAT, 0640);
				if (mainconfig.radlog_fd < 0) {
					fprintf(stderr, "radiusd: Failed to open log file %s: %s\n", mainconfig.log_file, strerror(errno));
					exit(1);
				}
				fr_log_fp = fdopen(mainconfig.radlog_fd, "a");
				break;		  

			case 'i':
				if (ip_hton(optarg, AF_UNSPEC, &mainconfig.myip) < 0) {
					fprintf(stderr, "radiusd: Invalid IP Address or hostname \"%s\"\n", optarg);
					exit(1);
				}
				flag |= 1;
				break;

			case 'n':
				mainconfig.name = optarg;
				break;

			case 'm':
				debug_memory = 1;
				break;

			case 'p':
				mainconfig.port = atoi(optarg);
				if ((mainconfig.port <= 0) ||
				    (mainconfig.port >= 65536)) {
					fprintf(stderr, "radiusd: Invalid port number %s\n", optarg);
					exit(1);
				}
				flag |= 2;
				break;

			case 's':	/* Single process mode */
				spawn_flag = FALSE;
				dont_fork = TRUE;
				break;

			case 't':	/* no child threads */
				spawn_flag = FALSE;
				break;

			case 'v':
				/* Don't print timestamps */
				debug_flag += 2;
				fr_log_fp = stdout;
				mainconfig.radlog_dest = RADLOG_STDOUT;
				mainconfig.radlog_fd = STDOUT_FILENO;
				
				version();
				exit(0);
			case 'X':
				spawn_flag = FALSE;
				dont_fork = TRUE;
				debug_flag += 2;
				mainconfig.log_auth = TRUE;
				mainconfig.log_auth_badpass = TRUE;
				mainconfig.log_auth_goodpass = TRUE;
		do_stdout:
				fr_log_fp = stdout;
				mainconfig.radlog_dest = RADLOG_STDOUT;
				mainconfig.radlog_fd = STDOUT_FILENO;
				break;

			case 'x':
				debug_flag++;
				break;

			default:
				usage(1);
				break;
		}
	}

	/*
	 *	Mismatch between build time OpenSSL and linked SSL,
	 *	better to die here than segfault later.
	 */
	if (ssl_check_version() < 0) {
		exit(1);
	}

	if (flag && (flag != 0x03)) {
		fprintf(stderr, "radiusd: The options -i and -p cannot be used individually.\n");
		exit(1);
	}

	if (debug_flag)
		version();
		

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (read_mainconfig(0) < 0) {
		exit(1);
	}

#ifndef __MINGW32__
	/*
	 *  Disconnect from session
	 */
	if (dont_fork == FALSE) {
		pid_t pid = fork();

		if (pid < 0) {
			radlog(L_ERR, "Couldn't fork: %s", strerror(errno));
			exit(1);
		}

		/*
		 *  The parent exits, so the child can run in the background.
		 */
		if (pid > 0) {
			exit(0);
		}
#ifdef HAVE_SETSID
		setsid();
#endif
	}
#endif

	/*
	 *  Ensure that we're using the CORRECT pid after forking,
	 *  NOT the one we started with.
	 */
	radius_pid = getpid();

	/*
	 *	If we're running as a daemon, close the default file
	 *	descriptors, AFTER forking.
	 */
	if (!debug_flag) {
		int devnull;

		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			radlog(L_ERR|L_CONS, "Failed opening /dev/null: %s\n",
			       strerror(errno));
			exit(1);
		}
		dup2(devnull, STDIN_FILENO);
		if (mainconfig.radlog_dest == RADLOG_STDOUT) {
			setlinebuf(stdout);
			mainconfig.radlog_fd = STDOUT_FILENO;
		} else {
			dup2(devnull, STDOUT_FILENO);
		}
		if (mainconfig.radlog_dest == RADLOG_STDERR) {
			setlinebuf(stderr);
			mainconfig.radlog_fd = STDERR_FILENO;
		} else {
			dup2(devnull, STDERR_FILENO);
		}
		close(devnull);

	} else {
		setlinebuf(stdout); /* unbuffered output */
	}
	
	/*
	 *	Now we have logging check that the OpenSSL 
	 */

	/*
	 *	Initialize the event pool, including threads.
	 */
	radius_event_init(mainconfig.config, spawn_flag);

	/*
	 *	Now that we've set everything up, we can install the signal
	 *	handlers.  Before this, if we get any signal, we don't know
	 *	what to do, so we might as well do the default, and die.
	 */
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef HAVE_SIGACTION
	act.sa_handler = sig_hup;
	sigaction(SIGHUP, &act, NULL);
	act.sa_handler = sig_fatal;
	sigaction(SIGTERM, &act, NULL);
#else
#ifdef SIGHUP
	signal(SIGHUP, sig_hup);
#endif
	signal(SIGTERM, sig_fatal);
#endif
	/*
	 *	If we're debugging, then a CTRL-C will cause the
	 *	server to die immediately.  Use SIGTERM to shut down
	 *	the server cleanly in that case.
	 */
	if ((debug_memory == 1) || (debug_flag == 0)) {
#ifdef HAVE_SIGACTION
	        act.sa_handler = sig_fatal;
		sigaction(SIGINT, &act, NULL);
		sigaction(SIGQUIT, &act, NULL);
#else
		signal(SIGINT, sig_fatal);
#ifdef SIGQUIT
		signal(SIGQUIT, sig_fatal);
#endif
#endif
	}

	/*
	 *	Everything seems to have loaded OK, exit gracefully.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK.");
		exit(0);
	}

#ifdef WITH_STATS
	radius_stats_init(0);
#endif

	/*
	 *  Only write the PID file if we're running as a daemon.
	 *
	 *  And write it AFTER we've forked, so that we write the
	 *  correct PID.
	 */
	if (dont_fork == FALSE) {
		FILE *fp;

		fp = fopen(mainconfig.pid_file, "w");
		if (fp != NULL) {
			/*
			 *	FIXME: What about following symlinks,
			 *	and having it over-write a normal file?
			 */
			fprintf(fp, "%d\n", (int) radius_pid);
			fclose(fp);
		} else {
			radlog(L_ERR|L_CONS, "Failed creating PID file %s: %s\n",
			       mainconfig.pid_file, strerror(errno));
			exit(1);
		}
	}

	exec_trigger(NULL, NULL, "server.start", FALSE);

	/*
	 *	Process requests until HUP or exit.
	 */
	while ((rcode = radius_event_process()) == 0x80) {
#ifdef WITH_STATS
		radius_stats_init(1);
#endif
		hup_mainconfig();
	}

	if (rcode < 0) {
		radlog(L_ERR, "Exiting due to internal error: %s",
		       fr_strerror());
		rcode = 2;
	} else {
		radlog(L_INFO, "Exiting normally.");
	}

	exec_trigger(NULL, NULL, "server.stop", FALSE);

	/*
	 *	Ignore the TERM signal: we're
	 *	about to die.
	 */
	signal(SIGTERM, SIG_IGN);
	
	/*
	 *	Send a TERM signal to all
	 *	associated processes
	 *	(including us, which gets
	 *	ignored.)
	 */
#ifndef __MINGW32__
	if (spawn_flag) kill(-radius_pid, SIGTERM);
#endif
	
	/*
	 *	We're exiting, so we can delete the PID
	 *	file.  (If it doesn't exist, we can ignore
	 *	the error returned by unlink)
	 */
	if (dont_fork == FALSE) {
		unlink(mainconfig.pid_file);
	}
		
	radius_event_free();
	
	/*
	 *	Detach any modules.
	 */
	detach_modules();
	
	/*
	 *	Free the configuration items.
	 */
	free_mainconfig();
	
	xlat_free();		/* modules may have xlat's */

	free(radius_dir);
		
#ifdef WIN32
	WSACleanup();
#endif

	return (rcode - 1);
}


/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output,
			"Usage: %s [-d db_dir] [-l log_dir] [-i address] [-n name] [-fsvXx]\n", progname);
	fprintf(output, "Options:\n\n");
	fprintf(output, "  -C              Check configuration and exit.\n");
	fprintf(output, "  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	fprintf(output, "  -f              Run as a foreground process, not a daemon.\n");
	fprintf(output, "  -h              Print this help message.\n");
	fprintf(output, "  -i ipaddr       Listen on ipaddr ONLY.\n");
	fprintf(output, "  -l log_file     Logging output will be written to this file.\n");
	fprintf(output, "  -m              On SIGINT or SIGQUIT exit cleanly instead of immediately.\n");
	fprintf(output, "  -n name         Read raddb/name.conf instead of raddb/radiusd.conf\n");
	fprintf(output, "  -p port         Listen on port ONLY.\n");
	fprintf(output, "  -s              Do not spawn child processes to handle requests.\n");
	fprintf(output, "  -t              Disable threads.\n");
	fprintf(output, "  -v              Print server version information.\n");
	fprintf(output, "  -X              Turn on full debugging.\n");
	fprintf(output, "  -x              Turn on additional debugging. (-xx gives more debugging).\n");
	exit(status);
}


/*
 *	We got a fatal signal.
 */
static void sig_fatal(int sig)
{
	if (getpid() != radius_pid) _exit(sig);

	switch(sig) {
		case SIGTERM:
			radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
			break;

		case SIGINT:
#ifdef SIGQUIT
		case SIGQUIT:
#endif
			if (debug_memory) {
				radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
				break;
			}
			/* FALL-THROUGH */

		default:
			_exit(sig);
	}
}

#ifdef SIGHUP
/*
 *  We got the hangup signal.
 *  Re-read the configuration files.
 */
static void sig_hup(int sig)
{
	sig = sig; /* -Wunused */

	reset_signal(SIGHUP, sig_hup);

	radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
}
#endif
