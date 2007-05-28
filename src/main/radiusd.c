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
 * Copyright 2000-2004,2006  The FreeRADIUS server project
 * Copyright 1999,2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman-radius@cqc.com>
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 * Copyright 2000  Chad Miller <cmiller@surfsouth.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius_snmp.h>
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
const char *radius_dir = NULL;
const char *radacct_dir = NULL;
const char *radlog_dir = NULL;
const char *radlib_dir = NULL;
int log_stripped_names;
int debug_flag = 0;
int log_auth_detail = FALSE;


const char *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION ", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

time_t time_now;
static pid_t radius_pid;
static int debug_memory = 0;
static int has_detail_listener = FALSE;

static int radius_self_pipe[2];

/*
 *  Configuration items.
 */

/*
 *	Static functions.
 */
static void usage(int);

static void sig_fatal (int);
static void sig_hup (int);

/*
 *	The main guy.
 */
int main(int argc, char *argv[])
{
	REQUEST *request;
	unsigned char buffer[4096];
	fd_set readfds;
	int argval;
	int pid;
	int max_fd;
	int status;
	int dont_fork = FALSE;
	int spawn_flag = TRUE;
	int sig_hup_block = FALSE;
	struct timeval tv, *ptv = NULL;
	int read_from_detail = FALSE;
	int fd_flags;

#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif
	rad_listen_t *listener;

#ifdef OSFC2
	set_auth_parameters(argc,argv);
#endif

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	debug_flag = 0;
	spawn_flag = TRUE;
	radius_dir = strdup(RADIUS_DIR);

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));
	mainconfig.myip.af = AF_UNSPEC;
	mainconfig.port = -1;
	mainconfig.radiusd_conf = strdup("radiusd.conf");

#ifdef HAVE_SIGACTION
	memset(&act, 0, sizeof(act));
	act.sa_flags = 0 ;
	sigemptyset( &act.sa_mask ) ;
#endif

	/*
	 *	Don't put output anywhere until we get told a little
	 *	more.
	 */
	mainconfig.radlog_fd = -1;
	mainconfig.log_file = NULL;

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Aa:bcd:fg:hi:l:mn:p:sSvxXyz")) != EOF) {

		switch(argval) {

			case 'A':
				log_auth_detail = TRUE;
				break;

			case 'a':
				if (radacct_dir) free(radacct_dir);
				radacct_dir = strdup(optarg);
				break;

			case 'c':
				/* ignore for backwards compatibility with Cistron */
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

			case 'i':
				if (ip_hton(optarg, AF_UNSPEC, &mainconfig.myip) < 0) {
					fprintf(stderr, "radiusd: Invalid IP Address or hostname \"%s\"\n", optarg);
					exit(1);
				}
				break;

			case 'l':
				if ((strcmp(optarg, "stdout") == 0) ||
				    (strcmp(optarg, "stderr") == 0) ||
				    (strcmp(optarg, "syslog") == 0)) {
					fprintf(stderr, "radiusd: -l %s is unsupported.  Use log_destination in radiusd.conf\n", optarg);
					exit(1);
				}
				if (radlog_dir) free(radlog_dir);
				radlog_dir = strdup(optarg);
				break;

			case 'g':
				fprintf(stderr, "radiusd: -g is unsupported.  Use log_destination in radiusd.conf.\n");
				exit(1);
				break;

			case 'm':
				debug_memory = 1;
				break;

			case 'n':
				if ((strchr(optarg, '/') != NULL) ||
				    (strchr(optarg, '.') != NULL) ||
				    (strlen(optarg) > 45)) usage(1);

				snprintf(buffer, sizeof(buffer), "%s.conf",
					 optarg);
				if (mainconfig.radiusd_conf)
					free(mainconfig.radiusd_conf);
				mainconfig.radiusd_conf = strdup(buffer);
				break;

			case 'S':
				log_stripped_names++;
				break;

			case 'p':
				mainconfig.port = atoi(optarg);
				if ((mainconfig.port <= 0) ||
				    (mainconfig.port >= 65536)) {
					fprintf(stderr, "radiusd: Invalid port number %s\n", optarg);
					exit(1);
				}
				break;

			case 's':	/* Single process mode */
				spawn_flag = FALSE;
				dont_fork = TRUE;
				break;

			case 'v':
				version();
				break;

				/*
				 *  BIG debugging mode for users who are
				 *  TOO LAZY to type '-sfxxyz -l stdout' themselves.
				 */
			case 'X':
				spawn_flag = FALSE;
				dont_fork = TRUE;
				debug_flag += 2;
				mainconfig.log_auth = TRUE;
				mainconfig.log_auth_badpass = TRUE;
				mainconfig.log_auth_goodpass = TRUE;
				mainconfig.radlog_dest = RADLOG_STDOUT;
				mainconfig.radlog_fd = STDOUT_FILENO;
				break;

			case 'x':
				debug_flag++;
				break;

			case 'y':
				mainconfig.log_auth = TRUE;
				mainconfig.log_auth_badpass = TRUE;
				break;

			case 'z':
				mainconfig.log_auth_badpass = TRUE;
				mainconfig.log_auth_goodpass = TRUE;
				break;

			default:
				usage(1);
				break;
		}
	}

	if (debug_flag) {
		radlog(L_INFO, "%s", radiusd_version);
		radlog(L_INFO, "Copyright (C) 2000-2007 The FreeRADIUS server project.\n");
		radlog(L_INFO, "There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
		radlog(L_INFO, "PARTICULAR PURPOSE.\n");
		radlog(L_INFO, "You may redistribute copies of FreeRADIUS under the terms of the\n");
		radlog(L_INFO, "GNU General Public License.\n");
		fflush(NULL);
	}

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (read_mainconfig(0) < 0) {
		exit(1);
	}

	/*
	 *  Disconnect from session
	 */
	if (debug_flag == 0 && dont_fork == FALSE) {
		pid = fork();
		if(pid < 0) {
			radlog(L_ERR|L_CONS, "Couldn't fork");
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

	/*
	 *	If we're NOT debugging, trap fatal signals, so we can
	 *	easily clean up after ourselves.
	 *
	 *	If we ARE debugging, don't trap them, so we can
	 *	dump core.
	 */
	if ((mainconfig.allow_core_dumps == FALSE) && (debug_flag == 0)) {
#ifdef SIGSEGV
#ifdef HAVE_SIGACTION
		act.sa_handler = sig_fatal;
		sigaction(SIGSEGV, &act, NULL);
#else
		signal(SIGSEGV, sig_fatal);
#endif
#endif
	}

	/*
	 *  Ensure that we're using the CORRECT pid after forking,
	 *  NOT the one we started with.
	 */
	radius_pid = getpid();

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

	/*
	 *	Child threads need a pipe to signal us, as do the
	 *	signal handlers.
	 */
	if (pipe(radius_self_pipe) < 0) {
		radlog(L_ERR, "radiusd: Error opening internal pipe: %s",
		       strerror(errno));
		exit(1);
	}
	if (fcntl(radius_self_pipe[0], F_SETFL, O_NONBLOCK | FD_CLOEXEC) < 0) {
		radlog(L_ERR, "radiusd: Error setting internal flags: %s",
		       strerror(errno));
		exit(1);
	}
	if (fcntl(radius_self_pipe[1], F_SETFL, O_NONBLOCK | FD_CLOEXEC) < 0) {
		radlog(L_ERR, "radiusd: Error setting internal flags: %s",
		       strerror(errno));
		exit(1);
	}

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
			mainconfig.radlog_fd = dup(STDOUT_FILENO);
		}
		dup2(devnull, STDOUT_FILENO);
		if (mainconfig.radlog_dest == RADLOG_STDERR) {
			mainconfig.radlog_fd = dup(STDERR_FILENO);
		}
		dup2(devnull, STDERR_FILENO);
		close(devnull);
	}

	/*
	 *	It's called the thread pool, but it does a little
	 *	more than that.
	 */
	radius_event_init(spawn_flag);

	/*
	 *  Use linebuffered or unbuffered stdout if
	 *  the debug flag is on.
	 */
	if (debug_flag == TRUE)
		setlinebuf(stdout);

	/*
	 *	Print out which ports we're listening on.
	 */
	for (listener = mainconfig.listen;
	     listener != NULL;
	     listener = listener->next) {
		listener->print(listener, buffer, sizeof(buffer));
		switch (listener->type) {
		case RAD_LISTEN_AUTH:
			DEBUG("Listening on authentication address %s", buffer);
			break;

		case RAD_LISTEN_ACCT:
			DEBUG("Listening on accounting address %s", buffer);
			break;

		case RAD_LISTEN_PROXY:
			DEBUG("Listening on proxy address %s", buffer);
			break;

		case RAD_LISTEN_DETAIL:
			has_detail_listener = TRUE;
			read_from_detail = TRUE;
			DEBUG("Listening on detail file %s", buffer);
			break;

		case RAD_LISTEN_SNMP:
			DEBUG("Listening on SNMP %s", buffer);
			break;

		case RAD_LISTEN_VQP:
			DEBUG("Listening on vmps %s", buffer);
			break;

		default:
			break;
		}
	}

	/*
	 *	Now that we've set everything up, we can install the signal
	 *	handlers.  Before this, if we get any signal, we don't know
	 *	what to do, so we might as well do the default, and die.
	 */
	signal(SIGPIPE, SIG_IGN);
#ifdef HAVE_SIGACTION
	act.sa_handler = sig_hup;
	sigaction(SIGHUP, &act, NULL);
	act.sa_handler = sig_fatal;
	sigaction(SIGTERM, &act, NULL);
#else
	signal(SIGHUP, sig_hup);
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
		signal(SIGQUIT, sig_fatal);
#endif
	}

 restart:
	radlog(L_INFO, "Ready to process requests.");

	/*
	 *  Receive user requests
	 */
	for (;;) {
		ssize_t rcode;

		FD_ZERO(&readfds);
		max_fd = 0;

		/*
		 *	Loop over all the listening FD's.
		 */
		for (listener = mainconfig.listen;
		     listener != NULL;
		     listener = listener->next) {
			if (listener->fd < 0) continue;

			if (!read_from_detail &&
			    (listener->type == RAD_LISTEN_DETAIL)) continue;

			FD_SET(listener->fd, &readfds);
			if (listener->fd > max_fd) max_fd = listener->fd;
		}

		/*
		 *	Add in the self pipe FD, for signals or
		 *	notices from the child threads.
		 */
		FD_SET(radius_self_pipe[0], &readfds);
		if (radius_self_pipe[0] > max_fd) {
			max_fd = radius_self_pipe[0];
		}

		if (!ptv) {
			DEBUG2("Nothing to do.  Sleeping until we see a request.");
		} else if (tv.tv_sec) {
				DEBUG2("Waking up in %d seconds...",
				       (int) tv.tv_sec);
		}

		status = select(max_fd + 1, &readfds, NULL, NULL, ptv);
		if ((status < 0) && (errno != EINTR)) {
			radlog(L_ERR, "Unexpected error in select(): %s",
			       strerror(errno));
				exit(1);
		}
		time_now = time(NULL);

#ifndef HAVE_PTHREAD_H
		/*
		 *	If there are no child threads, then there may
		 *	be child processes.  In that case, wait for
		 *	their exit status, and throw that exit status
		 *	away.  This helps get rid of zxombie children.
		 */
		while (waitpid(-1, &argval, WNOHANG) > 0) {
			/* do nothing */
		}
#endif

		/*
		 *	Before doing anything else, check the self pipe.
		 */
		if (FD_ISSET(radius_self_pipe[0], &readfds) &&
		    (rcode = read(radius_self_pipe[0], buffer, sizeof(buffer))) > 0) {
			ssize_t i;

			for (i = 1; i < rcode; i++) {
				buffer[0] |= buffer[i];
			}

			if ((buffer[0] & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
				DEBUG("Exiting...");

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
				kill(-radius_pid, SIGTERM);

				/*
				 *	FIXME: Kill child threads, and
				 *	clean up?
				 */

				/*
				 *	FIXME: clean up any active REQUEST
				 *	handles.
				 */

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
				 *	Free the configuration items.
				 */
				free_mainconfig();

				/*
				 *	Detach any modules.
				 */
				detach_modules();

				free(radius_dir);

				/*
				 *	SIGTERM gets do_exit=0,
				 *	and we want to exit cleanly.
				 *
				 *	Other signals make us exit
				 *	with an error status.
				 */
				if ((buffer[0] & RADIUS_SIGNAL_SELF_EXIT) != 0) {
					exit(1);
				}
				exit(0);
			} /* else exit/term flags weren't set */

			if ((buffer[0] & RADIUS_SIGNAL_SELF_HUP) != 0) {
				DEBUG("Received HUP signal");
#ifdef HAVE_PTHREAD_H
				/*
				 *	Threads: wait for all threads to stop
				 *	processing before re-loading the
				 *	config, so we don't pull the rug out
				 *	from under them.
				 */
				int max_wait = 0;
				if (spawn_flag) for(;;) {
					/*
					 *	Block until there are
					 *	zero threads with a
					 *	REQUEST handle.
					 *
					 *	FIXME: Wait for
					 *	threads to send us a
					 *	signal in the pipe?
					 */
					sig_hup_block = TRUE;

					if( (total_active_threads() == 0) ||
					    (max_wait >= 5) ) {
						sig_hup_block = FALSE;
						break;
					}
					sleep(1);
					max_wait++;
				}
#endif

#ifdef WITH_SNMP
				if (mainconfig.do_snmp) {
					rad_snmp.smux_failures = 0;
					rad_snmp.smux_event = SMUX_CONNECT;
				}
#endif
				if (read_mainconfig(TRUE) < 0) {
					exit(1);
				}

				goto restart;
			}

			/*
			 *	Check if we can read from the detail file
			 */
			if (has_detail_listener &&
			    (buffer[0] & RADIUS_SIGNAL_SELF_DETAIL) != 0) {
				DEBUG3("Can now read from detail file(s)");
				read_from_detail = TRUE;
			}
		} /* else the self pipe didn't have data ready */

		/*
		 *	Loop over the open socket FD's, reading any data.
		 */
		for (listener = mainconfig.listen;
		     listener != NULL;
		     listener = listener->next) {
			RAD_REQUEST_FUNP fun;

			if ((listener->fd >= 0) &&
			    !FD_ISSET(listener->fd, &readfds))
				continue;

			/*
			 *  Receive the packet.
			 */
			if (sig_hup_block != FALSE) {
				continue;
			}

			/*
			 *	Do per-socket receive processing of
			 *	the packet.  This also takes care of
			 *	inserting the request into the event
			 *	tree, and adding it to the queue for
			 *	threads.
			 */
			if (!listener->recv(listener, &fun, &request)) {
				continue;
			}

			/*
			 *	Drop the request into the thread pool,
			 *	and let the thread pool take care of
			 *	doing something with it.
			 */
			if (!thread_pool_addrequest(request, fun)) {
				request->child_state = REQUEST_DONE;
			}

			/*
			 *	If we've read a packet from a socket
			 *	OTHER than the detail file, we start
			 *	ignoring the detail file.
			 *
			 *	When the child thread pulls the
			 *	request off of the queues, it will
			 *	check if the queues are empty.  Once
			 *	all queues are empty, it will signal
			 *	us to read the detail file again.
			 */
			if (spawn_flag &&
			    (listener->type != RAD_LISTEN_DETAIL)) {
				read_from_detail = FALSE;
			}
		} /* loop over listening sockets*/

		ptv = &tv;
		radius_event_process(&ptv);

#ifdef HAVE_PTHREAD_H

		/*
		 *	Only clean the thread pool if we're spawning
		 *	child threads.
		 *
		 *	FIXME: Move this to the event handler!
		 */
		if (spawn_flag) {
			thread_pool_clean(time_now);
		}
#endif
	} /* loop forever */
}


/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output,
			"Usage: %s [-a acct_dir] [-d db_dir] [-l log_dir] [-i address] [-AcfnsSvXxyz]\n", progname);
	fprintf(output, "Options:\n\n");
	fprintf(output, "  -a acct_dir     use accounting directory 'acct_dir'.\n");
	fprintf(output, "  -A              Log auth detail.\n");
	fprintf(output, "  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	fprintf(output, "  -f              Run as a foreground process, not a daemon.\n");
	fprintf(output, "  -h              Print this help message.\n");
	fprintf(output, "  -i ipaddr       Listen on ipaddr ONLY\n");
	fprintf(output, "  -l log_dir      Log file is \"log_dir/radius.log\" (not used in debug mode)\n");
	fprintf(output, "  -p port         Listen on port ONLY\n");
	fprintf(output, "  -s              Do not spawn child processes to handle requests.\n");
	fprintf(output, "  -S              Log stripped names.\n");
	fprintf(output, "  -v              Print server version information.\n");
	fprintf(output, "  -X              Turn on full debugging.\n");
	fprintf(output, "  -x              Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(output, "  -y              Log authentication failures, with password.\n");
	fprintf(output, "  -z              Log authentication successes, with password.\n");
	exit(status);
}


/*
 *	We got a fatal signal.
 */
static void sig_fatal(int sig)
{
	switch(sig) {
		case SIGSEGV:
			/*
			 *	We can't really do anything
			 *	intelligent here so just die
			 */
			_exit(1);

		case SIGTERM:
			radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
			break;

		case SIGINT:
		case SIGQUIT:
			if (debug_memory) {
				radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
				break;
			}
			/* FALL-THROUGH */

		default:
			radius_signal_self(RADIUS_SIGNAL_SELF_EXIT);
			break;
	}
}


/*
 *  We got the hangup signal.
 *  Re-read the configuration files.
 */
static void sig_hup(int sig)
{
	sig = sig; /* -Wunused */

	reset_signal(SIGHUP, sig_hup);

	write(STDOUT_FILENO, "STUFF\n", 6);

	radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
}

void radius_signal_self(int flag)
{
	ssize_t rcode;
	uint8_t buffer[16];

	/*
	 *	The caller is telling us it's OK to read from the
	 *	detail files.  However, we're not even listening on
	 *	the detail files.  Therefore, suppress the flag to
	 *	avoid bothering the mail worker thread.
	 */
	if ((flag == RADIUS_SIGNAL_SELF_DETAIL) &&
	    !has_detail_listener) {
		return;
	}

	/*
	 *	The read MUST be non-blocking for this to work.
	 */
	rcode = read(radius_self_pipe[0], buffer, sizeof(buffer));
	if (rcode > 0) {
		ssize_t i;

		for (i = 1; i < rcode; i++) {
			buffer[0] |= buffer[i];
		}
	}

#ifndef NDEBUG
	memset(buffer + 1, 0, sizeof(buffer) - 1);
#endif

	buffer[0] |= flag;


	write(radius_self_pipe[1], buffer, 1);
}
