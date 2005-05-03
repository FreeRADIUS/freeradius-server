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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001,2002,2003,2004  The FreeRADIUS server project
 * Copyright 1999,2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman-radius@cqc.com>
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 * Copyright 2000  Chad Miller <cmiller@surfsouth.com>
 */

/* don't look here for the version, run radiusd -v or look in version.c */
static const char rcsid[] =
"$Id$";

#include "autoconf.h"

#include <sys/file.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif

#include <signal.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#	include <sys/select.h>
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

#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"
#include "modules.h"
#include "request_list.h"
#include "radius_snmp.h"

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
int need_reload = FALSE;
const char *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION ", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

time_t time_now;
static pid_t radius_pid;

/*
 *  Configuration items.
 */
static int do_exit = 0;

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
	struct timeval *tv = NULL;
	int spawn_flag = TRUE;
	int dont_fork = FALSE;
	int sig_hup_block = FALSE;

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

#ifdef HAVE_SIGACTION
	memset(&act, 0, sizeof(act));
	act.sa_flags = 0 ;
	sigemptyset( &act.sa_mask ) ;
#endif

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "Aa:bcd:fg:hi:l:p:sSvxXyz")) != EOF) {

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
				if (ip_hton(optarg, AF_INET, &mainconfig.myip) < 0) {
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
				radlog_dir = strdup(optarg);
				break;

			case 'g':
				fprintf(stderr, "radiusd: -g is unsupported.  Use log_destination in radiusd.conf.\n");
				exit(1);
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

	/*
	 *	Get our PID.
	 */
	radius_pid = getpid();

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (read_mainconfig(0) < 0) {
		exit(1);
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

	/*  Reload the modules.  */
	DEBUG2("radiusd:  entering modules setup");
	if (setup_modules() < 0) {
		radlog(L_ERR|L_CONS, "Errors setting up modules");
		exit(1);
	}

	/*  Initialize the request list.  */
	rl_init();

#ifdef WITH_SNMP
	if (mainconfig.do_snmp) radius_snmp_init();
#endif

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
		if(pid > 0) {
			exit(0);
		}
#ifdef HAVE_SETSID
		setsid();
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
	 *	If we're running as a daemon, close the default file
	 *	descriptors, AFTER forking.
	 */
	mainconfig.radlog_fd = -1;
	if (debug_flag) {
		mainconfig.radlog_fd = STDOUT_FILENO;
	} else {
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
	thread_pool_init(spawn_flag);

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
		if ((listener->ipaddr.af == AF_INET) &&
		    (listener->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
			strcpy(buffer, "*");
		} else if ((listener->ipaddr.af == AF_INET6) &&
			   (IN6_IS_ADDR_UNSPECIFIED(&listener->ipaddr.ipaddr))) {
			strcpy(buffer, "* (IPv6)");

		} else {
			ip_ntoh(&listener->ipaddr, buffer, sizeof(buffer));
		}
		
		switch (listener->type) {
		case RAD_LISTEN_AUTH:
			DEBUG("Listening on authentication address %s port %d",
			      buffer, listener->port);
			break;

		case RAD_LISTEN_ACCT:
			DEBUG("Listening on accounting addres %s port %d",
			      buffer, listener->port);
			break;

		case RAD_LISTEN_PROXY:
			DEBUG("Listening on proxy address %s port %d",
			      buffer, listener->port);
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
	if (debug_flag == 0) {
#ifdef HAVE_SIGACTION
	        act.sa_handler = sig_fatal;
		sigaction(SIGINT, &act, NULL);
		sigaction(SIGQUIT, &act, NULL);
#else
		signal(SIGINT, sig_fatal);
		signal(SIGQUIT, sig_fatal);
#endif
	}

	radlog(L_INFO, "Ready to process requests.");

	/*
	 *  Receive user requests
	 */
	for (;;) {
		/*
		 *	If we've been told to exit, then do so,
		 *	even if we have data waiting.
		 */
		if (do_exit) {
			DEBUG("Exiting...");

			/*
			 *	Ignore the TERM signal: we're about
			 *	to die.
			 */
			signal(SIGTERM, SIG_IGN);

			/*
			 *	Send a TERM signal to all associated
			 *	processes (including us, which gets
			 *	ignored.)
			 */
			kill(-radius_pid, SIGTERM);

			/*
			 *	FIXME: Kill child threads, and
			 *	clean up?
			 */

			/*
			 *	Detach any modules.
			 */
			detach_modules();

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

			/*
			 *	Free the configuration items.
			 */
			free_mainconfig();

			/*
			 *	SIGTERM gets do_exit=0,
			 *	and we want to exit cleanly.
			 *
			 *	Other signals make us exit
			 *	with an error status.
			 */
			exit(do_exit - 1);
		}

		if (need_reload) {
#ifdef HAVE_PTHREAD_H
			/*
			 *	Threads: wait for all threads to stop
			 *	processing before re-loading the
			 *	config, so we don't pull the rug out
			 *	from under them.
			 */
		        int max_wait = 0;
		        if (!spawn_flag) for(;;) {
			        /*
				 * Block until there are '0' threads
				 * with a REQUEST handle.
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
			if (read_mainconfig(TRUE) < 0) {
				exit(1);
			}

			/*  Reload the modules.  */
			DEBUG2("radiusd:  entering modules setup");
			if (setup_modules() < 0) {
				radlog(L_ERR|L_CONS, "Errors setting up modules");
				exit(1);
			}

			need_reload = FALSE;
			radlog(L_INFO, "Ready to process requests.");
		}

		FD_ZERO(&readfds);
		max_fd = 0;

		/*
		 *	Loop over all the listening FD's.
		 */
		for (listener = mainconfig.listen;
		     listener != NULL;
		     listener = listener->next) {
			FD_SET(listener->fd, &readfds);
			if (listener->fd > max_fd) max_fd = listener->fd;
		}

#ifdef WITH_SNMP
		if (mainconfig.do_snmp &&
		    (rad_snmp.smux_fd >= 0)) {
			FD_SET(rad_snmp.smux_fd, &readfds);
			if (rad_snmp.smux_fd > max_fd) max_fd = rad_snmp.smux_fd;
		}
#endif
		status = select(max_fd + 1, &readfds, NULL, NULL, tv);
		if (status == -1) {
			/*
			 *	On interrupts, we clean up the request
			 *	list.  We then continue with the loop,
			 *	so that if we're supposed to exit,
			 *	then the code at the start of the loop
			 *	catches that, and exits.
			 */
			if (errno == EINTR) {
#ifdef MEMORY_USE_DEBUGGING
				/*
				 *	Run the server in debugging mode,
				 *	without threads, and give it a
				 *	SIGHUP.  It will clean up after
				 *	itself, and any memory left over
				 *	should be allocated by C libraries,
				 *	and the like.
				 */
				detach_modules();
				rl_deinit();
				free_mainconfig();
				xlat_free();
				dict_free();
				exit(1);
#endif
				tv = rl_clean_list(time(NULL));
				continue;
			}
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
		 *	Loop over the open socket FD's, reading any data.
		 */
		for (listener = mainconfig.listen;
		     listener != NULL;
		     listener = listener->next) {
			RAD_REQUEST_FUNP fun;

			if (!FD_ISSET(listener->fd, &readfds))
				continue;
			/*
			 *  Receive the packet.
			 */
			if (sig_hup_block != FALSE) {
				continue;
			}

			/*
			 *	Do per-socket receive processing of the
			 *	packet.
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
				/*
				 *	FIXME: Maybe just drop
				 *	the packet on the floor?
				 */
				request_reject(request, REQUEST_FAIL_NO_THREADS);
				request->finished = TRUE;
			}
		} /* loop over listening sockets*/

#ifdef WITH_SNMP
		if (mainconfig.do_snmp) {
			/*
			 *  After handling all authentication/accounting
			 *  requests, THEN process any pending SMUX/SNMP
			 *  queries.
			 *
			 *  Note that the handling is done in the main server,
			 *  which probably isn't a Good Thing.  It really
			 *  should be wrapped, and handled in a thread pool.
			 */
			if ((rad_snmp.smux_fd >= 0) &&
			    FD_ISSET(rad_snmp.smux_fd, &readfds) &&
			    (rad_snmp.smux_event == SMUX_READ)) {
				smux_read();
			}

			/*
			 *  If we've got to re-connect, then do so now,
			 *  before calling select again.
			 */
			if (rad_snmp.smux_event == SMUX_CONNECT) {
				smux_connect();
			}
		}
#endif

		/*
		 *  After processing all new requests,
		 *  check if we've got to delete old requests
		 *  from the request list.
		 */
		tv = rl_clean_list(time_now);
#ifdef HAVE_PTHREAD_H

		/*
		 *	Only clean the thread pool if we're spawning
		 *	child threads. 
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
static void usage(int status)
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
			/* We can't really do anything intelligent here so just die */
			exit(1);
		case SIGTERM:
			do_exit = 1;
			break;
		default:
			do_exit = 2;
			break;
	}
}


/*
 *  We got the hangup signal.
 *  Re-read the configuration files.
 */
/*ARGSUSED*/
static void sig_hup(int sig)
{
	sig = sig; /* -Wunused */

	reset_signal(SIGHUP, sig_hup);

	/*
	 *  Only do the reload if we're the main server, both
	 *  for processes, and for threads.
	 */
	if (getpid() == radius_pid) {
		need_reload = TRUE;
	}
#ifdef WITH_SNMP
	if (mainconfig.do_snmp) {
		rad_snmp.smux_failures = 0;
		rad_snmp.smux_event = SMUX_CONNECT;
	}
#endif
}
