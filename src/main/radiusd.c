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
 * Copyright 2000,2001  The FreeRADIUS server project
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
#include "libradius.h"

#include <sys/socket.h>
#include <sys/file.h>

#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>

#if HAVE_UNISTD_H
#	include <unistd.h>
#endif

#include <signal.h>

#if HAVE_GETOPT_H
#	include <getopt.h>
#endif

#if HAVE_SYS_SELECT_H
#	include <sys/select.h>
#endif

#if HAVE_SYSLOG_H
#	include <syslog.h>
#endif

#if HAVE_SYS_WAIT_H
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

#ifdef WITH_SNMP
#	include "radius_snmp.h"
#endif

/*
 *  Global variables.
 */
const char *progname = NULL;
const char *radius_dir = NULL;
const char *radacct_dir = NULL;
const char *radlog_dir = NULL;
radlog_dest_t radlog_dest = RADLOG_FILES;
const char *radlib_dir = NULL;
int syslog_facility;
int log_stripped_names;
int debug_flag = 0;
int log_auth_detail = FALSE;
int auth_port = 0;
int acct_port;
int proxy_port;
int need_reload = FALSE;
int sig_hup_block = FALSE;
const char *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION ", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

static int got_child = FALSE;
static int authfd;
int acctfd;
int proxyfd;
static pid_t radius_pid;
static int request_num_counter = 0; /* per-request unique ID */

/*
 *  Configuration items.
 */
static int dont_fork = FALSE;
static int needs_child_cleanup = 0;
static time_t start_time = 0;
static int spawn_flag = TRUE;
static int do_exit = 0;


/*
 *	Static functions.
 */
static void usage(void);

static void sig_fatal (int);
static void sig_hup (int);
#ifdef HAVE_PTHREAD_H
static void sig_cleanup(int);
#endif

static void rfc_clean(RADIUS_PACKET *packet);
static void rad_reject(REQUEST *request);
static struct timeval *rad_clean_list(time_t curtime);
static REQUEST *rad_check_list(REQUEST *);
static REQUEST *proxy_check_list(REQUEST *request);
static int refresh_request(REQUEST *request, void *data);
#ifdef HAVE_PTHREAD_H
extern int rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#else
#ifdef ALLOW_CHILD_FORKS
static int rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#endif
#endif
static int rad_status_server(REQUEST *request);

/*
 *  Parse a string into a syslog facility level.
 */
static int str2fac(const char *s)
{
#ifdef LOG_KERN
	if(!strcmp(s, "kern"))
		return LOG_KERN;
	else
#endif
#ifdef LOG_USER
	if(!strcmp(s, "user"))
		return LOG_USER;
	else
#endif
#ifdef LOG_MAIL
	if(!strcmp(s, "mail"))
		return LOG_MAIL;
	else
#endif
#ifdef LOG_DAEMON
	if(!strcmp(s, "daemon"))
		return LOG_DAEMON;
	else
#endif
#ifdef LOG_AUTH
	if(!strcmp(s, "auth"))
		return LOG_AUTH;
	else
#endif
#ifdef LOG_SYSLOG
	if(!strcmp(s, "auth"))
		return LOG_AUTH;
	else
#endif
#ifdef LOG_LPR
	if(!strcmp(s, "lpr"))
		return LOG_LPR;
	else
#endif
#ifdef LOG_NEWS
	if(!strcmp(s, "news"))
		return LOG_NEWS;
	else
#endif
#ifdef LOG_UUCP
	if(!strcmp(s, "uucp"))
		return LOG_UUCP;
	else
#endif
#ifdef LOG_CRON
	if(!strcmp(s, "cron"))
		return LOG_CRON;
	else
#endif
#ifdef LOG_AUTHPRIV
	if(!strcmp(s, "authpriv"))
		return LOG_AUTHPRIV;
	else
#endif
#ifdef LOG_FTP
	if(!strcmp(s, "ftp"))
		return LOG_FTP;
	else
#endif
#ifdef LOG_LOCAL0
	if(!strcmp(s, "local0"))
		return LOG_LOCAL0;
	else
#endif
#ifdef LOG_LOCAL1
	if(!strcmp(s, "local1"))
		return LOG_LOCAL1;
	else
#endif
#ifdef LOG_LOCAL2
	if(!strcmp(s, "local2"))
		return LOG_LOCAL2;
	else
#endif
#ifdef LOG_LOCAL3
	if(!strcmp(s, "local3"))
		return LOG_LOCAL3;
	else
#endif
#ifdef LOG_LOCAL4
	if(!strcmp(s, "local4"))
		return LOG_LOCAL4;
	else
#endif
#ifdef LOG_LOCAL5
	if(!strcmp(s, "local5"))
		return LOG_LOCAL5;
	else
#endif
#ifdef LOG_LOCAL6
	if(!strcmp(s, "local6"))
		return LOG_LOCAL6;
	else
#endif
#ifdef LOG_LOCAL7
	if(!strcmp(s, "local7"))
		return LOG_LOCAL7;
	else
#endif
	{
		fprintf(stderr, "%s: Error: Unknown syslog facility: %s\n",
			progname, s);
		exit(1);
	}
	
	/* this should never be reached */
	return LOG_DAEMON;
}

int main(int argc, char *argv[])
{
	REQUEST *request;
	RADIUS_PACKET *packet;
	u_char *secret;
	unsigned char buffer[4096];
	struct sockaddr salocal;
	struct sockaddr_in *sa;
	fd_set readfds;
	int result;
	int argval;
	int pid;
	int i;
	int fd = 0;
	int max_fd;
	int status;
	int radius_port = 0;
	struct servent *svp;
	struct timeval *tv = NULL;
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

	syslog_facility = LOG_DAEMON;

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
				if (radacct_dir) xfree(radacct_dir);
				radacct_dir = strdup(optarg);
				break;
			
			case 'c':
				/* ignore for backwards compatibility with Cistron */
				break;

			case 'd':
				if (radius_dir) xfree(radius_dir);
				radius_dir = strdup(optarg);
				break;
			
			case 'f':
				dont_fork = TRUE;
				break;

			case 'h':
				usage();
				break;

			case 'i':
				if ((mainconfig.myip = ip_getaddr(optarg)) == INADDR_NONE) {
					fprintf(stderr, "radiusd: %s: host unknown\n",
						optarg);
					exit(1);
				}
				break;
			
			case 'l':
				radlog_dir = strdup(optarg);
				break;
			
				/*
				 *  We should also have this as a configuration
				 *  file directive.
				 */
			case 'g':
				syslog_facility = str2fac(optarg);
				break;

			case 'S':
				log_stripped_names++;
				break;

			case 'p':
				radius_port = atoi(optarg);
				break;

			case 's':	/* Single process mode */
				spawn_flag = FALSE;
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
				debug_flag = 2;
				mainconfig.log_auth = TRUE;
				mainconfig.log_auth_badpass = TRUE;
				mainconfig.log_auth_goodpass = TRUE;
				radlog_dir = strdup("stdout");
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
				usage();
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

#if HAVE_SYSLOG_H
	/*
	 *  If they asked for syslog, then give it to them.
	 *  Also, initialize the logging facility with the
	 *  configuration that they asked for.
	 */
	if (strcmp(radlog_dir, "syslog") == 0) {
		openlog(progname, LOG_PID, syslog_facility);
		radlog_dest = RADLOG_SYSLOG;
	}
	/* Do you want a warning if -g is used without a -l to activate it? */
#endif
	if (strcmp(radlog_dir, "stdout") == 0) {
		radlog_dest = RADLOG_STDOUT;
	} else if (strcmp(radlog_dir, "stderr") == 0) {
		radlog_dest = RADLOG_STDERR;
	}

	/*  Initialize the request list.  */
	rl_init();

	/*
	 *  We prefer (in order) the port from the command-line,
	 *  then the port from the configuration file, then
	 *  the port that the system names "radius", then
	 *  1645.
	 */
	if (radius_port != 0) {
		auth_port = radius_port;
	} /* else auth_port is set from the config file */
	
	/*
	 *  Maybe auth_port *wasn't* set from the config file,
	 *  or the config file set it to zero.
	 */
	acct_port = 0;
	if (auth_port == 0) {
		svp = getservbyname ("radius", "udp");
		if (svp != NULL) {
			auth_port = ntohs(svp->s_port);

			/*
			 *  We're getting auth_port from
			 *  /etc/services, get acct_port from
			 *  there, too.
			 */
			svp = getservbyname ("radacct", "udp");
			if (svp != NULL) 
				acct_port = ntohs(svp->s_port);
		} else {
			auth_port = PW_AUTH_UDP_PORT;
		}
	}

	/*
	 *  Open Authentication socket.
	 *
	 */
	authfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (authfd < 0) {
		perror("auth socket");
		exit(1);
	}

	sa = (struct sockaddr_in *) &salocal;
	memset ((char *) sa, '\0', sizeof(salocal));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = mainconfig.myip;
	sa->sin_port = htons(auth_port);

	result = bind (authfd, &salocal, sizeof(*sa));
	if (result < 0) {
		perror ("auth bind");
		DEBUG("  There appears to be another RADIUS server already running on the authentication port UDP %d.", auth_port);
		exit(1);
	}

	/*
	 *  Open Accounting Socket.
	 *
	 *  If we haven't already gotten acct_port from /etc/services,
	 *  then make it auth_port + 1.
	 */
	if (acct_port == 0) 
		acct_port = auth_port + 1;
	
	acctfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (acctfd < 0) {
		perror ("acct socket");
		exit(1);
	}

	sa = (struct sockaddr_in *) &salocal;
	memset ((char *) sa, '\0', sizeof(salocal));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = mainconfig.myip;
	sa->sin_port = htons(acct_port);

	result = bind (acctfd, & salocal, sizeof(*sa));
	if (result < 0) {
		perror ("acct bind");
		DEBUG("  There appears to be another RADIUS server already running on the accounting port UDP %d.", acct_port);
		exit(1);
	}

	/*
	 *  If we're proxying requests, open the proxy FD.
	 *  Otherwise, don't do anything.
	 */
	if (mainconfig.proxy_requests == TRUE) {
		/*
		 *  Open Proxy Socket.
		 */
		proxyfd = socket (AF_INET, SOCK_DGRAM, 0);
		if (proxyfd < 0) {
			perror ("proxy socket");
			exit(1);
		}
		
		sa = (struct sockaddr_in *) &salocal;
		memset((char *) sa, '\0', sizeof(salocal));
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = mainconfig.myip;
		
		/*
		 *  Set the proxy port to be one more than the
		 *  accounting port.
		 */
		for (proxy_port = acct_port + 1; proxy_port < 64000; proxy_port++) {
			sa->sin_port = htons(proxy_port);
			result = bind(proxyfd, & salocal, sizeof(*sa));
			if (result == 0) {
				break;
			}
		}
		
		/*
		 *  Couldn't find a port to which we could bind.
		 */
		if (proxy_port == 64000) {
			perror("proxy bind");
			exit(1);
		}

	} else {
		/*
		 *  NOT proxying requests, set the FD to a bad value.
		 */
		proxyfd = -1;
		proxy_port = 0;
	}

	/*
	 *  Register built-in compare functions.
	 */
	pair_builtincompare_init();

#ifdef WITH_SNMP
	if (mainconfig.do_snmp) radius_snmp_init();
#endif

	/*
	 *  Disconnect from session
	 */
	if (debug_flag == 0 && dont_fork == 0) {
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
#if HAVE_SETSID
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
	if (debug_flag == FALSE) {
		int devnull;
		
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			radlog(L_ERR|L_CONS, "Failed opening /dev/null: %s\n",
			       strerror(errno));
			exit(1);
		}
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		close(devnull);
	}

#if HAVE_PTHREAD_H
	/*
	 *  If we're spawning children, set up the thread pool.
	 */
	if (spawn_flag == TRUE) {
		thread_pool_init();
	}

	rad_exec_init();
#else
	/*
	 *	Without threads, we ALWAYS run in single-server mode.
	 */
	spawn_flag = FALSE;
#endif

	/*
	 *  Use linebuffered or unbuffered stdout if
	 *  the debug flag is on.
	 */
	if (debug_flag == TRUE) 
		setlinebuf(stdout);

	if (mainconfig.myip == INADDR_ANY) {
		strcpy((char *)buffer, "*");
	} else {
		ip_ntoa((char *)buffer, mainconfig.myip);
	}

	if (mainconfig.proxy_requests == TRUE) {
		radlog(L_INFO, "Listening on IP address %s, ports %d/udp and %d/udp, with proxy on %d/udp.",
				buffer, auth_port, acct_port, proxy_port);
	} else {
		radlog(L_INFO, "Listening on IP address %s, ports %d/udp and %d/udp.",
				buffer, auth_port, acct_port);
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

#ifdef HAVE_PTHREAD_H
	/*
	 *	If we have pthreads, then the child threads block
	 *	SIGCHLD, and the main server thread catches it.
	 *
	 *	That way, the SIGCHLD handler can grab the exit status,
	 *	and save it for the child thread.
	 *
	 *	If we don't have pthreads, then each child process
	 *	will do a waitpid(), and we ignore SIGCHLD.
	 *
	 *	Once we have multiple child processes to handle
	 *	requests, and shared memory, then we've got to
	 *	re-enable SIGCHLD catching.
	 */
#ifdef HAVE_SIGACTION
	act.sa_handler = sig_cleanup;
	sigaction(SIGCHLD, &act, NULL);
#else
	signal(SIGCHLD, sig_cleanup);
#endif
#endif

	radlog(L_INFO, "Ready to process requests.");
	start_time = time(NULL);

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
		        int max_wait = 0;
		        for(;;) {
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
		if (authfd >= 0) {
			FD_SET(authfd, &readfds);
			if (authfd > max_fd) max_fd = authfd;
		}
		if (acctfd >= 0) {
			FD_SET(acctfd, &readfds);
			if (acctfd > max_fd) max_fd = acctfd;
		}
		if (proxyfd >= 0) {
			FD_SET(proxyfd, &readfds);
			if (proxyfd > max_fd) max_fd = proxyfd;
		}
#ifdef WITH_SNMP
		if (mainconfig.do_snmp &&
		    (rad_snmp.smux_fd >= 0)) {
			FD_SET(rad_snmp.smux_fd, &readfds);
			if (rad_snmp.smux_fd > max_fd) max_fd = rad_snmp.smux_fd;
		}
#endif

		status = select(max_fd + 1, &readfds, NULL, NULL, tv);
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

		if (status == -1) {
			/*
			 *	On interrupts, we clean up the request
			 *	list.  We then continue with the loop,
			 *	so that if we're supposed to exit,
			 *	then the code at the start of the loop
			 *	catches that, and exits.
			 */
			if (errno == EINTR) {
				tv = rad_clean_list(time(NULL));
				continue;
			}
			radlog(L_ERR, "Unexpected error in select(): %s",
					strerror(errno));
			exit(1);
		}

		/*
		 *  Loop over the open socket FD's, reading any data.
		 */
		for (i = 0; i < 3; i++) {

			if (i == 0) fd = authfd;
			if (i == 1) fd = acctfd;
			if (i == 2) fd = proxyfd;
			if (fd < 0 || !FD_ISSET(fd, &readfds))
				continue;
			/*
			 *  Receive the packet.
			 */
			if (sig_hup_block != FALSE) {
			  continue;
			}
			packet = rad_recv(fd);
			if (packet == NULL) {
				radlog(L_ERR, "%s", librad_errstr);
				continue;
			}
#ifdef WITH_SNMP
			if (mainconfig.do_snmp) {
				if (fd == acctfd)
					rad_snmp.acct.total_requests++;
				if (fd == authfd)
					rad_snmp.auth.total_requests++;
			}
#endif

			/*
			 *  Check if we know this client for
			 *  authfd and acctfd.  Check if we know
			 *  this proxy for proxyfd.
			 */
			if (fd != proxyfd) {
				RADCLIENT *cl;
				if ((cl = client_find(packet->src_ipaddr)) == NULL) {
					radlog(L_ERR, "Ignoring request from unknown client %s:%d",
					ip_ntoa((char *)buffer, packet->src_ipaddr),
					packet->src_port);
					rad_free(&packet);
					continue;
				} else {
					secret = cl->secret;
				}
				
			} else {    /* It came in on the proxy port */
				REALM *rl;
				if ((rl = realm_findbyaddr(packet->src_ipaddr,packet->src_port)) == NULL) {
					radlog(L_ERR, "Ignoring request from unknown home server %s:%d",
					ip_ntoa((char *)buffer, packet->src_ipaddr),
					packet->src_port);
					rad_free(&packet);
					continue;
				} else {
					secret = rl->secret;
				}
			}

			/*
			 *  Do yet another check, to see if the
			 *  packet code is valid.  We only understand
			 *  a few, so stripping off obviously invalid
			 *  packets here will make our life easier.
			 */
			if (packet->code > PW_STATUS_SERVER) {
				radlog(L_ERR, "Ignoring request from client %s:%d with unknown code %d",
				       ip_ntoa((char *)buffer, packet->src_ipaddr),
				       packet->src_port, packet->code);
				rad_free(&packet);
				continue;
			}

			/*
			 *	Get the new request, and process it.
			 */
			request = request_alloc();
			request->packet = packet;
			request->number = request_num_counter++;
			strNcpy(request->secret, (char *)secret, sizeof(request->secret));
			rad_process(request, spawn_flag);
		} /* loop over authfd, acctfd, proxyfd */

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
		tv = rad_clean_list(time(NULL));

	} /* loop forever */
}


/*
 *  Process supported requests:
 *
 *  	PW_AUTHENTICATION_REQUEST - Authentication request from
 *  	 a client network access server.
 *
 *  	PW_ACCOUNTING_REQUEST - Accounting request from
 *  	 a client network access server.
 *
 *  	PW_AUTHENTICATION_ACK
 *  	PW_ACCESS_CHALLENGE
 *  	PW_AUTHENTICATION_REJECT
 *  	PW_ACCOUNTING_RESPONSE - Reply from a remote Radius server.
 *  	 Relay reply back to original NAS.
 *
 */
int rad_process(REQUEST *request, int dospawn)
{
	RAD_REQUEST_FUNP fun;

	fun = NULL;

	rad_assert(request->magic == REQUEST_MAGIC);

	switch(request->packet->code) {
		default:
			radlog(L_ERR, "Unknown packet type %d from client %s:%d "
					"- ID %d : IGNORED", request->packet->code, 
					client_name(request->packet->src_ipaddr), request->packet->src_port,
					request->packet->id); 
			request_free(&request);
			return -1;
			break;

		case PW_AUTHENTICATION_REQUEST:
			/*
			 *  Check for requests sent to the wrong port,
			 *  and ignore them, if so.
			 */
			if (request->packet->sockfd != authfd) {
				radlog(L_ERR, "Authentication-Request sent to a non-authentication port from "
					"client %s:%d - ID %d : IGNORED",
					client_name(request->packet->src_ipaddr), request->packet->src_port,
				request->packet->id);
				request_free(&request);
				return -1;
			}
			fun = rad_authenticate;
			break;

		case PW_ACCOUNTING_REQUEST:
			/*
			 *  Check for requests sent to the wrong port,
			 *  and ignore them, if so.
			 */
			if (request->packet->sockfd != acctfd) {
				radlog(L_ERR, "Accounting-Request packet sent to a non-accounting port from "
					"client %s:%d - ID %d : IGNORED",
					client_name(request->packet->src_ipaddr), request->packet->src_port,
					request->packet->id);
				request_free(&request);
				return -1;
			}
			fun = rad_accounting;
			break;

		case PW_AUTHENTICATION_ACK:
		case PW_ACCESS_CHALLENGE:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCOUNTING_RESPONSE:
			/*
			 *  Replies NOT sent to the proxy port get an
			 *  error message logged, and the packet is
			 *  dropped.
			 */
			if (request->packet->sockfd != proxyfd) {
				radlog(L_ERR, "Reply packet code %d sent to a non-proxy reply port from "
						"client %s:%d - ID %d : IGNORED", request->packet->code,
						client_name(request->packet->src_ipaddr), request->packet->src_port,
						request->packet->id);
				request_free(&request);
				return -1;
			}
			if (request->packet->code != PW_ACCOUNTING_RESPONSE) {
				fun = rad_authenticate;
			} else {
				fun = rad_accounting;
			}
			break;

		case PW_STATUS_SERVER:
			if (!mainconfig.status_server) {
				DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
				request_free(&request);
				return -1;
			} else {
				fun = rad_status_server;
			}
			break;

		case PW_PASSWORD_REQUEST:
			/*
			 *  We don't support this anymore.
			 */
			radlog(L_ERR, "Deprecated password change request from client %s:%d - ID %d : IGNORED",
					client_name(request->packet->src_ipaddr), request->packet->src_port,
					request->packet->id);
			request_free(&request);
			return -1;
			break;
	}

	/*
	 *  Check for a duplicate, or error.
	 *  Throw away the the request if so.
	 */
	request = rad_check_list(request);
	if (request == NULL) {
		return 0;
	}
	
	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *  This next assertion catches a race condition in the
	 *  server.  If it core dumps here, then it means that
	 *  the code WOULD HAVE core dumped elsewhere, but in
	 *  some random, unpredictable location.
	 *
	 *  Having the assert here means that we can catch the problem
	 *  in a well-known manner, until such time as we fix it.
	 */
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

	/*
	 *  The request passes many of our sanity checks.  From
	 *  here on in, if anything goes wrong, we send a reject
	 *  message, instead of dropping the packet.
	 *
	 *  Build the reply template from the request template.
	 */
	if (!request->reply) {
		if ((request->reply = rad_alloc(0)) == NULL) {
			radlog(L_ERR, "No memory");
			exit(1);
		}
		request->reply->sockfd = request->packet->sockfd;
		request->reply->dst_ipaddr = request->packet->src_ipaddr;
		request->reply->dst_port = request->packet->src_port;
		request->reply->id = request->packet->id;
		request->reply->code = 0; /* UNKNOWN code */
		memcpy(request->reply->vector, request->packet->vector, sizeof(request->reply->vector));
		request->reply->vps = NULL;
		request->reply->data = NULL;
		request->reply->data_len = 0;
	}

	/*
	 *	If we don't have threads, then the child CANNOT save
	 *	it's state in the memory used by the main server core.
	 *
	 *	That is, until someone goes and implements shared
	 *	memory across processes...
	 */
#ifdef HAVE_PTHREAD_H
	/*
	 *  If we're spawning a child thread, let it do all of
	 *  the work of handling a request, and exit.
	 */
	if (dospawn == TRUE) {
		/*
		 *  Maybe the spawn failed.  If so, then we
		 *  trivially reject the request (because we can't
		 *  handle it), and return.
		 */
		if (rad_spawn_child(request, fun) < 0) {
			rad_reject(request);
			request->finished = TRUE;
		}
		return 0;
	}
#endif

	rad_respond(request, fun);
	return 0;
}

/*
 *  Reject a request, by sending a trivial reply packet.
 */
static void rad_reject(REQUEST *request)
{
	VALUE_PAIR *vps;
	
	DEBUG2("Server rejecting request %d.", request->number);
	switch (request->packet->code) {
		/*
		 *  Accounting requests, etc. get dropped on the floor.
		 */
		default:
		case PW_ACCOUNTING_REQUEST:
		case PW_STATUS_SERVER:
			break;

		/*
		 *  Authentication requests get their Proxy-State
		 *  attributes copied over, and an otherwise blank
		 *  reject message sent.
		 */
		case PW_AUTHENTICATION_REQUEST:
			request->reply->code = PW_AUTHENTICATION_REJECT; 

			/*
			 *  Perform RFC limitations on outgoing replies.
			 */
			rfc_clean(request->reply);

			/*
			 *  Need to copy Proxy-State from request->packet->vps
			 */
			vps = paircopy2(request->packet->vps, PW_PROXY_STATE);
			if (vps != NULL)
				pairadd(&(request->reply->vps), vps);
			break;
	}
	
	/*
	 *  If a reply exists, send it.
	 */
	if (request->reply->code != 0) {
		/*
		 *	If we're not delaying authentication rejects,
		 *	then send the response immediately.  Otherwise,
		 *	mark the request as delayed, and do NOT send a
		 *	response.
		 */
		if (mainconfig.reject_delay == 0) {
			rad_send(request->reply, request->packet,
				 request->secret);
		} else {
			request->options |= RAD_REQUEST_OPTION_DELAYED_REJECT;
		}
	}
}

/*
 *  Perform any RFC specified cleaning of outgoing replies
 */
static void rfc_clean(RADIUS_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;

	switch (packet->code) {
		/*
		 *	In the default case, we just move all of the
		 *	attributes over.
		 */
	default:
		vps = packet->vps;
		packet->vps = NULL;
		break;
		
		/*
		 *	Accounting responses can only contain
		 *	Proxy-State and VSA's.  Note that we do NOT
		 *	move the Proxy-State attributes over, as the
		 *	Proxy-State attributes in this packet are NOT
		 *	the right ones to use.  The reply function
		 *	takes care of copying those attributes from
		 *	the original request, which ARE the right ones
		 *	to use.
		 */
	case PW_ACCOUNTING_RESPONSE:
		pairmove2(&vps, &(packet->vps), PW_VENDOR_SPECIFIC);
		break;

		/*
		 *	Authentication REJECT's can have only
		 *	EAP-Message, Message-Authenticator
		 *	Reply-Message and Proxy-State.
		 *
		 *	We delete everything other than these.
		 *	Proxy-State is added below, just before the
		 *	reply is sent.
		 */
	case PW_AUTHENTICATION_REJECT:
		pairmove2(&vps, &(packet->vps), PW_EAP_MESSAGE);
		pairmove2(&vps, &(packet->vps), PW_MESSAGE_AUTHENTICATOR);
		pairmove2(&vps, &(packet->vps), PW_REPLY_MESSAGE);
		pairmove2(&vps, &(packet->vps), PW_VENDOR_SPECIFIC);
		break;
	}

	/*
	 *	Move the newly cleaned attributes over.
	 */
	pairfree(&packet->vps);
	packet->vps = vps;

	/*
	 *	FIXME: Perform other, more generic sanity checks.
	 */
}

/* 
 * FIXME:  The next two functions should all
 * be in a module.  But not until we have
 * more control over module execution.
 * -jcarneal
 */

/*
 *  Lowercase the string value of a pair.
 */
static int rad_lowerpair(REQUEST *request, VALUE_PAIR *vp) {
	if (vp == NULL) {
		return -1;
	}

	rad_lowercase((char *)vp->strvalue);
	DEBUG2("rad_lowerpair:  %s now '%s'", vp->name, vp->strvalue);
	return 0;
}

/*
 *  Remove spaces in a pair.
 */
static int rad_rmspace_pair(REQUEST *request, VALUE_PAIR *vp) {
	if (vp == NULL) {
		return -1;
	}
	
	rad_rmspace((char *)vp->strvalue);
	vp->length = strlen((char *)vp->strvalue);
	DEBUG2("rad_rmspace_pair:  %s now '%s'", vp->name, vp->strvalue);
	
	return 0;
}

/*
 *  Respond to a request packet.
 *
 *  Maybe we reply, maybe we don't.
 *  Maybe we proxy the request to another server, or else maybe
 *  we replicate it to another server.
 */
int rad_respond(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	RADIUS_PACKET *packet, *original;
	const char *secret;
	int finished = FALSE;
	int reprocess = 0;
	
	/*
	 *  Put the decoded packet into it's proper place.
	 */
	if (request->proxy_reply != NULL) {
		packet = request->proxy_reply;
		secret = request->proxysecret;
		original = request->proxy;
	} else {
		packet = request->packet;
		secret = request->secret;
		original = NULL;
	}

	rad_assert(request->magic == REQUEST_MAGIC);
	
	/*
	 *  Decode the packet, verifying it's signature,
	 *  and parsing the attributes into structures.
	 *
	 *  Note that we do this CPU-intensive work in
	 *  a child thread, not the master.  This helps to
	 *  spread the load a little bit.
	 *
	 *  Internal requests (ones that never go on the
	 *  wire) have ->data==NULL (data is the wire
	 *  format) and don't need to be "decoded"
	 */
	if (packet->data && rad_decode(packet, original, secret) != 0) {
		radlog(L_ERR, "%s", librad_errstr);
		rad_reject(request);
		goto finished_request;
	}
	
	/*
	 *  For proxy replies, remove non-allowed
	 *  attributes from the list of VP's.
	 */
	if (request->proxy) {
            int rcode;
            rcode = proxy_receive(request);
            switch (rcode) {
                default:  /* Don't Do Anything */
                    break;
                case RLM_MODULE_FAIL:
                    /* on error just continue with next request */
                    goto next_request;
                case RLM_MODULE_HANDLED:
                    /* if this was a replicated request, mark it as
                     * finished first, because it was postponed
                     */
                    goto finished_request;
            }

	} else {
		/*
		 *	This is the initial incoming request which
		 *	we're processing.
		 *
		 *	Some requests do NOT get cached, as they
		 *	CANNOT possibly have duplicates.  Set the
		 *	magic option here.
		 *
		 *	Status-Server messages are easy to generate,
		 *	so we toss them as soon as we see a reply.
		 *
		 *	Accounting-Request packets WITHOUT an
		 *	Acct-Delay-Time attribute are NEVER
		 *	duplicated, as RFC 2866 Section 4.1 says that
		 *	the Acct-Delay-Time MUST be updated when the
		 *	packet is re-sent, which means the packet
		 *	changes, so it MUST have a new identifier and
		 *	Request Authenticator.  */
		if ((request->packet->code == PW_STATUS_SERVER) ||
		    ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
		     (pairfind(request->packet->vps, PW_ACCT_DELAY_TIME) == NULL))) {
			request->options |= RAD_REQUEST_OPTION_DONT_CACHE;
		}
	}
	
	/*
	 *  We should have a User-Name attribute now.
	 */
	if (request->username == NULL) {
		request->username = pairfind(request->packet->vps,
				PW_USER_NAME);
	}

	/*
	 *  We have the semaphore, and have decoded the packet.
	 *  Let's process the request.
	 */
	rad_assert(request->magic == REQUEST_MAGIC);

	/* 
	 *  FIXME:  All this lowercase/nospace junk will be moved
	 *  into a module after module failover is fully in place
	 *
	 *  See if we have to lower user/pass before processing
	 */
	if(strcmp(mainconfig.do_lower_user, "before") == 0)
		rad_lowerpair(request, request->username);
	if(strcmp(mainconfig.do_lower_pass, "before") == 0)
		rad_lowerpair(request,
			      pairfind(request->packet->vps, PW_PASSWORD));

	if(strcmp(mainconfig.do_nospace_user, "before") == 0)
		rad_rmspace_pair(request, request->username);
	if(strcmp(mainconfig.do_nospace_pass, "before") == 0)
		rad_rmspace_pair(request,
				 pairfind(request->packet->vps, PW_PASSWORD));

	(*fun)(request);

	/*
	 *  Reprocess if we rejected last time
	 */
	if ((fun == rad_authenticate) &&
	    (request->reply->code == PW_AUTHENTICATION_REJECT)) {
	  /* See if we have to lower user/pass after processing */
	  if (strcmp(mainconfig.do_lower_user, "after") == 0) {
		  rad_lowerpair(request, request->username);
		  reprocess = 1;
	  }
	  if (strcmp(mainconfig.do_lower_pass, "after") == 0) {
		rad_lowerpair(request,
			      pairfind(request->packet->vps, PW_PASSWORD));
		reprocess = 1;
	  }
	  if (strcmp(mainconfig.do_nospace_user, "after") == 0) {
		  rad_rmspace_pair(request, request->username);
		  reprocess = 1;
	  }
	  if (strcmp(mainconfig.do_nospace_pass, "after") == 0) {
		  rad_rmspace_pair(request,
				   pairfind(request->packet->vps, PW_PASSWORD));

		  reprocess = 1;
	  }
	  
	  /*
	   *	If we're re-processing the request, re-set it.
	   */
	  if (reprocess) {
		  pairfree(&request->config_items);
		  pairfree(&request->reply->vps);
		  request->reply->code = 0;
		  (*fun)(request);
	  }
	}
	
	/*
	 *  If we don't already have a proxy packet for this request,
	 *  we MIGHT have to go proxy it.
	 *
	 *  Status-Server requests NEVER get proxied.
	 */
	if (mainconfig.proxy_requests) {
		if ((request->proxy == NULL) &&
		    (request->packet->code != PW_STATUS_SERVER)) {
			int rcode;

			/*
			 *  Try to proxy this request.
			 */
			rcode = proxy_send(request);

			switch (rcode) {
			default:
				break;
				
			/*
			 *  There was an error trying to proxy the request.
			 *  Drop it on the floor.
			 */
			case RLM_MODULE_FAIL:
				DEBUG2("Error trying to proxy request %d: Rejecting it", request->number);
				rad_reject(request);
				goto finished_request;
				break;

			/*
			 *  The pre-proxy module has decided to reject
			 *  the request.  Do so.
			 */
			case RLM_MODULE_REJECT:
				DEBUG2("Request %d rejected in proxy_send.", request->number);
				rad_reject(request);
				goto finished_request;
				break;
				
			/*
			 *  If the proxy code has handled the request,
			 *  then postpone more processing, until we get
			 *  the reply packet from the home server.
			 */
			case RLM_MODULE_HANDLED:
				/*
				 *  rad_send??
				 */
				goto postpone_request;
				break;
			}

			/*
			 *  Else rcode==RLM_MODULE_NOOP
			 *  and the proxy code didn't do anything, so
			 *  we continue handling the request here.
			 */
		}
	} else if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
		   (request->reply->code == 0)) {
		/*
		 *  We're not configured to reply to the packet,
		 *  and we're not proxying, so the DEFAULT behaviour
		 *  is to REJECT the user.
		 */
		DEBUG2("There was no response configured: rejecting request %d", request->number);
		rad_reject(request);
		goto finished_request;
	}

	/*
	 *  If we have a reply to send, copy the Proxy-State
	 *  attributes from the request to the tail of the reply,
	 *  and send the packet.
	 */
	rad_assert(request->magic == REQUEST_MAGIC);
	if (request->reply->code != 0) {
		VALUE_PAIR *vp = NULL;

		/*
		 *  Perform RFC limitations on outgoing replies.
		 */
		rfc_clean(request->reply);

		/*
		 *  Need to copy Proxy-State from request->packet->vps
		 */
		vp = paircopy2(request->packet->vps, PW_PROXY_STATE);
		if (vp != NULL) 
			pairadd(&(request->reply->vps), vp);

		/*
		 *  If the request isn't an authentication reject, OR
		 *  it's a reject, but the reject_delay is zero, then
		 *  send it immediately.
		 *
		 *  Otherwise, delay the authentication reject to shut
		 *  up DoS attacks.
		 */
		if ((request->reply->code != PW_AUTHENTICATION_REJECT) ||
		    (mainconfig.reject_delay == 0)) {
			rad_send(request->reply, request->packet,
				 request->secret);
		} else {
			DEBUG2("Delaying request %d for %d seconds",
			       request->number, mainconfig.reject_delay);
			request->options |= RAD_REQUEST_OPTION_DELAYED_REJECT;
		}
	}

	/*
	 *  We're done processing the request, set the
	 *  request to be finished, clean up as necessary,
	 *  and forget about the request.
	 */

finished_request:

	/*
	 *  We're done handling the request.  Free up the linked
	 *  lists of value pairs.  This might take a long time,
	 *  so it's more efficient to do it in a child thread,
	 *  instead of in the main handler when it eventually
	 *  gets around to deleting the request.
	 *
	 *  Also, no one should be using these items after the
	 *  request is finished, and the reply is sent.  Cleaning
	 *  them up here ensures that they're not being used again.
	 *
	 *  Hmm... cleaning them up in the child thread also seems
	 *  to make the server run more efficiently!
	 *
	 *  If we've delayed the REJECT, then do NOT clean up the request,
	 *  as we haven't created the REJECT message yet.
	 */
	if ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) == 0) {
		if (request->packet) {
			pairfree(&request->packet->vps);
			request->username = NULL;
			request->password = NULL;
		}

		/*
		 *  If we've sent a reply to the NAS, then this request is
		 *  pretty much finished, and we have no more need for any
		 *  of the value-pair's in it, including the proxy stuff.
		 */
		if (request->reply->code != 0) {
			pairfree(&request->reply->vps);
		}
	}

	pairfree(&request->config_items);
	if (request->proxy) {
		pairfree(&request->proxy->vps);
	}
	if (request->proxy_reply) {
		pairfree(&request->proxy_reply->vps);
	}

	DEBUG2("Finished request %d", request->number);
	finished = TRUE;

	/*
	 *  Go to the next request, without marking
	 *  the current one as finished.
	 *
	 *  Hmm... this may not be the brightest thing to do.
	 */
next_request:
	DEBUG2("Going to the next request");

postpone_request:
#if HAVE_PTHREAD_H
	/*
	 *  We are finished with the child thread.  The thread is detached,
	 *  so that when it exits, there's nothing more for the server
	 *  to do.
	 *
	 *  If we're running with thread pools, then this frees up the
	 *  thread in the pool for another request.
	 */
	request->child_pid = NO_SUCH_CHILD_PID;
#endif
	request->finished = finished; /* do as the LAST thing before exiting */
	return 0;
}

typedef struct rad_walk_t {
	time_t	now;
	time_t	smallest;
} rad_walk_t;

/*
 *  Clean up the request list, every so often.
 *
 *  This is done by walking through ALL of the list, and
 *  - marking any requests which are finished, and expired
 *  - killing any processes which are NOT finished after a delay
 *  - deleting any marked requests.
 */
static REQUEST *last_request = NULL;
static struct timeval *rad_clean_list(time_t now)
{
	/*
	 *  Static variables, so that we don't do all of this work
	 *  more than once per second.
	 *
	 *  Note that we have 'tv' and 'last_tv'.  'last_tv' is
	 *  pointed to by 'last_tv_ptr', and depending on the
	 *  system implementation of select(), it MAY be modified.
	 *
	 *  In that was, we want to use the ORIGINAL value, from
	 *  'tv', and wipe out the (possibly modified) last_tv.
	 */
	static time_t last_cleaned_list = 0;
	static struct timeval tv, *last_tv_ptr = NULL;
	static struct timeval last_tv;

	rad_walk_t info;

	info.now = now;
	info.smallest = -1;

	/*
	 *  If we've already set up the timeout or cleaned the
	 *  request list this second, then don't do it again.  We
	 *  simply return the sleep delay from last time.
	 *
	 *  Note that if we returned NULL last time, there was nothing
	 *  to do.  BUT we've been woken up since then, which can only
	 *  happen if we received a packet.  And if we've received a
	 *  packet, then there's some work to do in the future.
	 *
	 *  FIXME: We can probably use gettimeofday() for finer clock
	 *  resolution, as the current method will cause it to sleep
	 *  too long...
	 */
	if ((last_tv_ptr != NULL) &&
			(last_cleaned_list == now) &&
			(tv.tv_sec != 0)) {		
		int i;

		/*
		 *  If we're NOT walking the entire request list,
		 *  then we want to iteratively check the request
		 *  list.
		 *
		 *  If there is NO previous request, go look for one.
		 */
		if (!last_request) 
			last_request = rl_next(last_request);

		/*
		 *  On average, there will be one request per
		 *  'cleanup_delay' requests, which needs to be
		 *  serviced.
		 *
		 *  And only do this servicing, if we have a request
		 *  to service.
		 */
		if (last_request) 
			for (i = 0; i < mainconfig.cleanup_delay; i++) {
				REQUEST *next;
			
				/*
				 *  This function call MAY delete the
				 *  request pointed to by 'last_request'.
				 */
				next = rl_next(last_request);
				refresh_request(last_request, &info);
				last_request = next;

				/*
				 *  Nothing to do any more, exit.
				 */
				if (!last_request) 
					break;
			}

		last_tv = tv;
		DEBUG2("Waking up in %d seconds...",
				(int) last_tv_ptr->tv_sec);
		return last_tv_ptr;
	}
	last_cleaned_list = now;
	last_request = NULL;
	DEBUG2("--- Walking the entire request list ---");

#if HAVE_PTHREAD_H
	/*
	 *  Only clean the thread pool if we've spawned child threads.
	 */
	if (spawn_flag) {
		thread_pool_clean(now);
	}
#endif
	
	/*
	 *  Hmmm... this is Big Magic.  We make it seem like
	 *  there's an additional second to wait, for a whole
	 *  host of reasons which I can't explain adequately,
	 *  but which cause the code to Just Work Right.
	 */
	info.now--;

	rl_walk(refresh_request, &info);

	/*
	 *  We haven't found a time at which we need to wake up.
	 *  Return NULL, so that the select() call will sleep forever.
	 */
	if (info.smallest < 0) {
		/*
		 *  If we're not proxying, then there really isn't anything
		 *  to do.
		 *
		 *  If we ARE proxying, then we can safely sleep
		 *  forever if we're told to NEVER send proxy retries
		 *  ourselves, until the NAS kicks us again.
		 * 
		 *  Otherwise, there are no outstanding requests, then
		 *  we can sleep forever.  This happens when we get
		 *  woken up with a bad packet.  It's discarded, so if
		 *  there are no live requests, we can safely sleep
		 *  forever.
		 */
		if ((!mainconfig.proxy_requests) ||
		    mainconfig.proxy_synchronous ||
		    (rl_num_requests() == 0)) {
			DEBUG2("Nothing to do.  Sleeping until we see a request.");
			last_tv_ptr = NULL;
			return NULL;
		}

		/*
		 *  We ARE proxying.  In that case, we avoid a race condition
		 *  where a child thread handling a request proxies the
		 *  packet, and sets the retry delay.  In that case, we're
		 *  supposed to wake up in N seconds, but we can't, as
		 *  we're sleeping forever.
		 *
		 *  Instead, we prevent the problem by waking up anyhow
		 *  at the 'proxy_retry_delay' time, even if there's
		 *  nothing to do.  In the worst case, this will cause
		 *  the server to wake up every N seconds, to do a small
		 *  amount of unnecessary work.
		 */
		info.smallest = mainconfig.proxy_retry_delay;
	}
	/*
	 *  Set the time (in seconds) for how long we're
	 *  supposed to sleep.
	 */
	tv.tv_sec = info.smallest;
	tv.tv_usec = 0;
	DEBUG2("Waking up in %d seconds...", (int) info.smallest);

	/*
	 *  Remember how long we should sleep for.
	 */
	last_tv = tv;
	last_tv_ptr = &last_tv;
	return last_tv_ptr;
}

/*
 *  Walk through the request list, cleaning up completed child
 *  requests, and verifing that there is only one process
 *  responding to each request (duplicate requests are filtered
 *  out).
 *
 *  Also, check if the request is a reply from a request proxied to
 *  a remote server.  If so, play games with the request, and return
 *  the old one.
 */
static REQUEST *rad_check_list(REQUEST *request)
{
	REQUEST		*curreq;
	time_t		now;

	/*
	 *  If the request has come in on the proxy FD, then
	 *  it's a proxy reply, so pass it through the proxy
	 *  code for checking the REQUEST list.
	 */
	if (request->packet->sockfd == proxyfd) {
		return proxy_check_list(request);

		/*
		 *  If the request already has a proxy packet,
		 *  then it obviously is not a new request, either.
		 */
	} else if (request->proxy != NULL) {
		return request;
	}

	now = request->timestamp; /* good enough for our purposes */

	/*
	 *  Look for an existing copy of this request.
	 */
	curreq = rl_find(request);
	if (curreq != NULL) {
		/*
		 *	If the request (duplicate or now) is currently
		 *	being processed, then discard the new request.
		 */
		if (curreq->child_pid != NO_SUCH_CHILD_PID) {
			radlog(L_ERR, "Discarding new request from "
			       "client %s:%d - ID: %d due to live request %d",
			       client_name(curreq->packet->src_ipaddr),
			       curreq->packet->src_port, curreq->packet->id,
			       curreq->number);
			request_free(&request);
			return NULL;
		}

		/*
		 *	The current request isn't finished, which
		 *	means that the NAS sent us a new packet, while
		 *	we were waiting for a proxy response.
		 *
		 *	In that case, it doesn't matter if the vectors
		 *	are the same, as deleting the un-finished request
		 *	would mean that the (eventual) proxy response would
		 *	be associated with the wrong NAS request.
		 */
		if (!curreq->finished) {
			radlog(L_ERR, "Dropping conflicting packet from "
			       "client %s:%d - ID: %d due to unfinished request %d",
			       client_name(request->packet->src_ipaddr),
			       request->packet->src_port,
			       request->packet->id,
			       curreq->number);
			request_free(&request);
			return NULL;
		}

		/*
		 *	We now check the authentication vectors.  If
		 *	the client has sent us a request with
		 *	identical code && ID, but different vector,
		 *	then they MUST have gotten our response, so
		 *	we can delete the original request, and
		 *	process the new one.
		 *
		 *	If the vectors are the same, then it's a
		 *	duplicate request, and we can send a
		 *	duplicate reply.
		 */
		if (memcmp(curreq->packet->vector, request->packet->vector,
				sizeof(request->packet->vector)) == 0) {
			rad_assert(curreq->reply != NULL);

			/*
			 *	If the packet has been delayed, then
			 *	silently send a response, and clear the
			 *	delayed flag.
			 *
			 *	Note that this means if the NAS kicks
			 *	us while we're delaying a reject, then
			 *	the reject may be sent sooner than
			 *	otherwise.
			 *
			 *	This COULD be construed as a bug.
			 *	Maybe what we want to do is to ignore
			 *	the duplicate packet, and send the
			 *	reject later.
			 */
			if (curreq->options & RAD_REQUEST_OPTION_DELAYED_REJECT) {
				curreq->options &= ~RAD_REQUEST_OPTION_DELAYED_REJECT;
				rad_send(curreq->reply, curreq->packet, curreq->secret);
				request_free(&request);
				return NULL;
			}

			/*
			 *	Maybe we've saved a reply packet.  If
			 *	so, re-send it.  Otherwise, just
			 *	complain.
			 */
			if (curreq->reply->code != 0) {
				DEBUG2("Sending duplicate reply "
				       "to client %s:%d - ID: %d",
				       client_name(curreq->packet->src_ipaddr),
				       curreq->packet->src_port, curreq->packet->id);
				rad_send(curreq->reply, curreq->packet, curreq->secret);
				request_free(&request);
				return NULL;
			}

			/*
			 *	At this point, there isn't a live
			 *	thread handling the old request.  The
			 *	old request isn't finished, AND
			 *	there's no reply for it.
			 *
			 *	Therefore, we MUST be waiting for a reply
			 *	from the proxy.
			 *
			 *	If not, then it's an Accounting-Request
			 *	which we tried to "reject", which means
			 *	that we silently drop the response.
			 *      We want to give the same response for the
			 *      duplicate request, so we silently drop it,
			 *	too.
			 */
			if (!curreq->proxy) {
				radlog(L_ERR, "Dropping packet from client "
				       "%s:%d - ID: %d due to dead request %d",
				       client_name(request->packet->src_ipaddr),
				       request->packet->src_port,
				       request->packet->id,
				       curreq->number);
				request_free(&request);
				return NULL;
			}

			/*
			 *	If there IS a reply from the proxy,
			 *	then curreq SHOULD be marked alive, OR
			 *	there should have been a reply sent to
			 *	the NAS.  If none of these is true, then
			 *	we don't know what to do, so we drop the
			 *	request.
			 */
			if (curreq->proxy_reply) {
				radlog(L_ERR, "Dropping packet from client "
				       "%s:%d - ID: %d due to confused proxied request %d",
				       client_name(request->packet->src_ipaddr),
				       request->packet->src_port,
				       request->packet->id,
				       curreq->number);
				request_free(&request);
				return NULL;
			}

			/*
			 *	We're taking care of sending duplicate
			 *	proxied packets, so we ignore any duplicate
			 *	requests from the NAS.
			 */
			if (!mainconfig.proxy_synchronous) {
				DEBUG2("Ignoring duplicate packet from client "
				       "%s:%d - ID: %d, due to outstanding proxied request %d.",
				       client_name(request->packet->src_ipaddr),
				       request->packet->src_port,
				       request->packet->id,
				       curreq->number);
				
				request_free(&request);
				return NULL;
			}

			/*
			 *	We ARE proxying the request, and we
			 *	have NOT received a proxy reply yet,
			 *	and we ARE doing synchronous proxying.
			 *
			 *	In that case, go kick the home RADIUS
			 *	server again.
			 */
			{
				char buffer[32];

				DEBUG2("Sending duplicate proxied request to home server %s:%d - ID: %d",
				       ip_ntoa(buffer, curreq->proxy->dst_ipaddr),
				       curreq->proxy->dst_port,
									
				       curreq->proxy->id);
			}
			curreq->proxy_next_try = request->timestamp + mainconfig.proxy_retry_delay;
			rad_send(curreq->proxy, curreq->packet, curreq->proxysecret);
			request_free(&request);
			return NULL;
		} /* else the vectors were different. */

		/*
		 *	If we're keeping a delayed reject, and we
		 *	get a new request, then we discard the reject,
		 *	in order to not confuse the NAS with an old
		 *	response to a new request.
		 */
		
		/*
		 *	Fix up stuff.
		 */
		if (last_request == curreq) {
			last_request = rl_next(last_request);
		}

		rl_delete(curreq);
	} /* a similar packet already exists. */

	/*
	 *  Count the total number of requests, to see if there
	 *  are too many.  If so, return with an error.
	 */
	if (mainconfig.max_requests) {
		int request_count = rl_num_requests();
		
		/*
		 *  This is a new request.  Let's see if it
		 *  makes us go over our configured bounds.
		 */
		if (request_count > mainconfig.max_requests) {
			radlog(L_ERR, "Dropping request (%d is too many): "
					"from client %s:%d - ID: %d", request_count, 
					client_name(request->packet->src_ipaddr),
					request->packet->src_port,
					request->packet->id);
			radlog(L_INFO, "WARNING: Please check the radiusd.conf file.\n"
					"\tThe value for 'max_requests' is probably set too low.\n");
			request_free(&request);
			return NULL;
		}
	}

	/*
	 *  Add this request to the list
	 */
	rl_add(request);

	/*
	 *  And return the request to be handled.
	 */
	return request;
}

/*
 *  If we're using the thread pool, then the function in
 *  'threads.c' replaces this one.
 *
 *  This code is NOT well tested, and should NOT be used!
 *
 *  Note that ALLOW_CHILD_FORKS is never defined.  This code
 *  is here for historical purposes, so that if (or when) someone
 *  implements shared memory between processes, that we have a template
 *  of code to work from.
 */
#ifdef ALLOW_CHILD_FORKS
/*
 *  Spawns a child process or thread to perform
 *  authentication/accounting and respond to RADIUS clients.
 */
static int rad_spawn_child(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	child_pid_t		child_pid;
	int retval = 0;

	/* spawning and registering a child is a critical section, so
	 * we refuse to handle SIGCHLDs normally until we're finished. */
#ifdef HAVE_SIGACTION
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_flags = 0 ;
	sigemptyset( &act.sa_mask ) ;
	act.sa_handler = queue_sig_cleanup;
	sigaction(SIGCHLD, &act, NULL);
#else
	signal(SIGCHLD, queue_sig_cleanup);
#endif

	/*
	 *  fork our child
	 */
	child_pid = fork();
	if (child_pid < 0) {
		radlog(L_ERR, "Fork failed for request from client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);
		retval = -1;
		goto exit_child_critsec;
	}

	if (child_pid == 0) {

		/*
		 *  This is the child, it should go ahead and respond
		 */
		signal(SIGCHLD, SIG_DFL);
		rad_respond(request, fun);
		exit(0);
	}

	/*
	 *  Register the Child
	 */
	request->child_pid = child_pid;

exit_child_critsec:
#ifdef HAVE_SIGACTION
	act.sa_handler = sig_cleanup;
	sigaction(SIGCHLD, &act, NULL);
#else
	signal(SIGCHLD, sig_cleanup);
#endif
	if (needs_child_cleanup > 0) {
		sig_cleanup(0);
	}
	return retval;
}

static int sig_cleanup_walker(REQUEST *req, void *data)
{
	int pid = (int)data;
		if ( req->child_pid != pid ) {
			return RL_WALK_CONTINUE;
		}
	req->child_pid = NO_SUCH_CHILD_PID;
	req->finished = TRUE;
	return 0;
}

/* used in critical section */
void queue_sig_cleanup(int sig) {
	sig = sig; /* -Wunused */
	needs_child_cleanup++;
	return;
}
#endif /* ALLOW_CHILD_FORKS */


#ifdef HAVE_PTHREAD_H
static void sig_cleanup(int sig)
{
	int status;
	child_pid_t pid;
#ifdef ALLOW_CHILD_FORKS
	REQUEST *curreq;
#endif

	sig = sig; /* -Wunused */
 
	got_child = FALSE;

	needs_child_cleanup = 0;  /* reset the queued cleanup number */

	/*
	 *  Reset the signal handler, if required.
	 */
	reset_signal(SIGCHLD, sig_cleanup);
	
	/*
	 *	Wait for the child, without hanging.
	 */
	for (;;) {
		pid = (child_pid_t) waitpid((pid_t)-1, &status, WNOHANG);
		if ((int)pid <= 0)
			return;

		/*
		 *  Check to see if the child did a bad thing.
		 *  If so, kill ALL processes in the current
		 *  process group, to prevent further attacks.
		 */
		if (debug_flag && (WIFSIGNALED(status))) {
			radlog(L_ERR|L_CONS, "MASTER: Child PID %d failed to catch "
					"signal %d: killing all active servers.\n",
					(int)pid, WTERMSIG(status));
			kill(-radius_pid, SIGTERM);
			exit(1);
		}

		/*
		 *	If we have pthreads, then the only children
		 *	are from Exec-Program.  We don't care about them,
		 *	so once we've grabbed their PID's, we're done.
		 */
#ifdef HAVE_PTHREAD_H
		rad_savepid(pid, status);
#else
#ifdef ALLOW_CHILD_FORKS
		/*
		 *  Loop over ALL of the active requests, looking
		 *  for the one which caused the signal.
		 */
		if (rl_walk(sig_cleanup_walker, (void*)pid) != 0) {
			radlog(L_ERR, "Failed to cleanup child %d", pid);
		}
#endif
#endif /* !defined HAVE_PTHREAD_H */
	}
}
#endif /* HAVE_PTHREAD_H */

/*
 *  Display the syntax for starting this program.
 */
static void usage(void)
{
	fprintf(stderr,
			"Usage: %s [-a acct_dir] [-d db_dir] [-l log_dir] [-i address] [-p port] [-AcfnsSvXxyz]\n", progname);
	fprintf(stderr, "Options:\n\n");
	fprintf(stderr, "  -a acct_dir     use accounting directory 'acct_dir'.\n");
	fprintf(stderr, "  -A              Log auth detail.\n");
	fprintf(stderr, "  -d db_dir       Use database directory 'db_dir'.\n");
	fprintf(stderr, "  -f              Run as a foreground process, not a daemon.\n");
	fprintf(stderr, "  -h              Print this help message.\n");
	fprintf(stderr, "  -i address      Listen only in the given IP address.\n");
	fprintf(stderr, "  -l log_dir      Log messages to 'log_dir'.  Special values are:\n");
	fprintf(stderr, "                  stdout == log all messages to standard output.\n");
	fprintf(stderr, "                  syslog == log all messages to the system logger.\n");
	fprintf(stderr, "  -p port         Bind to 'port', and not to the radius/udp, or 1646/udp.\n");
	fprintf(stderr, "  -s              Do not spawn child processes to handle requests.\n");
	fprintf(stderr, "  -S              Log stripped names.\n");
	fprintf(stderr, "  -v              Print server version information.\n");
	fprintf(stderr, "  -X              Turn on full debugging. (Means: -sfxxyz -l stdout)\n");
	fprintf(stderr, "  -x              Turn on partial debugging. (-xx gives more debugging).\n");
	fprintf(stderr, "  -y              Log authentication failures, with password.\n");
	fprintf(stderr, "  -z              Log authentication successes, with password.\n");
	exit(1);
}


/*
 *	We got a fatal signal.
 */
static void sig_fatal(int sig)
{
	switch(sig) {
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

/*
 *  Do a proxy check of the REQUEST list when using the new proxy code.
 */
static REQUEST *proxy_check_list(REQUEST *request)
{
	REALM *cl;
	REQUEST *oldreq;
	char buffer[32];
	
	/*
	 *	Find the original request in the request list
	 */
	oldreq = rl_find_proxy(request);

	/*
	 *	If we haven't found the original request which was
	 *	sent, to get this reply.  Complain, and discard this
	 *	request, as there's no way for us to send it to a NAS.
	 */
	if (!oldreq) {
		radlog(L_PROXY, "No outstanding request was found for proxy reply from home server %s:%d - ID %d",
		       ip_ntoa(buffer, request->packet->src_ipaddr),
		       request->packet->src_port,
		       request->packet->id);
		request_free(&request);
		return NULL;
	}

	/*
	 *	If the request (duplicate or now) is currently
	 *	being processed, then discard the new request.
	 */
	if (oldreq->child_pid != NO_SUCH_CHILD_PID) {
		radlog(L_ERR, "Discarding duplicate reply from home server %s:%d - ID: %d due to live request %d",
		       ip_ntoa(buffer, request->packet->src_ipaddr),
		       request->packet->src_port,
		       request->packet->id,
		       oldreq->number);
		request_free(&request);
		return NULL;
	}
	
	/*
	 *	The proxy reply has arrived too late, as the original
	 *	(old) request has timed out, been rejected, and marked
	 *	as finished.  The client has already received a
	 *	response, so there is nothing that can be done. Delete
	 *	the tardy reply from the home server, and return NULL.
	 */
	if ((oldreq->reply->code != 0) ||
	    (oldreq->finished)) {
		radlog(L_ERR, "Reply from home server %s:%d arrived too late for request %d. Try increasing 'retry_delay' or 'max_request_time'",
		       ip_ntoa(buffer, request->packet->src_ipaddr),
		       request->packet->src_port,
		       oldreq->number);
		request_free(&request);
		return NULL;
	}
	
	/*
	 *	If there is already a reply, maybe this one is a
	 *	duplicate?
	 */
	if (oldreq->proxy_reply) {
		if (memcmp(oldreq->proxy_reply->vector,
			   request->packet->vector,
			   sizeof(oldreq->proxy_reply->vector)) == 0) {
			DEBUG2("Ignoring duplicate proxy reply");
		} else {
				/*
				 *  ??? The home server gave us a new
				 *  proxy reply, which doesn't match
				 *  the old one.  Delete it!
				 */
			DEBUG2("Ignoring conflicting proxy reply");
		}
		
		/*
		 *	We've already received a reply, so
		 *	we discard this one, as we don't want
		 *	to do duplicate work.
		 */
		request_free(&request);
		return NULL;
	} /* else there wasn't a proxy reply yet, so we can process it */

	/*
	 *  Refresh the old request, and update it with the proxy reply.
	 *
	 *  ??? Can we delete the proxy request here?
	 *  Is there any more need for it?
	 */
	oldreq->timestamp = request->timestamp;
	oldreq->proxy_reply = request->packet;
	request->packet = NULL;
	request_free(&request);

	/*
	 *	Now that we've verified the packet IS actually
	 *	from that realm, and not forged, we can go mark the
	 *	realms for this home server as active.
	 *
	 *	If we had done this check in the 'find realm by IP address'
	 *	function, then an attacker could force us to use a home
	 *	server which was inactive, by forging reply packets
	 *	which didn't match any request.  We would think that
	 *	the reply meant the home server was active, would
	 *	re-activate the realms, and THEN bounce the packet
	 *	as garbage.
	 */
	for (cl = mainconfig.realms; cl != NULL; cl = cl->next) {
		if (oldreq->proxy_reply->src_ipaddr == cl->ipaddr) {
			if (oldreq->proxy_reply->src_port == cl->auth_port) {
				cl->active = TRUE;
				cl->last_reply = oldreq->timestamp;
			} else if (oldreq->proxy_reply->src_port == cl->acct_port) {
				cl->acct_active = TRUE;
				cl->last_reply = oldreq->timestamp;
			}
		}
	}

	return oldreq;
}

/*
 *  Refresh a request, by using proxy_retry_delay, cleanup_delay,
 *  max_request_time, etc.
 *
 *  When walking over the request list, all of the per-request
 *  magic is done here.
 */
static int refresh_request(REQUEST *request, void *data)
{
	rad_walk_t *info = (rad_walk_t *) data;
	time_t difference;
	child_pid_t child_pid;

	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *  If the request is marked as a delayed reject, AND it's
	 *  time to send the reject, then do so now.
	 */
	if (request->finished &&
	    ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) != 0)) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);

		difference = info->now - request->timestamp;
		if (difference >= (time_t) mainconfig.reject_delay) {

			/*
			 *  Clear the 'delayed reject' bit, so that we
			 *  don't do this again.
			 */
			request->options &= ~RAD_REQUEST_OPTION_DELAYED_REJECT;
			rad_send(request->reply, request->packet,
				 request->secret);
		}
	}

	/*
	 *  If the request has finished processing, AND it's child has
	 *  been cleaned up, AND it's time to clean up the request,
	 *  OR, it's an accounting request.  THEN, go delete it.
	 *
	 *  If this is a request which had the "don't cache" option
	 *  set, then delete it immediately, as it CANNOT have a
	 *  duplicate.
	 */
	if (request->finished &&
	    ((request->timestamp + mainconfig.cleanup_delay <= info->now) ||
	     ((request->options & RAD_REQUEST_OPTION_DONT_CACHE) != 0))) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
		/*
		 *  Request completed, delete it, and unlink it
		 *  from the currently 'alive' list of requests.
		 */
		DEBUG2("Cleaning up request %d ID %d with timestamp %08lx",
				request->number, request->packet->id,
				(unsigned long)request->timestamp);
		
		/*
		 *  Delete the request.
		 */
		rl_delete(request);
		return RL_WALK_CONTINUE;
	}

	/*
	 *  Maybe the child process handling the request has hung:
	 *  kill it, and continue.
	 */
	if ((request->timestamp + mainconfig.max_request_time) <= info->now) {
		int number;

		child_pid = request->child_pid;
		number = request->number;

		/*
		 *	There MUST be a RAD_PACKET reply.
		 */
		rad_assert(request->reply != NULL);

		/*
		 *	If we've tried to proxy the request, and
		 *	the proxy server hasn't responded, then
		 *	we send a REJECT back to the caller.
		 *
		 *	For safety, we assert that there is no child
		 *	handling the request.  If the assertion fails,
		 *	it means that we've sent a proxied request to
		 *	the home server, and the child thread is still
		 *	sitting on the request!
		 */
		if (request->proxy && !request->proxy_reply) {
			rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
			
			radlog(L_ERR, "Rejecting request %d due to lack of any response from home server %s:%d",
			       request->number,
			       client_name(request->packet->src_ipaddr),
			       request->packet->src_port);
			rad_reject(request);
			request->finished = TRUE;
			return RL_WALK_CONTINUE;
		}

		if (mainconfig.kill_unresponsive_children) {
			if (child_pid != NO_SUCH_CHILD_PID) {
				/*
				 *  This request seems to have hung
				 *   - kill it
				 */
#if HAVE_PTHREAD_H
				radlog(L_ERR, "Killing unresponsive thread for request %d",
				       request->number);
				pthread_cancel(child_pid);
#else
#ifdef ALLOW_CHILD_FORKS
				radlog(L_ERR, "Killing unresponsive child %lu for request %d",
				       child_pid, request->number);
				kill(child_pid, SIGTERM);
#endif
#endif
			} /* else no proxy reply, quietly fail */
		
			/*
			 *	Maybe we haven't killed it.  In that
			 *	case, print a warning.
			 */
		} else if ((child_pid != NO_SUCH_CHILD_PID) &&
			   ((request->options & RAD_REQUEST_OPTION_LOGGED_CHILD) == 0)) {
			radlog(L_ERR, "WARNING: Unresponsive child (id %lu) for request %d",
			       (unsigned long)child_pid, number);

			/*
			 *  Set the option that we've sent a log message,
			 *  so that we don't send more than one message
			 *  per request.
			 */
			request->options |= RAD_REQUEST_OPTION_LOGGED_CHILD;
		}

		/*
		 *  Send a reject message for the request, mark it
		 *  finished, and forget about the child.
		 */
		rad_reject(request);
		request->child_pid = NO_SUCH_CHILD_PID;
		if (mainconfig.kill_unresponsive_children)
			request->finished = TRUE;
		return RL_WALK_CONTINUE;
	} /* the request has been in the queue for too long */

	/*
	 *  If the request is still being processed, then due to the
	 *  above check, it's still within it's time limit.  In that
	 *  case, don't do anything.
	 */
	if (request->child_pid != NO_SUCH_CHILD_PID) {
		return RL_WALK_CONTINUE;
	}

	/*
	 *  The request is finished.
	 */
	if (request->finished) goto setup_timeout;

	/*
	 *  We're not proxying requests at all.
	 */
	if (!mainconfig.proxy_requests) goto setup_timeout;

	/*
	 *  We're proxying synchronously, so we don't retry it here.
	 *  Some other code takes care of retrying the proxy requests.
	 */
	if (mainconfig.proxy_synchronous) goto setup_timeout;

	/*
	 *  The proxy retry delay is zero, meaning don't retry.
	 */
	if (mainconfig.proxy_retry_delay == 0) goto setup_timeout;

	/*
	 *  There is no proxied request for this packet, so there's
	 *  no proxy retries.
	 */
	if (!request->proxy) goto setup_timeout;

	/*
	 *  We've already seen the proxy reply, so we don't need
	 *  to send another proxy request.
	 */
	if (request->proxy_reply) goto setup_timeout;

	/*
	 *  It's not yet time to re-send this proxied request.
	 */
	if (request->proxy_next_try > info->now) goto setup_timeout;
	
	/*
	 *  If the proxy retry count is zero, then
	 *  we've sent the last try, and have NOT received
	 *  a reply from the end server.  In that case,
	 *  we don't bother trying again, but just mark
	 *  the request as finished, and go to the next one.
	 */
	if (request->proxy_try_count == 0) {
		rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
		rad_reject(request);
		realm_disable(request->proxy->dst_ipaddr,request->proxy->dst_port);
		request->finished = TRUE;
		goto setup_timeout;
	}

	/*
	 *  We're trying one more time, so count down
	 *  the tries, and set the next try time.
	 */
	request->proxy_try_count--;
	request->proxy_next_try = info->now + mainconfig.proxy_retry_delay;
		
	/* Fix up Acct-Delay-Time */
	if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		VALUE_PAIR *delaypair;
		delaypair = pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME);
		
		if (!delaypair) {
			delaypair = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
			if (!delaypair) {
				radlog(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			pairadd(&request->proxy->vps, delaypair);
		}
		delaypair->lvalue = info->now - request->proxy->timestamp;
			
		/* Must recompile the valuepairs to wire format */
		free(request->proxy->data);
		request->proxy->data = NULL;
	} /* proxy accounting request */

	/*
	 *  Assert that we have NOT seen the proxy reply yet.
	 *
	 *  If we HAVE seen it, then we SHOULD NOT be bugging the
	 *  home server!
	 */
	rad_assert(request->proxy_reply == NULL);

	/*
	 *  Send the proxy packet.
	 */
	rad_send(request->proxy, NULL, request->proxysecret);

setup_timeout:
	/*
	 *  Don't do more long-term checks, if we've got to wake
	 *  up now.
	 */
	if (info->smallest == 0) {
		return RL_WALK_CONTINUE;
	}

	/*
	 *  The request is finished.  Wake up when it's time to
	 *  clean it up.
	 */
	if (request->finished) {
		difference = (request->timestamp + mainconfig.cleanup_delay) - info->now;

		/*
		 *  If the request is marked up to be rejected later,
		 *  then wake up later.
		 */
		if ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) != 0) {
			if (difference >= (time_t) mainconfig.reject_delay) {
				difference = (time_t) mainconfig.reject_delay;
			}
		}

	} else if (request->proxy && !request->proxy_reply) {
		/*
		 *  The request is NOT finished, but there is an
		 *  outstanding proxy request, with no matching
		 *  proxy reply.
		 *
		 *  Wake up when it's time to re-send
		 *  the proxy request.
		 *
		 *  But in synchronous proxy, we don't retry but we update
		 *  the next retry time as NAS has not resent the request
		 *  in the given retry window.
		 */
		if (mainconfig.proxy_synchronous) {
			request->proxy_next_try = info->now + mainconfig.proxy_retry_delay;
		}
		difference = request->proxy_next_try - info->now;
	} else {
		/*
		 *  The request is NOT finished.
		 *
		 *  Wake up when it's time to kill the errant
		 *  thread/process.
		 */
		difference = (request->timestamp + mainconfig.max_request_time) - info->now;
	}

	/*
	 *  If the server is CPU starved, then we CAN miss a time
	 *  for servicing requests.  In which case the 'difference'
	 *  value will be negative.  select() doesn't like that,
	 *  so we fix it.
	 */
	if (difference < 0) {
		difference = 0;
	}

	/*
	 *  Update the 'smallest' time.
	 */
	if ((info->smallest < 0) ||
		(difference < info->smallest)) {
		info->smallest = difference;
	}

	return RL_WALK_CONTINUE;
}

/*
 *	Process and reply to a server-status request.
 *	Like rad_authenticate and rad_accounting this should
 *	live in it's own file but it's so small we don't bother.
 */
static int rad_status_server(REQUEST *request)
{
	char		reply_msg[64];
	time_t		t;
	VALUE_PAIR	*vp;

	/*
	 *	Reply with an ACK. We might want to add some more
	 *	interesting reply attributes, such as server uptime.
	 */
	t = request->timestamp - start_time;
	sprintf(reply_msg, "FreeRadius up %d day%s, %02d:%02d",
		(int)(t / 86400), (t / 86400) == 1 ? "" : "s",
		(int)((t / 3600) % 24), (int)(t / 60) % 60);
	request->reply->code = PW_AUTHENTICATION_ACK;

	vp = pairmake("Reply-Message", reply_msg, T_OP_SET);
	pairadd(&request->reply->vps, vp); /* don't need to check if !vp */

	return 0;
}
