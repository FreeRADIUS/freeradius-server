/*
 * radiusd.c	Main loop of the radius server.
 *
 * Version:	$Id$
 *
 */

/* don't look here for the version, run radiusd -v or look in version.c */
static const char rcsid[] =
"$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/socket.h>
#include	<sys/file.h>

#if HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<ctype.h>

#if HAVE_UNISTD_H
#include	<unistd.h>
#endif

#include	<signal.h>

#if HAVE_GETOPT_H
#include	<getopt.h>
#endif

#if HAVE_SYS_SELECT_H
#include	<sys/select.h>
#endif

#if HAVE_SYSLOG_H
#include	<syslog.h>
#endif

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#include <assert.h>

#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"
#include	"request_list.h"

#if WITH_SNMP
#include	"radius_snmp.h"
#endif

#include	<sys/resource.h>

#include	<grp.h>
#include	<pwd.h>

/*
 *	Global variables.
 */
const char		*progname = NULL;
char	        	*radius_dir = NULL;
char			*radacct_dir = NULL;
char			*radlog_dir = NULL;
const char		*radlib_dir = NULL;
int			log_stripped_names;
int			debug_flag;
int			use_dbm	= FALSE;
uint32_t		myip = INADDR_ANY;
int			log_auth_detail	= FALSE;
int			auth_port = 0;
int			acct_port;
int			proxy_port;
int			proxy_retry_delay = RETRY_DELAY;
int			proxy_retry_count = RETRY_COUNT;
int			proxy_synchronous = TRUE;
int			need_reload = FALSE;
struct	main_config_t 	mainconfig;

static int		got_child = FALSE;
static int		authfd;
static int		acctfd;
int	        	proxyfd;
static pid_t		radius_pid;
static int		request_num_counter = 0; /* per-request unique ID */

/*
 *  Configuration items.
 */
static int		allow_core_dumps = FALSE;
static int		max_request_time = MAX_REQUEST_TIME;
static int		cleanup_delay = CLEANUP_DELAY;
static int		max_requests = MAX_REQUESTS;
static int		dont_fork = FALSE;
static const char	*pid_file = NULL;
static uid_t		server_uid;
static gid_t		server_gid;
static const char	*uid_name = NULL;
static const char	*gid_name = NULL;
static int		proxy_requests = TRUE;
static int		spawn_flag = TRUE;
static struct rlimit	core_limits;

static void	usage(void);

static void	sig_fatal (int);
static void	sig_hup (int);

static void	rad_reject(REQUEST *request);
static int	rad_process (REQUEST *, int);
static struct timeval *rad_clean_list(time_t curtime);
static REQUEST	*rad_check_list(REQUEST *);
static REQUEST *proxy_check_list(REQUEST *request);
static int     refresh_request(REQUEST *request, void *data);
#ifndef WITH_THREAD_POOL
static int	rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#else
extern int	rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#endif

/*
 *	Map the proxy server configuration parameters to variables.
 */
static CONF_PARSER proxy_config[] = {
  { "retry_delay",  PW_TYPE_INTEGER,
    &proxy_retry_delay, Stringify(RETRY_DELAY) },
  { "retry_count",  PW_TYPE_INTEGER,
    &proxy_retry_count, Stringify(RETRY_COUNT) },
  { "synchronous",  PW_TYPE_BOOLEAN, &proxy_synchronous, "yes" },

  { NULL, -1, NULL, NULL }
};

/*
 *	A mapping of configuration file names to internal variables
 */
static CONF_PARSER server_config[] = {
  { "max_request_time",   PW_TYPE_INTEGER,
    &max_request_time,    Stringify(MAX_REQUEST_TIME) },
  { "cleanup_delay",      PW_TYPE_INTEGER,
    &cleanup_delay,       Stringify(CLEANUP_DELAY) },
  { "max_requests",       PW_TYPE_INTEGER,
    &max_requests,	  Stringify(MAX_REQUESTS) },
  { "port",               PW_TYPE_INTEGER,
    &auth_port,		  Stringify(PW_AUTH_UDP_PORT) },
  { "allow_core_dumps",   PW_TYPE_BOOLEAN,    &allow_core_dumps,  "no" },
  { "log_stripped_names", PW_TYPE_BOOLEAN,    &log_stripped_names,"no" },
  { "log_auth",           PW_TYPE_BOOLEAN,    &mainconfig.log_auth,   "no" },
  { "log_auth_badpass",   PW_TYPE_BOOLEAN,    &mainconfig.log_auth_badpass,  "no" },
  { "log_auth_goodpass",  PW_TYPE_BOOLEAN,    &mainconfig.log_auth_goodpass, "no" },
  { "pidfile",            PW_TYPE_STRING_PTR, &pid_file,          "${run_dir}/radiusd.pid"},
  { "bind_address",       PW_TYPE_IPADDR,     &myip,              "*" },
  { "user",           PW_TYPE_STRING_PTR, &uid_name,  NULL},
  { "group",          PW_TYPE_STRING_PTR, &gid_name,  NULL},
  { "usercollide",   PW_TYPE_BOOLEAN,    &mainconfig.do_usercollide,  "no" },
  { "lower_user",     PW_TYPE_STRING_PTR,    &mainconfig.do_lower_user, "no" },
  { "lower_pass",     PW_TYPE_STRING_PTR,    &mainconfig.do_lower_pass, "no" },
  { "nospace_user",   PW_TYPE_STRING_PTR,    &mainconfig.do_nospace_user, "no" },
  { "nospace_pass",   PW_TYPE_STRING_PTR,    &mainconfig.do_nospace_pass, "no" },

  { "proxy_requests", PW_TYPE_BOOLEAN,    &proxy_requests,    "yes" },
  { "proxy",          PW_TYPE_SUBSECTION, proxy_config,       NULL },
  { NULL, -1, NULL, NULL }
};

/*
 *	Read config files.
 */
static int reread_config(int reload)
{
	int pid = getpid();
	CONF_SECTION *cs;

	if (!reload) {
		radlog(L_INFO, "Starting - reading configuration files ...");
	} else if (pid == radius_pid) {
		radlog(L_INFO, "Reloading configuration files.");
	}

	/* First read radiusd.conf */
	DEBUG2("reread_config:  reading radiusd.conf");
	if (read_radius_conf_file() < 0) {
		radlog(L_ERR|L_CONS, "Errors reading radiusd.conf");
		return -1;
	}

	/*
	 *	And parse the server's configuration values.
	 */
	cs = cf_section_find(NULL);
	if (!cs) {
		radlog(L_ERR|L_CONS, "No configuration information in radiusd.conf!");
		return -1;
	}
	cf_section_parse(cs, server_config);

	/*
	 *	Reload the modules.
	 */
	DEBUG2("read_config_files:  entering modules setup");
	if (setup_modules() < 0) {
		radlog(L_ERR|L_CONS, "Errors setting up modules");
		return -1;
	}

	/*
	 *	Go update our behaviour, based on the configuration
	 *	changes.
	 */
	if (allow_core_dumps) {
		if (setrlimit(RLIMIT_CORE, &core_limits) < 0) {
			radlog(L_ERR|L_CONS, "Cannot update core dump limit: %s",
			    strerror(errno));
			exit(1);

			/*
			 *	If we're running as a daemon, and core
			 *	dumps are enabled, log that information.
			 */
		} else if ((core_limits.rlim_cur != 0) && !debug_flag)
		  radlog(L_INFO, "Core dumps are enabled.");

	} else if (!debug_flag) {
		/*
		 *	Not debugging.  Set the core size to zero, to
		 *	prevent security breaches.  i.e. People
		 *	reading passwords from the 'core' file.
		 */
		struct rlimit limits;

		limits.rlim_cur = 0;
		limits.rlim_max = core_limits.rlim_max;
		
		if (setrlimit(RLIMIT_CORE, &limits) < 0) {
			radlog(L_ERR|L_CONS, "Cannot disable core dumps: %s",
			    strerror(errno));
			exit(1);
		}
	}

	/*
	 *	Set the UID and GID, but only if we're NOT running
	 *	in debugging mode.
	 */
	if (!debug_flag) {
		/*
		 *	Set group.
		 */
		if (gid_name) {
			struct group *gr;

			gr = getgrnam(gid_name);
			if (!gr) {
				radlog(L_ERR|L_CONS, "Cannot switch to Group %s: %s", gid_name, strerror(errno));
				exit(1);
			}
			server_gid = gr->gr_gid;
			if (setgid(server_gid) < 0) {
				radlog(L_ERR|L_CONS, "Failed setting Group to %s: %s", gid_name, strerror(errno));
				exit(1);
			}
		}

		/*
		 *	Set UID.
		 */
		if (uid_name) {
			struct passwd *pw;

			pw = getpwnam(uid_name);
			if (!pw) {
				radlog(L_ERR|L_CONS, "Cannot switch to User %s: %s", uid_name, strerror(errno));
				exit(1);
			}
			server_uid = pw->pw_uid;
			if (setuid(server_uid) < 0) {
				radlog(L_ERR|L_CONS, "Failed setting User to %s: %s", uid_name, strerror(errno));
				exit(1);
			}
		}
	}

	return 0;
}

/*
 *	Parse a string into a syslog facility level.
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

int main(int argc, char **argv)
{
	REQUEST			*request;
	RADIUS_PACKET		*packet;
	u_char                  *secret;
	unsigned char		buffer[4096];
	struct	sockaddr	salocal;
	struct	sockaddr_in	*sa;
	fd_set			readfds;
	int			result;
	int			argval;
	int			t;
	int			pid;
	int			i;
	int			fd = 0;
	int			devnull;
	int			status;
	int			syslog_facility = LOG_DAEMON;
	int			radius_port = 0;
	struct servent		*svp;
	struct timeval		*tv = NULL;
 
#ifdef OSFC2
	set_auth_parameters(argc,argv);
#endif

	/*
	 *	Open /dev/null, and make sure filedescriptors
	 *	0, 1 and 2 are connected to something.
	 */
	devnull = 0;
	while (devnull >= 0 && devnull < 3)
		devnull = open("/dev/null", O_RDWR);

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	debug_flag = 0;
	spawn_flag = TRUE;
	radius_dir = strdup(RADIUS_DIR);

	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_fatal);
	signal(SIGQUIT, sig_fatal);
#if WITH_SNMP
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGTRAP
	signal(SIGTRAP, sig_fatal);
#endif
#ifdef SIGIOT
	signal(SIGIOT, sig_fatal);
#endif

	/*
	 *	Pooled threads and child threads define their own
	 *	signal handler.
	 */
#ifndef WITH_THREAD_POOL
#ifndef HAVE_PTHREAD_H
	signal(SIGTERM, sig_fatal);
#endif
#endif
	signal(SIGCHLD, sig_cleanup);
#if 0
	signal(SIGFPE, sig_fatal);
	signal(SIGSEGV, sig_fatal);
	signal(SIGILL, sig_fatal);
#endif

	/*
	 *	Close unused file descriptors.
	 */
	for (t = 32; t >= 3; t--)
	    if(t!=devnull) close(t);

	/*
	 *	Process the options.
	 */
	while((argval = getopt(argc, argv, "Aa:bcd:fg:hi:l:p:sSvxXyz")) != EOF) {

		switch(argval) {

		case 'A':
			log_auth_detail = TRUE;
			break;

		case 'a':
			if (radacct_dir) free(radacct_dir);
			radacct_dir = strdup(optarg);
			break;
		
#if defined(WITH_DBM) || defined(WITH_NDBM)
		case 'b':
			use_dbm++;
			break;
#endif
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
			usage();
			break;

		case 'i':
			if ((myip = ip_getaddr(optarg)) == INADDR_NONE) {
				fprintf(stderr, "radiusd: %s: host unknown\n",
					optarg);
				exit(1);
			}
			break;
		
		case 'l':
			if (radlog_dir) free(radlog_dir);
			radlog_dir = strdup(optarg);
			break;
		
			/*
			 *	We should also have this as a configuration
			 *	file directive.
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
			librad_debug = 2;
			mainconfig.log_auth = TRUE;
			mainconfig.log_auth_badpass = TRUE;
			mainconfig.log_auth_goodpass = TRUE;
			radlog_dir = strdup("stdout");
			break;

		case 'x':
			debug_flag++;
			librad_debug++;
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
	 *	Get out PID: the configuration file reader uses it.
	 */
	radius_pid = getpid();

	/*
	 *	Get the current maximum for core files.
	 */
	if (getrlimit(RLIMIT_CORE, &core_limits) < 0) {
		radlog(L_ERR|L_CONS, "Failed to get current core limit:"
		    "  %s", strerror(errno));
		exit(1);
	}

	/*
	 *	Read the configuration files, BEFORE doing anything else.
	 */
	if (reread_config(0) < 0) {
		exit(1);
	}

#if HAVE_SYSLOG_H
	/*
	 *	If they asked for syslog, then give it to them.
	 *	Also, initialize the logging facility with the
	 *	configuration that they asked for.
	 */
	if (!strcmp(radlog_dir, "syslog")) {
		openlog(progname, LOG_PID, syslog_facility);
	}
	/* Do you want a warning if -g is used without a -l to activate it? */
#endif

	/*
	 *	Initialize the request list.
	 */
	rl_init();

	/*
	 *	We prefer (in order) the port from the command-line,
	 *	then the port from the configuration file, then
	 *	the port that the system names "radius", then
	 *	1645.
	 */
	if (radius_port) {
		auth_port = radius_port;
	} /* else auth_port is set from the config file */
	
	/*
	 *	Maybe auth_port *wasn't* set from the config file,
	 *	or the config file set it to zero.
	 */
	acct_port = 0;
	if (auth_port == 0) {
		svp = getservbyname ("radius", "udp");
		if (svp != NULL) {
			auth_port = ntohs(svp->s_port);

			/*
			 *	We're getting auth_port from
			 *	/etc/services, get acct_port from
			 *	there, too.
			 */
			svp = getservbyname ("radacct", "udp");
			if (svp) acct_port = ntohs(svp->s_port);
		} else {
			auth_port = PW_AUTH_UDP_PORT;
		}
	}

	/*
	 *	Open Authentication socket.
	 *
	 */
	authfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (authfd < 0) {
		perror("auth socket");
		exit(1);
	}

	sa = (struct sockaddr_in *) & salocal;
        memset ((char *) sa, '\0', sizeof (salocal));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = myip;
	sa->sin_port = htons(auth_port);

	result = bind (authfd, & salocal, sizeof (*sa));
	if (result < 0) {
		perror ("auth bind");
		exit(1);
	}

	/*
	 *	Open Accounting Socket.
	 *
	 *	If we haven't already gotten acct_port from /etc/services,
	 *	then make it auth_port + 1.
	 */
	if (!acct_port) 
		acct_port = auth_port + 1;
	
	acctfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (acctfd < 0) {
		perror ("acct socket");
		exit(1);
	}

	sa = (struct sockaddr_in *) & salocal;
        memset ((char *) sa, '\0', sizeof (salocal));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = myip;
	sa->sin_port = htons(acct_port);

	result = bind (acctfd, & salocal, sizeof (*sa));
	if (result < 0) {
		perror ("acct bind");
		exit(1);
	}

	/*
	 *	If we're proxying requests, open the proxy FD.
	 *	Otherwise, don't do anything.
	 */
	if (proxy_requests) {
		/*
		 *	Open Proxy Socket.
		 */
		proxyfd = socket (AF_INET, SOCK_DGRAM, 0);
		if (proxyfd < 0) {
			perror ("proxy socket");
			exit(1);
		}
		
		sa = (struct sockaddr_in *) & salocal;
		memset ((char *) sa, '\0', sizeof (salocal));
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = myip;
		
		/*
		 *	Set the proxy port to be one more than the
		 *	accounting port.
		 */
		for (proxy_port = acct_port + 1; proxy_port < 64000; proxy_port++) {
			sa->sin_port = htons(proxy_port);
			result = bind (proxyfd, & salocal, sizeof (*sa));
			if (result == 0) {
				break;
			}
		}
		
		/*
		 *	Couldn't find a port to which we could bind.
		 */
		if (proxy_port == 64000) {
			perror("proxy bind");
			exit(1);
		}

	} else {
		/*
		 *	NOT proxying requests, set the FD to a bad value.
		 */
		proxyfd = -1;
		proxy_port = 0;
	}

	/*
	 *	Register built-in compare functions.
	 */
	pair_builtincompare_init();

#if WITH_SNMP
	radius_snmp_init();
#endif

#if 0
	/*
	 *	Connect 0, 1 and 2 to /dev/null.
	 */
	if (!debug_flag && devnull >= 0) {
		dup2(devnull, 0);
		if (strcmp(radlog_dir, "stdout") != 0) {
		  dup2(devnull, 1);
		}
		dup2(devnull, 2);
		if (devnull > 2) close(devnull);
	}
#endif

	/*
	 *	Disconnect from session
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
	 *	Ensure that we're using the CORRECT pid after forking,
	 *	NOT the one we started with.
	 */
	radius_pid = getpid();

	/*
	 *	Only write the PID file if we're running as a daemon.
	 *
	 *	And write it AFTER we've forked, so that we write the
	 *	correct PID.
	 */
	if (dont_fork == FALSE) {
		FILE *fp;

		fp = fopen(pid_file, "w");
		if (fp != NULL) {
			fprintf(fp, "%d\n", (int) radius_pid);
			fclose(fp);
		} else {
			radlog(L_ERR|L_CONS, "Failed writing process id to file %s: %s\n",
			    pid_file, strerror(errno));
		}
	}

#if WITH_THREAD_POOL
	/*
	 *	If we're spawning children, set up the thread pool.
	 */
	if (spawn_flag) {
		thread_pool_init();
	}
#endif

	/*
	 *	Use linebuffered or unbuffered stdout if
	 *	the debug flag is on.
	 */
	if (debug_flag) setlinebuf(stdout);

	if (myip == 0) {
		strcpy((char *)buffer, "*");
	} else {
		ip_ntoa((char *)buffer, myip);
	}

	if (proxy_requests) {
		radlog(L_INFO, "Listening on IP address %s, ports %d/udp and %d/udp, with proxy on %d/udp.",
		    buffer, auth_port, acct_port, proxy_port);
	} else {
		radlog(L_INFO, "Listening on IP address %s, ports %d/udp and %d/udp.",
		    buffer, auth_port, acct_port);
	}

	/*
	 *	Note that we NO LONGER fork an accounting process!
	 *	We used to do it for historical reasons, but that
	 *	is no excuse...
	 */
	radlog(L_INFO, "Ready to process requests.");

	/*
	 *	Receive user requests
	 */
	for(;;) {
		if (need_reload) {
			if (reread_config(TRUE) < 0) {
				exit(1);
			}
			need_reload = FALSE;
			radlog(L_INFO, "Ready to process requests.");
		}

		FD_ZERO(&readfds);
		if (authfd >= 0)
			FD_SET(authfd, &readfds);
		if (acctfd >= 0)
			FD_SET(acctfd, &readfds);
		if (proxyfd >= 0)
			FD_SET(proxyfd, &readfds);
#ifdef WITH_SNMP
		if (rad_snmp.smux_fd >= 0)
			FD_SET(rad_snmp.smux_fd, &readfds);
#endif

		status = select(32, &readfds, NULL, NULL, tv);
		if (status == -1) {
			/*
			 *	On interrupts, we clean up the
			 *	request list.
			 */
			if (errno == EINTR) {
				tv = rad_clean_list(time(NULL));
				continue;
			}
			radlog(L_ERR, "Unexpected error in select(): %s",
			    strerror(errno));
			sig_fatal(101);
		}

		/*
		 *	Loop over the open socket FD's, reading any data.
		 */
		for (i = 0; i < 3; i++) {

			if (i == 0) fd = authfd;
			if (i == 1) fd = acctfd;
			if (i == 2) fd = proxyfd;
			if (fd < 0 || !FD_ISSET(fd, &readfds))
				continue;
			/*
			 *	Receive the packet.
			 */
			packet = rad_recv(fd);
			if (packet == NULL) {
				radlog(L_ERR, "%s", librad_errstr);
				continue;
			}
#if WITH_SNMP
			if (fd == acctfd)
				rad_snmp.acct_total_requests++;
			if (fd == authfd)
				rad_snmp.auth_total_requests++;
#endif

			/*
			 *	Check if we know this client for
			 *	authfd and acctfd.  Check if we know
			 *	this proxy for proxyfd.
			 */
			if(fd != proxyfd) {
			        RADCLIENT    *cl;
			        if ((cl = client_find(packet->src_ipaddr)) == NULL) {
			              radlog(L_ERR, "Ignoring request from unknown client %s:%d",
				        ip_ntoa(buffer, packet->src_ipaddr),
					packet->src_port);
				      rad_free(&packet);
				      continue;
				} else {
				      secret = cl->secret;
				}
				
			} else {    /* It came in on the proxy port */
			        REALM         *rl;
			        if ((rl = realm_findbyaddr(packet->src_ipaddr)) == NULL) {
				      radlog(L_ERR, "Ignoring request from unknown proxy %s:%d",
				 	ip_ntoa(buffer, packet->src_ipaddr),
					packet->src_port);
				      rad_free(&packet);
				      continue;
				} else {
				      secret = rl->secret;
				}
			}      

			/*
			 *	Do yet another check, to see if the
			 *	packet code is valid.  We only understand
			 *	a few, so stripping off obviously invalid
			 *	packets here will make our life easier.
			 */
			if (packet->code > PW_ACCESS_CHALLENGE) {
				radlog(L_ERR, "Ignoring request from client %s:%d with unknown code %d", buffer, packet->src_port, packet->code);
				rad_free(&packet);
				continue;
			}

			request = rad_malloc(sizeof(REQUEST));
			memset(request, 0, sizeof(REQUEST));
#ifndef NDEBUG
			request->magic = REQUEST_MAGIC;
#endif
			request->packet = packet;
			request->proxy = NULL;
			request->reply = NULL;
			request->proxy_reply = NULL;
			request->config_items = NULL;
			request->username = NULL;
			request->password = NULL;
			request->timestamp = time(NULL);
			request->number = request_num_counter++;
			request->child_pid = NO_SUCH_CHILD_PID;
			request->prev = NULL;
			request->next = NULL;
			strNcpy(request->secret, (char *)secret, sizeof(request->secret));
			rad_process(request, spawn_flag);
		} /* loop over authfd, acctfd, proxyfd */

#if WITH_SNMP
		/*
		 *	After handling all authentication/accounting
		 *	requests, THEN process any pending SMUX/SNMP
		 *	queries.
		 *
		 *	Note that the handling is done in the main server,
		 *	which probably isn't a Good Thing.  It really
		 *	should be wrapped, and handled in a thread pool.
		 */
		if ((rad_snmp.smux_fd >= 0) &&
		    FD_ISSET(rad_snmp.smux_fd, &readfds) &&
		    (rad_snmp.smux_event == SMUX_READ)) {
		  smux_read();
		}
		
		/*
		 *	If we've got to re-connect, then do so now,
		 *	before calling select again.
		 */
 		if (rad_snmp.smux_event == SMUX_CONNECT) {
		  smux_connect();
		}
#endif

		/*
		 *	After processing all new requests,
		 *	check if we've got to delete old requests
		 *	from the request list.
		 */
		tv = rad_clean_list(time(NULL));

	} /* loop forever */
}


/*
 *	Process supported requests:
 *
 *		PW_AUTHENTICATION_REQUEST - Authentication request from
 *				a client network access server.
 *
 *		PW_ACCOUNTING_REQUEST - Accounting request from
 *				a client network access server.
 *
 *		PW_AUTHENTICATION_ACK
 *		PW_AUTHENTICATION_REJECT
 *		PW_ACCOUNTING_RESPONSE - Reply from a remote Radius server.
 *				Relay reply back to original NAS.
 *
 */
int rad_process(REQUEST *request, int dospawn)
{
	RAD_REQUEST_FUNP fun;

	fun = NULL;

	assert(request->magic == REQUEST_MAGIC);

	switch(request->packet->code) {
	default:
		radlog(L_ERR, "Unknown packet type %d from client %s:%d "
		    "- ID %d : IGNORED",
		    request->packet->code,
		    client_name(request->packet->src_ipaddr),
		    request->packet->src_port,
		    request->packet->id);
		request_free(&request);
		return -1;
		break;

	case PW_AUTHENTICATION_REQUEST:
		/*
		 *	Check for requests sent to the wrong port,
		 *	and ignore them, if so.
		 */
		if (request->packet->sockfd != authfd) {
		  radlog(L_ERR, "Request packet code %d sent to authentication port from "
		      "client %s:%d - ID %d : IGNORED",
		      request->packet->code,
		      client_name(request->packet->src_ipaddr),
		      request->packet->src_port,
		      request->packet->id);
		  request_free(&request);
		  return -1;
		}
		fun = rad_authenticate;
		break;

	case PW_ACCOUNTING_REQUEST:
		/*
		 *	Check for requests sent to the wrong port,
		 *	and ignore them, if so.
		 */
		if (request->packet->sockfd != acctfd) {
		  radlog(L_ERR, "Request packet code %d sent to accounting port from "
		      "client %s:%d - ID %d : IGNORED",
		      request->packet->code,
		      client_name(request->packet->src_ipaddr),
		      request->packet->src_port,
		      request->packet->id);
		  request_free(&request);
		  return -1;
		}
		fun = rad_accounting;
		break;

	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_ACCOUNTING_RESPONSE:
		/*
		 *	Replies NOT sent to the proxy port get an
		 *	error message logged, and the packet is
		 *	dropped.
		 */
		if (request->packet->sockfd != proxyfd) {
			radlog(L_ERR, "Reply packet code %d sent to request port from "
			    "client %s:%d - ID %d : IGNORED",
			    request->packet->code,
			    client_name(request->packet->src_ipaddr),
			    request->packet->src_port,
			    request->packet->id);
			request_free(&request);
			return -1;
		}
		if (request->packet->code == PW_AUTHENTICATION_ACK) {
			fun = rad_authenticate;
		} else {
			fun = rad_accounting;
		}
		break;

	case PW_PASSWORD_REQUEST:
		/*
		 *	We don't support this anymore.
		 */
		radlog(L_ERR, "Deprecated password change request from client %s:%d - ID %d : IGNORED",
		    client_name(request->packet->src_ipaddr),
		    request->packet->src_port,
		    request->packet->id);
		request_free(&request);
		return -1;
		break;
	}

	/*
	 *	Check for a duplicate, or error.
	 *	Throw away the the request if so.
	 */
	request = rad_check_list(request);
	if (request == NULL) {
		return 0;
	}
	
	assert(request->magic == REQUEST_MAGIC);

	/*
	 *	The request passes many of our sanity checks.  From
	 *	here on in, if anything goes wrong, we send a reject
	 *	message, instead of dropping the packet.
	 *
	 *	Build the reply template from the request template.
	 */
	if ((request->reply = rad_alloc(0)) == NULL) {
		radlog(L_ERR, "No memory");
		exit(1);
	}
	request->reply->sockfd     = request->packet->sockfd;
	request->reply->dst_ipaddr = request->packet->src_ipaddr;
	request->reply->dst_port   = request->packet->src_port;
	request->reply->id         = request->packet->id;
	request->reply->code       = 0;	/* UNKNOWN code */
	memcpy(request->reply->vector, request->packet->vector,
	       sizeof(request->reply->vector));
	request->reply->vps = NULL;
	request->reply->data = NULL;
	request->reply->data_len = 0;

	/*
	 *	If we're spawning a child thread, let it do all of
	 *	the work of handling a request, and exit.
	 */
	if (dospawn) {
		/*
		 *	Maybe the spawn failed.  If so, then we
		 *	trivially reject the request (because we can't
		 *	handle it), and return.
		 */
		if (rad_spawn_child(request, fun) < 0) {
			rad_reject(request);
			request->finished = TRUE;
		}
		return 0;
	}

	rad_respond(request, fun);
	return 0;
}

/*
 *	Reject a request, by sending a trivial reply packet.
 */
static void rad_reject(REQUEST *request)
{
	VALUE_PAIR *vps;
	
	DEBUG2("Server rejecting request %d.", request->number);
	switch (request->packet->code) {
		/*
		 *	Accounting requests, etc. get dropped on the floor.
		 */
	case PW_ACCOUNTING_REQUEST:
	default:
		break;

		/*
		 *	Authentication requests get their Proxy-State
		 *	attributes copied over, and an otherwise blank
		 *	reject message sent.
		 */
	case PW_AUTHENTICATION_REQUEST:
		request->reply->code = PW_AUTHENTICATION_REJECT; 

		/*
		 *	Need to copy Proxy-State from request->packet->vps
		 */
		vps = paircopy2(request->packet->vps, PW_PROXY_STATE);
		if (vps != NULL)
			pairadd(&(request->reply->vps), vps);
		break;
	}
	
	/*
	 *	If a reply exists, send it.
	 */
	if (request->reply->code) rad_send(request->reply, request->secret);
}

/*
 *	Perform any RFC specified cleaning of outgoing replies
 */
static void rfc_clean(RADIUS_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	
	switch (packet->code) {
	default:
		break;
		
		/*
		 *	Authentication REJECT's can have only
		 *	Reply-Mesaage and Proxy-State.  We delete
		 *	everything other than Reply-Message, and
		 *	Proxy-State is added below, just before
		 *	the reply is sent.
		 */
	case PW_AUTHENTICATION_REJECT:
		pairmove2(&vps, &(packet->vps), PW_REPLY_MESSAGE);
		pairfree(&packet->vps);
		packet->vps = vps;
		break;
	}
}

/* 
 * FIXME:  The next two functions should all
 * be in a module.  But not until we have
 * more control over module execution.
 * -jcarneal
 */

/*
 *	Lowercase the string value of a pair.
 */
static int rad_lowerpair(REQUEST *request, VALUE_PAIR *vp) {
	if (!vp) {
		return -1;
	}

	rad_lowercase(vp->strvalue);
	DEBUG2("rad_lowerpair:  %s now '%s'", vp->name, vp->strvalue);
	return 0;
}

/*
 *	Remove spaces in a pair.
 */
static int rad_rmspace_pair(REQUEST *request, VALUE_PAIR *vp) {
	if (!vp) {
		return -1;
	}
	
	rad_rmspace(vp->strvalue);
	vp->length = strlen(vp->strvalue);
	DEBUG2("rad_rmspace_pair:  %s now '%s'", vp->name, vp->strvalue);
	
	return 0;
}

/*
 *	Respond to a request packet.
 *
 *	Maybe we reply, maybe we don't.
 *	Maybe we proxy the request to another server, or else maybe
 *	we replicate it to another server.
 */
int rad_respond(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	RADIUS_PACKET	*packet, *original;
	const char	*secret;
	int		finished = FALSE;
	int		proxy_sent = 0;
	int		reprocess = 0;
	
	/*
	 *	Put the decoded packet into it's proper place.
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

	assert(request->magic == REQUEST_MAGIC);
	
	/*
	 *	Decode the packet, verifying it's signature,
	 *	and parsing the attributes into structures.
	 *
	 *	Note that we do this CPU-intensive work in
	 *	a child thread, not the master.  This helps to
	 *	spread the load a little bit.
	 */
	if (rad_decode(packet, original, secret) != 0) {
		radlog(L_ERR, "%s", librad_errstr);
		rad_reject(request);
		goto finished_request;
	}
	
	/*
	 *	For proxy replies, remove non-allowed
	 *	attributes from the list of VP's.
	 */
	if (request->proxy) {
		int replicating;
		replicating = proxy_receive(request);
		if (replicating != 0) {
			goto next_request;
		}
	}
	
	/*
	 *	We should have a User-Name attribute now.
	 */
	if (request->username == NULL) {
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME);
	}

	/*
	 *	We have the semaphore, and have decoded the packet.
	 *	Let's process the request.
	 */
	assert(request->magic == REQUEST_MAGIC);

	/* 
	 *	FIXME:  All this lowercase/nospace junk will be moved
	 *	into a module after module failover is fully in place
	 *
	 *	See if we have to lower user/pass before processing
	 */
	if(strcmp(mainconfig.do_lower_user, "before") == 0)
		rad_lowerpair(request, request->username);
	if(strcmp(mainconfig.do_lower_pass, "before") == 0)
		rad_lowerpair(request, rad_getpass(request));

	if(strcmp(mainconfig.do_nospace_user, "before") == 0)
		rad_rmspace_pair(request, request->username);
	if(strcmp(mainconfig.do_nospace_pass, "before") == 0)
		rad_rmspace_pair(request, rad_getpass(request));

	(*fun)(request);

	/* See if we have to lower user/pass after processing */
	if(strcmp(mainconfig.do_lower_user, "after") == 0) {
		rad_lowerpair(request, request->username);
		reprocess = 1;
	}
	if(strcmp(mainconfig.do_lower_pass, "after") == 0) {
		rad_lowerpair(request, rad_getpass(request));
		reprocess = 1;
	}
	if(strcmp(mainconfig.do_nospace_user, "after") == 0) {
		rad_rmspace_pair(request, request->username);
		reprocess = 1;
	}
	if(strcmp(mainconfig.do_nospace_pass, "after") == 0) {
		rad_rmspace_pair(request, rad_getpass(request));
		reprocess = 1;
	}

	/* Reprocess if we rejected last time */
	if ((fun == rad_authenticate) &&
	    (request->reply->code == PW_AUTHENTICATION_REJECT) &&
	    (reprocess))  {
		pairfree(&request->config_items);
		(*fun)(request);
	}
	
	/*
	 *	If we don't already have a proxy
	 *	packet for this request, we MIGHT have
	 *	to go proxy it.
	 */
	if (proxy_requests) {
		if (request->proxy == NULL) {
			proxy_sent = proxy_send(request);
			
			/*
			 *	sent==1 means it's been proxied.  The child
			 *	is done handling the request, but the request
			 *	is NOT finished!
			 */
			if (proxy_sent == 1) {
				goto postpone_request;
			}
		}
	} else if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
		   (request->reply == NULL)) {
		/*
		 *	We're not configured to reply to the packet,
		 *	and we're not proxying, so the DEFAULT behaviour
		 *	is to REJECT the user.
		 */
		DEBUG2("There was no response configured: rejecting request %d", request->number);
		rad_reject(request);
		goto finished_request;
	}

	/*
	 *	If we have a reply to send, copy the Proxy-State
	 *	attributes from the request to the tail of the reply,
	 *	and send the packet.
	 */
	assert(request->magic == REQUEST_MAGIC);
	if (request->reply->code != 0) {
		VALUE_PAIR *vp = NULL;

		/*
		 *	Perform RFC limitations on outgoing replies.
		 */
		rfc_clean(request->reply);

		/*
		 *	Need to copy Proxy-State from request->packet->vps
		 */
		vp = paircopy2(request->packet->vps, PW_PROXY_STATE);
		if (vp != NULL) pairadd(&(request->reply->vps), vp);

		rad_send(request->reply, request->secret);
	}

	/*
	 *	We're done processing the request, set the
	 *	request to be finished, clean up as necessary,
	 *	and forget about the request.
	 */
 finished_request:
	/*
	 *	We're done handling the request.  Free up the linked
	 *	lists of value pairs.  This might take a long time,
	 *	so it's more efficient to do it in a child thread,
	 *	instead of in the main handler when it eventually
	 *	gets around to deleting the request.
	 *
	 *	Also, no one should be using these items after the
	 *	request is finished, and the reply is sent.  Cleaning
	 *	them up here ensures that they're not being used again.
	 *
	 *	Hmm... cleaning them up in the child thread also seems
	 *	to make the server run more efficiently!
	 */

	/*	If we proxied this request, it's not safe to delete it until
	 *	after the proxy reply
	 */
	if (proxy_sent)
		goto postpone_request;

	if (request->packet && request->packet->vps) {
		pairfree(&request->packet->vps);
		request->username = NULL;
		request->password = NULL;
	}
	if (request->reply && request->reply->vps) {
	  pairfree(&request->reply->vps);
	}

	if (request->config_items) pairfree(&request->config_items);

	DEBUG2("Finished request %d", request->number);
	finished = TRUE;
	
	/*
	 *	Go to the next request, without marking
	 *	the current one as finished.
	 */
 next_request:
	DEBUG2("Going to the next request");

#if WITH_THREAD_POOL
	request->child_pid = NO_SUCH_CHILD_PID;
#endif
	request->finished = finished; /* do as the LAST thing before exiting */

 postpone_request:
	return 0;
}

typedef struct rad_walk_t {
	time_t	now;
	time_t	smallest;
} rad_walk_t;

/*
 *	Clean up the request list, every so often.
 *
 *	This is done by walking through ALL of the list, and
 *	- marking any requests which are finished, and expired
 *	- killing any processes which are NOT finished after a delay
 *	- deleting any marked requests.
 */
static REQUEST *last_request = NULL;
static struct timeval *rad_clean_list(time_t now)
{
	/*
	 *	Static variables, so that we don't do all of this work
	 *	more than once per second.
	 *
	 *	Note that we have 'tv' and 'last_tv'.  'last_tv' is
	 *	pointed to by 'last_tv_ptr', and depending on the
	 *	system implementation of select(), it MAY be modified.
	 *
	 *	In that was, we want to use the ORIGINAL value, from
	 *	'tv', and wipe out the (possibly modified) last_tv.
	 */
	static time_t last_cleaned_list = 0;
	static struct timeval tv, *last_tv_ptr = NULL;
	static struct timeval last_tv;

	rad_walk_t info;

	info.now = now;
	info.smallest = -1;

	/*
	 *	If we've already set up the timeout or cleaned the
	 *	request list this second, then don't do it again.  We
	 *	simply return the sleep delay from last time.
	 *
	 *	Note that if we returned NULL last time, there was nothing
	 *	to do.  BUT we've been woken up since then, which can only
	 *	happen if we received a packet.  And if we've received a
	 *	packet, then there's some work to do in the future.
	 *
	 *	FIXME: We can probably use gettimeofday() for finer clock
	 *	resolution, as the current method will cause it to sleep
	 *	too long...
	 */
	if ((last_tv_ptr != NULL) &&
	    (last_cleaned_list == now) &&
	    (tv.tv_sec != 0)) {		
		int i;

		/*
		 *	If we're NOT walking the entire request list,
		 *	then we want to iteratively check the request
		 *	list.
		 *
		 *	If there is NO previous request, go look for one.
		 */
		if (!last_request) last_request = rl_next(last_request);

		/*
		 *	On average, there will be one request per
		 *	'cleanup_delay' requests, which needs to be
		 *	serviced.
		 *
		 *	And only do this servicing, if we have a request
		 *	to service.
		 */
		if (last_request) for (i = 0; i < cleanup_delay; i++) {
			REQUEST *next;
			
			/*
			 *	This function call MAY delete the
			 *	request pointed to by 'last_request'.
			 */
			next = rl_next(last_request);
			refresh_request(last_request, &info);
			last_request = next;

			/*
			 *	Nothing to do any more, exit.
			 */
			if (!last_request) break;
		}

		last_tv = tv;
		DEBUG2("Waking up in %d seconds...",
		       (int) last_tv_ptr->tv_sec);
		return last_tv_ptr;
	}
	last_cleaned_list = now;
	last_request = NULL;
	DEBUG2("--- Walking the entire request list ---");

#if WITH_THREAD_POOL
	/*
	 *	Only clean the thread pool if we've spawned child threads.
	 */
	if (spawn_flag) {
		thread_pool_clean(now);
	}
#endif
	
	/*
	 *	Hmmm... this is Big Magic.  We make it seem like
	 *	there's an additional second to wait, for a whole
	 *	host of reasons which I can't explain adequately,
	 *	but which cause the code to Just Work Right.
	 */
	info.now--;

	rl_walk(refresh_request, &info);

	/*
	 *	We haven't found a time at which we need to wake up.
	 *	Return NULL, so that the select() call will sleep forever.
	 */
	if (info.smallest < 0) {
		DEBUG2("Nothing to do.  Sleeping until we see a request.");
		last_tv_ptr = NULL;
		return NULL;
	}
	/*
	 *	Set the time (in seconds) for how long we're
	 *	supposed to sleep.
	 */
	tv.tv_sec = info.smallest;
	tv.tv_usec = 0;
	DEBUG2("Waking up in %d seconds...", (int) info.smallest);

	/*
	 *	Remember how long we should sleep for.
	 */
	last_tv = tv;
	last_tv_ptr = &last_tv;
	return last_tv_ptr;
}

/*
 *	Walk through the request list, cleaning up complete child
 *	requests, and verifing that there is only one process
 *	responding to each request (duplicate requests are filtered
 *	out).
 *
 *	Also, check if the request is a reply from a request proxied to
 *	a remote server.  If so, play games with the request, and return
 *	the old one.
 */
static REQUEST *rad_check_list(REQUEST *request)
{
	REQUEST		*curreq;
	time_t		now;

	/*
	 *	If the request has come in on the proxy FD, then
	 *	it's a proxy reply, so pass it through the proxy
	 *	code for checking the REQUEST list.
	 */
	if (request->packet->sockfd == proxyfd) {
		return proxy_check_list(request);

		/*
		 *	If the request already has a proxy packet,
		 *	then it obviously is not a new request, either.
		 */
	} else if (request->proxy != NULL) {
		return request;
	}

	now = request->timestamp; /* good enough for our purposes */

	/*
	 *	Look for an existing copy of this request.
	 */
	curreq = rl_find(request);
	if (curreq != NULL) {
		  /*
		   *	We now check the authentication vectors.
		   *	If the client has sent us a request with
		   *	identical code && ID, but different vector,
		   *	then they MUST have gotten our response, so
		   *	we can delete the original request, and process
		   *	the new one.
		   *
		   *	If the vectors are the same, then it's a duplicate
		   *	request, and we can send a duplicate reply.
		   */
		  if (memcmp(curreq->packet->vector, request->packet->vector,
			    sizeof(request->packet->vector)) == 0) {
			/*
			 *	Maybe we've saved a reply packet.  If so,
			 *	re-send it.  Otherwise, just complain.
			 */
			if (curreq->reply) {
				radlog(L_INFO,
				"Sending duplicate authentication reply"
				" to client %s:%d - ID: %d",
				client_name(curreq->packet->src_ipaddr),
				curreq->packet->src_port,
				curreq->packet->id);

				rad_send(curreq->reply, curreq->secret);

				/*
				 *	There's no reply, but maybe there's
				 *	an outstanding proxy request.
				 *
				 *	If so, then kick the proxy again.
				 */
			} else if (curreq->proxy != NULL) {
				if (proxy_synchronous) {
					DEBUG2("Sending duplicate proxy request to client %s:%d - ID: %d",
					       client_name(curreq->proxy->dst_ipaddr),
					       request->packet->src_port,
					       curreq->proxy->id);

					curreq->proxy_next_try = request->timestamp + proxy_retry_delay;
					rad_send(curreq->proxy, curreq->proxysecret);
				} else {
					DEBUG2("Ignoring duplicate authentication packet"
					       " from client %s:%d - ID: %d, due to outstanding proxy request.",
					       client_name(request->packet->src_ipaddr),
					       request->packet->src_port,
					       request->packet->id);
				}
			} else {
				/*
				 *	This request wasn't proxied.
				 */
				radlog(L_ERR,
				"Dropping duplicate authentication packet"
				" from client %s:%d - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->src_port,
				request->packet->id);
			}

		      	/*
			 *	Delete the duplicate request, and
			 *	stop processing the request list.
			 */
			request_free(&request);
			
			/*
			 *	The packet vectors are different, so
			 *	we can delete the old request from
			 *	the list.
			 */
		  } else if (curreq->finished) {
			  if (last_request == curreq) {
				  last_request = rl_next(last_request);
			  }
			  rl_delete(curreq);

			  /*
			   *	??? the client sent us a new request
			   *	with the same ID, while we were
			   *	processing the old one!  What should
			   *	we do?
			   *
			   *	Right now, we just drop the new packet..
			   */
		  } else {
			  radlog(L_ERR,
				 "Dropping conflicting authentication packet"
				 " from client %s:%d - ID: %d",
				 client_name(request->packet->src_ipaddr),
				 request->packet->src_port,
				 request->packet->id);
			  request_free(&request);
		  }
	} /* a similar packet already exists. */

	/*
	 *	If we've received a duplicate packet, 'request' is NULL,
	 *	and we have nothing more to do.
	 */
	if (request == NULL) {
		return NULL;
	}

	/*
	 *	Count the total number of requests, to see if there
	 *	are too many.  If so, return with an error.
	 */
	if (max_requests) {
		int request_count = rl_num_requests();
		
		/*
		 *	This is a new request.  Let's see if it
		 *	makes us go over our configured bounds.
		 */
		if (request_count > max_requests) {
			radlog(L_ERR, "Dropping request (%d is too many): "
			       "from client %s:%d - ID: %d", request_count, 
			       client_name(request->packet->src_ipaddr),
			       request->packet->src_port,
			       request->packet->id);
			radlog(L_INFO, "WARNING: Please check the radiusd.conf file.\n\tThe value for 'max_requests' is probably set too low.\n");
			request_free(&request);
			return NULL;
		}
	}

	/*
	 *	Add this request to the list
	 */
	rl_add(request);

	/*
	 *	And return the request to be handled.
	 */
	return request;
}

#ifndef WITH_THREAD_POOL
#if HAVE_PTHREAD_H
typedef struct spawn_thread_t {
  REQUEST *request;
  RAD_REQUEST_FUNP fun;
} spawn_thread_t;

/*
 *	If the child *thread* gets a termination signal,
 *	then exit from the thread.
 */
static void sig_term(int sig)
{
	sig = sig;			/* -Wunused */
	pthread_exit(NULL);
}

/*
 *	Spawn a new child thread to handle this request, and ONLY
 *	this request.
 */
static void *rad_spawn_thread(void *arg)
{
	int replicating;
	spawn_thread_t *data = (spawn_thread_t *)arg;
	
	/*
	 *	Note that this behaviour only works on Linux.
	 *
	 *	It's generally NOT the thing to do, and should
	 *	be fixed somehow.
	 *
	 *	Q: How do we signal a hung thread, and tell it to
	 *	kill itself?
	 */
	signal(SIGTERM, sig_term);
	
	/*
	 *	Keep only allowed attributes in the request.
	 */
	if (data->request->proxy) {
		replicating = proxy_receive(data->request);
		if (replicating != 0) {
			data->request->finished = TRUE;
			free(data);
			return NULL;
		}
	}
	
	rad_respond(data->request, data->fun);
	data->request->child_pid = NO_SUCH_CHILD_PID;
	free(data);
	return NULL;
}
#endif
#endif

/*
 *	If we're using the thread pool, then the function in
 *	'threads.c' replaces this one.
 */
#ifndef WITH_THREAD_POOL
/*
 *	Spawns a child process or thread to perform
 *	authentication/accounting and respond to RADIUS clients.
 */
static int rad_spawn_child(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	child_pid_t		child_pid;

#if HAVE_PTHREAD_H
	int rcode;
	spawn_thread_t *data;

	data = (spawn_thread_t *) rad_malloc(sizeof(spawn_thread_t));
	memset(data, 0, sizeof(data));
	data->request = request;
	data->fun = fun;

	/*
	 *	Create a child thread, complaining on error.
	 */
	rcode = pthread_create(&child_pid, NULL, rad_spawn_thread, data);
	if (rcode != 0) {
		radlog(L_ERR, "Thread create failed for request from nas %s - ID: %d : %s",
		    nas_name2(request->packet),
		    request->packet->id,
		    strerror(errno));
		return -1;
	}

	/*
	 *	Detach it, so it's state is automagically cleaned up on exit.
	 */
	pthread_detach(child_pid);

#else
	/*
	 *	fork our child
	 */
	child_pid = fork();
	if (child_pid < 0) {
		radlog(L_ERR, "Fork failed for request from nas %s - ID: %d",
				nas_name2(request->packet),
				request->packet->id);
		return -1;
	}

	if (child_pid == 0) {

		/*
		 *	This is the child, it should go ahead and respond
		 */
		signal(SIGCHLD, SIG_DFL);
		rad_respond(request, fun);
		exit(0);
	}
#endif

	/*
	 *	Register the Child
	 */
	request->child_pid = child_pid;
	return 0;
}
#endif /* WITH_THREAD_POOL */

/*ARGSUSED*/
void sig_cleanup(int sig)
{
#ifndef HAVE_PTHREAD_H
	int		i;
	int		status;
        child_pid_t	pid;
	REQUEST		*curreq;
#endif

	sig = sig; /* -Wunused */
 
	got_child = FALSE;

	/*
	 *	Reset the signal handler, if required.
	 */
	reset_signal(SIGCHLD, sig_cleanup);
	
	/*
	 *  If we're using pthreads, then there are NO child processes,
	 *  so the waitpid() call, and the following code, is useless.
	 */
#ifndef HAVE_PTHREAD_H
        for (;;) {
		pid = waitpid((pid_t)-1, &status, WNOHANG);
                if (pid <= 0)
                        return;

		/*
		 *	Check to see if the child did a bad thing.
		 *	If so, kill ALL processes in the current
		 *	process group, to prevent further attacks.
		 */
		if (debug_flag && (WIFSIGNALED(status))) {
			radlog(L_ERR|L_CONS, "MASTER: Child PID %d failed to catch signal %d: killing all active servers.\n",
			    pid, WTERMSIG(status));
			kill(0, SIGTERM);
			exit(1);
		}

		/*
		 *	Loop over ALL of the active requests, looking
		 *	for the one which caused the signal.
		 */
		for (curreq = rl_next(NULL); curreq != NULL; curreq = rl_next(curreq)) {
			if (curreq->child_pid == pid) {
				curreq->child_pid = NO_SUCH_CHILD_PID;
				break;
		}
        }
#endif /* !defined HAVE_PTHREAD_H */
}

/*
 *	Display the syntax for starting this program.
 */
static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [-a acct_dir] [-d db_dir] [-l log_dir] [-i address] [-p port] [-"
#if defined(WITH_DBM) || defined(WITH_NDBM)
		"b"
#endif
		"AcfnsSvXxyz]\n", progname);
	fprintf(stderr, "Options:\n\n");
	fprintf(stderr, "  -a acct_dir     use accounting directory 'acct_dir'.\n");
	fprintf(stderr, "  -A              Log auth detail.\n");
#if defined(WITH_DBM) || defined(WITH_NDBM)
	fprintf(stderr, "  -b              Use DBM.\n");
#endif
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
 *	We got a fatal signal. Clean up and exit.
 */
static void sig_fatal(int sig)
{
	const char *me = "MASTER: ";

	if (radius_pid != getpid()) {
		me = "CHILD: ";
	}

	switch(sig) {
		case 100:
			radlog(L_ERR, "%saccounting process died - exit.", me);
			break;
		case 101:
			radlog(L_ERR, "%sfailed in select() - exit.", me);
			break;
		case SIGTERM:
			radlog(L_INFO, "%sexit.", me);
			break;
		default:
			radlog(L_ERR, "%sexit on signal (%d)", me, sig);
			break;
	}

	/*
	 *	We're running as a daemon, we're the MASTER daemon,
	 *	and we got a fatal signal.  Tear the rest of the
	 *	daemons down, as something absolutely horrible happened.
	 */
	if ((debug_flag == 0) && (dont_fork == 0) &&
	    (radius_pid == getpid())) {
		/*
		 *      Kill all of the processes in the current
		 *	process group.
		 */
		kill(0, SIGKILL);
	}

	exit(sig == SIGTERM ? 0 : 1);
}


/*
 *	We got the hangup signal.
 *	Re-read the configuration files.
 */
/*ARGSUSED*/
static void sig_hup(int sig)
{
	sig = sig; /* -Wunused */
	reset_signal(SIGHUP, sig_hup);

	/*
	 *	Only do the reload if we're the main server, both
	 *	for processes, and for threads.
	 */
	if (getpid() == radius_pid) {
		need_reload = TRUE;
	}
}

/*
 *	Do a proxy check of the REQUEST list when using the new proxy code.
 */
static REQUEST *proxy_check_list(REQUEST *request)
{
	REQUEST *oldreq;
	
	/*
	 *	Find the original request in the request list
	 */
	oldreq = rl_find_proxy(request);
	if (oldreq) {
		/*
		 *	If there is already a reply,
		 *	maybe the new one is a duplicate?
		 */
		if (oldreq->proxy_reply) {
			if (memcmp(oldreq->proxy_reply->vector,
				   request->packet->vector,
				   sizeof(oldreq->proxy_reply->vector)) == 0) {
				DEBUG2("Ignoring duplicate proxy reply");
				request_free(&request);
				return NULL;
			} else {
				/*
				 *	??? The home server gave us a new
				 *	proxy reply, which doesn't match
				 *	the old one.  Delete it!
				 */
				DEBUG2("Ignoring conflicting proxy reply");
				request_free(&request);
				return NULL;
			}
		} /* else there's no reply yet. */

	} else {
		/*
		 *	If we haven't found the old request, complain.
		 */
		radlog(L_PROXY, "Unrecognized proxy reply from server %s - ID %d",
		       client_name(request->packet->src_ipaddr),
		       request->packet->id);
		request_free(&request);
		return NULL;
	}

	/*
	 *	Refresh the old request, and update it with the proxy reply.
	 *
	 *	??? Can we delete the proxy request here?
	 *	Is there any more need for it?
	 */
	oldreq->timestamp = request->timestamp;
	oldreq->proxy_reply = request->packet;
	request->packet = NULL;
	request_free(&request);
	return oldreq;
}

/*
 *	Refresh a request, by using proxy_retry_delay, cleanup_delay,
 *	max_request_time, etc.
 *
 *	When walking over the request list, all of the per-request
 *	magic is done here.
 */
static int refresh_request(REQUEST *request, void *data)
{
	rad_walk_t *info = (rad_walk_t *) data;
	time_t		difference;
	child_pid_t    	child_pid;

	assert(request->magic == REQUEST_MAGIC);

	/*
	 *	If the request has finished processing,
	 *	AND it's child has been cleaned up,
	 *	AND it's time to clean up the request,
	 *	    OR, it's an accounting request.
	 *	THEN, go delete it.
	 *
	 *	If this is an accounting request, we delete it
	 *	immediately, as there CANNOT be duplicate accounting
	 *	packets.  If there are, then something else is
	 *	seriously wrong...
	 */
	if (request->finished &&
	    (request->child_pid == NO_SUCH_CHILD_PID) &&
	    ((request->timestamp + cleanup_delay <= info->now) ||
	     (request->packet->code == PW_ACCOUNTING_REQUEST))) {
		/*
		 *	Request completed, delete it, and unlink it
		 *	from the currently 'alive' list of requests.
		 */
		DEBUG2("Cleaning up request %d ID %d with timestamp %08lx",
		       request->number, request->packet->id,
		       (unsigned long)request->timestamp);
		
		/*
		 *	Delete the request.
		 */
		rl_delete(request);
		return RL_WALK_CONTINUE;
	}

	/*
	 *	Maybe the child process
	 *	handling the request has hung:
	 *	kill it, and continue.
	 */
	if ((request->timestamp + max_request_time) <= info->now) {
		if (request->child_pid != NO_SUCH_CHILD_PID) {
			/*
			 *	This request seems to have hung
			 *	 - kill it
			 */
			child_pid = request->child_pid;
			radlog(L_ERR, "Killing unresponsive child %d for request %d",
			       child_pid, request->number);
			child_kill(child_pid, SIGTERM);
		} /* else no proxy reply, quietly fail */
		
		/*
		 *	Delete the request.
		 */
		rl_delete(request);
		return RL_WALK_CONTINUE;
	}

	/*
	 *	The request is finished.
	 */
	if (request->finished) goto setup_timeout;

	/*
	 *	We're not proxying requests at all.
	 */
	if (!proxy_requests) goto setup_timeout;

	/*
	 *	We're proxying synchronously, so the retry_delay is zero.
	 *	Some other code takes care of retrying the proxy requests.
	 */
	if (proxy_retry_delay == 0) goto setup_timeout;

	/*
	 *	There is no proxied request for this packet, so there's
	 *	no proxy retries.
	 */
	if (!request->proxy) goto setup_timeout;

	/*
	 *	We've already seen the proxy reply, so we don't need
	 *	to send another proxy request.
	 */
	if (request->proxy_reply) goto setup_timeout;

	/*
	 *	It's not yet time to re-send this proxied request.
	 */
	if (request->proxy_next_try > info->now) goto setup_timeout;
	
	/*
	 *	If the proxy retry count is zero, then
	 *	we've sent the last try, and have NOT received
	 *	a reply from the end server.  In that case,
	 *	we don't bother trying again, but just mark
	 *	the request as finished, and go to the next one.
	 */
	if (request->proxy_try_count == 0) {
		request->finished = TRUE;
		rad_reject(request);
		goto setup_timeout;
	}

	/*
	 *	We're trying one more time, so count down
	 *	the tries, and set the next try time.
	 */
	request->proxy_try_count--;
	request->proxy_next_try = info->now + proxy_retry_delay;
		
	/* Fix up Acct-Delay-Time */
	if (request->proxy->code == PW_ACCOUNTING_REQUEST) {
		VALUE_PAIR *delaypair;
		delaypair = pairfind(request->proxy->vps, PW_ACCT_DELAY_TIME);
		
		if (!delaypair) {
			delaypair = paircreate(PW_ACCT_DELAY_TIME,
					       PW_TYPE_INTEGER);
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
	 *	Send the proxy packet.
	 */
	rad_send(request->proxy, request->proxysecret);

 setup_timeout:
	/*
	 *	Don't do more long-term checks, if we've got to wake
	 *	up now.
	 */
	if (info->smallest == 0) {
		return RL_WALK_CONTINUE;
	}

	/*
	 *	The request is finished.  Wake up when it's time to
	 *	clean it up.
	 */
	if (request->finished) {
		difference = (request->timestamp + cleanup_delay) - info->now;
		
	} else if (request->proxy && !request->proxy_reply) {
		/*
		 *	The request is NOT finished, but there is an
		 *	outstanding proxy request, with no matching
		 *	proxy reply.
		 *
		 *	Wake up when it's time to re-send
		 *	the proxy request.
		 */
		difference = request->proxy_next_try - info->now;
		
	} else {
		/*
		 *	The request is NOT finished.
		 *
		 *	Wake up when it's time to kill the errant
		 *	thread/process.
		 */
		difference = (request->timestamp + max_request_time) - info->now;
	}

	/*
	 *	If the server is CPU starved, then we CAN miss a time
	 *	for servicing requests.  In which case the 'difference'
	 *	value will be negative.  select() doesn't like that,
	 *	so we fix it.
	 */
	if (difference < 0) {
		difference = 0;
	}

	/*
	 *	Update the 'smallest' time.
	 */
	if ((info->smallest < 0) ||
	    (difference < info->smallest)) {
		info->smallest = difference;
	}

	return RL_WALK_CONTINUE;
}
