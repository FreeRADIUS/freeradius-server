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

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>
#include	<sys/resource.h>
#if HAVE_GETOPT_H
#  include	<getopt.h>
#endif
#if HAVE_SYS_SELECT_H
#  include	<sys/select.h>
#endif

#if HAVE_SYSLOG_H
#include	<syslog.h>
#endif

#if HAVE_PTHREAD_H
#include	<pthread.h>
#endif

#include <assert.h>

#include	"radiusd.h"
#include	"conffile.h"

/*
 *	Global variables.
 */
const char		*progname = NULL;
const char	        *radius_dir = NULL;
const char		*radacct_dir = NULL;
const char		*radlog_dir = NULL;
int			log_stripped_names;
int 			cache_passwd = FALSE;
int			debug_flag;
int			use_dbm	= FALSE;
uint32_t		myip = INADDR_ANY;
int			log_auth_detail	= FALSE;
int			log_auth = FALSE;
int			log_auth_pass  = FALSE;
int			auth_port;
int			acct_port;
int			proxy_port;

static int		got_child = FALSE;
static int		request_list_busy = FALSE;
static int		authfd;
static int		acctfd;
int	        	proxyfd;
static int		spawn_flag = TRUE;
static int		radius_pid;
static int		need_reload = FALSE;
static struct rlimit	core_limits;
static time_t		last_cleaned_list;

/*
 *  We keep the incoming requests in an array, indexed by ID.
 *
 *  Each array element contains a linked list of active requests,
 *  a count of the number of requests, and a time at which the first
 *  request in the list must be serviced.
 */
typedef struct REQUEST_LIST {
  REQUEST	*first_request;
  int		request_count;
  time_t	service_time;
} REQUEST_LIST;

static REQUEST_LIST	request_list[256];

/*
 *  Configuration items.
 */
static int		allow_core_dumps = FALSE;
static int		max_request_time = MAX_REQUEST_TIME;
static int		cleanup_delay = CLEANUP_DELAY;
static int		max_requests = MAX_REQUESTS;
static const char	*pid_file = NULL;

#if !defined(__linux__) && !defined(__GNU_LIBRARY__)
extern int	errno;
#endif

static void	usage(void);

static void	sig_fatal (int);
static void	sig_hup (int);

static int	rad_process (REQUEST *, int);
static int	rad_clean_list(void);
static REQUEST	*rad_check_list(REQUEST *);
static REQUEST *proxy_check_list(REQUEST *request);
#ifndef WITH_THREAD_POOL
static void	rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#else
extern void	rad_spawn_child(REQUEST *, RAD_REQUEST_FUNP);
#endif

/*
 *	A mapping of configuration file names to internal integers
 */
CONF_PARSER rad_config[] = {
  { "max_request_time",   PW_TYPE_INTEGER,    &max_request_time },
  { "cleanup_delay",      PW_TYPE_INTEGER,    &cleanup_delay    },
  { "max_requests",       PW_TYPE_INTEGER,    &max_requests     },
  { "allow_core_dumps",   PW_TYPE_INTEGER,    &allow_core_dumps },
  { "log_stripped_names", PW_TYPE_INTEGER,    &log_stripped_names },
  { "log_auth",           PW_TYPE_INTEGER,    &log_auth },
  { "log_auth_pass",      PW_TYPE_INTEGER,    &log_auth_pass },
  { "pidfile",            PW_TYPE_STRING_PTR, &pid_file },
#if 0
  { "confdir",            PW_TYPE_STRING_PTR, &radius_dir },
#endif

  { NULL, -1, NULL}
};

/*
 *	Read config files.
 */
static void reread_config(int reload)
{
	int res = 0;
	int pid = getpid();

	if (allow_core_dumps) {
		if (setrlimit(RLIMIT_CORE, &core_limits) < 0) {
			log(L_ERR|L_CONS, "Cannot update core dump limit: %s",
			    strerror(errno));
			exit(1);

		} else if (core_limits.rlim_cur != 0)
		  log(L_INFO, "Core dumps are enabled.");


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
			log(L_ERR|L_CONS, "Cannot disable core dumps: %s",
			    strerror(errno));
			exit(1);
		}
	}

	if (!reload) {
		log(L_INFO, "Starting - reading configuration files ...");
	} else if (pid == radius_pid) {
		log(L_INFO, "Reloading configuration files.");
	}

	/* Read users file etc. */
	if (res == 0 && read_config_files() != 0)
		res = -1;

	if (res != 0) {
	  if (pid == radius_pid) {
			log(L_ERR|L_CONS,
				"Errors reading config file - EXITING");
		}
		exit(1);
	}
}


int main(int argc, char **argv)
{
	RADCLIENT		*cl;
	REQUEST			*request;
	RADIUS_PACKET		*packet;
#ifdef RADIUS_PID
	FILE			*fp;
#endif
	unsigned char		buffer[4096];
	struct	sockaddr	salocal;
	struct	sockaddr_in	saremote;
	struct	sockaddr_in	*sin;
	struct	servent		*svp;
	fd_set			readfds;
	struct timeval		tv, *tvp;
	int			salen;
	int			packet_length;
	uint32_t		packet_srcip;
	int			packet_code;
	int			result;
	int			argval;
	int			t;
	int			pid;
	int			i;
	int			fd = 0;
	int			devnull;
	int			status;
	int			dont_fork = FALSE;
	int			radius_port = 0;

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
	radacct_dir = RADACCT_DIR ;
	radius_dir = strdup(RADIUS_DIR);
	radlog_dir = RADLOG_DIR ;
	pid_file = strdup(RADIUS_PID);

	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_fatal);
	signal(SIGQUIT, sig_fatal);
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
	while((argval = getopt(argc, argv, "Aa:bcd:fhi:l:np:sSvxXyz")) != EOF) {

		switch(argval) {

		case 'A':
			log_auth_detail = TRUE;
			break;

		case 'a':
			radacct_dir = optarg;
			break;
		
#if defined(WITH_DBM) || defined(WITH_NDBM)
		case 'b':
			use_dbm++;
			break;
#endif
		case 'c':
			cache_passwd = TRUE;
			break;

		case 'd':
			free(radius_dir);
			radius_dir = strdup(optarg);
			break;
		
		case 'f':
			dont_fork = TRUE;
			break;

		case 'h':
			usage();
			break;

		case 'i':
			if ((myip = ip_getaddr(optarg)) == INADDR_ANY) {
				fprintf(stderr, "radiusd: %s: host unknown\n",
					optarg);
				exit(1);
			}
			break;
		
		case 'l':
			radlog_dir = optarg;
			break;

		case 'n':
			librad_dodns = FALSE;
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
#ifndef WITH_THREAD_POOL
			spawn_flag = FALSE;
#endif
			dont_fork = TRUE;
			debug_flag = 2;
			librad_debug = 2;
			log_auth = TRUE;
			log_auth_pass = TRUE;
			radlog_dir = "stdout";
			break;

		case 'x':
			debug_flag++;
			librad_debug++;
			break;
		
		case 'y':
			log_auth = TRUE;
			break;

		case 'z':
			log_auth_pass = TRUE;
			break;

		default:
			usage();
			break;
		}
	}

#if HAVE_SYSLOG_H
	/*
	 *	If they asked for syslog, then give it to them.
	 */
	if (strcmp(radlog_dir, "syslog") == 0) {
		openlog("radiusd", LOG_PID, LOG_DAEMON);
	}
#endif

	/*
	 *	Initialize the request_list[] array.
	 */
	for (i = 0; i < 256; i++) {
	  request_list[i].first_request = NULL;
	  request_list[i].request_count = 0;
	  request_list[i].service_time = 0;
	}

	/*
	 *	Open Authentication socket.
	 */
	svp = getservbyname ("radius", "udp");
	if (radius_port)
		auth_port = radius_port;
	else if (svp != NULL)
		auth_port = ntohs(svp->s_port);
	else
		auth_port = PW_AUTH_UDP_PORT;

	authfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (authfd < 0) {
		perror("auth socket");
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = myip;
	sin->sin_port = htons(auth_port);

	result = bind (authfd, & salocal, sizeof (*sin));
	if (result < 0) {
		perror ("auth bind");
		exit(1);
	}

	/*
	 *	Open Accounting Socket.
	 */
	svp = getservbyname ("radacct", "udp");
	if (radius_port || svp == (struct servent *) 0)
		acct_port = auth_port + 1;
	else
		acct_port = ntohs(svp->s_port);
	
	acctfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (acctfd < 0) {
		perror ("acct socket");
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = myip;
	sin->sin_port = htons(acct_port);

	result = bind (acctfd, & salocal, sizeof (*sin));
	if (result < 0) {
		perror ("acct bind");
		exit(1);
	}

	/*
	 *	Open Proxy Socket.
	 */
	proxyfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (proxyfd < 0) {
		perror ("proxy socket");
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = myip;

	/*
	 *	Set the proxy port to be one more than the
	 *	accounting port.
	 */
	for (proxy_port = acct_port + 1; proxy_port < 64000; proxy_port++) {
		sin->sin_port = htons(proxy_port);
		result = bind (proxyfd, & salocal, sizeof (*sin));
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

	radius_pid = getpid();
#ifdef RADIUS_PID
	/*
	 *	Only write the PID file if we're running as a daemon.
	 */
	if (dont_fork == FALSE) {
		fp = fopen(pid_file, "w");
		if (fp != NULL) {
			fprintf(fp, "%d\n", radius_pid);
			fclose(fp);
		} else {
			log(L_ERR|L_CONS, "Failed writing process id to file %s: %s\n",
			    pid_file, strerror(errno));
		}
	}
#endif


	/*
	 *	Get the current maximum for core files.
	 */
	if (getrlimit(RLIMIT_CORE, &core_limits) < 0) {
		log(L_ERR|L_CONS, "Failed to get current core limit:"
		    "  %s", strerror(errno));
		exit(1);
	}
		
	/*
	 *	Read config files.
	 */
	reread_config(0);

	/*
	 *	Register built-in compare functions.
	 */
	pair_builtincompare_init();

	/*
	 *  Initialize other, miscellaneous variables.
	 */
	last_cleaned_list = time(NULL);

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
	if(debug_flag == 0 && dont_fork == 0) {
		pid = fork();
		if(pid < 0) {
			log(L_ERR|L_CONS, "Couldn't fork");
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

#ifdef WITH_THREAD_POOL
	/*
	 *  This really should only be just after the 'setsid()', above.
	 *  That way, we only create the thread pool for daemon mode.
	 */
	thread_pool_init();
#endif

	/*
	 *	Use linebuffered or unbuffered stdout if
	 *	the debug flag is on.
	 */
	if (debug_flag) setlinebuf(stdout);

	log(L_INFO, "Listening on ports %d/udp and %d/udp, with proxy on %d/udp.",
	    auth_port, acct_port, proxy_port);

	/*
	 *	Note that we NO LONGER fork an accounting process!
	 *	We used to do it for historical reasons, but that
	 *	is no excuse...
	 */
	log(L_INFO, "Ready to process requests.");

	/*
	 *	Receive user requests
	 */
	for(;;) {
		if (need_reload) {
			reread_config(1);
			need_reload = FALSE;
		}

		FD_ZERO(&readfds);
		if (authfd >= 0)
			FD_SET(authfd, &readfds);
		if (acctfd >= 0)
			FD_SET(acctfd, &readfds);
		if (proxyfd >= 0)
			FD_SET(proxyfd, &readfds);
		tvp = proxy_setuptimeout(&tv);

		status = select(32, &readfds, NULL, NULL, tvp);
		if (status == -1) {
			/*
			 *	On interrupts, we clean up the
			 *	request list.
			 */
			if (errno == EINTR) {
				rad_clean_list();
				continue;
			}
			sig_fatal(101);
		}
		if (status == 0) {
			proxy_retry();
			rad_clean_list();
		}
		for (i = 0; i < 3; i++) {

			if (i == 0) fd = authfd;
			if (i == 1) fd = acctfd;
			if (i == 2) fd = proxyfd;
			if (fd < 0 || !FD_ISSET(fd, &readfds))
				continue;

			/*
			 *	Quickly see if we can actually receive
			 *	the packet.
			 *	If so, steal the source IP, and see if
			 *	they're allowed to talk to us.
			 *
			 *	Aarrg.. we really don't care to see the data,
			 *	but certain broken kernels don't fill in
			 *	the sockaddr function if we get 0 bytes.
			 */
			salen = sizeof(saremote);
			memset(&saremote, 0, sizeof(saremote));
			packet_length = recvfrom(fd, buffer, sizeof(buffer),
						 MSG_PEEK,
						 (struct sockaddr *)&saremote,
						 &salen);
			if (packet_length < 0) {
				log(L_ERR,
				    "Failed to received packet on FD %d: %s",
				    fd, strerror(errno));
				continue;
			}
			packet_code = buffer[0];
			packet_srcip = saremote.sin_addr.s_addr;
			ip_ntoa(buffer, packet_srcip);

			/*
			 *	Check if we know this client.
			 *	The check is performed HERE, instead of
			 *	after rad_recv(), so unknown clients CANNOT
			 *	force us to do ANY work.
			 */
			if ((cl = client_find(packet_srcip)) == NULL) {
				log(L_ERR, "Ignoring request from unknown client %s",
					buffer);
				/* eat the packet silently, and continue */
				recvfrom(fd, buffer, sizeof(buffer), 0,
					 (struct sockaddr *)&saremote,
					 &salen);
				continue;
			}

			/*
			 *	Do yet another check, to see if the
			 *	packet code is valid.  We only understand
			 *	a few, so stripping off obviously invalid
			 *	packets here will make our life easier.
			 */
			if (packet_code > PW_ACCESS_CHALLENGE) {
				log(L_ERR, "Ignoring request from client %s with unknown code %d", buffer, packet_code);
				/* eat the packet silently, and continue */
				recvfrom(fd, buffer, sizeof(buffer), 0,
					 (struct sockaddr *)&saremote,
					 &salen);
				continue;
			}

			packet = rad_recv(fd);
			if (packet == NULL) {
				log(L_ERR, "%s", librad_errstr);
				continue;
			}

#ifndef WITH_THREAD_POOL
			/*
			 *	If using thread pools, this work is
			 *	pushed onto the child threads.
			 */
			if (rad_decode(packet, cl->secret) != 0) {
				log(L_ERR, "%s", librad_errstr);
				rad_free(packet);
				continue;
			}
#endif

			if ((request = malloc(sizeof(REQUEST))) == NULL) {
				log(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			memset(request, 0, sizeof(REQUEST));
			request->packet = packet;
			request->proxy = NULL;
			request->reply = NULL;
			request->proxy_reply = NULL;
			request->config_items = NULL;
			request->username = pairfind(request->packet->vps, PW_USER_NAME);
			request->password = NULL;
			request->timestamp = time(NULL);
			request->child_pid = NO_SUCH_CHILD_PID;
			request->prev = NULL;
			request->next = NULL;
			strcpy(request->secret, cl->secret);
			rad_process(request, spawn_flag);

			/*
			 *	After processing the current request,
			 *	check if we've got to delete old requests
			 *	from the request list.
			 */
			rad_clean_list();
		}
	}
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
	int replicating = 0;

	fun = NULL;

	switch(request->packet->code) {

	case PW_AUTHENTICATION_REQUEST:
		/*
		 *	Check for requests sent to the wrongport,
		 *	and ignore them, if so.
		 */
		if (request->packet->sockfd != authfd) {
		  log(L_ERR, "Request packet code %d sent to authentication port from "
		      "client %s - ID %d : IGNORED",
		      request->packet->code,
		      client_name(request->packet->src_ipaddr),
		      request->packet->id);
		  request_free(request);
		  return -1;
		}
		break;

	case PW_ACCOUNTING_REQUEST:
		/*
		 *	Check for requests sent to the wrong port,
		 *	and ignore them, if so.
		 */
		if (request->packet->sockfd != acctfd) {
		  log(L_ERR, "Request packet code %d sent to accounting port from "
		      "client %s - ID %d : IGNORED",
		      request->packet->code,
		      client_name(request->packet->src_ipaddr),
		      request->packet->id);
		  request_free(request);
		  return -1;
		}
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
			log(L_ERR, "Reply packet code %d sent to request port from "
			    "client %s - ID %d : IGNORED",
			    request->packet->code,
			    client_name(request->packet->src_ipaddr),
			    request->packet->id);
			request_free(request);
			return -1;
		}
		break;
	}

	/*
	 *	Select the required function and indicate if
	 *	we need to fork off a child to handle it.
	 */
	switch(request->packet->code) {

	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_AUTHENTICATION_REQUEST:
		fun = rad_authenticate;
		break;
	
	case PW_ACCOUNTING_RESPONSE:
	case PW_ACCOUNTING_REQUEST:
		fun = rad_accounting;
		break;
	
	case PW_PASSWORD_REQUEST:
		/*
		 *	We don't support this anymore.
		 */
		log(L_ERR, "Deprecated password change request from client %s "
		    "- ID %d : IGNORED",
		    client_name(request->packet->src_ipaddr),
		    request->packet->id);
		request_free(request);
		return -1;
		break;
	
	default:
		log(L_ERR, "Unknown packet type %d from client %s "
		    "- ID %d : IGNORED",
		    request->packet->code,
		    client_name(request->packet->src_ipaddr),
		    request->packet->id);
		request_free(request);
		return -1;
		break;
	}

	/*
	 *	If we did NOT select a function, then exit immediately.
	 */
	if (!fun) {
		request_free(request);
		return 0;
	}

	/*
	 *	Check for a duplicate, or error.
	 *	Throw away the the request if so.
	 */
	request = rad_check_list(request);
	if (request == NULL) {
		return 0;
	}
	
	/*
	 *	If we're spawning a child thread, let it do all of
	 *	the work of handling a request, and exit.
	 */
	if (dospawn) {
		rad_spawn_child(request, fun);
		return 0;
	}

#ifndef WITH_THREAD_POOL
	/*
	 *	Keep only allowed attributes in the request.
	 */
	if (request->proxy) {
		replicating = proxy_receive(request);
		if (replicating != 0) {
			request->finished = TRUE;
			return 0;
		}
	}
#endif
	/*
	 *	We're the one who's supposed to handle the request,
	 *	as everyone else gave up on it.  Let's do so.
	 */
	(*fun)(request);
	rad_respond(request);

	/*
	 *	And the request is in the REQUEST_LIST, so we can't
	 *	delete it...
	 */

	return 0;
}

/*
 *	Respond to a request packet.
 *
 *	Maybe we reply, maybe we don't.
 *	Maybe we proxy the request to another server, or else maybe
 *	we replicate it to another server.
 */
int rad_respond(REQUEST *request)
{
	/*
	 *	If we don't already have a proxy
	 *	packet for this request, we MIGHT have
	 *	to go proxy it.
	 */
	if (request->proxy == NULL) {
		int sent;
		sent = proxy_send(request);

		/*
		 *	sent==1 means it's been proxied.  The child
		 *	is done handling the request, but the request
		 *	is NOT finished!
		 */
		if (sent == 1) {
#ifdef WITH_THREAD_POOL
			request->child_pid = NO_SUCH_CHILD_PID;
#endif
			return 0;
		}

#if 0
	} else {
		if (replicating != 0) {
			/* ??? */
		}
#endif
	}
	
	if (request->reply)
		rad_send(request->reply, request->secret);
	
#ifdef WITH_THREAD_POOL
	request->child_pid = NO_SUCH_CHILD_PID;
#endif
	request->finished = TRUE;
	return 0;
}

/*
 *	Clean up the request list, every so often.
 *
 *	This is done by walking through ALL of the list, and
 *	- joining any child threads which have exited.  (If not pooling)
 *	- killing any processes which are NOT finished after a delay
 *	- deleting any requests which are finished, and expired
 */
static int rad_clean_list(void)
{
	REQUEST		*curreq;
	REQUEST		*prevreq;
	time_t		curtime;
	child_pid_t    	child_pid;
	int		id;
	int		request_count;
	int		cleaned = FALSE;

	curtime = time(NULL);

	/*
	 *  Don't bother checking the list if we've done it
	 *  within the last second.
	 */
	if ((curtime - last_cleaned_list) == 0) {
		return FALSE;
	}

	DEBUG2("Cleaning up request list after %d seconds",
	       (int) (curtime - last_cleaned_list));
	
#ifdef WITH_THREAD_POOL
	thread_pool_clean();
#endif

	/*
	 *	When mucking around with the request list, we block
	 *	asynchronous access (through the SIGCHLD handler) to
	 *	the list - equivalent to sigblock(SIGCHLD).
	 */
	request_list_busy = TRUE;
		
	for (id = 0; id < 256; id++) {
		curreq = request_list[id].first_request;
		prevreq = NULL;

		while (curreq != NULL) {
			assert((curreq->finished == FALSE) ||
			       (curreq->reply != NULL));
			/*
			 *	We don't join threads which are in the pool.
			 */
#ifndef WITH_THREAD_POOL
#ifdef HAVE_PTHREAD_H
			/*
			 *	If the child request has finished, then
			 *	join it (to delete it's stack, etc), and
			 *	mark it as really done.
			 */
			if (curreq->finished &&
			    curreq->child_pid != NO_SUCH_CHILD_PID) {
			  
			  DEBUG2("Joining child thread %d\n", curreq->child_pid);
			  pthread_join(curreq->child_pid, NULL);
			  curreq->child_pid = NO_SUCH_CHILD_PID;
			}
#endif
#endif

			/*
			 *	Maybe the child process handling the request
			 *	has hung: kill it, and continue.
			 */
			if (!curreq->finished &&
			    (curreq->timestamp + max_request_time) <= curtime) {
				if (curreq->child_pid != NO_SUCH_CHILD_PID) {
					/*
					 *	This request seems to have hung
					 *	 - kill it
					 */
					child_pid = curreq->child_pid;
					log(L_ERR, "Killing unresponsive child %d",
					    child_pid);
					child_kill(child_pid, SIGTERM);
				} /* else no proxy reply, quietly fail */

				/*
				 *	Mark the request as unsalvagable.
				 */
				curreq->child_pid = NO_SUCH_CHILD_PID;
				curreq->finished = TRUE;
				curreq->timestamp = 0;
			}
		
			/*
			 *	Delete the current request, if it's
			 *	marked as such.  That is, the request
			 *	must be finished, there must be no
			 *	child associated with that request,
			 *	and it's timestamp must be marked to
			 *	be deleted.
			 */
			if (curreq->finished &&
			    (curreq->child_pid == NO_SUCH_CHILD_PID) &&
			    (curreq->timestamp + cleanup_delay <= curtime)) {
				/*
				 *	Request completed, delete it,
				 *	and unlink it from the
				 *	currently 'alive' list of
				 *	requests.
				 */
				DEBUG2("Cleaning up request ID %d with timestamp %08x",
				       curreq->packet->id, curreq->timestamp);
				prevreq = curreq->prev;
				if (request_list[id].request_count == 0) {
				  DEBUG("HORRIBLE ERROR!!!");
				} else {
				  request_list[id].request_count--;
				  cleaned = TRUE;
				}

				if (prevreq == NULL) {
					request_list[id].first_request = curreq->next;
					request_free(curreq);
					curreq = request_list[id].first_request;
				} else {
					prevreq->next = curreq->next;
					request_free(curreq);
					curreq = prevreq->next;
				}
				if (curreq)
					curreq->prev = prevreq;
				
			} else {	/* the request is still alive */
				prevreq = curreq;
				curreq = curreq->next;
			}
		} /* end of walking the request list for that ID */
	} /* for each entry in the request list array */

	request_count = 0;
	for (id = 0; id < 256; id++) {
		request_count += request_list[id].request_count;
	}
	DEBUG2("%d requests left in the list", request_count);

	/*
	 *	We're done playing with the request list.
	 */
	request_list_busy = FALSE;
	last_cleaned_list = curtime;

	return cleaned;
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
	REQUEST		*prevreq;
	RADIUS_PACKET	*pkt;
	int		request_count;
	REQUEST_LIST	*request_list_entry;
	int		i;
	time_t		curtime;
	int		id;

	/*
	 *	If the request has come in on the proxy FD, then
	 *	it's a proxy reply, so pass it through the proxy
	 *	code for checking the REQUEST_LIST.
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

	request_list_entry = &request_list[request->packet->id];

	assert((request_list_entry->first_request == NULL) ||
	       (request_list_entry->request_count != 0));
	assert((request_list_entry->first_request != NULL) ||
	       (request_list_entry->request_count == 0));
	curreq = request_list_entry->first_request;
	prevreq = NULL;
	pkt = request->packet;
	request_count = 0;
	curtime = time(NULL);
	id = pkt->id;

	/*
	 *	When mucking around with the request list, we block
	 *	asynchronous access (through the SIGCHLD handler) to
	 *	the list - equivalent to sigblock(SIGCHLD).
	 */
	request_list_busy = TRUE;

	while (curreq != NULL) {
		assert(curreq->packet->id == pkt->id);

		/*
		 *	Let's see if we received a duplicate of
		 *	a packet we already have in our list.
		 *
		 *	We do this be checking the src IP, (NOT port)
		 *	the packet code, and ID.
		 */
		if ((curreq->packet->src_ipaddr == pkt->src_ipaddr) &&
		    (curreq->packet->code == pkt->code)) {
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
		  if (memcmp(curreq->packet->vector, pkt->vector,
			    sizeof(pkt->vector)) == 0) {
			/*
			 *	Maybe we've saved a reply packet.  If so,
			 *	re-send it.  Otherwise, just complain.
			 */
			if (curreq->reply) {
				log(L_INFO,
				"Sending duplicate authentication reply"
				" to client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);
				rad_send(curreq->reply, curreq->secret);

				/*
				 *	There's no reply, but maybe there's
				 *	an outstanding proxy request.
				 */
			} else if (curreq->proxy_reply != NULL) {
				/* FIXME: kick the remote server again ? */
				DEBUG2("DUPLICATE got proxy reply???");
			} else {
				log(L_ERR,
				"Dropping duplicate authentication packet"
				" from client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);

			}

		      	/*
			 *	Delete the duplicate request, and
			 *	continue processing the request list.
			 */
			request_free(request);
			request = NULL;
			break;
		  } else {
			  /*
			   *	The packet vectors are different, so
			   *	we can mark the old request to be
			   *	deleted from the list.
			   *
			   *	Note that we don't actually delete it...
			   *	Maybe we should?
			   */
			  if (curreq->finished) {
				  curreq->timestamp = 0;
			  } else {
				  /*
				   *	??? the client sent us a new request
				   *	with the same ID, while we were processing
				   *	the old one!  What should we do?
				   */
			  }
		  }
		}

		/*
		 *	Ugh... duplicated code is bad...
		 */

		/*
		 *	Delete the current request, if it's
		 *	marked as such.  That is, the request
		 *	must be finished, there must be no
		 *	child associated with that request,
		 *	and it's timestamp must be marked to
		 *	be deleted.
		 */
		if (curreq->finished &&
		    (curreq->child_pid == NO_SUCH_CHILD_PID) &&
		    (curreq->timestamp + cleanup_delay <= curtime)) {
				/*
				 *	Request completed, delete it,
				 *	and unlink it from the
				 *	currently 'alive' list of
				 *	requests.
				 */
			DEBUG2("Cleaning up request ID %d with timestamp %08x",
			       curreq->packet->id, curreq->timestamp);
			prevreq = curreq->prev;
			if (request_list[id].request_count == 0) {
				DEBUG("HORRIBLE ERROR!!!");
			} else {
				request_list[id].request_count--;
			}
			
			if (prevreq == NULL) {
				request_list[id].first_request = curreq->next;
				request_free(curreq);
				curreq = request_list[id].first_request;
			} else {
				prevreq->next = curreq->next;
				request_free(curreq);
				curreq = prevreq->next;
			}
			if (curreq)
				curreq->prev = prevreq;
			
		} else {	/* the request is still alive */
			prevreq = curreq;
			curreq = curreq->next;
			request_count++;
		}
	} /* end of walking the request list */
	
	/*
	 *	If we've received a duplicate packet, 'request' is NULL.
	 */
	if (request == NULL) {
		request_list_busy = FALSE;
		return NULL;
	}

	assert(request_list_entry->request_count == request_count);

	/*
	 *	Count the total number of requests, to see if there
	 *	are too many.  If so, stop counting immediately,
	 *	and return with an error.
	 */
	request_count = 0;
	for (i = 0; i < 256; i++) {
		request_count += request_list[i].request_count;

		/*
		 *	This is a new request.  Let's see if it
		 *	makes us go over our configured bounds.
		 */
		if (request_count > max_requests) {
			/*
			 *	Too many: clean the request list,
			 *	if we can.  This work is done here,
			 *	as it's got to be done SOMETIME in the
			 *	main thread, and now is as good as ever.
			 *
			 *	If we can't, then die horribly.
			 */
			if (rad_clean_list() == TRUE) {
				return rad_check_list(request);
			}

			log(L_ERR, "Dropping request (%d is too many): "
			    "from client %s - ID: %d", request_count, 
			    client_name(request->packet->src_ipaddr),
			    request->packet->id);
			sig_cleanup(SIGCHLD);
			request_free(request);
			request_list_busy = FALSE;
			return NULL;
		}
	}

	/*
	 *	Add this request to the list
	 */
	request->prev = prevreq;
	request->next = NULL;
	request->child_pid = NO_SUCH_CHILD_PID;
	request_list_entry->request_count++;

	if (prevreq == NULL) {
		assert(request_list_entry->first_request == NULL);
		assert(request_list_entry->request_count == 1);
		request_list_entry->first_request = request;
	} else {
		assert(request_list_entry->first_request != NULL);
		prevreq->next = request;
	}

	/*
	 *	And return the request to be handled.
	 */
	request_list_busy = FALSE;
	return request;
}

#ifndef WITH_THREAD_POOL
#ifdef HAVE_PTHREAD_H
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
	
	signal(SIGTERM, sig_term);
	
	/*
	 *	Keep only allowed attributes in the request.
	 */
	if (request->proxy) {
		replicating = proxy_receive(request);
		if (replicating != 0) {
			request->finished = TRUE;
			free(data);
			return NULL;
		}
	}
	
	(*(data->fun))(data->request);
	rad_respond(data->request);
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
static void rad_spawn_child(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	child_pid_t		child_pid;

#ifdef HAVE_PTHREAD_H
	int rcode;
	spawn_thread_t *data;

	data = (spawn_thread_t *) malloc(sizeof(spawn_thread_t));
	memset(data, 0, sizeof(data));
	data->request = request;
	data->fun = fun;

	/*
	 *	Create a child thread, complaining on error.
	 */
	rcode = pthread_create(&child_pid, NULL, rad_spawn_thread, data);
	if (rcode != 0) {
	  log(L_ERR, "Thread create failed for request from nas %s - ID: %d : %s",
	      nas_name2(request->packet),
	      request->packet->id,
	      strerror(errno));
	}

#else
	/*
	 *	fork our child
	 */
	child_pid = fork();
	if (child_pid < 0) {
		log(L_ERR, "Fork failed for request from nas %s - ID: %d",
				nas_name2(request->packet),
				request->packet->id);
	}

	if (child_pid == 0) {

		/*
		 *	This is the child, it should go ahead and respond
		 */
		signal(SIGCHLD, SIG_DFL);
		(*fun)(request);
		rad_respond(request);
		exit(0);
	}
#endif

	/*
	 *	Register the Child
	 */
	request->child_pid = child_pid;

	sig_cleanup(SIGCHLD);
}
#endif /* WITH_THREAD_POOL */

/*ARGSUSED*/
void sig_cleanup(int sig)
{
	int		i;
	int		status;
        pid_t		pid;
	REQUEST		*curreq;
 
	/*
	 *	request_list_busy is a lock on the request list
	 */
	if (request_list_busy) {
		got_child = TRUE;
		return;
	}
	got_child = FALSE;

	/*
	 *	Reset the signal handler, if required.
	 */
	reset_signal(SIGCHLD, sig_cleanup);
	
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
			log(L_ERR|L_CONS, "MASTER: Child PID %d failed to catch signal %d: killing all active servers.\n",
			    pid, WTERMSIG(status));
			kill(0, SIGTERM);
			exit(1);
		}

		/*
		 *	Service all of the requests in the queues
		 */
		for (i = 0; i < 256; i++) {
			curreq = request_list[i].first_request;
			while (curreq != (REQUEST *)NULL) {
				if (curreq->child_pid == pid) {
					curreq->child_pid = NO_SUCH_CHILD_PID;
					curreq->timestamp = time(NULL);
					break;
				}
				curreq = curreq->next;
			}
		}
        }
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
	fprintf(stderr, "  -c              Cache /etc/passwd, /etc/shadow, and /etc/group.\n");
	fprintf(stderr, "  -d db_dir       Use database directory 'db_dir'.\n");
	fprintf(stderr, "  -f              Run as a foreground process, not a daemon.\n");
	fprintf(stderr, "  -h              Print this help message.\n");
	fprintf(stderr, "  -i address      Listen only in the given IP address.\n");
	fprintf(stderr, "  -l log_dir      Log messages to 'log_dir'.  Special values are:\n");
	fprintf(stderr, "                  stdout == log all messages to standard output.\n");
	fprintf(stderr, "                  syslog == log all messages to the system logger.\n");
	fprintf(stderr, "  -n              Do not do DNS host name lookups.\n");
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

	if (radius_pid == getpid()) {
		/*
		 *      Kill all of the processes in the current
		 *	process group.
		 */
		kill(0, SIGKILL);
	} else {
		me = "CHILD: ";
	}

	switch(sig) {
		case 100:
			log(L_ERR, "%saccounting process died - exit.", me);
			break;
		case 101:
			log(L_ERR, "%sfailed in select() - exit.", me);
			break;
		case SIGTERM:
			log(L_INFO, "%sexit.", me);
			break;
		default:
			log(L_ERR, "%sexit on signal (%d)", me, sig);
			break;
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
	reset_signal(SIGHUP, sig_hup);
	need_reload = TRUE;
}

/*
 *	Do a proxy check of the REQUEST_LIST when using the new proxy code.
 *
 *	This function is here because it has to access the REQUEST_LIST
 *	structure, which is 'static' to this C file.
 */
static REQUEST *proxy_check_list(REQUEST *request)
{
	int id;
	REQUEST *oldreq;
	RADIUS_PACKET *pkt;
	
	/*
	 *	Find the original request in the request list
	 */
	oldreq = NULL;
	pkt = request->packet;
	
	for (id = 0; (id < 256) && (oldreq == NULL); id++) {
		for (oldreq = request_list[id].first_request ;
		     oldreq != NULL ;
		     oldreq = oldreq->next) {
			
			/*
			 *	See if this reply packet matches a proxy
			 *	packet which we sent.
			 */
			if (oldreq->proxy &&
			    (oldreq->proxy->dst_ipaddr == pkt->src_ipaddr) &&
			    (oldreq->proxy->dst_port == pkt->src_port) &&
			    (oldreq->proxy->id == pkt->id)) {
				/*
				 *	If there is already a reply,
				 *	maybe the new one is a duplicate?
				 */
				if (oldreq->proxy_reply) {
					if (memcmp(oldreq->proxy_reply->vector,
						   request->packet->vector,
						   sizeof(oldreq->proxy_reply->vector)) == 0) {
						DEBUG2("Ignoring duplicate proxy reply");
						request_free(request);
						return NULL;
					} else {
						/*
						 *	got other stuff...
						 */
						continue;
					}
				} /* else no reply, this one must match */
				break;
			}
		}
	}
	
	/*
	 *	If we haven't found the old request, complain.
	 */
	if (oldreq == NULL) {
		request_free(request);
		log(L_PROXY, "Unrecognized proxy reply from server %s - ID %d",
		    client_name(request->packet->src_ipaddr),
		    request->packet->id);
		return NULL;
	}

	/*
	 *	Refresh the old request,. and update it.
	 */
	oldreq->timestamp += 5;
	oldreq->proxy_reply = request->packet;
	request->packet = NULL;
	request_free(request);
	return oldreq;
}
