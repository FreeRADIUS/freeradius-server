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

#include	"radiusd.h"

/*
 *	Global variables.
 */
const char		*progname;
const char	        *radius_dir;
const char		*radacct_dir;
const char		*radlog_dir;
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
int			proxyfd;

static int		got_child = FALSE;
static int		request_list_busy = FALSE;
static int		sockfd;
static int		acctfd;
static int		spawn_flag = FALSE;
static int		radius_pid;
static int		need_reload = FALSE;
static REQUEST		*first_request = NULL;
static int		allow_core_dumps = FALSE;
static struct rlimit	core_limits;

#if !defined(__linux__) && !defined(__GNU_LIBRARY__)
extern int	errno;
#endif

typedef		int (*FUNP)(REQUEST *);

static void	usage(void);

static void	sig_fatal (int);
static void	sig_hup (int);

static int	rad_process (REQUEST *);
static int	rad_respond (REQUEST *);
static REQUEST	*rad_check_list(REQUEST *);
static void	rad_spawn_child(REQUEST *, FUNP, int, int);

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
	CLIENT			*cl;
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
	radacct_dir = RADACCT_DIR;
	radius_dir = RADIUS_DIR;
	radlog_dir = RADLOG_DIR;

	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_fatal);
	signal(SIGQUIT, sig_fatal);
#ifdef SIGTRAP
	signal(SIGTRAP, sig_fatal);
#endif
#ifdef SIGIOT
	signal(SIGIOT, sig_fatal);
#endif
	signal(SIGTERM, sig_fatal);
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
			radius_dir = optarg;
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
			spawn_flag = FALSE;
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
	 *	Open Authentication socket.
	 */
	svp = getservbyname ("radius", "udp");
	if (radius_port)
		auth_port = radius_port;
	else if (svp != NULL)
		auth_port = ntohs(svp->s_port);
	else
		auth_port = PW_AUTH_UDP_PORT;

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("auth socket");
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = myip;
	sin->sin_port = htons(auth_port);

	result = bind (sockfd, & salocal, sizeof (*sin));
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
	 *  Pick a pseudo-random initial proxy port,
	 *  somewhere above 1024.
	 *
	 *  Hmmm.... this tells everyone in the world what out process ID
	 *  is, which might not be such a good idea...
	 */
	for (proxy_port = (getpid() & 0x7fff) + 1024; proxy_port < 64000; proxy_port++) {
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
	if ((fp = fopen(RADIUS_PID, "w")) != NULL) {
		fprintf(fp, "%d\n", radius_pid);
		fclose(fp);
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

	/*
	 *	Disconnect from session
	 */
	if(debug_flag == 0 && dont_fork == 0) {
		pid = fork();
		if(pid < 0) {
			log(L_ERR|L_CONS, "Couldn't fork");
			exit(1);
		}
		if(pid > 0) {
			exit(0);
		}
#ifdef HAVE_SETSID
		setsid();
#endif
	}
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
		if (sockfd >= 0)
			FD_SET(sockfd, &readfds);
		if (acctfd >= 0)
			FD_SET(acctfd, &readfds);
		if (proxyfd >= 0)
			FD_SET(proxyfd, &readfds);
		tvp = proxy_setuptimeout(&tv);

		status = select(32, &readfds, NULL, NULL, tvp);
		if (status == -1) {
			if (errno == EINTR)
				continue;
			sig_fatal(101);
		}
		if (status == 0)
			proxy_retry();
		for (i = 0; i < 3; i++) {

			if (i == 0) fd = sockfd;
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

			if (rad_decode(packet, cl->secret) != 0) {
				log(L_ERR, "%s", librad_errstr);
				rad_free(packet);
				continue;
			}
			if ((request = malloc(sizeof(REQUEST))) == NULL) {
				log(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			memset(request, 0, sizeof(REQUEST));
			request->packet = packet;
			request->proxy = NULL;
			request->reply = NULL;
			request->config_items = NULL;
			request->username = pairfind(request->packet->vps, PW_USER_NAME);
			request->password = NULL;
			request->timestamp = time(NULL);
			request->child_pid = NO_SUCH_CHILD_PID;
			request->prev = NULL;
			request->next = NULL;
			strcpy(request->secret, cl->secret);
			rad_process(request);
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
int rad_process(REQUEST *request)
{
	int dospawn;
	FUNP fun;
	int already_proxied=0;
	int replicating=0;

	dospawn = FALSE;
	fun = NULL;

	switch(request->packet->code) {

	case PW_AUTHENTICATION_REQUEST:
	case PW_ACCOUNTING_REQUEST:
		/*
		 *	Check for requests sent to the proxy port,
		 *	and ignore them, if so.
		 */
		if (request->packet->sockfd == proxyfd) {
		  log(L_ERR, "Request packet code %d sent to proxy port from "
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
		 *	Replies sent to the proxy port get passed through
		 *	the proxy receive code.  All other replies get
		 *	an error message logged, and the packet is dropped.
		 */
		if (request->packet->sockfd == proxyfd) {
			int recvd=proxy_receive(request);
			if (recvd < 0) {
				return -1;
			}
			already_proxied=1;
			replicating=recvd;
			break;
		}
		/* NOT proxyfd: fall through to error message */

		log(L_ERR, "Reply packet code %d sent to request port from "
		    "client %s - ID %d : IGNORED",
		    request->packet->code,
		    client_name(request->packet->src_ipaddr),
		    request->packet->id);
		return -1;
		break;
	}

	/*
	 *	Select the required function and indicate if
	 *	we need to fork off a child to handle it.
	 */
	switch(request->packet->code) {

	case PW_AUTHENTICATION_REQUEST:
		dospawn = spawn_flag;
		fun = rad_authenticate;
		break;
	
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
		return -1;
		break;
	

	default:
		log(L_ERR, "Unknown packet type %d from client %s "
		    "- ID %d : IGNORED",
		    request->packet->code,
		    client_name(request->packet->src_ipaddr),
		    request->packet->id);
		return -1;
		break;
	}

	/*
	 *	If we did select a function, execute it
	 */
	if (fun) {
		/*
		 *	Check for a duplicate, or error.
		 *	Throw away the the request if so.
		 */
		request = rad_check_list(request);
		if (request == NULL) {
			request_list_busy = FALSE;
			return 0;
		}

		if (dospawn) {
			rad_spawn_child(request, fun,
					already_proxied, replicating);
			/* AFTER spawning the child */
			request_list_busy = FALSE;
		} else {
			/* BEFORE doing the request */
			request_list_busy = FALSE;
			(*fun)(request);
			if(!already_proxied) {
				int sent;
				sent=proxy_send(request);
				if(sent==0 || sent==2)
					rad_respond(request);
			} else {
				if(!replicating)
					rad_respond(request);
			}
		}
	}

	return 0;
}

/*
 *	Respond to a request packet.
 *
 *	Maybe we reply, maybe we don't.
 *	Maybe we proxy the request to another server, or else maybe
 *	we replicate it to another server.
 */
static int rad_respond(REQUEST *request)
{
  if (request->reply)
  	rad_send(request->reply, request->secret);

  request->finished = TRUE;
  return 0;
}


/*
 *	Walk through the request list, cleaning up complete child
 *	requests, and verifing that there is only one process
 *	responding to each request (duplicate requests are filtered
 *	out).
 */
static REQUEST *rad_check_list(REQUEST *request)
{
	REQUEST		*curreq;
	REQUEST		*prevreq;
	RADIUS_PACKET	*pkt;
	time_t		curtime;
	int		request_count;
	child_pid_t    	child_pid;

	curtime = time(NULL);
	request_count = 0;
	curreq = first_request;
	prevreq = NULL;
	pkt = request->packet;

	/*
	 *	When mucking around with the request list, we block
	 *	asynchronous access (through the SIGCHLD handler) to
	 *	the list - equivalent to sigblock(SIGCHLD).
	 */
	request_list_busy = TRUE;

	while (curreq != (REQUEST *)NULL) {
		/*
		 *	Let's see if we received a duplicate of
		 *	a packet we already have in our list.
		 *
		 *	We do this be checking the src IP, (NOT port)
		 *	the packet code, ID, and authentication vectors.
		 */
		if (request &&
		    (curreq->packet->src_ipaddr == pkt->src_ipaddr) &&
		    (curreq->packet->code == pkt->code) &&
		    (curreq->packet->id == pkt->id) &&
		    (memcmp(curreq->packet->vector, pkt->vector,
			    sizeof(pkt->vector)) == 0)) {
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
		} /* checks for duplicate packets */

		/*
		 *	Maybe the child process handling the request
		 *	has hung: kill it, and continue.
		 */
		if (curreq->timestamp + MAX_REQUEST_TIME <= curtime &&
		    curreq->child_pid != NO_SUCH_CHILD_PID) {
			/*
			 *	This request seems to have hung - kill it
			 */
			child_pid = curreq->child_pid;
			log(L_ERR, "Killing unresponsive child pid %d",
			    child_pid);
			kill(child_pid, SIGTERM);

			/*
			 *	Mark the request as unsalvagable.
			 */
			curreq->child_pid = NO_SUCH_CHILD_PID;
			curreq->finished = TRUE;
			curreq->timestamp = 0;
		}
		
		/*
		 *	Delete the current request, if it's marked as such.
		 *	That is, the request must be finished, there must
		 *	be no child associated with that request, and it's
		 *	timestamp must be marked to be deleted.
		 */
		if (curreq->finished &&
		    (curreq->child_pid == NO_SUCH_CHILD_PID) &&
		    (curreq->timestamp + CLEANUP_DELAY <= curtime)) {
			/*
			 *	Request completed, delete it,
			 *	and unlink it from the currently 'alive'
			 *	list of requests.
			 */
			prevreq = curreq->prev;

			if (prevreq == (REQUEST *)NULL) {
				first_request = curreq->next;
				request_free(curreq);
				curreq = first_request;
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
		return NULL;
	}

	/*
	 *	This is a new request.
	 */
	if (request_count > MAX_REQUESTS) {
		log(L_ERR, "Dropping request (too many): "
				"from client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);
		sig_cleanup(SIGCHLD);
		request_free(request);
		return NULL;
	}

	/*
	 *	Add this request to the list
	 */
	request->prev = prevreq;
	request->next = (REQUEST *)NULL;
	request->child_pid = NO_SUCH_CHILD_PID;
	request->timestamp = curtime;

	if (prevreq == (REQUEST *)NULL)
		first_request = request;
	else
		prevreq->next = request;

	/*
	 *	And return the request to be handled.
	 */
	return request;
}

/* Remove a request from the pending list without looking at it or freeing
 * it. Called from proxy code when it wants to take over */
void remove_from_request_list(REQUEST *request)
{
  REQUEST *prevreq;
  REQUEST *curreq;

  for(prevreq=0,curreq=first_request;curreq;curreq=curreq->next) {
    if(curreq==request) {
      if(prevreq)
	prevreq->next=request->next;
      else
	first_request=request->next;
      break;
    }
  }
}

/*
 *	Spawns a child process or thread to perform
 *	authentication/accounting and respond to RADIUS clients.
 */
static void rad_spawn_child(REQUEST *request, FUNP fun,
			    int already_proxied, int replicating)
{
	child_pid_t		child_pid;

#if 0
	/*
	 *	FIXME!!!
	 *
	 *	When threading is done, wrap with
	 * #ifdef HAVE_PTHREAD_H, etc.
	 **/
	int rcode;

	/*
	 *	Create a child thread, complaining on error.
	 */
	rcode = pthread_create(&child_pid, NULL, fun, request);
	if (rcode != 0) {
		log(L_ERR, "Thread create failed for request from nas %s - ID: %d : %s",
				nas_name2(request->packet),
				request->packet->id,
		                strerror(errno));
	}
	/* respond to the request ??? */
#endif
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
		request_list_busy = FALSE;
		signal(SIGCHLD, SIG_DFL);
		(*fun)(request);
		rad_respond(request);
		exit(0);
	}

	/*
	 *	Register the Child
	 */
	request->child_pid = child_pid;

	sig_cleanup(SIGCHLD);
}

/*ARGSUSED*/
void sig_cleanup(int sig)
{
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

		curreq = first_request;
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
