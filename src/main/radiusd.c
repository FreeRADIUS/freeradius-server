/*
 * radiusd.c	Main loop of the radius server.
 *
 * Version:	@(#)radiusd.c  1.90  22-Jul-1999  miquels@cistron.nl
 *
 */

/* don't look here for the version, run radiusd -v or look in version.c */
char radiusd_sccsid[] =
"@(#)radiusd.c	1.90 Copyright 1999 Cistron Internet Services B.V.";

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
#if HAVE_GETOPT_H
#  include	<getopt.h>
#endif
#if HAVE_SYS_SELECT_H
#  include	<sys/select.h>
#endif

#include	"radiusd.h"

/*
 *	Global variables.
 */
char			*progname;
char			*radius_dir;
char			*radacct_dir;
char			*radlog_dir;
int			log_stripped_names;
int 			cache_passwd = 0;
int			debug_flag;
int			use_dbm = 0;
UINT4			myip = 0;
int			log_auth_detail = 0;
int			log_auth = 0;
int			log_auth_pass  = 0;
int			auth_port;
int			acct_port;

static int		got_chld = 0;
static int		request_list_busy = 0;
static int		sockfd;
static int		acctfd;
static int		spawn_flag;
static int		acct_pid;
static int		radius_pid;
static int		need_reload = 0;
static REQUEST		*first_request;

#if !defined(__linux__) && !defined(__GNU_LIBRARY__)
extern int	errno;
#endif

typedef		int (*FUNP)(REQUEST *, int);

static void	usage(void);

static void	sig_fatal (int);
static void	sig_hup (int);

static int	radrespond (REQUEST *, int);
static void	rad_spawn_child (REQUEST *, int, FUNP);

/*
 *	Read config files.
 */
static void reread_config(int reload)
{
	int res = 0;
	int pid = getpid();

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
			if (acct_pid) {
				signal(SIGCHLD, SIG_DFL);
				kill(acct_pid, SIGTERM);
			}
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
	struct	sockaddr	salocal;
	struct	sockaddr_in	*sin;
	struct	servent		*svp;
	fd_set			readfds;
	int			result;
	int			argval;
	int			t;
	int			pid;
	int			i;
	int			fd = 0;
	int			status;
	int			dontfork = 0;
	int			radius_port = 0;

#ifdef OSFC2
	set_auth_parameters(argc,argv);
#endif

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	debug_flag = 0;
	spawn_flag = 1;
	radacct_dir = RADACCT_DIR;
	radius_dir = RADIUS_DIR;
	radlog_dir = RADLOG_DIR;

	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_fatal);
	signal(SIGQUIT, sig_fatal);
	signal(SIGTRAP, sig_fatal);
	signal(SIGIOT, sig_fatal);
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
			close(t);

	/*
	 *	Process the options.
	 */
	while((argval = getopt(argc, argv, "ASa:ci:l:d:bfp:svxyz")) != EOF) {

		switch(argval) {

		case 'A':
			log_auth_detail++;
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
			cache_passwd = 1;
			break;

		case 'd':
			radius_dir = optarg;
			break;
		
		case 'f':
			dontfork = 1;
			break;

		case 'i':
			if ((myip = ip_getaddr(optarg)) == 0) {
				fprintf(stderr, "radiusd: %s: host unknown\n",
					optarg);
				exit(1);
			}
			break;
		
		case 'l':
			radlog_dir = optarg;
			break;
		
		case 'S':
			log_stripped_names++;
			break;

		case 'p':
			radius_port = atoi(optarg);
			break;

		case 's':	/* Single process mode */
			spawn_flag = 0;
			break;

		case 'v':
			version();
			break;

		case 'x':
			debug_flag++;
			librad_debug++;
			break;
		
		case 'y':
			log_auth = 1;
			break;

		case 'z':
			log_auth_pass = 1;
			break;

		default:
			usage();
			break;
		}
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

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("auth socket");
		exit(1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = myip ? myip : INADDR_ANY;
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
	sin->sin_addr.s_addr = myip ? myip : INADDR_ANY;
	sin->sin_port = htons(acct_port);

	result = bind (acctfd, & salocal, sizeof (*sin));
	if (result < 0) {
		perror ("acct bind");
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
	 *	Read config files.
	 */
	reread_config(0);

	/*
	 *	Register built-in compare functions.
	 */
	pair_builtincompare_init();

	/*
	 *	Disconnect from session
	 */
	if(debug_flag == 0 && dontfork == 0) {
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

#if !defined(M_UNIX) && !defined(__linux__)
	/*
	 *	Open system console as stderr
	 */
	if (!debug_flag) {
		t = open("/dev/console", O_WRONLY | O_NOCTTY);
		if (t != 2) {
			dup2(t, 2);
			close(t);
		}
	}
#endif
	/*
	 *	If we are in forking mode, we will start a child
	 *	to listen for Accounting requests.  If not, we will 
	 *	listen for them ourself.
	 */
	if (spawn_flag) {
		acct_pid = fork();
		if(acct_pid < 0) {
			log(L_ERR|L_CONS, "Couldn't fork");
			exit(1);
		}
		if(acct_pid > 0) {
			close(acctfd);
			acctfd = -1;
			log(L_INFO, "Ready to process requests.");
		}
		else {
			close(sockfd);
			sockfd = -1;
		}
	} else
		log(L_INFO, "Ready to process requests.");


	/*
	 *	Receive user requests
	 */
	for(;;) {

		if (need_reload) {
			reread_config(1);
			need_reload = 0;
			if (getpid() == radius_pid && acct_pid)
				kill(acct_pid, SIGHUP);
		}

		FD_ZERO(&readfds);
		if (sockfd >= 0)
			FD_SET(sockfd, &readfds);
		if (acctfd >= 0)
			FD_SET(acctfd, &readfds);

		status = select(32, &readfds, NULL, NULL, NULL);
		if (status == -1) {
			if (errno == EINTR)
				continue;
			sig_fatal(101);
		}
		for (i = 0; i < 2; i++) {

			if (i == 0) fd = sockfd;
			if (i == 1) fd = acctfd;
			if (fd < 0 || !FD_ISSET(fd, &readfds))
				continue;

			packet = rad_recv(fd);
			if (packet == NULL) continue;

			/*
			 *	See if we know this client.
			 */
			if ((cl = client_find(packet->src_ipaddr)) == NULL) {
				log(L_ERR, "request from unknown client: %s",
					ip_hostname(packet->src_ipaddr));
					rad_free(packet);
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
			request->timestamp = time(NULL);
			strcpy(request->secret, cl->secret);
			radrespond(request, fd);
		}
	}
}


/*
 *	Respond to supported requests:
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
int radrespond(REQUEST *request, int activefd)
{
	int dospawn;
	FUNP fun;
	VALUE_PAIR *namepair;
	int e;

	dospawn = 0;
	fun = NULL;

	/*
	 *	First, see if we need to proxy this request.
	 */
	switch(request->packet->code) {

	case PW_AUTHENTICATION_REQUEST:
	case PW_ACCOUNTING_REQUEST:
		/*
		 *	Setup username and stuff.
		 */
		if ((e = rad_mangle(request)) < 0)
			return e;
		namepair = pairfind(request->packet->vps, PW_USER_NAME);
		if (namepair == NULL)
			break;
		/*
		 *	We always call proxy_send, it returns non-zero
		 *	if it did actually proxy the request.
		 */
		if (proxy_send(request, activefd) != 0)
			return 0;
		break;

	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_ACCOUNTING_RESPONSE:
		if (proxy_receive(request, activefd) < 0)
			return 0;
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
		 *	FIXME: print an error message here.
		 *	We don't support this anymore.
		 */
		/* rad_passchange(request, activefd); */
		break;
	

	default:
		break;
	}

	/*
	 *	If we did select a function, execute it
	 *	(perhaps through rad_spawn_child)
	 */
	if (fun) {
		if (dospawn)
			rad_spawn_child(request, activefd, fun);
		else {
			(*fun)(request, activefd);
			request_free(request);
		}
	}

	return 0;
}


/*
 *	Spawns child processes to perform authentication/accounting
 *	and respond to RADIUS clients.  This functions also
 *	cleans up complete child requests, and verifies that there
 *	is only one process responding to each request (duplicate
 *	requests are filtered out).
 */
static void rad_spawn_child(REQUEST *request, int activefd, FUNP fun)
{
	REQUEST		*curreq;
	REQUEST		*prevreq;
	RADIUS_PACKET	*pkt;
	UINT4		curtime;
	int		request_count;
	int		child_pid;

	curtime = (UINT4)time(NULL);
	request_count = 0;
	curreq = first_request;
	prevreq = (REQUEST *)NULL;
	pkt = request->packet;

	/*
	 *	When mucking around with the request list, we block
	 *	asynchronous access (through the SIGCHLD handler) to
	 *	the list - equivalent to sigblock(SIGCHLD).
	 */
	request_list_busy = 1;

	while(curreq != (REQUEST *)NULL) {
		if (curreq->child_pid == -1 &&
		    curreq->timestamp + CLEANUP_DELAY <= curtime) {
			/*
			 *	Request completed, delete it
			 */
			if (prevreq == (REQUEST *)NULL) {
				first_request = curreq->next;
				request_free(curreq);
				curreq = first_request;
			} else {
				prevreq->next = curreq->next;
				request_free(curreq);
				curreq = prevreq->next;
			}
		} else if (curreq->packet->src_ipaddr == pkt->src_ipaddr &&
			   curreq->packet->id == pkt->id) {
			/*
			 *	Compare the request vectors to see
			 *	if it really is the same request.
			 */
			if (!memcmp(curreq->packet->vector, pkt->vector, 16)) {
				/*
				 * This is a duplicate request - just drop it
				 */
				log(L_ERR,
				"Dropping duplicate authentication packet"
				" from client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);

				request_free(request);
				request_list_busy = 0;
				sig_cleanup(SIGCHLD);

				return;
			}
			/*
			 *	If the old request was completed,
			 *	delete it right now.
			 */
			if (curreq->child_pid == -1) {
				curreq->timestamp = curtime - CLEANUP_DELAY;
				continue;
			}

			/*
			 *	Not completed yet, do nothing special.
			 */
			prevreq = curreq;
			curreq = curreq->next;
			request_count++;
		} else {
			if (curreq->timestamp + MAX_REQUEST_TIME <= curtime &&
			    curreq->child_pid != -1) {
				/*
				 *	This request seems to have hung -
				 *	kill it
				 */
				child_pid = curreq->child_pid;
				log(L_ERR,
					"Killing unresponsive child pid %d",
								child_pid);
				curreq->child_pid = -1;
				kill(child_pid, SIGTERM);
			}
			prevreq = curreq;
			curreq = curreq->next;
			request_count++;
		}
	}

	/*
	 *	This is a new request
	 */
	if (request_count > MAX_REQUESTS) {
		log(L_ERR, "Dropping request (too many): "
				"from client %s - ID: %d",
				client_name(request->packet->src_ipaddr),
				request->packet->id);
		request_free(request);

		request_list_busy = 0;
		sig_cleanup(SIGCHLD);
				
		return;
	}

	/*
	 *	Add this request to the list
	 */
	request->next = (REQUEST *)NULL;
	request->child_pid = -1;
	request->timestamp = curtime;

	if (prevreq == (REQUEST *)NULL)
		first_request = request;
	else
		prevreq->next = request;

	/*
	 *	fork our child
	 */
	if ((child_pid = fork()) < 0) {
		log(L_ERR, "Fork failed for request from nas %s - ID: %d",
				nas_name2(request->packet),
				request->packet->id);
	}
	if (child_pid == 0) {
		/*
		 *	This is the child, it should go ahead and respond
		 */
		request_list_busy = 0;
		signal(SIGCHLD, SIG_DFL);
		(*fun)(request, activefd);
		exit(0);
	}

	/*
	 *	Register the Child
	 */
	request->child_pid = child_pid;

	request_list_busy = 0;
	sig_cleanup(SIGCHLD);
}


/*ARGSUSED*/
void sig_cleanup(int sig)
{
	int		status;
        pid_t		pid;
	REQUEST	*curreq;
 
	/*
	 *	request_list_busy is a lock on the request list
	 */
	if (request_list_busy) {
		got_chld = 1;
		return;
	}
	got_chld = 0;

	/*
	 *	There are reports that this line on Solaris 2.5.x
	 *	caused trouble. Should be fixed now that Solaris
	 *	[defined(sun) && defined(__svr4__)] has it's own
	 *	sun_signal() function.
	 */
	signal(SIGCHLD, sig_cleanup);

        for (;;) {
		pid = waitpid((pid_t)-1, &status, WNOHANG);
                if (pid <= 0)
                        return;

		if (pid == acct_pid)
			sig_fatal(100);

		curreq = first_request;
		while (curreq != (REQUEST *)NULL) {
			if (curreq->child_pid == pid) {
				curreq->child_pid = -1;
				/*
				 *	FIXME: UINT4 ?
				 */
				curreq->timestamp = (UINT4)time(NULL);
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
#if defined(WITH_DBM) || defined(WITH_NDBM)
		"Usage: %s [-a acct_dir] [-d db_dir] [-l logdir] [-bcsxyz]\n",
#else
		"Usage: %s [-a acct_dir] [-d db_dir] [-l logdir] [-csxyz]\n",
#endif
		progname);
	exit(1);
}


/*
 *	We got a fatal signal. Clean up and exit.
 */
static void sig_fatal(int sig)
{
	char *me = "MASTER: ";

	if (radius_pid == getpid()) {
		/*
		 *      FIXME: kill all children, not only the
		 *      accounting process. Oh well..
		 */
		if (acct_pid > 0)
			kill(acct_pid, SIGKILL);
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
	signal(SIGHUP, sig_hup);
	need_reload = 1;
}

