/*
 * radclient	General radius packet debug tool.
 *
 * Version:	$Id$
 *
 */

#include	"autoconf.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<ctype.h>
#include	<netdb.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>
#include <errno.h>

#if HAVE_SYS_SELECT_H
#  include      <sys/select.h>
#endif

#if HAVE_ERRNO_H
#  include      <errno.h>
#endif

#if HAVE_GETOPT_H
#  include	<getopt.h>
#endif

#include	"conf.h"
#include	"libradius.h"
#include	"radpaths.h"

/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
static VALUE_PAIR *readvp(FILE *fp)
{
	char		buf[128];
	int 		eol;
	char		*p;
	VALUE_PAIR	*vp;
	VALUE_PAIR	*list;
	int		error = 0;

	list = NULL;

	while (!error && fgets(buf, sizeof(buf), fp) != NULL) {

		p = buf;
		do {
			if ((vp = pairread(&p, &eol)) == NULL) {
				librad_perror("radclient:");
				error = 1;
				break;
			}
			pairadd(&list, vp);
		} while (!eol);
	}
	return error ? NULL: list;
}

static void usage(void)
{
	fprintf(stderr, "Usage: radclient [-d raddb ] [-f file] [-r retries] [-t timeout] [-nx]\n		server acct|auth <secret>\n");
	exit(1);
}

static int getport(const char *name)
{
	struct	servent		*svp;

	svp = getservbyname (name, "udp");
	if (!svp) {
		return 0;
	}

	return ntohs(svp->s_port);
}

int main(int argc, char **argv)
{
	RADIUS_PACKET	*req;
	RADIUS_PACKET	*rep = NULL;
	struct timeval	tv;
	char		*p;
	const char	*secret = "secret";
	int		do_output = 1;
	int		c;
	int		port = 0;
	int		retries = 10;
	float		timeout = 3;
	int		i;
	const char	*radius_dir = RADDBDIR;
	char		*filename = NULL;
	FILE		*fp;

	while ((c = getopt(argc, argv, "d:f:nt:r:xv")) != EOF) switch(c) {
		case 'd':
			radius_dir = optarg;
			break;
       		case 'f':
			filename = optarg;
			break;
		case 'n':
			do_output = 0;
			break;
		case 'x':
			librad_debug = 1;
			break;
		case 'r':
			if (!isdigit(*optarg)) usage();
			retries = atoi(optarg);
			break;
		case 't':
			if (!isdigit(*optarg)) usage();
			timeout = atof(optarg);
			break;
		case 'v':
			printf("radclient: $Id$ built on " __DATE__ "\n");
			exit(0);
			break;
		default:
			usage();
			break;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (argc < 4) {
		usage();
	}

	if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		librad_perror("radclient");
		return 1;
	}

	if ((req = rad_alloc(1)) == NULL) {
		librad_perror("radclient");
		exit(1);
	}

	req->id = getpid() & 0xFF;

	/*
	 *	Strip port from hostname if needed.
	 */
	if ((p = strchr(argv[1], ':')) != NULL) {
		*p++ = 0;
		port = atoi(p);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (strcmp(argv[2], "auth") == 0) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		req->code = PW_AUTHENTICATION_REQUEST;
	} else if (strcmp(argv[2], "acct") == 0) {
		if (port == 0) port = getport("radacct");
		if (port == 0) port = PW_ACCT_UDP_PORT;
		req->code = PW_ACCOUNTING_REQUEST;
	} else if (isdigit(argv[2][0])) {
		if (port == 0) port = PW_AUTH_UDP_PORT;
		port = atoi(argv[2]);
	} else {
		usage();
	}

	/*
	 *	Resolve hostname.
	 */
	req->dst_port = port;
	req->dst_ipaddr = ip_getaddr(argv[1]);
	if (req->dst_ipaddr == 0) {
		librad_perror("radclient: %s: ", argv[1]);
		exit(1);
	}

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = argv[3];

	/*
	 *	Read valuepairs.
	 *	Maybe read them, from stdin, if there's no
	 *	filename, or if the filename is '-'.
	 */
	if (filename && (strcmp(filename, "-") != 0)) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "radclient: Error opening %s: %s\n",
				filename, strerror(errno));
			exit(1);
		}
	} else {
		fp = stdin;
	}

	if ((req->vps = readvp(fp)) == NULL) {
		exit(1);
	}

	/*
	 *	Send request.
	 */
	if ((req->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radclient: socket: ");
		exit(1);
	}

	for (i = 0; i < retries; i++) {
		fd_set		rdfdesc;

		rad_send(req, secret);

		/* And wait for reply, timing out as necessary */
		FD_ZERO(&rdfdesc);
		FD_SET(req->sockfd, &rdfdesc);

		tv.tv_sec = (int)timeout;
		tv.tv_usec = 1000000 * (timeout - (int)timeout);

		/* Something's wrong if we don't get exactly one fd. */
		if (select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
			continue;
		}

		rep = rad_recv(req->sockfd);
		if (rep != NULL) {
			break;
		} else {	/* NULL: couldn't receive the packet */
			librad_perror("radclient:");
			exit(1);
		}
	}

	/* No response or no data read (?) */
	if (i == retries) {
		fprintf(stderr, "radclient: no response from server\n");
		exit(1);
	}

	if (rad_decode(rep, secret) != 0) {
		librad_perror("rad_decode");
		exit(1);
	}

	/* libradius debug already prints out the value pairs for us */
	if (!librad_debug && do_output)
		vp_printlist(stdout, rep->vps);

	return 0;
}

