/*
 * radclient	General radius packet debug tool.
 *
 * Version:	@(#)radclient  1.10  25-Jul-1999  miquels@cistron.nl
 *
 */

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<getopt.h>
#include	<ctype.h>
#include	<netdb.h>
#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#if HAVE_SYS_SELECT_H
#  include      <sys/select.h>
#endif

#if HAVE_ERRNO_H
#  include      <errno.h>
#endif

#include	"conf.h"
#include	"libradius.h"

/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
VALUE_PAIR *readvp(FILE *fp)
{
	char		buf[128];
	int 		eol;
	char		*p;
	VALUE_PAIR	*vp;
	VALUE_PAIR	*list;
	int		error = 0;

	list = NULL;

	while (!error && fgets(buf, 128, fp) != NULL) {

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

void usage(void)
{
	fprintf(stderr, "Usage: radclient [-d raddb ] [-f file] [-t timeout] [-nx] server acct|auth <secret>\n");
	exit(1);
}

int getport(char *name)
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
	char		*secret = "secret";
	int		do_output = 1;
	int		c;
	int		port = 0;
	int		s;
	int		timeout = 3;
	int		i;
	char		*radius_dir = RADDBDIR;
	char		*filename = NULL;
	FILE		*fp;

	while ((c = getopt(argc, argv, "d:f:nxt:")) != EOF) switch(c) {
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
		case 't':
			timeout = atoi(optarg);
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
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radclient: socket: ");
		exit(1);
	}

	for (i = 0; i < 10; i++) {
		fd_set		rdfdesc;

		rad_send(req, s, secret);

		/* And wait for reply, timing out as necessary */
		FD_ZERO(&rdfdesc);
		FD_SET(s, &rdfdesc);

		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		/* Something's wrong if we don't get exactly one fd. */
		if (select(s+1, &rdfdesc, NULL, NULL, &tv) != 1) {
			continue;
		}

		rep = rad_recv(s);
		if (rep != NULL) {
			break;
		} else {	/* NULL: couldn't receive the packet */
			librad_perror("radclient:");
			exit(1);
		}
	}

	/* No response or no data read (?) */
	if (i == 10) {
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

