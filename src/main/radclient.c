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
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	"conf.h"
#include	"libradius.h"

/*
 *	Read valuepairs from stdin up to End-Of-File.
 */
VALUE_PAIR *readvp(void)
{
	char		buf[128];
	int 		eol;
	char		*p;
	VALUE_PAIR	*vp;
	VALUE_PAIR	*list;
	int		error = 0;

	list = NULL;

	while (!error && fgets(buf, 128, stdin) != NULL) {

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
	fprintf(stderr, "Usage: radclient [-d raddb ] [-nx] server acct|auth <secret>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	RADIUS_PACKET	*req;
	RADIUS_PACKET	*rep;
	VALUE_PAIR	*vp;
	char		*p;
	char		*secret = "secret";
	int		do_output = 1;
	int		c;
	int		port = 0;
	int		s;
	char		*radius_dir = RADDBDIR;

	while ((c = getopt(argc, argv, "d:nx")) != EOF) switch(c) {
		case 'd':
			radius_dir = optarg;
			break;
		case 'n':
			do_output = 0;
			break;
		case 'x':
			librad_debug = 1;
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
		if (port == 0) port = 1645;
		req->code = PW_AUTHENTICATION_REQUEST;
	} else if (strcmp(argv[2], "acct") == 0) {
		if (port == 0) port = 1646;
		req->code = PW_ACCOUNTING_REQUEST;
	} else if (isdigit(argv[2][0])) {
		if (port == 0) port = 1645;
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
	 */
	if ((req->vps = readvp()) == NULL) {
		exit(1);
	}

	/*
	 *	Find the password pair and encode it.
	 */
	if ((vp = pairfind(req->vps, PW_PASSWORD)) != NULL)
		rad_pwencode(vp->strvalue, &(vp->length), secret, req->vector);

	/*
	 *	Send request.
	 */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radclient: socket: ");
		exit(1);
	}
	rad_send(req, s, secret);

	/*
	 *	And wait for reply.
	 */
	rep = rad_recv(s);
	if (rep == NULL)
		exit(1);

	if (rad_decode(rep, secret) != 0) {
		librad_perror("rad_decode");
		exit(1);
	}

	if (do_output)
		vp_printlist(stdout, rep->vps);

	return 0;
}

