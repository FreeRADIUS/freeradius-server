/*
 * radzap	Zap a user from the radutmp and radwtmp file.
 *
 * Version:	$Id$
 *
 */

#include	"autoconf.h"

#include	<sys/file.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"

int debug_flag = 0;
const char *progname = "radzap";
char *radlog_dir = NULL;

/*
 *	Zap a user from the radutmp and radwtmp file.
 */
int main(int argc, char **argv)
{
	NAS	*nas;
	uint32_t ip = 0;
	int	nas_port = -1;
	char	*user = NULL;
	char	*s;
	time_t	t;
	char	buf[256];

	if (argc < 2 || argc > 4 || (argc > 1 && argv[1][0] == '-')) {
		fprintf(stderr, "Usage: radzap termserver [port] [user]\n");
		fprintf(stderr, "       radzap is only an admin tool to clean the radutmp file!\n");
		exit(1);
	}
	if (argc > 2) {
		s = argv[2];
		if (*s == 's' || *s == 'S') s++;
		nas_port = atoi(s);
	}
	if (argc > 3) user     = argv[3];

	/*
	 *	Read the "naslist" file.
	 */
	sprintf(buf, "%s/%s", RADIUS_DIR, RADIUS_NASLIST);
	if (read_naslist_file(buf) < 0)
		exit(1);

	/*
	 *	Find the IP address of the terminal server.
	 */
	if ((nas = nas_findbyname(argv[1])) == NULL && argv[1][0] != 0) {
		if ((ip = ip_getaddr(argv[1])) == 0) {
			fprintf(stderr, "%s: host not found.\n", argv[1]);
			exit(1);
		}
	}
	if (nas) ip = nas->ipaddr;

	printf("radzap: zapping termserver %s, port %d",
		ip_hostname(buf, sizeof(buf), ip), nas_port);
	if (user) printf(", user %s", user);
	printf("\n");

	t = time(NULL);
	radutmp_zap(ip, nas_port, user, t);

	return 0;
}
