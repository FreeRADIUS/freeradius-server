/*
 * radzap.c	Zap a user from the radutmp and radwtmp file.
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.com>
 */

#include	"autoconf.h"
#include	"libradius.h"

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
const char *radlog_dir = NULL;

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
		if ((ip = ip_getaddr(argv[1])) == INADDR_NONE) {
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
