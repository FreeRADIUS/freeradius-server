/*
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file unix.c
 * @brief Functions to work with Unix domain sockets.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#  ifndef SUN_LEN
#    define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#  endif

/** Open a Unix socket
 *
 * @note If the file doesn't exist then errno will be set to ENOENT.
 *
 * @param path to the file bound to the unix socket.
 * @return 0 on success, -1 on error.
 */
int fr_domain_socket(char const *path)
{
	int			sockfd = -1;
	size_t			len;
	socklen_t		socklen;
	struct sockaddr_un	saremote;

	len = strlen(path);
	if (len >= sizeof(saremote.sun_path)) {
		fr_strerror_printf("Path too long, maximum length is %zu", sizeof(saremote.sun_path) - 1);
		errno = EINVAL;
		return -1;
	}

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fr_strerror_printf("Failed creating socket: %s", fr_syserror(errno));
		return -1;
	}

	saremote.sun_family = AF_UNIX;
	memcpy(saremote.sun_path, path, len + 1); /* SUN_LEN does strlen */

	socklen = SUN_LEN(&saremote);

	if (connect(sockfd, (struct sockaddr *)&saremote, socklen) < 0) {
		close(sockfd);
		fr_strerror_printf("Failed connecting to %s: %s", path, fr_syserror(errno));

		return -1;
	}
	return sockfd;
}
#else
int fr_domain_socket(UNUSED char const *path)
{
	fprintf(stderr, "Unix domain sockets not supported on this system");
	return -1;
}
#endif /* WITH_SYS_UN_H */
