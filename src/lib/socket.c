/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file socket.c
 * @brief Functions for establishing and managing low level sockets.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @author Alan DeKok <aland@freeradius.org>
 *
 * @copyright 2015 The FreeRADIUS project
 */
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
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_unix(path, true);
   if (sockfd < 0) {
   	fr_perror();
   	exit(1);
}
   if ((errno == EINPROGRESS) && (fr_socket_wait_for_connect(sockfd, timeout) < 0)) {
   error:
   	fr_perror();
   	close(sockfd);
   	goto error;
}
//Optionally, if blocking operation is required
   if (fr_blocking(sockfd) < 0) goto error;
 @endcode
 *
 * @param path to the file bound to the unix socket.
 * @param async Whether to set the socket to nonblocking, allowing use of
 *	#fr_socket_wait_for_connect.
 * @return socket FD on success, -1 on error.
 */
int fr_socket_client_unix(char const *path, bool async)
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

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("Failed creating UNIX socket: %s", fr_syserror(errno));
		return -1;
	}

	if (async && (fr_nonblock(sockfd) < 0)) {
		close(sockfd);
		return -1;
	}

	saremote.sun_family = AF_UNIX;
	memcpy(saremote.sun_path, path, len + 1); /* SUN_LEN does strlen */

	socklen = SUN_LEN(&saremote);

	/*
	 *	Although we ignore SIGPIPE, some operating systems
	 *	like BSD and OSX ignore the ignoring.
	 *
	 *	Fortunately, those operating systems usually support
	 *	SO_NOSIGPIPE, to prevent them raising the signal in
	 *	the first place.
	 */
#ifdef SO_NOSIGPIPE
	{
		int set = 1;

		setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif

	if (connect(sockfd, (struct sockaddr *)&saremote, socklen) < 0) {
		/*
		 *	POSIX says the only time we will get this,
		 *	is if the socket has been marked as
		 *	nonblocking. This is not an error, the caller
		 *	must check the state of errno, and wait for
		 *	the connection to complete.
		 */
		if (errno == EINPROGRESS) return sockfd;

		close(sockfd);
		fr_strerror_printf("Failed connecting to %s: %s", path, fr_syserror(errno));

		return -1;
	}
	return sockfd;
}
#else
int fr_socket_client_unix(UNUSED char const *path, UNUSED bool async)
{
	fprintf(stderr, "Unix domain sockets not supported on this system");
	return -1;
}
#endif /* WITH_SYS_UN_H */

/** Establish a connected TCP socket
 *
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_tcp(NULL, ipaddr, port, true);
   if (sockfd < 0) {
   	fr_perror();
   	exit(1);
}
   if ((errno == EINPROGRESS) && (fr_socket_wait_for_connect(sockfd, timeout) < 0)) {
   error:
   	fr_perror();
   	close(sockfd);
   	goto error;
}
//Optionally, if blocking operation is required
   if (fr_blocking(sockfd) < 0) goto error;
 @endcode
 *
 * @param src_ipaddr to bind socket to, may be NULL if socket is not bound to any specific
 *	address.
 * @param dst_ipaddr Where to connect to.
 * @param dst_port Where to connect to.
 * @param async Whether to set the socket to nonblocking, allowing use of
 *	#fr_socket_wait_for_connect.
 * @return FD on success, -1 on failure.
 */
int fr_socket_client_tcp(fr_ipaddr_t *src_ipaddr, fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, bool async)
{
	int sockfd;
	struct sockaddr_storage salocal;
	socklen_t	salen;

	if (!dst_ipaddr) return -1;

	sockfd = socket(dst_ipaddr->af, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("Error creating TCP socket: %s", fr_syserror(errno));
		return sockfd;
	}

	if (async && (fr_nonblock(sockfd) < 0)) {
		close(sockfd);
		return -1;
	}

	/*
	 *	Allow the caller to bind us to a specific source IP.
	 */
	if (src_ipaddr && (src_ipaddr->af != AF_UNSPEC)) {
		if (!fr_ipaddr2sockaddr(src_ipaddr, 0, &salocal, &salen)) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (!fr_ipaddr2sockaddr(dst_ipaddr, dst_port, &salocal, &salen)) {
		close(sockfd);
		return -1;
	}

	/*
	 *	Although we ignore SIGPIPE, some operating systems
	 *	like BSD and OSX ignore the ignoring.
	 *
	 *	Fortunately, those operating systems usually support
	 *	SO_NOSIGPIPE, to prevent them raising the signal in
	 *	the first place.
	 */
#ifdef SO_NOSIGPIPE
	{
		int set = 1;

		setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif

	if (connect(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
		/*
		 *	POSIX says the only time we will get this,
		 *	is if the socket has been marked as
		 *	nonblocking. This is not an error, the caller
		 *	must check the state of errno, and wait for
		 *	the connection to complete.
		 */
		if (errno == EINPROGRESS) return sockfd;

		fr_strerror_printf("Failed connecting socket: %s", fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/** Establish a connected UDP socket
 *
 * Connected UDP sockets can be used with write(), unlike unconnected sockets
 * which must be used with sendto and recvfrom.
 *
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_udp(NULL, ipaddr, port, true);
   if (sockfd < 0) {
   	fr_perror();
   	exit(1);
}
   if ((errno == EINPROGRESS) && (fr_socket_wait_for_connect(sockfd, timeout) < 0)) {
   error:
   	fr_perror();
   	close(sockfd);
   	goto error;
}
//Optionally, if blocking operation is required
   if (fr_blocking(sockfd) < 0) goto error;
 @endcode
 *
 * @param src_ipaddr to bind socket to, may be NULL if socket is not bound to any specific
 *	address.
 * @param dst_ipaddr Where to send datagrams.
 * @param dst_port Where to send datagrams.
 * @param async Whether to set the socket to nonblocking, allowing use of
 *	#fr_socket_wait_for_connect.
 * @return FD on success, -1 on failure.
 */
int fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, bool async)
{
	int			sockfd;
	struct sockaddr_storage salocal;
	socklen_t		salen;

	if (!dst_ipaddr) return -1;

	sockfd = socket(dst_ipaddr->af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("Error creating UDP socket: %s", fr_syserror(errno));
		return sockfd;
	}

	if (async && (fr_nonblock(sockfd) < 0)) {
		close(sockfd);
		return -1;
	}

	/*
	 *	Allow the caller to bind us to a specific source IP.
	 */
	if (src_ipaddr && (src_ipaddr->af != AF_UNSPEC)) {
		if (!fr_ipaddr2sockaddr(src_ipaddr, 0, &salocal, &salen)) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (!fr_ipaddr2sockaddr(dst_ipaddr, dst_port, &salocal, &salen)) {
		close(sockfd);
		return -1;
	}

	/*
	 *	Although we ignore SIGPIPE, some operating systems
	 *	like BSD and OSX ignore the ignoring.
	 *
	 *	Fortunately, those operating systems usually support
	 *	SO_NOSIGPIPE, to prevent them raising the signal in
	 *	the first place.
	 */
#ifdef SO_NOSIGPIPE
	{
		int set = 1;

		setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif

	if (connect(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
		/*
		 *	POSIX says the only time we will get this,
		 *	is if the socket has been marked as
		 *	nonblocking. This is not an error, the caller
		 *	must check the state of errno, and wait for
		 *	the connection to complete.
		 */
		if (errno == EINPROGRESS) return sockfd;

		fr_strerror_printf("Failed connecting socket: %s", fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/** Wait for a socket to be connected, with an optional timeout
 *
 * @note On error the caller is expected to ``close(sockfd)``.
 *
 * @param sockfd the socket to wait on.
 * @param timeout How long to wait for socket to open.
 * @return 0 on success, -1 on connection error, -2 on timeout, -3 on select error.
 */
int fr_socket_wait_for_connect(int sockfd, struct timeval *timeout)
{
	int	ret;
	fd_set	error_set;
	fd_set	write_set;	/* POSIX says sockets are open when they become writeable */

	FD_ZERO(&error_set);
	FD_ZERO(&write_set);

	FD_SET(sockfd, &error_set);
	FD_SET(sockfd, &write_set);

	/* Don't let signals mess up the select */
	do {
		ret = select(sockfd + 1, NULL, &write_set, &error_set, timeout);
	} while ((ret == -1) && (errno == EINTR));

	switch (ret) {
	case 1: /* ok (maybe) */
	{
		int error;
		socklen_t socklen = sizeof(error);

		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&error, &socklen)) {
			fr_strerror_printf("Failed connecting socket: %s", fr_syserror(errno));
			return -1;
		}

		if (FD_ISSET(sockfd, &error_set)) {
			fr_strerror_printf("Failed connecting socket: Unknown error");
			return -1;
		}
	}
		return 0;

	case 0: /* timeout */
		if (!fr_assert(timeout)) return -1;
		fr_strerror_printf("Connection timed out after %" PRIu64"ms",
				   (timeout->tv_sec * (uint64_t)1000) + (timeout->tv_usec / 1000));
		return -2;

	case -1: /* select error */
		fr_strerror_printf("Failed waiting for connection: %s", fr_syserror(errno));
		return -3;

	default:
		fr_assert(0);
		return -1;
	}
}
