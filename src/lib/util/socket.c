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

/** Functions for establishing and managing low level sockets
 *
 * @file src/lib/util/socket.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2015 The FreeRADIUS project
 */

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/udpfromto.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/cap.h>

#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SO_BINDTODEVICE
#include <net/if.h>
#endif

#include <ifaddrs.h>

/** Resolve a named service to a port
 *
 * @param[in] proto	The protocol. Either IPPROTO_TCP or IPPROTO_UDP.
 * @param[in] port_name	The service name, i.e. "radius".
 * @return
 *	- > 0 the port port_name resolves to.
 *	- < 0 on error.
 */
static int socket_port_from_service(int proto, char const *port_name)
{
	struct servent	*service;
	char const	*proto_name;

	if (!port_name) {
		fr_strerror_printf("No port specified");
		return -1;
	}

	switch (proto) {
	case IPPROTO_UDP:
		proto_name = "udp";
		break;

	case IPPROTO_TCP:
		proto_name = "tcp";
		break;

#ifdef IPPROTO_SCTP
	case IPPROTO_SCTP:
		proto_name = "sctp";
		break;
#endif

	default:
		fr_strerror_printf("Unrecognised proto %i", proto);
		return -1;
	}

	service = getservbyname(port_name, proto_name);
	if (!service) {
		fr_strerror_printf("Unknown service %s", port_name);
		return -1;
	}

	return ntohs(service->s_port);
}

#ifdef FD_CLOEXEC
static int socket_dont_inherit(int sockfd)
{
	int rcode;

	/*
	 *	We don't want child processes inheriting these
	 *	file descriptors.
	 */
	rcode = fcntl(sockfd, F_GETFD);
	if (rcode >= 0) {
		if (fcntl(sockfd, F_SETFD, rcode | FD_CLOEXEC) < 0) {
			fr_strerror_printf("Failed setting close on exec: %s", fr_syserror(errno));
			return -1;
		}
	}

	return 0;
}
#else
static socket_dont_inherit(UNUSED int sockfd)
{
	return 0;
}
#endif

#ifdef HAVE_STRUCT_SOCKADDR_IN6
/** Restrict wildcard sockets to v6 only
 *
 * If we don't do this we get v4 and v6 packets coming in on the same
 * socket, which is weird.
 *
 * @param[in] sockfd to modify.
 * @param[in] ipaddr we will be binding to.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int socket_inaddr_any_v6only(int sockfd, fr_ipaddr_t const *ipaddr)
{
	/*
	 *	Listening on '::' does NOT get you IPv4 to
	 *	IPv6 mapping.  You've got to listen on an IPv4
	 *	address, too.  This makes the rest of the server
	 *	design a little simpler.
	 */
	if (ipaddr->af == AF_INET6) {
#  ifdef IPV6_V6ONLY
		if (IN6_IS_ADDR_UNSPECIFIED(&ipaddr->addr.v6)) {
			int on = 1;

			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				       (char *)&on, sizeof(on)) < 0) {
				fr_strerror_printf("Failed setting socket to IPv6 only: %s", fr_syserror(errno));
				close(sockfd);
				return -1;
			}
		}
#  endif /* IPV6_V6ONLY */
	}
	return 0;
}
#else
static int socket_inaddr_any_v6only(UNUSED int sockfd, UNUSED fr_ipaddr_t const *ipaddr)
{
	return 0;
}
#endif

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
/** Set the don't fragment bit
 *
 * @param[in] sockfd	to set don't fragment bit for.
 * @param[in] af	of the socket.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int socket_dont_fragment(int sockfd, int af)
{
	/*
	 *	Set the "don't fragment" flag on UDP sockets.  Most
	 *	routers don't have good support for fragmented UDP
	 *	packets.
	 */
	if (af == AF_INET) {
		int flag;

#  if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;

		if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag)) < 0) {
			fr_strerror_printf("Failed disabling PMTU discovery: %s", fr_syserror(errno));
			return -1;
		}
#  endif

#  if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;

		if (setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &flag, sizeof(flag)) < 0) {
			fr_strerror_printf("Failed setting don't fragment flag: %s", fr_syserror(errno));
			return -1;
		}
#  endif
	}

	return 0;
}
#else
static int socket_dont_fragment(UNUSED int sockfd, UNUSED int af)
{
	return 0;
}
#endif	/* lots of things */

/** Check the proto value is sane/supported
 *
 * @param[in] proto to check
 * @return
 *	- true if it is.
 *	- false if it's not.
 */
bool fr_socket_is_valid_proto(int proto)
{
	/*
	 *	Check the protocol is sane
	 */
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
#ifdef IPPROTO_SCTP
	case IPPROTO_SCTP:
#endif
		return true;

	default:
		fr_strerror_printf("Unknown IP protocol %d", proto);
		return false;
	}
}

#ifdef HAVE_SYS_UN_H
/** Open a Unix socket
 *
 * @note If the file doesn't exist then errno will be set to ENOENT.
 *
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_unix(path, true);
   if (sockfd < 0) {
   	fr_perror();
   	fr_exit_now(1);
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
 * @param path		to the file bound to the unix socket.
 * @param async		Whether to set the socket to nonblocking, allowing use of
 *			#fr_socket_wait_for_connect.
 * @return
 *	- Socket FD on success.
 *	- -1 on failure.
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

/** Establish a connected UDP socket
 *
 * Connected UDP sockets can be used with write(), unlike unconnected sockets
 * which must be used with sendto and recvfrom.
 *
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_udp(NULL, NULL, ipaddr, port, true);
   if (sockfd < 0) {
   	fr_perror();
   	fr_exit_now(1);
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
 * @param[in,out] src_ipaddr	to bind socket to, may be NULL if socket is not bound to any specific
 *			address.  If non-null, the bound IP is copied here, too.
 * @param[out] src_port	The source port we were bound to, may be NULL.
 * @param dst_ipaddr	Where to send datagrams.
 * @param dst_port	Where to send datagrams.
 * @param async		Whether to set the socket to nonblocking, allowing use of
 *			#fr_socket_wait_for_connect.
 * @return
 *	- FD on success.
 *	- -1 on failure.
 */
int fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t const *dst_ipaddr, uint16_t dst_port, bool async)
{
	int			sockfd;
	struct sockaddr_storage salocal;
	socklen_t		salen;

	if (!dst_ipaddr) return -1;

	sockfd = socket(dst_ipaddr->af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("Error creating UDP socket: %s", fr_syserror(errno));
		return -1;
	}

	if (async && (fr_nonblock(sockfd) < 0)) {
	error:
		close(sockfd);
		return -1;
	}

	/*
	 *	Allow the caller to bind us to a specific source IP.
	 */
	if (src_ipaddr && (src_ipaddr->af != AF_UNSPEC)) {
		/*
		 *	Ensure don't fragment bit is set
		 */
		if (socket_dont_fragment(sockfd, src_ipaddr->af) < 0) goto error;

		if (fr_ipaddr_to_sockaddr(src_ipaddr, 0, &salocal, &salen) < 0) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
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

	/*
	 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
	 *	kernel instead binds us to a 1.2.3.4.  So once the
	 *	socket is bound, ask it what it's IP address is.
	 */
	if (src_port) {
		fr_ipaddr_t		my_ipaddr;
		uint16_t		my_port;

		salen = sizeof(salocal);
		memset(&salocal, 0, salen);
		if (getsockname(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed getting socket name: %s", fr_syserror(errno));
			return -1;
		}

		/*
		 *	Return these if the caller cared.
		 */
		if (!src_ipaddr) src_ipaddr = &my_ipaddr;
		if (!src_port) src_port = &my_port;

		if (fr_ipaddr_from_sockaddr(&salocal, salen, src_ipaddr, src_port) < 0) {
			close(sockfd);
			return -1;
		}
	}

	/*
	 *	And now get our destination
	 */
	if (fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &salocal, &salen) < 0) {
		close(sockfd);
		return -1;
	}

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

/** Establish a connected TCP socket
 *
 * The following code demonstrates using this function with a connection timeout:
 @code {.c}
   sockfd = fr_socket_client_tcp(NULL, ipaddr, port, true);
   if (sockfd < 0) {
   	fr_perror();
   	fr_exit_now(1);
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
 * @param src_ipaddr	to bind socket to, may be NULL if socket is not bound to any specific
 *			address.
 * @param dst_ipaddr	Where to connect to.
 * @param dst_port	Where to connect to.
 * @param async		Whether to set the socket to nonblocking, allowing use of
 *			#fr_socket_wait_for_connect.
 * @return
 *	- FD on success
 *	- -1 on failure.
 */
int fr_socket_client_tcp(fr_ipaddr_t const *src_ipaddr, fr_ipaddr_t const *dst_ipaddr, uint16_t dst_port, bool async)
{
	int			sockfd;
	struct sockaddr_storage	salocal;
	socklen_t		salen;

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
		if (fr_ipaddr_to_sockaddr(src_ipaddr, 0, &salocal, &salen) < 0) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &salocal, &salen) < 0) {
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
 * @return
 *	- 0 on success.
 *	- -1 on connection error.
 *	- -2 on timeout.
 *	- -3 on select error.
 */
int fr_socket_wait_for_connect(int sockfd, fr_time_delta_t timeout)
{
	int	ret;
	fd_set	error_set;
	fd_set	write_set;	/* POSIX says sockets are open when they become writable */

	FD_ZERO(&error_set);
	FD_ZERO(&write_set);

	FD_SET(sockfd, &error_set);
	FD_SET(sockfd, &write_set);

	/* Don't let signals mess up the select */
	do {
		ret = select(sockfd + 1, NULL, &write_set, &error_set, &fr_time_delta_to_timeval(timeout));
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
		if (!fr_cond_assert(timeout)) return -1;
		fr_strerror_printf("Connection timed out after %pVs", fr_box_time_delta(timeout));
		return -2;

	case -1: /* select error */
		fr_strerror_printf("Failed waiting for connection: %s", fr_syserror(errno));
		return -3;

	default:
		(void)fr_cond_assert(0);
		return -1;
	}
}

/** Open an IPv4/IPv6 unconnected UDP socket
 *
 * Function name is a bit of a misnomer as it can also be used to create client sockets too,
 * such is the nature of UDP.
 *
 * @param[in] src_ipaddr	The IP address to listen on
 * @param[in,out] src_port	the port to listen on.  If *port == 0, the resolved
 *				service port will be written here.
 * @param[in] port_name		if *port == 0, the name of the port
 * @param[in] async		whether we block or not on reads and writes
 * @return
 *	- Socket FD on success.
 *	- -1 on failure.
 */
int fr_socket_server_udp(fr_ipaddr_t const *src_ipaddr, uint16_t *src_port, char const *port_name, bool async)
{
	int		sockfd;
	uint16_t	my_port = 0;

	if (src_port) my_port = *src_port;

	/*
	 *	Check IP looks OK
	 */
	if (!src_ipaddr || ((src_ipaddr->af != AF_INET) && (src_ipaddr->af != AF_INET6))) {
		fr_strerror_printf("No address specified");
		return -1;
	}

	/*
	 *	Check we have a port value or stuff we can resolve to a port
	 */
	if (!my_port && port_name) {
		int ret;

		ret = socket_port_from_service(IPPROTO_UDP, port_name);
		if (ret < 0) return -1;

		my_port = ret;
	}

	/*
	 *	Open the socket
	 */
	sockfd = socket(src_ipaddr->af, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fr_strerror_printf("Failed creating UDP socket: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Make it non-blocking if asked
	 */
	if (async && (fr_nonblock(sockfd) < 0)) {
	error:
		close(sockfd);
		return -1;
	}

	/*
	 *	Don't allow child processes to inherit the socket
	 */
	if (socket_dont_inherit(sockfd) < 0) goto error;

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for UDP sockets.
	 */
	if (udpfromto_init(sockfd) != 0) {
		fr_strerror_printf("Failed initializing udpfromto: %s", fr_syserror(errno));
		goto error;
	}
#endif

	/*
	 *	Make sure we don't get v4 and v6 packets on inaddr_any sockets.
	 */
	if (socket_inaddr_any_v6only(sockfd, src_ipaddr) < 0) goto error;

	/*
	 *	Ensure don't fragment bit is set
	 */
	if (socket_dont_fragment(sockfd, src_ipaddr->af) < 0) goto error;

#ifdef SO_TIMESTAMP
	{
		int on = 1;

		/*
		 *	Enable receive timestamps, these should reflect
		 *	when the packet was received, not when it was read
		 *	from the socket.
		 */
		if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(int)) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed enabling socket timestamps: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

	if (src_port) *src_port = my_port;

	return sockfd;
}

/** Open an IPv4/IPv6 TCP socket
 *
 * @param[in] src_ipaddr	The IP address to listen on
 * @param[in,out] src_port	the port to listen on.  If *port == 0, the resolved
 *				service port will be written here.
 *				NULL if any port is allowed.
 * @param[in] port_name		if *port == 0, the name of the port
 * @param[in] async		whether we block or not on reads and writes
 * @return
 *	- Socket FD on success.
 *	- -1 on failure.
 */
int fr_socket_server_tcp(fr_ipaddr_t const *src_ipaddr, uint16_t *src_port, char const *port_name, bool async)
{
	int		sockfd;
	uint16_t	my_port = 0;

	if (src_port) my_port = *src_port;

	/*
	 *	Check IP looks OK
	 */
	if (!src_ipaddr || ((src_ipaddr->af != AF_INET) && (src_ipaddr->af != AF_INET6))) {
		fr_strerror_printf("No address specified");
		return -1;
	}

	/*
	 *	Check we have a port value or stuff we can resolve to a port
	 */
	if (!my_port && port_name) {
		int ret;

		ret = socket_port_from_service(IPPROTO_TCP, port_name);
		if (ret < 0) return -1;

		my_port = ret;
	}

	/*
	 *	Open the socket
	 */
	sockfd = socket(src_ipaddr->af, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		fr_strerror_printf("Failed creating TCP socket: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Make it non-blocking if asked
	 */
	if (async && (fr_nonblock(sockfd) < 0)) {
	error:
		close(sockfd);
		return -1;
	}

	/*
	 *	Don't allow child processes to inherit the socket
	 */
	if (socket_dont_inherit(sockfd) < 0) goto error;

	/*
	 *	Make sure we don't get v4 and v6 packets on inaddr_any sockets.
	 */
	if (socket_inaddr_any_v6only(sockfd, src_ipaddr) < 0) goto error;

	{
		int on = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed to reuse address: %s", fr_syserror(errno));
			return -1;
		}
	}

	if (src_port) *src_port = my_port;

	return sockfd;
}

/** Bind a UDP/TCP v4/v6 socket to a given ipaddr src port, and interface.
 *
 * Use one of:
 * - fr_socket_client_udp - for a connected socket.
 * - fr_socket_server_udp - for non-connected socket.
 * - fr_socket_server_tcp
 * ...to open a file descriptor, then call this function to bind the socket to an IP address.
 *
 * @param[in] sockfd		the socket which opened by fr_socket_server_*.
 * @param[in,out] src_ipaddr	The IP address to bind to.  NULL to just bind to an interface.
 * @param[in] src_port		the port to bind to.  NULL if any port is allowed.
 * @param[in] interface		to bind to.
 * @return
 *	- 0 on success
 *	- -1 on failure.
 */
int fr_socket_bind(int sockfd, fr_ipaddr_t const *src_ipaddr, uint16_t *src_port, char const *interface)
{
	int				rcode;
	uint16_t			my_port = 0;
	fr_ipaddr_t			my_ipaddr;
	struct sockaddr_storage		salocal;
	socklen_t			salen;

	/*
	 *	Clear the thread local error stack as we may
	 *	push multiple errors onto the stack, and this
	 *	is likely to be the function which returns
	 *	the "original" error.
	 */
	(void)fr_strerror();

	if (src_port) my_port = *src_port;
	if (src_ipaddr) {
		my_ipaddr = *src_ipaddr;
	} else {
		my_ipaddr = (fr_ipaddr_t) {
			.af = AF_UNSPEC
		};
	}

#ifdef HAVE_CAPABILITY_H
	/*
	 *	If we're binding to a special port as non-root, then
	 *	check capabilities.  If we're root, we already have
	 *	equivalent capabilities so we don't need to check.
	 */
	if (src_port && (*src_port < 1024) && (geteuid() != 0)) (void)fr_cap_set(CAP_NET_BIND_SERVICE);
#endif

	/*
	 *	Bind to a device BEFORE touching IP addresses.
	 */
	if (interface) {
		bool bound = false;

#ifdef HAVE_NET_IF_H
		uint32_t scope_id;

		scope_id = if_nametoindex(interface);
		if (!scope_id) {
			fr_strerror_printf_push("Failed finding interface %s: %s",
						interface, fr_syserror(errno));
			return -1;
		}

		/*
		 *	If the scope ID hasn't already been set, then
		 *	set it.  This allows us to get the scope from the interface name.
		 */
		if ((my_ipaddr.scope_id != 0) && (scope_id != my_ipaddr.scope_id)) {
			fr_strerror_printf_push("Cannot bind to interface %s: Socket is already bound "
						"to another interface", interface);
			return -1;
		}
#endif

#ifdef SO_BINDTODEVICE
		/*
		 *	The caller didn't specify a scope_id, but we
		 *	have one from above.  Call "bind to device",
		 *	and set the scope_id.
		 */
		if (!my_ipaddr.scope_id) {
			struct ifreq ifreq;

			memset(&ifreq, 0, sizeof(ifreq));
			strlcpy(ifreq.ifr_name, interface, sizeof(ifreq.ifr_name));

			rcode = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq));
			if (rcode < 0) {
				fr_strerror_printf_push("Failed binding to interface %s: %s",
							interface, fr_syserror(errno));
				return -1;
			} /* else it worked. */

			/*
			 *	Set the scope ID.
			 */
			my_ipaddr.scope_id = scope_id;
			bound = true;
		}
#else
		struct ifaddrs *list = NULL;

		/*
		 *	Troll through all interfaces to see if there's
		 */
		if (getifaddrs(&list) == 0) {
			struct ifaddrs *i;

			for (i = list; i != NULL; i = i->ifa_next) {
				if (i->ifa_addr && i->ifa_name && (strcmp(i->ifa_name, interface) == 0)) {
					/*
					 *	IPv4, and there's either no src_ip, OR src_ip is INADDR_ANY,
					 *	it's a match.
					 *
					 *	We also update my_ipaddr to point to this particular IP,
					 *	so that we can later bind() to it.  This gets us the same
					 *	effect as SO_BINDTODEVICE.
					 */
					if ((i->ifa_addr->sa_family == AF_INET) &&
					    (!src_ipaddr || fr_ipaddr_is_inaddr_any(src_ipaddr))) {
						(void) fr_ipaddr_from_sockaddr((struct sockaddr_storage *) i->ifa_addr,
									       sizeof(struct sockaddr_in), &my_ipaddr, NULL);
						my_ipaddr.scope_id = scope_id;
						bound = true;
						break;
					}

					/*
					 *	The caller specified a source IP, and we find a matching
					 *	address family.  Allow it.
					 *
					 *	Note that we do NOT check for matching IPs here.  If we did,
					 *	then binding to an interface and the *wrong* IP would get us
					 *	a "bind to device is unsupported" message.
					 *
					 *	Instead we say "yes, we found a matching interface", and then
					 *	allow the bind() call below to run.  If that fails, we get a
					 *	"Can't assign requested address" error, which is more informative.
					 */
					if (src_ipaddr && (src_ipaddr->af == i->ifa_addr->sa_family)) {
						my_ipaddr.scope_id = scope_id;
						bound = true;
						break;
					}
				}
			}

			freeifaddrs(list);
		}
#endif

		if (!bound) {
			/*
			 *	IPv4: no link local addresses,
			 *	and no bind to device.
			 */
			fr_strerror_printf_push("Failed binding to interface %s: \"bind to device\" is unsupported",
						interface);
			return -1;
		}
	} /* else no interface */

	/*
	 *	Don't bind to an IP address if there's no src IP address.
	 */
	if (my_ipaddr.af == AF_UNSPEC) goto done;

	/*
	 *	Set up sockaddr stuff.
	 */
	if (fr_ipaddr_to_sockaddr(&my_ipaddr, my_port, &salocal, &salen) < 0) return -1;

	rcode = bind(sockfd, (struct sockaddr *) &salocal, salen);
	if (rcode < 0) {
		fr_strerror_printf_push("Bind failed: %s", fr_syserror(errno));
		return rcode;
	}

	if (!src_port) goto done;

	/*
	 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
	 *	kernel instead binds us to a 1.2.3.4.  So once the
	 *	socket is bound, ask it what it's IP address is.
	 *
	 *	@todo - Uh... we don't update src_ipaddr with the new
	 *	IP address.  This means that we don't tell the caller
	 *	what IP address we're bound to.  That seems wrong.
	 */
	salen = sizeof(salocal);
	memset(&salocal, 0, salen);
	if (getsockname(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
		fr_strerror_printf_push("Failed getting socket name: %s", fr_syserror(errno));
		return -1;
	}

	if (fr_ipaddr_from_sockaddr(&salocal, salen, &my_ipaddr, &my_port) < 0) return -1;
	*src_port = my_port;

done:
#ifdef HAVE_CAPABILITY_H
	/*
	 *	Clear any errors we may have produced in the
	 *	capabilities check.
	 */
	fr_strerror();
#endif
	return 0;
}
