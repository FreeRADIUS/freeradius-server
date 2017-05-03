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
#include <freeradius-devel/udpfromto.h>

#include <fcntl.h>

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
		if (!fr_ipaddr_to_sockaddr(src_ipaddr, 0, &salocal, &salen)) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (!fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &salocal, &salen)) {
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
 * @return
 *	- FD on success.
 *	- -1 on failure.
 */
int fr_socket_client_udp(fr_ipaddr_t const *src_ipaddr, fr_ipaddr_t const *dst_ipaddr, uint16_t dst_port, bool async)
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
		if (!fr_ipaddr_to_sockaddr(src_ipaddr, 0, &salocal, &salen)) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (!fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &salocal, &salen)) {
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
int fr_socket_wait_for_connect(int sockfd, struct timeval const *timeout)
{
	int	ret;
	struct	timeval tv = *timeout;
	fd_set	error_set;
	fd_set	write_set;	/* POSIX says sockets are open when they become writeable */

	FD_ZERO(&error_set);
	FD_ZERO(&write_set);

	FD_SET(sockfd, &error_set);
	FD_SET(sockfd, &write_set);

	/* Don't let signals mess up the select */
	do {
		ret = select(sockfd + 1, NULL, &write_set, &error_set, &tv);
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
		fr_strerror_printf("Connection timed out after %" PRIu64"ms",
				   (timeout->tv_sec * (uint64_t)1000) + (timeout->tv_usec / 1000));
		return -2;

	case -1: /* select error */
		fr_strerror_printf("Failed waiting for connection: %s", fr_syserror(errno));
		return -3;

	default:
		(void)fr_cond_assert(0);
		return -1;
	}
}

/** Open an IPv4 / IPv6, and UDP / TCP socket, server side.
 *
 * @param[in] proto IPPROTO_UDP or IPPROTO_TCP
 * @param[in] ipaddr The IP address to listen on
 * @param[in,out] port the port to listen on
 * @param[in] port_name if port==0, the name of the port
 * @param[in] async whether we block or not on reads and writes
 * @return
 *	- Socket FD on success.
 *	- -1 on failure.
 */
int fr_socket_server_base(int proto, fr_ipaddr_t *ipaddr, int *port, char const *port_name, bool async)
{
#ifdef FD_CLOEXEC
	int rcode;
#endif
	int sockfd;
	int sock_type;

	if (!proto) proto = IPPROTO_UDP;

	if ((proto != IPPROTO_UDP) && (proto != IPPROTO_TCP)) {
		fr_strerror_printf("Unknown IP protocol %d", proto);
		return -1;
	}

	if (!ipaddr || ((ipaddr->af != AF_INET) && (ipaddr->af != AF_INET6))) {
		fr_strerror_printf("No address specified");
		return -1;
	}

	if (!*port) {
		struct servent	*svp;
		char const *proto_name;

		if (!port_name) {
			fr_strerror_printf("No port specified");
			return -1;
		}

		if (proto == IPPROTO_UDP) {
			proto_name = "udp";
		} else {
			proto_name = "tcp";
		}

		svp = getservbyname(port_name, proto_name);
		if (!svp) {
			fr_strerror_printf("Unknown port %s", port_name);
			return -1;
		}


		*port = ntohs(svp->s_port);
	}

	if (proto == IPPROTO_UDP) {
		sock_type = SOCK_DGRAM;
	} else {
		sock_type = SOCK_STREAM;
	}

	sockfd = socket(ipaddr->af, sock_type, proto);
	if (sockfd < 0) {
		fr_strerror_printf("Failed creating UNIX socket: %s", fr_syserror(errno));
		return -1;
	}

#ifdef FD_CLOEXEC
	/*
	 *	We don't want child processes inheriting these
	 *	file descriptors.
	 */
	rcode = fcntl(sockfd, F_GETFD);
	if (rcode >= 0) {
		if (fcntl(sockfd, F_SETFD, rcode | FD_CLOEXEC) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed setting close on exec: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

	if (async && (fr_nonblock(sockfd) < 0)) {
		close(sockfd);
		return -1;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for UDP sockets.
	 */
	if ((proto == IPPROTO_UDP) && (udpfromto_init(sockfd) != 0)) {
		fr_strerror_printf("Failed initializing udpfromto: %s", fr_syserror(errno));
		close(sockfd);
		return -1;
	}
#endif

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	/*
	 *	Listening on '::' does NOT get you IPv4 to
	 *	IPv6 mapping.  You've got to listen on an IPv4
	 *	address, too.  This makes the rest of the server
	 *	design a little simpler.
	 */
	if (ipaddr->af == AF_INET6) {
#  ifdef IPV6_V6ONLY
		if (IN6_IS_ADDR_UNSPECIFIED(&ipaddr->ipaddr.ip6addr)) {
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
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
	/*
	 *	Set the "don't fragment" flag on UDP sockets.  Most
	 *	routers don't have good support for fragmented UDP
	 *	packets.
	 */
	if ((proto == IPPROTO_UDP) && (ipaddr->af == AF_INET)) {
		int flag;

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)

		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;

		if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag)) < 0) {
			fr_strerror_printf("Failed disabling PMTU discovery: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
#endif

#if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;

		if (setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &flag, sizeof(flag)) < 0) {
			fr_strerror_printf("Failed setting don't fragment flag: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
#endif
	}
#endif	/* lots of things */

#if defined(WITH_TCP)
	if (proto == IPPROTO_TCP) {
		int on = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed to reuse address: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

#ifdef SO_TIMESTAMP
	if (proto == IPPROTO_UDP) {
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

	return sockfd;
}

/** Bind to an IPv4 / IPv6, and UDP / TCP socket, server side.
 *
 * @param[in] sockfd the socket which was opened via fr_socket_server_base()
 * @param[in,out] ipaddr The IP address to bind to
 * @param[in] port the port to bind to
 * @param[in] interface the interface name to bind to
 * @return
 *	- 0 on success
 *	- -1 on failure.
 */
int fr_socket_server_bind(int sockfd, fr_ipaddr_t *ipaddr, int *port, char const *interface)
{
	int			rcode;
	uint16_t		my_port;
	struct sockaddr_storage	salocal;
	socklen_t		salen;

	/*
	 *	Bind to a device BEFORE touching IP addresses.
	 */
	if (interface) {
#ifdef SO_BINDTODEVICE
		struct ifreq ifreq;

		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, interface, sizeof(ifreq.ifr_name));

		rcode = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq));
		if (rcode < 0) {
			fr_strerror_printf("Failed binding to interface %s: %s", interface, fr_syserror(errno));
			return -1;
		} /* else it worked. */
#else

#  ifdef HAVE_STRUCT_SOCKADDR_IN6
#  ifdef HAVE_NET_IF_H
		/*
		 *	Odds are that any system supporting "bind to
		 *	device" also supports IPv6, so this next bit
		 *	isn't necessary.  But it's here for
		 *	completeness.
		 *
		 *	If we're doing IPv6, and the scope hasn't yet
		 *	been defined, set the scope to the scope of
		 *	the interface.
		 */
		if (ipaddr->af == AF_INET6) {
			if (ipaddr->zone_id == 0) {
				ipaddr->zone_id = if_nametoindex(interface);
				if (ipaddr->zone_id == 0) {
					fr_strerror_printf("Failed finding interface %s: %s", interface, fr_syserror(errno));
					return -1;
				}
			} /* else scope was defined: we're OK. */
		} else
#  endif
#endif
		{
			/*
			 *	IPv4: no link local addresses,
			 *	and no bind to device.
			 */
			fr_strerror_printf("Failed binding to interface %s: \"bind to device\" is unsupported", interface);
			return -1;
		}
#endif
	} /* else no interface */

	if (!port) return 0;

	/*
	 *	Set up sockaddr stuff.
	 */
	my_port = *port;
	if (!fr_ipaddr_to_sockaddr(ipaddr, my_port, &salocal, &salen)) {
		return -1;
	}

	rcode = bind(sockfd, (struct sockaddr *) &salocal, salen);
	if (rcode < 0) return rcode;

	/*
	 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
	 *	kernel instead binds us to a 1.2.3.4.  So once the
	 *	socket is bound, ask it what it's IP address is.
	 */
	salen = sizeof(salocal);
	memset(&salocal, 0, salen);
	if (getsockname(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
		fr_strerror_printf("Failed getting socket name: %s", fr_syserror(errno));
		return -1;
	}

	if (!fr_ipaddr_from_sockaddr(&salocal, salen, ipaddr, &my_port)) {
		return -1;
	}

	*port = my_port;

	return 0;
}

/*
 *	Open a socket on the given IP and port.
 */
int fr_socket(fr_ipaddr_t const *ipaddr, uint16_t port)
{
	int			sockfd;
	struct sockaddr_storage	salocal;
	socklen_t		salen;

	sockfd = socket(ipaddr->af, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fr_strerror_printf("cannot open socket: %s", fr_syserror(errno));
		return sockfd;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(sockfd) != 0) {
		close(sockfd);
		fr_strerror_printf("cannot initialize udpfromto: %s", fr_syserror(errno));
		return -1;
	}
#endif

	if (!fr_ipaddr_to_sockaddr(ipaddr, port, &salocal, &salen)) {
		return sockfd;
	}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (ipaddr->af == AF_INET6) {
		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY

		if (IN6_IS_ADDR_UNSPECIFIED(&ipaddr->ipaddr.ip6addr)) {
			int on = 1;

			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				       (char *)&on, sizeof(on)) < 0) {
				close(sockfd);
				fr_strerror_printf("Failed setting sockopt "
						   "IPPROTO_IPV6 - IPV6_V6ONLY"
						   ": %s", fr_syserror(errno));
				return -1;
			}
		}
#endif /* IPV6_V6ONLY */
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
	if (ipaddr->af == AF_INET) {
		int flag;

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)

		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER,
			       &flag, sizeof(flag)) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed setting sockopt "
					   "IPPROTO_IP - IP_MTU_DISCOVER: %s",
					   fr_syserror(errno));
			return -1;
		}
#endif

#if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;
		if (setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG,
			   &flag, sizeof(flag)) < 0) {
			close(sockfd);
			fr_strerror_printf("Failed setting sockopt "
					   "IPPROTO_IP - IP_DONTFRAG: %s",
					   fr_syserror(errno));
			return -1;
		}
#endif
	}
#endif

	if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
		close(sockfd);
		fr_strerror_printf("Cannot bind socket: %s", fr_syserror(errno));
		return -1;
	}

	return sockfd;
}
