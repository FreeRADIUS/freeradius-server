/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** API for sending and receiving packets on unconnected UDP sockets
 *
 * Like recvfrom, but also stores the destination IP address. Useful on multihomed hosts.
 *
 * @file src/lib/util/udpfromto.c
 *
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 * @copyright 2002 Miquel van Smoorenburg
 */
RCSID("$Id$")

#include <freeradius-devel/util/udpfromto.h>

#ifdef WITH_UDPFROMTO

#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
 *	More portability idiocy
 *	Mac OSX Lion doesn't define SOL_IP.  But IPPROTO_IP works.
 */
#ifndef SOL_IP
#  define SOL_IP IPPROTO_IP
#endif

/*
 *  glibc 2.4 and uClibc 0.9.29 introduce IPV6_RECVPKTINFO etc. and
 *  change IPV6_PKTINFO This is only supported in Linux kernel >=
 *  2.6.14
 *
 *  This is only an approximation because the kernel version that libc
 *  was compiled against could be older or newer than the one being
 *  run.  But this should not be a problem -- we just keep using the
 *  old kernel interface.
 */
#ifdef __linux__
#  ifdef IPV6_RECVPKTINFO
#    include <linux/version.h>
#    if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#      ifdef IPV6_2292PKTINFO
#        undef IPV6_RECVPKTINFO
#        undef IPV6_PKTINFO
#        define IPV6_RECVPKTINFO IPV6_2292PKTINFO
#        define IPV6_PKTINFO IPV6_2292PKTINFO
#      endif
#    endif
/* Fall back to the legacy socket option if IPV6_RECVPKTINFO isn't defined */
#  elif defined(IPV6_2292PKTINFO)
#      define IPV6_RECVPKTINFO IPV6_2292PKTINFO
#  endif
#else

/*
 *  For everything that's not Linux we assume RFC 3542 compliance
 *  - setsockopt() takes IPV6_RECVPKTINFO
 *  - cmsg_type is IPV6_PKTINFO (in sendmsg, recvmsg)
 *
 *  If we don't have IPV6_RECVPKTINFO defined but do have IPV6_PKTINFO
 *  defined, chances are the API is RFC2292 compliant and we need to use
 *  IPV6_PKTINFO for both.
 */
#  if !defined(IPV6_RECVPKTINFO) && defined(IPV6_PKTINFO)
#    define IPV6_RECVPKTINFO IPV6_PKTINFO

/*
 *  Ensure IPV6_RECVPKTINFO is not defined somehow if we have we
 *  don't have IPV6_PKTINFO.
 */
#  elif !defined(IPV6_PKTINFO)
#    undef IPV6_RECVPKTINFO
#  endif
#endif

int udpfromto_init(int s)
{
	int proto, flag = 0, opt = 1;
	struct sockaddr_storage si;
	socklen_t si_len = sizeof(si);

	errno = ENOSYS;

	/*
	 *	Clang analyzer doesn't see that getsockname initialises
	 *	the memory passed to it.
	 */
#ifdef __clang_analyzer__
	memset(&si, 0, sizeof(si));
#endif

	if (getsockname(s, (struct sockaddr *) &si, &si_len) < 0) {
		return -1;
	}

	if (si.ss_family == AF_INET) {
#ifdef HAVE_IP_PKTINFO
		/*
		 *	Linux
		 */
		proto = SOL_IP;
		flag = IP_PKTINFO;
#else
#  ifdef IP_RECVDSTADDR

		/*
		 *	Set the IP_RECVDSTADDR option (BSD).  Note:
		 *	IP_RECVDSTADDR == IP_SENDSRCADDR
		 */
		proto = IPPROTO_IP;
		flag = IP_RECVDSTADDR;
#  else
		return -1;
#  endif
#endif

#if defined(AF_INET6) && defined(IPV6_PKTINFO)
	} else if (si.ss_family == AF_INET6) {
		/*
		 *	This should actually be standard IPv6
		 */
		proto = IPPROTO_IPV6;

		/*
		 *	Work around Linux-specific hackery.
		 */
		flag = IPV6_RECVPKTINFO;
	} else {
#endif

		/*
		 *	Unknown AF.  Return an error if possible.
		 */
#  ifdef EPROTONOSUPPORT
		errno = EPROTONOSUPPORT;
#  endif
		return -1;
	}

	return setsockopt(s, proto, flag, &opt, sizeof(opt));
}

/** Read a packet from a file descriptor, retrieving additional header information
 *
 * Abstracts away the complexity of using the complexity of using recvmsg().
 *
 * In addition to reading data from the file descriptor, the src and dst addresses
 * and the receiving interface index are retrieved.  This enables us to send
 * replies using the correct IP interface, in the case where the server is multihomed.
 * This is not normally possible on unconnected datagram sockets.
 *
 * @param[in] fd	The file descriptor to read from.
 * @param[out] buf	Where to write the received datagram data.
 * @param[in] len	of buf.
 * @param[in] flags	passed unmolested to recvmsg.
 * @param[out] from	Where to write the source address.
 * @param[in] from_len	Length of the structure pointed to by from.
 * @param[out] to	Where to write the destination address.  If NULL recvmsg()
 *			will be used instead.
 * @param[in] to_len	Length of the structure pointed to by to.
 * @param[out] if_index	The interface which received the datagram (may be NULL).
 *			Will only be populated if to is not NULL.
 * @param[out] when	the packet was received (may be NULL).  If SO_TIMESTAMP is
 *			not available or SO_TIMESTAMP Was not set on the socket,
 *			then another method will be used instead to get the time.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int recvfromto(int fd, void *buf, size_t len, int flags,
	       struct sockaddr *from, socklen_t *from_len,
	       struct sockaddr *to, socklen_t *to_len,
	       int *if_index, fr_time_t *when)
{
	struct msghdr		msgh;
	struct cmsghdr		*cmsg;
	struct iovec		iov;
	char			cbuf[256];
	int			ret;
	struct sockaddr_storage	si;
	socklen_t		si_len = sizeof(si);

#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR) && !defined(IPV6_PKTINFO)
	/*
	 *	If the recvmsg() flags aren't defined, fall back to
	 *	using recvfrom().
	 */
	to = NULL:
#endif

	/*
	 *	Catch the case where the caller passes invalid arguments.
	 */
	if (!to || !to_len) {
		if (when) *when = fr_time();
		return recvfrom(fd, buf, len, flags, from, from_len);
	}

	/*
	 *	Clang analyzer doesn't see that getsockname initialises
	 *	the memory passed to it.
	 */
#ifdef __clang_analyzer__
	memset(&si, 0, sizeof(si));
#endif

	/*
	 *	recvmsg doesn't provide sin_port so we have to
	 *	retrieve it using getsockname().
	 */
	if (getsockname(fd, (struct sockaddr *)&si, &si_len) < 0) {
		return -1;
	}

	/*
	 *	Initialize the 'to' address.  It may be INADDR_ANY here,
	 *	with a more specific address given by recvmsg(), below.
	 */
	if (si.ss_family == AF_INET) {
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR)
		return recvfrom(fd, buf, len, flags, from, from_len);
#else
		struct sockaddr_in *dst = (struct sockaddr_in *) to;
		struct sockaddr_in *src = (struct sockaddr_in *) &si;		//-V641

		if (*to_len < sizeof(*dst)) {
			errno = EINVAL;
			return -1;
		}
		*to_len = sizeof(*dst);
		*dst = *src;
#endif
	}

#ifdef AF_INET6
	else if (si.ss_family == AF_INET6) {
#if !defined(IPV6_PKTINFO)
		return recvfrom(fd, buf, len, flags, from, from_len);
#else
		struct sockaddr_in6 *dst = (struct sockaddr_in6 *) to;
		struct sockaddr_in6 *src = (struct sockaddr_in6 *) &si;		//-V641

		if (*to_len < sizeof(*dst)) {
			errno = EINVAL;
			return -1;
		}
		*to_len = sizeof(*dst);
		*dst = *src;
#endif
	}
#endif
	/*
	 *	Unknown address family.
	 */
	else {
		errno = EINVAL;
		return -1;
	}

	/* Set up iov and msgh structures. */
	memset(&cbuf, 0, sizeof(cbuf));
	memset(&msgh, 0, sizeof(struct msghdr));
	iov.iov_base = buf;
	iov.iov_len  = len;
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_name = from;
	msgh.msg_namelen = from_len ? *from_len : 0;
	msgh.msg_iov  = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* Receive one packet. */
	ret = recvmsg(fd, &msgh, flags);
	if (ret < 0) return ret;

	if (from_len) *from_len = msgh.msg_namelen;

	if (if_index) *if_index = 0;
	if (when) *when = 0;

	/* Process auxiliary received data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msgh, cmsg)) {

#ifdef IP_PKTINFO
		if ((cmsg->cmsg_level == SOL_IP) &&
		    (cmsg->cmsg_type == IP_PKTINFO)) {
			struct in_pktinfo *i = (struct in_pktinfo *) CMSG_DATA(cmsg);

			((struct sockaddr_in *)to)->sin_addr = i->ipi_addr;
			*to_len = sizeof(struct sockaddr_in);

			if (if_index) *if_index = i->ipi_ifindex;

			break;
		}
#endif

#ifdef IP_RECVDSTADDR
		if ((cmsg->cmsg_level == IPPROTO_IP) &&
		    (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			struct in_addr *i = (struct in_addr *) CMSG_DATA(cmsg);

			((struct sockaddr_in *)to)->sin_addr = *i;

			*to_len = sizeof(struct sockaddr_in);

			break;
		}
#endif

#ifdef IPV6_PKTINFO
		if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
		    (cmsg->cmsg_type == IPV6_PKTINFO)) {
			struct in6_pktinfo *i = (struct in6_pktinfo *) CMSG_DATA(cmsg);

			((struct sockaddr_in6 *)to)->sin6_addr = i->ipi6_addr;
			*to_len = sizeof(struct sockaddr_in6);

			if (if_index) *if_index = i->ipi6_ifindex;

			break;
		}
#endif

#ifdef SO_TIMESTAMP
		if (when && (cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == SO_TIMESTAMP)) {
			*when = fr_time_from_timeval((struct timeval *)CMSG_DATA(cmsg));
		}
#endif
	}

	if (when && !*when) *when = fr_time();

	return ret;
}

/** Send packet via a file descriptor, setting the src address and outbound interface
 *
 * Abstracts away the complexity of using the complexity of using sendmsg().
 *
 * @param[in] fd	The file descriptor to write to.
 * @param[in] buf	Where to read datagram data from.
 * @param[in] len	of datagram data.
 * @param[in] flags	passed unmolested to sendmsg.
 * @param[in] from	The source address.
 * @param[in] from_len	Length of the structure pointed to by from.
 * @param[in] to	The destination address.
 * @param[in] to_len	Length of the structure pointed to by to.
 * @param[in] if_index	The interface on which to send the datagram.
 *			If automatic interface selection is desired, value should be 0.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int sendfromto(int fd, void *buf, size_t len, int flags,
	       struct sockaddr *from, socklen_t from_len,
	       struct sockaddr *to, socklen_t to_len, int if_index)
{
	struct msghdr	msgh;
	struct iovec	iov;
	char		cbuf[256];

	/*
	 *	Unknown address family, die.
	 */
	if (from && (from->sa_family != AF_INET) && (from->sa_family != AF_INET6)) {
		errno = EINVAL;
		return -1;
	}

#ifdef __FreeBSD__
	/*
	 *	FreeBSD is extra pedantic about the use of IP_SENDSRCADDR,
	 *	and sendmsg will fail with EINVAL if IP_SENDSRCADDR is used
	 *	with a socket which is bound to something other than
	 *	INADDR_ANY
	 */
	struct sockaddr bound;
	socklen_t bound_len = sizeof(bound);

	if (getsockname(fd, &bound, &bound_len) < 0) {
		return -1;
	}

	switch (bound.sa_family) {
	case AF_INET:
		if (((struct sockaddr_in *) &bound)->sin_addr.s_addr != INADDR_ANY) {
			from = NULL;
		}
		break;

	case AF_INET6:
		if (!IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *) &bound)->sin6_addr)) {
			from = NULL;
		}
		break;
	}
#endif	/* !__FreeBSD__ */

	/*
	 *	If the sendmsg() flags aren't defined, fall back to
	 *	using sendto().  These flags are defined on FreeBSD,
	 *	but laying it out this way simplifies the look of the
	 *	code.
	 */
#  if !defined(IP_PKTINFO) && !defined(IP_SENDSRCADDR)
	if (from && from->sa_family == AF_INET) from = NULL;
#  endif

#  if !defined(IPV6_PKTINFO)
	if (from && from->sa_family == AF_INET6) from = NULL;
#  endif

	/*
	 *	No "from", just use regular sendto.
	 */
	if (!from || (from_len == 0)) return sendto(fd, buf, len, flags, to, to_len);

	/* Set up control buffer iov and msgh structures. */
	memset(&cbuf, 0, sizeof(cbuf));
	memset(&msgh, 0, sizeof(msgh));
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = len;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = to;
	msgh.msg_namelen = to_len;

# if defined(IP_PKTINFO) || defined(IP_SENDSRCADDR)
	if (from->sa_family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *) from;

#  ifdef IP_PKTINFO
		struct cmsghdr *cmsg;
		struct in_pktinfo *pkt;

		msgh.msg_control = cbuf;
		msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi_spec_dst = s4->sin_addr;
		pkt->ipi_ifindex = if_index;

#  elif defined(IP_SENDSRCADDR)
		struct cmsghdr *cmsg;
		struct in_addr *in;

		msgh.msg_control = cbuf;
		msgh.msg_controllen = CMSG_SPACE(sizeof(*in));

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_SENDSRCADDR;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

		in = (struct in_addr *) CMSG_DATA(cmsg);
		*in = s4->sin_addr;
#  endif
	}
#endif

#  if defined(IPV6_PKTINFO)
	if (from->sa_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) from;

		struct cmsghdr *cmsg;
		struct in6_pktinfo *pkt;

		msgh.msg_control = cbuf;
		msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi6_addr = s6->sin6_addr;
		pkt->ipi6_ifindex = if_index;
	}
#  endif	/* IPV6_PKTINFO */

	return sendmsg(fd, &msgh, flags);
}


#ifdef TESTING
/*
 *	Small test program to test recvfromto/sendfromto
 *
 *	use a virtual IP address as first argument to test
 *
 *	reply packet should originate from virtual IP and not
 *	from the default interface the alias is bound to
 */
#  include <sys/wait.h>

#  define DEF_PORT 20000		/* default port to listen on */
#  define DESTIP "127.0.0.1"	/* send packet to localhost per default */
#  define TESTSTRING "foo"	/* what to send */
#  define TESTLEN 4			/* 4 bytes */

int main(int argc, char **argv)
{
	struct sockaddr_in from, to, in;
	char buf[TESTLEN];
	char *destip = DESTIP;
	uint16_t port = DEF_PORT;
	int n, server_socket, client_socket, fl, tl, pid;
	int if_index;
	fr_time_t when;

	if (argc > 1) destip = argv[1];
	if (argc > 2) port = atoi(argv[2]);

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = INADDR_ANY;
	in.sin_port = htons(port);
	fl = tl = sizeof(struct sockaddr_in);
	memset(&from, 0, sizeof(from));
	memset(&to,  0, sizeof(to));

	switch (pid = fork()) {
		case -1:
			perror("fork");
			return 0;
		case 0:
			/* child */
			usleep(100000);
			goto client;
	}

	/* parent: server */
	server_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udpfromto_init(server_socket) != 0) {
		perror("udpfromto_init\n");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	if (bind(server_socket, (struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("server: bind");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	printf("server: waiting for packets on INADDR_ANY:%d\n", port);
	if ((n = recvfromto(server_socket, buf, sizeof(buf), 0,
	    (struct sockaddr *)&from, &fl,
	    (struct sockaddr *)&to, &tl, &if_index, &when)) < 0) {
		perror("server: recvfromto");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	printf("server: received a packet of %d bytes [%s] ", n, buf);
	printf("(src ip:port %s:%d ",
		inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	printf(" dst ip:port %s:%d) via if %i\n",
		inet_ntoa(to.sin_addr), ntohs(to.sin_port), if_index);

	printf("server: replying from address packet was received on to source address\n");

	if ((n = sendfromto(server_socket, buf, n, 0,
		(struct sockaddr *)&to, tl,
		(struct sockaddr *)&from, fl, 0)) < 0) {
		perror("server: sendfromto");
	}

	waitpid(pid, NULL, 0);
	return 0;

client:
	close(server_socket);
	client_socket = socket(PF_INET, SOCK_DGRAM, 0);
	fr_assert_fatal_msg(udpfromto_init(client_socket) != 0, "udpfromto_init - %s", fr_syserror(errno));

	/* bind client on different port */
	in.sin_port = htons(port+1);
	fr_assert_fatal_msg(bind(client_socket, (struct sockaddr *)&in, sizeof(in)) < 0,
			    "client: bind - %s", fr_syserror(errno));

	in.sin_port = htons(port);
	in.sin_addr.s_addr = inet_addr(destip);

	printf("client: sending packet to %s:%d\n", destip, port);
	fr_assert_fatal_msg(sendto(client_socket, TESTSTRING, TESTLEN, 0, (struct sockaddr *)&in, sizeof(in)) < 0,
			    "client: sendto");

	printf("client: waiting for reply from server on INADDR_ANY:%d\n", port+1);

	fr_assert_fatal_msg((n = recvfromto(client_socket, buf, sizeof(buf), 0,
	    		    (struct sockaddr *)&from, &fl,
	    		    (struct sockaddr *)&to, &tl, &if_index, NULL)) < 0,
	    		    "client: recvfromto - %s", fr_syserror(errno));

	printf("client: received a packet of %d bytes [%s] ", n, buf);
	printf("(src ip:port %s:%d",
		inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	printf(" dst ip:port %s:%d) via if %i\n",
		inet_ntoa(to.sin_addr), ntohs(to.sin_port), if_index);

	return EXIT_SUCCESS;
}

#endif /* TESTING */
#endif /* WITH_UDPFROMTO */
