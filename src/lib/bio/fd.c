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
 * @file lib/bio/fd.c
 * @brief BIO abstractions for file descriptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/fd_priv.h>
#include <freeradius-devel/bio/null.h>

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

#define ADDR_INIT do { \
		addr->when = fr_time(); \
		addr->socket.type = my->info.socket.type; \
		addr->socket.fd = -1; \
		addr->socket.inet.ifindex = my->info.socket.inet.ifindex; \
	} while (0)

/*
 *	Close the descriptor and free the bio.
 */
static int fr_bio_fd_destructor(fr_bio_fd_t *my)
{
	/*
	 *	The upstream bio must have unlinked it from the chain before calling talloc_free() on this
	 *	bio.
	 */
	fr_assert(!fr_bio_prev(&my->bio));
	fr_assert(!fr_bio_next(&my->bio));

	if (my->connect.ev) {
		talloc_const_free(my->connect.ev);
		my->connect.ev = NULL;
	}

	if (my->connect.el) {
		(void) fr_event_fd_delete(my->connect.el, my->info.socket.fd, FR_EVENT_FILTER_IO);
		my->connect.el = NULL;
	}

	if (my->cb.shutdown) my->cb.shutdown(&my->bio);

	return fr_bio_fd_close(&my->bio);
}

static int fr_bio_fd_eof(fr_bio_t *bio)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	my->info.eof = true;

	bio->read = fr_bio_null_read;
	bio->write = fr_bio_null_write;

	/*
	 *	Nothing more for us to do, tell fr_bio_eof() that it can continue with poking other BIOs.
	 */
	return 1;
}

static int fr_bio_fd_write_resume(fr_bio_t *bio)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	my->info.write_blocked = false;
	return 1;
}

/** Stream read.
 *
 *	Stream sockets return 0 at EOF.  However, we want to distinguish that from the case of datagram
 *	sockets, which return 0 when there's no data.  So we return 0 to the caller for "no data", but also
 *	call the EOF function to tell all of the related BIOs that we're at EOF.
 */
static ssize_t fr_bio_fd_read_stream(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

retry:
	rcode = read(my->info.socket.fd, buffer, size);
	if (rcode == 0) {
		fr_bio_eof(bio);
		return 0;
	}

#include "fd_read.h"

	return fr_bio_error(IO);
}

/** Connected datagram read.
 *
 *  The difference between this and stream protocols is that for datagrams. a read of zero means "no packets",
 *  where a read of zero on a steam socket means "EOF".
 *
 *  Connected sockets do _not_ update per-packet contexts.
 */
static ssize_t fr_bio_fd_read_connected_datagram(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

retry:
	rcode = read(my->info.socket.fd, buffer, size);
	if (rcode == 0) return rcode;

#include "fd_read.h"

	return fr_bio_error(IO);
}

/** Read from a UDP socket where we know our IP
 */
static ssize_t fr_bio_fd_recvfrom(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	socklen_t salen;
	struct sockaddr_storage sockaddr;

retry:
	salen = sizeof(sockaddr);

	rcode = recvfrom(my->info.socket.fd, buffer, size, 0, (struct sockaddr *) &sockaddr, &salen);
	if (rcode > 0) {
		fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

		ADDR_INIT;

		addr->socket.inet.dst_ipaddr = my->info.socket.inet.src_ipaddr;
		addr->socket.inet.dst_port = my->info.socket.inet.src_port;

		(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.src_ipaddr, &addr->socket.inet.src_port,
					       &sockaddr, salen);
	}

	if (rcode == 0) return rcode;

#include "fd_read.h"

	return fr_bio_error(IO);
}

/** Write to fd.
 *
 *  This function is used for connected sockets, where we ignore the packet_ctx.
 */
static ssize_t fr_bio_fd_write(fr_bio_t *bio, UNUSED void *packet_ctx, const void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	/*
	 *	FD bios do nothing on flush.
	 */
	if (!buffer) return 0;

retry:
	/*
	 *	We could call send() instead of write()!  Posix says:
	 *
	 *	"A write was attempted on a socket that is shut down for writing, or is no longer
	 *	connected. In the latter case, if the socket is of type SOCK_STREAM, a SIGPIPE signal shall
	 *	also be sent to the thread."
	 *
	 *	We can override this behavior by calling send(), and passing the special flag which says
	 *	"don't do that!".  The system call will then return EPIPE, which indicates that the socket is
	 *	no longer usable.
	 *
	 *	However, we also set the SO_NOSIGPIPE socket option, which means that we can just call write()
	 *	here.
	 */
	rcode = write(my->info.socket.fd, buffer, size);

#include "fd_write.h"

	return fr_bio_error(IO);
}

/** Write to a UDP socket where we know our IP
 *
 */
static ssize_t fr_bio_fd_sendto(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);
	socklen_t salen;
	struct sockaddr_storage sockaddr;

	/*
	 *	FD bios do nothing on flush.
	 */
	if (!buffer) return 0;

	// get destination IP
	(void) fr_ipaddr_to_sockaddr(&sockaddr, &salen, &addr->socket.inet.dst_ipaddr, addr->socket.inet.dst_port);

retry:
	rcode = sendto(my->info.socket.fd, buffer, size, 0, (struct sockaddr *) &sockaddr, salen);

#include "fd_write.h"

	return fr_bio_error(IO);
}


#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR) || defined(IPV6_PKTINFO)
static ssize_t fd_fd_recvfromto_common(fr_bio_fd_t *my, void *packet_ctx, void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	struct sockaddr_storage from;
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

#ifdef STATIC_ANALYZER
	from.ss_family = AF_UNSPEC;
#endif

	memset(&my->cbuf, 0, sizeof(my->cbuf));
	memset(&my->msgh, 0, sizeof(struct msghdr));

	my->iov = (struct iovec) {
		.iov_base	= buffer,
		.iov_len	= size,
	};

	my->msgh = (struct msghdr) {
		.msg_control	= my->cbuf,
		.msg_controllen	= sizeof(my->cbuf),
		.msg_name	= &from,
		.msg_namelen	= sizeof(from),
		.msg_iov	= &my->iov,
		.msg_iovlen	= 1,
		.msg_flags	= 0,
	};

retry:
	rcode = recvmsg(my->info.socket.fd, &my->msgh, 0);
	if (rcode > 0) {
		ADDR_INIT;

		(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.src_ipaddr, &addr->socket.inet.src_port,
					       &from, my->msgh.msg_namelen);
	}

	if (rcode == 0) return rcode;

#include "fd_read.h"

	return fr_bio_error(IO);
}
#endif

#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR)

/** Read from a UDP socket where we can change our IP, IPv4 version.
 */
static ssize_t fr_bio_fd_recvfromto4(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	struct cmsghdr *cmsg;
	fr_time_t when = fr_time_wrap(0);
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

	rcode = fd_fd_recvfromto_common(my, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

DIAG_OFF(sign-compare)
	/* Process auxiliary received data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&my->msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&my->msgh, cmsg)) {
DIAG_ON(sign-compare)

#ifdef IP_PKTINFO
		if ((cmsg->cmsg_level == SOL_IP) &&
		    (cmsg->cmsg_type == IP_PKTINFO)) {
			struct in_pktinfo *i = (struct in_pktinfo *) CMSG_DATA(cmsg);
			struct sockaddr_in to;

			to.sin_addr = i->ipi_addr;

			(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.dst_ipaddr, &addr->socket.inet.dst_port,
						       (struct sockaddr_storage *) &to, sizeof(struct sockaddr_in));
			addr->socket.inet.ifindex = i->ipi_ifindex;
			break;
		}
#endif

#ifdef IP_RECVDSTADDR
		if ((cmsg->cmsg_level == IPPROTO_IP) &&
		    (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			struct in_addr *i = (struct in_addr *) CMSG_DATA(cmsg);
			struct sockaddr_in to;

			to.sin_addr = *i;
			(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.dst_ipaddr, &addr->socket.inet.dst_port,
						       (struct sockaddr_storage *) &to, sizeof(struct sockaddr_in));
			break;
		}
#endif

#ifdef SO_TIMESTAMPNS
		if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == SO_TIMESTAMPNS)) {
			when = fr_time_from_timespec((struct timespec *)CMSG_DATA(cmsg));
		}

#elif defined(SO_TIMESTAMP)
		if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == SO_TIMESTAMP)) {
			when = fr_time_from_timeval((struct timeval *)CMSG_DATA(cmsg));
		}
#endif
	}

	if fr_time_eq(when, fr_time_wrap(0)) when = fr_time();

	addr->when = when;

	return rcode;
}

/** Send to UDP socket where we can change our IP, IPv4 version.
 */
static ssize_t fr_bio_fd_sendfromto4(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	struct cmsghdr *cmsg;
	struct sockaddr_storage to;
	socklen_t to_len;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

	memset(&my->cbuf, 0, sizeof(my->cbuf));
	memset(&my->msgh, 0, sizeof(struct msghdr));

	(void) fr_ipaddr_to_sockaddr(&to, &to_len, &addr->socket.inet.dst_ipaddr, addr->socket.inet.dst_port);

	my->iov = (struct iovec) {
		.iov_base	= UNCONST(void *, buffer),
		.iov_len	= size,
	};

	my->msgh = (struct msghdr) {
		.msg_control	= my->cbuf,
		// controllen is set below
		.msg_name	= &to,
		.msg_namelen	= to_len,
		.msg_iov	= &my->iov,
		.msg_iovlen	= 1,
		.msg_flags	= 0,
	};

	{
#ifdef IP_PKTINFO
		struct in_pktinfo *pkt;

		my->msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&my->msgh);
		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi_spec_dst = addr->socket.inet.src_ipaddr.addr.v4;
		pkt->ipi_ifindex = addr->socket.inet.ifindex;

#elif defined(IP_SENDSRCADDR)
		struct in_addr *in;

		my->msgh.msg_controllen = CMSG_SPACE(sizeof(*in));

		cmsg = CMSG_FIRSTHDR(&my->msgh);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_SENDSRCADDR;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

		in = (struct in_addr *) CMSG_DATA(cmsg);
		*in = addr->socket.inet.src_ipaddr.addr.v4;
#endif
	}

retry:
	rcode = sendmsg(my->info.socket.fd, &my->msgh, 0);

#include "fd_write.h"

	return fr_bio_error(IO);
}

static inline int fr_bio_fd_udpfromto_init4(int fd)
{
	int proto = 0, flag = 0, opt = 1;

#ifdef HAVE_IP_PKTINFO
	/*
	 *	Linux
	 */
	proto = SOL_IP;
	flag = IP_PKTINFO;

#elif defined(IP_RECVDSTADDR)
	/*
	 *	Set the IP_RECVDSTADDR option (BSD).  Note:
	 *	IP_RECVDSTADDR == IP_SENDSRCADDR
	 */
	proto = IPPROTO_IP;
	flag = IP_RECVDSTADDR;
#endif

	return setsockopt(fd, proto, flag, &opt, sizeof(opt));
}
#endif

#if defined(IPV6_PKTINFO)
/** Read from a UDP socket where we can change our IP, IPv4 version.
 */
static ssize_t fr_bio_fd_recvfromto6(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	struct cmsghdr *cmsg;
	fr_time_t when = fr_time_wrap(0);
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

	rcode = fd_fd_recvfromto_common(my, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

DIAG_OFF(sign-compare)
	/* Process auxiliary received data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&my->msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&my->msgh, cmsg)) {
DIAG_ON(sign-compare)

		if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
		    (cmsg->cmsg_type == IPV6_PKTINFO)) {
			struct in6_pktinfo *i = (struct in6_pktinfo *) CMSG_DATA(cmsg);
			struct sockaddr_in6 to;

			to.sin6_addr = i->ipi6_addr;

			(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.dst_ipaddr, &addr->socket.inet.dst_port,
						       (struct sockaddr_storage *) &to, sizeof(struct sockaddr_in6));
			addr->socket.inet.ifindex = i->ipi6_ifindex;
			break;
		}

#ifdef SO_TIMESTAMPNS
		if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == SO_TIMESTAMPNS)) {
			when = fr_time_from_timespec((struct timespec *)CMSG_DATA(cmsg));
		}

#elif defined(SO_TIMESTAMP)
		if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == SO_TIMESTAMP)) {
			when = fr_time_from_timeval((struct timeval *)CMSG_DATA(cmsg));
		}
#endif
	}

	if fr_time_eq(when, fr_time_wrap(0)) when = fr_time();

	addr->when = when;

	return rcode;
}

/** Send to UDP socket where we can change our IP, IPv4 version.
 */
static ssize_t fr_bio_fd_sendfromto6(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	struct cmsghdr *cmsg;
	struct sockaddr_storage to;
	socklen_t to_len;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

	memset(&my->cbuf, 0, sizeof(my->cbuf));
	memset(&my->msgh, 0, sizeof(struct msghdr));

	(void) fr_ipaddr_to_sockaddr(&to, &to_len, &addr->socket.inet.dst_ipaddr, addr->socket.inet.dst_port);

	my->iov = (struct iovec) {
		.iov_base	= UNCONST(void *, buffer),
		.iov_len	= size,
	};

	my->msgh = (struct msghdr) {
		.msg_control	= my->cbuf,
		// controllen is set below
		.msg_name	= &to,
		.msg_namelen	= to_len,
		.msg_iov	= &my->iov,
		.msg_iovlen	= 1,
		.msg_flags	= 0,
	};

	{
		struct in6_pktinfo *pkt;

		my->msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&my->msgh);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi6_addr = addr->socket.inet.src_ipaddr.addr.v6;
		pkt->ipi6_ifindex = addr->socket.inet.ifindex;
	}

retry:
	rcode = sendmsg(my->info.socket.fd, &my->msgh, 0);

#include "fd_write.h"

	return fr_bio_error(IO);
}


static inline int fr_bio_fd_udpfromto_init6(int fd)
{
	int opt = 1;

	return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
}
#endif

int fr_filename_to_sockaddr(struct sockaddr_un *sun, socklen_t *sunlen, char const *filename)
{
	size_t len;

	len = strlen(filename);
	if (len >= sizeof(sun->sun_path)) {
		fr_strerror_const("Failed parsing unix domain socket filename: Name is too long");
		return -1;
	}

	sun->sun_family = AF_LOCAL;
	memcpy(sun->sun_path, filename, len + 1); /* SUN_LEN will do strlen */

	*sunlen = SUN_LEN(sun);

	return 0;
}

int fr_bio_fd_socket_name(fr_bio_fd_t *my)
{
        socklen_t salen;
        struct sockaddr_storage salocal;

	/*
	 *	Already set: do nothing.
	 */
	if (!fr_ipaddr_is_inaddr_any(&my->info.socket.inet.src_ipaddr) &&
	    (my->info.socket.inet.src_port != 0)) {
		return 0;
	}

	/*
	 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
	 *	kernel instead binds us to a 1.2.3.4.  So once the
	 *	socket is bound, ask it what it's IP address is.
	 */
	salen = sizeof(salocal);
	memset(&salocal, 0, salen);
	if (getsockname(my->info.socket.fd, (struct sockaddr *) &salocal, &salen) < 0) {
		fr_strerror_printf("Failed getting socket name: %s", fr_syserror(errno));
		return -1;
	}

	if (fr_ipaddr_from_sockaddr(&my->info.socket.inet.src_ipaddr, &my->info.socket.inet.src_port, &salocal, salen) < 0) return -1;

	fr_ipaddr_get_scope_id(&my->info.socket.inet.src_ipaddr);
	my->info.socket.inet.ifindex = my->info.socket.inet.src_ipaddr.scope_id;

	return 0;
}

static void fr_bio_fd_set_open(fr_bio_fd_t *my)
{
	my->info.state = FR_BIO_FD_STATE_OPEN;
	my->info.eof = false;
	my->info.read_blocked = false;
	my->info.write_blocked = false;

	/*
	 *	Tell the caller that the socket is ready for application data.
	 */
	if (my->cb.connected) my->cb.connected(&my->bio);
}


/** Try to connect().
 *
 *  If connect is blocking, we either succeed or error immediately.  Otherwise, the caller has to select the
 *  socket for writeability, and then call fr_bio_fd_connect() as soon as the socket is writeable.
 */
static ssize_t fr_bio_fd_try_connect(fr_bio_fd_t *my)
{
        int tries = 0;
	int rcode;
        socklen_t salen;
        struct sockaddr_storage sockaddr;

	if (my->info.socket.af != AF_LOCAL) {
		rcode = fr_ipaddr_to_sockaddr(&sockaddr, &salen, &my->info.socket.inet.dst_ipaddr, my->info.socket.inet.dst_port);
	} else {
		rcode = fr_filename_to_sockaddr((struct sockaddr_un *) &sockaddr, &salen, my->info.socket.unix.path);
	}

	if (rcode < 0) {
		fr_bio_shutdown(&my->bio);
		return fr_bio_error(GENERIC);
	}

        my->info.state = FR_BIO_FD_STATE_CONNECTING;

retry:
        if (connect(my->info.socket.fd, (struct sockaddr *) &sockaddr, salen) == 0) {
		fr_bio_fd_set_open(my);

		/*
		 *	The source IP may have changed, so get the new one.
		 */
		if (fr_bio_fd_socket_name(my) < 0) goto fail;

                if (fr_bio_fd_init_common(my) < 0) goto fail;

                return 0;
        }

        switch (errno) {
        case EINTR:
                tries++;
                if (tries <= my->max_tries) goto retry;
                FALL_THROUGH;

                /*
                 *      This shouldn't happen, but we'll allow it
                 */
        case EALREADY:
                FALL_THROUGH;

                /*
                 *      Once the socket is writable, it will be active, or in an error state.  The caller has
                 *      to call fr_bio_fd_connect() before calling write()
                 */
        case EINPROGRESS:
		if (!my->info.write_blocked) {
			my->info.write_blocked = true;

			rcode = fr_bio_write_blocked((fr_bio_t *) my);
			if (rcode < 0) return rcode;
		}

		return fr_bio_error(IO_WOULD_BLOCK);

        default:
                break;
        }

fail:
	fr_bio_shutdown(&my->bio);
        return fr_bio_error(IO);
}


/** Files are a special case of connected sockets.
 *
 */
static int fr_bio_fd_init_file(fr_bio_fd_t *my)
{
	fr_bio_fd_set_open(my);

	/*
	 *	Other flags may be O_CREAT, etc.
	 */
	switch (my->info.cfg->flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_RDONLY:
		my->bio.read = fr_bio_fd_read_stream;
		my->bio.write = fr_bio_fail_write;
		break;

	case O_WRONLY:
		my->bio.read = fr_bio_fail_read;
		my->bio.write = fr_bio_fd_write;
		break;

	case O_RDWR:
		my->bio.read = fr_bio_fd_read_stream;
		my->bio.write = fr_bio_fd_write;
		break;

	default:
		fr_strerror_const("Invalid flag for opening file");
		return -1;
	}

	return 0;
}

int fr_bio_fd_init_connected(fr_bio_fd_t *my)
{
	int rcode;

	if (my->info.socket.af == AF_FILE_BIO) return fr_bio_fd_init_file(my);

	/*
	 *	The source IP can be unspecified.  It will get updated after we call connect().
	 */

	/*
	 *	All connected sockets must have a destination IP.
	 */
	if (fr_ipaddr_is_inaddr_any(&my->info.socket.inet.dst_ipaddr)) {
		fr_strerror_const("Destination IP address cannot be wildcard");
		return -1;
	}

	/*
	 *	Don't do any reads until we're connected.
	 */
	my->bio.read = fr_bio_null_read;
	my->bio.write = fr_bio_null_write;

	my->info.eof = false;

	my->info.read_blocked = false;
	my->info.write_blocked = false;

#ifdef SO_NOSIGPIPE
	/*
	 *	Although the server ignore SIGPIPE, some operating systems like BSD and OSX ignore the
	 *	ignoring.
	 *
	 *	Fortunately, those operating systems usually support SO_NOSIGPIPE.  We set that to prevent
	 *	them raising the signal in the first place.
	 */
	{
		int on = 1;

		setsockopt(my->info.socket.fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	}
#endif

	/*
	 *	Don't call connect() if the socket is synchronous, it will block.
	 */
	if (!my->info.cfg->async) return 0;

	rcode = fr_bio_fd_try_connect(my);
	if (rcode == 0) return 0;

	if (rcode != fr_bio_error(IO_WOULD_BLOCK)) return rcode;

	/*
	 *	The socket is blocked, and should be selected for writing.
	 */
	fr_assert(my->info.write_blocked);
	fr_assert(my->info.state == FR_BIO_FD_STATE_CONNECTING);

	return 0;
}

int fr_bio_fd_init_common(fr_bio_fd_t *my)
{
	if (my->info.socket.type == SOCK_STREAM) {				//!< stream socket
		my->bio.read = fr_bio_fd_read_stream;
		my->bio.write = fr_bio_fd_write;

	} else if (my->info.type == FR_BIO_FD_CONNECTED) {		       	//!< connected datagram
		my->bio.read = fr_bio_fd_read_connected_datagram;
		my->bio.write = fr_bio_fd_write;

	} else if (!fr_ipaddr_is_inaddr_any(&my->info.socket.inet.src_ipaddr)) { //!< we know our IP address
		my->bio.read = fr_bio_fd_recvfrom;
		my->bio.write = fr_bio_fd_sendto;

#if defined(IP_PKTINFO) || defined(IP_RECVDSTADDR)
	} else if (my->info.socket.inet.src_ipaddr.af == AF_INET) {		//!< we don't know our IPv4
		if (fr_bio_fd_udpfromto_init4(my->info.socket.fd) < 0) return -1;

		my->bio.read = fr_bio_fd_recvfromto4;
		my->bio.write = fr_bio_fd_sendfromto4;
#endif

#if defined(IPV6_PKTINFO)
	} else if (my->info.socket.inet.src_ipaddr.af == AF_INET6) {		//!< we don't know our IPv6

		if (fr_bio_fd_udpfromto_init6(my->info.socket.fd) < 0) return -1;

		my->bio.read = fr_bio_fd_recvfromto6;
		my->bio.write = fr_bio_fd_sendfromto6;
#endif

	} else {
		fr_strerror_const("Failed initializing socket: cannot determine what to do");
		return -1;
	}

	fr_bio_fd_set_open(my);

	return 0;
}

/** Return an fd on read()
 *
 *  With packet_ctx containing information about the socket.
 */
static ssize_t fr_bio_fd_read_accept(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	int fd, tries = 0;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	socklen_t salen;
	struct sockaddr_storage sockaddr;

	if (size < sizeof(int)) return fr_bio_error(BUFFER_TOO_SMALL);

	salen = sizeof(sockaddr);

retry:
#ifdef __linux__
	/*
	 *	Set these flags immediately on the new socket.
	 */
	fd = accept4(my->info.socket.fd, (struct sockaddr *) &sockaddr, &salen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
	fd = accept(my->info.socket.fd, (struct sockaddr *) &sockaddr, &salen);
#endif
	if (fd >= 0) {
		fr_bio_fd_packet_ctx_t *addr = fr_bio_fd_packet_ctx(my, packet_ctx);

		ADDR_INIT;

		(void) fr_ipaddr_from_sockaddr(&addr->socket.inet.src_ipaddr, &addr->socket.inet.src_port,
					       &sockaddr, salen);

		addr->socket.inet.dst_ipaddr = my->info.socket.inet.src_ipaddr;
		addr->socket.inet.dst_port = my->info.socket.inet.src_port;
		addr->socket.fd = fd; /* might as well! */

		*(int *) buffer = fd;
		return sizeof(int);
	}

	switch (errno) {
	case EINTR:
		/*
		 *	Try a few times before giving up.
		 */
		tries++;
		if (tries <= my->max_tries) goto retry;
		return 0;

		/*
		 *	We can ignore these errors.
		 */
	case ECONNABORTED:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
	case EWOULDBLOCK:
#endif
	case EAGAIN:
#ifdef EPERM
	case EPERM:
#endif
#ifdef ETIMEDOUT
	case ETIMEDOUT:
#endif
		return 0;

	default:
		/*
		 *	Some other error, it's fatal.
		 */
		fr_bio_shutdown(&my->bio);
		break;
	}

	return fr_bio_error(IO);
}


int fr_bio_fd_init_listen(fr_bio_fd_t *my)
{
	my->bio.read = fr_bio_fd_read_accept;
	my->bio.write = fr_bio_null_write;

	if (listen(my->info.socket.fd, 8) < 0) {
		fr_strerror_printf("Failed opening setting FD_CLOEXE: %s", fr_syserror(errno));
		return -1;
	}

	fr_bio_fd_set_open(my);

	return 0;
}

/** Allocate a FD bio
 *
 *  The caller is responsible for tracking the FD, and all associated management of it.  The bio API is
 *  intended to be simple, and does not provide wrapper functions for various ioctls.  The caller should
 *  instead do that work.
 *
 *  Once the FD is give to the bio, its lifetime is "owned" by the bio.  Calling talloc_free(bio) will close
 *  the FD.
 *
 *  The caller can still manage the FD for being readable / writeable.  However, the caller should not call
 *  this bio directly (unless it is the only one).  Instead, the caller should read from / write to the
 *  previous bio which will then eventually call this one.
 *
 *  Before updating any event handler readable / writeable callbacks, the caller should check
 *  fr_bio_fd_at_eof().  If true, then the handlers should not be inserted.  The previous bios should still be
 *  called to process any pending data, until they return EOF.
 *
 *  The main purpose of an FD bio is to wrap the FD in a bio container.  That, and handling retries on read /
 *  write, along with returning EOF as an error instead of zero.
 *
 *  Note that the read / write functions can return partial data.  It is the callers responsibility to ensure
 *  that any writes continue from where they left off (otherwise dat awill be missing).  And any partial reads
 *  should go to a memory bio.
 *
 *  If a read returns EOF, then the FD remains open until talloc_free(bio) or fr_bio_fd_close() is called.
 *
 *  @param ctx		the talloc ctx
 *  @param cfg		structure holding configuration information
 *  @param offset	only for unconnected datagram sockets, where #fr_bio_fd_packet_ctx_t is stored
 *  @return
 *	- NULL on error, memory allocation failed
 *	- !NULL the bio
 */
fr_bio_t *fr_bio_fd_alloc(TALLOC_CTX *ctx, fr_bio_fd_config_t const *cfg, size_t offset)
{
	fr_bio_fd_t *my;

	my = talloc_zero(ctx, fr_bio_fd_t);
	if (!my) return NULL;

	my->max_tries = 4;
	my->offset = offset;

	if (!cfg) {
		/*
		 *	Add place-holder information.
		 */
		my->info = (fr_bio_fd_info_t) {
			.socket = {
				.af = AF_UNSPEC,
			},
			.type = FR_BIO_FD_UNCONNECTED,
			.read_blocked = false,
			.write_blocked = false,
			.eof = false,
			.state = FR_BIO_FD_STATE_CLOSED,
		};

		my->bio.read = fr_bio_null_read;
		my->bio.write = fr_bio_null_write;
	} else {
		my->info.state = FR_BIO_FD_STATE_CLOSED;

		if (fr_bio_fd_open(&my->bio, cfg) < 0) {
			talloc_free(my);
			return NULL;
		}
	}

	my->priv_cb.eof = fr_bio_fd_eof;
	my->priv_cb.write_resume = fr_bio_fd_write_resume;

	talloc_set_destructor(my, fr_bio_fd_destructor);
	return (fr_bio_t *) my;
}

/** Close the FD, but leave the bio allocated and alive.
 *
 */
int fr_bio_fd_close(fr_bio_t *bio)
{
	int rcode;
	int tries = 0;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	if (my->info.state == FR_BIO_FD_STATE_CLOSED) return 0;

	/*
	 *	Shut the bio down cleanly.
	 */
	rcode = fr_bio_shutdown(bio);
	if (rcode < 0) return rcode;

	my->bio.read = fr_bio_fail_read;
	my->bio.write = fr_bio_fail_write;

	/*
	 *	Shut down the connected socket.  The only errors possible here are things we can't do anything
	 *	about.
	 *
	 *	shutdown() will close ALL versions of this file descriptor, even if it's (somehow) used in
	 *	another process.  shutdown() will also tell the kernel to gracefully close the connected
	 *	socket, so that it can signal the other end, instead of having the connection disappear.
	 *
	 *	This shouldn't strictly be necessary, as no other processes should be sharing this file
	 *	descriptor.  But it's the safe (and polite) thing to do.
	 */
	if (my->info.type == FR_BIO_FD_CONNECTED) {
		(void) shutdown(my->info.socket.fd, SHUT_RDWR);
	}

retry:
	rcode = close(my->info.socket.fd);
	if (rcode < 0) {
		switch (errno) {
		case EINTR:
		case EIO:
			tries++;
			if (tries < my->max_tries) goto retry;
			return -1;

		default:
			/*
			 *	EBADF, or other unrecoverable error.  We just call it closed, and continue.
			 */
			break;
		}
	}

	my->info.state = FR_BIO_FD_STATE_CLOSED;
	my->info.read_blocked = true;
	my->info.write_blocked = true;
	my->info.eof = true;

	return 0;
}

/** FD error when trying to connect, give up on the BIO.
 *
 */
static void fr_bio_fd_el_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_bio_fd_t *my = talloc_get_type_abort(uctx, fr_bio_fd_t);

	my->info.connect_errno = fd_errno;

	if (my->connect.error) {
		my->connect.error(&my->bio);
	}

	fr_bio_shutdown(&my->bio);
}

/** Connect callback for when the socket is writable.
 *
 *  We try to connect the socket, and if so, call the application which should update the BIO status.
 */
static void fr_bio_fd_el_connect(NDEBUG_UNUSED fr_event_list_t *el, NDEBUG_UNUSED int fd, NDEBUG_UNUSED int flags, void *uctx)
{
	fr_bio_fd_t *my = talloc_get_type_abort(uctx, fr_bio_fd_t);

	fr_assert(my->info.type == FR_BIO_FD_CONNECTED);
	fr_assert(my->info.state == FR_BIO_FD_STATE_CONNECTING);
	fr_assert(my->connect.el == el); /* and not NULL */
	fr_assert(my->connect.success != NULL);
	fr_assert(my->info.socket.fd == fd);

#ifndef NDEBUG
	/*
	 *	This check shouldn't be necessary, as we have a kqeueue error callback.  That should be called
	 *	when there's a connect error.
	 */
	{
		int error;
		socklen_t socklen = sizeof(error);

		/*
		 *	The socket is writeable.  Let's see if there's an error.
		 *
		 *	Unix Network Programming says:
		 *
		 *	""If so_error is nonzero when the process calls write, -1 is returned with errno set to the
		 *	value of SO_ERROR (p. 495 of TCPv2) and SO_ERROR is reset to 0.  We have to check for the
		 *	error, and if there's no error, set the state to "open". ""
		 *
		 *	The same applies to connect().  If a non-blocking connect returns INPROGRESS, it may later
		 *	become writable.  It will be writable even if the connection fails.  Rather than writing some
		 *	random application data, we call SO_ERROR, and get the underlying error.
		 */
		if (getsockopt(my->info.socket.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &socklen) < 0) {
			fr_bio_fd_el_error(el, fd, flags, errno, uctx);
			return;
		}

		fr_assert(error == 0);

		/*
		 *	There was an error, we call the error handler.
		 */
		if (error) {
			fr_bio_fd_el_error(el, fd, flags, error, uctx);
			return;
		}
	}
#endif

	/*
	 *	Try to connect it.  Any magic handling is done in the callbacks.
	 */
	if (fr_bio_fd_try_connect(my) < 0) return;

	fr_assert(my->connect.success);

	if (my->connect.ev) {
		talloc_const_free(my->connect.ev);
		my->connect.ev = NULL;
	}
	my->connect.el = NULL;

	/*
	 *	This function MUST change the read/write/error callbacks for the FD.
	 */
	my->connect.success(&my->bio);
}

/**  We have a timeout on the conenction
 *
 */
static void fr_bio_fd_el_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_bio_fd_t *my = talloc_get_type_abort(uctx, fr_bio_fd_t);

	fr_assert(my->connect.timeout);

	my->connect.timeout(&my->bio);

	fr_bio_shutdown(&my->bio);
}


/** Finalize a connect()
 *
 *  connect() said "come back when the socket is writeable".  It's now writeable, so we check if there was a
 *  connection error.
 *
 *  @param bio		the binary IO handler
 *  @param el		the event list
 *  @param connected_cb	callback to run when the BIO is connected
 *  @param error_cb	callback to run when the FD has an error
 *  @param timeout	when to time out the connect() attempt
 *  @param timeout_cb	to call when the timeout runs.
 *  @return
 *	- <0 on error
 *	- 0 for "try again later".  If callbacks are set, the callbacks will try again.  Otherwise the application has to try again.
 *	- 1 for "we are now connected".
 */
int fr_bio_fd_connect_full(fr_bio_t *bio, fr_event_list_t *el, fr_bio_callback_t connected_cb,
			   fr_bio_callback_t error_cb,
			   fr_time_delta_t *timeout, fr_bio_callback_t timeout_cb)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	/*
	 *	We shouldn't be connected an unconnected socket.
	 */
	if (my->info.type == FR_BIO_FD_UNCONNECTED) {
	error:
#ifdef ECONNABORTED
		my->info.connect_errno = ECONNABORTED;
#else
		my->info.connect_errno = ECONNREFUSED;
#endif
		if (error_cb) error_cb(bio);
		fr_bio_shutdown(&my->bio);
		return fr_bio_error(GENERIC);
	}

	/*
	 *	The initial open may have succeeded in connecting the socket.  In which case we just run the
	 *	callbacks and return.
	 */
	if (my->info.state == FR_BIO_FD_STATE_OPEN) {
	connected:
		if (connected_cb) connected_cb(bio);

		return 1;
	}

	/*
	 *	The caller may just call us without caring about what the underlying BIO is.  In which case we
	 *	need to be safe.
	 */
	if ((my->info.socket.af == AF_FILE_BIO) || (my->info.type == FR_BIO_FD_LISTEN)) {
		fr_bio_fd_set_open(my);
		goto connected;
	}

	/*
	 *	It must be in the connecting state, i.e. not INVALID or CLOSED.
	 */
	if (my->info.state != FR_BIO_FD_STATE_CONNECTING) goto error;

	/*
	 *	No callback
	 */
	if (!connected_cb) {
		ssize_t rcode;

		rcode = fr_bio_fd_try_connect(my);
		if (rcode < 0) {
			if (error_cb) error_cb(bio);
			return rcode; /* it already called shutdown */
		}

		return 1;
	}

	/*
	 *	It's not connected, the caller has to try again.
	 */
	if (!el) return 0;

	/*
	 *	Set the callbacks to run when something happens.
	 */
	my->connect.success = connected_cb;
	my->connect.error = error_cb;
	my->connect.timeout = timeout_cb;

	/*
	 *	Set the timeout callback if asked.
	 */
	if (timeout_cb) {
		if (fr_event_timer_in(my, el, &my->connect.ev, *timeout, fr_bio_fd_el_timeout, my) < 0) {
			goto error;
		}
	}

	/*
	 *	Set the FD callbacks, and tell the caller that we're not connected.
	 */
	if (fr_event_fd_insert(my, NULL, el, my->info.socket.fd, NULL,
			       fr_bio_fd_el_connect, fr_bio_fd_el_error, my) < 0) {
		goto error;
	}
	my->connect.el = el;

	return 0;
}

/** Returns a pointer to the bio-specific information.
 *
 */
fr_bio_fd_info_t const *fr_bio_fd_info(fr_bio_t *bio)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	return &my->info;
}


/** Discard all reads from a UDP socket.
 */
static ssize_t fr_bio_fd_read_discard(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	int tries = 0;
	ssize_t rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

retry:
	rcode = read(my->info.socket.fd, buffer, size);
	if (rcode >= 0) return 0; /* always return that we read no data */

#undef flag_blocked
#define flag_blocked read_blocked
#include "fd_errno.h"

	return fr_bio_error(IO);
}

/** Mark up a bio as write-only
 *
 */
int fr_bio_fd_write_only(fr_bio_t *bio)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	switch (my->info.type) {
	case FR_BIO_FD_INVALID:
		return -1;

	case FR_BIO_FD_UNCONNECTED:
		if (my->info.socket.type != SOCK_DGRAM) {
			fr_strerror_const("Only datagram sockets can be marked 'write-only'");
			return -1;
		}
		goto set_recv_buff_zero;

	case FR_BIO_FD_CONNECTED:
	case FR_BIO_FD_ACCEPTED:
		/*
		 *	Further reads are disallowed.  However, this likely has no effect for UDP sockets.
		 */
		if (shutdown(my->info.socket.fd, SHUT_RD) < 0) {
			fr_strerror_printf("Failed shutting down connected socket - %s", fr_syserror(errno));
			return -1;
		}

	set_recv_buff_zero:
#ifdef __linux__
#ifdef SO_RCVBUF
		/*
		 *	On Linux setting the receive buffer to zero has the effect of discarding all incoming
		 *	data in the kernel.  With macOS and others it's an invalid value.
		 */
		{
			int opt = 0;

			if (setsockopt(my->info.socket.fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
				fr_strerror_printf("Failed setting SO_RCVBUF: %s", fr_syserror(errno));
				return -1;
			}
		}
#endif
#endif
		break;

	case FR_BIO_FD_LISTEN:
		fr_strerror_const("Only unconnected sockets can be marked 'write-only'");
		return -1;
	}

	/*
	 *	No matter what the possibilities above, we replace the read function with a "discard"
	 *	function.
	 */
	my->bio.read = fr_bio_fd_read_discard;
	return 0;
}

/** Alternative to calling fr_bio_read() on new socket.
 *
 */
int fr_bio_fd_accept(TALLOC_CTX *ctx, fr_bio_t **out_p, fr_bio_t *bio)
{
	int fd, tries = 0;
	int rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);
	socklen_t salen;
	struct sockaddr_storage sockaddr;
	fr_bio_fd_t *out;
	fr_bio_fd_config_t *cfg;

	salen = sizeof(sockaddr);
	*out_p = NULL;

	fr_assert(my->info.type == FR_BIO_FD_LISTEN);
	fr_assert(my->info.socket.type == SOCK_STREAM);

retry:
#ifdef __linux__
	/*
	 *	Set these flags immediately on the new socket.
	 */
	fd = accept4(my->info.socket.fd, (struct sockaddr *) &sockaddr, &salen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
	fd = accept(my->info.socket.fd, (struct sockaddr *) &sockaddr, &salen);
#endif
	if (fd < 0) {
		switch (errno) {
		case EINTR:
			/*
			 *	Try a few times before giving up.
			 */
			tries++;
			if (tries <= my->max_tries) goto retry;
			return 0;

			/*
			 *	We can ignore these errors.
			 */
		case ECONNABORTED:
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:
#endif
		case EAGAIN:
#ifdef EPERM
		case EPERM:
#endif
#ifdef ETIMEDOUT
		case ETIMEDOUT:
#endif
			return 0;

		default:
			/*
			 *	Some other error, it's fatal.
			 */
			fr_bio_shutdown(&my->bio);
			break;
		}

		return fr_bio_error(IO);
	}

	/*
	 *	Allocate the base BIO and set it up.
	 */
	out = (fr_bio_fd_t *) fr_bio_fd_alloc(ctx, NULL, my->offset);
	if (!out) {
		close(fd);
		return fr_bio_error(GENERIC);
	}

	/*
	 *	We have a file descriptor.  Initialize the configuration with the new information.
	 */
	cfg = talloc_memdup(out, my->info.cfg, sizeof(*my->info.cfg));
	if (!cfg) {
		fr_strerror_const("Out of memory");
		close(fd);
		talloc_free(out);
		return fr_bio_error(GENERIC);
	}

	/*
	 *	Set the type to ACCEPTED, and set up the rest of the callbacks to match.
	 */
	cfg->type = FR_BIO_FD_ACCEPTED;
	out->info.socket.fd = fd;

	rcode = fr_bio_fd_open(bio, cfg);
	if (rcode < 0) {
		talloc_free(out);
		return rcode;
	}

	fr_assert(out->info.type == FR_BIO_FD_CONNECTED);

	*out_p = (fr_bio_t *) out;
	return 1;
}
