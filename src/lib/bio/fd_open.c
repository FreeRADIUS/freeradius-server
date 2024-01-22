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
 * @file lib/bio/fd_open.c
 * @brief BIO abstractions for opening file descriptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/fd_priv.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/cap.h>

#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <libgen.h>

/** Initialize common datagram information
 *
 */
static int fr_bio_fd_common_tcp(int fd, UNUSED fr_socket_t const *sock, UNUSED fr_bio_fd_config_t const *cfg)
{
	int on = 1;

#ifdef SO_KEEPALIVE
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
		fr_strerror_printf("Failed setting SO_KEEPALIVE: %s", fr_syserror(errno));
		return -1;
	}
#endif

	return 0;
}


/** Initialize common datagram information
 *
 */
static int fr_bio_fd_common_datagram(int fd, UNUSED fr_socket_t const *sock, fr_bio_fd_config_t const *cfg)
{
	int on = 1;

#ifdef SO_TIMESTAMPNS
	/*
	 *	Enable receive timestamps, these should reflect
	 *	when the packet was received, not when it was read
	 *	from the socket.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(int)) < 0) {
		fr_strerror_printf("Failed setting SO_TIMESTAMPNS: %s", fr_syserror(errno));
		return -1;
	}

#elif defined(SO_TIMESTAMP)
	/*
	 *	Enable receive timestamps, these should reflect
	 *	when the packet was received, not when it was read
	 *	from the socket.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(int)) < 0) {
		fr_strerror_printf("Failed setting SO_TIMESTAMP: %s", fr_syserror(errno));
		return -1;
	}
#endif

#ifdef SO_RCVBUF
	if (cfg->recv_buff) {
		int opt = cfg->recv_buff;

		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
			fr_strerror_printf("Failed setting SO_RCVBUF: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

#ifdef SO_SNDBUF
	if (cfg->send_buff) {
		int opt = cfg->send_buff;

		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
			fr_strerror_printf("Failed setting SO_SNDBUF: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

	return 0;
}

/** Initialize a UDP server socket.
 *
 */
static int fr_bio_fd_server_udp(int fd, fr_socket_t const *sock, fr_bio_fd_config_t const *cfg)
{
#ifdef SO_REUSEPORT
	int on = 1;

	/*
	 *	Set SO_REUSEPORT before bind, so that all sockets can
	 *	listen on the same destination IP address.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
		fr_strerror_printf("Failed setting SO_REUSEPORT: %s", fr_syserror(errno));
		return -1;
	}
#endif

	return fr_bio_fd_common_datagram(fd, sock, cfg);
}

/** Initialize a TCP server socket.
 *
 */
static int fr_bio_fd_server_tcp(int fd, UNUSED fr_socket_t const *sock)
{
	int on = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		fr_strerror_printf("Failed setting SO_REUSEADDR: %s", fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Initialize an IPv4 server socket.
 *
 */
static int fr_bio_fd_server_ipv4(int fd, fr_socket_t const *sock, fr_bio_fd_config_t const *cfg)
{
	int flag;

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
	/*
	 *	Disable PMTU discovery.  On Linux, this also makes sure that the "don't
	 *	fragment" flag is zero.
	 */
	flag = IP_PMTUDISC_DONT;

	if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag)) < 0) {
		fr_strerror_printf("Failed setting IP_MTU_DISCOVER: %s", fr_syserror(errno));
		return -1;
	}
#endif

#if defined(IP_DONTFRAG)
	/*
	 *	Ensure that the "don't fragment" flag is zero.
	 */
	flag = 0;

	if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &flag, sizeof(flag)) < 0) {
		fr_strerror_printf("Failed setting IP_DONTFRAG: %s", fr_syserror(errno));
		return -1;
	}
#endif

	/*
	 *	And set up any UDP / TCP specific information.
	 */
	if (sock->type == SOCK_DGRAM) return fr_bio_fd_server_udp(fd, sock, cfg);

	return fr_bio_fd_server_tcp(fd, sock);
}

/** Initialize an IPv6 server socket.
 *
 */
static int fr_bio_fd_server_ipv6(int fd, fr_socket_t const *sock, fr_bio_fd_config_t const *cfg)
{
#ifdef IPV6_V6ONLY
	/*
	 *	Don't allow v4 packets on v6 connections.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(UNCONST(struct in6_addr *, &sock->inet.src_ipaddr.addr.v6))) {
		int on = 1;

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on)) < 0) {
			fr_strerror_printf("Failed setting IPV6_ONLY: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif /* IPV6_V6ONLY */

	/*
	 *	And set up any UDP / TCP specific information.
	 */
	if (sock->type == SOCK_DGRAM) return fr_bio_fd_server_udp(fd, sock, cfg);

	return fr_bio_fd_server_tcp(fd, sock);
}

/** Verify or clean up a pre-existing domain socket.
 *
 */
static int fr_bio_fd_socket_unix_verify(int dirfd, char const *filename, fr_bio_fd_config_t const *cfg)
{
	int fd;
	struct stat buf;

	/*
	 *	See if the socket exits.  If there's an error opening it, that's an issue.
	 *
	 *	If it doesn't exist, that's fine.
	 */
	if (fstatat(dirfd, filename, &buf, AT_SYMLINK_NOFOLLOW) < 0) {
		if (errno != ENOENT) {
			fr_strerror_printf("Failed opening domain socket %s: %s", cfg->path, fr_syserror(errno));
			return -1;
		}

		return 0;
	}

	/*
	 *	If it exists, it must be a socket.
	 */
	if (!S_ISSOCK(buf.st_mode)) {
		fr_strerror_printf("Failed open domain socket %s: it is not a socket", filename);
		return -1;
	}

	/*
	 *	Refuse to open sockets not owned by us.  This prevents configurations from stomping on each
	 *	other.
	 */
	if (buf.st_uid != cfg->uid) {
		fr_strerror_printf("Failed opening domain socket %s: incorrect UID", cfg->path);
		return -1;
	}

	/*
	 *	The file exists,and someone is listening.  We can't claim it for ourselves.
	 *
	 *	Note that this function calls connect(), but connect() always returns immediately for domain
	 *	sockets.
	 *
	 *	@todo - redo that function here, with separate checks for permission errors vs anything else.
	 */
	fd = fr_socket_client_unix(cfg->path, false);
	if (fd >= 0) {
		close(fd);
		fr_strerror_printf("Failed creating domain socket %s: It is currently active", cfg->path);
		return -1;
	}

	/*
	 *	It exists, but no one is listening.  Delete it so that we can re-bind to it.
	 */
	if (unlinkat(dirfd, filename, 0) < 0) {
		fr_strerror_printf("Failed removing pre-existing domain socket %s: %s",
				   cfg->path, fr_syserror(errno));
		return -1;
	}

	return 0;
}

/*
 *	We normally can't call fchmod() or fchown() on sockets, as they don't really exist in the file system.
 *	Instead, we enforce those permissions on the parent directory of the socket.
 */
static int fr_bio_fd_socket_unix_mkdir(int *dirfd, char const **filename, fr_bio_fd_config_t const *cfg)
{
	mode_t perm;
	int parent_fd, fd;
	char const *path = cfg->path;
	char *dir, *p;
	char *slashes[2];

	perm = S_IREAD | S_IWRITE | S_IEXEC;
	perm |= S_IRGRP | S_IWGRP | S_IXGRP;

	/*
	 *	The parent directory exists.  Ensure that it has the correct ownership and permissions.
	 *
	 *	If the parent directory exists, then it enforces access, and we can create the domain socket
	 *	within it.
	 */
	if (fr_dirfd(dirfd, filename, path) == 0) {
		struct stat buf;

		if (fstat(*dirfd, &buf) < 0) {
			fr_strerror_printf("Failed reading parent directory for file %s: %s", path, fr_syserror(errno));
			close(*dirfd);
			return -1;
		}

		if (buf.st_uid != cfg->uid) {
			fr_strerror_printf("Failed reading parent directory for file %s: Incorrect UID", path);
			return -1;
		}

		if (buf.st_gid != cfg->gid) {
			fr_strerror_printf("Failed reading parent directory for file %s: Incorrect GID", path);
			return -1;
		}

		/*
		 *	We don't have the correct permissions on the directory, so we fix them.
		 *
		 *	@todo - allow for "other" to read/write if we do authentication on the socket?
		 */
		if (fchmod(*dirfd, perm) < 0) {
			fr_strerror_printf("Failed setting parent directory permissions for file %s: %s", path, fr_syserror(errno));
			close(*dirfd);
			return -1;
		}

		return 0;
	}

	dir = talloc_strdup(NULL, path);
	if (!dir) return -1;

	/*
	 *	Find the last two directory separators.
	 */
	slashes[0] = slashes[1] = NULL;
	for (p = dir; *p != '\0'; p++) {
		if (*p == '/') {
			slashes[0] = slashes[1];
			slashes[1] = p;
		}
	}

	/*
	 *	There's only one / in the path, we can't do anything.
	 *
	 *	Opening 'foo/bar.sock' might be useful, but isn't normally a good idea.
	 */
	if (!slashes[0]) {
		fr_strerror_printf("Failed parsing filename %s: it is not absolute", path);
	fail:
		talloc_free(dir);
		return -1;
	}

	/*
	 *	Ensure that the grandparent directory exists.
	 *
	 *	/var/run/radiusd/foo.sock
	 *
	 *	slashes[0] points to the slash after 'run'.
	 *
	 *	slashes[1] points to the slash after 'radiusd', which doesn't exist.
	 */
	*slashes[0] = '\0';

	/*
	 *	If the grandparent doesn't exist, then we don't create it.
	 *
	 *	These checks minimize the possibility that a misconfiguration by user "radiusd" can cause a
	 *	suid-root binary top create a directory in the wrong place.  These checks are only necessary
	 *	if the unix domain socket is opened as root.
	 */
	parent_fd = open(dir, O_DIRECTORY | O_NOFOLLOW);
	if (parent_fd < 0) {
		fr_strerror_printf("Failed opening directory %s: %s", dir, fr_syserror(errno));
		goto fail;
	}

	/*
	 *	Create the parent directory.
	 */
	*slashes[0] = '/';
	*slashes[1] = '\0';
	if (mkdirat(parent_fd, dir, 0700) < 0) {
		fr_strerror_printf("Failed creating directory %s: %s", dir, fr_syserror(errno));
	close_parent:
		close(parent_fd);
		goto fail;
	}

	fd = openat(parent_fd, dir, O_DIRECTORY);
	if (fd < 0) {
		fr_strerror_printf("Failed opening directory %s: %s", dir, fr_syserror(errno));
		goto close_parent;
	}

	if (fchmod(fd, perm) < 0) {
		fr_strerror_printf("Failed changing permission for directory %s: %s", dir, fr_syserror(errno));
	close_fd:
		close(fd);
		goto close_parent;
	}

	/*
	 *	This is a NOOP if we're chowning a file owned by ourselves to our own UID / GID.
	 *
	 *	Otherwise if we're running as root, it will set ownership to the correct user.
	 */
	if (fchown(fd, cfg->uid, cfg->gid) < 0) {
		fr_strerror_printf("Failed changing ownershipt for directory %s: %s", dir, fr_syserror(errno));
		goto close_fd;
	}

	talloc_free(dir);
	close(fd);
	close(parent_fd);

	return 0;
}

static int fr_bio_fd_unix_shutdown(fr_bio_t *bio)
{
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	/*
	 *	The bio must be open in order to shut it down.
	 *
	 *	Unix domain sockets are deleted when the bio is closed.
	 *
	 *	Unix domain sockets are never in the "connecting" state, because connect() always returns
	 *	immediately.
	 */
	fr_assert(my->info.state == FR_BIO_FD_STATE_OPEN);

	/*
	 *	Run the user shutdown before we run ours.
	 */
	if (my->user_shutdown) {
		if (my->user_shutdown(bio) < 0) return -1;
	}

	return unlink(my->info.socket.unix.path);
}

/** Bind to a Unix domain socket.
 *
 *  @todo - this function only does a tiny bit of what fr_server_domain_socket_peercred() and
 *  fr_server_domain_socket_perm() do.  Those functions do a lot more sanity checks.
 *
 *  The main question is whether or not those checks are useful.  In many cases, fchmod() and fchown() are not
 *  possible on Unix sockets, so we shouldn't bother doing them,
 *
 *  Note that the listeners generally call these functions with wrappers of fr_suid_up() and fr_suid_down().
 *  So these functions are running as "root", and will create files owned as "root".
 */
static int fr_bio_fd_socket_bind_unix(fr_bio_fd_t *my, fr_bio_fd_config_t const *cfg)
{
	int dirfd, rcode;
	char const *filename, *p;
	socklen_t sunlen;
	struct sockaddr_un sun;

	p = strrchr(my->info.socket.unix.path, '/');

	/*
	 *	The UID and GID should be taken automatically from the "user" and "group" settings in
	 *	mainconfig.  There is no reason to set them to anything else.
	 */
	if (cfg->uid == (uid_t) -1) {
		fr_strerror_printf("Failed opening domain socket %s: no UID specified", my->info.socket.unix.path);
		return -1;
	}

	if (cfg->gid == (gid_t) -1) {
		fr_strerror_printf("Failed opening domain socket %s: no GID specified", my->info.socket.unix.path);
		return -1;
	}

	if (cfg->uid == 0) {
		fr_strerror_printf("Failed opening domain socket %s: refusing to open as UID 0", my->info.socket.unix.path);
		return -1;
	}

	if (cfg->gid == 0) {
		fr_strerror_printf("Failed opening domain socket %s: refusing to open as GID 0", my->info.socket.unix.path);
		return -1;
	}

	/*
	 *	Opening 'foo.sock' is OK.
	 */
	if (!p) {
		dirfd = AT_FDCWD;
		filename = my->info.socket.unix.path;

	} else if (p == my->info.socket.unix.path) {
		/*
		 *	Opening '/foo.sock' is dumb.
		 */
		fr_strerror_printf("Failed opening domain socket %s: cannot exist at file system root", p);
		return -1;

	} else if (fr_bio_fd_socket_unix_mkdir(&dirfd, &filename, cfg) < 0) {
		return -1;
	}

	/*
	 *	Verify and/or clean up the domain socket.
	 */
	if (fr_bio_fd_socket_unix_verify(dirfd, filename, cfg) < 0) {
	fail:
		if (dirfd != AT_FDCWD) close(dirfd);
		return -1;
	}

#ifdef HAVE_BINDAT
	/*
	 *	The best function to use here is bindat(), but only quite recent versions of FreeBSD actually
	 *	have it, and it's definitely not POSIX.
	 *
	 *	If we use bindat(), we pass a relative pathname.
	 */
	if (fr_filename_to_sockaddr(&sun, &sunlen, filename) < 0) goto fail;

	rcode = bindat(dirfd, my->info.socket.fd, (struct sockaddr *) &sun, sunlen);
#else
	/*
	 *	For bind(), we pass the full path.
	 */
	if (fr_filename_to_sockaddr(&sun, &sunlen, my->info.socket.unix.path) < 0) goto fail;

	rcode = bind(my->info.socket.fd, (struct sockaddr *) &sun, sunlen);
#endif
	if (rcode < 0) {
		/*
		 *	@todo - if EADDRINUSE, then the socket exists.  Try connect(), and if that fails,
		 *	delete the socket and try again.  This may be simpler than the checks above.
		 */
		fr_strerror_printf("Failed binding to domain socket %s: %s", my->info.socket.unix.path, fr_syserror(errno));
		goto fail;
	}

#ifdef __linux__
	/*
	 *	Linux supports chown && chmod for sockets.
	 */
	if (fchmod(my->info.socket.fd, S_IREAD | S_IWRITE | S_IEXEC | S_IRGRP | S_IWGRP | S_IXGRP) < 0) {
		fr_strerror_printf("Failed changing permission for domain socket %s: %s", my->info.socket.unix.path, fr_syserror(errno));
		goto fail;
	}

	/*
	 *	This is a NOOP if we're chowning a file owned by ourselves to our own UID / GID.
	 *
	 *	Otherwise if we're running as root, it will set ownership to the correct user.
	 */
	if (fchown(my->info.socket.fd, cfg->uid, cfg->gid) < 0) {
		fr_strerror_printf("Failed changing ownershipt for domain directory %s: %s", my->info.socket.unix.path, fr_syserror(errno));
		goto fail;
	}

#endif

	/*
	 *	Socket is open.  We need to clean it up on shutdown.
	 */
	if (my->cb.shutdown) my->user_shutdown = my->cb.shutdown;
	my->cb.shutdown = fr_bio_fd_unix_shutdown;

	return 0;
}

#ifdef SO_BINDTODEVICE
/** Linux bind to device by name.
 *
 */
static int fr_bio_fd_socket_bind_to_device(fr_bio_fd_t *my, fr_bio_fd_config_t const *cfg)
{
	char *ifname;
	char buffer[IFNAMSIZ];

	/*
	 *	ifindex isn't set, do nothing.
	 */
	if (!my->info.socket.inet.ifindex) return 0;

	/*
	 *	The internet hints that CAP_NET_RAW is required to use SO_BINDTODEVICE.
	 *
	 *	This function also sets fr_strerror() on failure, which will be seen if the bind fails.  If
	 *	the bind succeeds, then we don't really care that the capability change has failed.  We must
	 *	already have that capability.
	 */
#ifdef HAVE_CAPABILITY_H
	(void)fr_cap_enable(CAP_NET_RAW, CAP_EFFECTIVE);
#endif

	if (setsockopt(my->info.socket.fd, SOL_SOCKET, SO_BINDTODEVICE, cfg->interface, strlen(cfg->interface)) < 0) {
		fr_strerror_printf("Failed setting SO_BINDTODEVICE for %s: %s", cfg->interface, fr_syserror(errno));
		return -1;
	}

	return 0;
}

#elif defined(IP_BOUND_IF) || defined(IPV6_BOUND_IF)
/** *BSD bind to interface by index.
 *
 */
static int fr_bio_fd_socket_bind_to_device(fr_bio_fd_t *my, UNUSED fr_bio_fd_config_t const *cfg)
{
	int opt, rcode;

	if (!my->info.socket.inet.ifindex) return 0;

	opt = my->info.socket.inet.ifindex;

	switch (my->info.socket.af) {
	case AF_UNIX:
		rcode = setsockopt(my->info.socket.fd, IPPROTO_IP, IP_BOUND_IF, &opt, sizeof(opt));
		break;

	case AF_INET6:
		rcode = setsockopt(my->info.socket.fd, IPPROTO_IPV6, IPV6_BOUND_IF, &opt, sizeof(opt));
		break;

	default:
		rcode = -1;
		errno = EAFNOSUPPORT;
		break;
	}

	fr_strerror_printf("Failed setting IP_BOUND_IF: %s", fr_syserror(errno));
	return rcode;
}
#else

#error This system is missing SO_BINDTODEVICE, IP_BOUND_IF, IPV6_BOUND_IF

/** ??? Who knows?
 *
 */
static int fr_bio_fd_socket_bind_to_device(fr_bio_fd_t *my, fr_bio_fd_config_t const *cfg)
{
	/*
	 *	@todo - see fr_socket_bind().  Troll through the interfaces to see which interface has a name
	 *	which matches the named interface.  If so, copy over it's IP to our src_ip, so long as src_ip
	 *	is INADDR_ANY.
	 */

	return -1;
}

/* bind to device */
#endif

static int fr_bio_fd_socket_bind(fr_bio_fd_t *my, fr_bio_fd_config_t const *cfg)
{
	socklen_t salen;
	struct sockaddr_storage	salocal;

	if (my->info.socket.af == AF_UNIX) {
		return fr_bio_fd_socket_bind_unix(my, cfg);
	}

#ifdef HAVE_CAPABILITY_H
	/*
	 *	If we're binding to a special port as non-root, then
	 *	check capabilities.  If we're root, we already have
	 *	equivalent capabilities so we don't need to check.
	 */
	if ((my->info.socket.inet.src_port < 1024) && (geteuid() != 0)) {
		(void)fr_cap_enable(CAP_NET_BIND_SERVICE, CAP_EFFECTIVE);
	}
#endif

	if (fr_bio_fd_socket_bind_to_device(my, cfg) < 0) return -1;

	/*
	 *	Bind to the IP + interface.
	 */
	if (fr_ipaddr_to_sockaddr(&salocal, &salen, &my->info.socket.inet.src_ipaddr, my->info.socket.inet.src_port) < 0) return -1;

	if (bind(my->info.socket.fd, (struct sockaddr *) &salocal, salen) < 0) {
		fr_strerror_printf("Failed binding to socket: %s", fr_syserror(errno));
		return -1;
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

	return 0;
}

/** Opens a socket and updates sock->fd
 *
 *  Note that it does not call connect()!
 */
int fr_bio_fd_socket_open(fr_bio_t *bio, fr_bio_fd_config_t const *cfg)
{
	int fd, protocol;
	int rcode;
	fr_bio_fd_t *my = talloc_get_type_abort(bio, fr_bio_fd_t);

	fr_strerror_clear();

	my->info.socket = (fr_socket_t) {};

	if (cfg->path) {
		my->info.socket.af = AF_UNIX;
	} else {
		my->info.socket.af = cfg->src_ipaddr.af;
	}
	my->info.socket.type = cfg->socket_type;

	switch (my->info.socket.af) {
	case AF_INET:
	case AF_INET6:
		my->info.socket.inet.src_ipaddr = cfg->src_ipaddr;
		my->info.socket.inet.dst_ipaddr = cfg->dst_ipaddr;
		my->info.socket.inet.src_port = cfg->src_port;
		my->info.socket.inet.dst_port = cfg->dst_port;

		if (cfg->socket_type == SOCK_STREAM) {
			protocol = IPPROTO_TCP;
		} else {
			protocol = IPPROTO_UDP;
		}

		if (cfg->interface) {
			my->info.socket.inet.ifindex = if_nametoindex(cfg->interface);

			if (!my->info.socket.inet.ifindex) {
				fr_strerror_printf_push("Failed finding interface %s: %s", cfg->interface, fr_syserror(errno));
				return -1;
			}
		}
		break;

	case AF_UNIX:
		my->info.socket.unix.path = cfg->path;
		my->info.socket.type = SOCK_STREAM;
		protocol = 0;
		break;

	default:
		fr_strerror_const("Failed opening socket: unsupported address family");
		return -1;
	}

	/*
	 *	Open the socket.
	 */
	fd = socket(my->info.socket.af, my->info.socket.type, protocol);
	if (fd < 0) {
		fr_strerror_printf("Failed opening socket: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Set it to be non-blocking if required.
	 */
	if (cfg->async && (fr_nonblock(fd) < 0)) {
		fr_strerror_printf("Failed opening setting O_NONBLOCK: %s", fr_syserror(errno));

	fail:
		my->info.socket.fd = -1;
		my->info.state = FR_BIO_FD_STATE_CLOSED;
		close(fd);
		return -1;
	}

#ifdef FD_CLOEXEC
	/*
	 *	We don't want child processes inheriting these file descriptors.
	 */
	rcode = fcntl(fd, F_GETFD);
	if (rcode >= 0) {
		if (fcntl(fd, F_SETFD, rcode | FD_CLOEXEC) < 0) {
			fr_strerror_printf("Failed opening setting FD_CLOEXE: %s", fr_syserror(errno));
			goto fail;
		}
	}
#endif

	/*
	 *	Initialize the bio information before calling the various setup functions.
	 */
	my->info.state = (cfg->type == FR_BIO_FD_CONNECTED) ? FR_BIO_FD_STATE_CONNECTING : FR_BIO_FD_STATE_OPEN;

	/*
	 *	Set the FD so that the subsequent calls can use it.
	 */
	my->info.socket.fd = fd;

	/*
	 *	Do sanity checks, bootstrap common socket options, bind to the socket, and initialize the read
	 *	/ write functions.
	 */
	switch (cfg->type) {
		/*
		 *	Unconnected UDP or datagram AF_UNUX server sockets.
		 */
	case FR_BIO_FD_UNCONNECTED:
		if (my->info.socket.type != SOCK_DGRAM) {
			fr_strerror_const("Failed configuring socket: unconnected sockets must be UDP");
			return -1;
		}

		if (my->info.socket.af == AF_UNIX) {
			rcode = fr_bio_fd_common_datagram(fd, &my->info.socket, cfg);
		} else {
			rcode = fr_bio_fd_server_udp(fd, &my->info.socket, cfg); /* sets SO_REUSEPORT, too */
		}
		if (rcode < 0) goto fail;

		if (fr_bio_fd_socket_bind(my, cfg) < 0) goto fail;

		if (fr_bio_fd_init_common(my) < 0) goto fail;
		break;

		/*
		 *	A connected client: UDP, TCP, or AF_UNIX.
		 */
	case FR_BIO_FD_CONNECTED:
		if (my->info.socket.type == SOCK_DGRAM) {
			rcode = fr_bio_fd_common_datagram(fd, &my->info.socket, cfg); /* we don't use SO_REUSEPORT for clients */
			if (rcode < 0) goto fail;

		} else if (my->info.socket.af != AF_UNIX) {
			rcode = fr_bio_fd_common_tcp(fd, &my->info.socket, cfg);
			if (rcode < 0) goto fail;
		}

		if (fr_bio_fd_socket_bind(my, cfg) < 0) goto fail;

		if (fr_bio_fd_init_connected(my) < 0) goto fail;
		break;

		/*
		 *	Server socket which listens for new stream connections
		 */
	case FR_BIO_FD_ACCEPT:
		fr_assert(my->info.socket.type == SOCK_STREAM);

		switch (my->info.socket.af) {
		case AF_INET:
			rcode = fr_bio_fd_server_ipv4(fd, &my->info.socket, cfg);
			break;

		case AF_INET6:
			rcode = fr_bio_fd_server_ipv6(fd, &my->info.socket, cfg);
			break;

		case AF_UNIX:
			rcode = 0;
			break;

		default:
			rcode = -1;
			errno = EAFNOSUPPORT;
			break;
		}
		if (rcode < 0) goto fail;

		if (fr_bio_fd_socket_bind(my, cfg) < 0) goto fail;

		if (fr_bio_fd_init_accept(my) < 0) goto fail;
		break;
	}
	return 0;
}
