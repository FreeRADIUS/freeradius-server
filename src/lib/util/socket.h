#pragma once

/*
 *   This program is free software; you can redistribute it and/or modify
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
RCSIDH(socket_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/time.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
/*
 *  The linux headers define the macro as:
 *
 * # define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
 *                      + strlen ((ptr)->sun_path))
 *
 * Which trips UBSAN, because it sees an operation on a NULL pointer.
 */
#  undef SUN_LEN
#  define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

/** Holds information necessary for binding or connecting to a socket.
 *
 * May also be used in protocol contexts to store information necessary for
 * returning packets to their originators.
 */
typedef struct {
	union {
		struct {
			int		ifindex;	//!< Source interface to bind to or originate the packet from.
			fr_ipaddr_t	src_ipaddr;	//!< IP address to bind to, or originate the packet from.
			uint16_t	src_port;	//!< Port to bind to, or originate the packet from.

			fr_ipaddr_t	dst_ipaddr;	//!< IP address to connect to, or send the packet to.
			uint16_t	dst_port;	//!< Port to connect to or send the packet to.
		} inet;

		struct {
			char const *path;		//!< Unix socket path.
		} unix;
	};
	int proto;		//!< Protocol.

	int fd;			//!< File descriptor if this is a live socket.
} fr_socket_t;

/** Check the proto value is sane/supported
 *
 * @param[in] proto to check
 * @return
 *	- true if it is.
 *	- false if it's not.
 */
static inline bool fr_socket_is_inet(int proto)
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

#define FR_SOCKET_ADDR_ALLOC_DEF_FUNC(_func, ...) \
	fr_socket_t *addr; \
	addr = talloc(ctx, fr_socket_t); \
	if (unlikely(!addr)) return NULL; \
	return _func(addr, ##__VA_ARGS__);

/** Swap src/dst information of a fr_socket_t
 *
 * @param[out] dst	Where to write the swapped addresses. May be the same as src.
 * @param[in] src	Socket address to swap.
 */
static inline void fr_socket_addr_swap(fr_socket_t *dst, fr_socket_t const *src)
{
	fr_socket_t	tmp = *src;

	if (dst != src) *dst = tmp;	/* copy non-address fields over */

	switch (src->proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
#ifdef IPPROTO_SCTP
	case IPPROTO_SCTP:
#endif
		dst->inet.dst_ipaddr = tmp.inet.src_ipaddr;
		dst->inet.dst_port = tmp.inet.src_port;
		dst->inet.src_ipaddr = tmp.inet.dst_ipaddr;
		dst->inet.src_port = tmp.inet.dst_port;
		break;

	default:
		return;
	}
}

/** Initialise a fr_socket_t for connecting to a remote host using a specific src interface, address and port
 *
 * Can also be used to record information from an incoming packet so that we can
 * identify the correct return path later.
 *
 * @param[out] addr		to initialise.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ifindex		The interface to originate the packet from Pass <= 0 to
 *				indicate an unknown or unspecified interface.
 * @param[in] src_ipaddr	The source IP address of the packet, or source interface for
 *				packets to egress out of.
 * @param[in] src_port		The source port of the packet or the source
 * @param[in] dst_ipaddr	The destination IP address of the packet.
 * @param[in] dst_port		The destination port of the packet.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_init_inet(fr_socket_t *addr,
						    int proto,
						    int ifindex, fr_ipaddr_t const *src_ipaddr, int src_port,
						    fr_ipaddr_t const *dst_ipaddr, int dst_port)
{
	if (!fr_socket_is_inet(proto)) return NULL;

	*addr = (fr_socket_t){
		.proto = proto,
		.inet = {
			.ifindex = ifindex,
			.src_ipaddr = *src_ipaddr,
			.src_port = src_port,
			.dst_ipaddr = *dst_ipaddr,
			.dst_port = dst_port
		}
	};

	return addr;
}

/** Initialise a fr_socket_t for connecting to a remote host using a specific src interface, address and port
 *
 * Can also be used to record information from an incoming packet so that we can
 * identify the correct return path later.
 *
 * @param[in] ctx		to allocate a new #fr_socket_t struct in.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ifindex		The interface to originate the packet from Pass <= 0 to
 *				indicate an unknown or unspecified interface.
 * @param[in] src_ipaddr	The source IP address of the packet, or source interface for
 *				packets to egress out of.
 * @param[in] src_port		The source port of the packet or the source
 * @param[in] dst_ipaddr	The destination IP address of the packet.
 * @param[in] dst_port		The destination port of the packet.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_alloc_inet(TALLOC_CTX *ctx, int proto,
						     int ifindex, fr_ipaddr_t const *src_ipaddr, int src_port,
						     fr_ipaddr_t const *dst_ipaddr, int dst_port)
{
	FR_SOCKET_ADDR_ALLOC_DEF_FUNC(fr_socket_addr_init_inet,
				      proto, ifindex, src_ipaddr, src_port, dst_ipaddr, dst_port)
}

/** A variant of fr_socket_addr_alloc_inet will also allocates a #fr_socket_t
 *

 * @param[out] addr		to initialise.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ifindex		The interface to originate the packet from Pass <= 0 to
 *				indicate an unknown or unspecified interface.
 * @param[in] ipaddr		The IP address to bind to.  May be all zeros to bind to
 *				all addresses, but the AF must still be specified.
 * @param[in] port		The source port to bind to.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_init_inet_src(fr_socket_t *addr,
							int proto, int ifindex, fr_ipaddr_t const *ipaddr, int port)
{
	if (!fr_socket_is_inet(proto)) return NULL;

	*addr = (fr_socket_t){
		.proto = proto,
		.inet = {
			.ifindex = ifindex,
			.src_ipaddr = *ipaddr,
			.src_port = port
		}
	};

	return addr;
}

/** A variant of fr_socket_addr_init_inet_src will also allocates a #fr_socket_t
 *
 * @param[in] ctx		to allocate a new #fr_socket_t struct in.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ifindex		The interface to originate the packet from Pass <= 0 to
 *				indicate an unknown or unspecified interface.
 * @param[in] ipaddr		The IP address to bind to.  May be all zeros to bind to
 *				all addresses, but the AF must still be specified.
 * @param[in] port		The source port to bind to.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_alloc_inet_src(TALLOC_CTX *ctx, int proto,
							 int ifindex, fr_ipaddr_t const *ipaddr, int port)
{
	FR_SOCKET_ADDR_ALLOC_DEF_FUNC(fr_socket_addr_init_inet_src, proto, ifindex, ipaddr, port)
}
/** Initialise a #fr_socket_t for connecting to a remote host
 *
 * @param[out] addr		to initialise.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ipaddr		The IP address to bind to.  May be all zeros to bind to
 *				all addresses, but the AF must still be specified.
 * @param[in] port		The source port to bind to.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_init_inet_dst(fr_socket_t *addr, int proto, fr_ipaddr_t const *ipaddr, int port)
{
	if (!fr_socket_is_inet(proto)) return NULL;

	*addr = (fr_socket_t){
		.proto = proto,
		.inet = {
			.dst_ipaddr = *ipaddr,
			.dst_port = port
		}
	};

	return addr;
}

/** A variant of fr_socket_addr_alloc_inet_dst that will also allocates a #fr_socket_t
 *
 * @param[in] ctx		to allocate new #fr_socket_t struct in.
 * @param[in] proto		one of the IPPROTO_* macros, i.e. IPPROTO_TCP, IPPROTO_UDP
 * @param[in] ipaddr		The IP address to bind to.  May be all zeros to bind to
 *				all addresses, but the AF must still be specified.
 * @param[in] port		The source port to bind to.
 * @return
 *	- NULL if invalid parameters are provided.
 *	- An initialised fr_socket_t struct.
 */
static inline fr_socket_t *fr_socket_addr_alloc_inet_dst(TALLOC_CTX *ctx, int proto,
							 fr_ipaddr_t const *ipaddr, int port)
{
	FR_SOCKET_ADDR_ALLOC_DEF_FUNC(fr_socket_addr_init_inet_dst, proto, ipaddr, port)
}

int		fr_socket_client_unix(char const *path, bool async);

int		fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);

int		fr_socket_client_tcp(fr_ipaddr_t const *src_ipaddr, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);
int		fr_socket_wait_for_connect(int sockfd, fr_time_delta_t timeout);

int		fr_socket_server_udp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);

int		fr_socket_server_tcp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);

int		fr_socket_bind(int sockfd, fr_ipaddr_t const *ipaddr, uint16_t *port, char const *interface);

#ifdef __cplusplus
}
#endif
