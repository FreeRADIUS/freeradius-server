#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/** Structures and functions for parsing, printing, masking and retrieving IP addresses
 *
 * @file src/lib/util/inet.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(inet_h, "$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <arpa/inet.h>
#include <net/if.h>		/* SIOCGIFADDR et al */
#include <netinet/in.h>		/* in6?_addr */
#include <stdbool.h>
#include <talloc.h>

#ifdef __cplusplus
extern "C" {
#endif
/** IPv4/6 prefix
 *
 * Abstraction around the standard in_addr/in6_addr structures to
 * support address family agnostic functions.
 */
typedef struct {
	int		af;			//!< Address family.
	union {
		struct in_addr	v4;		//!< IPv4 address.
		struct in6_addr v6;		//!< IPv6 address.
	} addr;
	uint8_t		prefix;	        	//!< Prefix length - Between 0-32 for IPv4 and 0-128 for IPv6.
	uint32_t	scope_id;		//!< A host may have multiple link-local interfaces
						//!< the scope ID allows the application to specify which of
						//!< those interfaces the IP applies to.  A special scope_id
						//!< of zero means that any interface of a given scope can
						//!< be used.
} fr_ipaddr_t;

/** Holds information necessary for binding or connecting to a socket.
 *
 */
typedef struct {
	union {
		struct {
			fr_ipaddr_t	ipaddr;	//!< IP address to bind or connect to.
			uint16_t	port;	//!< Port to bind or connect to.
		};
		char const *path;		//!< Unix socket path.
	};
	int proto;				//!< Protocol.
} fr_socket_addr_t;

#  if defined(SIOCGIFADDR) && (defined(SIOCGIFNAME) || defined(HAVE_IF_INDEXTONAME))
#    define WITH_IFINDEX_RESOLUTION 1
#  endif

#  if defined(SIOCGIFNAME) || defined(HAVE_IF_INDEXTONAME)
#    define WITH_IFINDEX_NAME_RESOLUTION 1
#  endif

extern struct in6_addr fr_inet_link_local6;

/** Like INET6_ADDRSTRLEN but includes space for the textual Zone ID
 */
#define FR_IPADDR_STRLEN (INET6_ADDRSTRLEN + 1 + IFNAMSIZ)

/** Like FR_IPADDR_STRLEN but with space for a prefix
 */
#define FR_IPADDR_PREFIX_STRLEN (FR_IPADDR_STRLEN + 1 + 3)

extern bool	fr_reverse_lookups;	/* do IP -> hostname lookups? */
extern bool	fr_hostname_lookups; /* do hostname -> IP lookups? */

/*
 *	Utility functions
 */
int	fr_ipaddr_is_inaddr_any(fr_ipaddr_t const *ipaddr);
int	fr_ipaddr_is_prefix(fr_ipaddr_t const *ipaddr);

/*
 *	IP address masking
 */
void	fr_ipaddr_mask(fr_ipaddr_t *addr, uint8_t prefix);

/*
 *	Presentation to network, and network to presentation conversion
 */
int	fr_inet_hton(fr_ipaddr_t *out, int af, char const *hostname, bool fallback);

char const *fr_inet_ntoh(fr_ipaddr_t const *src, char *out, size_t outlen);

int	fr_inet_pton4(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask);

int	fr_inet_pton6(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask);

int	fr_inet_pton(fr_ipaddr_t *out, char const *value, ssize_t inlen, int af, bool resolve, bool mask);

int	fr_inet_pton_port(fr_ipaddr_t *out, uint16_t *port_out, char const *value,
			  ssize_t inlen, int af, bool resolve, bool mask);

char	*fr_inet_ntop(char out[static FR_IPADDR_STRLEN], size_t outlen, fr_ipaddr_t const *addr);

char	*fr_inet_ntop_prefix(char out[static FR_IPADDR_PREFIX_STRLEN], size_t outlen, fr_ipaddr_t const *addr);

char	*fr_inet_ifid_ntop(char *out, size_t outlen, uint8_t const *ifid);

uint8_t	*fr_inet_ifid_pton(uint8_t out[static 8], char const *ifid_str);

/*
 *	if_index and if_name resolution
 */
int	fr_ipaddr_from_ifname(fr_ipaddr_t *out, int af, char const *name);

#ifdef WITH_IFINDEX_NAME_RESOLUTION
char	*fr_ifname_from_ifindex(char out[static IFNAMSIZ], int if_index);
#endif

#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
int	fr_ipaddr_from_ifindex(fr_ipaddr_t *out, int fd, int af, int if_index);
#endif

char	*fr_ipaddr_to_interface(TALLOC_CTX *ctx, fr_ipaddr_t *ipaddr);
int	fr_interface_to_ipaddr(char const *interface, fr_ipaddr_t *ipaddr, int af, bool link_local);

int	fr_interface_to_ethernet(char const *interface, uint8_t ethernet[static 6]);
/*
 *	Comparison
 */
int	fr_ipaddr_cmp(fr_ipaddr_t const *a, fr_ipaddr_t const *b);

/*
 *	Sockaddr conversion functions
 */
int	fr_ipaddr_to_sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port,
			      struct sockaddr_storage *sa, socklen_t *salen);

int	fr_ipaddr_from_sockaddr(struct sockaddr_storage const *sa, socklen_t salen,
				fr_ipaddr_t *ipaddr, uint16_t *port);

#ifdef __cplusplus
}
#endif
