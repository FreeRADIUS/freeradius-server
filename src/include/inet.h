#ifndef FR_INET_H
#define FR_INET_H
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
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
 * @file include/inet.h
 * @brief Structures and functions for parsing, printing, masking and retrieving IP addresses.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>

/** IPv4/6 prefix
 *
 * Abstraction around the standard in_addr/in6_addr structures to
 * support address family agnostic functions.
 */
typedef struct fr_ipaddr_t {
	int		af;	//!< Address family.
	union {
		struct in_addr	ip4addr;	//!< IPv4 address.
		struct in6_addr ip6addr;	//!< IPv6 address.
	} ipaddr;
	uint8_t		prefix;	//!< Prefix length - Between 0-32 for IPv4 and 0-128 for IPv6.
	uint32_t	scope;	//!< Scope for IPv6.
} fr_ipaddr_t;

#  if defined(SIOCGIFADDR) && (defined(SIOCGIFNAME) || defined(HAVE_IF_INDEXTONAME))
#    define WITH_IFINDEX_RESOLUTION
#  endif

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

char	*fr_inet_ntop(char *out, size_t outlen, fr_ipaddr_t *addr);

char	*fr_inet_ntop_prefix(char *out, size_t outlen, fr_ipaddr_t *addr);

char	*fr_inet_ifid_ntop(char *out, size_t outlen, uint8_t const *ifid);

uint8_t	*fr_inet_ifid_pton(uint8_t out[8], char const *ifid_str);

/*
 *	if_index and if_name resolution
 */
int	fr_ipaddr_from_ifname(fr_ipaddr_t *out, int af, char const *name);

#ifdef WITH_IFINDEX_RESOLUTION
char	*fr_ifname_from_ifindex(char out[IFNAMSIZ], int if_index);

int	fr_ipaddr_from_ifindex(fr_ipaddr_t *out, int fd, int af, int if_index);
#endif

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
#endif
