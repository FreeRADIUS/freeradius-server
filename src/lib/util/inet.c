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

/** Functions for parsing, printing, masking and retrieving IP addresses
 *
 * @file src/lib/util/inet.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/value.h>

#include <stdlib.h>
#include <ifaddrs.h>
#include <net/if_arp.h>

/*
 *	Linux
 */
#if defined(HAVE_LINUX_IF_PACKET_H)
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
/*
 *	Apple, *BSD
 */
#elif defined(HAVE_NET_IF_DL_H)
#  include <net/if_dl.h>		 /* Needed for struct sockaddr_ll def */
/*
 *	emscripten/musl
 */
#elif defined(HAVE_NETPACKET_PACKET_H)
#  include <netpacket/packet.h>	 	/* Needed for struct sockaddr_ll def */
#endif

bool fr_reverse_lookups = false;		//!< IP -> hostname lookups?
bool fr_hostname_lookups = true;		//!< hostname -> IP lookups?

/** Determine if an address is the INADDR_ANY address for its address family
 *
 * @param ipaddr to check.
 * @return
 *	- 0 if it's not.
 *	- 1 if it is.
 *	- -1 on error.
 */
int fr_ipaddr_is_inaddr_any(fr_ipaddr_t const *ipaddr)
{

	if (ipaddr->af == AF_INET) {
		if (ipaddr->addr.v4.s_addr == htonl(INADDR_ANY)) {
			return 1;
		}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		/* Unconst for emscripten/musl */
		if (IN6_IS_ADDR_UNSPECIFIED(UNCONST(struct in6_addr *, &(ipaddr->addr.v6)))) {
			return 1;
		}
#endif

	} else {
		fr_strerror_const("Unknown address family");
		return -1;
	}

	return 0;
}

/** Determine if an address is a multicast address
 *
 * @param ipaddr to check.
 * @return
 *	- 0 if it's not.
 *	- 1 if it is.
 *	- -1 on error.
 */
int fr_ipaddr_is_multicast(fr_ipaddr_t const *ipaddr)
{
	if (ipaddr->af == AF_INET) {
		/*
		 *	224.0.0.0 (3758096384) - 239.255.255.255 (4026531839)
		 */
		if ((ipaddr->addr.v4.s_addr >= 3758096384) && (ipaddr->addr.v4.s_addr <= 4026531839)) return 1;
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		/* Unconst for emscripten/musl */
		if (IN6_IS_ADDR_MULTICAST(UNCONST(struct in6_addr *, &(ipaddr->addr.v6)))) {
			return 1;
		}
#endif

	} else {
		fr_strerror_const("Unknown address family");
		return -1;
	}

	return 0;
}

/** Determine if an address is a prefix
 *
 * @param ipaddr to check.
 * @return
 *	- 0 if it's not.
 *	- 1 if it is.
 *	- -1 on error.
 */
int fr_ipaddr_is_prefix(fr_ipaddr_t const *ipaddr)
{
	switch (ipaddr->af) {
	case AF_INET:
		return (ipaddr->prefix < 32);

	case AF_INET6:
		return (ipaddr->prefix < 128);

	default:
		fr_strerror_const("Unknown address family");
		return -1;
	}
}

/** Mask off a portion of an IPv4 address
 *
 * @param ipaddr to mask.
 * @param prefix Number of contiguous bits to mask.
 * @return an ipv4 address with the host portion zeroed out.
 */
static struct in_addr fr_inaddr_mask(struct in_addr const *ipaddr, uint8_t prefix)
{
	uint32_t ret;

	if (prefix > 32) prefix = 32;

	/* Short circuit */
	if (prefix == 32) return *ipaddr;

	if (prefix == 0) ret = 0;
	else ret = htonl(~((0x00000001UL << (32 - prefix)) - 1)) & ipaddr->s_addr;

	return (*(struct in_addr *)&ret);
}

/** Mask off a portion of an IPv6 address
 *
 * @param ipaddr to mask.
 * @param prefix Number of contiguous bits to mask.
 * @return an ipv6 address with the host portion zeroed out.
 */
static struct in6_addr fr_in6addr_mask(struct in6_addr const *ipaddr, uint8_t prefix)
{
	uint64_t const *p = (uint64_t const *) ipaddr;
	uint64_t addr;					/* Needed for alignment */
	uint64_t ret[2], *o = ret;

	if (prefix > 128) prefix = 128;

	/* Short circuit */
	if (prefix == 128) return *ipaddr;

	if (prefix >= 64) {
		prefix -= 64;
		memcpy(&addr, p, sizeof(addr));		/* Needed for aligned access (ubsan) */
		*o++ = 0xffffffffffffffffULL & addr;	/* lhs portion masked */
		p++;
	} else {
		ret[1] = 0;				/* rhs portion zeroed */
	}

	/* Max left shift is 63 else we get overflow */
	if (prefix > 0) {
		memcpy(&addr, p, sizeof(addr));		/* Needed for aligned access (ubsan) */
		*o = htonll(~((uint64_t)(0x0000000000000001ULL << (64 - prefix)) - 1)) & addr;
	} else {
		*o = 0;
	}

	return *(struct in6_addr *) &ret;
}

/** Zeroes out the host portion of an fr_ipaddr_t
 *
 * @param[in,out] addr to mask
 * @param[in] prefix Length of the network portion.
 */
void fr_ipaddr_mask(fr_ipaddr_t *addr, uint8_t prefix)
{

	switch (addr->af) {
	case AF_INET:
		addr->addr.v4 = fr_inaddr_mask(&addr->addr.v4, prefix);
		break;

	case AF_INET6:
		addr->addr.v6 = fr_in6addr_mask(&addr->addr.v6, prefix);
		break;

	default:
		return;
	}
	addr->prefix = prefix;
}

/** Wrappers for IPv4/IPv6 host to IP address lookup
 *
 * This function returns only one IP address, of the specified address family,
 * or the first address (of whatever family), if AF_UNSPEC is used.
 *
 * If fallback is specified and af is AF_INET, but not AF_INET records were
 * found and a record for AF_INET6 exists that record will be returned.
 *
 * If fallback is specified and af is AF_INET6, and a record with AF_INET4 exists
 * that record will be returned inseted.
 *
 * @param[out] out Where to write result.
 * @param[in] af To search for in preference.
 * @param[in] hostname to search for.
 * @param[in] fallback to the other address family, if no records matching af, found.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_inet_hton(fr_ipaddr_t *out, int af, char const *hostname, bool fallback)
{
	int ret;
	struct addrinfo hints, *ai = NULL, *alt = NULL, *res = NULL;

	/*
	 *	Avoid alloc for IP addresses.  This helps us debug
	 *	memory errors when using talloc.
	 */
	if (!fr_hostname_lookups) {
#ifdef HAVE_STRUCT_SOCKADDR_IN6
		if (af == AF_UNSPEC) {
			char const *p;

			for (p = hostname; *p != '\0'; p++) {
				if ((*p == ':') ||
				    (*p == '[') ||
				    (*p == ']')) {
					af = AF_INET6;
					break;
				}
			}
		}
#endif

		if (af == AF_UNSPEC) af = AF_INET;

		if (inet_pton(af, hostname, &(out->addr)) == 0) {
			fr_strerror_printf("\"%s\" is not a valid IP address and "
					   "hostname lookups are disabled", hostname);
			return -1;
		}
		out->af = af;
		out->prefix = 32;
		out->scope_id = 0;

		return 0;
	}

	memset(&hints, 0, sizeof(hints));

	/*
	 *	If we're falling back we need both IPv4 and IPv6 records
	 */
	if (fallback) {
		hints.ai_family = AF_UNSPEC;
	} else {
		hints.ai_family = af;
	}

	if ((ret = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		switch (af) {
		default:
		case AF_UNSPEC:
			fr_strerror_printf("Failed resolving \"%s\" to IP address: %s",
					   hostname, gai_strerror(ret));
			return -1;

		case AF_INET:
			fr_strerror_printf("Failed resolving \"%s\" to IPv4 address: %s",
					   hostname, gai_strerror(ret));
			return -1;

		case AF_INET6:
			fr_strerror_printf("Failed resolving \"%s\" to IPv6 address: %s",
					   hostname, gai_strerror(ret));
			return -1;
		}
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if ((af == ai->ai_family) || (af == AF_UNSPEC)) break;
		if (!alt && fallback && ((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6))) alt = ai;
	}

	if (!ai) ai = alt;
	if (!ai) {
		fr_strerror_printf("Failed resolving \"%s\": No records matching requested address family returned",
				   hostname);
		freeaddrinfo(res);
		return -1;
	}

	ret = fr_ipaddr_from_sockaddr(out, NULL, (struct sockaddr_storage *)ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(res);
	if (ret < 0) {
		fr_strerror_const("Failed converting sockaddr to ipaddr");
		return -1;
	}

	return 0;
}

/** Perform reverse resolution of an IP address
 *
 * Attempt to resolve an IP address to a DNS record (if dns lookups are enabled).
 *
 * @param[in] src address to resolve.
 * @param[out] out Where to write the resulting hostname.
 * @param[in] outlen length of the output buffer.
 */
char const *fr_inet_ntoh(fr_ipaddr_t const *src, char *out, size_t outlen)
{
	struct sockaddr_storage ss;
	int error;
	socklen_t salen;

	/*
	 *	No DNS lookups
	 */
	if (!fr_reverse_lookups) {
		return inet_ntop(src->af, &(src->addr), out, outlen);
	}

	if (fr_ipaddr_to_sockaddr(&ss, &salen, src, 0) < 0) return NULL;

	if ((error = getnameinfo((struct sockaddr *)&ss, salen, out, outlen, NULL, 0,
				 NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		fr_strerror_printf("fr_inet_ntoh: %s", gai_strerror(error));
		return NULL;
	}
	return out;
}


/** Parse a single octet of an IPv4 address string
 *
 * @param[out] out Where to write integer.
 * @param[in] str to parse.
 * @return
 *	- >= 0 on success (number of bytes parsed of in).
 *	- < 0 on error.
 */
static int ip_octet_from_str(uint32_t *out, char const *str)
{
	uint32_t octet;
	char const *p = str;

	if ((*p < '0') || (*p > '9')) return -1;

	octet = 0;

	while ((*p >= '0') && (*p <= '9')) {
		octet *= 10;
		octet += *p - '0';
		p++;

		if (octet > 255) return -1;
	}

	*out = octet;
	return p - str;
}

/** Parses the network portion of an IPv4 prefix into an in_addr
 *
 * @note output is in network order.
 *
 * Parses address strings in dotted quad notation.
 * Unlike inet_pton allows octets to be omitted, in which case their value is considered to be 0.
 * Unlike inet_aton treats integers as representing the highest octet of an IPv4 address, and
 * limits them to 255.
 *
 * Examples of acceptable strings:
 * - 192.168.0.0
 * - 192.168.0.0/24
 * - 192.168/16
 * - 192
 * - 192/8
 *
 * @param[out] out Where to write parsed address.
 * @param[in] str to parse.
 * @return
 *	- >= 0 on success (number of bytes parsed of in).
 *	- < 0 on error.
 */
static int ip_prefix_addr_from_str(struct in_addr *out, char const *str)
{
	int shift, length;
	uint32_t octet;
	uint32_t addr;
	char const *p = str;

	addr = 0;
	out->s_addr = 0;

	for (shift = 24; shift >= 0; shift -= 8) {
		length = ip_octet_from_str(&octet, p);
		if (length <= 0) return -1;

		addr |= octet << shift;
		p += length;

		/*
		 *	EOS or / means we're done.
		 */
		if (!*p || (*p == '/')) break;

		/*
		 *	We require dots between octets.
		 */
		if (*p != '.') return -1;
		p++;
	}

	out->s_addr = htonl(addr);
	return p - str;
}

/** Parse an IPv4 address or IPv4 prefix in presentation format (and others)
 *
 * @param[out] out	Where to write the ip address value.
 * @param[in] value	to parse, may be:
 *			- dotted quad [+ prefix]
 *			- integer
 *			- octal number
 *			- '*' (INADDR_ANY)
 *			- FQDN if resolve is true.
 * @param[in] inlen	Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] resolve	If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @param[in] fallback	to IPv6 resolution if no A records can be found.
 * @param[in] mask_bits	If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton4(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask_bits)
{
	char		*p;
	unsigned int	mask;
	char const	*end;
	char		*eptr;
	char		buffer[256];	/* As per RFC1035 */
	int		ret;

	/*
	 *	Zero out output so we don't have invalid fields
	 *	like scope_id hanging around with garbage values.
	 */
	memset(out, 0, sizeof(*out));

	end = value + inlen;
	while ((value < end) && isspace((int) *value)) value++;
	if (value == end) {
		fr_strerror_const("Empty IPv4 address string is invalid");
		return -1;
	}
	inlen = end - value;

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen >= 0) {
		if (inlen >= (ssize_t)sizeof(buffer)) {
			fr_strerror_printf("Invalid IPv4 address string \"%pV\"", fr_box_strvalue_len(value, inlen));
			return -1;
		}
		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
		value = buffer;
	}

	p = strchr(value, '/');

	/*
	 *	192.0.2.2 is parsed as if it was /32
	 */
	if (!p) {
		out->prefix = 32;
		out->af = AF_INET;

		/*
		 *	Allow '*' as the wildcard address usually 0.0.0.0
		 */
		if ((value[0] == '*') && (value[1] == '\0')) {
			out->addr.v4.s_addr = htonl(INADDR_ANY);

		/*
		 *	Convert things which are obviously integers to IP addresses
		 *
		 *	We assume the number is the bigendian representation of the
		 *	IP address.
		 */
		} else if (is_integer(value) || ((value[0] == '0') && (value[1] == 'x'))) {
			out->addr.v4.s_addr = htonl(strtoul(value, NULL, 0));

		} else if (!resolve) {
			unsigned int a, b, c, d;
			int num;
			char rest;

			a = b = c = d = 0;

			num = sscanf(value, "%u.%u.%u.%u%c", &a, &b, &c, &d, &rest);
			if ((num == 0) || (num == 5) ||
			    (a > 255) || (b > 255) || (c > 255) || (d > 255)) {
				fr_strerror_printf("Failed to parse IPv4 address string \"%s\"", value);
				return -1;
			}

			out->addr.v4.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);

		} else if (fr_inet_hton(out, AF_INET, value, fallback) < 0) return -1;

		return 0;
	}

	/*
	 *     Otherwise parse the prefix
	 */
	if ((size_t)(p - value) >= INET_ADDRSTRLEN) {
               fr_strerror_printf("Invalid IPv4 address string \"%s\"", value);
               return -1;
	}

	/*
	 *	Copy the IP portion into a temporary buffer if we haven't already.
	 */
	if (inlen < 0) memcpy(buffer, value, p - value);

	/*
	 *	We need a special function here, as inet_pton doesn't like
	 *	address strings with octets omitted, and inet_aton treats
	 *	127 as an integer value, and sets the lowest octet of the
	 *	prefix to 127 instead of the highest.
	 *
	 *	@todo we should allow hostnames to be parsed as prefixes.
	 */
	buffer[p - value] = '\0';
	ret = ip_prefix_addr_from_str(&out->addr.v4, buffer);
	buffer[p - value] = '/';	/* Set back to '/' to produce proper errors */

	if (ret <= 0) {
		fr_strerror_printf("Failed to parse IPv4 prefix string \"%s\"", value);
		return -1;
	}

	mask = strtoul(p + 1, &eptr, 10);
	if (mask > 32) {
		fr_strerror_printf("Invalid IPv4 mask length \"%s\".  Should be between 0-32", p);
		return -1;
	}

	if (eptr[0] != '\0') {
		fr_strerror_printf("Failed to parse IPv4 prefix string \"%s\", "
				   "got garbage after mask length \"%s\"", value, eptr);
		return -1;
	}

	if (mask_bits && (mask < 32)) {
		out->addr.v4 = fr_inaddr_mask(&out->addr.v4, mask);
	}

	out->prefix = (uint8_t) mask;
	out->af = AF_INET;

	return 0;
}

/** Parse an IPv6 address or IPv6 prefix in presentation format (and others)
 *
 * @param[out] out	Where to write the ip address value.
 * @param[in] value	to parse, may be:
 *				- IPv6 hexits [+ prefix].
 *				- '*' wildcard.
 *				- FQDN if resolve is true.
 * @param[in] inlen	Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] resolve	If true and value doesn't look like an IP address,
 *			try and resolve value as a hostname.
 * @param[in] fallback	to IPv4 resolution if no AAAA records can be found.
 * @param[in] mask	If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton6(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask)
{
	char		*p;
	char const	*end;
	unsigned int	prefix;
	char		*eptr;
	char		buffer[256];	/* As per RFC1035 */
	int		ret;

	/*
	 *	Zero out output so we don't have fields
	 *	like scope_id hanging around with garbage values.
	 */
	memset(out, 0, sizeof(*out));

	if (inlen < 0) inlen = strlen(value);

	end = value + inlen;
	while ((value < end) && isspace((int) *value)) value++;
	if (value == end) {
		fr_strerror_const("Empty IPv6 address string is invalid");
		return -1;
	}
	inlen = end - value;	/* always >0 due to the above check for value==end */

	/*
	 *	Copy to intermediary buffer.
	 */
	if (inlen >= (ssize_t)sizeof(buffer)) {
		fr_strerror_printf("Invalid IPv6 address string \"%pV\"", fr_box_strvalue_len(value, inlen));
		return -1;
	}

	memcpy(buffer, value, inlen);
	buffer[inlen] = '\0';
	value = buffer;

	p = strchr(value, '/');
	if (!p) {
		out->prefix = 128;
		out->af = AF_INET6;

		/*
		 *	Allow scopes for non-prefix values.
		 */
		p = strchr(value, '%');
		if (p) *(p++) = '\0';

		/*
		 *	Allow '*' as the wildcard address
		 */
		if ((value[0] == '*') && (value[1] == '\0')) {
			out->addr.v6 = (struct in6_addr)IN6ADDR_ANY_INIT;
		} else if (!resolve) {
			if (inet_pton(AF_INET6, value, out->addr.v6.s6_addr) <= 0) {
				fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
				return -1;
			}
		} else if (fr_inet_hton(out, AF_INET6, value, fallback) < 0) return -1;

		/*
		 *	No scope, or just '%'.  That's fine.
		 */
		if (!p || !*p) return 0;

		/*
		 *	Parse scope.
		 */
		prefix = strtoul(p, &eptr, 10);
		if (prefix > UINT32_MAX) {
			fr_strerror_printf("Invalid scope ID \"%s\".  Should be between 0-2^32-1", p);
			return -1;
		}
		if (eptr[0] != '\0') {
			fr_strerror_printf("Failed to parse scope \"%s\", "
					   "got garbage after numerical scope value \"%s\"", p, eptr);
			return -1;
		}

		return 0;
	}

	if ((p - value) >= INET6_ADDRSTRLEN) {
		fr_strerror_printf("Invalid IPv6 address string \"%s\"", value);
		return -1;
	}

	/*
	 *	Copy string to temporary buffer if we didn't do it earlier
	 */
	if (inlen < 0) memcpy(buffer, value, p - value);

	if (!resolve) {
		buffer[p - value] = '\0';
		ret = inet_pton(AF_INET6, buffer, out->addr.v6.s6_addr);
		buffer[p - value] = '/';
		if (ret <= 0) {
			fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
			return -1;
		}
	} else {
		buffer[p - value] = '\0';
		ret = fr_inet_hton(out, AF_INET6, buffer, fallback);
		buffer[p - value] = '/';
		if (ret < 0) return -1;
	}

	prefix = strtoul(p + 1, &eptr, 10);
	if (prefix > 128) {
		fr_strerror_printf("Invalid IPv6 mask length \"%s\".  Should be between 0-128", p);
		return -1;
	}
	if (eptr[0] != '\0') {
		fr_strerror_printf("Failed to parse IPv6 address string \"%s\", "
				   "got garbage after mask length \"%s\"", value, eptr);
		return -1;
	}

	if (mask && (prefix < 128)) {
		struct in6_addr addr;

		addr = fr_in6addr_mask(&out->addr.v6, prefix);
		memcpy(out->addr.v6.s6_addr, addr.s6_addr, sizeof(out->addr.v6.s6_addr));
	}

	out->af = AF_INET6;
	out->prefix = (uint8_t) prefix;

	return 0;
}

/** Simple wrapper to decide whether an IP value is v4 or v6 and call the appropriate parser
 *
 * @param[out] out	Where to write the ip address value.
 * @param[in] value	to parse.
 * @param[in] inlen	Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] resolve	If true and value doesn't look like an IP address, try and resolve value
 *			as a hostname.
 * @param[in] af	If the address type is not obvious from the format, and resolve is true,
 *			the DNS record (A or AAAA) we require.  Also controls which parser we pass
 *			the address to if we have no idea what it is.
 *			- AF_UNSPEC - Use the server default IP family.
 *			- AF_INET - Treat value as an IPv4 address.
 *			- AF_INET6 - Treat value as in IPv6 address.
 * @param[in] mask If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton(fr_ipaddr_t *out, char const *value, ssize_t inlen, int af, bool resolve, bool mask)
{
	size_t len, i;
	bool hostname = true;
	bool ipv4 = true;
	bool ipv6 = true;
	char const *end;

	end = value + inlen;
	while ((value < end) && isspace((int) *value)) value++;
	if (value == end) {
		fr_strerror_const("Empty IPv4 address string is invalid");
		return -1;
	}
	inlen = end - value;

	len = (inlen >= 0) ? (size_t)inlen : strlen(value);

	for (i = 0; i < len; i++) {
		/*
		 *	These are valid for IPv4, IPv6, and host names.
		 */
		if ((value[i] >= '0') && (value[i] <= '9')) {
			continue;
		}

		/*
		 *	These are invalid for IPv4, but OK for IPv6
		 *	and host names.
		 */
		if ((value[i] >= 'a') && (value[i] <= 'f')) {
			ipv4 = false;
			continue;
		}

		/*
		 *	These are invalid for IPv4, but OK for IPv6
		 *	and host names.
		 */
		if ((value[i] >= 'A') && (value[i] <= 'F')) {
			ipv4 = false;
			continue;
		}

		/*
		 *	This is only valid for IPv6 addresses.
		 */
		if (value[i] == ':') {
			ipv4 = false;
			hostname = false;
			continue;
		}

		/*
		 *	Valid for IPv4 and host names, not for IPv6.
		 */
		if (value[i] == '.') {
			ipv6 = false;
			continue;
		}

		/*
		 *	Netmasks are allowed by us, and MUST come at
		 *	the end of the address.
		 */
		if (value[i] == '/') {
			break;
		}

		/*
		 *	Any characters other than what are checked for
		 *	above can't be IPv4 or IPv6 addresses.
		 */
		ipv4 = false;
		ipv6 = false;
	}

	/*
	 *	It's not an IPv4 or IPv6 address.  It MUST be a host
	 *	name.
	 */
	if (!ipv4 && !ipv6) {
		/*
		 *	Not an IPv4 or IPv6 address, and we weren't
		 *	asked to do DNS resolution, we can't do it.
		 */
		if (!resolve) {
			fr_strerror_const("Not IPv4/6 address, and asked not to resolve");
			return -1;
		}

		/*
		 *	It's not a hostname, either, so bail out
		 *	early.
		 */
		if (!hostname) {
			fr_strerror_const("Invalid address");
			return -1;
		}
	}

	/*
	 *	The name has a ':' in it.  Therefore it must be an
	 *	IPv6 address.  Error out if the caller specified IPv4.
	 *	Otherwise, force IPv6.
	 */
	if (ipv6 && !hostname) {
		if (af == AF_INET) {
			fr_strerror_const("Invalid address");
			return -1;
		}

		af = AF_INET6;
	}

	/*
	 *	Use whatever the caller specified, OR what we
	 *	insinuated above from looking at the name string.
	 */
	switch (af) {
	case AF_UNSPEC:
		return fr_inet_pton4(out, value, inlen, resolve, true, mask);

	case AF_INET:
		return fr_inet_pton4(out, value, inlen, resolve, false, mask);

	case AF_INET6:
		return fr_inet_pton6(out, value, inlen, resolve, false, mask);

	default:
		break;
	}

	/*
	 *	No idea what it is...
	 */
	fr_strerror_printf("Invalid address family %i", af);
	return -1;
}

/** Parses IPv4/6 address + port, to fr_ipaddr_t and integer (port)
 *
 * @param[out] out	Where to write the ip address value.
 * @param[out] port_out	Where to write the port (0 if no port found).
 * @param[in] value	to parse.
 * @param[in] inlen	Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] resolve	If true and value doesn't look like an IP address, try and resolve value
 *			as a hostname.
 * @param[in] af	If the address type is not obvious from the format, and resolve is true,
 *			the DNS record (A or AAAA) we require.  Also controls which parser we pass
 *			the address to if we have no idea what it is.
 *			- AF_UNSPEC - Use the server default IP family.
 *			- AF_INET - Treat value as an IPv4 address.
 *			- AF_INET6 - Treat value as in IPv6 address.
 * @param[in] mask If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton_port(fr_ipaddr_t *out, uint16_t *port_out, char const *value,
		      ssize_t inlen, int af, bool resolve, bool mask)
{
	char const	*p = value, *q;
	char		*end;
	unsigned long	port;
	char		buffer[6];
	size_t		len;

	*port_out = 0;

	len = (inlen >= 0) ? (size_t)inlen : strlen(value);

	if (*p == '[') {
		if (!(q = memchr(p + 1, ']', len - 1))) {
			fr_strerror_const("Missing closing ']' for IPv6 address");
			return -1;
		}

		/*
		 *	inet_pton doesn't like the address being wrapped in []
		 */
		if (fr_inet_pton6(out, p + 1, (q - p) - 1, false, false, mask) < 0) return -1;

		if (q[1] == ':') {
			q++;
			goto do_port;
		}

		return 0;
	}

	/*
	 *	Host, IPv4 or IPv6 with no port
	 */
	q = memchr(p, ':', len);
	if (!q) return fr_inet_pton(out, p, len, af, resolve, mask);

	/*
	 *	IPv4 or host, with port
	 */
	if (fr_inet_pton(out, p, (q - p), af, resolve, mask) < 0) return -1;
do_port:
	/*
	 *	Valid ports are a maximum of 5 digits, so if the
	 *	input length indicates there are more than 5 chars
	 *	after the ':' then there's an issue.
	 */
	if (len > (size_t) ((q + sizeof(buffer)) - value)) {
	error:
		fr_strerror_const("IP string contains trailing garbage after port delimiter");
		return -1;
	}

	p = q + 1;			/* Move to first digit */

	strlcpy(buffer, p, (len - (p - value)) + 1);
	port = strtoul(buffer, &end, 10);
	if (*end != '\0') goto error;	/* Trailing garbage after integer */

	if ((port > UINT16_MAX) || (port == 0)) {
		fr_strerror_printf("Port %lu outside valid port range 1-" STRINGIFY(UINT16_MAX), port);
		return -1;
	}
	*port_out = port;

	return 0;
}

/** Print the address portion of a #fr_ipaddr_t
 *
 * @note Includes the textual scope_id name (eth0, en0 etc...) if supported.
 *
 * @param[out] out Where to write the resulting IP string.
 *	Should be at least FR_IPADDR_STRLEN bytes.
 * @param[in] outlen of output buffer.
 * @param[in] addr to convert to presentation format.
 * @return
 *	- NULL on error (use fr_syserror(errno)).
 *	- a pointer to out on success.
 */
char *fr_inet_ntop(char out[static FR_IPADDR_STRLEN], size_t outlen, fr_ipaddr_t const *addr)
{
	char	*p;
	size_t	len;

	out[0] = '\0';

	if (inet_ntop(addr->af, &addr->addr, out, outlen) == NULL) {
		fr_strerror_printf("%s", fr_syserror(errno));
		return NULL;
	}

	if ((addr->af == AF_INET) || (addr->scope_id == 0)) return out;

	p = out + strlen(out);

#ifdef WITH_IFINDEX_NAME_RESOLUTION
	{
		char buffer[IFNAMSIZ];
		char *ifname;

		ifname = fr_ifname_from_ifindex(buffer, addr->scope_id);
		if (ifname) {
			len = snprintf(p, outlen - (p - out), "%%%s", ifname);
			if (is_truncated(len + (p - out), outlen)) {
				fr_strerror_printf("Address buffer too small, needed %zu bytes, have %zu bytes",
						   (p - out) + len, outlen);
				return NULL;
			}
			return out;
		}

	}
#endif

	len = snprintf(p, outlen - (p - out), "%%%u", addr->scope_id);
	if (is_truncated(len + (p - out), outlen)) {
		fr_strerror_printf("Address buffer too small, needed %zu bytes, have %zu bytes",
				   (p - out) + len, outlen);
		return NULL;
	}

	return out;
}

/** Print a #fr_ipaddr_t as a CIDR style network prefix
 *
 * @param[out] out Where to write the resulting prefix string.
 *	Should be at least FR_IPADDR_PREFIX_STRLEN bytes.
 * @param[in] outlen of output buffer.
 * @param[in] addr to convert to presentation format.
 * @return
 *	- NULL on error (use fr_syserror(errno)).
 *	- a pointer to out on success.
 */
char *fr_inet_ntop_prefix(char out[static FR_IPADDR_PREFIX_STRLEN], size_t outlen, fr_ipaddr_t const *addr)
{
	char	*p;
	size_t	len;

	if (fr_inet_ntop(out, outlen, addr) == NULL) return NULL;

	p = out + strlen(out);

	len = snprintf(p, outlen - (p - out), "/%i", addr->prefix);
	if (is_truncated(len + (p - out), outlen)) {
		fr_strerror_printf("Address buffer too small, needed %zu bytes, have %zu bytes",
				   (p - out) + len, outlen);
		return NULL;
	}

	return out;
}

/** Print an interface-id in standard colon notation
 *
 * @param[out] out Where to write the resulting interface-id string.
 * @param[in] outlen of output buffer.
 * @param[in] ifid to print.
 * @return a pointer to out.
 */
char *fr_inet_ifid_ntop(char *out, size_t outlen, uint8_t const *ifid)
{
	snprintf(out, outlen, "%x:%x:%x:%x",
		 fr_nbo_to_uint16(ifid),     fr_nbo_to_uint16(ifid + 2),
		 fr_nbo_to_uint16(ifid + 4), fr_nbo_to_uint16(ifid + 6));
	return out;
}

/** Convert interface-id in colon notation to 8 byte binary form
 *
 * @param[out] out Where to write the binary interface-id.
 * @param[in] ifid_str to parse.
 * @return a pointer to out.
 */
uint8_t *fr_inet_ifid_pton(uint8_t out[static 8], char const *ifid_str)
{
	static char const xdigits[] = "0123456789abcdef";
	char const *p, *pch;
	int num_id = 0, val = 0, idx = 0;

	for (p = ifid_str; ; ++p) {
		if (*p == ':' || *p == '\0') {
			if (num_id <= 0)
				return NULL;

			/*
			 *	Drop 'val' into the array.
			 */
			out[idx] = (val >> 8) & 0xff;
			out[idx + 1] = val & 0xff;
			if (*p == '\0') {
				/*
				 *	Must have all entries before
				 *	end of the string.
				 */
				if (idx != 6)
					return NULL;
				break;
			}
			val = 0;
			num_id = 0;
			if ((idx += 2) > 6)
				return NULL;
		} else if ((pch = strchr(xdigits, tolower(*p))) != NULL) {
			if (++num_id > 4)
				return NULL;
			/*
			 *	Dumb version of 'scanf'
			 */
			val <<= 4;
			val |= (pch - xdigits);
		} else
			return NULL;
	}
	return out;
}

#ifdef SIOCGIFADDR
/** Retrieve the primary IP address associated with an interface
 *
 * @param[out] out The primary IP address associated with the named interface.
 * @param[in] af of IP address to retrieve (AF_INET or AF_INET6).
 * @param[in] name of interface.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ipaddr_from_ifname(fr_ipaddr_t *out, int af, char const *name)
{
	int			fd;
	struct ifreq		if_req;
	fr_ipaddr_t		ipaddr;

	memset(&if_req, 0, sizeof(if_req));
	memset(out, 0, sizeof(*out));

	/*
	 *	Set the interface we're resolving, and the address family.
	 */
	if_req.ifr_addr.sa_family = af;
	strlcpy(if_req.ifr_name, name, sizeof(if_req.ifr_name));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fr_strerror_printf("Failed opening temporary socket for SIOCGIFADDR: %s", fr_syserror(errno));
	error:
		close(fd);
		return -1;
	}
	if (ioctl(fd, SIOCGIFADDR, &if_req) < 0) {
		fr_strerror_printf("Failed determining address for interface %s: %s", name, fr_syserror(errno));
		goto error;
	}

	/*
	 *	There's nothing in the ifreq struct that gives us the length
	 *	of the sockaddr struct, so we just use sizeof here.
	 *	sockaddr2ipaddr uses the address family anyway, so we should
	 *	be OK.
	 */
	if (fr_ipaddr_from_sockaddr(&ipaddr, NULL,
				    (struct sockaddr_storage *)&if_req.ifr_addr,
				    sizeof(if_req.ifr_addr)) < 0) goto error;
	*out = ipaddr;

	close(fd);

	return 0;
}
#else
int fr_ipaddr_from_ifname(UNUSED fr_ipaddr_t *out, UNUSED int af, char const *name)
{
	fr_strerror_printf("No support for SIOCGIFADDR, can't determine IP address of %s", name);
	return -1;
}
#endif

#ifdef WITH_IFINDEX_NAME_RESOLUTION
/** Resolve ifindex to interface name
 *
 * @param[out] out Buffer to use to store the name, must be at least IFNAMSIZ bytes.
 * @param[in] ifindex to resolve to name.
 * @return
 *	- NULL on error.
 *	- a pointer to out on success.
 */
char *fr_ifname_from_ifindex(char out[static IFNAMSIZ], int ifindex)
{
#ifdef HAVE_IF_INDEXTONAME
	if (!if_indextoname(ifindex, out)) {
		fr_strerror_printf("Failed resolving interface index %i to name", ifindex);
		return NULL;
	}
#else
	struct ifreq	if_req;
	int		fd;

	memset(&if_req, 0, sizeof(if_req));
	if_req.ifr_ifindex = ifindex;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fr_strerror_printf("Failed opening temporary socket for SIOCGIFADDR: %s", fr_syserror(errno));
	error:
		close(fd);
		return NULL;
	}

	/*
	 *	First we resolve the interface index to the interface name
	 *	Which is pretty inefficient, but it seems the only way to
	 *	identify interfaces for SIOCG* operations is with the interface
	 *	name.
	 */
	if (ioctl(fd, SIOCGIFNAME, &if_req) < 0) {
		fr_strerror_printf("Failed resolving interface index %i to name: %s", ifindex, fr_syserror(errno));
		goto error;
	}
	strlcpy(out, if_req.ifr_name, IFNAMSIZ);
	close(fd);
#endif
	return out;
}
#endif

#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
/** Returns the primary IP address for a given interface index
 *
 * @note Intended to be used with udpfromto (recvfromto) to retrieve the
 *	source IP address to use when responding to broadcast packets.
 *
 * @note Will likely be quite slow due to the number of system calls.
 *
 * @param[out] out Where to write the primary IP address.
 * @param[in] fd File descriptor of any datagram or raw socket.
 * @param[in] af to get interface for.
 * @param[in] ifindex of interface to get IP address for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ipaddr_from_ifindex(fr_ipaddr_t *out, int fd, int af, int ifindex)
{
	struct ifreq		if_req;
	fr_ipaddr_t		ipaddr;

	memset(&if_req, 0, sizeof(if_req));
	memset(out, 0, sizeof(*out));

#ifdef SIOCGIFNAME
	if_req.ifr_ifindex = ifindex;
	/*
	 *	First we resolve the interface index to the interface name
	 *	Which is pretty inefficient, but it seems the only way to
	 *	identify interfaces for SIOCG* operations is with the interface
	 *	name.
	 */
	if (ioctl(fd, SIOCGIFNAME, &if_req) < 0) {
		fr_strerror_printf("Failed resolving interface index %i to name: %s", ifindex, fr_syserror(errno));
		return -1;
	}
#elif defined(HAVE_IF_INDEXTONAME)
	if (!if_indextoname(ifindex, if_req.ifr_name)) {
		fr_strerror_printf("Failed resolving interface index %i to name", ifindex);
		return -1;
	}
#else
#  error Need SIOCGIFNAME or if_indextoname
#endif

	/*
	 *	Name should now be present in if_req, so we just need to
	 *	set the address family.
	 */
	if_req.ifr_addr.sa_family = af;

	if (ioctl(fd, SIOCGIFADDR, &if_req) < 0) {
		fr_strerror_printf("Failed determining address for interface %s: %s",
				   if_req.ifr_name, fr_syserror(errno));
		return -1;
	}

	/*
	 *	There's nothing in the ifreq struct that gives us the length
	 *	of the sockaddr struct, so we just use sizeof here.
	 *	sockaddr2ipaddr uses the address family anyway, so we should
	 *	be OK.
	 */
	if (fr_ipaddr_from_sockaddr(&ipaddr, NULL,
				    (struct sockaddr_storage *)&if_req.ifr_addr,
				    sizeof(if_req.ifr_addr)) < 0) return -1;
	*out = ipaddr;

	return 0;
}
#endif

/** Compare two ip addresses
 *
 * @param[in] a		First ip to compare.
 * @param[in] b		Second ip to compare.
 * @return
 *	- 1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 *	- -2 on error.
 */
int8_t fr_ipaddr_cmp(fr_ipaddr_t const *a, fr_ipaddr_t const *b)
{
	int ret;
	size_t len;

	CMP_RETURN(a, b, af);
	CMP_RETURN(a, b, prefix);

	/*
	 *	We only care about prefix bytes.
	 *
	 *	Host bytes should be masked on ingestion
	 *	for prefix types.
	 */
	len = ((a->prefix + 7) & -8) >> 3;
	switch (a->af) {
	case AF_INET:
		ret = memcmp(&a->addr.v4, &b->addr.v4, len);
		return CMP(ret, 0);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	case AF_INET6:
		CMP_RETURN(a, b, scope_id);
		ret = memcmp(&a->addr.v6, &b->addr.v6, len);
		return CMP(ret, 0);
#endif

	default:
		fr_strerror_printf("Invalid address family %u", a->af);
		return -2;
	}
}

/** Convert our internal ip address representation to a sockaddr
 *
 * @param[out] sa	where to write out the sockaddr,
 *			must be large enough to hold
 *			sizeof(s6).
 * @param[out] salen	Length of the sockaddr struct.
 * @param[in] ipaddr	IP address to convert.
 * @param[in] port	Port to convert.

 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ipaddr_to_sockaddr(struct sockaddr_storage *sa, socklen_t *salen,
			  fr_ipaddr_t const *ipaddr, uint16_t port)
{
	memset(sa, 0, sizeof(*sa));

	if (ipaddr->af == AF_INET) {
		struct sockaddr_in s4;

		*salen = sizeof(s4);

		memset(&s4, 0, sizeof(s4));
		s4.sin_family = AF_INET;
		s4.sin_addr = ipaddr->addr.v4;
		s4.sin_port = htons(port);
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s4, sizeof(s4));

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		struct sockaddr_in6 s6;

		*salen = sizeof(s6);

		memset(&s6, 0, sizeof(s6));
		s6.sin6_family = AF_INET6;
		s6.sin6_addr = ipaddr->addr.v6;
		s6.sin6_port = htons(port);
		s6.sin6_scope_id = ipaddr->scope_id;
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s6, sizeof(s6));
#endif
	} else {
		fr_strerror_printf("Unsupported address family %d", ipaddr->af);
		return -1;
	}

	return 0;
}

/** Convert sockaddr to our internal ip address representation
 *
 * @param[out] ipaddr	Where to write the ipaddr.
 * @param[out] port	Where to write the port.
 * @param[in] sa	struct to convert.
 * @param[in] salen	Length of the sockaddr struct.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ipaddr_from_sockaddr(fr_ipaddr_t *ipaddr, uint16_t *port,
			    struct sockaddr_storage const *sa, socklen_t salen)
{
	memset(ipaddr, 0, sizeof(*ipaddr));

	if (sa->ss_family == AF_INET) {
		struct sockaddr_in s4;

		if (salen < sizeof(s4)) {
			fr_strerror_const("IPv4 address is too small");
			return 0;
		}

		memcpy(&s4, sa, sizeof(s4));
		ipaddr->af = AF_INET;
		ipaddr->prefix = 32;
		ipaddr->addr.v4 = s4.sin_addr;
		if (port) *port = ntohs(s4.sin_port);
		ipaddr->scope_id = 0;

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (sa->ss_family == AF_INET6) {
		struct sockaddr_in6 s6;

		if (salen < sizeof(s6)) {
			fr_strerror_const("IPv6 address is too small");
			return 0;
		}

		memcpy(&s6, sa, sizeof(s6));
		ipaddr->af = AF_INET6;
		ipaddr->prefix = 128;
		ipaddr->addr.v6 = s6.sin6_addr;
		if (port) *port = ntohs(s6.sin6_port);
		ipaddr->scope_id = s6.sin6_scope_id;
#endif

	} else {
		fr_strerror_printf("Unsupported address family %d", sa->ss_family);
		return -1;
	}

	return 0;
}

char *fr_ipaddr_to_interface(TALLOC_CTX *ctx, fr_ipaddr_t *ipaddr)
{
	struct ifaddrs *list = NULL;
	struct ifaddrs *i;
	char *interface = NULL;

	/*
	 *	Bind manually to an IP used by the named interface.
	 */
	if (getifaddrs(&list) < 0) return NULL;

	for (i = list; i != NULL; i = i->ifa_next) {
		int scope_id;
		fr_ipaddr_t my_ipaddr;

		if (!i->ifa_addr || !i->ifa_name || (ipaddr->af != i->ifa_addr->sa_family)) continue;

		fr_ipaddr_from_sockaddr(&my_ipaddr, NULL,
					(struct sockaddr_storage *)i->ifa_addr, sizeof(struct sockaddr_in6));

		/*
		 *	my_ipaddr will have a scope_id, but the input
		 *	ipaddr won't have one.  We therefore set the
		 *	local one to zero, so that we can do correct
		 *	IP address comparisons.
		 *
		 *	If the comparison succeeds, then we return
		 *	both the interface name, and we update the
		 *	input ipaddr with the correct scope_id.
		 */
		scope_id = my_ipaddr.scope_id;
		my_ipaddr.scope_id = 0;
		if (fr_ipaddr_cmp(ipaddr, &my_ipaddr) == 0) {
			interface = talloc_strdup(ctx, i->ifa_name);
			ipaddr->scope_id = scope_id;
			break;
		}
	}

	freeifaddrs(list);
	return interface;
}

int fr_interface_to_ipaddr(char const *interface, fr_ipaddr_t *ipaddr, int af, bool link_local)
{
	struct ifaddrs *list = NULL;
	struct ifaddrs *i;
	int ret = -1;

	if (getifaddrs(&list) < 0) return -1;

	for (i = list; i != NULL; i = i->ifa_next) {
		fr_ipaddr_t my_ipaddr;
		struct sockaddr_storage sa;

		if (!i->ifa_addr || !i->ifa_name || ((af != AF_UNSPEC) && (af != i->ifa_addr->sa_family))) continue;
		if (strcmp(i->ifa_name, interface) != 0) continue;

		memcpy(&sa, i->ifa_addr,  sizeof(struct sockaddr_in6)); /* ifa->ifa_addr may not be aligned properly */

		fr_ipaddr_from_sockaddr(&my_ipaddr, NULL, &sa, sizeof(struct sockaddr_in6));

		/*
		 *	If they ask for a link local address, then give
		 *	it to them.
		 */
		if (link_local) {
			if (my_ipaddr.af != AF_INET6) continue;
			if (!IN6_IS_ADDR_LINKLOCAL(&my_ipaddr.addr.v6)) continue;
		}

		*ipaddr = my_ipaddr;
		ret = 0;
		break;
	}

	freeifaddrs(list);
	return ret;
}

/*
 *	AF_PACKET on Linux
 *	AF_LINK on BSD
 */
#ifndef AF_LINK
#define AF_LINK AF_PACKET
#endif

int fr_interface_to_ethernet(char const *interface, fr_ethernet_t *ethernet)
{
	struct ifaddrs *list = NULL;
	struct ifaddrs *i;
	int ret = -1;

	if (getifaddrs(&list) < 0) return -1;

	for (i = list; i != NULL; i = i->ifa_next) {
		if (!i->ifa_addr || !i->ifa_name || (i->ifa_addr->sa_family != AF_LINK)) continue;
		if (strcmp(i->ifa_name, interface) != 0) continue;

#if defined(__linux__) || defined(__EMSCRIPTEN__)
		struct sockaddr_ll *ll;

		ll = (struct sockaddr_ll *) i->ifa_addr;
		if ((ll->sll_hatype != 1) || (ll->sll_halen != 6)) continue;

		memcpy(ethernet->addr, ll->sll_addr, 6);

#else
		struct sockaddr_dl *ll;

		ll = (struct sockaddr_dl *) i->ifa_addr;
		if (ll->sdl_alen != 6) continue;

		memcpy(ethernet->addr, LLADDR(ll), 6);
#endif
		ret = 0;
		break;
	}

	freeifaddrs(list);
	return ret;
}
