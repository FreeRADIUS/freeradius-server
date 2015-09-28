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
 * @file inet.c
 * @brief Functions to parse, print, mask and retrieve IP addresses
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/inet.h>
#include <freeradius-devel/libradius.h>
#include <ctype.h>

bool	fr_dns_lookups = false;	    //!< IP -> hostname lookups?
bool    fr_hostname_lookups = true; //!< hostname -> IP lookups?

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
	uint64_t ret[2], *o = ret;

	if (prefix > 128) prefix = 128;

	/* Short circuit */
	if (prefix == 128) return *ipaddr;

	if (prefix >= 64) {
		prefix -= 64;
		*o++ = 0xffffffffffffffffULL & *p++;	/* lhs portion masked */
	} else {
		ret[1] = 0;				/* rhs portion zeroed */
	}

	/* Max left shift is 63 else we get overflow */
	if (prefix > 0) {
		*o = htonll(~((uint64_t)(0x0000000000000001ULL << (64 - prefix)) - 1)) & *p;
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
		addr->ipaddr.ip4addr = fr_inaddr_mask(&addr->ipaddr.ip4addr, prefix);
		break;

	case AF_INET6:
		addr->ipaddr.ip6addr = fr_in6addr_mask(&addr->ipaddr.ip6addr, prefix);
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
	int rcode;
	struct addrinfo hints, *ai = NULL, *alt = NULL, *res = NULL;

	/*
	 *	Avoid malloc for IP addresses.  This helps us debug
	 *	memory errors when using talloc.
	 */
#ifdef TALLOC_DEBUG
	if (true) {
#else
	if (!fr_hostname_lookups) {
#endif
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

		if (!inet_pton(af, hostname, &(out->ipaddr))) return -1;

		out->af = af;
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

	if ((rcode = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		switch (af) {
		default:
		case AF_UNSPEC:
			fr_strerror_printf("Failed resolving \"%s\" to IP address: %s",
					   hostname, gai_strerror(rcode));
			return -1;

		case AF_INET:
			fr_strerror_printf("Failed resolving \"%s\" to IPv4 address: %s",
					   hostname, gai_strerror(rcode));
			return -1;

		case AF_INET6:
			fr_strerror_printf("Failed resolving \"%s\" to IPv6 address: %s",
					   hostname, gai_strerror(rcode));
			return -1;
		}
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if ((af == ai->ai_family) || (af == AF_UNSPEC)) break;
		if (!alt && fallback && ((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6))) alt = ai;
	}

	if (!ai) ai = alt;
	if (!ai) {
		fr_strerror_printf("fr_inet_hton failed to find requested information for host %.100s", hostname);
		freeaddrinfo(res);
		return -1;
	}

	rcode = fr_ipaddr_from_sockaddr((struct sockaddr_storage *)ai->ai_addr,
				   ai->ai_addrlen, out, NULL);
	freeaddrinfo(res);
	if (!rcode) {
		fr_strerror_printf("Failed converting sockaddr to ipaddr");
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
	if (!fr_dns_lookups) {
		return inet_ntop(src->af, &(src->ipaddr), out, outlen);
	}

	if (!fr_ipaddr_to_sockaddr(src, 0, &ss, &salen)) {
		return NULL;
	}

	if ((error = getnameinfo((struct sockaddr *)&ss, salen, out, outlen, NULL, 0,
				 NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		fr_strerror_printf("fr_inet_ntoh: %s", gai_strerror(error));
		return NULL;
	}
	return out;
}

/** Parse an IPv4 address or IPv4 prefix in presentation format (and others)
 *
 * @param out Where to write the ip address value.
 * @param value to parse, may be dotted quad [+ prefix], or integer, or octal number, or '*' (INADDR_ANY).
 * @param inlen Length of value, if value is \0 terminated inlen may be -1.
 * @param resolve If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @param fallback to IPv6 resolution if no A records can be found.
 * @param mask If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully
 *	- -1 on failure.
 */
int fr_inet_pton4(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask)
{
	char *p;
	unsigned int prefix;
	char *eptr;

	/* Dotted quad + / + [0-9]{1,2} */
	char buffer[INET_ADDRSTRLEN + 3];

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen >= 0) {
		if (inlen >= (ssize_t)sizeof(buffer)) {
			fr_strerror_printf("Invalid IPv4 address string \"%s\"", value);
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
			out->ipaddr.ip4addr.s_addr = htonl(INADDR_ANY);
		/*
		 *	Convert things which are obviously integers to IP addresses
		 *
		 *	We assume the number is the bigendian representation of the
		 *	IP address.
		 */
		} else if (is_integer(value) || ((value[0] == '0') && (value[1] == 'x'))) {
			out->ipaddr.ip4addr.s_addr = htonl(strtoul(value, NULL, 0));
		} else if (!resolve) {
			if (inet_pton(AF_INET, value, &out->ipaddr.ip4addr.s_addr) <= 0) {
				fr_strerror_printf("Failed to parse IPv4 address string \"%s\"", value);
				return -1;
			}
		} else if (fr_inet_hton(out, AF_INET, value, fallback) < 0) return -1;

		return 0;
	}

	/*
	 *	Otherwise parse the prefix
	 */
	if ((size_t)(p - value) >= INET_ADDRSTRLEN) {
		fr_strerror_printf("Invalid IPv4 address string \"%s\"", value);
		return -1;
	}

	/*
	 *	Copy the IP portion into a temporary buffer if we haven't already.
	 */
	if (inlen < 0) memcpy(buffer, value, p - value);
	buffer[p - value] = '\0';

	if (!resolve) {
		if (inet_pton(AF_INET, buffer, &out->ipaddr.ip4addr.s_addr) <= 0) {
			fr_strerror_printf("Failed to parse IPv4 address string \"%s\"", value);
			return -1;
		}
	} else if (fr_inet_hton(out, AF_INET, buffer, fallback) < 0) return -1;

	prefix = strtoul(p + 1, &eptr, 10);
	if (prefix > 32) {
		fr_strerror_printf("Invalid IPv4 mask length \"%s\".  Should be between 0-32", p);
		return -1;
	}
	if (eptr[0] != '\0') {
		fr_strerror_printf("Failed to parse IPv4 address string \"%s\", "
				   "got garbage after mask length \"%s\"", value, eptr);
		return -1;
	}

	if (mask && (prefix < 32)) {
		out->ipaddr.ip4addr = fr_inaddr_mask(&out->ipaddr.ip4addr, prefix);
	}

	out->prefix = (uint8_t) prefix;
	out->af = AF_INET;

	return 0;
}

/** Parse an IPv6 address or IPv6 prefix in presentation format (and others)
 *
 * @param out Where to write the ip address value.
 * @param value to parse.
 * @param inlen Length of value, if value is \0 terminated inlen may be -1.
 * @param resolve If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @param fallback to IPv4 resolution if no AAAA records can be found.
 * @param mask If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton6(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask)
{
	char const *p;
	unsigned int prefix;
	char *eptr;

	/* IPv6  + / + [0-9]{1,3} */
	char buffer[INET6_ADDRSTRLEN + 4];

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen >= 0) {
		if (inlen >= (ssize_t)sizeof(buffer)) {
			fr_strerror_printf("Invalid IPv6 address string \"%s\"", value);
			return -1;
		}
		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
		value = buffer;
	}

	p = strchr(value, '/');
	if (!p) {
		out->prefix = 128;
		out->af = AF_INET6;

		/*
		 *	Allow '*' as the wildcard address
		 */
		if ((value[0] == '*') && (value[1] == '\0')) {
			memset(out->ipaddr.ip6addr.s6_addr, 0, sizeof(out->ipaddr.ip6addr.s6_addr));
		} else if (!resolve) {
			if (inet_pton(AF_INET6, value, out->ipaddr.ip6addr.s6_addr) <= 0) {
				fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
				return -1;
			}
		} else if (fr_inet_hton(out, AF_INET6, value, fallback) < 0) return -1;

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
	buffer[p - value] = '\0';

	if (!resolve) {
		if (inet_pton(AF_INET6, buffer, out->ipaddr.ip6addr.s6_addr) <= 0) {
			fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
			return -1;
		}
	} else if (fr_inet_hton(out, AF_INET6, buffer, fallback) < 0) return -1;

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

		addr = fr_in6addr_mask(&out->ipaddr.ip6addr, prefix);
		memcpy(out->ipaddr.ip6addr.s6_addr, addr.s6_addr, sizeof(out->ipaddr.ip6addr.s6_addr));
	}

	out->prefix = (uint8_t) prefix;
	out->af = AF_INET6;

	return 0;
}

/** Simple wrapper to decide whether an IP value is v4 or v6 and call the appropriate parser
 *
 * @param[out] out Where to write the ip address value.
 * @param[in] value to parse.
 * @param[in] inlen Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] resolve If true and value doesn't look like an IP address, try and resolve value as a
 *	hostname.
 * @param[in] af If the address type is not obvious from the format, and resolve is true, the DNS
 *	record (A or AAAA) we require.  Also controls which parser we pass the address to if
 *	we have no idea what it is.
 * @param[in] mask If true, set address bits to zero.
 * @return
 *	- 0 if ip address was parsed successfully.
 *	- -1 on failure.
 */
int fr_inet_pton(fr_ipaddr_t *out, char const *value, ssize_t inlen, int af, bool resolve, bool mask)
{
	size_t len, i;

	len = (inlen >= 0) ? (size_t)inlen : strlen(value);
	for (i = 0; i < len; i++) switch (value[i]) {
	/*
	 *	':' is illegal in domain names and IPv4 addresses.
	 *	Must be v6 and cannot be a domain.
	 */
	case ':':
		return fr_inet_pton6(out, value, inlen, false, false, mask);

	/*
	 *	Chars which don't really tell us anything
	 */
	case '.':
	case '/':
		continue;

	default:
		/*
		 *	Outside the range of IPv4 chars, must be a domain
		 *	Use A record in preference to AAAA record.
		 */
		if ((value[i] < '0') || (value[i] > '9')) {
			if (!resolve) {
				fr_strerror_printf("Not IPv4/6 address, and asked not to resolve");
				return -1;
			}
			switch (af) {
			case AF_UNSPEC:
				return fr_inet_pton4(out, value, inlen, resolve, true, mask);

			case AF_INET:
				return fr_inet_pton4(out, value, inlen, resolve, false, mask);

			case AF_INET6:
				return fr_inet_pton6(out, value, inlen, resolve, false, mask);

			default:
				fr_strerror_printf("Invalid address family %i", af);
				return -1;
			}
		}
		break;
	}

 	/*
 	 *	All chars were in the IPv4 set [0-9/.], must be an IPv4
 	 *	address.
 	 */
	return fr_inet_pton4(out, value, inlen, false, false, mask);
}

/** Parses IPv4/6 address + port, to fr_ipaddr_t and integer (port)
 *
 * @param[out] out Where to write the ip address value.
 * @param[out] port_out Where to write the port (0 if no port found).
 * @param[in] value to parse.
 * @param[in] inlen Length of value, if value is \0 terminated inlen may be -1.
 * @param[in] af If the address type is not obvious from the format, and resolve is true, the DNS
 *	record (A or AAAA) we require.  Also controls which parser we pass the address to if
 *	we have no idea what it is.
 * @param[in] resolve If true and value doesn't look like an IP address, try and resolve value as a
 *	hostname.
 * @param[in] mask If true, set address bits to zero.
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
			fr_strerror_printf("Missing closing ']' for IPv6 address");
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
	if (!q || !memchr(p, '.', len)) return fr_inet_pton(out, p, len, af, resolve, mask);

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
	if (inlen > ((q + sizeof(buffer)) - value)) {
	error:
		fr_strerror_printf("IP string contains trailing garbage after port delimiter");
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
 * @param[out] out Where to write the resulting IP string.
 * @param[in] outlen of output buffer.
 * @param[in] addr to convert to presentation format.
 * @return
 *	- NULL on error (use fr_syserror(errno)).
 *	- a pointer to out on success.
 */
char *fr_inet_ntop(char *out, size_t outlen, fr_ipaddr_t *addr)
{
	if (inet_ntop(addr->af, &addr->ipaddr, out, outlen) == NULL) return NULL;

	return out;
}

/** Print a #fr_ipaddr_t as a CIDR style network prefix
 *
 * @param[out] out Where to write the resulting prefix string.
 * @param[in] outlen of output buffer.
 * @param[in] addr to convert to presentation format.
 * @return
 *	- NULL on error (use fr_syserror(errno)).
 *	- a pointer to out on success.
 */
char *fr_inet_ntop_prefix(char *out, size_t outlen, fr_ipaddr_t *addr)
{
	char buffer[INET6_ADDRSTRLEN];

	if (inet_ntop(addr->af, &(addr->ipaddr), buffer, sizeof(buffer)) == NULL) return NULL;

	snprintf(out, outlen, "%s/%i", buffer, addr->prefix);

	return out;
}

/** Print an interface-id in standard colon notation
 *
 * @param[out] out Where to write the resulting interface-id string.
 * @param[in] outlen of output buffer.
 * @return a pointer to out.
 */
char *fr_inet_ifid_ntop(char *out, size_t outlen, uint8_t const *ifid)
{
	snprintf(out, outlen, "%x:%x:%x:%x",
		 (ifid[0] << 8) + ifid[1], (ifid[2] << 8) + ifid[3],
		 (ifid[4] << 8) + ifid[5], (ifid[6] << 8) + ifid[7]);
	return out;
}

/** Convert interface-id in colon notation to 8 byte binary form
 *
 * @param[out] out Where to write the binary interface-id.
 * @param[in] ifid_str to parse.
 * @return a pointer to out.
 */
uint8_t *fr_inet_ifid_pton(uint8_t out[8], char const *ifid_str)
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
/** Resolve an interface to an ipaddress
 *
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
	if (fr_ipaddr_from_sockaddr((struct sockaddr_storage *)&if_req.ifr_addr,
			       sizeof(if_req.ifr_addr), &ipaddr, NULL) == 0) goto error;
	*out = ipaddr;

	close(fd);

	return 0;
}
#else
int fr_ipaddr_from_ifname(UNUSED fr_ipaddr_t *out, UNUSED int af, UNUSED char const *name)
{
	fr_strerror_printf("No support for SIOCGIFADDR, can't determine IP address of %s", name);
	return -1;
}
#endif

#ifdef WITH_IFINDEX_RESOLUTION
/** Resolve if_index to interface name
 *
 * @param[out] out Buffer to use to store the name, must be at least IFNAMSIZ bytes.
 * @parma[in] if_index to resolve to name.
 * @return
 *	- NULL on error.
 *	- a pointer to out on success.
 */
char *fr_ifname_from_ifindex(char out[IFNAMSIZ], int if_index)
{
#ifdef HAVE_IF_INDEXTONAME
	if (!if_indextoname(if_index, out)) {
		fr_strerror_printf("Failed resolving interface index %i to name", if_index);
		return NULL;
	}
#else
	struct ifreq	if_req;
	int		fd;

	memset(&if_req, 0, sizeof(if_req));
	if_req.ifr_ifindex = if_index;

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
		fr_strerror_printf("Failed resolving interface index %i to name: %s", if_index, fr_syserror(errno));
		goto error;
	}
	strlcpy(out, if_req.ifr_name, IFNAMSIZ);
	close(fd);
#endif
	return out;
}

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
 * @param[in] if_index of interface to get IP address for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ipaddr_from_ifindex(fr_ipaddr_t *out, int fd, int af, int if_index)
{
	struct ifreq		if_req;
	fr_ipaddr_t		ipaddr;

	memset(&if_req, 0, sizeof(if_req));
	memset(out, 0, sizeof(*out));

#ifdef SIOCGIFNAME
	if_req.ifr_ifindex = if_index;
	/*
	 *	First we resolve the interface index to the interface name
	 *	Which is pretty inefficient, but it seems the only way to
	 *	identify interfaces for SIOCG* operations is with the interface
	 *	name.
	 */
	if (ioctl(fd, SIOCGIFNAME, &if_req) < 0) {
		fr_strerror_printf("Failed resolving interface index %i to name: %s", if_index, fr_syserror(errno));
		return -1;
	}
#else
	if (!if_indextoname(if_index, if_req.ifr_name)) {
		fr_strerror_printf("Failed resolving interface index %i to name", if_index);
		return -1;
	}
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
	if (fr_ipaddr_from_sockaddr((struct sockaddr_storage *)&if_req.ifr_addr,
			       sizeof(if_req.ifr_addr), &ipaddr, NULL) == 0) return -1;
	*out = ipaddr;

	return 0;
}
#endif

/** Compare two ip addresses
 *
 */
int fr_ipaddr_cmp(fr_ipaddr_t const *a, fr_ipaddr_t const *b)
{
	if (a->af < b->af) return -1;
	if (a->af > b->af) return +1;

	if (a->prefix < b->prefix) return -1;
	if (a->prefix > b->prefix) return +1;

	switch (a->af) {
	case AF_INET:
		return memcmp(&a->ipaddr.ip4addr,
			      &b->ipaddr.ip4addr,
			      sizeof(a->ipaddr.ip4addr));

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	case AF_INET6:
		if (a->scope < b->scope) return -1;
		if (a->scope > b->scope) return +1;

		return memcmp(&a->ipaddr.ip6addr,
			      &b->ipaddr.ip6addr,
			      sizeof(a->ipaddr.ip6addr));
#endif

	default:
		break;
	}

	return -1;
}

int fr_ipaddr_to_sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port,
		          struct sockaddr_storage *sa, socklen_t *salen)
{
	memset(sa, 0, sizeof(*sa));

	if (ipaddr->af == AF_INET) {
		struct sockaddr_in s4;

		*salen = sizeof(s4);

		memset(&s4, 0, sizeof(s4));
		s4.sin_family = AF_INET;
		s4.sin_addr = ipaddr->ipaddr.ip4addr;
		s4.sin_port = htons(port);
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s4, sizeof(s4));

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		struct sockaddr_in6 s6;

		*salen = sizeof(s6);

		memset(&s6, 0, sizeof(s6));
		s6.sin6_family = AF_INET6;
		s6.sin6_addr = ipaddr->ipaddr.ip6addr;
		s6.sin6_port = htons(port);
		s6.sin6_scope_id = ipaddr->scope;
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s6, sizeof(s6));
#endif
	} else {
		return 0;
	}

	return 1;
}

int fr_ipaddr_from_sockaddr(struct sockaddr_storage const *sa, socklen_t salen,
			    fr_ipaddr_t *ipaddr, uint16_t *port)
{
	memset(ipaddr, 0, sizeof(*ipaddr));

	if (sa->ss_family == AF_INET) {
		struct sockaddr_in	s4;

		if (salen < sizeof(s4)) {
			fr_strerror_printf("IPv4 address is too small");
			return 0;
		}

		memcpy(&s4, sa, sizeof(s4));
		ipaddr->af = AF_INET;
		ipaddr->prefix = 32;
		ipaddr->ipaddr.ip4addr = s4.sin_addr;
		if (port) *port = ntohs(s4.sin_port);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (sa->ss_family == AF_INET6) {
		struct sockaddr_in6	s6;

		if (salen < sizeof(s6)) {
			fr_strerror_printf("IPv6 address is too small");
			return 0;
		}

		memcpy(&s6, sa, sizeof(s6));
		ipaddr->af = AF_INET6;
		ipaddr->prefix = 128;
		ipaddr->ipaddr.ip6addr = s6.sin6_addr;
		if (port) *port = ntohs(s6.sin6_port);
		ipaddr->scope = s6.sin6_scope_id;
#endif

	} else {
		fr_strerror_printf("Unsupported address famility %d",
				   sa->ss_family);
		return 0;
	}

	return 1;
}
