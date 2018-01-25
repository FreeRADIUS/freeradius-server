/*
 * value.c	Functions to handle value_data_t
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2014 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <ctype.h>

/** Compare two values
 *
 * @param[in] a_type of data to compare.
 * @param[in] a_len of data to compare.
 * @param[in] a Value to compare.
 * @param[in] b_type of data to compare.
 * @param[in] b_len of data to compare.
 * @param[in] b Value to compare.
 * @return -1 if a is less than b, 0 if both are equal, 1 if a is more than b, < -1 on error.
 */
int value_data_cmp(PW_TYPE a_type, value_data_t const *a, size_t a_len,
		   PW_TYPE b_type, value_data_t const *b, size_t b_len)
{
	int compare = 0;

	if (a_type != b_type) {
		fr_strerror_printf("Can't compare values of different types");
		return -2;
	}

	/*
	 *	After doing the previous check for special comparisons,
	 *	do the per-type comparison here.
	 */
	switch (a_type) {
	case PW_TYPE_ABINARY:
	case PW_TYPE_OCTETS:
	case PW_TYPE_STRING:	/* We use memcmp to be \0 safe */
	{
		size_t length;

		if (a_len < b_len) {
			length = a_len;
		} else {
			length = b_len;
		}

		if (length) {
			compare = memcmp(a->octets, b->octets, length);
			if (compare != 0) break;
		}

		/*
		 *	Contents are the same.  The return code
		 *	is therefore the difference in lengths.
		 *
		 *	i.e. "0x00" is smaller than "0x0000"
		 */
		compare = a_len - b_len;
	}
		break;

		/*
		 *	Short-hand for simplicity.
		 */
#define CHECK(_type) if (a->_type < b->_type)   { compare = -1; \
		} else if (a->_type > b->_type) { compare = +1; }

	case PW_TYPE_BOOLEAN:	/* this isn't a RADIUS type, and shouldn't really ever be used */
	case PW_TYPE_BYTE:
		CHECK(byte);
		break;


	case PW_TYPE_SHORT:
		CHECK(ushort);
		break;

	case PW_TYPE_DATE:
		CHECK(date);
		break;

	case PW_TYPE_INTEGER:
		CHECK(integer);
		break;

	case PW_TYPE_SIGNED:
		CHECK(sinteger);
		break;

	case PW_TYPE_INTEGER64:
		CHECK(integer64);
		break;

	case PW_TYPE_ETHERNET:
		compare = memcmp(a->ether, b->ether, sizeof(a->ether));
		break;

	case PW_TYPE_IPV4_ADDR: {
			uint32_t a_int, b_int;

			a_int = ntohl(a->ipaddr.s_addr);
			b_int = ntohl(b->ipaddr.s_addr);
			if (a_int < b_int) {
				compare = -1;
			} else if (a_int > b_int) {
				compare = +1;
			}
		}
		break;

	case PW_TYPE_IPV6_ADDR:
		compare = memcmp(&a->ipv6addr, &b->ipv6addr, sizeof(a->ipv6addr));
		break;

	case PW_TYPE_IPV6_PREFIX:
		compare = memcmp(a->ipv6prefix, b->ipv6prefix, sizeof(a->ipv6prefix));
		break;

	case PW_TYPE_IPV4_PREFIX:
		compare = memcmp(a->ipv4prefix, b->ipv4prefix, sizeof(a->ipv4prefix));
		break;

	case PW_TYPE_IFID:
		compare = memcmp(a->ifid, b->ifid, sizeof(a->ifid));
		break;

	/*
	 *	Na of the types below should be in the REQUEST
	 */
	case PW_TYPE_INVALID:		/* We should never see these */
	case PW_TYPE_COMBO_IP_ADDR:		/* This should have been converted into IPADDR/IPV6ADDR */
	case PW_TYPE_COMBO_IP_PREFIX:		/* This should have been converted into IPADDR/IPV6ADDR */
	case PW_TYPE_TLV:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
	case PW_TYPE_EVS:
	case PW_TYPE_VSA:
	case PW_TYPE_TIMEVAL:
	case PW_TYPE_MAX:
		fr_assert(0);	/* unknown type */
		return -2;

	/*
	 *	Do NOT add a default here, as new types are added
	 *	static analysis will warn us they're not handled
	 */
	}

	if (compare > 0) {
		return 1;
	} else if (compare < 0) {
		return -1;
	}
	return 0;
}

/*
 *	We leverage the fact that IPv4 and IPv6 prefixes both
 *	have the same format:
 *
 *	reserved, prefix-len, data...
 */
static int value_data_cidr_cmp_op(FR_TOKEN op, int bytes,
				  uint8_t a_net, uint8_t const *a,
				  uint8_t b_net, uint8_t const *b)
{
	int i, common;
	uint32_t mask;

	/*
	 *	Handle the case of netmasks being identical.
	 */
	if (a_net == b_net) {
		int compare;

		compare = memcmp(a, b, bytes);

		/*
		 *	If they're identical return true for
		 *	identical.
		 */
		if ((compare == 0) &&
		    ((op == T_OP_CMP_EQ) ||
		     (op == T_OP_LE) ||
		     (op == T_OP_GE))) {
			return true;
		}

		/*
		 *	Everything else returns false.
		 *
		 *	10/8 == 24/8  --> false
		 *	10/8 <= 24/8  --> false
		 *	10/8 >= 24/8  --> false
		 */
		return false;
	}

	/*
	 *	Netmasks are different.  That limits the
	 *	possible results, based on the operator.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return false;

	case T_OP_NE:
		return true;

	case T_OP_LE:
	case T_OP_LT:	/* 192/8 < 192.168/16 --> false */
		if (a_net < b_net) {
			return false;
		}
		break;

	case T_OP_GE:
	case T_OP_GT:	/* 192/16 > 192.168/8 --> false */
		if (a_net > b_net) {
			return false;
		}
		break;

	default:
		return false;
	}

	if (a_net < b_net) {
		common = a_net;
	} else {
		common = b_net;
	}

	/*
	 *	Do the check byte by byte.  If the bytes are
	 *	identical, it MAY be a match.  If they're different,
	 *	it is NOT a match.
	 */
	i = 0;
	while (i < bytes) {
		/*
		 *	All leading bytes are identical.
		 */
		if (common == 0) return true;

		/*
		 *	Doing bitmasks takes more work.
		 */
		if (common < 8) break;

		if (a[i] != b[i]) return false;

		common -= 8;
		i++;
		continue;
	}

	mask = 1;
	mask <<= (8 - common);
	mask--;
	mask = ~mask;

	if ((a[i] & mask) == ((b[i] & mask))) {
		return true;
	}

	return false;
}

/** Compare two attributes using an operator
 *
 * @param[in] op to use in comparison.
 * @param[in] a_type of data to compare.
 * @param[in] a_len of data to compare.
 * @param[in] a Value to compare.
 * @param[in] b_type of data to compare.
 * @param[in] b_len of data to compare.
 * @param[in] b Value to compare.
 * @return 1 if true, 0 if false, -1 on error.
 */
int value_data_cmp_op(FR_TOKEN op,
		      PW_TYPE a_type, value_data_t const *a, size_t a_len,
		      PW_TYPE b_type, value_data_t const *b, size_t b_len)
{
	int compare = 0;

	if (!a || !b) return -1;

	switch (a_type) {
	case PW_TYPE_IPV4_ADDR:
		switch (b_type) {
		case PW_TYPE_IPV4_ADDR:		/* IPv4 and IPv4 */
			goto cmp;

		case PW_TYPE_IPV4_PREFIX:	/* IPv4 and IPv4 Prefix */
			return value_data_cidr_cmp_op(op, 4, 32, (uint8_t const *) &a->ipaddr,
						      b->ipv4prefix[1], (uint8_t const *) &b->ipv4prefix[2]);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}

	case PW_TYPE_IPV4_PREFIX:		/* IPv4 and IPv4 Prefix */
		switch (b_type) {
		case PW_TYPE_IPV4_ADDR:
			return value_data_cidr_cmp_op(op, 4, a->ipv4prefix[1],
						    (uint8_t const *) &a->ipv4prefix[2],
						    32, (uint8_t const *) &b->ipaddr);

		case PW_TYPE_IPV4_PREFIX:	/* IPv4 Prefix and IPv4 Prefix */
			return value_data_cidr_cmp_op(op, 4, a->ipv4prefix[1],
						    (uint8_t const *) &a->ipv4prefix[2],
						    b->ipv4prefix[1], (uint8_t const *) &b->ipv4prefix[2]);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}

	case PW_TYPE_IPV6_ADDR:
		switch (b_type) {
		case PW_TYPE_IPV6_ADDR:		/* IPv6 and IPv6 */
			goto cmp;

		case PW_TYPE_IPV6_PREFIX:	/* IPv6 and IPv6 Preifx */
			return value_data_cidr_cmp_op(op, 16, 128, (uint8_t const *) &a->ipv6addr,
						      b->ipv6prefix[1], (uint8_t const *) &b->ipv6prefix[2]);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}

	case PW_TYPE_IPV6_PREFIX:
		switch (b_type) {
		case PW_TYPE_IPV6_ADDR:		/* IPv6 Prefix and IPv6 */
			return value_data_cidr_cmp_op(op, 16, a->ipv6prefix[1],
						      (uint8_t const *) &a->ipv6prefix[2],
						      128, (uint8_t const *) &b->ipv6addr);

		case PW_TYPE_IPV6_PREFIX:	/* IPv6 Prefix and IPv6 */
			return value_data_cidr_cmp_op(op, 16, a->ipv6prefix[1],
						      (uint8_t const *) &a->ipv6prefix[2],
						      b->ipv6prefix[1], (uint8_t const *) &b->ipv6prefix[2]);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}

	default:
	cmp:
		compare = value_data_cmp(a_type, a, a_len,
					 b_type, b, b_len);
		if (compare < -1) {	/* comparison error */
			return -1;
		}
	}

	/*
	 *	Now do the operator comparison.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return (compare == 0);

	case T_OP_NE:
		return (compare != 0);

	case T_OP_LT:
		return (compare < 0);

	case T_OP_GT:
		return (compare > 0);

	case T_OP_LE:
		return (compare <= 0);

	case T_OP_GE:
		return (compare >= 0);

	default:
		return 0;
	}
}

static char const hextab[] = "0123456789abcdef";

/** Convert string value to a value_data_t type
 *
 * @param[in] ctx to alloc strings in.
 * @param[out] dst where to write parsed value.
 * @param[in,out] src_type of value data to create/type of value created.
 * @param[in] src_enumv DICT_ATTR with string aliases for integer values.
 * @param[in] src String to convert. Binary safe for variable length values if len is provided.
 * @param[in] src_len may be < 0 in which case strlen(len) is used to determine length, else src_len
 *	  should be the length of the string or sub string to parse.
 * @param[in] quote quotation character used to drive de-escaping
 * @return length of data written to out or -1 on parse error.
 */
ssize_t value_data_from_str(TALLOC_CTX *ctx, value_data_t *dst,
			    PW_TYPE *src_type, DICT_ATTR const *src_enumv,
			    char const *src, ssize_t src_len, char quote)
{
	DICT_VALUE	*dval;
	size_t		len;
	ssize_t		ret;
	char		buffer[256];

	if (!src) return -1;

	len = (src_len < 0) ? strlen(src) : (size_t)src_len;

	/*
	 *	Set size for all fixed length attributes.
	 */
	ret = dict_attr_sizes[*src_type][1];	/* Max length */

	/*
	 *	It's a variable ret src_type so we just alloc a new buffer
	 *	of size len and copy.
	 */
	switch (*src_type) {
	case PW_TYPE_STRING:
	{
		char		*p, *buff;
		char const	*q;
		int		x;

		buff = p = talloc_bstrndup(ctx, src, len);

		/*
		 *	No de-quoting.  Just copy the string.
		 */
		if (!quote) {
			ret = len;
			dst->strvalue = buff;
			goto finish;
		}

		/*
		 *	Do escaping for single quoted strings.  Only
		 *	single quotes get escaped.  Everything else is
		 *	left as-is.
		 */
		if (quote == '\'') {
			q = p;

			while (q < (buff + len)) {
				/*
				 *	The quotation character is escaped.
				 */
				if ((q[0] == '\\') &&
				    (q[1] == quote)) {
					*(p++) = quote;
					q += 2;
					continue;
				}

				/*
				 *	Two backslashes get mangled to one.
				 */
				if ((q[0] == '\\') &&
				    (q[1] == '\\')) {
					*(p++) = '\\';
					q += 2;
					continue;
				}

				/*
				 *	Not escaped, just copy it over.
				 */
				*(p++) = *(q++);
			}

			*p = '\0';
			ret = p - buff;

			/* Shrink the buffer to the correct size */
			dst->strvalue = talloc_realloc(ctx, buff, char, ret + 1);
			goto finish;
		}

		/*
		 *	It's "string" or `string`, do all standard
		 *	escaping.
		 */
		q = p;
		while (q < (buff + len)) {
			char c = *q++;

			if ((c == '\\') && (q >= (buff + len))) {
				fr_strerror_printf("Invalid escape at end of string");
				talloc_free(buff);
				return -1;
			}

			/*
			 *	Fix up \X -> ... the binary form of it.
			 */
			if (c == '\\') {
				switch (*q) {
				case 'r':
					c = '\r';
					q++;
					break;

				case 'n':
					c = '\n';
					q++;
					break;

				case 't':
					c = '\t';
					q++;
					break;

				case '\\':
					c = '\\';
					q++;
					break;

				default:
					/*
					 *	\" --> ", but only inside of double quoted strings, etc.
					 */
					if (*q == quote) {
						c = quote;
						q++;
						break;
					}

					/*
					 *	\000 --> binary zero character
					 */
					if ((q[0] >= '0') &&
					    (q[0] <= '9') &&
					    (q[1] >= '0') &&
					    (q[1] <= '9') &&
					    (q[2] >= '0') &&
					    (q[2] <= '9') &&
					    (sscanf(q, "%3o", &x) == 1)) {
						c = x;
						q += 3;
					}

					/*
					 *	Else It's not a recognised escape sequence DON'T
					 *	consume the backslash. This is identical
					 *	behaviour to bash and most other things that
					 *	use backslash escaping.
					 */
				}
			}

			*p++ = c;
		}

		*p = '\0';
		ret = p - buff;
		dst->strvalue = talloc_realloc(ctx, buff, char, ret + 1);
	}
		goto finish;

	case PW_TYPE_VSA:
		fr_strerror_printf("Must use 'Attr-26 = ...' instead of 'Vendor-Specific = ...'");
		return -1;

	/* raw octets: 0x01020304... */
#ifndef WITH_ASCEND_BINARY
	do_octets:
#endif
	case PW_TYPE_OCTETS:
	{
		uint8_t	*p;

		/*
		 *	No 0x prefix, just copy verbatim.
		 */
		if ((len < 2) || (strncasecmp(src, "0x", 2) != 0)) {
			dst->octets = talloc_memdup(ctx, (uint8_t const *)src, len);
			talloc_set_type(dst->octets, uint8_t);
			ret = len;
			goto finish;
		}

		len -= 2;

		/*
		 *	Invalid.
		 */
		if ((len & 0x01) != 0) {
			fr_strerror_printf("Length of Hex String is not even, got %zu bytes", len);
			return -1;
		}

		ret = len >> 1;
		p = talloc_array(ctx, uint8_t, ret);
		if (fr_hex2bin(p, ret, src + 2, len) != (size_t)ret) {
			talloc_free(p);
			fr_strerror_printf("Invalid hex data");
			return -1;
		}

		dst->octets = p;
	}
		goto finish;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		if ((len > 1) && (strncasecmp(src, "0x", 2) == 0)) {
			ssize_t bin;

			if (len > ((sizeof(dst->filter) + 1) * 2)) {
				fr_strerror_printf("Hex data is too large for ascend filter");
				return -1;
			}

			bin = fr_hex2bin((uint8_t *) &dst->filter, ret, src + 2, len - 2);
			if (bin < ret) {
				memset(((uint8_t *) &dst->filter) + bin, 0, ret - bin);
			}
		} else {
			if (ascend_parse_filter(dst, src, len) < 0 ) {
				/* Allow ascend_parse_filter's strerror to bubble up */
				return -1;
			}
		}

		ret = sizeof(dst->filter);
		goto finish;
#else
		/*
		 *	If Ascend binary is NOT defined,
		 *	then fall through to raw octets, so that
		 *	the user can at least make them by hand...
		 */
	 	goto do_octets;
#endif

	/* don't use this! */
	case PW_TYPE_TLV:
		fr_strerror_printf("Cannot parse TLV");
		return -1;

	case PW_TYPE_IPV4_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_pton4(&addr, src, src_len, fr_hostname_lookups, false) < 0) return -1;

		/*
		 *	We allow v4 addresses to have a /32 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 32) {
			fr_strerror_printf("Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		dst->ipaddr.s_addr = addr.ipaddr.ip4addr.s_addr;
	}
		goto finish;

	case PW_TYPE_IPV4_PREFIX:
	{
		fr_ipaddr_t addr;

		if (fr_pton4(&addr, src, src_len, fr_hostname_lookups, false) < 0) return -1;

		dst->ipv4prefix[1] = addr.prefix;
		memcpy(&dst->ipv4prefix[2], &addr.ipaddr.ip4addr.s_addr, sizeof(dst->ipv4prefix) - 2);
	}
		goto finish;

	case PW_TYPE_IPV6_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_pton6(&addr, src, src_len, fr_hostname_lookups, false) < 0) return -1;

		/*
		 *	We allow v6 addresses to have a /128 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 128) {
			fr_strerror_printf("Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		memcpy(&dst->ipv6addr, addr.ipaddr.ip6addr.s6_addr, sizeof(dst->ipv6addr));
	}
		goto finish;

	case PW_TYPE_IPV6_PREFIX:
	{
		fr_ipaddr_t addr;

		if (fr_pton6(&addr, src, src_len, fr_hostname_lookups, false) < 0) return -1;

		dst->ipv6prefix[1] = addr.prefix;
		memcpy(&dst->ipv6prefix[2], addr.ipaddr.ip6addr.s6_addr, sizeof(dst->ipv6prefix) - 2);
	}
		goto finish;

	default:
		break;
	}

	/*
	 *	It's a fixed size src_type, copy to a temporary buffer and
	 *	\0 terminate if insize >= 0.
	 */
	if (src_len > 0) {
		if (len >= sizeof(buffer)) {
			fr_strerror_printf("Temporary buffer too small");
			return -1;
		}

		memcpy(buffer, src, src_len);
		buffer[src_len] = '\0';
		src = buffer;
	}

	switch (*src_type) {
	case PW_TYPE_BYTE:
	{
		char *p;
		unsigned int i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		i = fr_strtoul(src, &p);

		/*
		 *	Look for the named src for the given
		 *	attribute.
		 */
		if (src_enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(src_enumv->attr, src_enumv->vendor, src)) == NULL) {
				fr_strerror_printf("Unknown or invalid value \"%s\" for attribute %s",
						   src, src_enumv->name);
				return -1;
			}

			dst->byte = dval->value;
		} else {
			if (i > 255) {
				fr_strerror_printf("Byte value \"%s\" is larger than 255", src);
				return -1;
			}

			dst->byte = i;
		}
		break;
	}

	case PW_TYPE_SHORT:
	{
		char *p;
		unsigned int i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		i = fr_strtoul(src, &p);

		/*
		 *	Look for the named src for the given
		 *	attribute.
		 */
		if (src_enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(src_enumv->attr, src_enumv->vendor, src)) == NULL) {
				fr_strerror_printf("Unknown or invalid value \"%s\" for attribute %s",
						   src, src_enumv->name);
				return -1;
			}

			dst->ushort = dval->value;
		} else {
			if (i > 65535) {
				fr_strerror_printf("Short value \"%s\" is larger than 65535", src);
				return -1;
			}

			dst->ushort = i;
		}
		break;
	}

	case PW_TYPE_INTEGER:
	{
		char *p;
		unsigned int i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		i = fr_strtoul(src, &p);

		/*
		 *	Look for the named src for the given
		 *	attribute.
		 */
		if (src_enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(src_enumv->attr, src_enumv->vendor, src)) == NULL) {
				fr_strerror_printf("Unknown or invalid value \"%s\" for attribute %s",
						   src, src_enumv->name);
				return -1;
			}

			dst->integer = dval->value;
		} else {
			/*
			 *	Value is always within the limits
			 */
			dst->integer = i;
		}
	}
		break;

	case PW_TYPE_INTEGER64:
	{
		uint64_t i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		if (sscanf(src, "%" PRIu64, &i) != 1) {
			fr_strerror_printf("Failed parsing \"%s\" as unsigned 64bit integer", src);
			return -1;
		}
		dst->integer64 = i;
	}
		break;

	case PW_TYPE_DATE:
	{
		/*
		 *	time_t may be 64 bits, whule vp_date MUST be 32-bits.  We need an
		 *	intermediary variable to handle the conversions.
		 */
		time_t date;

		if (fr_get_time(src, &date) < 0) {
			fr_strerror_printf("failed to parse time string \"%s\"", src);
			return -1;
		}

		dst->date = date;
	}

		break;

	case PW_TYPE_IFID:
		if (ifid_aton(src, (void *) dst->ifid) == NULL) {
			fr_strerror_printf("Failed to parse interface-id string \"%s\"", src);
			return -1;
		}
		break;

	case PW_TYPE_ETHERNET:
	{
		char const *c1, *c2, *cp;
		size_t p_len = 0;

		/*
		 *	Convert things which are obviously integers to Ethernet addresses
		 *
		 *	We assume the number is the bigendian representation of the
		 *	ethernet address.
		 */
		if (is_integer(src)) {
			uint64_t integer = htonll(atoll(src));

			memcpy(dst->ether, &integer, sizeof(dst->ether));
			break;
		}

		cp = src;
		while (*cp) {
			if (cp[1] == ':') {
				c1 = hextab;
				c2 = memchr(hextab, tolower((int) cp[0]), 16);
				cp += 2;
			} else if ((cp[1] != '\0') && ((cp[2] == ':') || (cp[2] == '\0'))) {
				c1 = memchr(hextab, tolower((int) cp[0]), 16);
				c2 = memchr(hextab, tolower((int) cp[1]), 16);
				cp += 2;
				if (*cp == ':') cp++;
			} else {
				c1 = c2 = NULL;
			}
			if (!c1 || !c2 || (p_len >= sizeof(dst->ether))) {
				fr_strerror_printf("failed to parse Ethernet address \"%s\"", src);
				return -1;
			}
			dst->ether[p_len] = ((c1-hextab)<<4) + (c2-hextab);
			p_len++;
		}
	}
		break;

	/*
	 *	Crazy polymorphic (IPv4/IPv6) attribute src_type for WiMAX.
	 *
	 *	We try and make is saner by replacing the original
	 *	da, with either an IPv4 or IPv6 da src_type.
	 *
	 *	These are not dynamic da, and will have the same vendor
	 *	and attribute as the original.
	 */
	case PW_TYPE_COMBO_IP_ADDR:
	{
		if (inet_pton(AF_INET6, src, &dst->ipv6addr) > 0) {
			*src_type = PW_TYPE_IPV6_ADDR;
			ret = dict_attr_sizes[PW_TYPE_COMBO_IP_ADDR][1]; /* size of IPv6 address */
		} else {
			fr_ipaddr_t ipaddr;

			if (ip_hton(&ipaddr, AF_INET, src, false) < 0) {
				fr_strerror_printf("Failed to find IPv4 address for %s", src);
				return -1;
			}

			*src_type = PW_TYPE_IPV4_ADDR;
			dst->ipaddr.s_addr = ipaddr.ipaddr.ip4addr.s_addr;
			ret = dict_attr_sizes[PW_TYPE_COMBO_IP_ADDR][0]; /* size of IPv4 address */
		}
	}
		break;

	case PW_TYPE_SIGNED:
		/* Damned code for 1 WiMAX attribute */
		dst->sinteger = (int32_t)strtol(src, NULL, 10);
		break;

	/*
	 *  Anything else.
	 */
	default:
		fr_strerror_printf("Unknown attribute type %d", *src_type);
		return -1;
	}

finish:
	return ret;
}

/** Performs byte order reversal for types that need it
 *
 */
static void value_data_hton(value_data_t *dst, PW_TYPE type, void const *src, size_t src_len)
{
	/* 8 byte integers */
	switch (type) {
	case PW_TYPE_INTEGER64:
		dst->integer64 = htonll(*(uint64_t const *)src);
		break;

	/* 4 byte integers */
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE:
	case PW_TYPE_SIGNED:
		dst->integer = htonl(*(uint32_t const *)src);
		break;

	/* 2 byte integers */
	case PW_TYPE_SHORT:
		dst->ushort = htons(*(uint16_t const *)src);
		break;

	case PW_TYPE_OCTETS:
	case PW_TYPE_STRING:
		fr_assert(0);
		return;		/* shouldn't happen */

	default:
		memcpy(dst, src, src_len);
	}
}

/** Convert one type of value_data_t to another
 *
 * @note This should be the canonical function used to convert between data types.
 *
 * @param ctx to allocate buffers in (usually the same as dst)
 * @param dst Where to write result of casting.
 * @param dst_type to cast to.
 * @param dst_enumv Enumerated values used to converts strings to integers.
 * @param src_type to cast from.
 * @param src_enumv Enumerated values used to convert integers to strings.
 * @param src Input data.
 * @param src_len Input data len.
 * @return the length of data in the dst or -1 on error.
 */
ssize_t value_data_cast(TALLOC_CTX *ctx, value_data_t *dst,
			PW_TYPE dst_type, DICT_ATTR const *dst_enumv,
			PW_TYPE src_type, DICT_ATTR const *src_enumv,
			value_data_t const *src, size_t src_len)
{
	if (!fr_assert(dst_type != src_type)) return -1;

	/*
	 *	Deserialise a value_data_t
	 */
	if (src_type == PW_TYPE_STRING) {
		return value_data_from_str(ctx, dst, &dst_type, dst_enumv, src->strvalue, src_len, '\0');
	}

	/*
	 *	Converts the src data to octets with no processing.
	 */
	if (dst_type == PW_TYPE_OCTETS) {
		value_data_hton(dst, src_type, src, src_len);
		dst->octets = talloc_memdup(ctx, dst, src_len);
		talloc_set_type(dst->octets, uint8_t);
		return talloc_array_length(dst->strvalue);
	}

	/*
	 *	Serialise a value_data_t
	 */
	if (dst_type == PW_TYPE_STRING) {
		dst->strvalue = value_data_aprints(ctx, src_type, src_enumv, src, src_len, '\0');
		return talloc_array_length(dst->strvalue) - 1;
	}

	if ((src_type == PW_TYPE_IFID) &&
	    (dst_type == PW_TYPE_INTEGER64)) {
		memcpy(&dst->integer64, src->ifid, sizeof(src->ifid));
		dst->integer64 = htonll(dst->integer64);
	fixed_length:
		return dict_attr_sizes[dst_type][0];
	}

	if ((src_type == PW_TYPE_INTEGER64) &&
	    (dst_type == PW_TYPE_ETHERNET)) {
		uint8_t array[8];
		uint64_t i;

		i = htonll(src->integer64);
		memcpy(array, &i, 8);

		/*
		 *	For OUIs in the DB.
		 */
		if ((array[0] != 0) || (array[1] != 0)) return -1;

		memcpy(dst->ether, &array[2], 6);
		goto fixed_length;
	}

	/*
	 *	For integers, we allow the casting of a SMALL type to
	 *	a larger type, but not vice-versa.
	 */
	if (dst_type == PW_TYPE_INTEGER64) {
		switch (src_type) {
		case PW_TYPE_BYTE:
			dst->integer64 = src->byte;
			break;

		case PW_TYPE_SHORT:
			dst->integer64 = src->ushort;
			break;

		case PW_TYPE_INTEGER:
			dst->integer64 = src->integer;
			break;

		case PW_TYPE_DATE:
			dst->integer64 = src->date;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
		invalid_cast:
			fr_strerror_printf("Invalid cast from %s to %s",
					   fr_int2str(dict_attr_types, src_type, "<INVALID>"),
					   fr_int2str(dict_attr_types, dst_type, "<INVALID>"));
			return -1;

		}
		goto fixed_length;
	}

	/*
	 *	We can cast LONG integers to SHORTER ones, so long
	 *	as the long one is on the LHS.
	 */
	if (dst_type == PW_TYPE_INTEGER) {
		switch (src_type) {
		case PW_TYPE_BYTE:
			dst->integer = src->byte;
			break;

		case PW_TYPE_SHORT:
			dst->integer = src->ushort;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			goto invalid_cast;
		}
		goto fixed_length;
	}

	if (dst_type == PW_TYPE_SHORT) {
		switch (src_type) {
		case PW_TYPE_BYTE:
			dst->ushort = src->byte;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			goto invalid_cast;
		}
		goto fixed_length;
	}

	/*
	 *	We can cast integers less that < INT_MAX to signed
	 */
	if (dst_type == PW_TYPE_SIGNED) {
		switch (src_type) {
		case PW_TYPE_BYTE:
			dst->sinteger = src->byte;
			break;

		case PW_TYPE_SHORT:
			dst->sinteger = src->ushort;
			break;

		case PW_TYPE_INTEGER:
			if (src->integer > INT_MAX) {
				fr_strerror_printf("Invalid cast: From integer to signed.  integer value %u is larger "
						   "than max signed int and would overflow", src->integer);
				return -1;
			}
			dst->sinteger = (int)src->integer;
			break;

		case PW_TYPE_INTEGER64:
			if (src->integer > INT_MAX) {
				fr_strerror_printf("Invalid cast: From integer64 to signed.  integer64 value %" PRIu64
						   " is larger than max signed int and would overflow", src->integer64);
				return -1;
			}
			dst->sinteger = (int)src->integer64;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			goto invalid_cast;
		}
		goto fixed_length;
	}
	/*
	 *	Conversions between IPv4 addresses, IPv6 addresses, IPv4 prefixes and IPv6 prefixes
	 *
	 *	For prefix to ipaddress conversions, we assume that the host portion has already
	 *	been zeroed out.
	 *
	 *	We allow casts from v6 to v4 if the v6 address has the correct mapping prefix.
	 *
	 *	We only allow casts from prefixes to addresses if the prefix is the the length of
	 *	the address, e.g. 32 for ipv4 128 for ipv6.
	 */
	{
		/*
		 *	10 bytes of 0x00 2 bytes of 0xff
		 */
		static uint8_t const v4_v6_map[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						     0x00, 0x00, 0x00, 0x00, 0xff, 0xff };

		switch (dst_type) {
		case PW_TYPE_IPV4_ADDR:
			switch (src_type) {
			case PW_TYPE_IPV6_ADDR:
				if (memcmp(src->ipv6addr.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) {
				bad_v6_prefix_map:
					fr_strerror_printf("Invalid cast from %s to %s.  No IPv4-IPv6 mapping prefix",
							   fr_int2str(dict_attr_types, src_type, "<INVALID>"),
							   fr_int2str(dict_attr_types, dst_type, "<INVALID>"));
					return -1;
				}

				memcpy(&dst->ipaddr, &src->ipv6addr.s6_addr[sizeof(v4_v6_map)],
				       sizeof(dst->ipaddr));
				goto fixed_length;

			case PW_TYPE_IPV4_PREFIX:
				if (src->ipv4prefix[1] != 32) {
				bad_v4_prefix_len:
					fr_strerror_printf("Invalid cast from %s to %s.  Only /32 prefixes may be "
							   "cast to IP address types",
							   fr_int2str(dict_attr_types, src_type, "<INVALID>"),
							   fr_int2str(dict_attr_types, dst_type, "<INVALID>"));
					return -1;
				}

				memcpy(&dst->ipaddr, &src->ipv4prefix[2], sizeof(dst->ipaddr));
				goto fixed_length;

			case PW_TYPE_IPV6_PREFIX:
				if (src->ipv6prefix[1] != 128) {
				bad_v6_prefix_len:
					fr_strerror_printf("Invalid cast from %s to %s.  Only /128 prefixes may be "
							   "cast to IP address types",
							   fr_int2str(dict_attr_types, src_type, "<INVALID>"),
							   fr_int2str(dict_attr_types, dst_type, "<INVALID>"));
					return -1;
				}
				if (memcmp(&src->ipv6prefix[2], v4_v6_map, sizeof(v4_v6_map)) != 0) {
					goto bad_v6_prefix_map;
				}
				memcpy(&dst->ipaddr, &src->ipv6prefix[2 + sizeof(v4_v6_map)],
				       sizeof(dst->ipaddr));
				goto fixed_length;

			default:
				break;
			}
			break;

		case PW_TYPE_IPV6_ADDR:
			switch (src_type) {
			case PW_TYPE_IPV4_ADDR:
				/* Add the v4/v6 mapping prefix */
				memcpy(dst->ipv6addr.s6_addr, v4_v6_map, sizeof(v4_v6_map));
				memcpy(&dst->ipv6addr.s6_addr[sizeof(v4_v6_map)], &src->ipaddr,
				       sizeof(dst->ipv6addr.s6_addr) - sizeof(v4_v6_map));

				goto fixed_length;

			case PW_TYPE_IPV4_PREFIX:
				if (src->ipv4prefix[1] != 32) goto bad_v4_prefix_len;

				/* Add the v4/v6 mapping prefix */
				memcpy(dst->ipv6addr.s6_addr, v4_v6_map, sizeof(v4_v6_map));
				memcpy(&dst->ipv6addr.s6_addr[sizeof(v4_v6_map)], &src->ipv4prefix[2],
				       sizeof(dst->ipv6addr.s6_addr) - sizeof(v4_v6_map));
				goto fixed_length;

			case PW_TYPE_IPV6_PREFIX:
				if (src->ipv4prefix[1] != 128) goto bad_v6_prefix_len;

				memcpy(dst->ipv6addr.s6_addr, &src->ipv6prefix[2], sizeof(dst->ipv6addr.s6_addr));
				goto fixed_length;

			default:
				break;
			}
			break;

		case PW_TYPE_IPV4_PREFIX:
			switch (src_type) {
			case PW_TYPE_IPV4_ADDR:
				memcpy(&dst->ipv4prefix[2], &src->ipaddr, sizeof(dst->ipv4prefix) - 2);
				dst->ipv4prefix[0] = 0;
				dst->ipv4prefix[1] = 32;
				goto fixed_length;

			case PW_TYPE_IPV6_ADDR:
				if (memcmp(src->ipv6addr.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) {
					goto bad_v6_prefix_map;
				}
				memcpy(&dst->ipv4prefix[2], &src->ipv6addr.s6_addr[sizeof(v4_v6_map)],
				       sizeof(dst->ipv4prefix) - 2);
				dst->ipv4prefix[0] = 0;
				dst->ipv4prefix[1] = 32;
				goto fixed_length;

			case PW_TYPE_IPV6_PREFIX:
				if (memcmp(&src->ipv6prefix[2], v4_v6_map, sizeof(v4_v6_map)) != 0) {
					goto bad_v6_prefix_map;
				}

				/*
				 *	Prefix must be >= 96 bits. If it's < 96 bytes and the
				 *	above check passed, the v6 address wasn't masked
				 *	correctly when it was packet into a value_data_t.
				 */
				if (!fr_assert(src->ipv6prefix[1] >= (sizeof(v4_v6_map) * 8))) return -1;

				memcpy(&dst->ipv4prefix[2], &src->ipv6prefix[2 + sizeof(v4_v6_map)],
				       sizeof(dst->ipv4prefix) - 2);
				dst->ipv4prefix[0] = 0;
				dst->ipv4prefix[1] = src->ipv6prefix[1] - (sizeof(v4_v6_map) * 8);
				goto fixed_length;

			default:
				break;
			}
			break;

		case PW_TYPE_IPV6_PREFIX:
			switch (src_type) {
			case PW_TYPE_IPV4_ADDR:
				/* Add the v4/v6 mapping prefix */
				memcpy(&dst->ipv6prefix[2], v4_v6_map, sizeof(v4_v6_map));
				memcpy(&dst->ipv6prefix[2 + sizeof(v4_v6_map)], &src->ipaddr,
				       (sizeof(dst->ipv6prefix) - 2) - sizeof(v4_v6_map));
				dst->ipv6prefix[0] = 0;
				dst->ipv6prefix[1] = 128;
				goto fixed_length;

			case PW_TYPE_IPV4_PREFIX:
				/* Add the v4/v6 mapping prefix */
				memcpy(&dst->ipv6prefix[2], v4_v6_map, sizeof(v4_v6_map));
				memcpy(&dst->ipv6prefix[2 + sizeof(v4_v6_map)], &src->ipv4prefix[2],
				       (sizeof(dst->ipv6prefix) - 2) - sizeof(v4_v6_map));
				dst->ipv6prefix[0] = 0;
				dst->ipv6prefix[1] = (sizeof(v4_v6_map) * 8) + src->ipv4prefix[1];
				goto fixed_length;

			case PW_TYPE_IPV6_ADDR:
				memcpy(&dst->ipv6prefix[2], &src->ipv6addr, sizeof(dst->ipv6prefix) - 2);
				dst->ipv6prefix[0] = 0;
				dst->ipv6prefix[1] = 128;
				goto fixed_length;

			default:
				break;
			}

			break;

		default:
			break;
		}
	}

	/*
	 *	The attribute we've found has to have a size which is
	 *	compatible with the type of the destination cast.
	 */
	if ((src_len < dict_attr_sizes[dst_type][0]) ||
	    (src_len > dict_attr_sizes[dst_type][1])) {
	    	char const *src_type_name;

	    	src_type_name =  fr_int2str(dict_attr_types, src_type, "<INVALID>");
		fr_strerror_printf("Invalid cast from %s to %s. Length should be between %zu and %zu but is %zu",
				   src_type_name,
				   fr_int2str(dict_attr_types, dst_type, "<INVALID>"),
				   dict_attr_sizes[dst_type][0], dict_attr_sizes[dst_type][1],
				   src_len);
		return -1;
	}

	if (src_type == PW_TYPE_OCTETS) {
	do_octets:
		value_data_hton(dst, dst_type, src->octets, src_len);
		return src_len;
	}

	/*
	 *	Convert host order to network byte order.
	 */
	if ((dst_type == PW_TYPE_IPV4_ADDR) &&
	    ((src_type == PW_TYPE_INTEGER) ||
	     (src_type == PW_TYPE_DATE) ||
	     (src_type == PW_TYPE_SIGNED))) {
		dst->ipaddr.s_addr = htonl(src->integer);

	} else if ((src_type == PW_TYPE_IPV4_ADDR) &&
		   ((dst_type == PW_TYPE_INTEGER) ||
		    (dst_type == PW_TYPE_DATE) ||
		    (dst_type == PW_TYPE_SIGNED))) {
		dst->integer = htonl(src->ipaddr.s_addr);

	} else {		/* they're of the same byte order */
		memcpy(&dst, &src, src_len);
	}

	return src_len;
}

/** Copy value data verbatim duplicating any buffers
 *
 * @param ctx To allocate buffers in.
 * @param dst Where to copy value_data to.
 * @param src_type Type of src.
 * @param src Where to copy value_data from.
 * @param src_len Where
 */
ssize_t value_data_copy(TALLOC_CTX *ctx, value_data_t *dst, PW_TYPE src_type,
			const value_data_t *src, size_t src_len)
{
	switch (src_type) {
	default:
		memcpy(dst, src, sizeof(*src));
		break;

	case PW_TYPE_STRING:
		dst->strvalue = talloc_bstrndup(ctx, src->strvalue, src_len);
		if (!dst->strvalue) return -1;
		break;

	case PW_TYPE_OCTETS:
		dst->octets = talloc_memdup(ctx, src->octets, src_len);
		talloc_set_type(dst->strvalue, uint8_t);
		if (!dst->octets) return -1;
		break;
	}

	return src_len;
}



/** Print one attribute value to a string
 *
 */
char *value_data_aprints(TALLOC_CTX *ctx,
			 PW_TYPE type, DICT_ATTR const *enumv, value_data_t const *data,
			 size_t inlen, char quote)
{
	char *p = NULL;
	unsigned int i;

	switch (type) {
	case PW_TYPE_STRING:
	{
		size_t len, ret;

		if (!quote) {
			p = talloc_bstrndup(ctx, data->strvalue, inlen);
			if (!p) return NULL;
			talloc_set_type(p, char);
			return p;
		}

		/* Gets us the size of the buffer we need to alloc */
		len = fr_prints_len(data->strvalue, inlen, quote);
		p = talloc_array(ctx, char, len);
		if (!p) return NULL;

		ret = fr_prints(p, len, data->strvalue, inlen, quote);
		if (!fr_assert(ret == (len - 1))) {
			talloc_free(p);
			return NULL;
		}
		break;
	}

	case PW_TYPE_INTEGER:
		i = data->integer;
		goto print_int;

	case PW_TYPE_SHORT:
		i = data->ushort;
		goto print_int;

	case PW_TYPE_BYTE:
		i = data->byte;

	print_int:
	{
		DICT_VALUE const *dv;

		if (enumv && (dv = dict_valbyattr(enumv->attr, enumv->vendor, i))) {
			p = talloc_typed_strdup(ctx, dv->name);
		} else {
			p = talloc_typed_asprintf(ctx, "%u", i);
		}
	}
		break;

	case PW_TYPE_SIGNED:
		p = talloc_typed_asprintf(ctx, "%d", data->sinteger);
		break;

	case PW_TYPE_INTEGER64:
		p = talloc_typed_asprintf(ctx, "%" PRIu64 , data->integer64);
		break;

	case PW_TYPE_ETHERNET:
		p = talloc_typed_asprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
					  data->ether[0], data->ether[1],
					  data->ether[2], data->ether[3],
					  data->ether[4], data->ether[5]);
		break;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		p = talloc_array(ctx, char, 128);
		if (!p) return NULL;
		print_abinary(p, 128, (uint8_t const *) &data->filter, inlen, 0);
		break;
#else
		  /* FALL THROUGH */
#endif

	case PW_TYPE_OCTETS:
		p = talloc_array(ctx, char, 2 + 1 + inlen * 2);
		if (!p) return NULL;
		p[0] = '0';
		p[1] = 'x';

		fr_bin2hex(p + 2, data->octets, inlen);
		p[2 + (inlen * 2)] = '\0';
		break;

	case PW_TYPE_DATE:
	{
		time_t t;
		struct tm s_tm;

		t = data->date;

		p = talloc_array(ctx, char, 64);
		strftime(p, 64, "%b %e %Y %H:%M:%S %Z",
			 localtime_r(&t, &s_tm));
		break;
	}

	/*
	 *	We need to use the proper inet_ntop functions for IP
	 *	addresses, else the output might not match output of
	 *	other functions, which makes testing difficult.
	 *
	 *	An example is tunnelled ipv4 in ipv6 addresses.
	 */
	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_IPV4_PREFIX:
	{
		char buff[INET_ADDRSTRLEN  + 4]; // + /prefix

		buff[0] = '\0';
		value_data_prints(buff, sizeof(buff), type, enumv, data, inlen, '\0');

		p = talloc_typed_strdup(ctx, buff);
	}
	break;

	case PW_TYPE_IPV6_ADDR:
	case PW_TYPE_IPV6_PREFIX:
	{
		char buff[INET6_ADDRSTRLEN + 4]; // + /prefix

		buff[0] = '\0';
		value_data_prints(buff, sizeof(buff), type, enumv, data, inlen, '\0');

		p = talloc_typed_strdup(ctx, buff);
	}
	break;

	case PW_TYPE_IFID:
		p = talloc_typed_asprintf(ctx, "%x:%x:%x:%x",
					  (data->ifid[0] << 8) | data->ifid[1],
					  (data->ifid[2] << 8) | data->ifid[3],
					  (data->ifid[4] << 8) | data->ifid[5],
					  (data->ifid[6] << 8) | data->ifid[7]);
		break;

	case PW_TYPE_BOOLEAN:
		p = talloc_typed_strdup(ctx, data->byte ? "yes" : "no");
		break;

	/*
	 *	Don't add default here
	 */
	case PW_TYPE_INVALID:
	case PW_TYPE_COMBO_IP_ADDR:
	case PW_TYPE_COMBO_IP_PREFIX:
	case PW_TYPE_TLV:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
	case PW_TYPE_EVS:
	case PW_TYPE_VSA:
	case PW_TYPE_TIMEVAL:
	case PW_TYPE_MAX:
		fr_assert(0);
		return NULL;
	}

	return p;
}


/** Print the value of an attribute to a string
 *
 * @note return value should be checked with is_truncated.
 * @note Will always \0 terminate unless outlen == 0.
 *
 * @param out Where to write the printed version of the attribute value.
 * @param outlen Length of the output buffer.
 * @param type of data being printed.
 * @param enumv Enumerated string values for integer types.
 * @param data to print.
 * @param inlen Length of data.
 * @param quote char to escape in string output.
 * @return  the number of bytes written to the out buffer, or a number >= outlen if truncation has occurred.
 */
size_t value_data_prints(char *out, size_t outlen,
			 PW_TYPE type, DICT_ATTR const *enumv, value_data_t const *data,
			 ssize_t inlen, char quote)
{
	DICT_VALUE	*v;
	char		buf[1024];	/* Interim buffer to use with poorly behaved printing functions */
	char const	*a = NULL;
	char		*p = out;
	time_t		t;
	struct tm	s_tm;
	unsigned int	i;

	size_t		len = 0, freespace = outlen;

	if (!data) return 0;
	if (outlen == 0) return inlen;

	*out = '\0';

	p = out;

	switch (type) {
	case PW_TYPE_STRING:

		/*
		 *	Ensure that WE add the quotation marks around the string.
		 */
		if (quote) {
			if (freespace < 3) return inlen + 2;

			*p++ = quote;
			freespace--;

			len = fr_prints(p, freespace, data->strvalue, inlen, quote);
			/* always terminate the quoted string with another quote */
			if (len >= (freespace - 1)) {
				/* Use out not p as we're operating on the entire buffer */
				out[outlen - 2] = (char) quote;
				out[outlen - 1] = '\0';
				return len + 2;
			}
			p += len;
			freespace -= len;

			*p++ = (char) quote;
			freespace--;
			*p = '\0';

			return len + 2;
		}

		return fr_prints(out, outlen, data->strvalue, inlen, quote);

	case PW_TYPE_INTEGER:
		i = data->integer;
		goto print_int;

	case PW_TYPE_SHORT:
		i = data->ushort;
		goto print_int;

	case PW_TYPE_BYTE:
		i = data->byte;

print_int:
		/* Normal, non-tagged attribute */
		if (enumv && (v = dict_valbyattr(enumv->attr, enumv->vendor, i)) != NULL) {
			a = v->name;
			len = strlen(a);
		} else {
			/* should never be truncated */
			len = snprintf(buf, sizeof(buf), "%u", i);
			a = buf;
		}
		break;

	case PW_TYPE_INTEGER64:
		return snprintf(out, outlen, "%" PRIu64, data->integer64);

	case PW_TYPE_DATE:
		t = data->date;
		if (quote > 0) {
			len = strftime(buf, sizeof(buf) - 1, "%%%b %e %Y %H:%M:%S %Z%%", localtime_r(&t, &s_tm));
			buf[0] = (char) quote;
			buf[len - 1] = (char) quote;
			buf[len] = '\0';
		} else {
			len = strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S %Z", localtime_r(&t, &s_tm));
		}
		a = buf;
		break;

	case PW_TYPE_SIGNED: /* Damned code for 1 WiMAX attribute */
		len = snprintf(buf, sizeof(buf), "%d", data->sinteger);
		a = buf;
		break;

	case PW_TYPE_IPV4_ADDR:
		a = inet_ntop(AF_INET, &(data->ipaddr), buf, sizeof(buf));
		len = strlen(buf);
		break;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		print_abinary(buf, sizeof(buf), (uint8_t const *) data->filter, inlen, quote);
		a = buf;
		len = strlen(buf);
		break;
#else
	/* FALL THROUGH */
#endif
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
	{
		size_t binlen;
		size_t hexlen;

		binlen = inlen;
		hexlen = (binlen * 2) + 2; /* NOT accounting for trailing NUL */

		/*
		 *	If the buffer is too small, put something into
		 *	it, and return how much we should have written
		 *
		 *	0 + x + H + H + NUL = 5
		 */
		if (freespace < 5) {
			switch (freespace) {
			case '4':
			case '3':
				out[0] = '0';
				out[1] = 'x';
				out[2] = '\0';
				return hexlen;

			case 2:
				*out = '0';
				out++;
				/* FALL-THROUGH */

			case 1:
				*out = '\0';
				break;

			case 0:
				break;
			}

			return hexlen;
		}

		/*
		 *	The output buffer is at least 5 bytes, we haev
		 *	room for '0xHH' plus a trailing NUL byte.
		 */
		out[0] = '0';
		out[1] = 'x';

		/*
		 *	Get maximum number of bytes we can encode
		 *	given freespace, ensuring we account for '0',
		 *	'x', and the trailing NUL in the buffer.
		 *
		 *	Note that we can't have "freespace = 0" after
		 *	this, as 'freespace' has to be at least 5.
		 */
		freespace -= 3;
		freespace /= 2;
		if (binlen > freespace) {
			binlen = freespace;
		}

		fr_bin2hex(out + 2, data->octets, binlen);
		return hexlen;
	}

	case PW_TYPE_IFID:
		a = ifid_ntoa(buf, sizeof(buf), data->ifid);
		len = strlen(buf);
		break;

	case PW_TYPE_IPV6_ADDR:
		a = inet_ntop(AF_INET6, &data->ipv6addr, buf, sizeof(buf));
		len = strlen(buf);
		break;

	case PW_TYPE_IPV6_PREFIX:
	{
		struct in6_addr addr;

		/*
		 *	Alignment issues.
		 */
		memcpy(&addr, &(data->ipv6prefix[2]), sizeof(addr));

		a = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
		if (a) {
			p = buf;

			len = strlen(buf);
			p += len;
			len += snprintf(p, sizeof(buf) - len, "/%u", (unsigned int) data->ipv6prefix[1]);
		}
	}
		break;

	case PW_TYPE_IPV4_PREFIX:
	{
		struct in_addr addr;

		/*
		 *	Alignment issues.
		 */
		memcpy(&addr, &(data->ipv4prefix[2]), sizeof(addr));

		a = inet_ntop(AF_INET, &addr, buf, sizeof(buf));
		if (a) {
			p = buf;

			len = strlen(buf);
			p += len;
			len += snprintf(p, sizeof(buf) - len, "/%u", (unsigned int) (data->ipv4prefix[1] & 0x3f));
		}
	}
		break;

	case PW_TYPE_ETHERNET:
		return snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
				data->ether[0], data->ether[1],
				data->ether[2], data->ether[3],
				data->ether[4], data->ether[5]);

	/*
	 *	Don't add default here
	 */
	case PW_TYPE_INVALID:
	case PW_TYPE_COMBO_IP_ADDR:
	case PW_TYPE_COMBO_IP_PREFIX:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
	case PW_TYPE_EVS:
	case PW_TYPE_VSA:
	case PW_TYPE_TIMEVAL:
	case PW_TYPE_BOOLEAN:
	case PW_TYPE_MAX:
		fr_assert(0);
		*out = '\0';
		return 0;
	}

	if (a) strlcpy(out, a, outlen);

	return len;	/* Return the number of bytes we would of written (for truncation detection) */
}

