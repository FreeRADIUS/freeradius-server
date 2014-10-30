/*
 * valuepair.c	Functions to handle value_data_t
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
int value_data_cmp(PW_TYPE a_type, size_t a_len, value_data_t const *a,
		   PW_TYPE b_type, size_t b_len, value_data_t const *b)
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

		if (a_len > b_len) {
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
		compare = memcmp(&a->ether, &b->ether, sizeof(a->ether));
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
		compare = memcmp(&a->ipv6prefix, &b->ipv6prefix, sizeof(a->ipv6prefix));
		break;

	case PW_TYPE_IPV4_PREFIX:
		compare = memcmp(&a->ipv4prefix, &b->ipv4prefix, sizeof(a->ipv4prefix));
		break;

	case PW_TYPE_IFID:
		compare = memcmp(&a->ifid, &b->ifid, sizeof(a->ifid));
		break;

	/*
	 *	Na of the types below should be in the REQUEST
	 */
	case PW_TYPE_INVALID:		/* We should never see these */
	case PW_TYPE_IP_ADDR:		/* This should have been converted into IPADDR/IPV6ADDR */
	case PW_TYPE_IP_PREFIX:		/* This should have been converted into IPADDR/IPV6ADDR */
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
		      PW_TYPE a_type, size_t a_len, value_data_t const *a,
		      PW_TYPE b_type, size_t b_len, value_data_t const *b)
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
						    b->ipv4prefix[1], (uint8_t const *) &b->ipv4prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV4_PREFIX:		/* IPv4 and IPv4 Prefix */
		switch (b_type) {
		case PW_TYPE_IPV4_ADDR:
			return value_data_cidr_cmp_op(op, 4, a->ipv4prefix[1],
						    (uint8_t const *) &a->ipv4prefix + 2,
						    32, (uint8_t const *) &b->ipaddr);

		case PW_TYPE_IPV4_PREFIX:	/* IPv4 Prefix and IPv4 Prefix */
			return value_data_cidr_cmp_op(op, 4, a->ipv4prefix[1],
						    (uint8_t const *) &a->ipv4prefix + 2,
						    b->ipv4prefix[1], (uint8_t const *) &b->ipv4prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV6_ADDR:
		switch (b_type) {
		case PW_TYPE_IPV6_ADDR:		/* IPv6 and IPv6 */
			goto cmp;

		case PW_TYPE_IPV6_PREFIX:	/* IPv6 and IPv6 Preifx */
			return value_data_cidr_cmp_op(op, 16, 128, (uint8_t const *) &a->ipv6addr,
						    b->ipv6prefix[1], (uint8_t const *) &b->ipv6prefix + 2);
			break;

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV6_PREFIX:
		switch (b_type) {
		case PW_TYPE_IPV6_ADDR:		/* IPv6 Prefix and IPv6 */
			return value_data_cidr_cmp_op(op, 16, a->ipv6prefix[1],
						    (uint8_t const *) &a->ipv6prefix + 2,
						    128, (uint8_t const *) &b->ipv6addr);

		case PW_TYPE_IPV6_PREFIX:	/* IPv6 Prefix and IPv6 */
			return value_data_cidr_cmp_op(op, 16, a->ipv6prefix[1],
						    (uint8_t const *) &a->ipv6prefix + 2,
						    b->ipv6prefix[1], (uint8_t const *) &b->ipv6prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}
		break;

	default:
	cmp:
		compare = value_data_cmp(a_type, a_len, a,
				       b_type, b_len, b);
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
 * @param[out] out where to write parsed value.
 * @param[in,out] type of value data to create/type of value created.
 * @param[in] enumv DICT_ATTR with string aliases for integer values.
 * @param[in] value String to convert. Binary safe for variable length values if len is provided.
 * @param[in] inlen may be < 0 in which case strlen(len) is used to determine length, else inlen
 *	  should be the length of the string or sub string to parse.
 * @return length of data written to out or -1 on parse error.
 */
ssize_t value_data_from_str(TALLOC_CTX *ctx, value_data_t *out,
			    PW_TYPE *type, DICT_ATTR const *enumv,
			    char const *value, ssize_t inlen)
{
	DICT_VALUE	*dval;
	size_t		len;
	ssize_t		ret;
	char		buffer[256];

	if (!value) return -1;

	len = (inlen < 0) ? strlen(value) : inlen;

	/*
	 *	Set size for all fixed length attributes.
	 */
	ret = dict_attr_sizes[*type][1];	/* Max length */

	/*
	 *	It's a variable ret type so we just alloc a new buffer
	 *	of size len and copy.
	 */
	switch (*type) {
	case PW_TYPE_STRING:
	{
		size_t		p_len;
		char const	*cp;
		char		*p;
		int		x;

		/*
		 *	Do escaping here
		 */
		out->strvalue = p = talloc_memdup(ctx, value, len + 1);
		p[len] = '\0';
		talloc_set_type(p, char);

		cp = value;
		p_len = 0;
		while (*cp) {
			char c = *cp++;

			if (c == '\\') switch (*cp) {
			case 'r':
				c = '\r';
				cp++;
				break;
			case 'n':
				c = '\n';
				cp++;
				break;
			case 't':
				c = '\t';
				cp++;
				break;
			case '"':
				c = '"';
				cp++;
				break;
			case '\'':
				c = '\'';
				cp++;
				break;
			case '\\':
				c = '\\';
				cp++;
				break;
			case '`':
				c = '`';
				cp++;
				break;
			case '\0':
				c = '\\'; /* no cp++ */
				break;
			default:
				if ((cp[0] >= '0') &&
				    (cp[0] <= '9') &&
				    (cp[1] >= '0') &&
				    (cp[1] <= '9') &&
				    (cp[2] >= '0') &&
				    (cp[2] <= '9') &&
				    (sscanf(cp, "%3o", &x) == 1)) {
					c = x;
					cp += 3;

				} else if (cp[0]) {
					/*
					 *	\p --> p
					 */
					c = *cp++;
				} /* else at EOL \ --> \ */
			}
			*p++ = c;
			p_len++;
		}
		*p = '\0';
		ret = p_len;
	}
		goto finish;

	/* raw octets: 0x01020304... */
	case PW_TYPE_VSA:
		if (strcmp(value, "ANY") == 0) {
			ret = 0;
			goto finish;
		} /* else it's hex */

	case PW_TYPE_OCTETS:
	{
		uint8_t	*p;

		/*
		 *	No 0x prefix, just copy verbatim.
		 */
		if ((len < 2) || (strncasecmp(value, "0x", 2) != 0)) {
			out->octets = talloc_memdup(ctx, (uint8_t const *)value, len);
			talloc_set_type(out->octets, uint8_t);
			ret = len;
			goto finish;
		}


	do_octets:
		len -= 2;

		/*
		 *	Invalid.
		 */
		if ((len & 0x01) != 0) {
			fr_strerror_printf("Length of Hex String is not even, got %zu bytes", ret);
			return -1;
		}

		ret = len >> 1;
		p = talloc_array(ctx, uint8_t, ret);
		if (fr_hex2bin(p, ret, value + 2, len) != (size_t)ret) {
			talloc_free(p);
			fr_strerror_printf("Invalid hex data");
			return -1;
		}

		out->octets = p;
	}
		goto finish;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		if ((len > 1) && (strncasecmp(value, "0x", 2) == 0)) goto do_octets;

		if (ascend_parse_filter(out, value, len) < 0 ) {
			/* Allow ascend_parse_filter's strerror to bubble up */
			return -1;
		}
		ret = sizeof(out->filter);
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
	{
		uint8_t	*p;

		if ((len < 2) || (len & 0x01) || (strncasecmp(value, "0x", 2) != 0)) {
			fr_strerror_printf("Invalid TLV specification");
			return -1;
		}
		len -= 2;

		ret = len >> 1;
		p = talloc_array(ctx, uint8_t, ret);
		if (!p) {
			fr_strerror_printf("No memory");
			return -1;
		}
		if (fr_hex2bin(p, ret, value + 2, len) != (size_t)ret) {
			fr_strerror_printf("Invalid hex data in TLV");
			return -1;
		}

		out->tlv = p;
	}
		goto finish;

	case PW_TYPE_IPV4_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_pton4(&addr, value, inlen, fr_hostname_lookups, false) < 0) return -1;

		/*
		 *	We allow v4 addresses to have a /32 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 32) {
			fr_strerror_printf("Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		out->ipaddr.s_addr = addr.ipaddr.ip4addr.s_addr;
	}
		goto finish;

	case PW_TYPE_IPV4_PREFIX:
	{
		fr_ipaddr_t addr;

		if (fr_pton4(&addr, value, inlen, fr_hostname_lookups, false) < 0) return -1;

		out->ipv4prefix[1] = addr.prefix;
		memcpy(out->ipv4prefix + 2, &addr.ipaddr.ip4addr.s_addr, sizeof(out->ipv4prefix) - 2);
	}
		goto finish;

	case PW_TYPE_IPV6_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_pton6(&addr, value, inlen, fr_hostname_lookups, false) < 0) return -1;

		/*
		 *	We allow v6 addresses to have a /128 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 128) {
			fr_strerror_printf("Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		memcpy(&out->ipv6addr, &addr.ipaddr.ip6addr.s6_addr, sizeof(out->ipv6addr));
	}
		goto finish;

	case PW_TYPE_IPV6_PREFIX:
	{
		fr_ipaddr_t addr;

		if (fr_pton6(&addr, value, inlen, fr_hostname_lookups, false) < 0) return -1;

		out->ipv6prefix[1] = addr.prefix;
		memcpy(out->ipv6prefix + 2, &addr.ipaddr.ip6addr.s6_addr, sizeof(out->ipv6prefix) - 2);
	}
		goto finish;

	default:
		break;
	}

	/*
	 *	It's a fixed size type, copy to a temporary buffer and
	 *	\0 terminate if insize >= 0.
	 */
	if (inlen > 0) {
		if (len >= sizeof(buffer)) {
			fr_strerror_printf("Temporary buffer too small");
			return -1;
		}

		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
		value = buffer;
	}

	switch(*type) {
	case PW_TYPE_BYTE:
	{
		char *p;
		unsigned int i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		i = fr_strtoul(value, &p);

		/*
		 *	Look for the named value for the given
		 *	attribute.
		 */
		if (enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(enumv->attr, enumv->vendor, value)) == NULL) {
				fr_strerror_printf("Unknown value '%s' for attribute '%s'", value, enumv->name);
				return -1;
			}

			out->byte = dval->value;
		} else {
			if (i > 255) {
				fr_strerror_printf("Byte value \"%s\" is larger than 255", value);
				return -1;
			}

			out->byte = i;
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
		i = fr_strtoul(value, &p);

		/*
		 *	Look for the named value for the given
		 *	attribute.
		 */
		if (enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(enumv->attr, enumv->vendor, value)) == NULL) {
				fr_strerror_printf("Unknown value '%s' for attribute '%s'", value, enumv->name);
				return -1;
			}

			out->ushort = dval->value;
		} else {
			if (i > 65535) {
				fr_strerror_printf("Short value \"%s\" is larger than 65535", value);
				return -1;
			}

			out->ushort = i;
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
		i = fr_strtoul(value, &p);

		/*
		 *	Look for the named value for the given
		 *	attribute.
		 */
		if (enumv && *p && !is_whitespace(p)) {
			if ((dval = dict_valbyname(enumv->attr, enumv->vendor, value)) == NULL) {
				fr_strerror_printf("Unknown value '%s' for attribute '%s'", value, enumv->name);
				return -1;
			}

			out->integer = dval->value;
		} else {
			/*
			 *	Value is always within the limits
			 */
			out->integer = i;
		}
	}
		break;

	case PW_TYPE_INTEGER64:
	{
		uint64_t i;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		if (sscanf(value, "%" PRIu64, &i) != 1) {
			fr_strerror_printf("Invalid value '%s' for attribute '%s'",
					   value, enumv->name);
			return -1;
		}
		out->integer64 = i;
	}
		break;

	case PW_TYPE_DATE:
	{
		/*
		 *	time_t may be 64 bits, whule vp_date MUST be 32-bits.  We need an
		 *	intermediary variable to handle the conversions.
		 */
		time_t date;

		if (fr_get_time(value, &date) < 0) {
			fr_strerror_printf("failed to parse time string \"%s\"", value);
			return -1;
		}

		out->date = date;
	}

		break;

	case PW_TYPE_IFID:
		if (ifid_aton(value, (void *) &out->ifid) == NULL) {
			fr_strerror_printf("Failed to parse interface-id string \"%s\"", value);
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
		if (is_integer(value)) {
			uint64_t integer = htonll(atoll(value));

			memcpy(&out->ether, &integer, sizeof(out->ether));
			break;
		}

		cp = value;
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
			if (!c1 || !c2 || (p_len >= sizeof(out->ether))) {
				fr_strerror_printf("failed to parse Ethernet address \"%s\"", value);
				return -1;
			}
			out->ether[p_len] = ((c1-hextab)<<4) + (c2-hextab);
			p_len++;
		}
	}
		break;

	/*
	 *	Crazy polymorphic (IPv4/IPv6) attribute type for WiMAX.
	 *
	 *	We try and make is saner by replacing the original
	 *	da, with either an IPv4 or IPv6 da type.
	 *
	 *	These are not dynamic da, and will have the same vendor
	 *	and attribute as the original.
	 */
	case PW_TYPE_IP_ADDR:
	{
		if (inet_pton(AF_INET6, value, &out->ipv6addr) > 0) {
			*type = PW_TYPE_IPV6_ADDR;
			ret = dict_attr_sizes[PW_TYPE_IP_ADDR][1]; /* size of IPv6 address */
		} else {
			fr_ipaddr_t ipaddr;

			if (ip_hton(&ipaddr, AF_INET, value, false) < 0) {
				fr_strerror_printf("Failed to find IPv4 address for %s", value);
				return -1;
			}

			*type = PW_TYPE_IPV4_ADDR;
			out->ipaddr.s_addr = ipaddr.ipaddr.ip4addr.s_addr;
			ret = dict_attr_sizes[PW_TYPE_IP_ADDR][0]; /* size of IPv4 address */
		}
	}
		break;

	case PW_TYPE_SIGNED:
		/* Damned code for 1 WiMAX attribute */
		out->sinteger = (int32_t)strtol(value, NULL, 10);
		break;

		/*
		 *  Anything else.
		 */
	default:
		fr_strerror_printf("Unknown attribute type %d", *type);
		return -1;
	}

finish:
	return ret;
}

