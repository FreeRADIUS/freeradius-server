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
