/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @brief Valuepair functions that are radiusd-specific and as such do not
 * 	  belong in the library.
 * @file src/lib/server/paircmp.c
 *
 * @ingroup AVP
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/unlang/xlat.h>

/** Compares check and vp by value.
 *
 * Does not call any per-attribute comparison function, but does honour
 * check.operator. Basically does "vp.value check.op check.value".
 *
 * @param[in] request	Current request.
 * @param[in] check	rvalue, and operator.
 * @param[in] vp	lvalue.
 * @return
 *	- 0 if check and vp are equal
 *	- -1 if vp value is less than check value.
 *	- 1 is vp value is more than check value.
 *	- -2 on error.
 */
#ifdef HAVE_REGEX
int paircmp_pairs(request_t *request, fr_pair_t const *check, fr_pair_t *vp)
#else
int paircmp_pairs(UNUSED request_t *request, fr_pair_t const *check, fr_pair_t *vp)
#endif
{
	int ret = 0;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->op == T_OP_CMP_TRUE)  return 0;
	if (check->op == T_OP_CMP_FALSE) return 1;

	if (!vp) {
		REDEBUG("Non-Unary operations require two operands");
		return -2;
	}

#ifdef HAVE_REGEX
	if ((check->op == T_OP_REG_EQ) || (check->op == T_OP_REG_NE)) {
		ssize_t		slen;
		regex_t		*preg = NULL;
		uint32_t	subcaptures;
		fr_regmatch_t	*regmatch;

		char *expr = NULL, *value = NULL;
		char const *expr_p, *value_p;

		if (check->vp_type == FR_TYPE_STRING) {
			expr_p = check->vp_strvalue;
		} else {
			fr_value_box_aprint(request, &expr, &check->data, NULL);
			expr_p = expr;
		}

		if (vp->vp_type == FR_TYPE_STRING) {
			value_p = vp->vp_strvalue;
		} else {
			fr_value_box_aprint(request, &value, &vp->data, NULL);
			value_p = value;
		}

		if (!expr_p || !value_p) {
			REDEBUG("Error stringifying operand for regular expression");

		regex_error:
			talloc_free(preg);
			talloc_free(expr);
			talloc_free(value);
			return -2;
		}

		/*
		 *	Include substring matches.
		 */
		slen = regex_compile(request, &preg, expr_p, talloc_array_length(expr_p) - 1,
				     NULL, true, true);
		if (slen <= 0) {
			REMARKER(expr_p, -slen, "%s", fr_strerror());

			goto regex_error;
		}

		subcaptures = regex_subcapture_count(preg);
		if (!subcaptures) subcaptures = REQUEST_MAX_REGEX + 1;	/* +1 for %{0} (whole match) capture group */
		MEM(regmatch = regex_match_data_alloc(NULL, subcaptures));

		/*
		 *	Evaluate the expression
		 */
		slen = regex_exec(preg, value_p, talloc_array_length(value_p) - 1, regmatch);
		if (slen < 0) {
			RPERROR("Invalid regex");

			goto regex_error;
		}

		if (check->op == T_OP_REG_EQ) {
			/*
			 *	Add in %{0}. %{1}, etc.
			 */
			regex_sub_to_request(request, &preg, &regmatch, &vp->data);
			ret = (slen == 1) ? 0 : -1;
		} else {
			ret = (slen != 1) ? 0 : -1;
		}

		talloc_free(regmatch);
		talloc_free(preg);
		talloc_free(expr);
		talloc_free(value);

		goto finish;
	}
#endif

	/*
	 *	Attributes must be of the same type.
	 *
	 *	FIXME: deal with type mismatch properly if one side contain
	 *	OCTETS or STRING by converting the other side to
	 *	a string
	 *
	 */
	if (vp->vp_type != check->vp_type) return -1;

	/*
	 *	Not a regular expression, compare the types.
	 */
	switch (check->vp_type) {
		case FR_TYPE_OCTETS:
			ret = CMP(vp->vp_length, check->vp_length);
			if (ret != 0) return ret;

			return CMP(memcmp(vp->vp_strvalue, check->vp_strvalue, vp->vp_length), 0);

		case FR_TYPE_STRING:
			return CMP(strcmp(vp->vp_strvalue, check->vp_strvalue), 0);

		case FR_TYPE_UINT8:
			return CMP(vp->vp_uint8, check->vp_uint8);

		case FR_TYPE_UINT16:
			return CMP(vp->vp_uint16, check->vp_uint16);

		case FR_TYPE_UINT32:
			return CMP(vp->vp_uint32, check->vp_uint32);

		case FR_TYPE_UINT64:
			return CMP(vp->vp_uint64, check->vp_uint64);

		case FR_TYPE_INT32:
			return CMP(vp->vp_int32, check->vp_int32);

		case FR_TYPE_DATE:
			return fr_unix_time_cmp(vp->vp_date, check->vp_date);

		case FR_TYPE_IPV4_ADDR:
			return CMP(ntohl(vp->vp_ipv4addr), ntohl(check->vp_ipv4addr));

		case FR_TYPE_IPV6_ADDR:
			return CMP(memcmp(vp->vp_ip.addr.v6.s6_addr, check->vp_ip.addr.v6.s6_addr,
					  sizeof(vp->vp_ip.addr.v6.s6_addr)), 0);

		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_PREFIX:
			ret = fr_pair_cmp_op(check->op, vp, check);
			if (ret == -1) return -2;   // error
			if (check->op == T_OP_LT || check->op == T_OP_LE)
				ret = (ret == 1) ? -1 : 1;
			else if (check->op == T_OP_GT || check->op == T_OP_GE)
				ret = (ret == 1) ? 1 : -1;
			else if (check->op == T_OP_CMP_EQ)
				ret = (ret == 1) ? 0 : -1;
			break;

		case FR_TYPE_IFID:
			return CMP(memcmp(vp->vp_ifid, check->vp_ifid, sizeof(vp->vp_ifid)), 0);
			
		default:
			return -2;
	}

finish:
	if (ret > 0) return 1;
	if (ret < 0) return -1;
	return 0;
}
