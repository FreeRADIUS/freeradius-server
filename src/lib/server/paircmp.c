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
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/server/request.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

typedef struct paircmp_s paircmp_t;
struct paircmp_s {
	fr_dict_attr_t const	*da;
	fr_dict_attr_t const	*from;
	bool			first_only;
	void			*instance; /* module instance */
	RAD_COMPARE_FUNC	compare;
	paircmp_t		*next;
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t paircmp_dict[];
fr_dict_autoload_t paircmp_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_client_ip_address;
static fr_dict_attr_t const *attr_crypt_password;
static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_prefix;
static fr_dict_attr_t const *attr_request_processing_stage;
static fr_dict_attr_t const *attr_strip_user_name;
static fr_dict_attr_t const *attr_stripped_user_name;
static fr_dict_attr_t const *attr_suffix;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_virtual_server;

extern fr_dict_attr_autoload_t paircmp_dict_attr[];
fr_dict_attr_autoload_t paircmp_dict_attr[] = {
	{ .out = &attr_client_ip_address, .name = "Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Crypt-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_prefix, .name = "Prefix", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_request_processing_stage, .name = "Request-Processing-Stage", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_strip_user_name, .name = "Strip-User-Name", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_suffix, .name = "Suffix", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_virtual_server, .name = "Virtual-Server", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static paircmp_t *cmp;


/*
 *	Compare prefix/suffix.
 *
 *	If they compare:
 *	- if FR_STRIP_USER_NAME is present in check_list,
 *	  strip the username of prefix/suffix.
 *	- if FR_STRIP_USER_NAME is not present in check_list,
 *	  add a FR_STRIPPED_USER_NAME to the request.
 */
static int prefix_suffix_cmp(UNUSED void *instance,
			     request_t *request,
			     fr_pair_t *req,
			     fr_pair_t *check,
			     fr_pair_t *check_list)
{
	fr_pair_t	*vp;
	char const	*name;
	char		rest[FR_MAX_STRING_LEN];
	int		len, namelen;
	int		ret = -1;
	fr_pair_t	*username;

	if (!request) return -1;

	username = fr_pair_find_by_da(&request->request_pairs, attr_stripped_user_name);
	if (!username) username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	if (!username) return -1;

	VP_VERIFY(check);

	name = username->vp_strvalue;

	RDEBUG3("Comparing name \"%s\" and check value \"%pV\"", name, &check->data);

	len = strlen(check->vp_strvalue);

	if (check->da == attr_prefix) {
		ret = strncmp(name, check->vp_strvalue, len);
		if (ret == 0)
			strlcpy(rest, name + len, sizeof(rest));
	} else if (check->da == attr_suffix) {
		namelen = strlen(name);
		if (namelen >= len) {
			ret = strcmp(name + namelen - len, check->vp_strvalue);
			if (ret == 0) strlcpy(rest, name, namelen - len + 1);
		}
	}

	if (ret != 0) return ret;

	/*
	 *	If Strip-User-Name == No, then don't do any more.
	 */
	vp = fr_pair_find_by_da(&check_list, attr_strip_user_name);
	if (vp && !vp->vp_uint32) return ret;

	/*
	 *	See where to put the stripped user name.
	 */
	vp = fr_pair_find_by_da(&check_list, attr_stripped_user_name);
	if (!vp) {
		/*
		 *	If "request" is NULL, then the memory will be
		 *	lost!
		 */
		MEM(vp = fr_pair_afrom_da(request->packet, attr_stripped_user_name));
		fr_pair_add(&req, vp);
	}
	fr_pair_value_strdup(vp, rest);

	return ret;
}


/*
 *	Compare the request packet type.
 */
static int packet_cmp(UNUSED void *instance,
		      request_t *request,
		      UNUSED fr_pair_t *req,
		      fr_pair_t *check,
		      UNUSED fr_pair_t *check_list)
{
	VP_VERIFY(check);

	if (request->packet->code == check->vp_uint32) return 0;

	return 1;
}

/*
 *	Generic comparisons, via xlat.
 */
static int generic_cmp(UNUSED void *instance,
		       request_t *request,
		       fr_pair_t *req,
		       fr_pair_t *check,
		       UNUSED fr_pair_t *check_list)
{
	VP_VERIFY(check);

	if ((check->op != T_OP_REG_EQ) && (check->op != T_OP_REG_NE)) {
		int rcode;
		char name[1024];
		char value[1024];
		fr_pair_t *vp;

		snprintf(name, sizeof(name), "%%{%s}", check->da->name);

		if (xlat_eval(value, sizeof(value), request, name, NULL, NULL) < 0) return 0;

		MEM(vp = fr_pair_afrom_da(req, check->da));
		vp->op = check->op;
		fr_pair_value_from_str(vp, value, -1, '"', false);

		/*
		 *	Paircmp returns 0 for failed comparison, 1 for succeeded -1 for error.
		 */
		rcode = fr_pair_cmp(check, vp);

		/*
		 *	We're being called from paircmp_func,
		 *	which wants 0 for success, and 1 for fail (sigh)
		 *
		 *	We should really fix the API so that it is
		 *	consistent.  i.e. the comparison callbacks should
		 *	return ONLY the resut of comparing A to B.
		 *	The radius_callback_cmp function should then
		 *	take care of using the operator to see if the
		 *	condition (A OP B) is true or not.
		 *
		 *	This would also allow "<", etc. to work in the
		 *	callback functions...
		 *
		 *	See rlm_ldap, ...groupcmp() for something that
		 *	returns 0 for matched, and 1 for didn't match.
		 */
		rcode = !rcode;
		fr_pair_list_free(&vp);

		return rcode;
	}

	/*
	 *	Will do the xlat for us
	 */
	return paircmp_pairs(request, check, NULL);
}

/** See what attribute we want to compare with.
 *
 * @param[in] da	to find comparison function for.
 * @param[in] from	reference to compare with.
 * @return
 *	- true if the comparison callback require
 *	  a matching attribute in the request.
 *	- false.
 */
static bool other_attr(fr_dict_attr_t const *da, fr_dict_attr_t const **from)
{
	paircmp_t *c;

	for (c = cmp; c; c = c->next) {
		if (c->da == da) {
			*from = c->from;
			return c->first_only;
		}
	}

	*from = da;

	return false;
}

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
int paircmp_pairs(request_t *request, fr_pair_t *check, fr_pair_t *vp)
#else
int paircmp_pairs(UNUSED request_t *request, fr_pair_t *check, fr_pair_t *vp)
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
			fr_value_box_aprint(check, &expr, &check->data, NULL);
			expr_p = expr;
		}

		if (vp->vp_type == FR_TYPE_STRING) {
			value_p = vp->vp_strvalue;
		} else {
			fr_value_box_aprint(vp, &value, &vp->data, NULL);
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
			regex_sub_to_request(request, &preg, &regmatch);
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
			if (vp->vp_length != check->vp_length) {
				ret = 1; /* NOT equal */
				break;
			}
			ret = memcmp(vp->vp_strvalue, check->vp_strvalue, vp->vp_length);
			break;

		case FR_TYPE_STRING:
			ret = strcmp(vp->vp_strvalue, check->vp_strvalue);
			break;

		case FR_TYPE_UINT8:
			ret = vp->vp_uint8 - check->vp_uint8;
			break;

		case FR_TYPE_UINT16:
			ret = vp->vp_uint16 - check->vp_uint16;
			break;

		case FR_TYPE_UINT32:
			ret = vp->vp_uint32 - check->vp_uint32;
			break;

		case FR_TYPE_UINT64:
			/*
			 *	Don't want integer overflow!
			 */
			if (vp->vp_uint64 < check->vp_uint64) {
				ret = -1;
			} else if (vp->vp_uint64 > check->vp_uint64) {
				ret = +1;
			} else {
				ret = 0;
			}
			break;

		case FR_TYPE_INT32:
			if (vp->vp_int32 < check->vp_int32) {
				ret = -1;
			} else if (vp->vp_int32 > check->vp_int32) {
				ret = +1;
			} else {
				ret = 0;
			}
			break;

		case FR_TYPE_DATE:
			ret = vp->vp_date - check->vp_date;
			break;

		case FR_TYPE_IPV4_ADDR:
			ret = ntohl(vp->vp_ipv4addr) - ntohl(check->vp_ipv4addr);
			break;

		case FR_TYPE_IPV6_ADDR:
			ret = memcmp(vp->vp_ip.addr.v6.s6_addr, check->vp_ip.addr.v6.s6_addr,
				     sizeof(vp->vp_ip.addr.v6.s6_addr));
			break;

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
			ret = memcmp(vp->vp_ifid, check->vp_ifid, sizeof(vp->vp_ifid));
			break;

		default:
			break;
	}

finish:
	if (ret > 0) return 1;
	if (ret < 0) return -1;
	return 0;
}

/** Compare check and vp. May call the attribute comparison function.
 *
 * Unlike paircmp_pairs() this function will call any attribute-specific
 * comparison functions registered.
 *
 * @param[in] request		Current request.
 * @param[in] request_list	list pairs.
 * @param[in] check		item to compare.
 * @param[in] check_list	list.
 * @return
 *	- 0 if check and vp are equal.
 *	- -1 if vp value is less than check value.
 *	- 1 is vp value is more than check value.
 */
static int paircmp_func(request_t *request,
			fr_pair_t *request_list,
			fr_pair_t *check,
			fr_pair_t *check_list)
{
	paircmp_t *c;

	VP_VERIFY(check);

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->op == T_OP_CMP_TRUE)  return 0;
	if (check->op == T_OP_CMP_FALSE) return 1;

	/*
	 *	See if there is a special compare function.
	 *
	 *	FIXME: use new RB-Tree code.
	 */
	for (c = cmp; c; c = c->next) {
		if (c->da == check->da) {
			return (c->compare)(c->instance, request, request_list, check, check_list);
		}
	}

	if (!request) return -1; /* doesn't exist, don't compare it */

	return paircmp_pairs(request, check, request_list);
}

/** Compare two pair lists except for the password information.
 *
 * For every element in "check" at least one matching copy must be present
 * in "reply".
 *
 * @param[in] request		Current request.
 * @param[in] request_list	request valuepairs.
 * @param[in] check		Check/control valuepairs.
 * @return 0 on match.
 */
int paircmp(request_t *request,
	    fr_pair_t *request_list,
	    fr_pair_t *check)
{
	fr_cursor_t		cursor;
	fr_pair_t		*check_item;
	fr_pair_t		*auth_item;
	fr_dict_attr_t const	*from;

	int			result = 0;
	int			compare;
	bool			first_only;

	for (check_item = fr_cursor_init(&cursor, &check);
	     check_item;
	     check_item = fr_cursor_next(&cursor)) {
		/*
		 *	If the user is setting a configuration value,
		 *	then don't bother comparing it to any attributes
		 *	sent to us by the user.  It ALWAYS matches.
		 */
		if ((check_item->op == T_OP_SET) ||
		    (check_item->op == T_OP_ADD)) {
			continue;
		}

		/*
		 *	Attributes we skip during comparison.
		 *	These are "server" check items.
		 */
		if ((check_item->da == attr_crypt_password) ||
		    (check_item->da == attr_auth_type) ||
		    (check_item->da == attr_strip_user_name)) {
			continue;
		}

		/*
		 *	IF the password attribute exists, THEN
		 *	we can do comparisons against it.  If not,
		 *	then the request did NOT contain a
		 *	User-Password attribute, so we CANNOT do
		 *	comparisons against it.
		 *
		 *	This hack makes CHAP-Password work..
		 */
		if (check_item->da == attr_user_password) {
			if (check_item->op == T_OP_CMP_EQ) {
				WARN("Found User-Password == \"...\"");
				WARN("Are you sure you don't mean Cleartext-Password?");
				WARN("See \"man rlm_pap\" for more information");
			}
			if (fr_pair_find_by_num(&request_list, 0, FR_USER_PASSWORD) == NULL) continue;
		}

		/*
		 *	See if this item is present in the request.
		 */
		first_only = other_attr(check_item->da, &from);

		auth_item = request_list;

	try_again:
		if (!first_only) {
			while (auth_item != NULL) {
				if ((auth_item->da == from) || (!from)) break;

				auth_item = auth_item->next;
			}
		}

		/*
		 *	Not found, it's not a match.
		 */
		if (auth_item == NULL) {
			/*
			 *	Didn't find it.  If we were *trying*
			 *	to not find it, then we succeeded.
			 */
			if (check_item->op == T_OP_CMP_FALSE) {
				continue;
			} else {
				return -1;
			}
		}

		/*
		 *	Else we found it, but we were trying to not
		 *	find it, so we failed.
		 */
		if (check_item->op == T_OP_CMP_FALSE) return -1;

		/*
		 *	We've got to xlat the string before doing
		 *	the comparison.
		 */
		xlat_eval_pair(request, check_item);

		/*
		 *	OK it is present now compare them.
		 */
		compare = paircmp_func(request, auth_item, check_item, check);
		switch (check_item->op) {
		case T_OP_EQ:
		default:
			RWDEBUG("Invalid operator '%s' for item %s: reverting to '=='",
				fr_table_str_by_value(fr_tokens_table, check_item->op, "<INVALID>"), check_item->da->name);
			FALL_THROUGH;
		case T_OP_CMP_TRUE:
		case T_OP_CMP_FALSE:
		case T_OP_CMP_EQ:
			if (compare != 0) result = -1;
			break;

		case T_OP_NE:
			if (compare == 0) result = -1;
			break;

		case T_OP_LT:
			if (compare >= 0) result = -1;
			break;

		case T_OP_GT:
			if (compare <= 0) result = -1;
			break;

		case T_OP_LE:
			if (compare > 0) result = -1;
			break;

		case T_OP_GE:
			if (compare < 0) result = -1;
			break;

#ifdef HAVE_REGEX
		case T_OP_REG_EQ:
		case T_OP_REG_NE:
			if (compare != 0) result = -1;
			break;
#endif
		} /* switch over the operator of the check item */

		/*
		 *	This attribute didn't match, but maybe there's
		 *	another of the same attribute, which DOES match.
		 */
		if ((result != 0) && (!first_only)) {
			auth_item = auth_item->next;
			result = 0;
			goto try_again;
		}

	} /* for every entry in the check item list */

	return result;
}

/** Find a comparison function for two attributes.
 *
 * @param[in] da	to find comparison function for.
 * @return
 *	- true if a comparison function was found.
 *	- false if a comparison function was not found.
 */
int paircmp_find(fr_dict_attr_t const *da)
{
	paircmp_t *c;

	for (c = cmp; c; c = c->next) if (c->da == da) return true;

	return false;
}

/** Register a function as compare function
 *
 * @param[in] name		the attribute comparison to register.
 * @param[in] from		the attribute we want to compare with.
 *				Normally this is the same as attribute.
 *				If null call the comparison function on
 *				every attributes in the request if
 *				first_only is false.
 * @param[in] first_only	will decide if we loop over the request
 *				attributes or stop on the first one.
 * @param[in] func		comparison function.
 * @param[in] instance		argument to comparison function.
 * @return
 *	- 0 on success
 *	- <0 on error
 */
int paircmp_register_by_name(char const *name, fr_dict_attr_t const *from,
			     bool first_only, RAD_COMPARE_FUNC func, void *instance)
{
	fr_dict_attr_flags_t	flags;
	fr_dict_attr_t const	*da;

	memset(&flags, 0, sizeof(flags));

	da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), name);
	if (da) {
		if (paircmp_find(da)) {
			fr_strerror_printf_push("Cannot register two comparions for attribute %s",
						name);
			return -1;
		}
	} else if (from) {
		if (fr_dict_attr_add(fr_dict_unconst(fr_dict_internal()), fr_dict_root(fr_dict_internal()),
				     name, -1, from->type, &flags) < 0) {
			fr_strerror_printf_push("Failed creating attribute '%s'", name);
			return -1;
		}

		da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), name);
		if (!da) {
			fr_strerror_printf("Failed finding attribute '%s'", name);
			return -1;
		}

		DEBUG("Creating attribute %s", name);
	}

	return paircmp_register(da, from, first_only, func, instance);
}

/** Register a function as compare function.
 *
 * @param[in] da		to register comparison function for.
 * @param[in] from		the attribute we want to compare with.
 *				Normally this is the same as attribute.
 *				If null call the comparison function
 *				on every attributes in the request if
 *				first_only is false.
 * @param[in] first_only	will decide if we loop over the request
 *				attributes or stop on the first one.
 * @param[in] func		comparison function.
 * @param[in] instance		argument to comparison function.
 * @return 0
 */
int paircmp_register(fr_dict_attr_t const *da, fr_dict_attr_t const *from,
		     bool first_only, RAD_COMPARE_FUNC func, void *instance)
{
	paircmp_t *c;

	fr_assert(da != NULL);

	paircmp_unregister(da, func);

	MEM(c = talloc_zero(NULL, paircmp_t));
	c->compare = func;
	c->da = da;
	c->from = from;
	c->first_only = first_only;
	c->instance = instance;
	c->next = cmp;
	cmp = c;

	return 0;
}

/** Unregister comparison function for an attribute
 *
 * @param[in] da		dict reference to unregister for.
 * @param[in] func		comparison function to remove.
 */
void paircmp_unregister(fr_dict_attr_t const *da, RAD_COMPARE_FUNC func)
{
	paircmp_t *c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if ((c->da == da) && (c->compare == func)) break;
		last = c;
	}

	if (c == NULL) return;

	if (last != NULL) {
		last->next = c->next;
	} else {
		cmp = c->next;
	}

	talloc_free(c);
}

/** Unregister comparison function for a module
 *
 *  All paircmp() functions for this module will be unregistered.
 *
 * @param instance the module instance
 */
void paircmp_unregister_instance(void *instance)
{
	paircmp_t *c, **tail;

	tail = &cmp;
	while ((c = *tail) != NULL) {
		if (c->instance == instance) {
			*tail = c->next;
			talloc_free(c);
			continue;
		}

		tail = &(c->next);
	}
}

/** Add built in pair comparisons
 *
 */
int paircmp_init(void)
{
	if (fr_dict_autoload(paircmp_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(paircmp_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(paircmp_dict);
		return -1;
	}

	paircmp_register(attr_prefix, attr_user_name, false, prefix_suffix_cmp, NULL);
	paircmp_register(attr_suffix, attr_user_name, false, prefix_suffix_cmp, NULL);
	paircmp_register(attr_packet_type, NULL, true, packet_cmp, NULL);

	paircmp_register(attr_client_ip_address, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_src_ip_address, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_dst_ip_address, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_src_port, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_dst_port, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_request_processing_stage, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_src_ipv6_address, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_packet_dst_ipv6_address, NULL, true, generic_cmp, NULL);
	paircmp_register(attr_virtual_server, NULL, true, generic_cmp, NULL);

	return 0;
}

void paircmp_free(void)
{
	paircmp_unregister(attr_prefix, prefix_suffix_cmp);
	paircmp_unregister(attr_suffix, prefix_suffix_cmp);
	paircmp_unregister(attr_packet_type, packet_cmp);

	paircmp_unregister(attr_client_ip_address, generic_cmp);
	paircmp_unregister(attr_packet_src_ip_address, generic_cmp);
	paircmp_unregister(attr_packet_dst_ip_address, generic_cmp);
	paircmp_unregister(attr_packet_src_port, generic_cmp);
	paircmp_unregister(attr_packet_dst_port, generic_cmp);
	paircmp_unregister(attr_request_processing_stage, generic_cmp);
	paircmp_unregister(attr_packet_src_ipv6_address, generic_cmp);
	paircmp_unregister(attr_packet_dst_ipv6_address, generic_cmp);
	paircmp_unregister(attr_virtual_server, generic_cmp);


	fr_dict_autofree(paircmp_dict);
}
