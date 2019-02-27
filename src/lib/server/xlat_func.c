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
 * @file xlat_func.c
 * @brief String expansion ("translation").  Baked in expansions.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/regex.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/value.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#include <ctype.h>
#include "xlat_priv.h"

static rbtree_t *xlat_root = NULL;

#ifdef WITH_UNLANG
static char const * const xlat_foreach_names[] = {"Foreach-Variable-0",
						  "Foreach-Variable-1",
						  "Foreach-Variable-2",
						  "Foreach-Variable-3",
						  "Foreach-Variable-4",
						  "Foreach-Variable-5",
						  "Foreach-Variable-6",
						  "Foreach-Variable-7",
						  "Foreach-Variable-8",
						  "Foreach-Variable-9",
						  NULL};
#endif

static char const hextab[] = "0123456789abcdef";

static int xlat_foreach_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

/** Return a VP from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.  @see xlat_fmt_to_cursor instead.
 *
 * @param out where to write the pointer to the resolved VP. Will be NULL if the attribute couldn't
 *	be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, &vpt, name,
				&(vp_tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = VP_ATTR_REF_PREFIX_AUTO
				}) <= 0) return -4;

	rcode = tmpl_find_vp(out, request, vpt);
	talloc_free(vpt);

	return rcode;
}

/** Copy VP(s) from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.  @see xlat_fmt_to_cursor instead.
 *
 * @param ctx to alloc new VALUE_PAIRs in.
 * @param out where to write the pointer to the copied VP. Will be NULL if the attribute couldn't be
 *	resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, &vpt, name, &(vp_tmpl_rules_t){ .dict_def = request->dict }) <= 0) return -4;

	rcode = tmpl_copy_vps(ctx, out, request, vpt);
	talloc_free(vpt);

	return rcode;
}

/** Convenience function to convert a string attribute reference to a cursor
 *
 * This is intended to be used by xlat functions which need to iterate over
 * an attribute reference provided as a format string or as a boxed value.
 *
 * We can't add attribute reference support to the xlat parser
 * as the inputs and outputs of xlat functions are all boxed values and
 * couldn't represent a VALUE_PAIR.
 *
 * @param[in] ctx	To allocate new cursor in.
 * @param[out] out	Where to write heap allocated cursor.  Must be freed
 *			once it's done with.  The heap based cursor is to
 *      		simplify memory management, as all tmpls are heap
 *			allocated, and we need to bind the lifetime of the
 *			tmpl and tmpl cursor together.
 * @param[in] tainted	May be NULL.  Set to true if one or more of the pairs
 *      		in the cursor's scope have the tainted flag high.
 * @param[in] request	The current request.
 * @param[in] fmt	string.  Leading whitespace will be ignored.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_fmt_to_cursor(TALLOC_CTX *ctx, fr_cursor_t **out,
		       bool *tainted, REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt;
	VALUE_PAIR	*vp;
	fr_cursor_t	*cursor;

	fr_skip_spaces(fmt);	/* Not binary safe, but attr refs should only contain printable chars */

	if (tmpl_afrom_attr_str(NULL, &vpt, fmt,
				&(vp_tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = VP_ATTR_REF_PREFIX_AUTO
				}) < 0) {
		RPEDEBUG("Failed parsing attribute reference");
		return -1;
	}

	MEM(cursor = talloc(ctx, fr_cursor_t));
	talloc_steal(cursor, vpt);
	vp = tmpl_cursor_init(NULL, cursor, request, vpt);
	*out = cursor;

	if (!tainted) return 0;

	*tainted = false;	/* Needed for the rest of the code */

	if (!vp) return 0;

	do {
		if (vp->vp_tainted) {
			*tainted = true;
			break;
		}
	} while ((vp = fr_cursor_next(cursor)));

	fr_cursor_head(cursor);	/* Reset */

	return 0;
}

static xlat_action_t xlat_func_strlen(TALLOC_CTX *ctx, fr_cursor_t *out,
				      REQUEST *request, UNUSED void const *xlat_inst,
				      UNUSED void *xlat_thread_inst, fr_value_box_t **in)
{
	fr_value_box_t	*vb;

	if (!*in) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
		vb->vb_size = 0;
		fr_cursor_append(out, vb);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
	vb->vb_size = strlen((*in)->vb_strvalue);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Return the on-the-wire size of the attribute(s) in bytes
 *
 */
static xlat_action_t xlat_func_length(TALLOC_CTX *ctx, fr_cursor_t *out,
				      REQUEST *request, UNUSED void const *xlat_inst,
				      UNUSED void *xlat_thread_inst, fr_value_box_t **in)

{
	VALUE_PAIR 	*vp;
	fr_value_box_t	*vb;
	fr_cursor_t	*cursor;

	if (!*in) {
		REDEBUG("Missing attribute reference");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Concatenate input boxes to form the reference
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input string for attribute reference");
		return XLAT_ACTION_FAIL;
	}

	if (xlat_fmt_to_cursor(NULL, &cursor, NULL, request, (*in)->vb_strvalue) < 0) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
	vb->vb_size = 0;

	/*
	 *	Get the length of all VPs
	 */
	for (vp = fr_cursor_head(cursor);
	     vp;
	     vp = fr_cursor_next(cursor)) {
	     	vb->vb_size += fr_value_box_network_length(&vp->data);
	}
	talloc_free(cursor);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Print data as integer, not as VALUE.
 *
 */
static ssize_t xlat_func_integer(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				 REQUEST *request, char const *fmt)
{
	VALUE_PAIR 	*vp;

	uint64_t 	int64 = 0;	/* Needs to be initialised to zero */
	uint32_t	int32 = 0;	/* Needs to be initialised to zero */

	fr_skip_spaces(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	switch (vp->vp_type) {
	case FR_TYPE_STRING:
	{
		fr_value_box_t vb;

		if (fr_value_box_cast(NULL, &vb, FR_TYPE_UINT64, NULL, &vp->data) < 0) {
			RPEDEBUG("Input string invalid");
			return -1;
		}

		return snprintf(*out, outlen, "%" PRIu64, vb.vb_uint64);
	}

	case FR_TYPE_OCTETS:
		if (vp->vp_length > 8) {
			break;
		}

		if (vp->vp_length > 4) {
			memcpy(&int64, vp->vp_octets, vp->vp_length);
			return snprintf(*out, outlen, "%" PRIu64, htonll(int64));
		}

		memcpy(&int32, vp->vp_octets, vp->vp_length);
		return snprintf(*out, outlen, "%i", htonl(int32));

	case FR_TYPE_UINT64:
		return snprintf(*out, outlen, "%" PRIu64, vp->vp_uint64);

	/*
	 *	IP addresses are treated specially, as parsing functions assume the value
	 *	is bigendian and will convert it for us.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:	/* Same addr field */
		return snprintf(*out, outlen, "%u", ntohl(vp->vp_ipv4addr));

	case FR_TYPE_UINT32:
		return snprintf(*out, outlen, "%u", vp->vp_uint32);

	case FR_TYPE_DATE:
		return snprintf(*out, outlen, "%u", vp->vp_date);

	case FR_TYPE_UINT8:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint8);

	case FR_TYPE_UINT16:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint16);

	/*
	 *	Ethernet is weird... It's network related, so it
	 *	should be bigendian.
	 */
	case FR_TYPE_ETHERNET:
		int64 = vp->vp_ether[0];
		int64 <<= 8;
		int64 |= vp->vp_ether[1];
		int64 <<= 8;
		int64 |= vp->vp_ether[2];
		int64 <<= 8;
		int64 |= vp->vp_ether[3];
		int64 <<= 8;
		int64 |= vp->vp_ether[4];
		int64 <<= 8;
		int64 |= vp->vp_ether[5];
		return snprintf(*out, outlen, "%" PRIu64, int64);

	case FR_TYPE_INT32:
		return snprintf(*out, outlen, "%i", vp->vp_int32);

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		return fr_snprint_uint128(*out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6addr));

	default:
		break;
	}

	REDEBUG("Type '%s' cannot be converted to integer", fr_int2str(fr_value_box_type_table, vp->vp_type, "???"));

	return -1;
}

/** Print data as hex, not as VALUE.
 *
 */
static xlat_action_t xlat_func_hex(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	char *buff, *buff_p;
	uint8_t const *p, *end;
	fr_value_box_t* vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_octets;
	end = p + (*in)->vb_length;

	buff = buff_p = talloc_array(NULL, char, ((*in)->vb_length * 2) + 1);

	while (p < end) {
		snprintf(buff_p, 3, "%02x", *(p++));
		buff_p += 2;
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Return the tag of an attribute reference
 *
 */
static xlat_action_t xlat_func_tag(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst,
				   UNUSED void *xlat_thread_inst, fr_value_box_t **in)
{
	fr_value_box_t	*vb;
	VALUE_PAIR 	*vp;
	fr_cursor_t	*cursor;

	if (!*in) {
		REDEBUG("Missing attribute reference");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (xlat_fmt_to_cursor(NULL, &cursor, NULL, request, (*in)->vb_strvalue) < 0) return XLAT_ACTION_FAIL;

	for (vp = fr_cursor_head(cursor);
	     vp;
	     vp = fr_cursor_next(cursor)) {
		if (!vp->da->flags.has_tag || !TAG_VALID(vp->tag)) continue;

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT8, NULL, false));
		vb->vb_int8 = vp->tag;
		fr_cursor_append(out, vb);
	}
	talloc_free(cursor);

	return XLAT_ACTION_DONE;
}

/** Print out attribute info
 *
 * Prints out all instances of a current attribute, or all attributes in a list.
 *
 * At higher debugging levels, also prints out alternative decodings of the same
 * value. This is helpful to determine types for unknown attributes of long
 * passed vendors, or just crazy/broken NAS.
 *
 * This expands to a zero length string.
 */
static ssize_t xlat_func_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
				    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				    REQUEST *request, char const *fmt)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;
	vp_tmpl_t	*vpt;

	if (!RDEBUG_ENABLED2) return 0;	/* NOOP if debugging isn't enabled */

	fr_skip_spaces(fmt);

	if (tmpl_afrom_attr_str(request, &vpt, fmt,
				&(vp_tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = VP_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		fr_dict_vendor_t const	*vendor;
		FR_NAME_NUMBER const	*type;

		if (vp->da->flags.has_tag) {
			RIDEBUG2("&%s:%s:%i %s %pV",
				fr_int2str(pair_list_table, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				vp->tag,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				&vp->data);
		} else {
			RIDEBUG2("&%s:%s %s %pV",
				fr_int2str(pair_list_table, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				&vp->data);
		}

		if (!RDEBUG_ENABLED3) continue;

		vendor = fr_dict_vendor_by_da(vp->da);
		if (vendor) RIDEBUG2("Vendor : %i (%s)", vendor->pen, vendor->name);
		RIDEBUG2("Type   : %s", fr_int2str(fr_value_box_type_table, vp->vp_type, "<INVALID>"));

		switch (vp->vp_type) {
		case FR_TYPE_VARIABLE_SIZE:
			RIDEBUG2("Length : %zu", vp->vp_length);
			break;

		default:
			break;
		}

		if (!RDEBUG_ENABLED4) continue;

		type = fr_value_box_type_table;
		while (type->name) {
			int pad;

			fr_value_box_t *dst = NULL;

			if ((fr_type_t) type->number == vp->vp_type) goto next_type;

			switch (type->number) {
			case FR_TYPE_NON_VALUES:	/* Skip everything that's not a value */
				goto next_type;

			default:
				break;
			}

			dst = fr_value_box_alloc_null(vp);
			/* We expect some to fail */
			if (fr_value_box_cast(dst, dst, type->number, NULL, &vp->data) < 0) {
				goto next_type;
			}

			if ((pad = (11 - strlen(type->name))) < 0) pad = 0;

			RINDENT();
			RDEBUG2("as %s%*s: %pV", type->name, pad, " ", dst);
			REXDENT();

		next_type:
			talloc_free(dst);
			type++;
		}
	}
	REXDENT();

	talloc_free(vpt);

	return 0;
}

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g. "%{map:&User-Name := 'foo'}"
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 */
static ssize_t xlat_func_map(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     REQUEST *request, char const *fmt)
{
	vp_map_t	*map = NULL;
	int		ret;

	vp_tmpl_rules_t parse_rules = {
		.dict_def = request->dict,
		.prefix = VP_ATTR_REF_PREFIX_AUTO
	};

	if (map_afrom_attr_str(request, &map, fmt, &parse_rules, &parse_rules) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt);
		return -1;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in left hand side of expression",
			fr_int2str(tmpl_type_table, map->lhs->type, "<INVALID>"));
		return strlcpy(*out, "0", outlen);
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_UNPARSED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in right hand side of expression",
			fr_int2str(tmpl_type_table, map->rhs->type, "<INVALID>"));
		return strlcpy(*out, "0", outlen);
	}

	RINDENT();
	ret = map_to_request(request, map, map_to_vp, NULL);
	REXDENT();
	talloc_free(map);
	if (ret < 0) return strlcpy(*out, "0", outlen);

	return strlcpy(*out, "1", outlen);
}

/** Prints the current module processing the request
 *
 */
static xlat_action_t xlat_func_module(TALLOC_CTX *ctx, fr_cursor_t *out,
				      REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      UNUSED fr_value_box_t **in)
{
	fr_value_box_t	*vb = NULL;

	/*
	 *	Don't do anything if we're outside of a module
	 */
	if (!request->module || !*request->module) return XLAT_ACTION_DONE;

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_strdup(vb, vb, NULL, request->module, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#ifdef WITH_UNLANG
/** Implements the Foreach-Variable-X
 *
 * @see modcall()
 */
static ssize_t xlat_foreach(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			    void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, UNUSED char const *fmt)
{
	VALUE_PAIR	**pvp;

	/*
	 *	See modcall, "FOREACH" for how this works.
	 */
	pvp = (VALUE_PAIR **) request_data_reference(request, (void *)xlat_fmt_get_vp, *(int const *) mod_inst);
	if (!pvp || !*pvp) return 0;

	*out = fr_pair_value_asprint(ctx, *pvp, '\0');
	return 	talloc_array_length(*out) - 1;
}
#endif

/** Print data as string, if possible.
 *
 * Concat and cast one or more input boxes to a single output box string.
 */
static xlat_action_t xlat_func_string(TALLOC_CTX *ctx, fr_cursor_t *out,
				      REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      fr_value_box_t **in)
{
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");

		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, *in);
	*in = NULL;	/* Let the caller know this was consumed */

	return XLAT_ACTION_DONE;
}

/** xlat expand string attribute value
 *
 */
static ssize_t xlat_func_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	ssize_t slen;
	VALUE_PAIR *vp;

	fr_skip_spaces(fmt);

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	RDEBUG2("EXPAND %s", fmt);
	RINDENT();

	/*
	 *	If it's a string, expand it again
	 */
	if (vp->vp_type == FR_TYPE_STRING) {
		slen = xlat_eval(*out, outlen, request, vp->vp_strvalue, NULL, NULL);
		if (slen <= 0) return slen;
	/*
	 *	If it's not a string, treat it as a literal
	 */
	} else {
		*out = fr_pair_value_asprint(ctx, vp, '\0');
		if (!*out) return -1;
		slen = talloc_array_length(*out) - 1;
	}

	REXDENT();
	RDEBUG2("--> %s", *out);

	return slen;
}

/** Dynamically change the debugging level for the current request
 *
 * Example %{debug:3}
 */
static ssize_t xlat_func_debug(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       REQUEST *request, char const *fmt)
{
	int level = 0;

	/*
	 *  Expand to previous (or current) level
	 */
	snprintf(*out, outlen, "%d", request->log.lvl);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;

	level = atoi(fmt);
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
	} else {
		if (level > 4) level = 4;
		request->log.lvl = level;
	}

done:
	return strlen(*out);
}

/** Generate a random integer value
 *
 */
static xlat_action_t xlat_func_rand(TALLOC_CTX *ctx, fr_cursor_t *out,
				    REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				    fr_value_box_t **in)
{
	int64_t		result;
	fr_value_box_t*	vb;

	/* Make sure input can be converted to an unsigned 32 bit integer */
	if (fr_value_box_cast_in_place(ctx, (*in), FR_TYPE_UINT32, NULL) < 0) {
		RPEDEBUG("Failed converting input to uint32");
		return XLAT_ACTION_FAIL;
	}

	result = (*in)->vb_uint32;

	/* Make sure it isn't too big */
	if (result > (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
	vb->vb_uint64 = result;

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Generate a string of random chars
 *
 *  Build strings of random chars, useful for generating tokens and passcodes
 *  Format similar to String::Random.
 */
static xlat_action_t xlat_func_randstr(TALLOC_CTX *ctx, fr_cursor_t *out,
				       REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	/*
 	 *	Lookup tables for randstr char classes
 	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

 	/*
 	 *	Characters humans rarely confuse. Reduces char set considerably
 	 *	should only be used for things such as one time passwords.
 	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

	char const 	*p, *start, *end;
	char		*endptr;
	char		*buff, *buff_p;
	unsigned int	result;
	unsigned int	reps;
	size_t		outlen = 0;
	fr_value_box_t*	vb;

	/** Max repetitions of a single character class
	 *
	 */
#define REPETITION_MAX 1024

	/*
	 *	Nothing to do if input is empty
	 */
	if (!(*in)) return XLAT_ACTION_DONE;

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	start = p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 *	Calculate size of output
	 */
	while (p < end) {
		/*
		 *	Repetition modifiers.
		 *
		 *	We limit it to REPETITION_MAX, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) reps = REPETITION_MAX;
			/* hexits take up 2 characters */
			outlen += reps;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = start;

	while (p < end) {
		size_t i;

		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) {
				reps = REPETITION_MAX;
				RMARKER(L_WARN, L_DBG_LVL_2, start, start - p,
					"Forcing repetition to %u", (unsigned int)REPETITION_MAX);
			}
			p = endptr;
		} else {
			reps = 1;
		}

		for (i = 0; i < reps; i++) {
			result = fr_rand();
			switch (*p) {
			/*
			 *  Lowercase letters
			 */
			case 'c':
				*buff_p++ = 'a' + (result % 26);
				break;

			/*
			 *  Uppercase letters
			 */
			case 'C':
				*buff_p++ = 'A' + (result % 26);
				break;

			/*
			 *  Numbers
			 */
			case 'n':
				*buff_p++ = '0' + (result % 10);
				break;

			/*
			 *  Alpha numeric
			 */
			case 'a':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
				break;

			/*
			 *  Punctuation
			 */
			case '!':
				*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
				break;

			/*
			 *  Alpa numeric + punctuation
			 */
			case '.':
				*buff_p++ = '!' + (result % 95);
				break;

			/*
			 *  Alpha numeric + salt chars './'
			 */
			case 's':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
				break;

			/*
			 *  Chars suitable for One Time Password tokens.
			 *  Alpha numeric with easily confused char pairs removed.
			 */
			case 'o':
				*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
				break;

			/*
			 *	Binary data - Copy between 1-4 bytes at a time
			 */
			case 'b':
			{
				size_t copy = (reps - i) > sizeof(result) ? sizeof(result) : reps - i;

				memcpy(buff_p, (uint8_t *)&result, copy);
				buff_p += copy;
				i += (copy - 1);	/* Loop +1 */
			}
				break;

			default:
				REDEBUG("Invalid character class '%c'", *p);
				talloc_free(buff);

				return XLAT_ACTION_FAIL;
			}
		}

		p++;
	}

	*buff_p++ = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
static xlat_action_t xlat_func_regex(TALLOC_CTX *ctx, fr_cursor_t *out,
				     REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				     fr_value_box_t **in)
{
	/*
	 *	Return the complete capture if no other capture is specified
	 */
	if (!(*in)) {
		fr_value_box_t	*vb;
		char		*p;

		if (regex_request_to_sub(ctx, &p, request, 0) < 0) return XLAT_ACTION_FAIL;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrsteal(vb, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	switch ((*in)->type) {
	/*
	 *	If the input is an integer value then get an
	 *	arbitrary subcapture index.
	 */
	case FR_TYPE_NUMERIC:
	{
		fr_value_box_t	idx;
		fr_value_box_t	*vb;
		char		*p;

		if ((*in)->next) {
			REDEBUG("Only one subcapture argument allowed");
			return XLAT_ACTION_FAIL;
		}

		if (fr_value_box_cast(NULL, &idx, FR_TYPE_UINT32, NULL, *in) < 0) {
			RPEDEBUG("Bad subcapture index");
			return XLAT_ACTION_FAIL;
		}

		if (regex_request_to_sub(ctx, &p, request, idx.vb_uint32) < 0) return XLAT_ACTION_FAIL;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrsteal(vb, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	default:
	{
		fr_value_box_t	*vb;
		char		*p;

		/*
		 *	Concatenate all input
		 */
		if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
			RPEDEBUG("Failed concatenating input");
			return XLAT_ACTION_FAIL;
		}

		if (regex_request_to_sub_named(request, &p, request, (*in)->vb_strvalue) < 0) return XLAT_ACTION_FAIL;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrsteal(vb, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}
	}
}
#endif

/** URLencode special characters
 *
 * Example: "%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
 */
static xlat_action_t xlat_func_urlquote(TALLOC_CTX *ctx, fr_cursor_t *out,
					REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					fr_value_box_t **in)
{
	char const 	*p, *end;
	char		*buff, *buff_p;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!(*in)) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isalnum(*p) ||
		    *p == '-' ||
		    *p == '_' ||
		    *p == '.' ||
		    *p == '~') {
			outlen++;
		} else {
			outlen += 3;
		}
		p++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (isalnum(*p)) {
			*buff_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*buff_p++ = *p++;
			break;

		default:
			/* MUST be upper case hex to be compliant */
			snprintf(buff_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			buff_p += 3;
		}
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** URLdecode special characters
 *
 * Example: "%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
 *
 * Remember to escape % with %% in strings, else xlat will try to parse it.
 */
static xlat_action_t xlat_func_urlunquote(TALLOC_CTX *ctx, fr_cursor_t *out,
					  REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					  fr_value_box_t **in)
{
	char const 	*p, *end;
	char		*buff, *buff_p;
	char *c1, *c2;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (*p == '%') {
			p += 3;
		} else {
			p++;
		}
		outlen++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (*p != '%') {
			*buff_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
			REMARKER((*in)->vb_strvalue, p - (*in)->vb_strvalue, "Non-hex char in %% sequence");
			talloc_free(buff);

			return XLAT_ACTION_FAIL;
		}
		p++;
		*buff_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Change case of a string
 *
 * If upper is true, change to uppercase, otherwise, change to lowercase
 *
 */
static xlat_action_t _xlat_change_case(bool upper, TALLOC_CTX *ctx, fr_cursor_t *out,
				       REQUEST *request, fr_value_box_t **in)
{
	char *buff, *buff_p;
	char const *p, *end;
	fr_value_box_t* vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	buff = buff_p = talloc_array(NULL, char, (*in)->vb_length + 1);

	while (p < end) {
		*(buff_p++) = upper ? toupper ((int) *(p++)) : tolower((int) *(p++));
	}

	*buff_p = '\0';

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Convert a string to lowercase
 *
 * Example: "%{tolower:Bar}" == "bar"
 *
 * Probably only works for ASCII
 */
static xlat_action_t xlat_func_tolower(TALLOC_CTX *ctx, fr_cursor_t *out,
				       REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	return _xlat_change_case(false, ctx, out, request, in);
}

/** Convert a string to uppercase
 *
 * Example: "%{toupper:Foo}" == "FOO"
 *
 * Probably only works for ASCII
 */
static xlat_action_t xlat_func_toupper(TALLOC_CTX *ctx, fr_cursor_t *out,
				       REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	return _xlat_change_case(true, ctx, out, request, in);
}


/** Calculate the MD4 hash of a string or attribute.
 *
 * Example: "%{md4:foo}" == "0ac6700c491d70fb8650940b1ca1e4b2"
 */
static xlat_action_t xlat_func_md4(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (*in) {
		fr_md4_calc(digest, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* Digest of empty string */
		fr_md4_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate the MD5 hash of a string or attribute.
 *
 * Example: "%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
 */
static xlat_action_t xlat_func_md5(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;

	/*
	 *	Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (*in) {
		fr_md5_calc(digest, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* Digest of empty string */
		fr_md5_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example: "%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
static xlat_action_t xlat_func_sha1(TALLOC_CTX *ctx, fr_cursor_t *out,
				    REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				    fr_value_box_t **in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	fr_sha1_ctx	sha1_ctx;
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	fr_sha1_init(&sha1_ctx);
	if (*in) {
		fr_sha1_update(&sha1_ctx, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* sha1 of empty string */
		fr_sha1_update(&sha1_ctx, NULL, 0);
	}
	fr_sha1_final(digest, &sha1_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example: "%{sha2_256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
#ifdef HAVE_OPENSSL_EVP_H
static xlat_action_t xlat_evp_md(TALLOC_CTX *ctx, fr_cursor_t *out,
			         REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			         fr_value_box_t **in, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen;
	EVP_MD_CTX	*md_ctx;
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	if (*in) {
		EVP_DigestUpdate(md_ctx, (*in)->vb_octets, (*in)->vb_length);
	} else {
		EVP_DigestUpdate(md_ctx, NULL, 0);
	}
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digestlen, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#  define EVP_MD_XLAT(_md, _md_func) \
static xlat_action_t xlat_func_##_md(TALLOC_CTX *ctx, fr_cursor_t *out,\
				      REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,\
				      fr_value_box_t **in)\
{\
	return xlat_evp_md(ctx, out, request, xlat_inst, xlat_thread_inst, in, EVP_##_md_func());\
}

EVP_MD_XLAT(sha2_224, sha224)
EVP_MD_XLAT(sha2_256, sha256)
EVP_MD_XLAT(sha2_384, sha384)
EVP_MD_XLAT(sha2_512, sha512)

#  ifdef HAVE_EVP_SHA3_512
EVP_MD_XLAT(sha3_224, sha3_224)
EVP_MD_XLAT(sha3_256, sha3_256)
EVP_MD_XLAT(sha3_384, sha3_384)
EVP_MD_XLAT(sha3_512, sha3_512)
#  endif
#endif

typedef enum {
	HMAC_MD5,
	HMAC_SHA1
} hmac_type;

static xlat_action_t _xlat_hmac(TALLOC_CTX *ctx, fr_cursor_t *out,
				REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				fr_value_box_t **in, uint8_t *digest, int digest_len, hmac_type type)
{
	uint8_t const	*data_p, *key_p;
	size_t		data_len, key_len;
	fr_value_box_t	*vb, *vb_data, *vb_sep, *vb_key;

	vb_data = fr_value_box_list_get(*in, 0);
	vb_sep = fr_value_box_list_get(*in, 1);
	vb_key = fr_value_box_list_get(*in, 2);

	if (!in || !vb_data || !vb_sep || !vb_key ||
            vb_sep->vb_length != 1 ||
            vb_sep->vb_strvalue[0] != ' ') {
		REDEBUG("HMAC requires exactly two arguments (%%{data} %%{key})");
		return XLAT_ACTION_FAIL;
	}

	data_p = vb_data->vb_octets;
	data_len = vb_data->vb_length;

	key_p = vb_key->vb_octets;
	key_len = vb_key->vb_length;

	if (type == HMAC_MD5) {
		fr_hmac_md5(digest, data_p, data_len, key_p, key_len);
	} else if (type == HMAC_SHA1) {
		fr_hmac_sha1(digest, data_p, data_len, key_p, key_len);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digest_len, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example: "%{hmacmd5:foo bar}" == "Zm9v"
 */
static xlat_action_t xlat_func_hmac_md5(TALLOC_CTX *ctx, fr_cursor_t *out,
					REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	return _xlat_hmac(ctx, out, request, xlat_inst, xlat_thread_inst, in, digest, MD5_DIGEST_LENGTH, HMAC_MD5);
}

/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example: "%{hmacsha1:foo bar}" == "Zm9v"
 */
static xlat_action_t xlat_func_hmac_sha1(TALLOC_CTX *ctx, fr_cursor_t *out,
					 REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					 fr_value_box_t **in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	return _xlat_hmac(ctx, out, request, xlat_inst, xlat_thread_inst, in, digest, SHA1_DIGEST_LENGTH, HMAC_SHA1);
}

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example: "%{pairs:request:}" == "User-Name = 'foo'User-Password = 'bar'"
 */
static xlat_action_t xlat_func_pairs(TALLOC_CTX *ctx, fr_cursor_t *out,
				     REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				     fr_value_box_t **in)
{
	vp_tmpl_t	*vpt = NULL;
	fr_cursor_t	cursor;
	char		*buff;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	VALUE_PAIR *vp;

	if (tmpl_afrom_attr_str(ctx, &vpt, (*in)->vb_strvalue,
				&(vp_tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = VP_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		FR_TOKEN op = vp->op;

		vp->op = T_OP_EQ;
		buff = fr_pair_asprint(ctx, vp, '"');
		vp->op = op;

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
		fr_value_box_bstrsteal(vb, vb, NULL, buff, false);

		fr_cursor_append(out, vb);
	}

	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}

/** Encode string or attribute as base64
 *
 * Example: "%{base64:foo}" == "Zm9v"
 */
static xlat_action_t xlat_func_base64_encode(TALLOC_CTX *ctx, fr_cursor_t *out,
					     REQUEST *request, UNUSED void const *xlat_inst,
					     UNUSED void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	size_t		alen;
	ssize_t		elen;
	char		*buff;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	alen = FR_BASE64_ENC_LENGTH((*in)->vb_length);
	MEM(buff = talloc_array(ctx, char, alen + 1));

	elen = fr_base64_encode(buff, alen + 1, (*in)->vb_octets, (*in)->vb_length);
	if (elen < 0) {
		RPEDEBUG("Base64 encoding failed");
		talloc_free(buff);
		return XLAT_ACTION_FAIL;
	}

	rad_assert((size_t)elen <= alen);

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_bstrsnteal(vb, vb, NULL, &buff, elen, (*in)->tainted) < 0) {
		RPEDEBUG("Failed assigning encoded data buffer to box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Decode base64 string
 *
 * Example: "%{base64decode:Zm9v}" == "foo"
 */
static xlat_action_t xlat_func_base64_decode(TALLOC_CTX *ctx, fr_cursor_t *out,
					     REQUEST *request, UNUSED void const *xlat_inst,
					     UNUSED void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	size_t		alen;
	ssize_t		declen;
	uint8_t		*decbuf;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	alen = FR_BASE64_DEC_LENGTH((*in)->vb_length);

	MEM(decbuf = talloc_array(ctx, uint8_t, alen));

	declen = fr_base64_decode(decbuf, alen, (*in)->vb_strvalue, (*in)->vb_length);
	if (declen < 0) {
		talloc_free(decbuf);
		REDEBUG("Base64 string invalid");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));

	/*
	 *	Should never fail as we're shrinking...
	 */
	if ((size_t)declen != alen) MEM(decbuf = talloc_realloc(ctx, decbuf, uint8_t, (size_t)declen));

	fr_value_box_memsteal(vb, vb, NULL, decbuf, (*in)->tainted);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Split an attribute into multiple new attributes based on a delimiter
 *
 * @todo should support multibyte delimiter for string types.
 *
 * Example: "%{explode:&ref <delim>}"
 */
static xlat_action_t xlat_func_explode(TALLOC_CTX *ctx, fr_cursor_t *out,
					REQUEST *request, UNUSED void const *xlat_inst,
					UNUSED void *xlat_thread_inst, fr_value_box_t **in)
{
	vp_tmpl_t	*vpt;
	fr_cursor_t	cursor, to_merge;
	fr_value_box_t  *vb;
	VALUE_PAIR	*vp, *head;
	ssize_t		slen, count = 0;
	char const	*p;
	char		delim;

	if (!*in) {
		REDEBUG("explode needs exactly two arguments: &ref <delim>");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}


	p = fr_value_box_list_get(*in, 0)->vb_strvalue;

	/*
	 *  Trim whitespace
	 */
	fr_skip_spaces(p);

	slen = tmpl_afrom_attr_substr(ctx, &vpt, p, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Invalid '%s' input", p);
		return XLAT_ACTION_FAIL;
	}

	p += slen;

	if (*p++ != ' ') {
	arg_error:
		talloc_free(vpt);
		REDEBUG("explode needs exactly two arguments: &ref <delim>");
		return XLAT_ACTION_FAIL;
	}

	if (*p == '\0') goto arg_error;

	delim = *p;

	fr_cursor_init(&to_merge, &head);

	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	while (vp) {
		VALUE_PAIR *nvp;
		char const *end;
		char const *q;

		/*
		 *	This can theoretically operate on lists too
		 *	so we need to check the type of each attribute.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			break;

		default:
			goto next;
		}

		p = vp->vp_ptr;
		end = p + vp->vp_length;
		while (p < end) {
			q = memchr(p, delim, end - p);
			if (!q) {
				/* Delimiter not present in attribute */
				if (p == vp->vp_ptr) goto next;
				q = end;
			}

			/* Skip zero length */
			if (q == p) {
				p = q + 1;
				continue;
			}

			nvp = fr_pair_afrom_da(talloc_parent(vp), vp->da);
			if (!nvp) {
				fr_pair_list_free(&head);
				goto arg_error;
			}
			nvp->tag = vp->tag;

			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
			{
				uint8_t *buff;

				buff = talloc_array(nvp, uint8_t, q - p);
				memcpy(buff, p, q - p);
				fr_pair_value_memsteal(nvp, buff);
			}
				break;

			case FR_TYPE_STRING:
			{
				char *buff;

				buff = talloc_array(nvp, char, (q - p) + 1);
				memcpy(buff, p, q - p);
				buff[q - p] = '\0';
				fr_pair_value_strsteal(nvp, (char *)buff);
			}
				break;

			default:
				rad_assert(0);
			}

			fr_cursor_append(&to_merge, nvp);

			p = q + 1;	/* next */

			count++;
		}

		/*
		 *	Remove the unexploded version
		 */
		vp = fr_cursor_remove(&cursor);
		talloc_free(vp);
		/*
		 *	Remove sets cursor->current to
		 *	the next iter value.
		 */
		vp = fr_cursor_current(&cursor);
		continue;

	next:
		vp = fr_cursor_next(&cursor);
	}

	fr_cursor_head(&to_merge);
	fr_cursor_merge(&cursor, &to_merge);
	talloc_free(vpt);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
	vb->vb_size = count;
	fr_cursor_insert(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %{nexttime:1h} would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 */
static ssize_t xlat_func_next_time(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				   REQUEST *request, char const *fmt)
{
	long		num;

	char const 	*p;
	char 		*q;
	time_t		now;
	struct tm	*local, local_buff;

	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = fmt;

	num = strtoul(p, &q, 10);
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
		return -1;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return -1;
	}

	return snprintf(*out, outlen, "%" PRIu64, (uint64_t)(mktime(local) - now));
}


/** Parse the 3 arguments to lpad / rpad.
 *
 * Parses a fmt string with the components @verbatim <tmpl> <pad_len> <pad_char>@endverbatim
 *
 * @param[out] vpt_p		Template to retrieve value to pad.
 * @param[out] pad_len_p	Length the string needs to be padded to.
 * @param[out] pad_char_p	Char to use for padding.
 * @param[in] request		The current request.
 * @param[in] fmt		string to parse.
 *
 * @return
 *	- <= 0 the negative offset the parse error ocurred at.
 *	- >0 how many bytes of fmt were parsed.
 */
static ssize_t parse_pad(vp_tmpl_t **vpt_p, size_t *pad_len_p, char *pad_char_p, REQUEST *request, char const *fmt)
{
	ssize_t		slen;
	unsigned long	pad_len;
	char const	*p;
	char		*end;
	vp_tmpl_t	*vpt;

	*pad_char_p = ' ';		/* the default */

	*vpt_p = NULL;

	p = fmt;
	fr_skip_spaces(p);

	if (*p != '&') {
		REDEBUG("First argument must be an attribute reference");
		return 0;
	}

	slen = tmpl_afrom_attr_substr(request, &vpt, p, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Failed parsing input string");
		return slen;
	}

	p = fmt + slen;

	fr_skip_spaces(p);

	pad_len = strtoul(p, &end, 10);
	if ((pad_len == ULONG_MAX) || (pad_len > 8192)) {
		talloc_free(vpt);
		REDEBUG("Invalid pad_len found at: %s", p);
		return fmt - p;
	}

	p += (end - p);

	/*
	 *	The pad_char_p character is optional.
	 *
	 *	But we must have a space after the previous number,
	 *	and we must have only ONE pad_char_p character.
	 */
	if (*p) {
		if (!isspace(*p)) {
			talloc_free(vpt);
			REDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		fr_skip_spaces(p);

		if (p[1] != '\0') {
			talloc_free(vpt);
			REDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		*pad_char_p = *p++;
	}

	*vpt_p = vpt;
	*pad_len_p = pad_len;

	return p - fmt;
}


/** left pad a string
 *
 *  %{lpad:&Attribute-Name length 'x'}
 */
static ssize_t xlat_func_lpad(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return -1;

	/*
	 *	Already big enough, no padding required...
	 */
	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	/*
	 *	Realloc is actually pretty cheap in most cases...
	 */
	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to shift the string to the right, and pad with
	 *	"fill" characters.
	 */
	memmove(to_pad + (pad - len), to_pad, len + 1);
	memset(to_pad, fill, pad - len);

	*out = to_pad;

	return pad;
}

/** right pad a string
 *
 *  %{rpad:&Attribute-Name length 'x'}
 */
static ssize_t xlat_func_rpad(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	rad_assert(!*out);

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return 0;

	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to pad with "fill" characters.
	 */
	memset(to_pad + len, fill, pad - len);
	to_pad[pad] = '\0';

	*out = to_pad;

	return pad;
}

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one, *b = two;
	size_t a_len, b_len;
	int ret;

	a_len = strlen(a->name);
	b_len = strlen(b->name);

	ret = (a_len > b_len) - (a_len < b_len);
	if (ret != 0) return ret;

	return memcmp(a->name, b->name, a_len);
}

/*
 *	find the appropriate registered xlat function.
 */
xlat_t *xlat_func_find(char const *name)
{
	xlat_t *found;

	if (!xlat_root) return NULL;

	found = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });

	return found;
}

/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_func_talloc_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	rbtree_deletebydata(xlat_root, xlat);
	if (rbtree_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
}

/** Callback for the rbtree to clear out any xlats still registered
 *
 */
static void _xlat_func_tree_free(void *xlat)
{
	talloc_free(xlat);
}

/** Register an xlat function.
 *
 * @param[in] mod_inst		Instance of module that's registering the xlat function.
 * @param[in] name		xlat name.
 * @param[in] func 		xlat function to be called.
 * @param[in] escape		function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instantiate	function to pre-parse any xlat specific data.
 * @param[in] inst_size		sizeof() this xlat's instance data.
 * @param[in] buf_len		Size of the output buffer to allocate when calling the function.
 *				May be 0 if the function allocates its own buffer.
 * @param[in] async_safe	whether or not the function is async-safe.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_register(void *mod_inst, char const *name,
		  xlat_func_sync_t func, xlat_escape_t escape,
		  xlat_instantiate_t instantiate, size_t inst_size,
		  size_t buf_len, bool async_safe)
{
	xlat_t	*c;
	bool	new = false;

	if (!xlat_root && (xlat_init() < 0)) return -1;;

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}

		if (c->async_safe != async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return -1;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(xlat_root, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		new = true;
	}

	c->func.sync = func;
	c->type = XLAT_FUNC_SYNC;
	c->buf_len = buf_len;
	c->escape = escape;
	c->mod_inst = mod_inst;
	c->instantiate = instantiate;
	c->inst_size = inst_size;
	c->async_safe = async_safe;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("Failed inserting xlat registration for %s",
		      c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
}

/** Register an async xlat
 *
 * All functions registered must be async_safe.
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
xlat_t const *xlat_async_register(TALLOC_CTX *ctx, char const *name, xlat_func_async_t func)
{
	xlat_t	*c;
	bool	new = false;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return NULL;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return NULL;
		}

		if (!c->async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return NULL;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(ctx, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		new = true;
	}

	c->func.async = func;
	c->type = XLAT_FUNC_ASYNC;
	c->async_safe = false;	/* async safe in this case means it might yield */

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return NULL;
	}

	return c;
}

/** Set global instantiation/detach callbacks
 *
 * All functions registered must be async_safe.
 *
 * @param[in] xlat		to set instantiation callbacks for.
 * @param[in] instantiate	Instantiation function. Called whenever a xlat is
 *				compiled.
 * @param[in] inst_type		Name of the instance structure.
 * @param[in] inst_size		The size of the instance struct.
 *				Pre-allocated for use by the instantiate function.
 *				If 0, no memory will be allocated.
 * @param[in] detach		Called when an xlat_exp_t is freed.
 * @param[in] uctx		Passed to the instantiation function.
 */
void _xlat_async_instantiate_set(xlat_t const *xlat,
				 xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
				 xlat_detach_t detach,
				 void *uctx)
{
	xlat_t *c;

	memcpy(&c, &xlat, sizeof(c));

	c->instantiate = instantiate;
	c->inst_type = inst_type;
	c->inst_size = inst_size;
	c->detach = detach;
	c->uctx = uctx;
}

/** Register an async xlat
 *
 * All functions registered must be async_safe.
 *
 * @param[in] xlat			to set instantiation callbacks for.
 * @param[in] thread_instantiate	Instantiation function. Called for every compiled xlat
 *					every time a thread is started.
 * @param[in] thread_inst_type		Name of the thread instance structure.
 * @param[in] thread_inst_size		The size of the thread instance struct.
 *					Pre-allocated for use by the instantiate function.
 *					If 0, no memory will be allocated.
 * @param[in] thread_detach		Called when the thread is freed.
 * @param[in] uctx			Passed to the thread instantiate function.
 */
void _xlat_async_thread_instantiate_set(xlat_t const *xlat,
					xlat_thread_instantiate_t thread_instantiate,
				        char const *thread_inst_type, size_t thread_inst_size,
				        xlat_thread_detach_t thread_detach,
				        void *uctx)
{
	xlat_t *c;

	memcpy(&c, &xlat, sizeof(c));

	c->thread_instantiate = thread_instantiate;
	c->thread_inst_type = thread_inst_type;
	c->thread_inst_size = thread_inst_size;
	c->thread_detach = thread_detach;
	c->thread_uctx = uctx;
}

/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 */
void xlat_unregister(char const *name)
{
	xlat_t	*c;

	if (!name || !xlat_root) return;

	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (!c) return;

	(void) talloc_get_type_abort(c, xlat_t);

	talloc_free(c);	/* Should also remove from tree */
}

static int _xlat_unregister_callback(void *mod_inst, void *data)
{
	xlat_t *c = (xlat_t *) data;

	if (c->mod_inst != mod_inst) return 0; /* keep walking */

	return 2;		/* delete it */
}

void xlat_unregister_module(void *instance)
{
	if (!xlat_root) return;	/* All xlats have already been freed */

	rbtree_walk(xlat_root, RBTREE_DELETE_ORDER, _xlat_unregister_callback, instance);
}

/*
 *	Internal redundant handler for xlats
 */
typedef enum xlat_redundant_type_t {
	XLAT_INVALID = 0,
	XLAT_REDUNDANT,
	XLAT_LOAD_BALANCE,
	XLAT_REDUNDANT_LOAD_BALANCE,
} xlat_redundant_type_t;

typedef struct {
	xlat_redundant_type_t		type;
	uint32_t			count;
	CONF_SECTION const		*cs;
} xlat_redundant_t;

static ssize_t xlat_redundant(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
			      void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	char const *name;
	xlat_t *xlat;

	rad_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */
	rad_assert(xr->type == XLAT_REDUNDANT);

	/*
	 *	Pick the first xlat which succeeds
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		ssize_t rcode;

		if (!cf_item_is_pair(ci)) continue;

		name = cf_pair_attr(cf_item_to_pair(ci));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (!xlat) continue;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}

		rcode = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (rcode <= 0) {
			TALLOC_FREE(*out);
			continue;
		}
		return rcode;
	}

	/*
	 *	Everything failed.  Oh well.
	 */
	*out = NULL;
	return 0;
}

static xlat_action_t xlat_func_concat(TALLOC_CTX *ctx, fr_cursor_t *out,
				      REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      fr_value_box_t **in)
{
	fr_value_box_t *result;
	fr_value_box_t *separator;
	char *buff;
	char const *sep;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	/*
	 * Separator is first value box
	 */
	separator = *in;

	if (!separator) {
		REDEBUG("Missing separator for concat xlat");
		return XLAT_ACTION_FAIL;
	}

	sep = separator->vb_strvalue;

	result = fr_value_box_alloc_null(ctx);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_asprint(result, (*in)->next, sep, '\0');
	if (!buff) goto error;

	fr_value_box_bstrsteal(result, result, NULL, buff, fr_value_box_list_tainted((*in)->next));

	fr_cursor_append(out, result);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_bin(TALLOC_CTX *ctx, fr_cursor_t *out,
				   REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	fr_value_box_t	*result;
	char		*buff = NULL, *p, *end;
	uint8_t		*bin;
	size_t		len, outlen;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	buff = fr_value_box_list_asprint(NULL, *in, NULL, '\0');
	if (!buff) return XLAT_ACTION_FAIL;

	len = talloc_array_length(buff) - 1;
	if ((len > 1) && (len & 0x01)) {
		REDEBUG("Input data length must be >1 and even, got %zu", len);
		talloc_free(buff);
		return XLAT_ACTION_FAIL;
	}

	p = buff;
	end = p + len;

	/*
	 *	Zero length octets string
	 */
	if ((p[0] == '0') && (p[1] == 'x')) p += 2;
	if (p == end) goto finish;

	outlen = len / 2;

	MEM(result = fr_value_box_alloc_null(ctx));
	MEM(bin = talloc_array(result, uint8_t, outlen));

	fr_hex2bin(bin, outlen, p, end - p);
	fr_value_box_memsteal(result, result, NULL, bin, fr_value_box_list_tainted(*in));
	fr_cursor_append(out, result);

finish:
	talloc_free(buff);
	return XLAT_ACTION_DONE;
}


static ssize_t xlat_load_balance(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
				 void const *mod_inst, UNUSED void const *xlat_inst,
				 REQUEST *request, char const *fmt)
{
	uint32_t count = 0;
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	CONF_ITEM *found = NULL;
	char const *name;
	xlat_t *xlat;

	rad_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */

	/*
	 *	Choose a child at random.
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		if (!cf_item_is_pair(ci)) continue;
		count++;

		/*
		 *	Replace the previously found one with a random
		 *	new one.
		 */
		if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
			found = ci;
		}
	}

	/*
	 *	Plain load balancing: do one child, and only one child.
	 */
	if (xr->type == XLAT_LOAD_BALANCE) {
		ssize_t slen;
		name = cf_pair_attr(cf_item_to_pair(found));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (!xlat) return -1;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}
		slen = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (slen <= 0) TALLOC_FREE(*out);

		return slen;
	}

	rad_assert(xr->type == XLAT_REDUNDANT_LOAD_BALANCE);

	/*
	 *	Try the random one we found.  If it fails, keep going
	 *	through the rest of the children.
	 */
	ci = found;
	do {
		name = cf_pair_attr(cf_item_to_pair(ci));
		rad_assert(name != NULL);

		xlat = xlat_func_find(name);
		if (xlat) {
			ssize_t rcode;

			if (xlat->buf_len > 0) {
				*out = talloc_array(ctx, char, xlat->buf_len);
				**out = '\0';	/* Be sure the string is \0 terminated */
			} else {
				*out = NULL;
			}
			rcode = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
			if (rcode > 0) return rcode;
			TALLOC_FREE(*out);
		}

		/*
		 *	Go to the next one, wrapping around at the end.
		 */
		ci = cf_item_next(xr->cs, ci);
		if (!ci) ci = cf_item_next(xr->cs, NULL);
	} while (ci != found);

	return -1;
}

/** Registers a redundant xlat
 *
 * These xlats wrap the xlat methods of the modules in a redundant section,
 * emulating the behaviour of a redundant section, but over xlats.
 *
 * @todo - make xlat_register() take ASYNC / SYNC / UNKNOWN.  We may
 * need "unknown" here in order to properly handle the children, which
 * we don't know are async-safe or not.  For now, it's best to assume
 * that all xlat's in a redundant block are module calls, and are not async-safe
 *
 * @return
 *	- 0 on success.
 *	- -1 on error.
 *	- 1 if the modules in the section do not have an xlat method.
 */
int xlat_register_redundant(CONF_SECTION *cs)
{
	char const *name1, *name2;
	xlat_redundant_t *xr;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (xlat_func_find(name2)) {
		cf_log_err(cs, "An expansion is already registered for this name");
		return -1;
	}

	MEM(xr = talloc_zero(cs, xlat_redundant_t));

	if (strcmp(name1, "redundant") == 0) {
		xr->type = XLAT_REDUNDANT;
	} else if (strcmp(name1, "redundant-load-balance") == 0) {
		xr->type = XLAT_REDUNDANT_LOAD_BALANCE;
	} else if (strcmp(name1, "load-balance") == 0) {
		xr->type = XLAT_LOAD_BALANCE;
	} else {
		rad_assert(0);
	}

	xr->cs = cs;

	/*
	 *	Get the number of children for load balancing.
	 */
	if (xr->type == XLAT_REDUNDANT) {
		if (xlat_register(xr, name2, xlat_redundant, NULL, NULL, 0, 0, false) < 0) {
			ERROR("Registering xlat for redundant section failed");
			talloc_free(xr);
			return -1;
		}

	} else {
		CONF_ITEM *ci = NULL;

		while ((ci = cf_item_next(cs, ci))) {
			char const *attr;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));

			/*
			 *	This is ok, it just means the module
			 *	doesn't have an xlat method.
			 */
			if (!xlat_func_find(attr)) {
				talloc_free(xr);
				return 1;
			}

			xr->count++;
		}

		if (xlat_register(xr, name2, xlat_load_balance, NULL, NULL, 0, 0, false) < 0) {
			ERROR("Registering xlat for load-balance section failed");
			talloc_free(xr);
			return -1;
		}
	}

	return 0;
}

/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_init(void)
{
	xlat_t	*c;

#ifdef WITH_UNLANG
	int i;
#endif
	if (xlat_root) return 0;

	/*
	 *	Lookup attributes used by virtual xlat expansions.
	 */
	if (xlat_eval_init() < 0) return -1;

	/*
	 *	Registers async xlat operations in the `unlang` interpreter.
	 */
	unlang_xlat_init();

	/*
	 *	Create the function tree
	 */
	xlat_root = rbtree_talloc_create(NULL, xlat_cmp, xlat_t, _xlat_func_tree_free, RBTREE_FLAG_REPLACE);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

#ifdef WITH_UNLANG
	for (i = 0; xlat_foreach_names[i] != NULL; i++) {
		xlat_register(&xlat_foreach_inst[i], xlat_foreach_names[i], xlat_foreach, NULL, NULL, 0, 0, true);
		c = xlat_func_find(xlat_foreach_names[i]);
		rad_assert(c != NULL);
		c->internal = true;
	}
#endif

#define XLAT_REGISTER(_x) xlat_register(NULL, STRINGIFY(_x), xlat_func_ ## _x, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true); \
	c = xlat_func_find(STRINGIFY(_x)); \
	rad_assert(c != NULL); \
	c->internal = true

	XLAT_REGISTER(integer);
	XLAT_REGISTER(xlat);
	XLAT_REGISTER(map);
	XLAT_REGISTER(debug_attr);

	xlat_register(NULL, "nexttime", xlat_func_next_time, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(NULL, "lpad", xlat_func_lpad, NULL, NULL, 0, 0, true);
	xlat_register(NULL, "rpad", xlat_func_rpad, NULL, NULL, 0, 0, true);

	xlat_register(&xlat_foreach_inst[0], "debug", xlat_func_debug, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	c = xlat_func_find("debug");
	rad_assert(c != NULL);
	c->internal = true;

	xlat_async_register(NULL, "explode", xlat_func_explode);
	xlat_async_register(NULL, "base64", xlat_func_base64_encode);
	xlat_async_register(NULL, "base64decode", xlat_func_base64_decode);
	xlat_async_register(NULL, "bin", xlat_func_bin);
	xlat_async_register(NULL, "concat", xlat_func_concat);
	xlat_async_register(NULL, "hex", xlat_func_hex);
	xlat_async_register(NULL, "hmacmd5", xlat_func_hmac_md5);
	xlat_async_register(NULL, "hmacsha1", xlat_func_hmac_sha1);
	xlat_async_register(NULL, "length", xlat_func_length);
	xlat_async_register(NULL, "md4", xlat_func_md4);
	xlat_async_register(NULL, "md5", xlat_func_md5);
	xlat_async_register(NULL, "module", xlat_func_module);
	xlat_async_register(NULL, "pairs", xlat_func_pairs);
	xlat_async_register(NULL, "rand", xlat_func_rand);
	xlat_async_register(NULL, "randstr", xlat_func_randstr);
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	xlat_async_register(NULL, "regex", xlat_func_regex);
#endif
	xlat_async_register(NULL, "sha1", xlat_func_sha1);

#ifdef HAVE_OPENSSL_EVP_H
	xlat_async_register(NULL, "sha2_224", xlat_func_sha2_224);
	xlat_async_register(NULL, "sha2_256", xlat_func_sha2_256);
	xlat_async_register(NULL, "sha2_384", xlat_func_sha2_384);
	xlat_async_register(NULL, "sha2_512", xlat_func_sha2_512);

#  ifdef HAVE_EVP_SHA3_512
	xlat_async_register(NULL, "sha3_224", xlat_func_sha3_224);
	xlat_async_register(NULL, "sha3_256", xlat_func_sha3_256);
	xlat_async_register(NULL, "sha3_384", xlat_func_sha3_384);
	xlat_async_register(NULL, "sha3_512", xlat_func_sha3_512);
#  endif
#endif

	xlat_async_register(NULL, "string", xlat_func_string);
	xlat_async_register(NULL, "strlen", xlat_func_strlen);
	xlat_async_register(NULL, "tag", xlat_func_tag);
	xlat_async_register(NULL, "tolower", xlat_func_tolower);
	xlat_async_register(NULL, "toupper", xlat_func_toupper);
	xlat_async_register(NULL, "urlquote", xlat_func_urlquote);
	xlat_async_register(NULL, "urlunquote", xlat_func_urlunquote);

	return 0;
}

/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	rbtree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */

	if (!xr) return;

	xlat_root = NULL;
	talloc_free(xr);

	xlat_eval_free();
}
