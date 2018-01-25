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
 * @file xlat.c
 * @brief String expansion ("translation"). Implements %Attribute -> value
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/base64.h>

#include <ctype.h>

typedef struct xlat_t {
	char			name[MAX_STRING_LEN];	//!< Name of the xlat expansion.
	int			length;			//!< Length of name.
	void			*instance;		//!< Module instance passed to xlat and escape functions.
	xlat_func_t		func;			//!< xlat function.
	xlat_escape_t	escape;			//!< Escape function to apply to dynamic input to func.
	bool			internal;		//!< If true, cannot be redefined.
} xlat_t;

typedef enum {
	XLAT_LITERAL,		//!< Literal string
	XLAT_PERCENT,		//!< Literal string with %v
	XLAT_MODULE,		//!< xlat module
	XLAT_VIRTUAL,		//!< virtual attribute
	XLAT_ATTRIBUTE,		//!< xlat attribute
#ifdef HAVE_REGEX
	XLAT_REGEX,		//!< regex reference
#endif
	XLAT_ALTERNATE		//!< xlat conditional syntax :-
} xlat_state_t;

struct xlat_exp {
	char const *fmt;	//!< The format string.
	size_t len;		//!< Length of the format string.

	xlat_state_t type;	//!< type of this expansion.
	xlat_exp_t *next;	//!< Next in the list.

	xlat_exp_t *child;	//!< Nested expansion.
	xlat_exp_t *alternate;	//!< Alternative expansion if this one expanded to a zero length string.

	vp_tmpl_t attr;	//!< An attribute template.
	xlat_t const *xlat;	//!< The xlat expansion to expand format with.
};

typedef struct xlat_out {
	char const *out;	//!< Output data.
	size_t len;		//!< Length of the output string.
} xlat_out_t;

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


static int xlat_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

/** Print length of its RHS.
 *
 */
static ssize_t xlat_strlen(UNUSED void *instance, UNUSED REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	snprintf(out, outlen, "%u", (unsigned int) strlen(fmt));
	return strlen(out);
}

/** Print the size of the attribute in bytes.
 *
 */
static ssize_t xlat_length(UNUSED void *instance, REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;
	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	snprintf(out, outlen, "%zu", vp->vp_length);
	return strlen(out);
}

/** Print data as integer, not as VALUE.
 *
 */
static ssize_t xlat_integer(UNUSED void *instance, REQUEST *request,
			    char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR 	*vp;

	uint64_t 	int64 = 0;	/* Needs to be initialised to zero */
	uint32_t	int32 = 0;	/* Needs to be initialised to zero */

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	switch (vp->da->type) {
	case PW_TYPE_OCTETS:
	case PW_TYPE_STRING:
		if (vp->vp_length > 8) {
			break;
		}

		if (vp->vp_length > 4) {
			memcpy(&int64, vp->vp_octets, vp->vp_length);
			return snprintf(out, outlen, "%" PRIu64, htonll(int64));
		}

		memcpy(&int32, vp->vp_octets, vp->vp_length);
		return snprintf(out, outlen, "%i", htonl(int32));

	case PW_TYPE_INTEGER64:
		return snprintf(out, outlen, "%" PRIu64, vp->vp_integer64);

	/*
	 *	IP addresses are treated specially, as parsing functions assume the value
	 *	is bigendian and will convert it for us.
	 */
	case PW_TYPE_IPV4_ADDR:
		return snprintf(out, outlen, "%u", htonl(vp->vp_ipaddr));

	case PW_TYPE_IPV4_PREFIX:
		return snprintf(out, outlen, "%u", htonl((*(uint32_t *)(vp->vp_ipv4prefix + 2))));

	case PW_TYPE_INTEGER:
		return snprintf(out, outlen, "%u", vp->vp_integer);

	case PW_TYPE_DATE:
		return snprintf(out, outlen, "%u", vp->vp_date);

	case PW_TYPE_BYTE:
		return snprintf(out, outlen, "%u", (unsigned int) vp->vp_byte);

	case PW_TYPE_SHORT:
		return snprintf(out, outlen, "%u", (unsigned int) vp->vp_short);

	/*
	 *	Ethernet is weird... It's network related, so we assume to it should be
	 *	bigendian.
	 */
	case PW_TYPE_ETHERNET:
		memcpy(&int64, vp->vp_ether, vp->vp_length);
		return snprintf(out, outlen, "%" PRIu64, htonll(int64));

	case PW_TYPE_SIGNED:
		return snprintf(out, outlen, "%i", vp->vp_signed);

	case PW_TYPE_IPV6_ADDR:
		return fr_prints_uint128(out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6addr));

	case PW_TYPE_IPV6_PREFIX:
		return fr_prints_uint128(out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6prefix[2]));

	default:
		break;
	}

	REDEBUG("Type '%s' of length %zu cannot be converted to integer",
		fr_int2str(dict_attr_types, vp->da->type, "???"), vp->vp_length);
	*out = '\0';

	return -1;
}

/** Print data as hex, not as VALUE.
 *
 */
static ssize_t xlat_hex(UNUSED void *instance, REQUEST *request,
			char const *fmt, char *out, size_t outlen)
{
	size_t i;
	VALUE_PAIR *vp;
	uint8_t const *p;
	ssize_t	ret;
	size_t	len;
	value_data_t dst;
	uint8_t const *buff = NULL;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
	error:
		*out = '\0';
		return -1;
	}

	/*
	 *	The easy case.
	 */
	if (vp->da->type == PW_TYPE_OCTETS) {
		p = vp->vp_octets;
		len = vp->vp_length;
	/*
	 *	Cast the value_data_t of the VP to an octets string and
	 *	print that as hex.
	 */
	} else {
		ret = value_data_cast(request, &dst, PW_TYPE_OCTETS, NULL, vp->da->type,
				      NULL, &vp->data, vp->vp_length);
		if (ret < 0) {
			REDEBUG("%s", fr_strerror());
			goto error;
		}
		len = (size_t) ret;
		p = buff = dst.octets;
	}

	rad_assert(p);

	/*
	 *	Don't truncate the data.
	 */
	if (outlen < (len * 2)) {
		rad_const_free(buff);
		goto error;
	}

	for (i = 0; i < len; i++) {
		snprintf(out + 2*i, 3, "%02x", p[i]);
	}
	rad_const_free(buff);

	return len * 2;
}

/** Return the tag of an attribute reference
 *
 */
static ssize_t xlat_tag(UNUSED void *instance, REQUEST *request,
		        char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	if (!vp->da->flags.has_tag || !TAG_VALID(vp->tag)) {
		*out = '\0';
		return 0;
	}

	return snprintf(out, outlen, "%u", vp->tag);
}

/** Return the vendor of an attribute reference
 *
 */
static ssize_t xlat_vendor(UNUSED void *instance, REQUEST *request,
		           char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;
	DICT_VENDOR *vendor;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	vendor = dict_vendorbyvalue(vp->da->vendor);
	if (!vendor) {
		*out = '\0';
		return 0;
	}
	strlcpy(out, vendor->name, outlen);

	return vendor->length;
}

/** Return the vendor number of an attribute reference
 *
 */
static ssize_t xlat_vendor_num(UNUSED void *instance, REQUEST *request,
		               char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	return snprintf(out, outlen, "%u", vp->da->vendor);
}

/** Return the attribute name of an attribute reference
 *
 */
static ssize_t xlat_attr(UNUSED void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}
	strlcpy(out, vp->da->name, outlen);

	return strlen(vp->da->name);
}

/** Return the attribute number of an attribute reference
 *
 */
static ssize_t xlat_attr_num(UNUSED void *instance, REQUEST *request,
		             char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	return snprintf(out, outlen, "%u", vp->da->attr);
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
static ssize_t xlat_debug_attr(UNUSED void *instance, REQUEST *request, char const *fmt,
			       char *out, UNUSED size_t outlen)
{
	VALUE_PAIR *vp;
	vp_cursor_t cursor;

	vp_tmpl_t vpt;

	if (!RDEBUG_ENABLED2) {
		*out = '\0';
		return -1;
	}

	while (isspace((int) *fmt)) fmt++;

	if (tmpl_from_attr_str(&vpt, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
		RDEBUG("%s", fr_strerror());
		return -1;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_cursor_init(NULL, &cursor, request, &vpt);
	     vp;
	     vp = tmpl_cursor_next(&cursor, &vpt)) {
		FR_NAME_NUMBER const *type;
		char *value;

		value = vp_aprints_value(vp, vp, '\'');
		if (vp->da->flags.has_tag) {
			RIDEBUG2("&%s:%s:%i %s %s",
				fr_int2str(pair_lists, vpt.tmpl_list, "<INVALID>"),
				vp->da->name,
				vp->tag,
				fr_int2str(fr_tokens, vp->op, "<INVALID>"),
				value);
		} else {
			RIDEBUG2("&%s:%s %s %s",
				fr_int2str(pair_lists, vpt.tmpl_list, "<INVALID>"),
				vp->da->name,
				fr_int2str(fr_tokens, vp->op, "<INVALID>"),
				value);
		}
		talloc_free(value);

		if (!RDEBUG_ENABLED3) continue;

		if (vp->da->vendor) {
			DICT_VENDOR *dv;

			dv = dict_vendorbyvalue(vp->da->vendor);
			RIDEBUG2("Vendor : %i (%s)", vp->da->vendor, dv ? dv->name : "unknown");
		}
		RIDEBUG2("Type   : %s", fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
		RIDEBUG2("Length : %zu", vp->vp_length);

		if (!RDEBUG_ENABLED4) continue;

		type = dict_attr_types;
		while (type->name) {
			int pad;

			value_data_t *dst = NULL;

			ssize_t ret;

			if ((PW_TYPE) type->number == vp->da->type) {
				goto next_type;
			}

			switch (type->number) {
			case PW_TYPE_INVALID:		/* Not real type */
			case PW_TYPE_MAX:		/* Not real type */
			case PW_TYPE_EXTENDED:		/* Not safe/appropriate */
			case PW_TYPE_LONG_EXTENDED:	/* Not safe/appropriate */
			case PW_TYPE_TLV:		/* Not safe/appropriate */
			case PW_TYPE_EVS:		/* Not safe/appropriate */
			case PW_TYPE_VSA:		/* @fixme We need special behaviour for these */
			case PW_TYPE_COMBO_IP_ADDR:	/* Covered by IPv4 address IPv6 address */
			case PW_TYPE_COMBO_IP_PREFIX:	/* Covered by IPv4 address IPv6 address */
			case PW_TYPE_TIMEVAL:		/* Not a VALUE_PAIR type */
				goto next_type;

			default:
				break;
			}

			dst = talloc_zero(vp, value_data_t);
			ret = value_data_cast(dst, dst, type->number, NULL, vp->da->type, vp->da,
					      &vp->data, vp->vp_length);
			if (ret < 0) goto next_type;	/* We expect some to fail */

			value = value_data_aprints(dst, type->number, NULL, dst, (size_t)ret, '\'');
			if (!value) goto next_type;

			if ((pad = (11 - strlen(type->name))) < 0) {
				pad = 0;
			}

			RINDENT();
			RDEBUG2("as %s%*s: %s", type->name, pad, " ", value);
			REXDENT();

		next_type:
			talloc_free(dst);
			type++;
		}
	}

	*out = '\0';
	return 0;
}

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g. "%{map:&User-Name := 'foo'}"
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 */
static ssize_t xlat_map(UNUSED void *instance, REQUEST *request,
			char const *fmt, char *out, size_t outlen)
{
	vp_map_t *map = NULL;
	int ret;

	if (map_afrom_attr_str(request, &map, fmt,
			       REQUEST_CURRENT, PAIR_LIST_REQUEST,
			       REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		REDEBUG("Failed parsing \"%s\" as map: %s", fmt, fr_strerror());
		return -1;
	}

	RINDENT();
	ret = map_to_request(request, map, map_to_vp, NULL);
	REXDENT();
	talloc_free(map);
	if (ret < 0) return strlcpy(out, "0", outlen);

	return strlcpy(out, "1", outlen);
}

/** Prints the current module processing the request
 *
 */
static ssize_t xlat_module(UNUSED void *instance, REQUEST *request,
			   UNUSED char const *fmt, char *out, size_t outlen)
{
	strlcpy(out, request->module, outlen);

	return strlen(out);
}

#if defined(HAVE_REGEX) && defined(HAVE_PCRE)
static ssize_t xlat_regex(UNUSED void *instance, REQUEST *request,
			  char const *fmt, char *out, size_t outlen)
{
	char *p;
	size_t len;

	if (regex_request_to_sub_named(request, &p, request, fmt) < 0) {
		*out = '\0';
		return 0;
	}

	len = talloc_array_length(p);
	if (len > outlen) {
		RDEBUG("Insufficient buffer space to write subcapture value, needed %zu bytes, have %zu bytes",
		       len, outlen);
		return -1;
	}
	strlcpy(out, p, outlen);

	return len - 1; /* - \0 */
}
#endif

#ifdef WITH_UNLANG
/** Implements the Foreach-Variable-X
 *
 * @see modcall()
 */
static ssize_t xlat_foreach(void *instance, REQUEST *request,
			    UNUSED char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR	**pvp;
	size_t		len;

	/*
	 *	See modcall, "FOREACH" for how this works.
	 */
	pvp = (VALUE_PAIR **) request_data_reference(request, (void *)radius_get_vp, *(int*) instance);
	if (!pvp || !*pvp) {
		*out = '\0';
		return 0;
	}

	len = vp_prints_value(out, outlen, *pvp, 0);
	if (is_truncated(len, outlen)) {
		RDEBUG("Insufficient buffer space to write foreach value");
		return -1;
	}

	return len;
}
#endif

/** Print data as string, if possible.
 *
 * If attribute "Foo" is defined as "octets" it will normally
 * be printed as 0x0a0a0a. The xlat "%{string:Foo}" will instead
 * expand to "\n\n\n"
 */
static ssize_t xlat_string(UNUSED void *instance, REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	size_t len;
	ssize_t ret;
	VALUE_PAIR *vp;
	uint8_t const *p;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		*out = '\0';
		return 0;
	}

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	ret = rad_vp2data(&p, vp);
	if (ret < 0) {
		return ret;
	}

	switch (vp->da->type) {
	case PW_TYPE_OCTETS:
		len = fr_prints(out, outlen, (char const *) p, vp->vp_length, '"');
		break;

		/*
		 *	Note that "%{string:...}" is NOT binary safe!
		 *	It is explicitly used to get rid of embedded zeros.
		 */
	case PW_TYPE_STRING:
		len = strlcpy(out, vp->vp_strvalue, outlen);
		break;

	default:
		len = fr_prints(out, outlen, (char const *) p, ret, '\0');
		break;
	}

	return len;
}

/** xlat expand string attribute value
 *
 */
static ssize_t xlat_xlat(UNUSED void *instance, REQUEST *request,
			char const *fmt, char *out, size_t outlen)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		*out = '\0';
		return 0;
	}

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	if (vp->da->type != PW_TYPE_STRING) goto nothing;

	return radius_xlat(out, outlen, request, vp->vp_strvalue, NULL, NULL);
}

/** Dynamically change the debugging level for the current request
 *
 * Example %{debug:3}
 */
static ssize_t xlat_debug(UNUSED void *instance, REQUEST *request,
			  char const *fmt, char *out, size_t outlen)
{
	int level = 0;

	/*
	 *  Expand to previous (or current) level
	 */
	snprintf(out, outlen, "%d", request->log.lvl);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;

	level = atoi(fmt);
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
		request->log.func = NULL;
	} else {
		if (level > 4) level = 4;

		request->log.lvl = level;
		request->log.func = vradlog_request;
	}

	done:
	return strlen(out);
}

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one;
	xlat_t const *b = two;

	if (a->length != b->length) {
		return a->length - b->length;
	}

	return memcmp(a->name, b->name, a->length);
}


/*
 *	find the appropriate registered xlat function.
 */
static xlat_t *xlat_find(char const *name)
{
	xlat_t my_xlat;

	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);

	return rbtree_finddata(xlat_root, &my_xlat);
}


/** Register an xlat function.
 *
 * @param[in] name xlat name.
 * @param[in] func xlat function to be called.
 * @param[in] escape function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instance of module that's registering the xlat function.
 * @return 0 on success, -1 on failure
 */
int xlat_register(char const *name, xlat_func_t func, xlat_escape_t escape, void *instance)
{
	xlat_t	*c;
	xlat_t	my_xlat;
	rbnode_t *node;

	if (!name || !*name) {
		DEBUG("xlat_register: Invalid xlat name");
		return -1;
	}

	/*
	 *	First time around, build up the tree...
	 *
	 *	FIXME: This code should be hoisted out of this function,
	 *	and into a global "initialization".  But it isn't critical...
	 */
	if (!xlat_root) {
#ifdef WITH_UNLANG
		int i;
#endif

		xlat_root = rbtree_create(NULL, xlat_cmp, NULL, RBTREE_FLAG_REPLACE);
		if (!xlat_root) {
			DEBUG("xlat_register: Failed to create tree");
			return -1;
		}

#ifdef WITH_UNLANG
		for (i = 0; xlat_foreach_names[i] != NULL; i++) {
			xlat_register(xlat_foreach_names[i],
				      xlat_foreach, NULL, &xlat_inst[i]);
			c = xlat_find(xlat_foreach_names[i]);
			rad_assert(c != NULL);
			c->internal = true;
		}
#endif

#define XLAT_REGISTER(_x) xlat_register(STRINGIFY(_x), xlat_ ## _x, NULL, NULL); \
		c = xlat_find(STRINGIFY(_x)); \
		rad_assert(c != NULL); \
		c->internal = true

		XLAT_REGISTER(integer);
		XLAT_REGISTER(strlen);
		XLAT_REGISTER(length);
		XLAT_REGISTER(hex);
		XLAT_REGISTER(tag);
		XLAT_REGISTER(vendor);
		XLAT_REGISTER(vendor_num);
		XLAT_REGISTER(attr);
		XLAT_REGISTER(attr_num);
		XLAT_REGISTER(string);
		XLAT_REGISTER(xlat);
		XLAT_REGISTER(map);
		XLAT_REGISTER(module);
		XLAT_REGISTER(debug_attr);
#if defined(HAVE_REGEX) && defined(HAVE_PCRE)
		XLAT_REGISTER(regex);
#endif

		xlat_register("debug", xlat_debug, NULL, &xlat_inst[0]);
		c = xlat_find("debug");
		rad_assert(c != NULL);
		c->internal = true;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);
	c = rbtree_finddata(xlat_root, &my_xlat);
	if (c) {
		if (c->internal) {
			DEBUG("xlat_register: Cannot re-define internal xlat");
			return -1;
		}

		c->func = func;
		c->escape = escape;
		c->instance = instance;
		return 0;
	}

	/*
	 *	Doesn't exist.  Create it.
	 */
	c = talloc_zero(xlat_root, xlat_t);

	c->func = func;
	c->escape = escape;
	strlcpy(c->name, name, sizeof(c->name));
	c->length = strlen(c->name);
	c->instance = instance;

	node = rbtree_insert_node(xlat_root, c);
	if (!node) {
		talloc_free(c);
		return -1;
	}

	/*
	 *	Ensure that the data is deleted when the node is
	 *	deleted.
	 *
	 *	@todo: Maybe this should be the other way around...
	 *	when a thing IN the tree is deleted, it's automatically
	 *	removed from the tree.  But for now, this works.
	 */
	(void) talloc_steal(node, c);
	return 0;
}

/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 * @param[in] func unused.
 * @param[in] instance data.
 */
void xlat_unregister(char const *name, UNUSED xlat_func_t func, void *instance)
{
	xlat_t	*c;
	xlat_t		my_xlat;

	if (!name || !xlat_root) return;

	strlcpy(my_xlat.name, name, sizeof(my_xlat.name));
	my_xlat.length = strlen(my_xlat.name);

	c = rbtree_finddata(xlat_root, &my_xlat);
	if (!c) return;

	if (c->instance != instance) return;

	rbtree_deletebydata(xlat_root, c);
}

static int xlat_unregister_callback(void *instance, void *data)
{
	xlat_t *c = (xlat_t *) data;

	if (c->instance != instance) return 0; /* keep walking */

	return 2;		/* delete it */
}

void xlat_unregister_module(void *instance)
{
	rbtree_walk(xlat_root, RBTREE_DELETE_ORDER, xlat_unregister_callback, instance);
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

typedef struct xlat_redundant_t {
	xlat_redundant_type_t type;
	uint32_t	count;
	CONF_SECTION *cs;
} xlat_redundant_t;


static ssize_t xlat_redundant(void *instance, REQUEST *request,
			      char const *fmt, char *out, size_t outlen)
{
	xlat_redundant_t *xr = instance;
	CONF_ITEM *ci;
	char const *name;
	xlat_t *xlat;

	rad_assert(xr->type == XLAT_REDUNDANT);

	/*
	 *	Pick the first xlat which succeeds
	 */
	for (ci = cf_item_find_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(xr->cs, ci)) {
		ssize_t rcode;

		if (!cf_item_is_pair(ci)) continue;

		name = cf_pair_attr(cf_item_to_pair(ci));
		rad_assert(name != NULL);

		xlat = xlat_find(name);
		if (!xlat) continue;

		rcode = xlat->func(xlat->instance, request, fmt, out, outlen);
		if (rcode <= 0) continue;
		return rcode;
	}

	/*
	 *	Everything failed.  Oh well.
	 */
	*out  = 0;
	return 0;
}


static ssize_t xlat_load_balance(void *instance, REQUEST *request,
			      char const *fmt, char *out, size_t outlen)
{
	uint32_t count = 0;
	xlat_redundant_t *xr = instance;
	CONF_ITEM *ci;
	CONF_ITEM *found = NULL;
	char const *name;
	xlat_t *xlat;

	/*
	 *	Choose a child at random.
	 */
	for (ci = cf_item_find_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(xr->cs, ci)) {
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
		name = cf_pair_attr(cf_item_to_pair(found));
		rad_assert(name != NULL);

		xlat = xlat_find(name);
		if (!xlat) return -1;

		return xlat->func(xlat->instance, request, fmt, out, outlen);
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

		xlat = xlat_find(name);
		if (xlat) {
			ssize_t rcode;

			rcode = xlat->func(xlat->instance, request, fmt, out, outlen);
			if (rcode > 0) return rcode;
		}

		/*
		 *	Go to the next one, wrapping around at the end.
		 */
		ci = cf_item_find_next(xr->cs, ci);
		if (!ci) ci = cf_item_find_next(xr->cs, NULL);
	} while (ci != found);

	return -1;
}


bool xlat_register_redundant(CONF_SECTION *cs)
{
	char const *name1, *name2;
	xlat_redundant_t *xr;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (!name2) return false;

	if (xlat_find(name2)) {
		cf_log_err_cs(cs, "An expansion is already registered for this name");
		return false;
	}

	xr = talloc_zero(cs, xlat_redundant_t);
	if (!xr) return false;

	if (strcmp(name1, "redundant") == 0) {
		xr->type = XLAT_REDUNDANT;

	} else if (strcmp(name1, "redundant-load-balance") == 0) {
		xr->type = XLAT_REDUNDANT_LOAD_BALANCE;

	} else if (strcmp(name1, "load-balance") == 0) {
		xr->type = XLAT_LOAD_BALANCE;

	} else {
		return false;
	}

	xr->cs = cs;

	/*
	 *	Get the number of children for load balancing.
	 */
	if (xr->type == XLAT_REDUNDANT) {
		if (xlat_register(name2, xlat_redundant, NULL, xr) < 0) {
			talloc_free(xr);
			return false;
		}

	} else {
		CONF_ITEM *ci;

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			if (!cf_item_is_pair(ci)) continue;

			if (!xlat_find(cf_pair_attr(cf_item_to_pair(ci)))) {
				talloc_free(xr);
				return false;
			}

			xr->count++;
		}

		if (xlat_register(name2, xlat_load_balance, NULL, xr) < 0) {
			talloc_free(xr);
			return false;
		}
	}

	return true;
}


/** Crappy temporary function to add attribute ref support to xlats
 *
 * This needs to die, and hopefully will die, when xlat functions accept
 * xlat node structures.
 *
 * Provides either a pointer to a buffer which contains the value of the reference VALUE_PAIR
 * in an architecture independent format. Or a pointer to the start of the fmt string.
 *
 * The pointer is only guaranteed to be valid between calls to xlat_fmt_to_ref,
 * and so long as the source VALUE_PAIR is not freed.
 *
 * @param out where to write a pointer to the buffer to the data the xlat function needs to work on.
 * @param request current request.
 * @param fmt string.
 * @returns the length of the data or -1 on error.
 */
ssize_t xlat_fmt_to_ref(uint8_t const **out, REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (fmt[0] == '&') {
		if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
			*out = NULL;
			return -1;
		}

		return rad_vp2data(out, vp);
	}

	*out = (uint8_t const *)fmt;
	return strlen(fmt);
}

/** De-register all xlat functions, used mainly for debugging.
 *
 */
void xlat_free(void)
{
	rbtree_free(xlat_root);
}

#ifdef DEBUG_XLAT
#  define XLAT_DEBUG DEBUG3
#else
#  define XLAT_DEBUG(...)
#endif

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				       char const **error);
static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     bool brace, char const **error);
static size_t xlat_process(char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void *escape_ctx);

static ssize_t xlat_tokenize_alternation(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
					 char const **error)
{
	ssize_t slen;
	char *p;
	xlat_exp_t *node;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');
	rad_assert(fmt[2] == '%');
	rad_assert(fmt[3] == '{');

	XLAT_DEBUG("ALTERNATE <-- %s", fmt);

	node = talloc_zero(ctx, xlat_exp_t);
	node->type = XLAT_ALTERNATE;

	p = fmt + 2;
	slen = xlat_tokenize_expansion(node, p, &node->child, error);
	if (slen <= 0) {
		talloc_free(node);
		return slen - (p - fmt);
	}
	p += slen;

	if (p[0] != ':') {
		talloc_free(node);
		*error = "Expected ':' after first expansion";
		return -(p - fmt);
	}
	p++;

	if (p[0] != '-') {
		talloc_free(node);
		*error = "Expected '-' after ':'";
		return -(p - fmt);
	}
	p++;

	/*
	 *	Allow the RHS to be empty as a special case.
	 */
	if (*p == '}') {
		/*
		 *	Hack up an empty string.
		 */
		node->alternate = talloc_zero(node, xlat_exp_t);
		node->alternate->type = XLAT_LITERAL;
		node->alternate->fmt = talloc_typed_strdup(node->alternate, "");
		*(p++) = '\0';

	} else {
		slen = xlat_tokenize_literal(node, p,  &node->alternate, true, error);
		if (slen <= 0) {
			talloc_free(node);
			return slen - (p - fmt);
		}

		if (!node->alternate) {
			talloc_free(node);
			*error = "Empty expansion is invalid";
			return -(p - fmt);
		}
		p += slen;
	}

	*head = node;
	return p - fmt;
}

static ssize_t xlat_tokenize_expansion(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				       char const **error)
{
	ssize_t slen;
	char *p, *q;
	xlat_exp_t *node;
	long num;

	rad_assert(fmt[0] == '%');
	rad_assert(fmt[1] == '{');

	/*
	 *	%{%{...}:-bar}
	 */
	if ((fmt[2] == '%') && (fmt[3] == '{')) return xlat_tokenize_alternation(ctx, fmt, head, error);

	XLAT_DEBUG("EXPANSION <-- %s", fmt);
	node = talloc_zero(ctx, xlat_exp_t);
	node->fmt = fmt + 2;
	node->len = 0;

#ifdef HAVE_REGEX
	/*
	 *	Handle regex's specially.
	 */
	p = fmt + 2;
	num = strtol(p, &q, 10);
	if (p != q && (*q == '}')) {
		XLAT_DEBUG("REGEX <-- %s", fmt);
		*q = '\0';

		if ((num > REQUEST_MAX_REGEX) || (num < 0)) {
			talloc_free(node);
			*error = "Invalid regex reference.  Must be in range 0-" STRINGIFY(REQUEST_MAX_REGEX);
			return -2;
		}
		node->attr.tmpl_num = num;

		node->type = XLAT_REGEX;
		*head = node;

		return (q - fmt) + 1;
	}
#endif /* HAVE_REGEX */

	/*
	 *	%{Attr-Name}
	 *	%{Attr-Name[#]}
	 *	%{Tunnel-Password:1}
	 *	%{Tunnel-Password:1[#]}
	 *	%{request:Attr-Name}
	 *	%{request:Tunnel-Password:1}
	 *	%{request:Tunnel-Password:1[#]}
	 *	%{mod:foo}
	 */

	/*
	 *	This is for efficiency, so we don't search for an xlat,
	 *	when what's being referenced is obviously an attribute.
	 */
	p = fmt + 2;
	for (q = p; *q != '\0'; q++) {
		if (*q == ':') break;

		if (isspace((int) *q)) break;

		if (*q == '[') continue;

		if (*q == '}') break;
	}

	/*
	 *	Check for empty expressions %{}
	 */
	if ((*q == '}') && (q == p)) {
		talloc_free(node);
		*error = "Empty expression is invalid";
		return -(p - fmt);
	}

	/*
	 *	Might be a module name reference.
	 *
	 *	If it's not, it's an attribute or parse error.
	 */
	if (*q == ':') {
		*q = '\0';
		node->xlat = xlat_find(node->fmt);
		if (node->xlat) {
			/*
			 *	%{mod:foo}
			 */
			node->type = XLAT_MODULE;

			p = q + 1;
			XLAT_DEBUG("MOD <-- %s ... %s", node->fmt, p);

			slen = xlat_tokenize_literal(node, p, &node->child, true, error);
			if (slen < 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}
			p += slen;

			*head = node;
			rad_assert(node->next == NULL);

			return p - fmt;
		}
		*q = ':';	/* Avoids a strdup */
	}

	/*
	 *	The first token ends with:
	 *	- '[' - Which is an attribute index, so it must be an attribute.
	 *      - '}' - The end of the expansion, which means it was a bareword.
	 */
	slen = tmpl_from_attr_substr(&node->attr, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, true, true);
	if (slen <= 0) {
		/*
		 *	If the parse error occurred before the ':'
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if ((*q == ':') && ((p + (slen * -1)) < q)) {
			*error = "Unknown module";
		} else {
			*error = fr_strerror();
		}

		talloc_free(node);
		return slen - (p - fmt);
	}

	/*
	 *	Might be a virtual XLAT attribute
	 */
	if (node->attr.type == TMPL_TYPE_ATTR_UNDEFINED) {
		node->xlat = xlat_find(node->attr.tmpl_unknown_name);
		if (node->xlat && node->xlat->instance && !node->xlat->internal) {
			talloc_free(node);
			*error = "Missing content in expansion";
			return -(p - fmt) - slen;
		}

		if (node->xlat) {
			node->type = XLAT_VIRTUAL;
			node->fmt = node->attr.tmpl_unknown_name;

			XLAT_DEBUG("VIRTUAL <-- %s", node->fmt);
			*head = node;
			rad_assert(node->next == NULL);
			q++;
			return q - fmt;
		}

		talloc_free(node);
		*error = "Unknown attribute";
		return -(p - fmt);
	}

	/*
	 *	Might be a list, too...
	 */
	node->type = XLAT_ATTRIBUTE;
	p += slen;

	if (*p != '}') {
		talloc_free(node);
		*error = "No matching closing brace";
		return -1;	/* second character of format string */
	}
	*p++ = '\0';
	*head = node;
	rad_assert(node->next == NULL);

	return p - fmt;
}


static ssize_t xlat_tokenize_literal(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
				     bool brace, char const **error)
{
	char *p;
	xlat_exp_t *node;

	if (!*fmt) return 0;

	XLAT_DEBUG("LITERAL <-- %s", fmt);

	node = talloc_zero(ctx, xlat_exp_t);
	node->fmt = fmt;
	node->len = 0;
	node->type = XLAT_LITERAL;

	p = fmt;

	while (*p) {
		if (*p == '\\') {
			if (!p[1]) {
				talloc_free(node);
				*error = "Invalid escape at end of string";
				return -(p - fmt);
			}

			p += 2;
			node->len += 2;
			continue;
		}

		/*
		 *	Process the expansion.
		 */
		if ((p[0] == '%') && (p[1] == '{')) {
			ssize_t slen;

			XLAT_DEBUG("EXPANSION-2 <-- %s", node->fmt);

			slen = xlat_tokenize_expansion(node, p, &node->next, error);
			if (slen <= 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}
			*p = '\0'; /* end the literal */
			p += slen;

			rad_assert(node->next != NULL);

			/*
			 *	Short-circuit the recursive call.
			 *	This saves another function call and
			 *	memory allocation.
			 */
			if (!*p) break;

			/*
			 *	"foo %{User-Name} bar"
			 *	LITERAL		"foo "
			 *	EXPANSION	User-Name
			 *	LITERAL		" bar"
			 */
			slen = xlat_tokenize_literal(node->next, p, &(node->next->next), brace, error);
			rad_assert(slen != 0);
			if (slen < 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}

			brace = false; /* it was found above, or else the above code errored out */
			p += slen;
			break;	/* stop processing the string */
		}

		/*
		 *	Check for valid single-character expansions.
		 */
		if (p[0] == '%') {
			ssize_t slen;
			xlat_exp_t *next;

			if (!p[1] || !strchr("%}dlmntDGHISTYv", p[1])) {
				talloc_free(node);
				*error = "Invalid variable expansion";
				p++;
				return - (p - fmt);
			}

			next = talloc_zero(node, xlat_exp_t);
			next->len = 1;

			switch (p[1]) {
			case '%':
			case '}':
				next->fmt = talloc_strndup(next, p + 1, 1);

				XLAT_DEBUG("LITERAL-ESCAPED <-- %s", next->fmt);
				next->type = XLAT_LITERAL;
				break;

			default:
				next->fmt = p + 1;

				XLAT_DEBUG("PERCENT <-- %c", *next->fmt);
				next->type = XLAT_PERCENT;
				break;
			}

			node->next = next;
			*p = '\0';
			p += 2;

			if (!*p) break;

			/*
			 *	And recurse.
			 */
			slen = xlat_tokenize_literal(node->next, p, &(node->next->next), brace, error);
			rad_assert(slen != 0);
			if (slen < 0) {
				talloc_free(node);
				return slen - (p - fmt);
			}

			brace = false; /* it was found above, or else the above code errored out */
			p += slen;
			break;	/* stop processing the string */
		}

		/*
		 *	If required, eat the brace.
		 */
		if (brace && (*p == '}')) {
			brace = false;
			*p = '\0';
			p++;
			break;
		}

		p++;
		node->len++;
	}

	/*
	 *	We were told to look for a brace, but we ran off of
	 *	the end of the string before we found one.
	 */
	if (brace) {
		*error = "Missing closing brace at end of string";
		return -(p - fmt);
	}

	/*
	 *	Squash zero-width literals
	 */
	if (node->len > 0) {
		*head = node;

	} else {
		(void) talloc_steal(ctx, node->next);
		*head = node->next;
		talloc_free(node);
	}

	return p - fmt;
}


static char const xlat_tabs[] = "																																																																																																																																";

static void xlat_tokenize_debug(xlat_exp_t const *node, int lvl)
{
	rad_assert(node != NULL);

	if (lvl >= (int) sizeof(xlat_tabs)) lvl = sizeof(xlat_tabs);

	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			DEBUG("%.*sliteral --> %s", lvl, xlat_tabs, node->fmt);
			break;

		case XLAT_PERCENT:
			DEBUG("%.*spercent --> %c", lvl, xlat_tabs, node->fmt[0]);
			break;

		case XLAT_ATTRIBUTE:
			rad_assert(node->attr.tmpl_da != NULL);
			DEBUG("%.*sattribute --> %s", lvl, xlat_tabs, node->attr.tmpl_da->name);
			rad_assert(node->child == NULL);
			if ((node->attr.tmpl_tag != TAG_ANY) || (node->attr.tmpl_num != NUM_ANY)) {
				DEBUG("%.*s{", lvl, xlat_tabs);

				DEBUG("%.*sref  %d", lvl + 1, xlat_tabs, node->attr.tmpl_request);
				DEBUG("%.*slist %d", lvl + 1, xlat_tabs, node->attr.tmpl_list);

				if (node->attr.tmpl_tag != TAG_ANY) {
					DEBUG("%.*stag %d", lvl + 1, xlat_tabs, node->attr.tmpl_tag);
				}
				if (node->attr.tmpl_num != NUM_ANY) {
					if (node->attr.tmpl_num == NUM_COUNT) {
						DEBUG("%.*s[#]", lvl + 1, xlat_tabs);
					} else if (node->attr.tmpl_num == NUM_ALL) {
						DEBUG("%.*s[*]", lvl + 1, xlat_tabs);
					} else {
						DEBUG("%.*s[%d]", lvl + 1, xlat_tabs, node->attr.tmpl_num);
					}
				}

				DEBUG("%.*s}", lvl, xlat_tabs);
			}
			break;

		case XLAT_VIRTUAL:
			rad_assert(node->fmt != NULL);
			DEBUG("%.*svirtual --> %s", lvl, xlat_tabs, node->fmt);
			break;

		case XLAT_MODULE:
			rad_assert(node->xlat != NULL);
			DEBUG("%.*sxlat --> %s", lvl, xlat_tabs, node->xlat->name);
			if (node->child) {
				DEBUG("%.*s{", lvl, xlat_tabs);
				xlat_tokenize_debug(node->child, lvl + 1);
				DEBUG("%.*s}", lvl, xlat_tabs);
			}
			break;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			DEBUG("%.*sregex-var --> %d", lvl, xlat_tabs, node->attr.tmpl_num);
			break;
#endif

		case XLAT_ALTERNATE:
			DEBUG("%.*sXLAT-IF {", lvl, xlat_tabs);
			xlat_tokenize_debug(node->child, lvl + 1);
			DEBUG("%.*s}", lvl, xlat_tabs);
			DEBUG("%.*sXLAT-ELSE {", lvl, xlat_tabs);
			xlat_tokenize_debug(node->alternate, lvl + 1);
			DEBUG("%.*s}", lvl, xlat_tabs);
			break;
		}
		node = node->next;
	}
}

size_t xlat_sprint(char *buffer, size_t bufsize, xlat_exp_t const *node)
{
	size_t len;
	char *p, *end;

	if (!node) {
		*buffer = '\0';
		return 0;
	}

	p = buffer;
	end = buffer + bufsize;

	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			strlcpy(p, node->fmt, end - p);
			p += strlen(p);
			break;

		case XLAT_PERCENT:
			p[0] = '%';
			p[1] = node->fmt[0];
			p += 2;
			break;

		case XLAT_ATTRIBUTE:
			*(p++) = '%';
			*(p++) = '{';

			/*
			 *	The node MAY NOT be an attribute.  It
			 *	may be a list.
			 */
			tmpl_prints(p, end - p, &node->attr, NULL);
			if (*p == '&') {
				memmove(p, p + 1, strlen(p + 1) + 1);
			}
			p += strlen(p);
			*(p++) = '}';
			break;
#ifdef HAVE_REGEX
		case XLAT_REGEX:
			snprintf(p, end - p, "%%{%i}", node->attr.tmpl_num);
			p += strlen(p);
			break;
#endif
		case XLAT_VIRTUAL:
			*(p++) = '%';
			*(p++) = '{';
			strlcpy(p, node->fmt, end - p);
			p += strlen(p);
			*(p++) = '}';
			break;

		case XLAT_MODULE:
			*(p++) = '%';
			*(p++) = '{';
			strlcpy(p, node->xlat->name, end - p);
			p += strlen(p);
			*(p++) = ':';
			rad_assert(node->child != NULL);
			len = xlat_sprint(p, end - p, node->child);
			p += len;
			*(p++) = '}';
			break;

		case XLAT_ALTERNATE:
			*(p++) = '%';
			*(p++) = '{';

			len = xlat_sprint(p, end - p, node->child);
			p += len;

			*(p++) = ':';
			*(p++) = '-';

			len = xlat_sprint(p, end - p, node->alternate);
			p += len;

			*(p++) = '}';
			break;
		}


		if (p == end) break;

		node = node->next;
	}

	*p = '\0';

	return p - buffer;
}

ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
		      char const **error)
{
	return xlat_tokenize_literal(ctx, fmt, head, false, error);
}


/** Tokenize an xlat expansion
 *
 * @param[in] request the input request.  Memory will be attached here.
 * @param[in] fmt the format string to expand
 * @param[out] head the head of the xlat list / tree structure.
 */
static ssize_t xlat_tokenize_request(REQUEST *request, char const *fmt, xlat_exp_t **head)
{
	ssize_t slen;
	char *tokens;
	char const *error = NULL;

	*head = NULL;

	/*
	 *	Copy the original format string to a buffer so that
	 *	the later functions can mangle it in-place, which is
	 *	much faster.
	 */
	tokens = talloc_typed_strdup(request, fmt);
	if (!tokens) {
		error = "Out of memory";
		return -1;
	}

	slen = xlat_tokenize_literal(request, tokens, head, false, &error);

	/*
	 *	Zero length expansion, return a zero length node.
	 */
	if (slen == 0) {
		*head = talloc_zero(request, xlat_exp_t);
	}

	/*
	 *	Output something like:
	 *
	 *	"format string"
	 *	"       ^ error was here"
	 */
	if (slen < 0) {
		talloc_free(tokens);

		if (!error) error = "Unknown error";

		REMARKER(fmt, -slen, error);
		return slen;
	}

	if (*head && (rad_debug_lvl > 2)) {
		DEBUG("%s", fmt);
		DEBUG("Parsed xlat tree:");
		xlat_tokenize_debug(*head, 0);
	}

	/*
	 *	All of the nodes point to offsets in the "tokens"
	 *	string.  Let's ensure that free'ing head will free
	 *	"tokens", too.
	 */
	(void) talloc_steal(*head, tokens);

	return slen;
}


static char *xlat_getvp(TALLOC_CTX *ctx, REQUEST *request, vp_tmpl_t const *vpt,
			bool escape, bool return_null)
{
	VALUE_PAIR *vp = NULL, *virtual = NULL;
	RADIUS_PACKET *packet = NULL;
	DICT_VALUE *dv;
	char *ret = NULL;

	vp_cursor_t cursor;
	char quote = escape ? '"' : '\0';

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	/*
	 *	We only support count and concatenate operations on lists.
	 */
	if (vpt->type == TMPL_TYPE_LIST) {
		vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
		goto do_print;
	}

	/*
	 *	See if we're dealing with an attribute in the request
	 *
	 *	This allows users to manipulate virtual attributes as if
	 *	they were real ones.
	 */
	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	if (vp) goto do_print;

	/*
	 *	We didn't find the VP in a list.
	 *	If it's not a virtual one, and we're not meant to
	 *	be counting it, return.
	 */
	if (!vpt->tmpl_da->flags.virtual) {
		if (vpt->tmpl_num == NUM_COUNT) goto do_print;
		return NULL;
	}

	/*
	 *	Switch out the request to the one specified by the template
	 */
	if (radius_request(&request, vpt->tmpl_request) < 0) return NULL;

	/*
	 *	Some non-packet expansions
	 */
	switch (vpt->tmpl_da->attr) {
	default:
		break;		/* ignore them */

	case PW_CLIENT_SHORTNAME:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (request->client && request->client->shortname) {
			return talloc_typed_strdup(ctx, request->client->shortname);
		}
		return talloc_typed_strdup(ctx, "<UNKNOWN-CLIENT>");

	case PW_REQUEST_PROCESSING_STAGE:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (request->component) {
			return talloc_typed_strdup(ctx, request->component);
		}
		return talloc_typed_strdup(ctx, "server_core");

	case PW_VIRTUAL_SERVER:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (!request->server) return NULL;
		return talloc_typed_strdup(ctx, request->server);

	case PW_MODULE_RETURN_CODE:
		if (vpt->tmpl_num == NUM_COUNT) goto count_virtual;
		if (!request->rcode) return NULL;
		return talloc_typed_strdup(ctx, fr_int2str(modreturn_table, request->rcode, ""));
	}

	/*
	 *	All of the attributes must now refer to a packet.
	 *	If there's no packet, we can't print any attribute
	 *	referencing it.
	 */
	packet = radius_packet(request, vpt->tmpl_list);
	if (!packet) {
		if (return_null) return NULL;
		return vp_aprints_type(ctx, vpt->tmpl_da->type);
	}

	vp = NULL;
	switch (vpt->tmpl_da->attr) {
	default:
		break;

	case PW_PACKET_TYPE:
		dv = dict_valbyattr(PW_PACKET_TYPE, 0, packet->code);
		if (dv) return talloc_typed_strdup(ctx, dv->name);
		return talloc_typed_asprintf(ctx, "%d", packet->code);

	case PW_RESPONSE_PACKET_TYPE:
	{
		int code = 0;

#ifdef WITH_PROXY
		if (request->proxy_reply && (!request->reply || !request->reply->code)) {
			code = request->proxy_reply->code;
		} else
#endif
			if (request->reply) {
				code = request->reply->code;
			}

		return talloc_typed_strdup(ctx, fr_packet_codes[code]);
	}

	/*
	 *	Virtual attributes which require a temporary VALUE_PAIR
	 *	to be allocated. We can't use stack allocated memory
	 *	because of the talloc checks sprinkled throughout the
	 *	various VP functions.
	 */
	case PW_PACKET_AUTHENTICATION_VECTOR:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		fr_pair_value_memcpy(virtual, packet->vector, sizeof(packet->vector));
		vp = virtual;
		break;

	case PW_CLIENT_IP_ADDRESS:
	case PW_PACKET_SRC_IP_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			virtual->vp_ipaddr = packet->src_ipaddr.ipaddr.ip4addr.s_addr;
			vp = virtual;
		}
		break;

	case PW_PACKET_DST_IP_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			virtual->vp_ipaddr = packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
			vp = virtual;
		}
		break;

	case PW_PACKET_SRC_IPV6_ADDRESS:
		if (packet->src_ipaddr.af == AF_INET6) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			memcpy(&virtual->vp_ipv6addr,
			       &packet->src_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->src_ipaddr.ipaddr.ip6addr));
			vp = virtual;
		}
		break;

	case PW_PACKET_DST_IPV6_ADDRESS:
		if (packet->dst_ipaddr.af == AF_INET6) {
			virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
			memcpy(&virtual->vp_ipv6addr,
			       &packet->dst_ipaddr.ipaddr.ip6addr,
			       sizeof(packet->dst_ipaddr.ipaddr.ip6addr));
			vp = virtual;
		}
		break;

	case PW_PACKET_SRC_PORT:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		virtual->vp_integer = packet->src_port;
		vp = virtual;
		break;

	case PW_PACKET_DST_PORT:
		virtual = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		virtual->vp_integer = packet->dst_port;
		vp = virtual;
		break;
	}

	/*
	 *	Fake various operations for virtual attributes.
	 */
	if (virtual) {
		if (vpt->tmpl_num != NUM_ANY) switch (vpt->tmpl_num) {
		/*
		 *	[n] is NULL (we only have [0])
		 */
		default:
			goto finish;
		/*
		 *	[*] means only one.
		 */
		case NUM_ALL:
			break;

		/*
		 *	[#] means 1 (as there's only one)
		 */
		case NUM_COUNT:
		count_virtual:
			ret = talloc_strdup(ctx, "1");
			goto finish;

		/*
		 *	[0] is fine (get the first instance)
		 */
		case 0:
			break;
		}
		goto print;
	}

do_print:
	switch (vpt->tmpl_num) {
	/*
	 *	Return a count of the VPs.
	 */
	case NUM_COUNT:
	{
		int count = 0;

		for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
		     vp;
		     vp = tmpl_cursor_next(&cursor, vpt)) count++;

		return talloc_typed_asprintf(ctx, "%d", count);
	}


	/*
	 *	Concatenate all values together,
	 *	separated by commas.
	 */
	case NUM_ALL:
	{
		char *p, *q;

		if (!fr_cursor_current(&cursor)) return NULL;
		p = vp_aprints_value(ctx, vp, quote);
		if (!p) return NULL;

		while ((vp = tmpl_cursor_next(&cursor, vpt)) != NULL) {
			q = vp_aprints_value(ctx, vp, quote);
			if (!q) return NULL;
			p = talloc_strdup_append(p, ",");
			p = talloc_strdup_append(p, q);
		}

		return p;
	}

	default:
		/*
		 *	The cursor was set to the correct
		 *	position above by tmpl_cursor_init.
		 */
		vp = fr_cursor_current(&cursor);
		break;
	}

	if (!vp) {
		if (return_null) return NULL;
		return vp_aprints_type(ctx, vpt->tmpl_da->type);
	}

print:
	ret = vp_aprints_value(ctx, vp, quote);

finish:
	talloc_free(virtual);
	return ret;
}

#ifdef DEBUG_XLAT
static const char xlat_spaces[] = "                                                                                                                                                                                                                                                                ";
#endif

static char *xlat_aprint(TALLOC_CTX *ctx, REQUEST *request, xlat_exp_t const * const node,
			 xlat_escape_t escape, void *escape_ctx,
#ifndef DEBUG_XLAT
			 UNUSED
#endif
			 int lvl)
{
	ssize_t rcode;
	char *str = NULL, *child;
	char const *p;

	XLAT_DEBUG("%.*sxlat aprint %d %s", lvl, xlat_spaces, node->type, node->fmt);

	switch (node->type) {
		/*
		 *	Don't escape this.
		 */
	case XLAT_LITERAL:
		XLAT_DEBUG("%.*sxlat_aprint LITERAL", lvl, xlat_spaces);
		return talloc_typed_strdup(ctx, node->fmt);

		/*
		 *	Do a one-character expansion.
		 */
	case XLAT_PERCENT:
	{
		char *nl;
		size_t freespace = 256;
		struct tm ts;
		time_t when;
		int usec;

		XLAT_DEBUG("%.*sxlat_aprint PERCENT", lvl, xlat_spaces);

		str = talloc_array(ctx, char, freespace); /* @todo do better allocation */
		p = node->fmt;

		when = request->timestamp;
		usec = 0;
		if (request->packet) {
			when = request->packet->timestamp.tv_sec;
			usec = request->packet->timestamp.tv_usec;
		}

		switch (*p) {
		case '%':
			str[0] = '%';
			str[1] = '\0';
			break;

		case 'd': /* request day */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%d", &ts);
			break;

		case 'l': /* request timestamp */
			snprintf(str, freespace, "%lu",
				 (unsigned long) when);
			break;

		case 'm': /* request month */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%m", &ts);
			break;

		case 'n': /* Request Number*/
			snprintf(str, freespace, "%u", request->number);
			break;

		case 't': /* request timestamp */
			CTIME_R(&when, str, freespace);
			nl = strchr(str, '\n');
			if (nl) *nl = '\0';
			break;

		case 'D': /* request date */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%Y%m%d", &ts);
			break;

		case 'G': /* request minute */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%M", &ts);
			break;

		case 'H': /* request hour */
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%H", &ts);
			break;

		case 'I': /* Request ID */
			if (request->packet) {
				snprintf(str, freespace, "%i", request->packet->id);
			}
			break;

		case 'S': /* request timestamp in SQL format*/
			if (!localtime_r(&when, &ts)) goto error;
			strftime(str, freespace, "%Y-%m-%d %H:%M:%S", &ts);
			break;

		case 'T': /* request timestamp */
			if (!localtime_r(&when, &ts)) goto error;
			nl = str + strftime(str, freespace, "%Y-%m-%d-%H.%M.%S", &ts);
			rad_assert(((str + freespace) - nl) >= 8);
			snprintf(nl, (str + freespace) - nl, ".%06d",  usec);
			break;

		case 'Y': /* request year */
			if (!localtime_r(&when, &ts)) {
				error:
				REDEBUG("Failed converting packet timestamp to localtime: %s", fr_syserror(errno));
				talloc_free(str);
				return NULL;
			}
			strftime(str, freespace, "%Y", &ts);
			break;

		case 'v': /* Version of code */
			RWDEBUG("%%v is deprecated and will be removed.  Use ${version.freeradius-server}");
			snprintf(str, freespace, "%s", radiusd_version_short);
			break;

		default:
			rad_assert(0 == 1);
			break;
		}
	}
		break;

	case XLAT_ATTRIBUTE:
		XLAT_DEBUG("%.*sxlat_aprint ATTRIBUTE", lvl, xlat_spaces);

		/*
		 *	Some attributes are virtual <sigh>
		 */
		str = xlat_getvp(ctx, request, &node->attr, escape ? false : true, true);
		if (str) {
			XLAT_DEBUG("%.*sEXPAND attr %s", lvl, xlat_spaces, node->attr.tmpl_da->name);
			XLAT_DEBUG("%.*s       ---> %s", lvl ,xlat_spaces, str);
		}
		break;

	case XLAT_VIRTUAL:
		XLAT_DEBUG("xlat_aprint VIRTUAL");
		str = talloc_array(ctx, char, 2048); /* FIXME: have the module call talloc_typed_asprintf */
		rcode = node->xlat->func(node->xlat->instance, request, NULL, str, 2048);
		if (rcode < 0) {
			talloc_free(str);
			return NULL;
		}
		RDEBUG2("EXPAND %s", node->xlat->name);
		RDEBUG2("   --> %s", str);
		break;

	case XLAT_MODULE:
		XLAT_DEBUG("xlat_aprint MODULE");

		if (node->child) {
			if (xlat_process(&child, request, node->child, node->xlat->escape, node->xlat->instance) == 0) {
				return NULL;
			}

			XLAT_DEBUG("%.*sEXPAND mod %s %s", lvl, xlat_spaces, node->fmt, node->child->fmt);
		} else {
			XLAT_DEBUG("%.*sEXPAND mod %s", lvl, xlat_spaces, node->fmt);
			child = talloc_typed_strdup(ctx, "");
		}

		XLAT_DEBUG("%.*s      ---> %s", lvl, xlat_spaces, child);

		/*
		 *	Smash \n --> CR.
		 *
		 *	The OUTPUT of xlat is a "raw" string.  The INPUT is a printable string.
		 *
		 *	This is really the reverse of fr_prints().
		 */
		if (cf_new_escape && *child) {
			ssize_t slen;
			PW_TYPE type;
			value_data_t data;

			type = PW_TYPE_STRING;
			slen = value_data_from_str(request, &data, &type, NULL, child, talloc_array_length(child) - 1, '"');
			if (slen <= 0) {
				talloc_free(child);
				return NULL;
			}

			talloc_free(child);
			child = data.ptr;

		} else {
			char *q;

			p = q = child;
			while (*p) {
				if (*p == '\\') switch (p[1]) {
					default:
						*(q++) = p[1];
						p += 2;
						continue;

					case 'n':
						*(q++) = '\n';
						p += 2;
						continue;

					case 't':
						*(q++) = '\t';
						p += 2;
						continue;
					}

				*(q++) = *(p++);
			}
			*q = '\0';
		}

		str = talloc_array(ctx, char, 2048); /* FIXME: have the module call talloc_typed_asprintf */
		*str = '\0';	/* Be sure the string is NULL terminated, we now only free on error */

		rcode = node->xlat->func(node->xlat->instance, request, child, str, 2048);
		talloc_free(child);
		if (rcode < 0) {
			talloc_free(str);
			return NULL;
		}
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		XLAT_DEBUG("%.*sxlat_aprint REGEX", lvl, xlat_spaces);
		if (regex_request_to_sub(ctx, &str, request, node->attr.tmpl_num) < 0) return NULL;

		break;
#endif

	case XLAT_ALTERNATE:
		XLAT_DEBUG("%.*sxlat_aprint ALTERNATE", lvl, xlat_spaces);
		rad_assert(node->child != NULL);
		rad_assert(node->alternate != NULL);

		/*
		 *	Call xlat_process recursively.  The child /
		 *	alternate nodes may have "next" pointers, and
		 *	those need to be expanded.
		 */
		if (xlat_process(&str, request, node->child, escape, escape_ctx) > 0) {
			XLAT_DEBUG("%.*sALTERNATE got first string: %s", lvl, xlat_spaces, str);
		} else {
			(void) xlat_process(&str, request, node->alternate, escape, escape_ctx);
			XLAT_DEBUG("%.*sALTERNATE got alternate string %s", lvl, xlat_spaces, str);
		}
		break;
	}

	/*
	 *	If there's no data, return that, instead of an empty string.
	 */
	if (str && !str[0]) {
		talloc_free(str);
		return NULL;
	}

	/*
	 *	Escape the non-literals we found above.
	 */
	if (str && escape) {
		size_t len;
		char *escaped;

		len = talloc_array_length(str) * 3;

		escaped = talloc_array(ctx, char, len);
		escape(request, escaped, len, str, escape_ctx);
		talloc_free(str);
		str = escaped;
	}

	return str;
}


static size_t xlat_process(char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void *escape_ctx)
{
	int i, list;
	size_t total;
	char **array, *answer;
	xlat_exp_t const *node;

	*out = NULL;

	/*
	 *	There are no nodes to process, so the result is a zero
	 *	length string.
	 */
	if (!head) {
		*out = talloc_zero_array(request, char, 1);
		return 0;
	}

	/*
	 *	Hack for speed.  If it's one expansion, just allocate
	 *	that and return, instead of allocating an intermediary
	 *	array.
	 */
	if (!head->next) {
		/*
		 *	Pass the MAIN escape function.  Recursive
		 *	calls will call node-specific escape
		 *	functions.
		 */
		answer = xlat_aprint(request, request, head, escape, escape_ctx, 0);
		if (!answer) {
			*out = talloc_zero_array(request, char, 1);
			return 0;
		}
		*out = answer;
		return strlen(answer);
	}

	list = 0;		/* FIXME: calculate this once */
	for (node = head; node != NULL; node = node->next) {
		list++;
	}

	array = talloc_array(request, char *, list);
	if (!array) return -1;

	for (node = head, i = 0; node != NULL; node = node->next, i++) {
		array[i] = xlat_aprint(array, request, node, escape, escape_ctx, 0); /* may be NULL */
	}

	total = 0;
	for (i = 0; i < list; i++) {
		if (array[i]) total += strlen(array[i]); /* FIXME: calculate strlen once */
	}

	if (!total) {
		talloc_free(array);
		*out = talloc_zero_array(request, char, 1);
		return 0;
	}

	answer = talloc_array(request, char, total + 1);

	total = 0;
	for (i = 0; i < list; i++) {
		size_t len;

		if (array[i]) {
			len = strlen(array[i]);
			memcpy(answer + total, array[i], len);
			total += len;
		}
	}
	answer[total] = '\0';
	talloc_free(array);	/* and child entries */

	*out = answer;
	return total;
}


/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
 *
 * @param[out] out Where to write pointer to output buffer.
 * @param[in] outlen Size of out.
 * @param[in] request current request.
 * @param[in] node the xlat structure to expand
 * @param[in] escape function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure
 */
static ssize_t xlat_expand_struct(char **out, size_t outlen, REQUEST *request, xlat_exp_t const *node,
				  xlat_escape_t escape, void *escape_ctx)
{
	char *buff;
	ssize_t len;

	rad_assert(node != NULL);

	len = xlat_process(&buff, request, node, escape, escape_ctx);
	if ((len < 0) || !buff) {
		rad_assert(buff == NULL);
		if (*out) *out[0] = '\0';
		return len;
	}

	len = strlen(buff);

	/*
	 *	If out doesn't point to an existing buffer
	 *	copy the pointer to our buffer over.
	 */
	if (!*out) {
		*out = buff;
		return len;
	}

	/*
	 *	Otherwise copy the malloced buffer to the fixed one.
	 */
	strlcpy(*out, buff, outlen);
	talloc_free(buff);
	return len;
}

static ssize_t xlat_expand(char **out, size_t outlen, REQUEST *request, char const *fmt,
			   xlat_escape_t escape, void *escape_ctx) CC_HINT(nonnull (1, 3, 4));

/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
 *
 * @param[out] out Where to write pointer to output buffer.
 * @param[in] outlen Size of out.
 * @param[in] request current request.
 * @param[in] fmt string to expand.
 * @param[in] escape function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure
 */
static ssize_t xlat_expand(char **out, size_t outlen, REQUEST *request, char const *fmt,
			   xlat_escape_t escape, void *escape_ctx)
{
	ssize_t len;
	xlat_exp_t *node;

	/*
	 *	Give better errors than the old code.
	 */
	len = xlat_tokenize_request(request, fmt, &node);
	if (len == 0) {
		if (*out) {
			*out[0] = '\0';
		} else {
			*out = talloc_zero_array(request, char, 1);
		}
		return 0;
	}

	if (len < 0) {
		if (*out) *out[0] = '\0';
		return -1;
	}

	len = xlat_expand_struct(out, outlen, request, node, escape, escape_ctx);
	talloc_free(node);

	RDEBUG2("EXPAND %s", fmt);
	RDEBUG2("   --> %s", *out);

	return len;
}

/** Try to convert an xlat to a tmpl for efficiency
 *
 * @param ctx to allocate new vp_tmpl_t in.
 * @param node to convert.
 * @return NULL if unable to convert (not necessarily error), or a new vp_tmpl_t.
 */
vp_tmpl_t *xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *node)
{
	vp_tmpl_t *vpt;

	if (node->next || (node->type != XLAT_ATTRIBUTE) || (node->attr.type != TMPL_TYPE_ATTR)) return NULL;

	/*
	 *   Concat means something completely different as an attribute reference
	 *   Count isn't implemented.
	 */
	if ((node->attr.tmpl_num == NUM_COUNT) || (node->attr.tmpl_num == NUM_ALL)) return NULL;

	vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, node->fmt, -1);
	if (!vpt) return NULL;
	memcpy(&vpt->data, &node->attr.data, sizeof(vpt->data));

	VERIFY_TMPL(vpt);

	return vpt;
}

/** Try to convert attr tmpl to an xlat for &attr[*] and artificially constructing expansions
 *
 * @param ctx to allocate new xlat_expt_t in.
 * @param vpt to convert.
 * @return NULL if unable to convert (not necessarily error), or a new vp_tmpl_t.
 */
xlat_exp_t *xlat_from_tmpl_attr(TALLOC_CTX *ctx, vp_tmpl_t *vpt)
{
	xlat_exp_t *node;

	if (vpt->type != TMPL_TYPE_ATTR) return NULL;

	node = talloc_zero(ctx, xlat_exp_t);
	node->type = XLAT_ATTRIBUTE;
	node->fmt = talloc_bstrndup(node, vpt->name, vpt->len);
	tmpl_init(&node->attr, TMPL_TYPE_ATTR, node->fmt, talloc_array_length(node->fmt) - 1);
	memcpy(&node->attr.data, &vpt->data, sizeof(vpt->data));

	return node;
}

ssize_t radius_xlat(char *out, size_t outlen, REQUEST *request, char const *fmt, xlat_escape_t escape, void *ctx)
{
	return xlat_expand(&out, outlen, request, fmt, escape, ctx);
}

ssize_t radius_xlat_struct(char *out, size_t outlen, REQUEST *request, xlat_exp_t const *xlat, xlat_escape_t escape, void *ctx)
{
	return xlat_expand_struct(&out, outlen, request, xlat, escape, ctx);
}

ssize_t radius_axlat(char **out, REQUEST *request, char const *fmt, xlat_escape_t escape, void *ctx)
{
	*out = NULL;
	return xlat_expand(out, 0, request, fmt, escape, ctx);
}

ssize_t radius_axlat_struct(char **out, REQUEST *request, xlat_exp_t const *xlat, xlat_escape_t escape, void *ctx)
{
	*out = NULL;
	return xlat_expand_struct(out, 0, request, xlat, escape, ctx);
}
