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
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/base64.h>

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

static int xlat_foreach_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

/** Print length of its RHS.
 *
 */
static ssize_t xlat_strlen(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   UNUSED REQUEST *request, char const *fmt)
{
	snprintf(*out, outlen, "%u", (unsigned int) strlen(fmt));
	return strlen(*out);
}

/** Print the size of the attribute in bytes.
 *
 */
static ssize_t xlat_length(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	snprintf(*out, outlen, "%zu", fr_value_box_network_length(&vp->data));
	return strlen(*out);
}

/** Print data as integer, not as VALUE.
 *
 */
static ssize_t xlat_integer(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, char const *fmt)
{
	VALUE_PAIR 	*vp;

	uint64_t 	int64 = 0;	/* Needs to be initialised to zero */
	uint32_t	int32 = 0;	/* Needs to be initialised to zero */

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
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
		return snprintf(*out, outlen, "%u", htonl(vp->vp_ipv4addr));

	case FR_TYPE_UINT32:
		return snprintf(*out, outlen, "%u", vp->vp_uint32);

	case FR_TYPE_DATE:
		return snprintf(*out, outlen, "%u", vp->vp_date);

	case FR_TYPE_UINT8:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint8);

	case FR_TYPE_UINT16:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint16);

	/*
	 *	Ethernet is weird... It's network related, so we assume to it should be
	 *	bigendian.
	 */
	case FR_TYPE_ETHERNET:
		memcpy(&int64, vp->vp_ether, sizeof(vp->vp_ether));
		return snprintf(*out, outlen, "%" PRIu64, htonll(int64));

	case FR_TYPE_INT32:
		return snprintf(*out, outlen, "%i", vp->vp_int32);

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		return fr_snprint_uint128(*out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6addr));

	default:
		break;
	}

	REDEBUG("Type '%s' cannot be converted to integer", fr_int2str(dict_attr_types, vp->vp_type, "???"));

	return -1;
}

/** Print data as hex, not as VALUE.
 *
 */
static ssize_t xlat_hex(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	size_t i;
	VALUE_PAIR *vp;
	uint8_t const *p;
	size_t	len;
	fr_value_box_t dst;
	uint8_t const *buff = NULL;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
	error:
		return -1;
	}

	/*
	 *	The easy case.
	 */
	if (vp->vp_type == FR_TYPE_OCTETS) {
		p = vp->vp_octets;
		len = vp->vp_length;
	/*
	 *	Cast the fr_value_box_t of the VP to an octets string and
	 *	print that as hex.
	 */
	} else {
		if (fr_value_box_cast(request, &dst, FR_TYPE_OCTETS, NULL, &vp->data) < 0) {
			RPEDEBUG("Invalid cast");
			goto error;
		}
		len = (size_t)dst.datum.length;
		p = buff = dst.vb_octets;
	}

	rad_assert(p);

	/*
	 *	Don't truncate the data.
	 */
	if (outlen < (len * 2)) {
		talloc_const_free(buff);
		goto error;
	}

	for (i = 0; i < len; i++) {
		snprintf((*out) + (2 * i), 3, "%02x", p[i]);
	}
	talloc_const_free(buff);

	return len * 2;
}

/** Return the tag of an attribute reference
 *
 */
static ssize_t xlat_tag(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	if (!vp->da->flags.has_tag || !TAG_VALID(vp->tag)) return 0;

	return snprintf(*out, outlen, "%u", vp->tag);
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
static ssize_t xlat_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       REQUEST *request, char const *fmt)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;
	vp_tmpl_t	*vpt;

	if (!RDEBUG_ENABLED2) return -1;

	while (isspace((int) *fmt)) fmt++;

	if (tmpl_afrom_attr_str(request, &vpt, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		FR_NAME_NUMBER const *type;
		char *value;

		value = fr_pair_value_asprint(vp, vp, '\'');
		if (vp->da->flags.has_tag) {
			RIDEBUG2("&%s:%s:%i %s %s",
				fr_int2str(pair_lists, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				vp->tag,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				value);
		} else {
			RIDEBUG2("&%s:%s %s %s",
				fr_int2str(pair_lists, vpt->tmpl_list, "<INVALID>"),
				vp->da->name,
				fr_int2str(fr_tokens_table, vp->op, "<INVALID>"),
				value);
		}
		talloc_free(value);

		if (!RDEBUG_ENABLED3) continue;

		if (vp->da->vendor) {
			fr_dict_vendor_t const *vendor;

			vendor = fr_dict_vendor_by_num(NULL, vp->da->vendor);
			RIDEBUG2("Vendor : %i (%s)", vp->da->vendor, vendor ? vendor->name : "unknown");
		}
		RIDEBUG2("Type   : %s", fr_int2str(dict_attr_types, vp->vp_type, "<INVALID>"));

		switch (vp->vp_type) {
		case FR_TYPE_VARIABLE_SIZE:
			RIDEBUG2("Length : %zu", vp->vp_length);
			break;

		default:
			break;
		}

		if (!RDEBUG_ENABLED4) continue;

		type = dict_attr_types;
		while (type->name) {
			int pad;

			fr_value_box_t *dst = NULL;

			if ((fr_type_t) type->number == vp->vp_type) goto next_type;

			switch (type->number) {
			case FR_TYPE_INVALID:		/* Not real type */
			case FR_TYPE_MAX:		/* Not real type */
			case FR_TYPE_COMBO_IP_ADDR:	/* Covered by IPv4 address IPv6 address */
			case FR_TYPE_COMBO_IP_PREFIX:	/* Covered by IPv4 address IPv6 address */
			case FR_TYPE_TIMEVAL:		/* Not a VALUE_PAIR type */
			case FR_TYPE_STRUCTURAL:
				goto next_type;

			default:
				break;
			}

			dst = talloc_zero(vp, fr_value_box_t);
			/* We expect some to fail */
			if (fr_value_box_cast(dst, dst, type->number, NULL, &vp->data) < 0) {
				goto next_type;
			}

			value = fr_value_box_asprint(dst, dst, '\'');
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
static ssize_t xlat_map(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	vp_map_t *map = NULL;
	int ret;

	if (map_afrom_attr_str(request, &map, fmt,
			       REQUEST_CURRENT, PAIR_LIST_REQUEST,
			       REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt);
		return -1;
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
static ssize_t xlat_module(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, UNUSED char const *fmt)
{
	strlcpy(*out, request->module, outlen);

	return strlen(*out);
}

#if defined(HAVE_REGEX) && defined(HAVE_PCRE)
static ssize_t xlat_regex(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	char *p;
	size_t len;

	if (regex_request_to_sub_named(request, &p, request, fmt) < 0) return 0;

	len = talloc_array_length(p);
	if (len > outlen) {
		RDEBUG("Insufficient buffer space to write subcapture value, needed %zu bytes, have %zu bytes",
		       len, outlen);
		return -1;
	}
	strlcpy(*out, p, outlen);

	return len - 1; /* - \0 */
}
#endif

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
	pvp = (VALUE_PAIR **) request_data_reference(request, (void *)radius_get_vp, *(int const *) mod_inst);
	if (!pvp || !*pvp) return 0;

	*out = fr_pair_value_asprint(ctx, *pvp, '\0');
	return 	talloc_array_length(*out) - 1;
}
#endif

/** Print data as string, if possible.
 *
 * If attribute "Foo" is defined as "octets" it will normally
 * be printed as 0x0a0a0a. The xlat "%{string:Foo}" will instead
 * expand to "\n\n\n"
 */
static ssize_t xlat_string(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	ssize_t		ret;
	VALUE_PAIR	*vp;
	uint8_t		buffer[64];

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	/*
	 *	These are printed specially.
	 */
	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
		return fr_snprint(*out, outlen, (char const *) vp->vp_octets, vp->vp_length, '"');

		/*
		 *	Note that "%{string:...}" is NOT binary safe!
		 *	It is explicitly used to get rid of embedded zeros.
		 */
	case FR_TYPE_STRING:
		return strlcpy(*out, vp->vp_strvalue, outlen);

	default:
		break;
	}

	ret = fr_value_box_to_network(NULL, buffer, sizeof(buffer), &vp->data);
	if (ret < 0) return ret;

	return fr_snprint(*out, outlen, (char const *) buffer, ret, '\0');
}

/** xlat expand string attribute value
 *
 */
static ssize_t xlat_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	ssize_t slen;
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

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
static ssize_t xlat_debug(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
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
	xlat_t find;
	xlat_t *found;

	if (!xlat_root) return NULL;

	find.name = name;
	found = rbtree_finddata(xlat_root, &find);

	return found;
}

/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	rbtree_deletebydata(xlat_root, xlat);
	if (rbtree_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
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
	xlat_t	find;
	bool	new = false;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	find.name = name;
	c = rbtree_finddata(xlat_root, &find);
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
		talloc_set_destructor(c, _xlat_free);
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
 * @param[in] ctx			Used to automate deregistration of the xlat fnction.
 * @param[in] name			of the xlat.
 * @param[in] func			to register.
 * @param[in] instantiate		Instantiation function. Called whenever a xlat is
 *					compiled.
 * @param[in] inst_size			The size of the instance struct.
 *					Pre-allocated for use by the instantiate function.
 *					If 0, no memory will be allocated.
 * @param[in] detach			Called when an xlat_exp_t is freed.
 * @param[in] thread_instantiate	thread_instantiation_function. Called whenever a
 *					a thread is started to create thread local instance
 *					data.
 * @param[in] thread_inst_size		The size of the thread instance struct.
 *					Pre-allocated for use by the thread instance function.
 *					If 0, no memory will be allocated.
 * @param[in] thread_detach		Called when an xlat_exp_t is freed (if ephemeral),
 *					or when a thread exits.
 * @param[in] uctx			To pass to instantiate callbacks and the xlat function
 *					when it's called.  Usually the module instance that
 *					registered the xlat.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_async_register(TALLOC_CTX *ctx,
			char const *name, xlat_func_async_t func,
			xlat_instantiate_t instantiate, size_t inst_size,
			xlat_detach_t detach,
			xlat_thread_instantiate_t thread_instantiate, size_t thread_inst_size,
			xlat_thread_detach_t thread_detach,
			void *uctx)
{
	xlat_t	*c;
	xlat_t	find;
	bool	new = false;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	find.name = name;
	c = rbtree_finddata(xlat_root, &find);
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}

		if (!c->async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return -1;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(ctx, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_free);
		new = true;
	}

	c->func.async = func;
	c->type = XLAT_FUNC_ASYNC;

	c->instantiate = instantiate;
	c->thread_instantiate = thread_instantiate;

	c->inst_size = inst_size;
	c->thread_inst_size = thread_inst_size;

	c->detach = detach;
	c->thread_detach = thread_detach;

	c->async_safe = false;	/* async safe in this case means it might yield */
	c->uctx = uctx;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
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
	xlat_t	find = { .name = name };

	if (!name || !xlat_root) return;

	c = rbtree_finddata(xlat_root, &find);
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

typedef struct xlat_redundant_t {
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

static xlat_action_t xlat_concat(TALLOC_CTX *ctx, fr_cursor_t *out,
				 REQUEST *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				 fr_value_box_t **in)
{
	fr_value_box_t *result;
	char *buff;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	/*
	 *	Otherwise, join the boxes together commas
	 *	FIXME It'd be nice to set a custom delimiter
	 */
	result = fr_value_box_alloc_null(ctx);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_asprint(result, *in, ",", '\0');
	if (!buff) goto error;

	fr_value_box_strsteal(result, result, NULL, buff, fr_value_box_list_tainted(*in));

	fr_cursor_insert(out, result);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_bin(TALLOC_CTX *ctx, fr_cursor_t *out,
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
	fr_cursor_insert(out, result);

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
	if (xlat_root) return 0;

	xlat_t	*c;

#ifdef WITH_UNLANG
	int i;
#endif

	/*
	 *	Registers async xlat operations
	 */
	xlat_unlang_init();

	/*
	 *	Create the function tree
	 */
	xlat_root = rbtree_create(NULL, xlat_cmp, NULL, RBTREE_FLAG_REPLACE);
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

#define XLAT_REGISTER(_x) xlat_register(NULL, STRINGIFY(_x), xlat_ ## _x, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true); \
	c = xlat_func_find(STRINGIFY(_x)); \
	rad_assert(c != NULL); \
	c->internal = true

	XLAT_REGISTER(integer);
	XLAT_REGISTER(strlen);
	XLAT_REGISTER(length);
	XLAT_REGISTER(hex);
	XLAT_REGISTER(tag);
	XLAT_REGISTER(string);
	XLAT_REGISTER(xlat);
	XLAT_REGISTER(map);
	XLAT_REGISTER(module);
	XLAT_REGISTER(debug_attr);
#if defined(HAVE_REGEX) && defined(HAVE_PCRE)
	XLAT_REGISTER(regex);
#endif

	xlat_register(&xlat_foreach_inst[0], "debug", xlat_debug, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	c = xlat_func_find("debug");
	rad_assert(c != NULL);
	c->internal = true;

	xlat_async_register(NULL, "concat", xlat_concat, NULL, 0, NULL, NULL, 0, NULL, NULL);
	xlat_async_register(NULL, "bin", xlat_bin, NULL, 0, NULL, NULL, 0, NULL, NULL);

	return 0;
}

/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	TALLOC_FREE(xlat_root);
}


