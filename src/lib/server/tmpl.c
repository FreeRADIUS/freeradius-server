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
 * @brief #VALUE_PAIR template functions
 * @file src/lib/server/tmpl.c
 *
 * @ingroup AVP
 *
 * @copyright 2014-2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>

/** Map #tmpl_type_t values to descriptive strings
 */
FR_NAME_NUMBER const tmpl_names[] = {
	{ "literal",		TMPL_TYPE_UNPARSED 	},
	{ "xlat",		TMPL_TYPE_XLAT		},
	{ "attr",		TMPL_TYPE_ATTR		},
	{ "unknown attr",	TMPL_TYPE_ATTR_UNDEFINED	},
	{ "list",		TMPL_TYPE_LIST		},
	{ "regex",		TMPL_TYPE_REGEX		},
	{ "exec",		TMPL_TYPE_EXEC		},
	{ "data",		TMPL_TYPE_DATA		},
	{ "parsed xlat",	TMPL_TYPE_XLAT_STRUCT	},
	{ "parsed regex",	TMPL_TYPE_REGEX_STRUCT	},
	{ "null",		TMPL_TYPE_NULL		},
	{ NULL, 0 }
};

/** Map keywords to #pair_lists_t values
 */
const FR_NAME_NUMBER pair_lists[] = {
	{ "request",		PAIR_LIST_REQUEST },
	{ "reply",		PAIR_LIST_REPLY },
	{ "control",		PAIR_LIST_CONTROL },		/* New name should have priority */
	{ "config",		PAIR_LIST_CONTROL },
	{ "session-state",	PAIR_LIST_STATE },
#ifdef WITH_PROXY
	{ "proxy-request",	PAIR_LIST_PROXY_REQUEST },
	{ "proxy-reply",	PAIR_LIST_PROXY_REPLY },
#endif
	{  NULL , -1 }
};

/** Map keywords to #request_refs_t values
 */
const FR_NAME_NUMBER request_refs[] = {
	{ "outer",		REQUEST_OUTER },
	{ "current",		REQUEST_CURRENT },
	{ "parent",		REQUEST_PARENT },
	{ "proxy",		REQUEST_PROXY },
	{  NULL , -1 }
};

/** @name Parse list and request qualifiers to #pair_lists_t and #request_refs_t values
 *
 * These functions also resolve #pair_lists_t and #request_refs_t values to #REQUEST
 * structs and the head of #VALUE_PAIR lists in those structs.
 *
 * For adding new #VALUE_PAIR to the lists, the #radius_list_ctx function can be used
 * to obtain the appropriate TALLOC_CTX pointer.
 *
 * @note These don't really have much to do with #vp_tmpl_t. They're in the same
 *	file as they're used almost exclusively by the tmpl_* functions.
 * @{
 */

/** Resolve attribute name to a #pair_lists_t value.
 *
 * Check the name string for #pair_lists qualifiers and write a #pair_lists_t value
 * for that list to out. This value may be passed to #radius_list, along with the current
 * #REQUEST, to get a pointer to the actual list in the #REQUEST.
 *
 * If we're sure we've definitely found a list qualifier token delimiter (``:``) but the
 * string doesn't match a #radius_list qualifier, return 0 and write #PAIR_LIST_UNKNOWN
 * to out.
 *
 * If we can't find a string that looks like a request qualifier, set out to def, and
 * return 0.
 *
 * @note #radius_list_name should be called before passing a name string that may
 *	contain qualifiers to #fr_dict_attr_by_name.
 *
 * @param[out] out Where to write the list qualifier.
 * @param[in] name String containing list qualifiers to parse.
 * @param[in] def the list to return if no qualifiers were found.
 * @return 0 if no valid list qualifier could be found, else the number of bytes consumed.
 *	The caller may then advanced the name pointer by the value returned, to get the
 *	start of the attribute name (if any).
 *
 * @see pair_list
 * @see radius_list
 */
size_t radius_list_name(pair_lists_t *out, char const *name, pair_lists_t def)
{
	char const *p = name;
	char const *q;

	/* This should never be a NULL pointer */
	rad_assert(name);

	/*
	 *	Try and determine the end of the token
	 */
	for (q = p; fr_dict_attr_allowed_chars[(uint8_t) *q]; q++);

	switch (*q) {
	/*
	 *	It's a bareword made up entirely of dictionary chars
	 *	check and see if it's a list qualifier, and if it's
	 *	not, return the def and say we couldn't parse
	 *	anything.
	 */
	case '\0':
		*out = fr_substr2int(pair_lists, p, PAIR_LIST_UNKNOWN, (q - p));
		if (*out != PAIR_LIST_UNKNOWN) return q - p;
		*out = def;
		return 0;

	/*
	 *	It may be a list qualifier delimiter. Because of tags
	 *	We need to check that it doesn't look like a tag suffix.
	 *	We do this by looking at the chars between ':' and the
	 *	next token delimiter, and seeing if they're all digits.
	 */
	case ':':
	{
		char const *d = q + 1;

		if (isdigit((int) *d)) {
			while (isdigit((int) *d)) d++;

			/*
			 *	Char after the number string
			 *	was a token delimiter, so this is a
			 *	tag, not a list qualifier.
			 */
			if (!fr_dict_attr_allowed_chars[(uint8_t) *d]) {
				*out = def;
				return 0;
			}
		}

		*out = fr_substr2int(pair_lists, p, PAIR_LIST_UNKNOWN, (q - p));
		if (*out == PAIR_LIST_UNKNOWN) return 0;

		return (q + 1) - name; /* Consume the list and delimiter */
	}

	default:
		*out = def;
		return 0;
	}
}

/** Resolve attribute #pair_lists_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of a #VALUE_PAIR list in the
 * #REQUEST. If the head of the list changes, the pointer will still be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_lists_t value to resolve to #VALUE_PAIR list. Will be NULL if list
 *	name couldn't be resolved.
 * @return a pointer to the HEAD of a list in the #REQUEST.
 *
 * @see tmpl_cursor_init
 * @see fr_pair_cursor_init
 */
VALUE_PAIR **radius_list(REQUEST *request, pair_lists_t list)
{
	if (!request) return NULL;

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		if (!request->packet) return NULL;
		return &request->packet->vps;

	case PAIR_LIST_REPLY:
		if (!request->reply) return NULL;
		return &request->reply->vps;

	case PAIR_LIST_CONTROL:
		return &request->control;

	case PAIR_LIST_STATE:
		return &request->state;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		if (!request->proxy || !request->proxy->packet) break;
		return &request->proxy->packet->vps;

	case PAIR_LIST_PROXY_REPLY:
		if (!request->proxy || !request->proxy->reply) break;
		return &request->proxy->reply->vps;
#endif
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_int2str(pair_lists, list, "<INVALID>"));

	return NULL;
}

/** Resolve a list to the #RADIUS_PACKET holding the HEAD pointer for a #VALUE_PAIR list
 *
 * Returns a pointer to the #RADIUS_PACKET that holds the HEAD pointer of a given list,
 * for the current #REQUEST.
 *
 * @param[in] request To resolve list in.
 * @param[in] list #pair_lists_t value to resolve to #RADIUS_PACKET.
 * @return
 *	- #RADIUS_PACKET on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
RADIUS_PACKET *radius_packet(REQUEST *request, pair_lists_t list)
{
	switch (list) {
	/* Don't add default */
	case PAIR_LIST_STATE:
	case PAIR_LIST_CONTROL:
	case PAIR_LIST_UNKNOWN:
		return NULL;

	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		if (!request->proxy) return NULL;
		return request->proxy->packet;

	case PAIR_LIST_PROXY_REPLY:
		if (!request->proxy) return NULL;
		return request->proxy->reply;
#endif
	}

	return NULL;
}

/** Return the correct TALLOC_CTX to alloc #VALUE_PAIR in, for a list
 *
 * Allocating new #VALUE_PAIR in the context of a #REQUEST is usually wrong.
 * #VALUE_PAIR should be allocated in the context of a #RADIUS_PACKET, so that if the
 * #RADIUS_PACKET is freed before the #REQUEST, the associated #VALUE_PAIR lists are
 * freed too.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_lists_t value to resolve to TALLOC_CTX.
 * @return
 *	- TALLOC_CTX on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
TALLOC_CTX *radius_list_ctx(REQUEST *request, pair_lists_t list)
{
	if (!request) return NULL;

	switch (list) {
	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;

	case PAIR_LIST_CONTROL:
		return request;

	case PAIR_LIST_STATE:
		return request->state_ctx;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		if (!request->proxy) return NULL;
		return request->proxy->packet;

	case PAIR_LIST_PROXY_REPLY:
		if (!request->proxy) return NULL;
		return request->proxy->reply;
#endif

	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;
	}

	return NULL;
}

/** Resolve attribute name to a #request_refs_t value.
 *
 * Check the name string for qualifiers that reference a parent #REQUEST.
 *
 * If we find a string that matches a #request_refs qualifier, return the number of chars
 * we consumed.
 *
 * If we're sure we've definitely found a list qualifier token delimiter (``*``) but the
 * qualifier doesn't match one of the #request_refs qualifiers, return 0 and set out to
 * #REQUEST_UNKNOWN.
 *
 * If we can't find a string that looks like a request qualifier, set out to def, and
 * return 0.
 *
 * @param[out] out The #request_refs_t value the name resolved to (or #REQUEST_UNKNOWN).
 * @param[in] name of attribute.
 * @param[in] def default request ref to return if no request qualifier is present.
 * @return 0 if no valid request qualifier could be found, else the number of bytes consumed.
 *	The caller may then advanced the name pointer by the value returned, to get the
 *	start of the attribute list or attribute name(if any).
 *
 * @see radius_list_name
 * @see request_refs
 */
size_t radius_request_name(request_refs_t *out, char const *name, request_refs_t def)
{
	char const *p, *q;

	p = name;
	/*
	 *	Try and determine the end of the token
	 */
	for (q = p; fr_dict_attr_allowed_chars[(uint8_t) *q] && (*q != '.') && (*q != '-'); q++);

	/*
	 *	First token delimiter wasn't a '.'
	 */
	if (*q != '.') {
		*out = def;
		return 0;
	}

	*out = fr_substr2int(request_refs, name, REQUEST_UNKNOWN, q - p);
	if (*out == REQUEST_UNKNOWN) return 0;

	return (q + 1) - p;
}

/** Resolve a #request_refs_t to a #REQUEST.
 *
 * Sometimes #REQUEST structs may be chained to each other, as is the case
 * when internally proxying EAP. This function resolves a #request_refs_t
 * to a #REQUEST higher in the chain than the current #REQUEST.
 *
 * @see radius_list
 * @param[in,out] context #REQUEST to start resolving from, and where to write
 *	a pointer to the resolved #REQUEST back to.
 * @param[in] name (request) to resolve.
 * @return
 *	- 0 if request is valid in this context.
 *	- -1 if request is not valid in this context.
 */
int radius_request(REQUEST **context, request_refs_t name)
{
	REQUEST *request = *context;

	switch (name) {
	case REQUEST_CURRENT:
		return 0;

	case REQUEST_PARENT:	/* for future use in request chaining */
	case REQUEST_OUTER:
		if (!request->parent) {
			return -1;
		}
		*context = request->parent;
		break;

	case REQUEST_PROXY:
		if (!request->proxy) {
			return -1;
		}
		*context = request->proxy;
		break;

	case REQUEST_UNKNOWN:
	default:
		rad_assert(0);
		return -1;
	}

	return 0;
}
/** @} */

/** @name Alloc or initialise #vp_tmpl_t
 *
 * @note Should not usually be called outside of tmpl_* functions, use one of
 *	the tmpl_*from_* functions instead.
 * @{
 */

/** Initialise stack allocated #vp_tmpl_t
 *
 * @note Name is not talloc_strdup'd or memcpy'd so must be available, and must not change
 *	for the lifetime of the #vp_tmpl_t.
 *
 * @param[out] vpt to initialise.
 * @param[in] type to set in the #vp_tmpl_t.
 * @param[in] name of the #vp_tmpl_t.
 * @param[in] len The length of the buffer (or a substring of the buffer) pointed to by name.
 *	If < 0 strlen will be used to determine the length.
 * @param[in] quote The type of quoting around the template name.
 * @return a pointer to the initialised #vp_tmpl_t. The same value as vpt.
 */
vp_tmpl_t *tmpl_init(vp_tmpl_t *vpt, tmpl_type_t type, char const *name, ssize_t len, FR_TOKEN quote)
{
	rad_assert(vpt);
	rad_assert(type != TMPL_TYPE_UNKNOWN);
	rad_assert(type <= TMPL_TYPE_NULL);

	memset(vpt, 0, sizeof(vp_tmpl_t));
	vpt->type = type;

	if (name) {
		vpt->name = name;
		vpt->len = len < 0 ? strlen(name) :
				     (size_t) len;
		vpt->quote = quote;
	}
	return vpt;
}

/** Create a new heap allocated #vp_tmpl_t
 *
 * @param[in,out] ctx to allocate in.
 * @param[in] type to set in the #vp_tmpl_t.
 * @param[in] name of the #vp_tmpl_t (will be copied to a new talloc buffer parented
 *	by the #vp_tmpl_t).
 * @param[in] len The length of the buffer (or a substring of the buffer) pointed to by name.
 *	If < 0 strlen will be used to determine the length.
 * @param[in] quote The type of quoting around the template name.
 * @return the newly allocated #vp_tmpl_t.
 */
vp_tmpl_t *tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name, ssize_t len, FR_TOKEN quote)
{
	vp_tmpl_t *vpt;

	rad_assert(type != TMPL_TYPE_UNKNOWN);
	rad_assert(type <= TMPL_TYPE_NULL);

#ifndef HAVE_REGEX
	if ((type == TMPL_TYPE_REGEX) || (type == TMPL_TYPE_REGEX_STRUCT)) {
		return NULL;
	}
#endif

	vpt = talloc_zero(ctx, vp_tmpl_t);
	if (!vpt) return NULL;
	vpt->type = type;
	if (name) {
		vpt->name = talloc_bstrndup(vpt, name, len < 0 ? strlen(name) : (size_t)len);
		vpt->len = talloc_array_length(vpt->name) - 1;
		vpt->quote = quote;
	}

	return vpt;
}
/* @} **/

/** @name Create new #vp_tmpl_t from a string
 *
 * @{
 */

/** Initialise a #vp_tmpl_t to search for, or create attributes
 *
 * @param vpt to initialise.
 * @param da of #VALUE_PAIR type to operate on.
 * @param tag Must be one of:
 *	- A positive integer specifying a specific tag.
 *	- #TAG_ANY - Attribute with no specific tag value.
 *	- #TAG_NONE - No tag.
 * @param num Specific instance, or all instances. Must be one of:
 *	- A positive integer specifying an instance.
 *	- #NUM_ALL - All instances.
 *	- #NUM_ANY - The first instance found.
 *	- #NUM_LAST - The last instance found.
 * @param request to operate on.
 * @param list to operate on.
 */
void tmpl_from_da(vp_tmpl_t *vpt, fr_dict_attr_t const *da, int8_t tag, int num,
		  request_refs_t request, pair_lists_t list)
{
	static char const name[] = "internal";

	rad_assert(da);

	tmpl_init(vpt, TMPL_TYPE_ATTR, name, sizeof(name), T_BARE_WORD);
	vpt->tmpl_da = da;

	vpt->tmpl_request = request;
	vpt->tmpl_list = list;

	/*
	 *	No tags can't have any tags
	 */
	if (!vpt->tmpl_da->flags.has_tag) {
		vpt->tmpl_tag = TAG_NONE;
	} else {
		vpt->tmpl_tag = tag;
	}
	vpt->tmpl_num = num;
}

/** Create a #vp_tmpl_t from a #fr_value_box_t
 *
 * @param[in,out] ctx	to allocate #vp_tmpl_t in.
 * @param[out] out	Where to write pointer to new #vp_tmpl_t.
 * @param[in] data	to convert.
 * @param[in] steal	If true, any buffers are moved to the new
 *			ctx instead of being duplicated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_afrom_value_box(TALLOC_CTX *ctx, vp_tmpl_t **out, fr_value_box_t *data, bool steal)
{
	char const *name;
	vp_tmpl_t *vpt;

	vpt = talloc(ctx, vp_tmpl_t);
	name = fr_value_box_asprint(vpt, data, '\0');
	tmpl_init(vpt, TMPL_TYPE_DATA, name, talloc_array_length(name),
		  (data->type == FR_TYPE_STRING) ? T_SINGLE_QUOTED_STRING : T_BARE_WORD);

	if (steal) {
		if (fr_value_box_steal(vpt, &vpt->tmpl_value, data) < 0) {
			talloc_free(vpt);
			return -1;
		}
	} else {
		if (fr_value_box_copy(vpt, &vpt->tmpl_value, data) < 0) {
			talloc_free(vpt);
			return -1;
		}
	}
	*out = vpt;

	return 0;
}

/** Default parser rules
 *
 * Because this is getting to be a ridiculous number of parsing rules
 * to pass in via arguments.
 *
 * Defaults are used if a NULL rules pointer is passed to the parsing function.
 */
static vp_tmpl_rules_t const default_rules = {
	.request_def = REQUEST_CURRENT,
	.list_def = PAIR_LIST_REQUEST
};

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #vp_tmpl_t
 *
 * @param[in,out] ctx		to allocate #vp_tmpl_t in.
 * @param[out] out		Where to write pointer to new #vp_tmpl_t.
 * @param[in] name		of attribute including #request_refs and #pair_lists qualifiers.
 *				If only #request_refs #pair_lists qualifiers are found,
 *				a #TMPL_TYPE_LIST #vp_tmpl_t will be produced.
 * @param[in] rules		Rules which control parsing:
 *				- dict_def		The default dictionary to use if attributes
 *							are unqualified.
 *				- request_def		The default #REQUEST to set if no
 *							#request_refs qualifiers are found in name.
 *				- list_def		The default list to set if no #pair_lists
 *							qualifiers are found in the name.
 *				- allow_unknown		If true attributes in the format accepted by
 *							#fr_dict_unknown_afrom_oid_substr will be allowed,
 *							even if they're not in the main dictionaries.
 *							If an unknown attribute is found a #TMPL_TYPE_ATTR
 *							#vp_tmpl_t will be produced.
 *							If #tmpl_afrom_attr_substr is being called on
 *							startup, the #vp_tmpl_t may be passed to
 *							#tmpl_define_unknown_attr to
 *							add the unknown attribute to the main dictionary.
 *							If the unknown attribute is not added to
 *							the main dictionary the #vp_tmpl_t cannot be used
 *							to search for a #VALUE_PAIR in a #REQUEST.
 *				- allow_undefined	If true, we don't generate a parse error on
 *							unknown attributes. If an unknown attribute is
 *							found a #TMPL_TYPE_ATTR_UNDEFINED
 *							#vp_tmpl_t will be produced.
 *				- allow_foreign		If true, allow attribute names to be qualified
 *							with a protocol outside of the passed dict_def.
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
ssize_t tmpl_afrom_attr_substr(TALLOC_CTX *ctx, vp_tmpl_t **out, char const *name, vp_tmpl_rules_t const *rules)
{
	char const	*p;
	long		num;
	ssize_t		slen;
	vp_tmpl_t	*vpt;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	p = name;

	if (*p == '&') p++;

	if (!*p) {
		fr_strerror_printf("Invalid attribute name.");
		return -1;
	}

	MEM(vpt = talloc_zero(ctx, vp_tmpl_t));

	/*
	 *	Search for a recognised list
	 *
	 *	There may be multiple '.' separated
	 *	components, so don't error out if
	 *	the first one doesn't match a known list.
	 *
	 *	The next check for a list qualifier
	 */
	p += radius_request_name(&vpt->tmpl_request, p, rules->request_def);
	if (vpt->tmpl_request == REQUEST_UNKNOWN) vpt->tmpl_request = rules->request_def;

	/*
	 *	Finding a list qualifier is optional
	 *
	 *	Because the list name parser can
	 *	determine if something was a tag
	 *	or a list, we trust that when it
	 *	returns PAIR_LIST_UNKOWN that
	 *	the input string is invalid.
	 */
	p += radius_list_name(&vpt->tmpl_list, p, rules->list_def);
	if (vpt->tmpl_list == PAIR_LIST_UNKNOWN) {
		fr_strerror_printf("Invalid list qualifier");
		slen = -(p - name);
	error:
		talloc_free(vpt);
		return slen;
	}

	vpt->tmpl_tag = TAG_NONE;
	vpt->tmpl_num = NUM_ANY;
	vpt->type = TMPL_TYPE_ATTR;

	/*
	 *	This may be just a bare list, but it can still
	 *	have instance selectors and tag selectors.
	 */
	switch (*p) {
	case '\0':
		vpt->type = TMPL_TYPE_LIST;
		goto finish;

	case '[':
		vpt->type = TMPL_TYPE_LIST;
		goto do_num;

	default:
		break;
	}

	/*
	 *	Look up by name, *including* any Attr-1.2.3.4 which was created when
	 *	parsing the configuration files.
	 */
	slen = fr_dict_attr_by_qualified_name_substr(NULL, &vpt->tmpl_da, rules->dict_def, p);
	if (slen <= 0) {
		char const *q;

		fr_strerror();	/* Clear out any existing errors */

		/*
		 *	At this point, the OID *must* be unknown, and
		 *	not previously used.
		 */
		slen = fr_dict_unknown_afrom_oid_substr(vpt, &vpt->tmpl_unknown,
						    	fr_dict_root(rules->dict_def), p);
		/*
		 *	Attr-1.2.3.4 is OK.
		 */
		if (slen > 0) {
			if (!rules->allow_unknown) {
				fr_strerror_printf("Unknown attribute");
				slen = -(p - name);
				goto error;
			}

			/*
			 *	Unknown attributes can't be encoded, as we don't
			 *	know how to encode them!
			 */
			vpt->tmpl_unknown->flags.internal = 1;
			vpt->tmpl_da = vpt->tmpl_unknown;

			p += slen;

			goto do_num; /* unknown attributes can't have tags */
		}

		/*
		 *	Can't parse it as an attribute, might be a literal string
		 *	let the caller decide.
		 *
		 *	Don't alter the fr_strerror buffer, should contain the parse
		 *	error from fr_dict_unknown_from_suboid.
		 */
		if (!rules->allow_undefined) {
			fr_strerror_printf("Undefined attributes not allowed here");
			slen = -(p - name);
			goto error;
		}

		/*
		 *	Copy the name to a field for later resolution
		 */
		vpt->type = TMPL_TYPE_ATTR_UNDEFINED;
		for (q = p; fr_dict_attr_allowed_chars[(uint8_t) *q]; q++);
		if (q == p) {
			fr_strerror_printf("Invalid attribute name");
			slen = -(p - name);
			goto error;
		}

		if ((q - p) >= FR_DICT_ATTR_MAX_NAME_LEN) {
			fr_strerror_printf("Attribute name is too long");
			slen = -(p - name);
			goto error;
		}
		vpt->tmpl_unknown_name = talloc_strndup(vpt, p, q - p);
		p = q;

		goto do_num;
	}

	/*
	 *	Check that the attribute we resolved was from an allowed dictionary
	 */
	if (!rules->allow_foreign && rules->dict_def && (fr_dict_by_da(vpt->tmpl_da) != rules->dict_def)) {
		fr_strerror_printf("Only attribute from protocol \"%s\" allowed", fr_dict_root(rules->dict_def)->name);
		slen = -(p - name);
		goto error;
	}

	/*
	 *	Parsing was successful, so advance the pointer
	 */
	p += slen;

	/*
	 *	If it's an attribute, look for a tag.
	 *
	 *	Note that we check for tags even if the attribute
	 *	isn't tagged.  This lets us print more useful error
	 *	messages.
	 */
	if (*p == ':') {
		char *q;

		if (!vpt->tmpl_da->flags.has_tag) { /* Lists don't have a da */
			fr_strerror_printf("Attribute '%s' cannot have a tag", vpt->tmpl_da->name);
			slen = -(p - name);
			goto error;
		}

		/*
		 *	Allow '*' as an explicit wildcard.
		 */
		if (p[1] == '*') {
			vpt->tmpl_tag = TAG_ANY;
			p += 2;

		} else {
			num = strtol(p + 1, &q, 10);
			if (!TAG_VALID_ZERO(num)) {
				fr_strerror_printf("Invalid tag value '%li' (should be between 0-31)", num);
				slen = -((p + 1) - name);
				goto error;
			}

			vpt->tmpl_tag = num;
			p = q;
		}

	/*
	 *	The attribute is tagged, but the admin didn't
	 *	specify one.  This means it's likely a
	 *	"search" thingy.. i.e. "find me ANY attribute,
	 *	no matter what the tag".
	 */
	} else if (vpt->tmpl_da->flags.has_tag) {
		vpt->tmpl_tag = TAG_ANY;
	}

do_num:
	if (*p == '\0') goto finish;

	if (*p == '[') {
		p++;

		switch (*p) {
		case '#':
			vpt->tmpl_num = NUM_COUNT;
			p++;
			break;

		case '*':
			vpt->tmpl_num = NUM_ALL;
			p++;
			break;

		case 'n':
			vpt->tmpl_num = NUM_LAST;
			p++;
			break;

		default:
		{
			char *q;

			num = strtol(p, &q, 10);
			if (p == q) {
				fr_strerror_printf("Array index is not an integer");
				slen = -(p - name);
				goto error;
			}

			if ((num > 1000) || (num < 0)) {
				fr_strerror_printf("Invalid array reference '%li' (should be between 0-1000)", num);
				slen = -(p - name);
				goto error;
			}
			vpt->tmpl_num = num;
			p = q;
		}
			break;
		}

		if (*p != ']') {
			fr_strerror_printf("No closing ']' for array index");
			slen = -(p - name);
			goto error;
		}
		p++;
	}

finish:
	vpt->name = talloc_strndup(vpt, name, p - name);
	vpt->len = p - name;
	vpt->quote = T_BARE_WORD;

	/*
	 *	Copy over the attribute definition, now we're
	 *	sure what we were passed is valid.
	 */
	if ((vpt->type == TMPL_TYPE_ATTR) && vpt->tmpl_da->flags.is_unknown) vpt->tmpl_da = vpt->tmpl_unknown;

	TMPL_VERIFY(vpt);	/* Because we want to ensure we produced something sane */

	*out = vpt;

	return vpt->len;
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #vp_tmpl_t
 *
 * @note Unlike #tmpl_afrom_attr_substr this function will error out if the entire
 *	name string isn't parsed.
 *
 * @copydetails tmpl_afrom_attr_substr
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, vp_tmpl_t **out, char const *name, vp_tmpl_rules_t const *rules)
{
	ssize_t slen;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	slen = tmpl_afrom_attr_substr(ctx, out, name, rules);
	if (slen <= 0) return slen;

	if (!fr_cond_assert(*out)) return -1;

	if (slen != (ssize_t)strlen(name)) {
		/* This looks wrong, but it produces meaningful errors for unknown attrs with tags */
		fr_strerror_printf("Unexpected text after %s", fr_int2str(tmpl_names, (*out)->type, "<INVALID>"));
		return -slen;
	}

	TMPL_VERIFY(*out);

	return slen;
}

/** Convert an arbitrary string into a #vp_tmpl_t
 *
 * @note Unlike #tmpl_afrom_attr_str return code 0 doesn't necessarily indicate failure,
 *	may just mean a 0 length string was parsed.
 *
 * @note xlats and regexes are left uncompiled.  This is to support the two pass parsing
 *	done by the modcall code.  Compilation on pass1 of that code could fail, as
 *	attributes or xlat functions registered by modules may not be available (yet).
 *
 * @note For details of attribute parsing see #tmpl_afrom_attr_substr.
 *
 * @param[in,out] ctx		To allocate #vp_tmpl_t in.
 * @param[out] out		Where to write the pointer to the new #vp_tmpl_t.
 * @param[in] in		String to convert to a #vp_tmpl_t.
 * @param[in] inlen		length of string to convert.
 * @param[in] type		of quoting around value. May be one of:
 *				- #T_BARE_WORD - If string begins with ``&``
 *				  produces #TMPL_TYPE_ATTR,
 *	  			  #TMPL_TYPE_ATTR_UNDEFINED, #TMPL_TYPE_LIST or error.
 *	  			  If string does not begin with ``&`` produces
 *				  #TMPL_TYPE_UNPARSED, #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 *				- #T_SINGLE_QUOTED_STRING - Produces #TMPL_TYPE_UNPARSED
 *				- #T_DOUBLE_QUOTED_STRING - Produces #TMPL_TYPE_XLAT or
 *				  #TMPL_TYPE_UNPARSED (if string doesn't contain ``%``).
 *				- #T_BACK_QUOTED_STRING - Produces #TMPL_TYPE_EXEC
 *				- #T_OP_REG_EQ - Produces #TMPL_TYPE_REGEX
 * @param[in] rules		Parsing rules for attribute references.
 * @param[in] do_unescape	whether or not we should do unescaping.
 *				Should be false if the caller already did it.
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @see tmpl_afrom_attr_substr
 */
ssize_t tmpl_afrom_str(TALLOC_CTX *ctx, vp_tmpl_t **out,
		       char const *in, size_t inlen, FR_TOKEN type, vp_tmpl_rules_t const *rules, bool do_unescape)
{
	bool		do_xlat;
	char		quote;
	char const	*p;
	ssize_t		slen;
	fr_type_t	data_type = FR_TYPE_STRING;
	vp_tmpl_t	*vpt = NULL;
	fr_value_box_t	data;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	switch (type) {
	case T_BARE_WORD:
	{
		vp_tmpl_rules_t	mrules;

		memcpy(&mrules, rules, sizeof(mrules));

		/*
		 *  No attribute names start with 0x, and if they did, the user
		 *  can just use the explicit & prefix.
		 */
		if ((in[0] == '0') && (tolower(in[1]) == 'x')) {
			size_t binlen, len;

			/*
			 *  Hex strings must contain even number of characters
			 */
			if (inlen & 0x01) {
				fr_strerror_printf("Hex string not even length");
				return -inlen;
			}

			if (inlen <= 2) {
				fr_strerror_printf("Zero length hex string is invalid");
				return -inlen;
			}

			binlen = (inlen - 2) / 2;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, in, inlen, type);
			vpt->tmpl_value.datum.ptr = talloc_array(vpt, uint8_t, binlen);
			vpt->tmpl_value_length = binlen;
			vpt->tmpl_value_type = FR_TYPE_OCTETS;

			len = fr_hex2bin(vpt->tmpl_value.datum.ptr, binlen, in + 2, inlen - 2);
			if (len != binlen) {
				fr_strerror_printf("Hex string contains none hex char");
				talloc_free(vpt);
				return -(len + 2);
			}
			slen = len;
			break;
		}

		/*
		 *	If we can parse it as an attribute, it's an attribute.
		 *	Otherwise, treat it as a literal.
		 */
		quote = '\0';

		mrules.allow_undefined = (in[0] == '&');

		slen = tmpl_afrom_attr_str(ctx, &vpt, in, &mrules);
		if (mrules.allow_undefined && (slen <= 0)) return slen;
		if (slen > 0) break;
	}
		goto parse;

	case T_SINGLE_QUOTED_STRING:
		quote = '\'';

	parse:
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL,
						  in, inlen, quote, false) < 0) return 0;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, data.vb_strvalue,
					 talloc_array_length(data.vb_strvalue) - 1, type);
			talloc_free(data.datum.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, in, inlen, type);
		}
		slen = vpt->len;
		break;

	case T_DOUBLE_QUOTED_STRING:
		do_xlat = false;

		p = in;
		while (*p) {
			if (do_unescape) { /* otherwise \ is just another character */
				if (*p == '\\') {
					if (!p[1]) break;
					p += 2;
					continue;
				}
			}

			if (*p == '%') {
				do_xlat = true;
				break;
			}

			p++;
		}

		/*
		 *	If the double quoted string needs to be
		 *	expanded at run time, make it an xlat
		 *	expansion.  Otherwise, convert it to be a
		 *	literal.
		 */
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL, in,
						  inlen, fr_token_quote[type], false) < 0) return -1;
			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT, data.vb_strvalue,
						 talloc_array_length(data.vb_strvalue) - 1, type);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, data.vb_strvalue,
						 talloc_array_length(data.vb_strvalue) - 1, type);
				vpt->quote = T_DOUBLE_QUOTED_STRING;
			}
			talloc_free(data.datum.ptr);
		} else {
			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT, in, inlen, type);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, in, inlen, type);
				vpt->quote = T_DOUBLE_QUOTED_STRING;
			}
		}
		slen = vpt->len;
		break;

	case T_BACK_QUOTED_STRING:
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL, in,
						  inlen, fr_token_quote[type], false) < 0) return -1;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, data.vb_strvalue,
					 talloc_array_length(data.vb_strvalue) - 1, type);
			talloc_free(data.datum.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, in, inlen, type);
		}
		slen = vpt->len;
		break;

	case T_OP_REG_EQ: /* hack */
		vpt = tmpl_alloc(ctx, TMPL_TYPE_REGEX, in, inlen, T_BARE_WORD);
		slen = vpt->len;
		break;

	default:
		rad_assert(0);
		return 0;	/* 0 is an error here too */
	}

	if (!vpt) return 0;

	vpt->quote = type;

	rad_assert(slen >= 0);

	TMPL_VERIFY(vpt);
	*out = vpt;

	return slen;
}
/* @} **/

/** @name Cast or convert #vp_tmpl_t
 *
 * #tmpl_cast_in_place can be used to convert #TMPL_TYPE_UNPARSED to a #TMPL_TYPE_DATA of a
 *  specified #fr_type_t.
 *
 * #tmpl_cast_in_place_str does the same as #tmpl_cast_in_place, but will always convert to
 * #fr_type_t #FR_TYPE_STRING.
 *
 * #tmpl_cast_to_vp does the same as #tmpl_cast_in_place, but outputs a #VALUE_PAIR.
 *
 * #tmpl_define_unknown_attr converts a #TMPL_TYPE_ATTR with an unknown #fr_dict_attr_t to a
 * #TMPL_TYPE_ATTR with a known #fr_dict_attr_t, by adding the unknown #fr_dict_attr_t to the main
 * dictionary, and updating the ``tmpl_da`` pointer.
 * @{
 */

/** Convert #vp_tmpl_t of type #TMPL_TYPE_UNPARSED or #TMPL_TYPE_DATA to #TMPL_TYPE_DATA of type specified
 *
 * @note Conversion is done in place.
 * @note Irrespective of whether the #vp_tmpl_t was #TMPL_TYPE_UNPARSED or #TMPL_TYPE_DATA,
 *	on successful cast it will be #TMPL_TYPE_DATA.
 *
 * @param[in,out] vpt	The template to modify. Must be of type #TMPL_TYPE_UNPARSED
 *			or #TMPL_TYPE_DATA.
 * @param[in] type	to cast to.
 * @param[in] enumv	Enumerated dictionary values associated with a #fr_dict_attr_t.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_in_place(vp_tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv)
{
	TMPL_VERIFY(vpt);

	rad_assert(vpt != NULL);
	rad_assert((vpt->type == TMPL_TYPE_UNPARSED) || (vpt->type == TMPL_TYPE_DATA));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		vpt->tmpl_value_type = type;

		/*
		 *	Why do we pass a pointer to the tmpl type? Goddamn WiMAX.
		 */
		if (fr_value_box_from_str(vpt, &vpt->tmpl_value, &vpt->tmpl_value_type,
					  enumv, vpt->name, vpt->len, '\0', false) < 0) return -1;
		vpt->type = TMPL_TYPE_DATA;
		break;

	case TMPL_TYPE_DATA:
	{
		fr_value_box_t new;

		if (type == vpt->tmpl_value_type) return 0;	/* noop */

		if (fr_value_box_cast(vpt, &new, type, enumv, &vpt->tmpl_value) < 0) return -1;

		/*
		 *	Free old value buffers
		 */
		switch (vpt->tmpl_value_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			talloc_free(vpt->tmpl_value.datum.ptr);
			break;

		default:
			break;
		}

		fr_value_box_copy(vpt, &vpt->tmpl_value, &new);
	}
		break;

	default:
		rad_assert(0);
	}

	TMPL_VERIFY(vpt);

	return 0;
}

/** Convert #vp_tmpl_t of type #TMPL_TYPE_UNPARSED to #TMPL_TYPE_DATA of type #FR_TYPE_STRING
 *
 * @note Conversion is done in place.
 *
 * @param[in,out] vpt The template to modify. Must be of type #TMPL_TYPE_UNPARSED.
 */
void tmpl_cast_in_place_str(vp_tmpl_t *vpt)
{
	rad_assert(vpt != NULL);
	rad_assert(vpt->type == TMPL_TYPE_UNPARSED);

	vpt->tmpl_value.vb_strvalue = talloc_typed_strdup(vpt, vpt->name);
	rad_assert(vpt->tmpl_value.vb_strvalue != NULL);

	vpt->type = TMPL_TYPE_DATA;
	vpt->tmpl_value_type = FR_TYPE_STRING;
	vpt->tmpl_value_length = talloc_array_length(vpt->tmpl_value.vb_strvalue) - 1;
}

/** Expand a #vp_tmpl_t to a string, parse it as an attribute of type cast, create a #VALUE_PAIR from the result
 *
 * @note Like #tmpl_expand, but produces a #VALUE_PAIR.
 *
 * @param out Where to write pointer to the new #VALUE_PAIR.
 * @param request The current #REQUEST.
 * @param vpt to cast. Must be one of the following types:
 *	- #TMPL_TYPE_UNPARSED
 *	- #TMPL_TYPE_EXEC
 *	- #TMPL_TYPE_XLAT
 *	- #TMPL_TYPE_XLAT_STRUCT
 *	- #TMPL_TYPE_ATTR
 *	- #TMPL_TYPE_DATA
 * @param cast type of #VALUE_PAIR to create.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
		    vp_tmpl_t const *vpt, fr_dict_attr_t const *cast)
{
	int		rcode;
	VALUE_PAIR	*vp;
	fr_value_box_t	data;
	char		*p;

	TMPL_VERIFY(vpt);

	*out = NULL;

	vp = fr_pair_afrom_da(request, cast);
	if (!vp) return -1;

	if (vpt->type == TMPL_TYPE_DATA) {
		VP_VERIFY(vp);
		rad_assert(vp->vp_type == vpt->tmpl_value_type);

		fr_value_box_copy(vp, &vp->data, &vpt->tmpl_value);
		*out = vp;
		return 0;
	}

	rcode = tmpl_aexpand(vp, &p, request, vpt, NULL, NULL);
	if (rcode < 0) {
		fr_pair_list_free(&vp);
		return rcode;
	}
	data.vb_strvalue = p;

	/*
	 *	New escapes: strings are in binary form.
	 */
	if (vp->vp_type == FR_TYPE_STRING) {
		fr_pair_value_strcpy(vp, data.datum.ptr);
	} else if (fr_pair_value_from_str(vp, data.vb_strvalue, rcode, '\0', false) < 0) {
		fr_value_box_clear(&data);
		fr_pair_list_free(&vp);
		return -1;
	}

	*out = vp;
	return 0;
}

/** Add an unknown #fr_dict_attr_t specified by a #vp_tmpl_t to the main dictionary
 *
 * @param vpt to add. ``tmpl_da`` pointer will be updated to point to the
 *	#fr_dict_attr_t inserted into the dictionary.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_define_unknown_attr(vp_tmpl_t *vpt)
{
	fr_dict_attr_t const *da;

	if (!vpt) return 1;

	TMPL_VERIFY(vpt);

	if (vpt->type != TMPL_TYPE_ATTR) return 1;

	if (!vpt->tmpl_da->flags.is_unknown) return 1;

	da = fr_dict_unknown_add(fr_dict_internal, vpt->tmpl_da);
	if (!da) return -1;
	vpt->tmpl_da = da;

	return 0;
}

/** Add an undefined #fr_dict_attr_t specified by a #vp_tmpl_t to the main dictionary
 *
 * @note fr_dict_attr_add will not return an error if the attribute already exists
 *	meaning that multiple #vp_tmpl_t specifying the same attribute can be
 *	passed to this function to be fixed up, so long as the type and flags
 *	are identical.
 *
 * @param[in] dict_def	Default dictionary to use if none is
 *			specified by the tmpl_unknown_name.
 * @param[in] vpt	specifying undefined attribute to add.
 *			``tmpl_da`` pointer will be updated to
 *			point to the #fr_dict_attr_t inserted
 *			into the dictionary. Lists and requests
 *			will be preserved.
 * @param[in] type	to define undefined attribute as.
 * @param[in] flags	to define undefined attribute with.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_define_undefined_attr(fr_dict_t *dict_def, vp_tmpl_t *vpt,
			       fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t const *da;

	if (!vpt) return -1;

	TMPL_VERIFY(vpt);

	if (vpt->type != TMPL_TYPE_ATTR_UNDEFINED) return 1;

	if (fr_dict_attr_add(dict_def, fr_dict_root(fr_dict_internal), vpt->tmpl_unknown_name, -1, type, flags) < 0) {
		return -1;
	}
	da = fr_dict_attr_by_name(dict_def, vpt->tmpl_unknown_name);
	if (!da) return -1;

	if (type != da->type) {
		fr_strerror_printf("Attribute %s of type %s already defined with type %s",
				   da->name, fr_int2str(fr_value_box_type_names, type, "<UNKNOWN>"),
				   fr_int2str(fr_value_box_type_names, da->type, "<UNKNOWN>"));
		return -1;
	}

	if (memcmp(flags, &da->flags, sizeof(*flags)) != 0) {
		fr_strerror_printf("Attribute %s already defined with different flags", da->name);
		return -1;
	}

#ifndef NDEBUG
	/*
	 *	Clear existing data (so we don't trip TMPL_VERIFY);
	 */
	memset(&vpt->data.attribute.unknown, 0, sizeof(vpt->data.attribute.unknown));
#endif

	vpt->tmpl_da = da;
	vpt->type = TMPL_TYPE_ATTR;

	return 0;
}
/* @} **/

/** @name Resolve a #vp_tmpl_t outputting the result in various formats
 *
 * @{
 */

/** Expand a #vp_tmpl_t to a string writing the result to a buffer
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #vp_tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * Depending what arguments are passed, either copies the value to buff, or writes a pointer
 * to a string buffer to out. This allows the most efficient access to the value resolved by
 * the #vp_tmpl_t, avoiding unecessary string copies.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint
 *	should be used before using these values in debug statements. #is_printable can be used to
 *	check if the string only contains printable chars.
 *
 * @param[out] out		Where to write a pointer to the string buffer. On return may
 *				point to buff if buff was used to store the value. Otherwise will
 *				point to a #fr_value_box_t buffer, or the name of the template.
 *				Must not be NULL.
 * @param[out] buff		Expansion buffer, may be NULL except for the following types:
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT
 *				- #TMPL_TYPE_XLAT_STRUCT
 * @param[in] bufflen		Length of expansion buffer. Must be >= 2.
 * @param[in] request		Current request.
 * @param[in] vpt		to expand. Must be one of the following types:
 *				- #TMPL_TYPE_UNPARSED
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT
 *				- #TMPL_TYPE_XLAT_STRUCT
 *				- #TMPL_TYPE_ATTR
 *				- #TMPL_TYPE_DATA
 * @param[in] escape		xlat escape function (only used for xlat types).
 * @param[in] escape_ctx	xlat escape function data.
 * @param dst_type		FR_TYPE_* matching out pointer.  @see tmpl_expand.
 * @return
 *	- -1 on failure.
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_type(void *out,
		      uint8_t *buff, size_t bufflen,
		      REQUEST *request,
		      vp_tmpl_t const *vpt,
		      xlat_escape_t escape, void const *escape_ctx,
		      fr_type_t dst_type)
{
	fr_value_box_t		value_to_cast;
	fr_value_box_t		value_from_cast;
	fr_value_box_t const	*to_cast = &value_to_cast;
	fr_value_box_t const	*from_cast = &value_from_cast;

	VALUE_PAIR		*vp = NULL;

	fr_type_t		src_type = FR_TYPE_STRING;

	ssize_t			slen = -1;	/* quiet compiler */

	TMPL_VERIFY(vpt);

	rad_assert(vpt->type != TMPL_TYPE_LIST);
	rad_assert(!buff || (bufflen >= 2));

	memset(&value_to_cast, 0, sizeof(value_to_cast));
	memset(&value_from_cast, 0, sizeof(value_from_cast));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		RDEBUG4("EXPAND TMPL UNPARSED");
		value_to_cast.vb_strvalue = vpt->name;
		value_to_cast.datum.length = vpt->len;
		break;

	case TMPL_TYPE_EXEC:
	{
		RDEBUG4("EXPAND TMPL EXEC");
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for EXEC");
			return -1;
		}

		if (radius_exec_program(request, (char *)buff, bufflen, NULL, request, vpt->name, NULL,
					true, false, EXEC_TIMEOUT) != 0) return -1;
		value_to_cast.vb_strvalue = (char *)buff;
		value_to_cast.datum.length = strlen((char *)buff);
	}
		break;

	case TMPL_TYPE_XLAT:
		RDEBUG4("EXPAND TMPL XLAT");
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for XLAT");
			return -1;
		}
		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_eval((char *)buff, bufflen, request, vpt->name, escape, escape_ctx);
		if (slen < 0) return slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		value_to_cast.datum.length = value_str_unescape(buff, (char *)buff, slen, '"');
		value_to_cast.vb_strvalue = (char *)buff;
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for XLAT_STRUCT");
			return -1;
		}
		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_eval_compiled((char *)buff, bufflen, request, vpt->tmpl_xlat, escape, escape_ctx);
		if (slen < 0) return slen;

		RDEBUG2("   --> %s", (char *)buff);	/* Print pre-unescaping (so it's escaped) */

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		value_to_cast.datum.length = value_str_unescape(buff, (char *)buff, slen, '"');
		value_to_cast.vb_strvalue = (char *)buff;

		break;

	case TMPL_TYPE_ATTR:
	{
		int ret;

		RDEBUG4("EXPAND TMPL ATTR");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		to_cast = &vp->data;
		src_type = vp->da->type;
	}
		break;

	case TMPL_TYPE_DATA:
	{
		int ret;

		RDEBUG4("EXPAND TMPL DATA");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		to_cast = &vpt->tmpl_value;
		src_type = vpt->tmpl_value_type;
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0);
		return -1;
	}

	/*
	 *	Deal with casts.
	 */
	switch (src_type) {
	case FR_TYPE_STRING:
		switch (dst_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	case FR_TYPE_OCTETS:
		switch (dst_type) {
		/*
		 *	Need to use the expansion buffer for this conversion as
		 *	we need to add a \0 terminator.
		 */
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer for octet->string cast");
				return -1;
			}
			if (bufflen <= to_cast->datum.length) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   to_cast->datum.length + 1);
				return -1;
			}
			memcpy(buff, to_cast->vb_octets, to_cast->datum.length);
			buff[to_cast->datum.length] = '\0';
			value_from_cast.vb_strvalue = (char *)buff;
			value_from_cast.datum.length = to_cast->datum.length;
			break;

		/*
		 *	Just copy the pointer.  Length does not include \0.
		 */
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	default:
	{
		int		ret;
		TALLOC_CTX	*ctx;

		/*
		 *	Same type, just set from_cast to to_cast and copy the value.
		 */
		if (src_type == dst_type) {
			from_cast = to_cast;
			break;
		}

		MEM(ctx = talloc_new(request));

		from_cast = &value_from_cast;

		/*
		 *	Data type conversion...
		 */
		ret = fr_value_box_cast(ctx, &value_from_cast, dst_type, NULL, to_cast);
		if (ret < 0) return -1;


		/*
		 *	For the dynamic types we need to copy the output
		 *	to the buffer.  Really we need a version of fr_value_box_cast
		 *	that works with buffers, but it's not a high priority...
		 */
		switch (dst_type) {
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer to store cast output");
			error:
				talloc_free(ctx);
				return -1;
			}
			if (from_cast->datum.length >= bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   from_cast->datum.length + 1);
				goto error;
			}
			memcpy(buff, from_cast->vb_strvalue, from_cast->datum.length);
			buff[from_cast->datum.length] = '\0';
			value_from_cast.vb_strvalue = (char *)buff;
			break;

		case FR_TYPE_OCTETS:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer to store cast output");
				goto error;
			}
			if (from_cast->datum.length > bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen, from_cast->datum.length);
				goto error;
			}
			memcpy(buff, from_cast->vb_octets, from_cast->datum.length);
			value_from_cast.vb_octets = buff;
			break;

		default:
			break;
		}

		talloc_free(ctx);	/* Free any dynamically allocated memory from the cast */
	}
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	memcpy(out, ((uint8_t const *) from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

	return from_cast->datum.length;
}

/** Expand a template to a string, allocing a new buffer to hold the string
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #vp_tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * This function will always duplicate values, whereas #tmpl_expand may return a pointer to an
 * existing buffer.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint should
 *	be used before using these values in debug statements. #is_printable can be used to check
 *	if the string only contains printable chars.
 *
 * @note The type (char or uint8_t) can be obtained with talloc_get_type, and may be used as a
 *	hint as to how to process or print the data.
 *
 * @param ctx		to allocate new buffer in.
 * @param out		Where to write pointer to the new buffer.
 * @param request	Current request.
 * @param vpt		to expand. Must be one of the following types:
 *			- #TMPL_TYPE_UNPARSED
 *			- #TMPL_TYPE_EXEC
 *			- #TMPL_TYPE_XLAT
 *			- #TMPL_TYPE_XLAT_STRUCT
 *			- #TMPL_TYPE_ATTR
 *			- #TMPL_TYPE_DATA
 * @param escape xlat	escape function (only used for TMPL_TYPE_XLAT_* types).
 * @param escape_ctx	xlat escape function data (only used for TMPL_TYPE_XLAT_* types).
 * @param dst_type	FR_TYPE_* matching out pointer.  @see tmpl_aexpand.
 * @return
 *	- -1 on failure.
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       REQUEST *request,
		       vp_tmpl_t const *vpt,
		       xlat_escape_t escape, void const *escape_ctx,
		       fr_type_t dst_type)
{
	fr_value_box_t const	*to_cast = NULL;
	fr_value_box_t		from_cast;

	VALUE_PAIR		*vp = NULL;
	fr_value_box_t		value;
	bool			needs_dup = false;

	ssize_t			slen = -1;
	int			ret;

	TALLOC_CTX		*tmp_ctx = talloc_new(ctx);

	TMPL_VERIFY(vpt);

	memset(&value, 0, sizeof(value));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		RDEBUG4("EXPAND TMPL UNPARSED");

		value.datum.length = vpt->len;
		value.vb_strvalue = vpt->name;
		value.type = FR_TYPE_STRING;
		to_cast = &value;
		needs_dup = true;
		break;

	case TMPL_TYPE_EXEC:
		RDEBUG4("EXPAND TMPL EXEC");

		MEM(value.vb_strvalue = talloc_array(tmp_ctx, char, 1024));
		if (radius_exec_program(request, (char *)value.datum.ptr, 1024, NULL, request, vpt->name, NULL,
					true, false, EXEC_TIMEOUT) != 0) {
		error:
			talloc_free(tmp_ctx);
			return slen;
		}
		value.datum.length = strlen(value.vb_strvalue);
		value.type = FR_TYPE_STRING;
		MEM(value.vb_strvalue = talloc_realloc(tmp_ctx, value.datum.ptr, char, value.datum.length + 1));	/* Trim */
		rad_assert(value.vb_strvalue[value.datum.length] == '\0');
		to_cast = &value;
		break;

	case TMPL_TYPE_XLAT:
	{
		fr_value_box_t	tmp;
		fr_type_t		src_type = FR_TYPE_STRING;

		RDEBUG4("EXPAND TMPL XLAT");

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval(tmp_ctx, (char **)&value.datum.ptr, request, vpt->name, escape, escape_ctx);
		if (slen < 0) goto error;
		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
		if (ret < 0) goto error;

		value.vb_strvalue = tmp.vb_strvalue;
		value.datum.length = tmp.datum.length;
		value.type = FR_TYPE_STRING;
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
	{
		fr_value_box_t	tmp;
		fr_type_t		src_type = FR_TYPE_STRING;

		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval_compiled(tmp_ctx, (char **)&value.datum.ptr, request, vpt->tmpl_xlat, escape, escape_ctx);
		if (slen < 0) return slen;

		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
		if (ret < 0) goto error;

		value.vb_strvalue = tmp.vb_strvalue;
		value.datum.length = tmp.datum.length;
		value.type = FR_TYPE_STRING;
		to_cast = &value;

		RDEBUG2("   --> %s", value.vb_strvalue);	/* Print post-unescaping */
	}
		break;

	case TMPL_TYPE_ATTR:
		RDEBUG4("EXPAND TMPL ATTR");

		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		rad_assert(vp);

		to_cast = &vp->data;
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			rad_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
		break;

	case TMPL_TYPE_DATA:
	{
		RDEBUG4("EXPAND TMPL DATA");

		to_cast = &vpt->tmpl_value;
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			rad_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0);
		goto error;
	}

	/*
	 *	Special case where we just copy the boxed value
	 *	directly instead of casting it.
	 */
	if (dst_type == FR_TYPE_VALUE_BOX) {
		fr_value_box_t	**vb_out = (fr_value_box_t **)out;

		MEM(*vb_out = fr_value_box_alloc_null(ctx));

		ret = needs_dup ? fr_value_box_copy(ctx, *vb_out, to_cast) : fr_value_box_steal(ctx, *vb_out, to_cast);
		if (ret < 0) {
			RPEDEBUG("Failed copying data to output box");
			return -1;
		}
		talloc_free(tmp_ctx);
		return 0;
	}

	/*
	 *	Don't dup the buffers unless we need to.
	 */
	if ((to_cast->type != dst_type) || needs_dup) {
		ret = fr_value_box_cast(ctx, &from_cast, dst_type, NULL, to_cast);
		if (ret < 0) goto error;
	} else {
		switch (to_cast->type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			/*
			 *	Ensure we don't free the output buffer when the
			 *	tmp_ctx is freed.
			 */
			if (value.datum.ptr && (talloc_parent(value.datum.ptr) == tmp_ctx)) {
				value.datum.ptr = talloc_reparent(tmp_ctx, ctx, value.datum.ptr);
			}
			break;

		default:
			break;
		}
		memcpy(&from_cast, to_cast, sizeof(from_cast));
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	memcpy(out, ((uint8_t *)&from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

	/*
	 *	Frees any memory allocated for temporary buffers
	 *	in this function.
	 */
	talloc_free(tmp_ctx);

	return from_cast.datum.length;
}

/** Print a #vp_tmpl_t to a string
 *
 * @param[out] out Where to write the presentation format #vp_tmpl_t string.
 * @param[in] outlen Size of output buffer.
 * @param[in] vpt to print.
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t tmpl_snprint(char *out, size_t outlen, vp_tmpl_t const *vpt)
{
	size_t		len;
	char const	*p;
	char		c;
	char		*out_p = out, *end = out_p + outlen;

	if (!vpt || (outlen < 3)) {
	empty:
		*out = '\0';
		return 0;
	}
	TMPL_VERIFY(vpt);

	out[outlen - 1] = '\0';	/* Always terminate for safety */

	switch (vpt->type) {
	case TMPL_TYPE_LIST:
		*out_p++ = '&';

		/*
		 *	Don't add &current.
		 */
		if (vpt->tmpl_request == REQUEST_CURRENT) {
			len = snprintf(out_p, end - out_p, "%s:", fr_int2str(pair_lists, vpt->tmpl_list, ""));
			RETURN_IF_TRUNCATED(out_p, len, end - out_p);
			goto inst_and_tag;
		}

		len = snprintf(out_p, end - out_p, "%s.%s:", fr_int2str(request_refs, vpt->tmpl_request, ""),
			       fr_int2str(pair_lists, vpt->tmpl_list, ""));
		RETURN_IF_TRUNCATED(out_p, len, end - out_p);
		goto inst_and_tag;

	case TMPL_TYPE_ATTR_UNDEFINED:
		*out_p++ = '&';
		p = vpt->tmpl_unknown_name;
		goto print_name;

	case TMPL_TYPE_ATTR:
		*out_p++ = '&';
		p = vpt->tmpl_da->name;

	print_name:
		/*
		 *	Don't add &current.
		 */
		if (vpt->tmpl_request == REQUEST_CURRENT) {
			if (vpt->tmpl_list == PAIR_LIST_REQUEST) {
				len = strlcpy(out_p, p, end - out_p);
				RETURN_IF_TRUNCATED(out_p, len, end - out_p);
				goto inst_and_tag;
			}

			/*
			 *	Don't add &request:
			 */
			len = snprintf(out_p, end - out_p, "%s:%s",
				       fr_int2str(pair_lists, vpt->tmpl_list, ""), p);
			RETURN_IF_TRUNCATED(out_p, len, end - out_p);
			goto inst_and_tag;
		}

		len = snprintf(out_p, end - out_p, "%s.%s:%s", fr_int2str(request_refs, vpt->tmpl_request, ""),
			       fr_int2str(pair_lists, vpt->tmpl_list, ""), p);
		RETURN_IF_TRUNCATED(out_p, len, end - out_p);

	inst_and_tag:
		if (TAG_VALID(vpt->tmpl_tag)) {
			len = snprintf(out_p, end - out_p, ":%d", vpt->tmpl_tag);
			RETURN_IF_TRUNCATED(out_p, len, end - out_p);
		}

		switch (vpt->tmpl_num) {
		case NUM_ANY:
			goto finish;

		case NUM_ALL:
			len = snprintf(out_p, end - out_p, "[*]");
			break;

		case NUM_COUNT:
			len = snprintf(out_p, end - out_p, "[#]");
			break;

		case NUM_LAST:
			len = snprintf(out_p, end - out_p, "[n]");
			break;

		default:
			len = snprintf(out_p, end - out_p, "[%i]", vpt->tmpl_num);
			break;
		}
		RETURN_IF_TRUNCATED(out_p, len, end - out_p);
		goto finish;

	/*
	 *	Regexes have their own set of escaping rules
	 */
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_STRUCT:
		if (outlen < 4) goto empty;	/* / + <c> + / + \0 */
		*out_p++ = '/';
		len = fr_snprint(out_p, (end - out_p) - 1, vpt->name, vpt->len, '\0');
		RETURN_IF_TRUNCATED(out_p, len, (end - out_p) - 1);
		*out_p++ = '/';
		goto finish;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		c = '"';
		goto do_literal;

	case TMPL_TYPE_EXEC:
		c = '`';
		goto do_literal;

	case TMPL_TYPE_UNPARSED:
		/*
		 *	Nasty nasty hack that needs to be fixed.
		 *
		 *	Determines what quoting to use around strings based on their content.
		 *	Should use vpt->quote, but that's not always set correctly
		 *	at the moment.
		 */
		for (p = vpt->name; *p != '\0'; p++) {
			if (*p == ' ') break;
			if (*p == '\'') break;
			if (!fr_dict_attr_allowed_chars[(uint8_t) *p]) break;
		}
		c = *p ? '"' : '\0';

do_literal:
		if (outlen < 4) goto empty;	/* / + <c> + / + \0 */
		if (c != '\0') *out_p++ = c;
		len = fr_snprint(out_p, (end - out_p) - ((c == '\0') ? 0 : 1), vpt->name, vpt->len, c);
		RETURN_IF_TRUNCATED(out_p, len, (end - out_p) - ((c == '\0') ? 0 : 1));
		if (c != '\0') *out_p++ = c;
		break;

	case TMPL_TYPE_DATA:
		return fr_value_box_snprint(out, outlen, &vpt->tmpl_value, fr_token_quote[vpt->quote]);

	default:
		goto empty;
	}

finish:
	*out_p = '\0';
	return (out_p - out);
}

#define TMPL_TAG_MATCH(_a, _t) ((_a->da == _t->tmpl_da) && ATTR_TAG_MATCH(_a, _t->tmpl_tag))

static void *_tmpl_cursor_next(void **prev, void *curr, void *ctx)
{
	VALUE_PAIR	*c, *p, *fc = NULL, *fp = NULL;
	vp_tmpl_t const	*vpt = ctx;
	int		num;

	if (!curr) return NULL;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
		switch (vpt->tmpl_num) {
		case NUM_ANY:				/* Bare attribute ref */
			if (*prev) {
			null_result:
				*prev = curr;
				return NULL;
			}
			/* FALL-THROUGH */

		case NUM_ALL:
		case NUM_COUNT:				/* Iterator is called multiple time to get the count */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
					*prev = p;
					return c;
				}
			}
			goto null_result;

		case NUM_LAST:				/* Get the last instance of a VALUE_PAIR */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
				    	fp = p;
					fc = c;
				}
			}
			*prev = fp;
			return fc;

		default:				/* Get the specified index*/
			if (*prev) goto null_result;
			for (c = curr, p = *prev, num = vpt->tmpl_num;
			     c && (num >= 0);
			     p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
					fp = p;
					fc = c;
					num--;
				}
			}
			if (num >= 0) goto null_result;	/* Not enough entries */
			*prev = fp;
			return fc;
		}

	case TMPL_TYPE_LIST:
		switch (vpt->tmpl_num) {
		case NUM_ANY:				/* Bare attribute ref */
			if (*prev) goto null_result;
			/* FALL-THROUGH */

		case NUM_COUNT:				/* Iterate over the list, one attribute at a time */
		case NUM_ALL:
			VP_VERIFY(curr);
			return curr;			/* (cursor already advanced by the caller) */

		case NUM_LAST:				/* Get the last attribute in the list */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
				VP_VERIFY(c);
				fp = p;
				fc = c;
			}
			*prev = fp;
			return fc;

		default:				/* Get the specified index*/
			if (*prev) goto null_result;	/* Subsequent call */
			for (c = curr, p = *prev, num = vpt->tmpl_num;
			     c && (num >= 0);
			     p = c, c = c->next) {
			     	VP_VERIFY(c);
			     	fp = p;
			     	fc = c;
			     	num--;
			}
			/* Not enough entries */
			if (num >= 0) goto null_result;
			*prev = fp;
			return fc;
		}

	default:
		rad_assert(0);
	}

	return NULL;
}

/** Initialise a #fr_cursor_t to the #VALUE_PAIR specified by a #vp_tmpl_t
 *
 * This makes iterating over the one or more #VALUE_PAIR specified by a #vp_tmpl_t
 * significantly easier.
 *
 * @param err May be NULL if no error code is required. Will be set to:
 *	- 0 on success.
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 * @param cursor to store iterator state.
 * @param request The current #REQUEST.
 * @param vpt specifying the #VALUE_PAIR type/tag or list to iterate over.
 * @return
 *	- First #VALUE_PAIR specified by the #vp_tmpl_t.
 *	- NULL if no matching #VALUE_PAIR found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
VALUE_PAIR *tmpl_cursor_init(int *err, fr_cursor_t *cursor, REQUEST *request, vp_tmpl_t const *vpt)
{
	VALUE_PAIR	**vps, *vp = NULL;

	TMPL_VERIFY(vpt);

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	if (err) *err = 0;

	if (radius_request(&request, vpt->tmpl_request) < 0) {
		if (err) {
			*err = -3;
			fr_strerror_printf("Request context \"%s\" not available",
					   fr_int2str(request_refs, vpt->tmpl_request, "<INVALID>"));
		}
		return NULL;
	}
	vps = radius_list(request, vpt->tmpl_list);
	if (!vps) {
		if (err) {
			*err = -2;
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_int2str(pair_lists, vpt->tmpl_list, "<INVALID>"));
		}
		return NULL;
	}

	vp = fr_cursor_talloc_iter_init(cursor, vps, _tmpl_cursor_next, vpt, VALUE_PAIR);
	if (!vp) {
		if (err) {
			*err = -1;
			if (vpt->type == TMPL_TYPE_LIST) {
				fr_strerror_printf("List \"%s\" is empty", vpt->name);
			} else {
				fr_strerror_printf("No matching \"%s\" pairs found", vpt->tmpl_da->name);
			}
		}
		return NULL;
	}

	return vp;
}

/** Copy pairs matching a #vp_tmpl_t in the current #REQUEST
 *
 * @param ctx to allocate new #VALUE_PAIR in.
 * @param out Where to write the copied #VALUE_PAIR (s).
 * @param request The current #REQUEST.
 * @param vpt specifying the #VALUE_PAIR type/tag or list to copy.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 *	- -4 on memory allocation error.
 */
int tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	from, to;

	TMPL_VERIFY(vpt);

	int err;

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	*out = NULL;

	fr_cursor_init(&to, out);

	for (vp = tmpl_cursor_init(&err, &from, request, vpt);
	     vp;
	     vp = fr_cursor_next(&from)) {
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(out);
			fr_strerror_printf("Out of memory");
			return -4;
		}
		fr_cursor_append(&to, vp);
	}

	return err;
}

/** Returns the first VP matching a #vp_tmpl_t
 *
 * @param[out] out where to write the retrieved vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type/tag to find.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- 0 on success (found matching #VALUE_PAIR).
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;

	TMPL_VERIFY(vpt);

	int err;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	if (out) *out = vp;

	return err;
}

/** Returns the first VP matching a #vp_tmpl_t, or if no VPs match, creates a new one.
 *
 * @param[out] out where to write the retrieved or created vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type/tag to retrieve or create.  Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 1 on success a pair was created.
 *	- 0 on success a pair was found.
 *	- -1 if a new #VALUE_PAIR couldn't be found or created.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_or_add_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;
	int		err;

	TMPL_VERIFY(vpt);
	rad_assert(vpt->type == TMPL_TYPE_ATTR);

	*out = NULL;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	switch (err) {
	case 0:
		*out = vp;
		return 0;

	case -1:
	{
		TALLOC_CTX	*ctx;
		VALUE_PAIR	**head;

		RADIUS_LIST_AND_CTX(ctx, head, request, vpt->tmpl_request, vpt->tmpl_list);

		vp = fr_pair_afrom_da(ctx, vpt->tmpl_da);
		if (!vp) {
			REDEBUG("Failed allocating attribute %s", vpt->tmpl_da->name);
			return -1;
		}
		*out = vp;
	}
		return 0;

	default:
		return err;
	}
}
/* @} **/

#ifdef WITH_VERIFY_PTR
/** Used to check whether areas of a vp_tmpl_t are zeroed out
 *
 * @param ptr Offset to begin checking at.
 * @param len How many bytes to check.
 * @return
 *	- Pointer to the first non-zero byte.
 *	- NULL if all bytes were zero.
 */
static uint8_t const *not_zeroed(uint8_t const *ptr, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (ptr[i] != 0x00) return ptr + i;
	}

	return NULL;
}
#define CHECK_ZEROED(_x) not_zeroed((uint8_t const *)&_x + sizeof(_x), sizeof(vpt->data) - sizeof(_x))

/** Verify fields of a vp_tmpl_t make sense
 *
 * @note If the #vp_tmpl_t is invalid, causes the server to exit.
 *
 * @param file obtained with __FILE__.
 * @param line obtained with __LINE__.
 * @param vpt to check.
 */
void tmpl_verify(char const *file, int line, vp_tmpl_t const *vpt)
{
	rad_assert(vpt);

	if (vpt->type == TMPL_TYPE_UNKNOWN) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: vp_tmpl_t type was "
			     "TMPL_TYPE_UNKNOWN (uninitialised)", file, line);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	if (vpt->type > TMPL_TYPE_NULL) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: vp_tmpl_t type was %i "
			     "(outside range of tmpl_names)", file, line, vpt->type);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	if (!vpt->name && (vpt->quote != T_INVALID)) {
		char quote = vpt->quote > T_TOKEN_LAST ? '?' : fr_token_quote[vpt->quote];

		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: Quote type '%c' (%i) was set for NULL name",
			     file, line, quote, vpt->quote);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	if (vpt->name && (vpt->quote == T_INVALID)) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: No quoting type was set for name \"%.*s\"",
			     file, line, (int)vpt->len, vpt->name);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	/*
	 *  Do a memcmp of the bytes after where the space allocated for
	 *  the union member should have ended and the end of the union.
	 *  These should always be zero if the union has been initialised
	 *  properly.
	 *
	 *  If they're still all zero, do TMPL_TYPE specific checks.
	 */
	switch (vpt->type) {
	case TMPL_TYPE_NULL:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_NULL "
				     "has non-zero bytes in its data union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_UNPARSED:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_UNPARSED "
				     "has non-zero bytes in its data union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		break;

/* @todo When regexes get converted to xlat the flags field of the regex union is used
	case TMPL_TYPE_XLAT:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT "
				     "has non-zero bytes in its data union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		if (CHECK_ZEROED(vpt->data.xlat)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_STRUCT "
				     "has non-zero bytes after the data.xlat pointer in the union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;
*/

	case TMPL_TYPE_EXEC:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_EXEC "
				     "has non-zero bytes in its data union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_ATTR_UNDEFINED:
		rad_assert(vpt->tmpl_da == NULL);
		break;

	case TMPL_TYPE_ATTR:
		if (CHECK_ZEROED(vpt->data.attribute)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
				     "has non-zero bytes after the data.attribute struct in the union",
				     file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_da->flags.is_unknown) {
			if (vpt->tmpl_da != vpt->tmpl_unknown) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "da is marked as unknown, but address is not equal to the template's "
					     "unknown da pointer", file, line);
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}

		} else {
			fr_dict_attr_t const *da;

			if (!vpt->tmpl_da->flags.has_tag &&
			    (vpt->tmpl_tag != TAG_NONE) && (vpt->tmpl_tag != TAG_ANY)) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "da is marked as not having a tag, but the template has a tag",
					     file, line);
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}

#if 0
			if (vpt->tmpl_da->flags.has_tag &&
			    !TAG_VALID_ZERO(vpt->tmpl_tag)) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "da is marked as not having a tag, but the template has an invalid tag",
					     file, line);
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}
#endif

			/*
			 *	Attribute may be present with multiple names
			 */
			da = fr_dict_attr_by_name(fr_dict_by_da(vpt->tmpl_da), vpt->tmpl_da->name);
			if (!da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "attribute \"%s\" (%s) not found in global dictionary",
					     file, line, vpt->tmpl_da->name,
					     fr_int2str(fr_value_box_type_names, vpt->tmpl_da->type, "<INVALID>"));
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}

			if ((da->type == FR_TYPE_COMBO_IP_ADDR) && (da->type != vpt->tmpl_da->type)) {
				da = fr_dict_attr_by_type(vpt->tmpl_da, vpt->tmpl_da->type);
				if (!da) {
					FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "attribute \"%s\" variant (%s) not found in global dictionary",
						     file, line, vpt->tmpl_da->name,
						     fr_int2str(fr_value_box_type_names, vpt->tmpl_da->type, "<INVALID>"));
					if (!fr_cond_assert(0)) fr_exit_now(1);
				}
			}

			if (da != vpt->tmpl_da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "dictionary pointer %p \"%s\" (%s) "
					     "and global dictionary pointer %p \"%s\" (%s) differ",
					     file, line,
					     vpt->tmpl_da, vpt->tmpl_da->name,
					     fr_int2str(fr_value_box_type_names, vpt->tmpl_da->type, "<INVALID>"),
					     da, da->name,
					     fr_int2str(fr_value_box_type_names, da->type, "<INVALID>"));
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}
		}
		break;

	case TMPL_TYPE_LIST:
		if (CHECK_ZEROED(vpt->data.attribute)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST"
				     "has non-zero bytes after the data.attribute struct in the union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_da != NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST da pointer was not NULL. "
				     "da name was %s", file, line, vpt->tmpl_da->name);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_DATA:
		if (CHECK_ZEROED(vpt->data.literal)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA "
				     "has non-zero bytes after the data.literal struct in the union",
				     file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_value_type == FR_TYPE_INVALID) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
				     "FR_TYPE_INVALID (uninitialised)", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_value_type >= FR_TYPE_MAX) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
				     "%i (outside the range of fr_type_ts)", file, line, vpt->tmpl_value_type);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		/*
		 *	Unlike VALUE_PAIRs we can't guarantee that VALUE_PAIR_TMPL buffers will
		 *	be talloced. They may be allocated on the stack or in global variables.
		 */
		switch (vpt->tmpl_value_type) {
		case FR_TYPE_STRING:
			if (vpt->tmpl_value.vb_strvalue[vpt->tmpl_value_length] != '\0') {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA char buffer not \\0 "
					     "terminated", file, line);
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}
			break;

		case FR_TYPE_TLV:
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA is of type TLV",
				     file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);

		default:
			break;
		}

		break;

	case TMPL_TYPE_REGEX:
#ifdef HAVE_REGEX
		/*
		 *	iflag field is used for non compiled regexes too.
		 */
		if (CHECK_ZEROED(vpt->data.preg)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "has non-zero bytes after the data.preg struct in the union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_preg != NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "preg field was not NULL", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if ((vpt->tmpl_iflag != true) && (vpt->tmpl_iflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "iflag field was neither true or false", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if ((vpt->tmpl_mflag != true) && (vpt->tmpl_mflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "mflag field was neither true or false", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
#else
		if (!fr_cond_assert(0)) fr_exit_now(1);
#endif
		break;

	case TMPL_TYPE_REGEX_STRUCT:
#ifdef HAVE_REGEX
		if (CHECK_ZEROED(vpt->data.preg)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "has non-zero bytes after the data.preg struct in the union", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vpt->tmpl_preg == NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "comp field was NULL", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if ((vpt->tmpl_iflag != true) && (vpt->tmpl_iflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "iflag field was neither true or false", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if ((vpt->tmpl_mflag != true) && (vpt->tmpl_mflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "mflag field was neither true or false", file, line);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
#else
		if (!fr_cond_assert(0)) fr_exit_now(1);
#endif
		break;

	case TMPL_TYPE_UNKNOWN:
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}
}
#endif
