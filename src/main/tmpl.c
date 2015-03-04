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
 * @brief VALUE_PAIR template functions
 * @file main/tmpl.c
 *
 * @ingroup AVP
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

FR_NAME_NUMBER const tmpl_names[] = {
	{ "literal",		TMPL_TYPE_LITERAL 	},
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
#ifdef WITH_COA
	{ "coa",		PAIR_LIST_COA },
	{ "coa-reply",		PAIR_LIST_COA_REPLY },
	{ "disconnect",		PAIR_LIST_DM },
	{ "disconnect-reply",	PAIR_LIST_DM_REPLY },
#endif
	{  NULL , -1 }
};

const FR_NAME_NUMBER request_refs[] = {
	{ "outer",		REQUEST_OUTER },
	{ "current",		REQUEST_CURRENT },
	{ "parent",		REQUEST_PARENT },
	{  NULL , -1 }
};

/** Resolve attribute name to a list.
 *
 * Check the name string for qualifiers that specify a list and write
 * a pair_lists_t value for that list to out. This value may be passed to
 * radius_list, along with the current request, to get a pointer to the
 * actual list in the request.
 *
 * If we're sure we've definitely found a list qualifier token delimiter
 * but the string doesn't match a list qualifier, return 0 and write
 * PAIR_LIST_UNKNOWN to out.
 *
 * radius_list_name should be called before passing a name string that
 * may contain qualifiers to dict_attrbyname.
 *
 * @see dict_attrbyname
 *
 * @param[out] out Where to write the list qualifier.
 * @param[in] name String containing list qualifiers to parse.
 * @param[in] def the list to return if no qualifiers were found.
 * @return 0 if no valid list qualifier could be found, else the number of
 *	bytes consumed.
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
	for (q = p; dict_attr_allowed_chars[(uint8_t) *q]; q++);

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
			if (!dict_attr_allowed_chars[(uint8_t) *d]) {
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

/** Resolve attribute pair_lists_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of the list
 * in the REQUEST. If the head of the list changes, the pointer will still
 * be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list pair_list_t value to resolve to VALUE_PAIR list.
 *	Will be NULL if list name couldn't be resolved.
 */
VALUE_PAIR **radius_list(REQUEST *request, pair_lists_t list)
{
	if (!request) return NULL;

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		return &request->packet->vps;

	case PAIR_LIST_REPLY:
		return &request->reply->vps;

	case PAIR_LIST_CONTROL:
		return &request->config_items;

	case PAIR_LIST_STATE:
		return &request->state;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		if (!request->proxy) break;
		return &request->proxy->vps;

	case PAIR_LIST_PROXY_REPLY:
		if (!request->proxy_reply) break;
		return &request->proxy_reply->vps;
#endif
#ifdef WITH_COA
	case PAIR_LIST_COA:
		if (request->coa &&
		    (request->coa->proxy->code == PW_CODE_COA_REQUEST)) {
			return &request->coa->proxy->vps;
		}
		break;

	case PAIR_LIST_COA_REPLY:
		if (request->coa && /* match reply with request */
		    (request->coa->proxy->code == PW_CODE_COA_REQUEST) &&
		    request->coa->proxy_reply) {
			return &request->coa->proxy_reply->vps;
		}
		break;

	case PAIR_LIST_DM:
		if (request->coa &&
		    (request->coa->proxy->code == PW_CODE_DISCONNECT_REQUEST)) {
			return &request->coa->proxy->vps;
		}
		break;

	case PAIR_LIST_DM_REPLY:
		if (request->coa && /* match reply with request */
		    (request->coa->proxy->code == PW_CODE_DISCONNECT_REQUEST) &&
		    request->coa->proxy_reply) {
			return &request->coa->proxy->vps;
		}
		break;
#endif
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_int2str(pair_lists, list, "<INVALID>"));

	return NULL;
}

/** Resolve a list name to the packet that parents the vps
 *
 * Returns the packet for an attribute list.
 * @param[in] request containing the target lists.
 * @param[in] list_name pair_list_t value to resolve to RADIUS_PACKET.
 * @return a RADIUS_PACKET on success, else NULL
 */
RADIUS_PACKET *radius_packet(REQUEST *request, pair_lists_t list_name)
{
	switch (list_name) {
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
		return request->proxy;

	case PAIR_LIST_PROXY_REPLY:
		return request->proxy_reply;
#endif

#ifdef WITH_COA
	case PAIR_LIST_COA:
	case PAIR_LIST_DM:
		return request->coa->packet;

	case PAIR_LIST_COA_REPLY:
	case PAIR_LIST_DM_REPLY:
		return request->coa->reply;
#endif
	}

	return NULL;
}

/** Get the correct TALLOC ctx for a list
 *
 * Returns the talloc context associated with an attribute list.
 *
 * @param[in] request containing the target lists.
 * @param[in] list_name pair_list_t value to resolve to TALLOC_CTX.
 * @return a TALLOC_CTX on success, else NULL
 */
TALLOC_CTX *radius_list_ctx(REQUEST *request, pair_lists_t list_name)
{
	if (!request) return NULL;

	switch (list_name) {
	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;

	case PAIR_LIST_CONTROL:
		return request;

	case PAIR_LIST_STATE:
		return request;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		return request->proxy;

	case PAIR_LIST_PROXY_REPLY:
		return request->proxy_reply;
#endif

#ifdef WITH_COA
	case PAIR_LIST_COA:
		if (!request->coa) return NULL;
		rad_assert(request->coa->proxy != NULL);
		if (request->coa->proxy->code != PW_CODE_COA_REQUEST) return NULL;
		return request->coa->proxy;

	case PAIR_LIST_COA_REPLY:
		if (!request->coa) return NULL;
		rad_assert(request->coa->proxy != NULL);
		if (request->coa->proxy->code != PW_CODE_COA_REQUEST) return NULL;
		return request->coa->proxy_reply;

	case PAIR_LIST_DM:
		if (!request->coa) return NULL;
		rad_assert(request->coa->proxy != NULL);
		if (request->coa->proxy->code != PW_CODE_DISCONNECT_REQUEST) return NULL;
		return request->coa->proxy;

	case PAIR_LIST_DM_REPLY:
		if (!request->coa) return NULL;
		rad_assert(request->coa->proxy != NULL);
		if (request->coa->proxy->code != PW_CODE_DISCONNECT_REQUEST) return NULL;
		return request->coa->proxy_reply;
#endif
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;
	}

	return NULL;
}

/** Resolve attribute name to a request.
 *
 * Check the name string for qualifiers that reference a parent request.
 *
 * If we find a string that matches a request, then return the number of
 * chars we consumed.
 *
 * If we find a string that looks like a request qualifier but isn't,
 * return 0 and set out to REQUEST_UNKNOWN.
 *
 * If we can't find a string that looks like a request qualifier, set out
 * to def, and return 0.
 *
 * @see radius_list_name
 * @param[out] out request ref.
 * @param[in] name of attribute.
 * @param[in] def default request ref to return if no request qualifier is present.
 * @return 0 if no valid request qualifier could be found, else the number of
 *	bytes consumed.
 */
size_t radius_request_name(request_refs_t *out, char const *name, request_refs_t def)
{
	char const *p, *q;

	p = name;
	/*
	 *	Try and determine the end of the token
	 */
	for (q = p; dict_attr_allowed_chars[(uint8_t) *q] && (*q != '.') && (*q != '-'); q++);

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

/** Resolve request to a request.
 *
 * Resolve name to a current request.
 *
 * @see radius_list
 * @param[in,out] context Base context to use, and to write the result back to.
 * @param[in] name (request) to resolve to.
 * @return 0 if request is valid in this context, else -1.
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

	case REQUEST_UNKNOWN:
	default:
		rad_assert(0);
		return -1;
	}

	return 0;
}

#ifdef WITH_VERIFY_PTR
static uint8_t const *not_zeroed(uint8_t const *ptr, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (ptr[i] != 0x00) return ptr + i;
	}

	return NULL;
}
#define CHECK_ZEROED(_x) not_zeroed((uint8_t const *)&_x + sizeof(_x), sizeof(vpt->data) - sizeof(_x))


/** Verify fields of a value_pair_tmpl_t make sense
 *
 */
void tmpl_verify(char const *file, int line, value_pair_tmpl_t const *vpt)
{
	rad_assert(vpt);

	if (vpt->type == TMPL_TYPE_UNKNOWN) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: value_pair_tmpl_t type was "
			     "TMPL_TYPE_UNKNOWN (uninitialised)", file, line);
		fr_assert(0);
		fr_exit_now(1);
	}

	if (vpt->type > TMPL_TYPE_NULL) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: value_pair_tmpl_t type was %i "
			     "(outside range of tmpl_names)", file, line, vpt->type);
		fr_assert(0);
		fr_exit_now(1);
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
			fr_assert(0);
			fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_LITERAL:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LITERAL "
				     "has non-zero bytes in its data union", file, line);
			fr_assert(0);
			fr_exit_now(1);
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
			fr_assert(0);
			fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		if (CHECK_ZEROED(vpt->data.xlat)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_STRUCT "
				     "has non-zero bytes after the data.xlat pointer in the union", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}
		break;
*/

	case TMPL_TYPE_EXEC:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_EXEC "
				     "has non-zero bytes in its data union", file, line);
			fr_assert(0);
			fr_exit_now(1);
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
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_da->flags.is_unknown) {
			if (vpt->tmpl_da != (DICT_ATTR *)&vpt->data.attribute.unknown.da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "da is marked as unknown, but does not point to the template's "
					     "unknown da buffer", file, line);
				fr_assert(0);
				fr_exit_now(1);
			}

		} else {
			DICT_ATTR const *da;

			/*
			 *	Attribute may be present with multiple names
			 */
			da = dict_attrbyname(vpt->tmpl_da->name);
			if (!da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "attribute \"%s\" (%s) not found in global dictionary",
					     file, line, vpt->tmpl_da->name,
					     fr_int2str(dict_attr_types, vpt->tmpl_da->type, "<INVALID>"));
				fr_assert(0);
				fr_exit_now(1);
			}

			if ((da->type == PW_TYPE_COMBO_IP_ADDR) && (da->type != vpt->tmpl_da->type)) {
				da = dict_attrbytype(vpt->tmpl_da->attr, vpt->tmpl_da->vendor, vpt->tmpl_da->type);
				if (!da) {
					FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "attribute \"%s\" variant (%s) not found in global dictionary",
						     file, line, vpt->tmpl_da->name,
						     fr_int2str(dict_attr_types, vpt->tmpl_da->type, "<INVALID>"));
					fr_assert(0);
					fr_exit_now(1);
				}
			}

			if (da != vpt->tmpl_da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "dictionary pointer %p \"%s\" (%s) "
					     "and global dictionary pointer %p \"%s\" (%s) differ",
					     file, line,
					     vpt->tmpl_da, vpt->tmpl_da->name,
					     fr_int2str(dict_attr_types, vpt->tmpl_da->type, "<INVALID>"),
					     da, da->name,
					     fr_int2str(dict_attr_types, da->type, "<INVALID>"));
				fr_assert(0);
				fr_exit_now(1);
			}
		}
		break;

	case TMPL_TYPE_LIST:
		if (CHECK_ZEROED(vpt->data.attribute)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST"
				     "has non-zero bytes after the data.attribute struct in the union", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_da != NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST da pointer was NULL", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_DATA:
		if (CHECK_ZEROED(vpt->data.literal)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA "
				     "has non-zero bytes after the data.literal struct in the union",
				     file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_data_type == PW_TYPE_INVALID) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
				     "PW_TYPE_INVALID (uninitialised)", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_data_type >= PW_TYPE_MAX) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
				     "%i (outside the range of PW_TYPEs)", file, line, vpt->tmpl_data_type);
			fr_assert(0);
			fr_exit_now(1);
		}
		/*
		 *	Unlike VALUE_PAIRs we can't guarantee that VALUE_PAIR_TMPL buffers will
		 *	be talloced. They may be allocated on the stack or in global variables.
		 */
		switch (vpt->tmpl_data_type) {
		case PW_TYPE_STRING:
		if (vpt->tmpl_data.vp_strvalue[vpt->tmpl_data_length] != '\0') {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA char buffer not \\0 "
				     "terminated", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}
			break;

		case PW_TYPE_TLV:
		case PW_TYPE_OCTETS:
			break;

		default:
			if (vpt->tmpl_data_length == 0) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA data pointer not NULL "
				             "but len field is zero", file, line);
				fr_assert(0);
				fr_exit_now(1);
			}
		}

		break;

	case TMPL_TYPE_REGEX:
		/*
		 *	iflag field is used for non compiled regexes too.
		 */
		if (CHECK_ZEROED(vpt->data.preg)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "has non-zero bytes after the data.preg struct in the union", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_preg != NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "preg field was not nULL", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if ((vpt->tmpl_iflag != true) && (vpt->tmpl_iflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "iflag field was neither true or false", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if ((vpt->tmpl_mflag != true) && (vpt->tmpl_mflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "mflag field was neither true or false", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		break;

	case TMPL_TYPE_REGEX_STRUCT:
		if (CHECK_ZEROED(vpt->data.preg)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "has non-zero bytes after the data.preg struct in the union", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vpt->tmpl_preg == NULL) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "comp field was NULL", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if ((vpt->tmpl_iflag != true) && (vpt->tmpl_iflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_STRUCT "
				     "iflag field was neither true or false", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}

		if ((vpt->tmpl_mflag != true) && (vpt->tmpl_mflag != false)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
				     "mflag field was neither true or false", file, line);
			fr_assert(0);
			fr_exit_now(1);
		}
		break;

	case TMPL_TYPE_UNKNOWN:
		rad_assert(0);
	}
}
#endif

/** Initialise stack allocated value_pair_tmpl_t
 *
 */
value_pair_tmpl_t *tmpl_init(value_pair_tmpl_t *vpt, tmpl_type_t type, char const *name, ssize_t len)
{
	rad_assert(vpt);
	rad_assert(type != TMPL_TYPE_UNKNOWN);
	rad_assert(type <= TMPL_TYPE_NULL);

	memset(vpt, 0, sizeof(value_pair_tmpl_t));
	vpt->type = type;

	if (name) {
		vpt->name = name;
		vpt->len = len < 0 ? strlen(name) :
				     (size_t) len;
	}
	return vpt;
}

/** Allocate and initialise heap allocated value_pair_tmpl_t
 *
 */
value_pair_tmpl_t *tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name, ssize_t len)
{
	char *p;
	value_pair_tmpl_t *vpt;

	rad_assert(type != TMPL_TYPE_UNKNOWN);
	rad_assert(type <= TMPL_TYPE_NULL);

	vpt = talloc_zero(ctx, value_pair_tmpl_t);
	if (!vpt) return NULL;
	vpt->type = type;
	if (name) {
		vpt->name = p = len < 0 ? talloc_strdup(vpt, name) :
				          talloc_memdup(vpt, name, len + 1);
		talloc_set_type(vpt->name, char);
		vpt->len = talloc_array_length(vpt->name) - 1;
		p[vpt->len] = '\0';
	}

	return vpt;
}

/** Parse qualifiers to convert attrname into a value_pair_tmpl_t.
 *
 * VPTs are used in various places where we need to pre-parse configuration
 * sections into attribute mappings.
 *
 * @note The name field is just a copy of the input pointer, if you know that
 * string might be freed before you're done with the vpt use tmpl_afrom_attr_str
 * instead.
 *
 * @param[out] vpt to modify.
 * @param[in] name of attribute including qualifiers.
 * @param[in] request_def The default request to insert unqualified attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @param[in] allow_unknown If true attributes in the format accepted by dict_unknown_from_substr
 *	will be allowed, even if they're not in the main dictionaries.
 * @param[in] allow_undefined If true, we don't generate a parse error on unknown
 *	attributes, and instead set type to TMPL_TYPE_ATTR_UNDEFINED.
 * @return <= 0 on error (offset as negative integer), > 0 on success (number of bytes parsed)
 */
ssize_t tmpl_from_attr_substr(value_pair_tmpl_t *vpt, char const *name,
			      request_refs_t request_def, pair_lists_t list_def,
			      bool allow_unknown, bool allow_undefined)
{
	char const *p;
	long num;
	char *q;
	tmpl_type_t type = TMPL_TYPE_ATTR;

	value_pair_tmpl_attr_t attr;	/* So we don't fill the tmpl with junk and then error out */

	memset(vpt, 0, sizeof(*vpt));
	memset(&attr, 0, sizeof(attr));

	p = name;

	if (*p == '&') p++;

	p += radius_request_name(&attr.request, p, request_def);
	if (attr.request == REQUEST_UNKNOWN) {
		fr_strerror_printf("Invalid request qualifier");
		return -(p - name);
	}

	/*
	 *	Finding a list qualifier is optional
	 */
	p += radius_list_name(&attr.list, p, list_def);
	if (attr.list == PAIR_LIST_UNKNOWN) {
		fr_strerror_printf("Invalid list qualifier");
		return -(p - name);
	}

	if (*p == '\0') {
		type = TMPL_TYPE_LIST;
		goto finish;
	}

	attr.tag = TAG_ANY;
	attr.num = NUM_ANY;

	attr.da = dict_attrbyname_substr(&p);
	if (!attr.da) {
		char const *a;

		/*
		 *	Record start of attribute in case we need to error out.
		 */
		a = p;

		fr_strerror();	/* Clear out any existing errors */

		/*
		 *	Attr-1.2.3.4 is OK.
		 */
		if (dict_unknown_from_substr((DICT_ATTR *)&attr.unknown.da, &p) == 0) {
			/*
			 *	Check what we just parsed really hasn't been defined
			 *	in the main dictionaries.
			 */
			attr.da = dict_attrbyvalue(((DICT_ATTR *)&attr.unknown.da)->attr,
						   ((DICT_ATTR *)&attr.unknown.da)->vendor);
			if (attr.da) goto do_tag;

			if (!allow_unknown) {
				fr_strerror_printf("Unknown attribute");
				return -(a - name);
			}

			attr.da = (DICT_ATTR *)&attr.unknown.da;
			goto skip_tag; /* unknown attributes can't have tags */
		}

		/*
		 *	Can't parse it as an attribute, might be a literal string
		 *	let the caller decide.
		 *
		 *	Don't alter the fr_strerror buffer, should contain the parse
		 *	error from dict_unknown_from_substr.
		 */
		if (!allow_undefined) return -(a - name);

		/*
		 *	Copy the name to a field for later resolution
		 */
		type = TMPL_TYPE_ATTR_UNDEFINED;
		for (q = attr.unknown.name; dict_attr_allowed_chars[(int) *p]; *q++ = *p++) {
			if (q >= (attr.unknown.name + sizeof(attr.unknown.name) - 1)) {
				fr_strerror_printf("Attribute name is too long");
				return -(p - name);
			}
		}
		*q = '\0';

		goto skip_tag;
	}

do_tag:
	type = TMPL_TYPE_ATTR;

	/*
	 *	The string MIGHT have a tag.
	 */
	if (*p == ':') {
		if (!attr.da->flags.has_tag) {
			fr_strerror_printf("Attribute '%s' cannot have a tag", attr.da->name);
			return -(p - name);
		}

		num = strtol(p + 1, &q, 10);
		if ((num > 0x1f) || (num < 0)) {
			fr_strerror_printf("Invalid tag value '%li' (should be between 0-31)", num);
			return -((p + 1)- name);
		}

		attr.tag = num;
		p = q;
	}

skip_tag:
	if (*p == '\0') goto finish;

	if (*p == '[') {
		p++;

		switch (*p) {
		case '#':
			attr.num = NUM_COUNT;
			p++;
			break;

		case '*':
			attr.num = NUM_ALL;
			p++;
			break;

		case 'n':
			attr.num = NUM_LAST;
			p++;
			break;

		default:
			num = strtol(p, &q, 10);
			if (p == q) {
				fr_strerror_printf("Array index is not an integer");
				return -(p - name);
			}

			if ((num > 1000) || (num < 0)) {
				fr_strerror_printf("Invalid array reference '%li' (should be between 0-1000)", num);
				return -(p - name);
			}
			attr.num = num;
			p = q;
			break;
		}

		if (*p != ']') {
			fr_strerror_printf("No closing ']' for array index");
			return -(p - name);
		}
		p++;
	}

finish:
	vpt->type = type;
	vpt->name = name;
	vpt->len = p - name;

	/*
	 *	Copy over the attribute definition, now we're
	 *	sure what we were passed is valid.
	 */
	memcpy(&vpt->data.attribute, &attr, sizeof(vpt->data.attribute));
	if ((vpt->type == TMPL_TYPE_ATTR) && attr.da->flags.is_unknown) {
		vpt->tmpl_da = (DICT_ATTR *)&vpt->data.attribute.unknown.da;
	}

	VERIFY_TMPL(vpt);

	return vpt->len;
}

/** Parse qualifiers to convert an attrname into a value_pair_tmpl_t.
 *
 * VPTs are used in various places where we need to pre-parse configuration
 * sections into attribute mappings.
 *
 * @note The name field is just a copy of the input pointer, if you know that
 * string might be freed before you're done with the vpt use tmpl_afrom_attr_str
 * instead.
 *
 * @param[out] vpt to modify.
 * @param[in] name attribute name including qualifiers.
 * @param[in] request_def The default request to insert unqualified attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @param[in] allow_unknown If true attributes in the format accepted by dict_unknown_from_substr
 *	will be allowed, even if they're not in the main dictionaries.
 * @param[in] allow_undefined If true, we don't generate a parse error on unknown
 *	attributes, and instead set type to TMPL_TYPE_ATTR_UNDEFINED.
 * @return <= 0 on error (offset as negative integer), > 0 on success (number of bytes parsed)
 */
ssize_t tmpl_from_attr_str(value_pair_tmpl_t *vpt, char const *name,
			   request_refs_t request_def, pair_lists_t list_def,
			   bool allow_unknown, bool allow_undefined)
{
	ssize_t slen;

	slen = tmpl_from_attr_substr(vpt, name, request_def, list_def, allow_unknown, allow_undefined);
	if (slen <= 0) return slen;
	if (name[slen] != '\0') {
		fr_strerror_printf("Unexpected text after attribute name");
		return -slen;
	}

	VERIFY_TMPL(vpt);

	return slen;
}

/** Parse qualifiers to convert attrname into a value_pair_tmpl_t.
 *
 * VPTs are used in various places where we need to pre-parse configuration
 * sections into attribute mappings.
 *
 * @param[in] ctx for talloc
 * @param[out] out Where to write the pointer to the new value_pair_tmpl_t.
 * @param[in] name attribute name including qualifiers.
 * @param[in] request_def The default request to insert unqualified
 *	attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @param[in] allow_unknown If true attributes in the format accepted by dict_unknown_from_substr
 *	will be allowed, even if they're not in the main dictionaries.
 * @param[in] allow_undefined If true, we don't generate a parse error on unknown
 *	attributes, and instead set type to TMPL_TYPE_ATTR_UNDEFINED.
 * @return <= 0 on error (offset as negative integer), > 0 on success (number of bytes parsed)
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, value_pair_tmpl_t **out, char const *name,
			    request_refs_t request_def, pair_lists_t list_def,
			    bool allow_unknown, bool allow_undefined)
{
	ssize_t slen;
	value_pair_tmpl_t *vpt;

	MEM(vpt = talloc(ctx, value_pair_tmpl_t)); /* tmpl_from_attr_substr zeros it */

	slen = tmpl_from_attr_substr(vpt, name, request_def, list_def, allow_unknown, allow_undefined);
	if (slen <= 0) {
		tmpl_free(&vpt);
		return slen;
	}
	if (name[slen] != '\0') {
		fr_strerror_printf("Unexpected text after attribute name");
		tmpl_free(&vpt);
		return -slen;
	}
	vpt->name = talloc_strndup(vpt, vpt->name, vpt->len);

	VERIFY_TMPL(vpt);

	*out = vpt;

	return slen;
}

/**  Print a template to a string
 *
 * @param[out] buffer for the output string
 * @param[in] bufsize of the buffer
 * @param[in] vpt to print
 * @param[in] values Used for integer attributes only. DICT_ATTR to use when mapping integer values to strings.
 * @return the size of the string written to the output buffer.
 */
size_t tmpl_prints(char *buffer, size_t bufsize, value_pair_tmpl_t const *vpt, DICT_ATTR const *values)
{
	size_t len;
	char c;
	char const *p;
	char *q = buffer;

	if (!vpt) {
		*buffer = '\0';
		return 0;
	}

	VERIFY_TMPL(vpt);

	switch (vpt->type) {
	default:
		return 0;

	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_STRUCT:
		c = '/';
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		c = '"';
		break;

	case TMPL_TYPE_LIST:
	case TMPL_TYPE_LITERAL:	/* single-quoted or bare word */
		/*
		 *	Hack
		 */
		for (p = vpt->name; *p != '\0'; p++) {
			if (*p == ' ') break;
			if (*p == '\'') break;
			if (!dict_attr_allowed_chars[(int) *p]) break;
		}

		if (!*p) {
			strlcpy(buffer, vpt->name, bufsize);
			return strlen(buffer);
		}

		c = vpt->quote;
		break;

	case TMPL_TYPE_EXEC:
		c = '`';
		break;

	case TMPL_TYPE_ATTR:
		buffer[0] = '&';
		if (vpt->tmpl_request == REQUEST_CURRENT) {
			if (vpt->tmpl_list == PAIR_LIST_REQUEST) {
				strlcpy(buffer + 1, vpt->tmpl_da->name, bufsize - 1);
			} else {
				snprintf(buffer + 1, bufsize - 1, "%s:%s",
					 fr_int2str(pair_lists, vpt->tmpl_list, ""),
					 vpt->tmpl_da->name);
			}

		} else {
			snprintf(buffer + 1, bufsize - 1, "%s.%s:%s",
				 fr_int2str(request_refs, vpt->tmpl_request, ""),
				 fr_int2str(pair_lists, vpt->tmpl_list, ""),
				 vpt->tmpl_da->name);
		}

		len = strlen(buffer);

		if ((vpt->tmpl_tag == TAG_ANY) && (vpt->tmpl_num == NUM_ANY)) {
			return len;
		}

		q = buffer + len;
		bufsize -= len;

		if (vpt->tmpl_tag != TAG_ANY) {
			snprintf(q, bufsize, ":%d", vpt->tmpl_tag);
			len = strlen(q);
			q += len;
			bufsize -= len;
		}

		switch (vpt->tmpl_num) {
		case NUM_ANY:
			break;

		case NUM_ALL:
			snprintf(q, bufsize, "[*]");
			len = strlen(q);
			q += len;
			break;

		case NUM_COUNT:
			snprintf(q, bufsize, "[#]");
			len = strlen(q);
			q += len;
			break;

		case NUM_LAST:
			snprintf(q, bufsize, "[n]");
			len = strlen(q);
			q += len;
			break;

		default:
			snprintf(q, bufsize, "[%i]", vpt->tmpl_num);
			len = strlen(q);
			q += len;
			break;
		}

		return (q - buffer);

	case TMPL_TYPE_ATTR_UNDEFINED:
		buffer[0] = '&';
		if (vpt->tmpl_request == REQUEST_CURRENT) {
			if (vpt->tmpl_list == PAIR_LIST_REQUEST) {
				strlcpy(buffer + 1, vpt->tmpl_unknown_name, bufsize - 1);
			} else {
				snprintf(buffer + 1, bufsize - 1, "%s:%s",
					 fr_int2str(pair_lists, vpt->tmpl_list, ""),
					 vpt->tmpl_unknown_name);
			}

		} else {
			snprintf(buffer + 1, bufsize - 1, "%s.%s:%s",
				 fr_int2str(request_refs, vpt->tmpl_request, ""),
				 fr_int2str(pair_lists, vpt->tmpl_list, ""),
				 vpt->tmpl_unknown_name);
		}

		len = strlen(buffer);

		if (vpt->tmpl_num == NUM_ANY) {
			return len;
		}

		q = buffer + len;
		bufsize -= len;

		if (vpt->tmpl_num != NUM_ANY) {
			snprintf(q, bufsize, "[%i]", vpt->tmpl_num);
			len = strlen(q);
			q += len;
		}

		return (q - buffer);

	case TMPL_TYPE_DATA:
		return vp_data_prints_value(buffer, bufsize, vpt->tmpl_data_type, values,
					    &vpt->tmpl_data_value, vpt->tmpl_data_length, vpt->quote);
	}

	if (bufsize <= 3) {
		*buffer = '\0';
		return 0;
	}

	*(q++) = c;

	/*
	 *	Print it with appropriate escaping
	 */
	len = fr_prints(q, bufsize - 3, vpt->name, -1, c);

	q += len;
	*(q++) = c;
	*q = '\0';

	return q - buffer;
}

/** Convert an arbitrary string into a value_pair_tmpl_t.
 *
 * @note Unlike #tmpl_afrom_attr_str return code 0 doesn't indicate failure, just means a 0 length string
 *	 was parsed.
 *
 * @param[in] ctx for talloc.
 * @param[out] out Where to write the pointer to the new value_pair_tmpl_t.
 * @param[in] in String to convert to a template.
 * @param[in] inlen length of string to convert.
 * @param[in] type of quoting around value. May be one of:
 *	- #T_BARE_WORD
 *	- #T_SINGLE_QUOTED_STRING
 *	- #T_DOUBLE_QUOTED_STRING
 *	- #T_BACK_QUOTED_STRING
 *	- #T_OP_REG_EQ
 * @param[in] request_def The default request to insert unqualified attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @param[in] do_escape whether or not we should do escaping. Should be false if the caller already did it.
 * @return < 0 on error (offset as negative integer), >= 0 on success (number of bytes parsed)
 */
ssize_t tmpl_afrom_str(TALLOC_CTX *ctx, value_pair_tmpl_t **out, char const *in, size_t inlen, FR_TOKEN type,
		       request_refs_t request_def, pair_lists_t list_def, bool do_escape)
{
	bool do_xlat;
	char quote;
	char const *p;
	ssize_t slen;
	PW_TYPE data_type = PW_TYPE_STRING;
	value_pair_tmpl_t *vpt = NULL;
	value_data_t data;

	switch (type) {
	case T_BARE_WORD:
		/*
		 *	If we can parse it as an attribute, it's an attribute.
		 *	Otherwise, treat it as a literal.
		 */
		quote = '\0';

		slen = tmpl_afrom_attr_str(ctx, &vpt, in, request_def, list_def, true, (in[0] == '&'));
		if ((in[0] == '&') && (slen <= 0)) return slen;
		if (slen > 0) break;
		goto parse;

	case T_SINGLE_QUOTED_STRING:
		quote = '\'';

	parse:
		if (cf_new_escape && do_escape) {
			slen = value_data_from_str(ctx, &data, &data_type, NULL, in, inlen, quote);
			rad_assert(slen >= 0);

			vpt = tmpl_alloc(ctx, TMPL_TYPE_LITERAL, data.strvalue, talloc_array_length(data.strvalue) - 1);
			talloc_free(data.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_LITERAL, in, inlen);
		}
		vpt->quote = quote;
		slen = vpt->len;
		break;

	case T_DOUBLE_QUOTED_STRING:
		do_xlat = false;

		p = in;
		while (*p) {
			if (do_escape) { /* otherwise \ is just another character */
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
		if (cf_new_escape && do_escape) {
			slen = value_data_from_str(ctx, &data, &data_type, NULL, in, inlen, '"');
			if (slen < 0) return slen;

			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT, data.strvalue, talloc_array_length(data.strvalue) - 1);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_LITERAL, data.strvalue, talloc_array_length(data.strvalue) - 1);
				vpt->quote = '"';
			}
			talloc_free(data.ptr);
		} else {
			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT, in, inlen);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_LITERAL, in, inlen);
				vpt->quote = '"';
			}
		}
		slen = vpt->len;
		break;

	case T_BACK_QUOTED_STRING:
		if (cf_new_escape && do_escape) {
			slen = value_data_from_str(ctx, &data, &data_type, NULL, in, inlen, '`');
			if (slen < 0) return slen;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, data.strvalue, talloc_array_length(data.strvalue) - 1);
			talloc_free(data.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, in, inlen);
		}
		slen = vpt->len;
		break;

	case T_OP_REG_EQ: /* hack */
		if (cf_new_escape) {
			slen = value_data_from_str(ctx, &data, &data_type, NULL, in, inlen, '\0'); /* no unescaping */
			if (slen < 0) return slen;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_REGEX, data.strvalue, talloc_array_length(data.strvalue) - 1);
			talloc_free(data.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_REGEX, in, inlen);
		}
		slen = vpt->len;
		break;

	default:
		rad_assert(0);
		return 0;	/* 0 is an error here too */
	}

	rad_assert((slen >= 0) && (vpt != NULL));

	VERIFY_TMPL(vpt);

	*out = vpt;

	return slen;
}

/** Convert a tmpl containing literal data, to the type specified by da.
 *
 * @param[in,out] vpt the template to modify
 * @param[in] type to cast to.
 * @param[in] enumv Enumerated dictionary values.
 * @return true for success, false for failure.
 */
bool tmpl_cast_in_place(value_pair_tmpl_t *vpt, PW_TYPE type, DICT_ATTR const *enumv)
{
	ssize_t ret;

	VERIFY_TMPL(vpt);

	rad_assert(vpt != NULL);
	rad_assert(vpt->type == TMPL_TYPE_LITERAL);

	vpt->tmpl_data_type = type;

	/*
	 *	Why do we pass a pointer to the tmpl type? Goddamn WiMAX.
	 */
	ret = value_data_from_str(vpt, &vpt->tmpl_data_value, &vpt->tmpl_data_type, enumv, vpt->name, vpt->len, '\0');
	if (ret < 0) return false;

	vpt->type = TMPL_TYPE_DATA;
	vpt->tmpl_data_length = (size_t) ret;

	VERIFY_TMPL(vpt);

	return true;
}

/** Convert a tmpl of TMPL_TYPE_LITERAL to TMPL_TYPE_DATA
 *
 */
void tmpl_cast_in_place_str(value_pair_tmpl_t *vpt)
{
	rad_assert(vpt != NULL);
	rad_assert(vpt->type == TMPL_TYPE_LITERAL);

	vpt->tmpl_data.vp_strvalue = talloc_typed_strdup(vpt, vpt->name);
	rad_assert(vpt->tmpl_data.vp_strvalue != NULL);

	vpt->type = TMPL_TYPE_DATA;
	vpt->tmpl_data_type = PW_TYPE_STRING;
	vpt->tmpl_data_length = talloc_array_length(vpt->tmpl_data.vp_strvalue) - 1;
}

/** Expand a template to a string, parse it as type of "cast", and create a VP from the data.
 */
int tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
		    value_pair_tmpl_t const *vpt, DICT_ATTR const *cast)
{
	int rcode;
	VALUE_PAIR *vp;
	value_data_t data;
	char *p;

	VERIFY_TMPL(vpt);

	*out = NULL;

	vp = pairalloc(request, cast);
	if (!vp) return -1;

	if (vpt->type == TMPL_TYPE_DATA) {
		VERIFY_VP(vp);
		rad_assert(vp->da->type == vpt->tmpl_data_type);

		value_data_copy(vp, &vp->data, vpt->tmpl_data_type, &vpt->tmpl_data_value, vpt->tmpl_data_length);
		*out = vp;
		return 0;
	}

	rcode = tmpl_aexpand(vp, &p, request, vpt, NULL, NULL);
	if (rcode < 0) {
		pairfree(&vp);
		return rcode;
	}
	data.strvalue = p;

	/*
	 *	New escapes: strings are in binary form.
	 */
	if (cf_new_escape && (vp->da->type == PW_TYPE_STRING)) {
		vp->data.ptr = talloc_steal(vp, data.ptr);
		vp->vp_length = rcode;

	} else if (pairparsevalue(vp, data.strvalue, rcode) < 0) {
		talloc_free(data.ptr);
		pairfree(&vp);
		return -1;
	}

	*out = vp;
	return 0;
}

/** Expand a template to a string, writing the result
 *
 * @param out Where to write a pointer to the string buffer.
 *	On return may point to buff if buff was used to store the value.
 *	Otherwise will point to a value_data_t buffer, or the name of
 *	the template. To force copying the value to the buffer, out
 *	should be NULL.
 * @param buff Expansion buffer, may be NULL if out is not NULL, and
 *	processing TMPL_TYPE_LITERAL or string types.
 * @param bufflen Length of expansion buffer.
 * @param request Current request.
 * @param vpt to evaluate.
 * @param escape xlat escape function (only used for xlat types).
 * @param escape_ctx xlat escape function data.
 * @return -1 on error, else 0.
 */
ssize_t tmpl_expand(char const **out, char *buff, size_t bufflen, REQUEST *request,
		    value_pair_tmpl_t const *vpt, RADIUS_ESCAPE_STRING escape, void *escape_ctx)
{
	VALUE_PAIR *vp;
	ssize_t slen = -1;	/* quiet compiler */

	VERIFY_TMPL(vpt);

	rad_assert(vpt->type != TMPL_TYPE_LIST);

	if (out) *out = NULL;

	switch (vpt->type) {
	case TMPL_TYPE_LITERAL:
		RDEBUG4("EXPAND TMPL LITERAL");

		if (!out) {
			rad_assert(buff);
			memcpy(buff, vpt->name, vpt->len >= bufflen ? bufflen : vpt->len + 1);
		} else {
			*out = vpt->name;
		}
		return vpt->len;

	case TMPL_TYPE_EXEC:
	{
		RDEBUG4("EXPAND TMPL EXEC");
		rad_assert(buff);
		if (radius_exec_program(buff, bufflen, NULL, request, vpt->name, NULL,
					true, false, EXEC_TIMEOUT) != 0) {
			return -1;
		}
		slen = strlen(buff);
		if (out) *out = buff;
	}
		break;

	case TMPL_TYPE_XLAT:
		RDEBUG4("EXPAND TMPL XLAT");
		rad_assert(buff);
		/* Error in expansion, this is distinct from zero length expansion */
		slen = radius_xlat(buff, bufflen, request, vpt->name, escape, escape_ctx);
		if (slen < 0) return slen;
		if (out) *out = buff;
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		rad_assert(buff);
		/* Error in expansion, this is distinct from zero length expansion */
		slen = radius_xlat_struct(buff, bufflen, request, vpt->tmpl_xlat, escape, escape_ctx);
		if (slen < 0) {
			return slen;
		}
		slen = strlen(buff);
		if (out) *out = buff;
		break;

	case TMPL_TYPE_ATTR:
	{
		int ret;

		RDEBUG4("EXPAND TMPL ATTR");
		rad_assert(buff);
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		if (out && (vp->da->type == PW_TYPE_STRING)) {
			*out = vp->vp_strvalue;
			slen = vp->vp_length;
		} else {
			if (out) *out = buff;
			slen = vp_prints_value(buff, bufflen, vp, '\0');
		}
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0 == 1);
		slen = -1;
		break;
	}

	if (slen < 0) return slen;


#if 0
	/*
	 *	If we're doing correct escapes, we may have to re-parse the string.
	 *	If the string is from another expansion, it needs re-parsing.
	 *	Or, if it's from a "string" attribute, it needs re-parsing.
	 *	Integers, IP addresses, etc. don't need re-parsing.
	 */
	if (cf_new_escape &&
	    ((vpt->type != TMPL_TYPE_ATTR) ||
	     (vpt->tmpl_da->type == PW_TYPE_STRING))) {
	     	value_data_t vd;

		PW_TYPE type = PW_TYPE_STRING;

		slen = value_data_from_str(ctx, &vd, &type, NULL, *out, slen, '"');
		talloc_free(*out);	/* free the old value */
		*out = vd.ptr;
	}
#endif

	if (vpt->type == TMPL_TYPE_XLAT_STRUCT) {
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
		RDEBUG2("   --> %s", buff);
	}

	return slen;
}

/** Expand a template to a string, writing the result
 *
 * @param ctx to alloc output string in.
 * @param out Result of expanding the tmpl.
 * @param request Current request.
 * @param vpt to evaluate.
 * @param escape xlat escape function (only used for xlat types).
 * @param escape_ctx xlat escape function data.
 * @return -1 on error, else 0.
 */
ssize_t tmpl_aexpand(TALLOC_CTX *ctx, char **out, REQUEST *request, value_pair_tmpl_t const *vpt,
		     RADIUS_ESCAPE_STRING escape, void *escape_ctx)
{
	VALUE_PAIR *vp;
	ssize_t slen = -1;	/* quiet compiler */

	rad_assert(vpt->type != TMPL_TYPE_LIST);

	VERIFY_TMPL(vpt);

	*out = NULL;

	switch (vpt->type) {
	case TMPL_TYPE_LITERAL:
		RDEBUG4("EXPAND TMPL LITERAL");
		*out = talloc_memdup(ctx, vpt->name, vpt->len);
		return vpt->len;

	case TMPL_TYPE_EXEC:
	{
		char *buff = NULL;

		RDEBUG4("EXPAND TMPL EXEC");
		buff = talloc_array(ctx, char, 1024);
		if (radius_exec_program(buff, 1024, NULL, request, vpt->name, NULL, true, false, EXEC_TIMEOUT) != 0) {
			TALLOC_FREE(buff);
			return -1;
		}
		slen = strlen(buff);
		*out = buff;
	}
		break;

	case TMPL_TYPE_XLAT:
		RDEBUG4("EXPAND TMPL XLAT");
		/* Error in expansion, this is distinct from zero length expansion */
		slen = radius_axlat(out, request, vpt->name, escape, escape_ctx);
		if (slen < 0) {
			rad_assert(!*out);
			return slen;
		}
		rad_assert(*out);
		slen = strlen(*out);
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		/* Error in expansion, this is distinct from zero length expansion */
		slen = radius_axlat_struct(out, request, vpt->tmpl_xlat, escape, escape_ctx);
		if (slen < 0) {
			rad_assert(!*out);
			return slen;
		}
		slen = strlen(*out);
		break;

	case TMPL_TYPE_ATTR:
	{
		int ret;

		RDEBUG4("EXPAND TMPL ATTR");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		*out = vp_aprints_value(ctx, vp, '"');
		if (!*out) return -1;
		slen = talloc_array_length(*out) - 1;
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0 == 1);
		slen = -1;
		break;
	}

	if (slen < 0) return slen;

	/*
	 *	If we're doing correct escapes, we may have to re-parse the string.
	 *	If the string is from another expansion, it needs re-parsing.
	 *	Or, if it's from a "string" attribute, it needs re-parsing.
	 *	Integers, IP addresses, etc. don't need re-parsing.
	 */
	if (cf_new_escape &&
	    ((vpt->type != TMPL_TYPE_ATTR) ||
	     (vpt->tmpl_da->type == PW_TYPE_STRING))) {
	     	value_data_t vd;

		PW_TYPE type = PW_TYPE_STRING;

		slen = value_data_from_str(ctx, &vd, &type, NULL, *out, slen, '"');
		talloc_free(*out);	/* free the old value */
		*out = vd.ptr;
	}

	if (vpt->type == TMPL_TYPE_XLAT_STRUCT) {
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
		RDEBUG2("   --> %s", *out);
	}

	return slen;
}

/** Initialise a vp_cursor_t to the VALUE_PAIR specified by a value_pair_tmpl_t
 *
 * This makes iterating over the one or more VALUE_PAIRs specified by a value_pair_tmpl_t
 * significantly easier.
 *
 * @see tmpl_cursor_next
 *
 * @param err Will be set to -1 if VP could not be found, -2 if list could not be found,
 *	-3 if context could not be found and NULL will be returned. Will be 0 on success.
 * @param cursor to store iterator state.
 * @param request The current request.
 * @param vpt specifying the VALUE_PAIRs to iterate over.
 * @return the first VALUE_PAIR specified by the value_pair_tmpl_t, NULL if no matching VALUE_PAIRs exist,
 * 	and NULL on error.
 */
VALUE_PAIR *tmpl_cursor_init(int *err, vp_cursor_t *cursor, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR **vps, *vp = NULL;

	VERIFY_TMPL(vpt);

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	if (err) *err = 0;

	if (radius_request(&request, vpt->tmpl_request) < 0) {
		if (err) *err = -3;
		return NULL;
	}
	vps = radius_list(request, vpt->tmpl_list);
	if (!vps) {
		if (err) *err = -2;
		return NULL;
	}
	(void) fr_cursor_init(cursor, vps);

	switch (vpt->type) {
	/*
	 *	May not may not be found, but it *is* a known name.
	 */
	case TMPL_TYPE_ATTR:
	{
		int num;

		switch (vpt->tmpl_num) {
		case NUM_ANY:
			vp = fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag);
			if (!vp) {
				if (err) *err = -1;
				return NULL;
			}
			VERIFY_VP(vp);
			return vp;

		/*
		 *	Get the last instance of a VALUE_PAIR.
		 */
		case NUM_LAST:

		{
			VALUE_PAIR *last = NULL;

			while ((vp = fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag))) {
				VERIFY_VP(vp);
				last = vp;
			}

			if (!last) break;
			return last;
		}

		/*
		 *	Callers expect NUM_COUNT to setup the cursor to point
		 *	to the first attribute in the list we're meant to be
		 *	counting.
		 *
		 *	It does not produce a virtual attribute containing the
		 *	total number of attributes.
		 */
		case NUM_COUNT:
		default:
			num = vpt->tmpl_num;
			while ((vp = fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag))) {
				VERIFY_VP(vp);
				if (num-- <= 0) return vp;
			}
			break;
		}

		if (err) *err = -1;
		return NULL;
	}

	case TMPL_TYPE_LIST:
		vp = fr_cursor_init(cursor, vps);
		break;

	default:
		rad_assert(0);
	}

	return vp;
}

/** Gets the next VALUE_PAIR specified by value_pair_tmpl_t
 *
 * Returns the next VALUE_PAIR matching a value_pair_tmpl_t
 *
 * @param cursor initialised with tmpl_cursor_init.
 * @param vpt specifying the VALUE_PAIRs to iterate over.
 * @return NULL if no more matching VALUE_PAIRs found.
 */
VALUE_PAIR *tmpl_cursor_next(vp_cursor_t *cursor, value_pair_tmpl_t const *vpt)
{
	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	VERIFY_TMPL(vpt);

	switch (vpt->type) {
	/*
	 *	May not may not be found, but it *is* a known name.
	 */
	case TMPL_TYPE_ATTR:
		if (vpt->tmpl_num != NUM_ALL) return NULL;
		return fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag);

	case TMPL_TYPE_LIST:
		return fr_cursor_next(cursor);

	default:
		rad_assert(0);
		return NULL;	/* Older versions of GCC flag the lack of return as an error */
	}
}

/** Copy pairs matching a VPT in the current request
 *
 * @param ctx to allocate new VALUE_PAIRs under.
 * @param out Where to write the copied vps.
 * @param request current request.
 * @param vpt specifying the VALUE_PAIRs to iterate over.
 * @return -1 if VP could not be found, -2 if list could not be found, -3 if context could not be found,
 *	-4 on memory allocation error.
 */
int tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR *vp;
	vp_cursor_t from, to;

	VERIFY_TMPL(vpt);

	int err;

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	*out = NULL;

	fr_cursor_init(&to, out);

	for (vp = tmpl_cursor_init(&err, &from, request, vpt);
	     vp;
	     vp = tmpl_cursor_next(&from, vpt)) {
		vp = paircopyvp(ctx, vp);
		if (!vp) {
			pairfree(out);
			return -4;
		}
		fr_cursor_insert(&to, vp);
	}

	return err;
}

/** Gets the first VP from a value_pair_tmpl_t
 *
 * @param out where to write the retrieved vp.
 * @param request current request.
 * @param vpt specifying the VALUE_PAIRs to iterate over.
 * @return -1 if VP could not be found, -2 if list could not be found, -3 if context could not be found.
 */
int tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	VERIFY_TMPL(vpt);

	int err;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	if (out) *out = vp;

	return err;
}

bool tmpl_define_unknown_attr(value_pair_tmpl_t *vpt)
{
	DICT_ATTR const *da;

	if (!vpt) return false;

	VERIFY_TMPL(vpt);

	if ((vpt->type != TMPL_TYPE_ATTR) &&
	    (vpt->type != TMPL_TYPE_DATA)) {
		return true;
	}

	if (!vpt->tmpl_da->flags.is_unknown) return true;

	da = dict_unknown_add(vpt->tmpl_da);
	if (!da) return false;
	vpt->tmpl_da = da;
	return true;
}
