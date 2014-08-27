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

/*
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

const FR_NAME_NUMBER pair_lists[] = {
	{ "request",		PAIR_LIST_REQUEST },
	{ "reply",		PAIR_LIST_REPLY },
	{ "control",		PAIR_LIST_CONTROL },		/* New name should have priority */
	{ "config",		PAIR_LIST_CONTROL },
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
 * Check the name string for qualifiers that specify a list and return
 * an pair_lists_t value for that list. This value may be passed to
 * radius_list, along with the current request, to get a pointer to the
 * actual list in the request.
 *
 * If qualifiers were consumed, write a new pointer into name to the
 * char after the last qualifier to be consumed.
 *
 * radius_list_name should be called before passing a name string that
 * may contain qualifiers to dict_attrbyname.
 *
 * @see dict_attrbyname
 *
 * @param[in,out] name of attribute.
 * @param[in] default_list the list to return if no qualifiers were found.
 * @return PAIR_LIST_UNKOWN if qualifiers couldn't be resolved to a list.
 */
pair_lists_t radius_list_name(char const **name, pair_lists_t default_list)
{
	char const *p = *name;
	char const *q;
	pair_lists_t output;

	/* This should never be a NULL pointer or zero length string */
	rad_assert(name && *name);

	/*
	 *	Unfortunately, ':' isn't a definitive separator for
	 *	the list name.  We may have numeric tags, too.
	 */
	q = strchr(p, ':');
	if (q) {
		/*
		 *	Check for tagged attributes.  They have
		 *	"name:tag", where tag is a decimal number.
		 *	Valid tags are invalid attributes, so that's
		 *	OK.
		 *
		 *	Also allow "name:tag[#]" as a tag.
		 *
		 *	However, "request:" is allowed, too, and
		 *	shouldn't be interpreted as a tag.
		 *
		 *	We do this check first rather than just
		 *	looking up the request name, because this
		 *	check is cheap, and looking up the request
		 *	name is expensive.
		 */
		if (isdigit((int) q[1])) {
			char const *d = q + 1;

			while (isdigit((int) *d)) {
				d++;
			}

			/*
			 *	Return the DEFAULT list as supplied by
			 *	the caller.  This is usually
			 *	PAIRLIST_REQUEST.
			 */
			if (!*d || (*d == '[')) {
				return default_list;
			}
		}

		/*
		 *	If the first part is a list name, then treat
		 *	it as a list.  This means that we CANNOT have
		 *	an attribute which is named "request",
		 *	"reply", etc.  Allowing a tagged attribute
		 *	"request:3" would just be insane.
		 */
		output = fr_substr2int(pair_lists, p, PAIR_LIST_UNKNOWN, (q - p));
		if (output != PAIR_LIST_UNKNOWN) {
			*name = (q + 1);	/* Consume the list and delimiter */
			return output;
		}

		/*
		 *	It's not a known list, say so.
		 */
		return PAIR_LIST_UNKNOWN;
	}

	/*
	 *	The input string may be just a list name,
	 *	e.g. "request".  Check for that.
	 */
	q = (p + strlen(p));
	output = fr_substr2int(pair_lists, p, PAIR_LIST_UNKNOWN, (q - p));
	if (output != PAIR_LIST_UNKNOWN) {
		*name = q;
		return output;
	}

	/*
	 *	It's just an attribute name.  Return the default list
	 *	as supplied by the caller.
	 */
	return default_list;
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
	case PAIR_LIST_UNKNOWN:
	default:
		break;

	case PAIR_LIST_REQUEST:
		return &request->packet->vps;

	case PAIR_LIST_REPLY:
		return &request->reply->vps;

	case PAIR_LIST_CONTROL:
		return &request->config_items;

#ifdef WITH_PROXY
	case PAIR_LIST_PROXY_REQUEST:
		if (!request->proxy) break;
		return &request->proxy->vps;

	case PAIR_LIST_PROXY_REPLY:
		if (!request->proxy) break;
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

	default:
		break;
	}

	return NULL;
}

/** Resolve attribute name to a request.
 *
 * Check the name string for qualifiers that reference a parent request and
 * write the pointer to this request to 'request'.
 *
 * If qualifiers were consumed, write a new pointer into name to the
 * char after the last qualifier to be consumed.
 *
 * radius_ref_request should be called before radius_list_name.
 *
 * @see radius_list_name
 * @param[in,out] name of attribute.
 * @param[in] def default request ref to return if no request qualifier is present.
 * @return one of the REQUEST_* definitions or REQUEST_UNKOWN
 */
request_refs_t radius_request_name(char const **name, request_refs_t def)
{
	char *p;
	int request;

	p = strchr(*name, '.');
	if (!p) {
		return def;
	}

	/*
	 *	We may get passed "127.0.0.1".
	 */
	request = fr_substr2int(request_refs, *name, REQUEST_UNKNOWN, p - *name);

	/*
	 *	If we get a valid name, skip it.
	 */
	if (request != REQUEST_UNKNOWN) {
		*name = p + 1;
		return request;
	}

	/*
	 *	Otherwise leave it alone, and return the caller's
	 *	default.
	 */
	return def;
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

/** Parse qualifiers to convert attrname into a value_pair_tmpl_t.
 *
 * VPTs are used in various places where we need to pre-parse configuration
 * sections into attribute mappings.
 *
 * Note: name field is just a copy of the input pointer, if you know that
 * string might be freed before you're done with the vpt use tmpl_afrom_attr_str
 * instead.
 *
 * The special return code of -2 is used only by tmpl_afrom_str, which allow
 * bare words which might (or might not) be an attribute reference.
 *
 * @param[out] vpt to modify.
 * @param[in] name attribute name including qualifiers.
 * @param[in] request_def The default request to insert unqualified attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @return -2 on partial parse followed by error, -1 on other error, or 0 on success
 */
int tmpl_from_attr_str(value_pair_tmpl_t *vpt, char const *name, request_refs_t request_def, pair_lists_t list_def)
{
	int error = -1;
	char const *p;
	size_t len;
	unsigned long num;
	char *q;
	DICT_ATTR const *da;

	memset(vpt, 0, sizeof(*vpt));
	vpt->name = name;
	p = name;

	if (*p == '&') {
		error = -2;
		p++;
	}

	vpt->tmpl_request = radius_request_name(&p, request_def);
	len = p - name;
	if (vpt->tmpl_request == REQUEST_UNKNOWN) {
		fr_strerror_printf("Invalid request qualifier \"%.*s\"", (int) len, name);
		return error;
	}
	name += len;

	vpt->tmpl_list = radius_list_name(&p, list_def);
	if (vpt->tmpl_list == PAIR_LIST_UNKNOWN) {
		len = p - name;
		fr_strerror_printf("Invalid list qualifier \"%.*s\"", (int) len, name);
		return error;
	}

	if (*p == '\0') {
		vpt->type = TMPL_TYPE_LIST;
		return 0;
	}

	da = dict_attrbytagged_name(p);
	if (!da) {
		da = dict_attrunknownbyname(p, false);
		if (!da) {
			fr_strerror_printf("Unknown attribute \"%s\"", p);
			return error;
		}
	}
	vpt->tmpl_da = da;
	vpt->type = TMPL_TYPE_ATTR;
	vpt->tmpl_tag = TAG_ANY;
	vpt->tmpl_num = NUM_ANY;

	/*
	 *	After this point, we return -2 to indicate that parts
	 *	of the string were parsed as an attribute, but others
	 *	weren't.
	 */
	while (*p) {
		if (*p == ':') break;
		if (*p == '[') break;
		p++;
	}

	if (*p == ':') {
		if (!da->flags.has_tag) {
			fr_strerror_printf("Attribute '%s' cannot have a tag", da->name);
			return -2;
		}

		num = strtoul(p + 1, &q, 10);
		if (num > 0x1f) {
			fr_strerror_printf("Invalid tag value '%u' (should be between 0-31)", (unsigned int) num);
			return -2;
		}

		vpt->tmpl_tag = num;
		p = q;
	}

	if (!*p) return 0;

	if (*p != '[') {
		fr_strerror_printf("Unexpected text after tag in '%s'", name);
		return -2;
	}
	p++;

	if (*p != '*') {
		num = strtoul(p, &q, 10);
		if (num > 1000) {
			fr_strerror_printf("Invalid array reference '%u' (should be between 0-1000)", (unsigned int) num);
			return -2;
		}
		vpt->tmpl_num = num;
		p = q;
	} else {
		vpt->tmpl_num = NUM_ALL;
		p++;
	}

	if ((*p != ']') || (p[1] != '\0')) {
		fr_strerror_printf("Unexpected text after array in '%s'", name);
		return -2;
	}

	return 0;
}

/** Parse qualifiers to convert attrname into a value_pair_tmpl_t.
 *
 * VPTs are used in various places where we need to pre-parse configuration
 * sections into attribute mappings.
 *
 * @param[in] ctx for talloc
 * @param[in] name attribute name including qualifiers.
 * @param[in] request_def The default request to insert unqualified
 *	attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @return pointer to a value_pair_tmpl_t struct (must be freed with
 *	tmpl_free) or NULL on error.
 */
value_pair_tmpl_t *tmpl_afrom_attr_str(TALLOC_CTX *ctx, char const *name, request_refs_t request_def,
				       pair_lists_t list_def)
{
	value_pair_tmpl_t *vpt;
	char const *copy;

	vpt = talloc(ctx, value_pair_tmpl_t); /* parse_attr zeroes it */
	copy = talloc_typed_strdup(vpt, name);

	if (tmpl_from_attr_str(vpt, copy, request_def, list_def) < 0) {
		ERROR("%s", fr_strerror());
		tmpl_free(&vpt);
		return NULL;
	}

	return vpt;
}

/** Release memory allocated to value pair template.
 *
 * @param[in,out] tmpl to free.
 */
void tmpl_free(value_pair_tmpl_t **tmpl)
{
	if (*tmpl == NULL) return;

	dict_attr_free(&((*tmpl)->tmpl_da));

	talloc_free(*tmpl);

	*tmpl = NULL;
}

/**  Print a template to a string
 *
 * @param[out] buffer for the output string
 * @param[in] bufsize of the buffer
 * @param[in] vpt to print
 * @return the size of the string printed
 */
size_t tmpl_prints(char *buffer, size_t bufsize, value_pair_tmpl_t const *vpt)
{
	size_t len;
	char c;
	char const *p;
	char *q = buffer;
	char *end;

	if (!vpt) {
		*buffer = '\0';
		return 0;
	}

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

		c = '\'';
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

		if (vpt->tmpl_num != NUM_ANY) {
			snprintf(q, bufsize, "[%u]", vpt->tmpl_num);
			len = strlen(q);
			q += len;
		}

		return (q - buffer);

	case TMPL_TYPE_DATA:
		if (vpt->tmpl_value) {
			return vp_data_prints_value(buffer, bufsize, vpt->tmpl_da,
						    vpt->tmpl_value, vpt->tmpl_length, '"');
		} else {
			*buffer = '\0';
			return 0;
		}
	}

	if (bufsize <= 3) {
	no_room:
		*buffer = '\0';
		return 0;
	}

	p = vpt->name;
	*(q++) = c;
	end = buffer + bufsize - 3; /* quotes + EOS */

	while (*p && (q < end)) {
		if (*p == c) {
			if ((end - q) < 4) goto no_room; /* escape, char, quote, EOS */
			*(q++) = '\\';
			*(q++) = *(p++);
			continue;
		}

		switch (*p) {
		case '\\':
			if ((end - q) < 4) goto no_room;
			*(q++) = '\\';
			*(q++) = *(p++);
			break;

		case '\r':
			if ((end - q) < 4) goto no_room;
			*(q++) = '\\';
			*(q++) = 'r';
			p++;
			break;

		case '\n':
			if ((end - q) < 4) goto no_room;
			*(q++) = '\\';
			*(q++) = 'r';
			p++;
			break;

		case '\t':
			if ((end - q) < 4) goto no_room;
			*(q++) = '\\';
			*(q++) = 't';
			p++;
			break;

		default:
			*(q++) = *(p++);
			break;
		}
	}

	*(q++) = c;
	*q = '\0';

	return q - buffer;
}

/** Convert module specific attribute id to value_pair_tmpl_t.
 *
 * @param[in] ctx for talloc
 * @param[in] name string to convert.
 * @param[in] type Type of quoting around value.
 * @param[in] request_def The default request to insert unqualified
 *	attributes into.
 * @param[in] list_def The default list to insert unqualified attributes into.
 * @return pointer to new VPT.
 */
value_pair_tmpl_t *tmpl_afrom_str(TALLOC_CTX *ctx, char const *name, FR_TOKEN type,
				  request_refs_t request_def, pair_lists_t list_def)
{
	int rcode;
	char const *p;
	value_pair_tmpl_t *vpt;
	char buffer[1024];

	vpt = talloc_zero(ctx, value_pair_tmpl_t);
	vpt->name = talloc_typed_strdup(vpt, name);

	switch (type) {
	case T_BARE_WORD:
		/*
		 *	If we can parse it as an attribute, it's an attribute.
		 *	Otherwise, treat it as a literal.
		 */
		rcode = tmpl_from_attr_str(vpt, vpt->name, request_def, list_def);
		if (rcode == -2) {
			talloc_free(vpt);
			return NULL;
		}
		if (rcode == 0) {
			break;
		}
		/* FALL-THROUGH */

	case T_SINGLE_QUOTED_STRING:
		vpt->type = TMPL_TYPE_LITERAL;
		break;

	case T_DOUBLE_QUOTED_STRING:
		p = name;
		while (*p) {
			if (*p == '\\') {
				if (!p[1]) break;
				p += 2;
				continue;
			}

			if (*p == '%') break;

			p++;
		}

		/*
		 *	If the double quoted string needs to be
		 *	expanded at run time, make it an xlat
		 *	expansion.  Otherwise, convert it to be a
		 *	literal.
		 */
		if (*p) {
			vpt->type = TMPL_TYPE_XLAT;
		} else {
			vpt->type = TMPL_TYPE_LITERAL;
		}
		break;

	case T_BACK_QUOTED_STRING:
		vpt->type = TMPL_TYPE_EXEC;
		break;

	case T_OP_REG_EQ: /* hack */
		vpt->type = TMPL_TYPE_REGEX;
		break;

	default:
		rad_assert(0);
		return NULL;
	}

	tmpl_prints(buffer, sizeof(buffer), vpt);

	return vpt;
}

/** Convert a tmpl containing literal data, to the type specified by da.
 *
 * @param[in,out] vpt the template to modify
 * @param[in] da the dictionary attribute to case it to
 * @return true for success, false for failure.
 */
bool tmpl_cast_in_place(value_pair_tmpl_t *vpt, DICT_ATTR const *da)
{
	VALUE_PAIR *vp;
	value_data_t *data;

	rad_assert(vpt != NULL);
	rad_assert(da != NULL);
	rad_assert(vpt->type == TMPL_TYPE_LITERAL);

	vp = pairalloc(vpt, da);
	if (!vp) return false;

	if (pairparsevalue(vp, vpt->name, 0) < 0) {
		pairfree(&vp);
		return false;
	}

	vpt->tmpl_length = vp->length;
	vpt->tmpl_value = data = talloc(vpt, value_data_t);
	if (!vpt->tmpl_value) return false;

	vpt->type = TMPL_TYPE_DATA;
	vpt->tmpl_da = da;

	if (vp->da->flags.is_pointer) {
		data->ptr = talloc_steal(vpt, vp->data.ptr);
		vp->data.ptr = NULL;
	} else {
		memcpy(data, &vp->data, sizeof(*data));
	}

	pairfree(&vp);

	return true;
}

/** Expand a template to a string, parse it as type of "cast", and create a VP from the data.
 */
int tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
		    value_pair_tmpl_t const *vpt, DICT_ATTR const *cast)
{
	int rcode;
	VALUE_PAIR *vp;
	char *str;

	*out = NULL;

	vp = pairalloc(request, cast);
	if (!vp) return -1;

	if (vpt->type == TMPL_TYPE_DATA) {
		rad_assert(vp->da->type == vpt->tmpl_da->type);
		pairdatacpy(vp, vpt->tmpl_da, vpt->tmpl_value, vpt->tmpl_length);
		*out = vp;
		return 0;
	}

	rcode = radius_expand_tmpl(&str, request, vpt);
	if (rcode < 0) {
		pairfree(&vp);
		return rcode;
	}

	if (pairparsevalue(vp, str, 0) < 0) {
		talloc_free(str);
		pairfree(&vp);
		return rcode;
	}

	*out = vp;
	return 0;
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
 * @param vpt specifying the VALUE_PAIRs to iterate over.
 * @return the first VALUE_PAIR specified by the value_pair_tmpl_t, NULL if no matching VALUE_PAIRs exist,
 * 	and NULL on error.
 */
VALUE_PAIR *tmpl_cursor_init(int *err, vp_cursor_t *cursor, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR **vps, *vp;

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

		if (vpt->tmpl_num == NUM_ANY) {
			vp = fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag);
			if (!vp) {
				if (err) *err = -1;
				return NULL;
			}
			VERIFY_VP(vp);
			break;
		}

		(void) fr_cursor_init(cursor, vps);
		num = vpt->tmpl_num;
		while ((vp = fr_cursor_next_by_da(cursor, vpt->tmpl_da, vpt->tmpl_tag))) {
			VERIFY_VP(vp);
			if (num-- <= 0) goto finish;
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

finish:
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

	int err;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	if (out) *out = vp;

	return err;
}
