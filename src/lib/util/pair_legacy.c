/*
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
 */

/** AVP manipulation and search API
 *
 * @file src/lib/util/pair.c
 *
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

/** Mark a valuepair for xlat expansion
 *
 * Copies xlat source (unprocessed) string to valuepair value, and sets value type.
 *
 * @param vp to mark for expansion.
 * @param value to expand.
 * @return
 *	- 0 if marking succeeded.
 *	- -1 if #fr_pair_t already had a value, or OOM.
 */
int fr_pair_mark_xlat(fr_pair_t *vp, char const *value)
{
	char *raw;

	/*
	 *	valuepair should not already have a value.
	 */
	if (vp->type != VT_NONE) {
		fr_strerror_printf("Pair already has a value");
		return -1;
	}

	raw = talloc_typed_strdup(vp, value);
	if (!raw) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	vp->type = VT_XLAT;
	vp->xlat = raw;
	vp->vp_length = 0;

	return 0;
}

/** Create a valuepair from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @param ctx for talloc
 * @param dict to user for partial resolution.
 * @param attribute name to parse.
 * @param value to parse (must be a hex string).
 * @param op to assign to new valuepair.
 * @return new #fr_pair_t or NULL on error.
 */
static fr_pair_t *fr_pair_make_unknown(TALLOC_CTX *ctx, fr_dict_t const *dict,
					char const *attribute, char const *value,
					fr_token_t op)
{
	fr_pair_t		*vp;
	fr_dict_attr_t		*n;
	fr_sbuff_t		sbuff = FR_SBUFF_IN(attribute, strlen(attribute));

	vp = fr_pair_alloc_null(ctx);
	if (!vp) return NULL;

	if ((fr_dict_unknown_afrom_oid_substr(vp, NULL, &n, fr_dict_root(dict), &sbuff) <= 0) ||
					      fr_sbuff_remaining(&sbuff)) {
		talloc_free(vp);
		return NULL;
	}
	vp->da = n;

	/*
	 *	No value, but ensure that we still set up vp->data properly.
	 */
	if (!value) {
		value = "";

	} else if (strncasecmp(value, "0x", 2) != 0) {
		/*
		 *	Unknown attributes MUST be of type 'octets'
		 */
		fr_strerror_printf("Unknown attribute \"%s\" requires a hex "
				   "string, not \"%s\"", attribute, value);
		talloc_free(vp);
		return NULL;
	}

	if (fr_pair_value_from_str(vp, value, -1, '"', false) < 0) {
		talloc_free(vp);
		return NULL;
	}

	vp->op = (op == 0) ? T_OP_EQ : op;
	return vp;
}

/** Create a #fr_pair_t from ASCII strings
 *
 * Converts an attribute string identifier (with an optional tag qualifier)
 * and value string into a #fr_pair_t.
 *
 * The string value is parsed according to the type of #fr_pair_t being created.
 *
 * @param[in] ctx	for talloc.
 * @param[in] dict	to look attributes up in.
 * @param[in] vps	list where the attribute will be added (optional)
 * @param[in] attribute	name.
 * @param[in] value	attribute value (may be NULL if value will be set later).
 * @param[in] op	to assign to new #fr_pair_t.
 * @return a new #fr_pair_t.
 */
fr_pair_t *fr_pair_make(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *vps,
			char const *attribute, char const *value, fr_token_t op)
{
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	char const		*attrname = attribute;

	/*
	 *	It's not found in the dictionary, so we use
	 *	another method to create the attribute.
	 */
	da = fr_dict_attr_by_qualified_oid(NULL, dict, attrname, true);
	if (da) {
		vp = fr_pair_make_unknown(ctx, dict, attrname, value, op);
		if (!vp) return NULL;

		if (vps) fr_pair_add(vps, vp);
		return vp;
	}

#ifndef NDEBUG
	if (!da) return NULL;
#endif

	if (da->type == FR_TYPE_GROUP) {
		fr_strerror_printf("Attributes of type 'group' are not supported");
		return NULL;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return NULL;
	vp->op = (op == 0) ? T_OP_EQ : op;

	switch (vp->op) {
	case T_OP_CMP_TRUE:
	case T_OP_CMP_FALSE:
		fr_pair_value_clear(vp);
		value = NULL;	/* ignore it! */
		break;

		/*
		 *	Regular expression comparison of integer attributes
		 *	does a STRING comparison of the names of their
		 *	integer attributes.
		 */
	case T_OP_REG_EQ:	/* =~ */
	case T_OP_REG_NE:	/* !~ */
	{
#ifndef HAVE_REGEX
		fr_strerror_printf("Regular expressions are not supported");
		return NULL;
#else
		ssize_t slen;
		regex_t *preg;

		/*
		 *	Someone else will fill in the value.
		 */
		if (!value) break;

		talloc_free(vp);

		slen = regex_compile(ctx, &preg, value, strlen(value), NULL, false, true);
		if (slen <= 0) {
			fr_strerror_printf_push("Error at offset %zu compiling regex for %s", -slen, attribute);
			return NULL;
		}
		talloc_free(preg);

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) return NULL;
		vp->op = op;

		if (fr_pair_mark_xlat(vp, value) < 0) {
			talloc_free(vp);
			return NULL;
		}

		value = NULL;	/* ignore it */
		break;
#endif
	}
	default:
		break;
	}

	/*
	 *	We probably want to fix fr_pair_value_from_str to accept
	 *	octets as values for any attribute.
	 */
	if (value && (fr_pair_value_from_str(vp, value, -1, '\"', true) < 0)) {
		talloc_free(vp);
		return NULL;
	}

	if (vps) fr_pair_add(vps, vp);
	return vp;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param[in] ctx	for talloc
 * @param[in] dict	to resolve attributes in.
 * @param[in] buffer	to read valuepairs from.
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @param[in,out] token	The last token we parsed
 * @param[in] depth	the nesting depth for FR_TYPE_GROUP
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
static ssize_t fr_pair_list_afrom_substr(TALLOC_CTX *ctx, fr_dict_t const *dict, char const *buffer,
					 fr_pair_list_t *list, fr_token_t *token, int depth)
{
	fr_pair_t	*vp, *head, **tail;
	char const	*p, *next;
	fr_token_t	last_token = T_INVALID;
	fr_pair_t_RAW	raw;
	fr_dict_attr_t const *root = fr_dict_root(dict);
	fr_dict_attr_t const *internal = fr_dict_root(fr_dict_internal());

	if (internal == root) internal = NULL;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		*token = T_EOL;
		return 0;
	}

	head = NULL;
	tail = &head;

	p = buffer;
	while (true) {
		ssize_t slen;
		fr_dict_attr_t const *da;
		fr_dict_attr_t *da_unknown = NULL;

		fr_skip_whitespace(p);

		/*
		 *	Stop at the end of the input, returning
		 *	whatever token was last read.
		 */
		if (!*p) break;

		if (*p == '#') {
			last_token = T_EOL;
			break;
		}

		/*
		 *	Parse the name.
		 */
		slen = fr_dict_attr_by_oid_substr(NULL, &da, root, &FR_SBUFF_IN(p, strlen(p)));
		if ((slen <= 0) && internal) slen = fr_dict_attr_by_oid_substr(NULL, &da, internal, &FR_SBUFF_IN(p, strlen(p)));
		if (slen <= 0) {
			slen = fr_dict_unknown_afrom_oid_substr(ctx, NULL, &da_unknown, root,
								&FR_SBUFF_IN(p, strlen(p)));
			if (slen <= 0) {
				p += -slen;

			error:
				fr_pair_list_free(&head);
				*token = T_INVALID;
				return -(p - buffer);
			}

			da = da_unknown;
		}

		next = p + slen;

		if ((size_t) (next - p) >= sizeof(raw.l_opand)) {
			fr_dict_unknown_free(&da);
			fr_strerror_printf("Attribute name too long");
			goto error;
		}

		memcpy(raw.l_opand, p, next - p);
		raw.l_opand[next - p] = '\0';
		raw.r_opand[0] = '\0';

		p = next;
		fr_skip_whitespace(p);

		/*
		 *	There must be an operator here.
		 */
		raw.op = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
		if ((raw.op  < T_EQSTART) || (raw.op  > T_EQEND)) {
			fr_dict_unknown_free(&da);
			fr_strerror_printf("Expecting operator");
			goto error;
		}

		fr_skip_whitespace(p);

		/*
		 *	Allow grouping attributes.
		 */
		if ((da->type == FR_TYPE_GROUP) || (da->type == FR_TYPE_TLV)) {
			fr_pair_t *child = NULL;

			if (*p != '{') {
				fr_strerror_printf("Group list for %s MUST start with '{'", da->name);
				goto error;
			}
			p++;

			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) goto error;

			slen = fr_pair_list_afrom_substr(vp, dict, p, &child, &last_token, depth + 1);
			if (slen <= 0) {
				talloc_free(vp);
				goto error;
			}

			if (last_token != T_RCBRACE) {
			failed_group:
				fr_strerror_printf("Failed to end group list with '}'");
				talloc_free(vp);
				goto error;
			}

			p += slen;
			fr_skip_whitespace(p);
			if (*p != '}') goto failed_group;
			p++;
			vp->vp_group = child;

		} else {
			fr_token_t quote;
			char const *q;

			/*
			 *	Get the RHS thing.
			 */
			quote = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
			if (quote == T_EOL) {
				fr_strerror_printf("Failed to get value");
				goto error;
			}

			switch (quote) {
				/*
				 *	Perhaps do xlat's
				 */
			case T_DOUBLE_QUOTED_STRING:
				/*
				 *	Only report as double quoted if it contained valid
				 *	a valid xlat expansion.
				 */
				q = strchr(raw.r_opand, '%');
				if (q && (q[1] == '{')) {
					raw.quote = quote;
				} else {
					raw.quote = T_SINGLE_QUOTED_STRING;
				}
				break;

			case T_SINGLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
			case T_BARE_WORD:
				raw.quote = quote;
				break;

			default:
				fr_strerror_printf("Failed to find expected value on right hand side in %s", da->name);
				goto error;
			}

			fr_skip_whitespace(p);

			/*
			 *	Regular expressions get sanity checked by pair_make().
			 *
			 *	@todo - note that they will also be escaped,
			 *	so we may need to fix that later.
			 */
			if ((raw.op == T_OP_REG_EQ) || (raw.op == T_OP_REG_NE)) {
				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) goto error;
				vp->op = raw.op;

				fr_pair_value_bstrndup(vp, raw.r_opand, strlen(raw.r_opand), false);
			} else {
				/*
				 *	All other attributes get the name
				 *	parsed.
				 */
				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) goto error;
				vp->op = raw.op;

				/*
				 *	We don't care what the value is, so
				 *	ignore it.
				 */
				if ((raw.op == T_OP_CMP_TRUE) || (raw.op == T_OP_CMP_FALSE)) goto next;

				/*
				 *	fr_pair_raw_from_str() only returns this when
				 *	the input looks like it needs to be xlat'd.
				 */
				if (raw.quote == T_DOUBLE_QUOTED_STRING) {
					if (fr_pair_mark_xlat(vp, raw.r_opand) < 0) {
						talloc_free(vp);
						goto error;
					}

					/*
					 *	Parse it ourselves.  The RHS
					 *	might NOT be tainted, but we
					 *	don't know.  So just mark it
					 *	as such to be safe.
					 */
				} else if (fr_pair_value_from_str(vp, raw.r_opand, -1, '"', true) < 0) {
					talloc_free(vp);
					goto error;
				}
			}
		}

	next:
		/*
		 *	Free the unknown attribute, we don't need it any more.
		 */
		fr_dict_unknown_free(&da);

		*tail = vp;
		tail = &((*tail)->next);

		/*
		 *	Now look for EOL, hash, etc.
		 */
		if (!*p || (*p == '#') || (*p == '\n')) {
			last_token = T_EOL;
			break;
		}

		/*
		 *	Check for nested groups.
		 */
		if ((depth > 0) && (p[0] == ' ') && (p[1] == '}')) p++;

		/*
		 *	Stop at '}', too, if we're inside of a group.
		 */
		if ((depth > 0) && (*p == '}')) {
			last_token = T_RCBRACE;
			break;
		}

		if (*p != ',') {
			fr_strerror_printf("Expected ',', got '%c' at offset %zu", *p, p - buffer);
			goto error;
		}
		p++;
		last_token = T_COMMA;
	}

	if (head) fr_pair_add(list, head);

	/*
	 *	And return the last token which we read.
	 */
	*token = last_token;
	return p - buffer;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param[in] ctx	for talloc
 * @param[in] dict	to resolve attributes in.
 * @param[in] buffer	to read valuepairs from.
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @return the last token parsed, or #T_INVALID
 */
fr_token_t fr_pair_list_afrom_str(TALLOC_CTX *ctx, fr_dict_t const *dict, char const *buffer, fr_pair_list_t *list)
{
	fr_token_t token;

	(void) fr_pair_list_afrom_substr(ctx, dict, buffer, list, &token, 0);
	return token;
}

/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
int fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *out, FILE *fp, bool *pfiledone)
{
	fr_token_t	last_token = T_EOL;
	bool		found = false;
	fr_cursor_t	cursor;
	char		buf[8192];

	fr_cursor_init(&cursor, out);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		fr_cursor_t append;
		fr_pair_t   *vp;

		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if (buf[0] == '\n') {
			if (found) {
				*pfiledone = false;
				return 0;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Read all of the attributes on the current line.
		 *
		 *	If we get nothing but an EOL, it's likely OK.
		 */
		vp = NULL;
		last_token = fr_pair_list_afrom_str(ctx, dict, buf, &vp);
		if (!vp) {
			if (last_token == T_EOL) break;

			/*
			 *	Didn't read anything, but the previous
			 *	line wasn't EOL.  The input file has a
			 *	format error.
			 */
			*pfiledone = false;
			vp = fr_cursor_head(&cursor);
			if (vp) fr_pair_list_free(&vp);
			*out = NULL;
			return -1;
		}

		found = true;
		fr_cursor_init(&append, &vp);
		fr_cursor_merge(&cursor, &append);
		(void) fr_cursor_tail(&cursor);
	}

	*pfiledone = true;
	return 0;
}


/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed
 *	 in most places. Consider using radius_pairmove in server code.
 *
 * @note fr_pair_list_free should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 *
 * @see radius_pairmove
 */
void fr_pair_list_move(fr_pair_list_t *to, fr_pair_list_t *from)
{
	fr_pair_t *i, *found;
	fr_pair_t *head_new, **tail_new;
	fr_pair_t **tail_from;

	if (!to || !from || !*from) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	head_new = NULL;
	tail_new = &head_new;

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	tail_from = from;
	while ((i = *tail_from) != NULL) {
		fr_pair_t *j;

		VP_VERIFY(i);

		/*
		 *	We never move Fall-Through.
		 */
		if (fr_dict_attr_is_top_level(i->da) && (i->da->attr == FR_FALL_THROUGH)) {
			tail_from = &(i->next);
			continue;
		}

		/*
		 *	Unlike previous versions, we treat all other
		 *	attributes as normal.  i.e. there's no special
		 *	treatment for passwords or Hint.
		 */

		switch (i->op) {
		/*
		 *	Anything else are operators which
		 *	shouldn't occur.  We ignore them, and
		 *	leave them in place.
		 */
		default:
			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = fr_pair_find_by_da(to, i->da);
			if (!found) goto do_add;

			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = fr_pair_find_by_da(to, i->da);
			if (!found) goto do_add;

			switch (found->vp_type) {
			default:
				j = found->next;
				memcpy(found, i, sizeof(*found));
				found->next = j;
				break;

			case FR_TYPE_OCTETS:
				fr_pair_value_memdup_buffer(found, i->vp_octets, i->vp_tainted);
				fr_pair_value_clear(i);
				break;

			case FR_TYPE_STRING:
				fr_pair_value_bstrdup_buffer(found, i->vp_strvalue, i->vp_tainted);
				fr_pair_value_clear(i);
				break;
			}

			/*
			 *	Delete *all* of the attributes
			 *	of the same number.
			 */
			fr_pair_delete_by_da(&found->next, found->da);

			/*
			 *	Remove this attribute from the
			 *	"from" list.
			 */
			*tail_from = i->next;
			i->next = NULL;
			fr_pair_list_free(&i);
			continue;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD:
	do_add:
			*tail_from = i->next;
			i->next = NULL;
			*tail_new = i;
			tail_new = &(i->next);
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	Take the "new" list, and append it to the "to" list.
	 */
	fr_pair_add(to, head_new);
}
