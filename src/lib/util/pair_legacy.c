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
#include "lib/util/dict.h"
RCSID("$Id$")

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>


static fr_sbuff_term_t const 	bareword_terminals =
				FR_SBUFF_TERMS(
					L("\t"),
					L("\n"),
					L(" "),
					L("!*"),
					L("!="),
					L("!~"),
					L("&&"),		/* Logical operator */
					L(")"),			/* Close condition/sub-condition */
					L("+="),
					L("-="),
					L(":="),
					L("<"),
					L("<="),
					L("=*"),
					L("=="),
					L("=~"),
					L(">"),
					L(">="),
					L("||"),		/* Logical operator */
				);

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param[in] ctx	for talloc
 * @param[in] parent	parent DA to start referencing from
 * @param[in] buffer	to read valuepairs from.
 * @param[in] end	end of the buffer
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @param[in,out] token	The last token we parsed
 * @param[in] depth	the nesting depth for FR_TYPE_GROUP
 * @param[in,out] relative_vp for relative attributes
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
static ssize_t fr_pair_list_afrom_substr(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, char const *buffer, char const *end,
					 fr_pair_list_t *list, fr_token_t *token, unsigned int depth, fr_pair_t **relative_vp)
{
	fr_pair_list_t		tmp_list;
	fr_pair_t		*vp = NULL;
	fr_pair_t		*my_relative_vp;
	char const		*p, *next;
	fr_token_t		quote, last_token = T_INVALID;
	fr_pair_t_RAW		raw;
	fr_dict_attr_t const	*internal = NULL;
	fr_pair_list_t		*my_list;
	TALLOC_CTX		*my_ctx;

	if (fr_dict_internal()) internal = fr_dict_root(fr_dict_internal());
	if (!internal && !parent) return 0;
	if (internal == parent) internal = NULL;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		*token = T_EOL;
		return 0;
	}

	fr_pair_list_init(&tmp_list);

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
		 *	Stop at '}', too, if we're inside of a group.
		 */
		if ((depth > 0) && (*p == '}')) {
			last_token = T_RCBRACE;
			break;
		}

		/*
		 *	Hacky hack...
		 */
		if (strncmp(p, "raw.", 4) == 0) goto do_unknown;

		if (*p == '.') {
			fr_dict_attr_err_t err;
			p++;

			if (!*relative_vp) {
				fr_strerror_const("Relative attributes can only be used immediately after an attribute of type 'group'");
				goto error;
			}

			slen = fr_dict_attr_by_oid_substr(&err, &da, (*relative_vp)->da, &FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
			if (err != FR_DICT_ATTR_OK) goto error;

			my_list = &(*relative_vp)->vp_group;
			my_ctx = *relative_vp;
		} else {
			fr_dict_attr_err_t err;

			/*
			 *	Parse the name.
			 */
			slen = fr_dict_attr_by_oid_substr(&err, &da, parent, &FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
			if ((err != FR_DICT_ATTR_OK) && internal) {
				slen = fr_dict_attr_by_oid_substr(&err, &da, internal,
								  &FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
			}
			if (err != FR_DICT_ATTR_OK) {
			do_unknown:
				slen = fr_dict_unknown_afrom_oid_substr(ctx, NULL, &da_unknown, parent,
									&FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
				if (slen < 0) {
					p += -slen;

				error:
					fr_pair_list_free(&tmp_list);
					*token = T_INVALID;
					return -(p - buffer);
				}

				da = da_unknown;
			}

			my_list = &tmp_list;
			my_ctx = ctx;
		}

		next = p + slen;

		if ((size_t) (next - p) >= sizeof(raw.l_opand)) {
			fr_dict_unknown_free(&da);
			fr_strerror_const("Attribute name too long");
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
			fr_strerror_const("Expecting operator");
			goto error;
		}

		fr_skip_whitespace(p);

		/*
		 *	Allow grouping attributes.
		 */
		switch (da->type) {
		case FR_TYPE_NON_LEAF:
			if (*p != '{') {
				fr_strerror_printf("Group list for %s MUST start with '{'", da->name);
				goto error;
			}
			p++;

			vp = fr_pair_afrom_da(my_ctx, da);
			if (!vp) goto error;

			/*
			 *	Parse nested attributes, but the
			 *	attributes here are relative to each
			 *	other, and not to our parent relative VP.
			 */
			my_relative_vp = NULL;
			slen = fr_pair_list_afrom_substr(vp, vp->da, p, end, &vp->vp_group, &last_token, depth + 1, &my_relative_vp);
			if (slen <= 0) {
				talloc_free(vp);
				goto error;
			}

			if (last_token != T_RCBRACE) {
			failed_group:
				fr_strerror_const("Failed to end group list with '}'");
				talloc_free(vp);
				goto error;
			}

			p += slen;
			fr_skip_whitespace(p);
			if (*p != '}') goto failed_group;
			p++;

			/*
			 *	Cache which VP is now the one for
			 *	relative references.
			 */
			*relative_vp = vp;
			break;

		case FR_TYPE_LEAF:
			/*
			 *	Get the RHS thing.
			 */
			quote = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
			if (quote == T_EOL) {
				fr_strerror_const("Failed to get value");
				goto error;
			}

			switch (quote) {
			case T_DOUBLE_QUOTED_STRING:
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
			vp = fr_pair_afrom_da(my_ctx, da);
			if (!vp) goto error;
			vp->op = raw.op;

			if ((raw.op == T_OP_REG_EQ) || (raw.op == T_OP_REG_NE)) {
				fr_pair_value_bstrndup(vp, raw.r_opand, strlen(raw.r_opand), false);

			} else if ((raw.op == T_OP_CMP_TRUE) || (raw.op == T_OP_CMP_FALSE)) {
				/*
				 *	We don't care what the value is, so
				 *	ignore it.
				 */
				break;
			}

			if (fr_pair_value_from_str(vp, raw.r_opand, strlen(raw.r_opand),
						   fr_value_unescape_by_quote[quote], false) < 0) {
				talloc_free(vp);
				goto error;
			}
			break;
		}

		/*
		 *	Free the unknown attribute, we don't need it any more.
		 */
		fr_dict_unknown_free(&da);

		fr_assert(vp != NULL);
		fr_pair_append(my_list, vp);

		/*
		 *	If there's a relative VP, and it's not the one
		 *	we just added above, and we're not adding this
		 *	VP to the relative one, then nuke the relative
		 *	VP.
		 */
		if (*relative_vp && (vp != *relative_vp) && (my_ctx != *relative_vp)) {
			*relative_vp = NULL;
		}

		/*
		 *	Now look for EOL, hash, etc.
		 */
		if (!*p || (*p == '#') || (*p == '\n')) {
			last_token = T_EOL;
			break;
		}

		fr_skip_whitespace(p);

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

	if (!fr_pair_list_empty(&tmp_list)) fr_pair_list_append(list, &tmp_list);

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
 * @param[in] parent	parent attribute for resolution
 * @param[in] buffer	to read valuepairs from.
 * @param[in] len	length of the buffer
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @return the last token parsed, or #T_INVALID
 */
fr_token_t fr_pair_list_afrom_str(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, char const *buffer, size_t len, fr_pair_list_t *list)
{
	fr_token_t token;
	fr_pair_t	*relative_vp = NULL;

	(void) fr_pair_list_afrom_substr(ctx, parent, buffer, buffer + len, list, &token, 0, &relative_vp);
	return token;
}

/** Read valuepairs from the fp up to End-Of-File.
 *
 * @param[in] ctx		for talloc
 * @param[in] dict		to resolve attributes in.
 * @param[in,out] out		where the parsed fr_pair_ts will be appended.
 * @param[in] fp		to read valuepairs from.
 * @param[out] pfiledone	true if file parsing complete;
 * @return
 *	- 0 on success
 *	- -1 on error
 */
int fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *out, FILE *fp, bool *pfiledone)
{
	fr_token_t	last_token = T_EOL;
	bool		found = false;
	char		buf[8192];
	fr_pair_t	*relative_vp = NULL;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		fr_pair_list_t tmp_list;

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
		fr_pair_list_init(&tmp_list);

		/*
		 *	Call our internal function, instead of the public wrapper.
		 */
		if (fr_pair_list_afrom_substr(ctx, fr_dict_root(dict), buf, buf + sizeof(buf), &tmp_list, &last_token, 0, &relative_vp) < 0) {
			goto fail;
		}

		/*
		 *	@todo - rely on actually checking the syntax, and "OK" result, instead of guessing.
		 *
		 *	The main issue is that it's OK to read no
		 *	attributes on a particular line, but only if
		 *	it's comments.
		 */
		if (!fr_pair_list_num_elements(&tmp_list)) {
			if (last_token == T_EOL) break;

			/*
			 *	This is allowed for relative attributes.
			 */
			if (relative_vp && (last_token == T_COMMA)) {
				found = true;
				continue;
			}

		fail:
			/*
			 *	Didn't read anything, but the previous
			 *	line wasn't EOL.  The input file has a
			 *	format error.
			 */
			*pfiledone = false;
			fr_pair_list_free(out);
			return -1;
		}

		found = true;
		fr_pair_list_append(out, &tmp_list);
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
 * @param[in] op operator for list move.
 *
 * @see radius_pairmove
 */
void fr_pair_list_move_op(fr_pair_list_t *to, fr_pair_list_t *from, fr_token_t op)
{
	fr_pair_t *i, *found;
	fr_pair_list_t head_new, head_prepend;

	if (!to || fr_pair_list_empty(from)) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	fr_pair_list_init(&head_new);

	/*
	 *	Any attributes that are requested to be prepended
	 *	are added to a temporary list here
	 */
	fr_pair_list_init(&head_prepend);

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	for (i = fr_pair_list_head(from); i; ) {
		fr_pair_t *j;

		PAIR_VERIFY(i);

		/*
		 *	We never move Fall-Through.
		 */
		if (fr_dict_attr_is_top_level(i->da) && (i->da->attr == FR_FALL_THROUGH)) {
			i = fr_pair_list_next(from, i);
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
			i = fr_pair_list_next(from, i);
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = fr_pair_find_by_da(to, NULL, i->da);
			if (!found) goto do_add;

			i = fr_pair_list_next(from, i);
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = fr_pair_find_by_da(to, NULL, i->da);
			if (!found) goto do_add;

			/*
			 *	Delete *all* of the attributes
			 *	of the same number.
			 */
			fr_pair_delete_by_da(to, found->da);
			goto do_add;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD_EQ:
	do_add:
			j = fr_pair_list_next(from, i);
			fr_pair_remove(from, i);
			fr_pair_append(&head_new, i);
			i = j;
			continue;
		case T_OP_PREPEND:
			j = fr_pair_list_next(from, i);
			fr_pair_remove(from, i);
			fr_pair_prepend(&head_prepend, i);
			i = j;
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	If the op parameter was prepend, add the "new list
	 *	attributes first as those whose individual operator
	 *	is prepend should be prepended to the resulting list
	 */
	if (op == T_OP_PREPEND) fr_pair_list_prepend(to, &head_new);

	/*
	 *	If there are any items in the prepend list prepend
	 *	it to the "to" list
	 */
	fr_pair_list_prepend(to, &head_prepend);

	/*
	 *	If the op parameter was not prepend, take the "new"
	 *	list, and append it to the "to" list.
	 */
	if (op != T_OP_PREPEND) fr_pair_list_append(to, &head_new);

}
