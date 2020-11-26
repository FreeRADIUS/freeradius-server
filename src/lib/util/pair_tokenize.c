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

/** AVP parsing
 *
 * @file src/lib/util/pair_tokenize.c
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

static ssize_t op_to_token(fr_token_t *token, char const *op, size_t oplen)
{
	char const *p = op;

	if (!token || !op || !oplen) return 0;

	switch (*p) {
	default:
		fr_strerror_printf("Invalid text. Expected comparison operator");
		return -(p - op);

	case '!':
		if (oplen < 2) goto invalid_operator;

		if (p[1] == '=') {
			*token = T_OP_NE;
			p += 2;

#ifdef HAVE_REGEX
		} else if (p[1] == '~') {
			*token = T_OP_REG_NE;
			p += 2;
#endif

		} else if (p[1] == '*') {
			*token = T_OP_CMP_FALSE;
			p += 2;

		} else {
		invalid_operator:
			fr_strerror_printf("Invalid operator");
			return -(p - op);
		}
		break;

	case '=':
		/*
		 *	Bare '=' is allowed.
		 */
		if (oplen == 1) {
			*token = T_OP_EQ;
			p++;
			break;
		}

		if (oplen < 2) goto invalid_operator;

		if (p[1] == '=') {
			*token = T_OP_CMP_EQ;
			p += 2;

#ifdef HAVE_REGEX
		} else if (p[1] == '~') {
			*token = T_OP_REG_EQ;
			p += 2;
#endif

		} else if (p[1] == '*') {
			*token = T_OP_CMP_TRUE;
			p += 2;

		} else {
			/*
			 *	Ignore whatever is after the '=' sign.
			 */
			*token = T_OP_EQ;
			p++;
		}
		break;

	case '<':
		if ((oplen > 1) && (p[1] == '=')) {
			*token = T_OP_LE;
			p += 2;

		} else {
			*token = T_OP_LT;
			p++;
		}
		break;

	case '>':
		if ((oplen > 1) && (p[1] == '=')) {
			*token = T_OP_GE;
			p += 2;

		} else {
			*token = T_OP_GT;
			p++;
		}
		break;
	}

	return p - op;
}

/** Allocate a fr_pair_t based on pre-parsed fields.
 *
 * @param ctx	the talloc ctx
 * @param da	the da for the vp
 * @param op	the operator
 * @param value the value to parse
 * @param value_len length of the value string
 * @param quote	the quotation character for the value string.
 * @return
 *	- fr_pair_t* on success
 *	- NULL on error
 *
 *  It's just better for this function to take the broken-out /
 *  pre-parsed fields.  That way the caller can do any necessary
 *  parsing.
 */
static fr_pair_t *fr_pair_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *da,
					fr_token_t op,
					char const *value, size_t value_len,
					char quote)
{
	fr_pair_t *vp;

	if (!da || !value || (value_len == 0)) return NULL;

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return NULL;

	vp->op = op;

	if (fr_pair_value_from_str(vp, value, value_len, quote, false) < 0) {
		talloc_free(vp);
		return NULL;
	}

	return vp;
}


/** Allocate one fr_pair_t from a string, and add it to the pair_ctx cursor.
 *
 * @param[in,out] pair_ctx	the parsing context
 * @param[in] start		Where to create relative error offsets in relation to.
 * @param in	String to parse
 * @param inlen	length of string to parse
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
static ssize_t fr_pair_afrom_str(fr_pair_ctx_t *pair_ctx, char const *start, char const *in, size_t inlen)
{
	char const *end = in + inlen;
	char const *p = in;
	ssize_t slen;
	fr_dict_attr_t const *da;
	char quote;
	char const *value;
	size_t value_len;
	fr_pair_t *vp;
	fr_token_t op;

	slen = fr_dict_attr_by_name_substr(NULL, &da, pair_ctx->parent, &FR_SBUFF_IN(p, end), NULL);
	if (slen <= 0) return slen - (in - start);

	if (da->parent != pair_ctx->parent) {
		fr_strerror_printf("Unexpected attribute %s is not a child of %s",
				   da->name, pair_ctx->parent->name);
		return -(in - start);
	}

	p = in + slen;
	if (p >= end) {
		fr_strerror_printf("Attribute name overflows the input buffer");
		return -(in - start);
	}

	while ((isspace((int) *p)) && (p < end)) p++;

	if (p >= end) {
		fr_strerror_printf("No operator found in the input buffer");
		return -(p - start);
	}

	/*
	 *	For now, the only allowed operator is equals.
	 */
	slen = op_to_token(&op, p, (end - p));
	if (slen <= 0) {
		fr_strerror_printf("Syntax error: expected '='");
		return slen - -(p - start);
	}
	p += slen;

	while ((isspace((int) *p)) && (p < end)) p++;

	if (p >= end) {
		fr_strerror_printf("No value found in the input buffer");
		return -(p - start);
	}

	if (*p == '`') {
		fr_strerror_printf("Invalid string quotation");
		return -(p - start);
	}

	if ((*p == '"') || (*p == '\'')) {
		quote = *p;
		value = p + 1;

		slen = fr_skip_string(p, end);
		if (slen <= 0) return slen - (p - start);
		p += slen;
		value_len = slen - 2; /* account for two "" */

	} else {
		quote = 0;
		value = p;

		/*
		 *	Skip bare words, but end at comma or end-of-buffer.
		 */
		while (!isspace((int) *p) && (*p != ',') && (p < end)) p++;

		value_len = p - value;
	}

	if (p > end) {
		fr_strerror_printf("Value overflows the input buffer");
		return -(p - start);
	}

	vp = fr_pair_afrom_fields(pair_ctx->ctx, da, op, value, value_len, quote);
	if (!vp) return -(in - start);

	fr_cursor_append(pair_ctx->cursor, vp);

	return p - start;
}

/** Set a new DA context based on the input string
 *
 * @param[in,out] pair_ctx	the parsing context
 * @param[in] in	String to parse
 * @param[in] inlen	length of string to parse
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 *
 *  pair_ctx->da is set to the new parsing context.
 *
 *  @todo - allow for child contexts, so that we can parse TLVs into vp->vp_children.
 *	    This change requires nested cursors, but not necessarily nested contexts.
 *	    We probably want to have a `fr_dlist_t` of pair_ctx, and we always
 *	    operate on the last one.  When we change contexts to an attributes parent,
 *	    we also change pair_ctx to a parent context.  This is like the da stack,
 *	    but with child cursors, too.
 *
 *	    We also want to emulate the previous behavior of group attributes based
 *	    on parent, and increasing child_num.  i.e. if we're parsing a series of
 *	    "attr-foo = bar", then we watch the parent context, and create a new
 *	    parent VP if this child has a SMALLER attribute number than the previous
 *	    child.  This allows the previous configurations to "just work".
 */
static ssize_t fr_pair_ctx_set(fr_pair_ctx_t *pair_ctx, char const *in, size_t inlen)
{
	char const *end = in + inlen;
	char const *p = in;
	ssize_t slen;
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent = pair_ctx->parent;

	/*
	 *	Parse the attribute name.
	 */
	while (p < end) {
		slen = fr_dict_attr_by_name_substr(NULL, &da, parent, &FR_SBUFF_IN(p, end), NULL);
		if (slen <= 0) return slen - (p - in);

		if (da->parent != parent) {
			fr_strerror_printf("Unexpected attribute %s is not a child of %s",
					   da->name, parent->name);
			return -(p - in);
		}

		if ((p + slen) > end) {
			fr_strerror_printf("Attribute name overflows the input buffer");
			return -(p - in);
		}

		/*
		 *	Check for ending conditions.
		 */
		p += slen;
		parent = da;

		if ((p >= end) || (*p == ',')) {
			break;
		}

		/*
		 *	We now MUST have FOO.BAR
		 */
		if (*p != '.') {
			fr_strerror_printf("Unexpected text after attribute");
			return -(p - in);
		}
		p++;
	}

	pair_ctx->parent = parent;
	return p - in;
}


/** Parse a pair context from a string.
 *
 * @param pair_ctx	the parsing context
 * @param in	String to parse
 * @param inlen	length of string to parse
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 *
 *  This function will parse fr_pair_ts, or context changes, up to
 *  end of string, or a trailing ','.  The caller is responsible for
 *  parsing the comma.
 *
 *  It accepts the following syntax:
 *
 *  - Attribute = value
 *	* reset to a new top-level context according to the parent of Attribute
 *	* parse the attribute and the value
 *
 *  - .Attribute = value
 *	* parse the attribute and the value in the CURRENT top-level context
 *
 *  - .Attribute
 *	* reset to a new context according to Attribute, relative to the current context
 *
 *  - ..Attribute
 *	* reset to a new context according to Attribute, relative to the current context
 *	* more '.' will walk back up the context tree.
 *
 *  - Attribute
 *	* reset to a new top-level context according to Attribute
 *
 */
ssize_t fr_pair_ctx_afrom_str(fr_pair_ctx_t *pair_ctx, char const *in, size_t inlen)
{
	char const *end = in + inlen;
	char const *p = in;
	ssize_t slen;
	fr_dict_attr_t const *da;

	while (isspace((int) *p) && (p < end)) p++;
	if (p >= end) return end - in;

	/*
	 *	There may be one or more leading '.'
	 */
	if (*p == '.') {

		/*
		 *	.ATTRIBUTE = VALUE
		 */
		if (p[1] != '.') {
			p++;
			return fr_pair_afrom_str(pair_ctx, in, p, end - p);
		}

		/*
		 *	'.' is our parent.
		 */
		da = pair_ctx->parent;

		/*
		 *	Loop until we find the end of the '.', resetting parent each time.
		 */
		while (p < end) {
			if (*p == '.') {
				pair_ctx->parent = da;
				da = da->parent;
				p++;
				continue;
			}

			/*
			 *	Comma is the end of a reference.
			 */
			if (*p == ',') {
				return p - in;
			}

			/*
			 *	.FOO, must be a reference.
			 */
			break;
		}

		if (p == end) return p - in;

	} else {
		/*
		 *	No leading '.', the reference MUST be from the root.
		 */
		pair_ctx->parent = fr_dict_root(pair_ctx->parent->dict);

		/*
		 *	We allow a leaf OR a reference here.
		 */
		slen = fr_dict_attr_by_name_substr(NULL, &da, pair_ctx->parent, &FR_SBUFF_IN(p, end), NULL);
		if (slen <= 0) return slen - (p - in);

		/*
		 *	Structural types do not have values.  So a
		 *	bare "Foo-Group" string MUST be changing the
		 *	reference to that da.
		 */
		switch (da->type) {
		case FR_TYPE_GROUP:
		case FR_TYPE_TLV:
		case FR_TYPE_STRUCT:
			pair_ctx->parent = da;
			p += slen;

			if ((p >= end) || (*p == ',')) return p - in;

			if (*p != '.') {
				fr_strerror_printf("Unexpected text");
				return - (p - in);
			}

			p++;
			break;

		default:
			/*
			 *	Non-structural types MUST have values.
			 *	So change the parent to its parent,
			 *	and parse the leaf pair.
			 */
			pair_ctx->parent = da->parent;
			return fr_pair_afrom_str(pair_ctx, in, p, end - in);
		}
	}

	/*
	 *	Set the new context based on the attribute
	 */
	slen = fr_pair_ctx_set(pair_ctx, p, end - p);
	if (slen <= 0) return slen - (p - in);

	p += slen;
	return p - in;
}

/** Reset a pair_ctx to the dictionary root.
 *
 * @param pair_ctx	the parsing context
 * @param dict		the dictionary to reset to the root
 *
 *  This function is used in order to reset contexts when parsing
 *  strings that change attribute lists. i.e. &request.foo, &reply.bar
 *
 *  This function is simple for now, but will get complex once we
 *  start using vp->vp_children
 */
void fr_pair_ctx_reset(fr_pair_ctx_t *pair_ctx, fr_dict_t const *dict)
{
	pair_ctx->parent = fr_dict_root(dict);
}
