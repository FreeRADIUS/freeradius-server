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
#include <freeradius-devel/util/pair_cursor.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

static ssize_t fr_pair_afrom_str(fr_pair_ctx_t *pair_ctx, char const *start, char const *in, size_t inlen)
{
	char const *end = in + inlen;
	char const *p = in;
	ssize_t slen;
	fr_dict_attr_t const *da;
	char quote;
	char const *value;
	size_t value_len;
	VALUE_PAIR *vp;

	slen = fr_dict_attr_by_name_substr(NULL, &da, pair_ctx->parent->dict, in);
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
	if (*p != '=') {
		fr_strerror_printf("Syntax error: expected '='");
		return -(p - start);
	}

	p++;
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

	vp = fr_pair_afrom_da(pair_ctx->ctx, da);

	if (!vp) return -(in - start);

	vp->op = T_OP_EQ;
	if (fr_pair_value_from_str(vp, value, value_len, quote, false) < 0) {
		talloc_free(vp);
		return -(in - start);
	}

	fr_cursor_append(pair_ctx->cursor, vp);

	return p - start;
}


static ssize_t fr_pair_ctx_walk(fr_pair_ctx_t *pair_ctx, char const *in, size_t inlen)
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
		slen = fr_dict_attr_by_name_substr(NULL, &da, parent->dict, p);
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


/** Allocate a VALUE_PAIR from fields
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
		slen = fr_dict_attr_by_name_substr(NULL, &da, pair_ctx->parent->dict, p);
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
	 *	Walk down the list of attribute references.
	 */
	slen = fr_pair_ctx_walk(pair_ctx, p, end - p);
	if (slen <= 0) return slen - (p - in);

	p += slen;
	return p - in;
}
