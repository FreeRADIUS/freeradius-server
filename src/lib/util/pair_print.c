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

/** Pair serialisation API
 *
 * @file src/lib/util/pair_print.c
 *
 * @copyright 2020 The FreeRADIUS server project
 */

char *fr_pair_type_asprint(TALLOC_CTX *ctx, fr_type_t type)
{
	switch (type) {
	case FR_TYPE_STRING :
		return talloc_typed_strdup(ctx, "_");

	case FR_TYPE_UINT64:
	case FR_TYPE_SIZE:
	case FR_TYPE_INT32:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_DATE:
		return talloc_typed_strdup(ctx, "0");

	case FR_TYPE_IPV4_ADDR:
		return talloc_typed_strdup(ctx, "?.?.?.?");

	case FR_TYPE_IPV4_PREFIX:
		return talloc_typed_strdup(ctx, "?.?.?.?/?");

	case FR_TYPE_IPV6_ADDR:
		return talloc_typed_strdup(ctx, "[:?:]");

	case FR_TYPE_IPV6_PREFIX:
		return talloc_typed_strdup(ctx, "[:?:]/?");

	case FR_TYPE_OCTETS:
		return talloc_typed_strdup(ctx, "??");

	case FR_TYPE_ETHERNET:
		return talloc_typed_strdup(ctx, "??:??:??:??:??:??:??:??");

	case FR_TYPE_ABINARY:
		return talloc_typed_strdup(ctx, "??");

	case FR_TYPE_GROUP:
		return talloc_typed_strdup(ctx, "{ ? }");

	default :
		break;
	}

	return talloc_typed_strdup(ctx, "<UNKNOWN-TYPE>");
}

/** Print one attribute and value to a string
 *
 * Print a VALUE_PAIR in the format:
@verbatim
	<attribute_name>[:tag] <op> <value>
@endverbatim
 * to a string.
 *
 * @param out Where to write the string.
 * @param outlen Length of output buffer.
 * @param vp to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
size_t fr_pair_snprint(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const	*token = NULL;
	size_t		len, freespace = outlen;

	if (!out) return 0;

	*out = '\0';
	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if (vp->da->flags.has_tag && (vp->tag != 0) && (vp->tag != TAG_ANY)) {
		len = snprintf(out, freespace, "%s:%d %s ", vp->da->name, vp->tag, token);
	} else {
		len = snprintf(out, freespace, "%s %s ", vp->da->name, token);
	}

	if (is_truncated(len, freespace)) return len;
	out += len;
	freespace -= len;

	len = fr_pair_value_snprint(out, freespace, vp, '"');
	if (is_truncated(len, freespace)) return (outlen - freespace) + len;
	freespace -= len;

	return (outlen - freespace);
}

/** Print one attribute and value to FP
 *
 * Complete string with '\\t' and '\\n' is written to buffer before printing to
 * avoid issues when running with multiple threads.
 *
 * @param fp to output to.
 * @param vp to print.
 */
void fr_pair_fprint(FILE *fp, VALUE_PAIR const *vp)
{
	char	buf[1024];
	char	*p = buf;
	size_t	len;

	if (!fp) return;
	VP_VERIFY(vp);

	*p++ = '\t';
	len = fr_pair_snprint(p, sizeof(buf) - 1, vp);
	if (!len) {
		return;
	}
	p += len;

	/*
	 *	Deal with truncation gracefully
	 */
	if (((size_t) (p - buf)) >= (sizeof(buf) - 2)) {
		p = buf + (sizeof(buf) - 2);
	}

	*p++ = '\n';
	*p = '\0';

	fputs(buf, fp);
}


/** Print a list of attributes and enumv
 *
 * @param[in] log to output to.
 * @param[in] vp to print.
 * @param[in] file where the message originated
 * @param[in] line where the message originated
 */
void _fr_pair_list_log(fr_log_t const *log, VALUE_PAIR const *vp, char const *file, int line)
{
	VALUE_PAIR *our_vp;
	fr_cursor_t cursor;

	memcpy(&our_vp, &vp, sizeof(vp)); /* const work-arounds */

	for (vp = fr_cursor_init(&cursor, &our_vp); vp; vp = fr_cursor_next(&cursor)) {
		fr_log(log, L_DBG, file, line, "\t%pP", vp);
	}
}

/** Print one attribute and value to a string
 *
 * Print a VALUE_PAIR in the format:
@verbatim
	<attribute_name>[:tag] <op> <value>
@endverbatim
 * to a string.
 *
 * @param ctx to allocate string in.
 * @param vp to print.
 * @param[in] quote the quotation character
 * @return a talloced buffer with the attribute operator and value.
 */
char *fr_pair_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote)
{
	char const	*token = NULL;
	char 		*str, *value;

	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	value = fr_pair_value_asprint(ctx, vp, quote);

	if (vp->da->flags.has_tag) {
		if (quote && (vp->vp_type == FR_TYPE_STRING)) {
			str = talloc_typed_asprintf(ctx, "%s:%d %s %c%s%c", vp->da->name, vp->tag, token, quote, value, quote);
		} else {
			str = talloc_typed_asprintf(ctx, "%s:%d %s %s", vp->da->name, vp->tag, token, value);
		}
	} else {
		if (quote && (vp->vp_type == FR_TYPE_STRING)) {
			str = talloc_typed_asprintf(ctx, "%s %s %c%s%c", vp->da->name, token, quote, value, quote);
		} else {
			str = talloc_typed_asprintf(ctx, "%s %s %s", vp->da->name, token, value);
		}
	}

	talloc_free(value);

	return str;
}

/** Print the attribute portion of a pair (only)
 *
 * @param[out] out	Where to write the output attribute.
 * @param[in] end	of the output buffer.
 * @param[in] vp	to print the attribute name for.
 * @return
 *	- >= 0 number of bytes written to out on success.
 *	- < 0 number of bytes we need to write out the value.
 */
static inline ssize_t fr_pair_snprint_attr(char * const out, char const * const end, VALUE_PAIR const *vp)
{
	char	*p = out;
	size_t	len = strlen(vp->da->name);

	RETURN_SLEN_IF_NO_SPACE(len, p, end);
	memcpy(p, vp->da->name, len);
	p += len;

	if (vp->tag) {
		size_t ret;

		RETURN_SLEN_IF_NO_SPACE(1, p, end);
		*p++ = ':';

		ret = snprintf(p, end - p, "%u", vp->tag);
		RETURN_SLEN_IF_TRUNCATED(ret, p, end);

		p += ret;
	}

	return p - out;
}

/** Print a leaf attribute pair i.e. <attr> <op> <value>
 *
 * @param[out] out	Where to write the output attribute.
 * @param[in] end	of the output buffer.
 * @param[in] vp	to print.
 * @param[in] str_quote	to use when printing quoted string values.
 */
static inline ssize_t fr_pair_snprintf_leaf(char * const out, char const * const end,
					    VALUE_PAIR const *vp, char str_quote)
{
	char *p = out;

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	fr_value_box_snprint(out, )
}


