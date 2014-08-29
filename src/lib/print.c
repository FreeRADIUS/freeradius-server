/*
 * print.c	Routines to print stuff.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#include	<ctype.h>

/*
 *	Checks for utf-8, taken from:
 *
 *  http://www.w3.org/International/questions/qa-forms-utf-8
 *
 *	Note that we don't care about the length of the input string,
 *	because '\0' is an invalid UTF-8 character.
 */
int fr_utf8_char(uint8_t const *str)
{
	if (*str < 0x20) return 0;

	if (*str <= 0x7e) return 1; /* 1 */

	if (*str <= 0xc1) return 0;

	if ((str[0] >= 0xc2) &&	/* 2 */
	    (str[0] <= 0xdf) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf)) {
		return 2;
	}

	if ((str[0] == 0xe0) &&	/* 3 */
	    (str[1] >= 0xa0) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xe1) &&	/* 4a */
	    (str[0] <= 0xec) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xee) &&	/* 4b */
	    (str[0] <= 0xef) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] == 0xed) &&	/* 5 */
	    (str[1] >= 0x80) &&
	    (str[1] <= 0x9f) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] == 0xf0) &&	/* 6 */
	    (str[1] >= 0x90) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}

	if ((str[0] >= 0xf1) &&	/* 6 */
	    (str[1] <= 0xf3) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}


	if ((str[0] == 0xf4) &&	/* 7 */
	    (str[1] >= 0x80) &&
	    (str[1] <= 0x8f) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}

	/*
	 *	Invalid UTF-8 Character
	 */
	return 0;
}

/** Escape any non printable or non-UTF8 characters in the input string
 *
 * @param[in] in string to escape.
 * @param[in] inlen length of string to escape (lets us deal with embedded NULLs)
 * @param[out] out where to write the escaped string.
 * @param[out] outlen the length of the buffer pointed to by out.
 * @return the number of bytes written to the out buffer, or a number > outlen if truncation has occurred.
 */
size_t fr_print_string(char const *in, size_t inlen, char *out, size_t outlen)
{
	uint8_t const	*p = (uint8_t const *) in;
	int		sp = 0;
	int		utf8 = 0;
	size_t		freespace = outlen;

	/* Can't '\0' terminate */
	if (freespace == 0) {
		return inlen;
	}

	/* No input, so no output... */
	if (!in) {
	no_input:
		*out = '\0';
		return 0;
	}

	/* Figure out the length of the input string */
	if (inlen == 0) inlen = strlen(in);

	/* Not enough space to hold one char */
	if (freespace < 2) {
		/* And there's input data... */
		if (inlen > 0) {
			*out = '\0';
			return inlen;
		}

		goto no_input;
	}

	while (inlen > 0) {
		/*
		 *	Hack: never print trailing zero.
		 *	Some clients send pings with an off-by-one
		 *	length (confused with strings in C).
		 */
		if ((inlen == 1) && (*p == '\0')) {
			inlen--;
			break;
		}
		switch (*p) {
		case '\\':
			sp = '\\';
			break;

		case '\r':
			sp = 'r';
			break;

		case '\n':
			sp = 'n';
			break;

		case '\t':
			sp = 't';
			break;

		case '"':
			sp = '"';
			break;

		default:
			sp = '\0';
			break;
		}

		if (sp) {
			if (freespace < 3) break; /* \ + <c> + \0 */
			*out++ = '\\';
			*out++ = sp;
			freespace -= 2;
			p++;
			inlen--;
			continue;
		}

		utf8 = fr_utf8_char(p);
		if (utf8 == 0) {
			if (freespace < 5) break; /* \ + <o><o><o> + \0 */
			snprintf(out, freespace, "\\%03o", *p);
			out += 4;
			freespace -= 4;
			p++;
			inlen--;
			continue;
		}

		do {
			if (freespace < 2) goto finish; /* <c> + \0 */
			*out++ = *p++;
			freespace--;
			inlen--;
		} while (--utf8 > 0);
	}

finish:
	*out = '\0';

	/* Indicate truncation occurred */
	if (inlen > 0) return outlen + inlen;

	return outlen - freespace;
}

/** Find the length of the buffer required to fully escape a string with fr_print_string
 *
 * Were assuming here that's it's cheaper to figure out the length and do one
 * alloc than repeatedly expand the buffer when we find extra chars which need
 * to be added.
 *
 * @param in string to calculate the escaped length for.
 * @param inlen length of the input string, if 0 strlen will be used to check the length.
 * @return the size of buffer required to hold the escaped string excluding the NULL byte.
 */
size_t fr_print_string_len(char const *in, size_t inlen)
{
	uint8_t const	*p = (uint8_t const *) in;
	size_t		outlen = 0;
	int		utf8 = 0;

	if (!in) {
		return 0;
	}

	if (inlen == 0) {
		inlen = strlen(in);
	}

	while (inlen > 0) {
		/*
		 *	Hack: never print trailing zero. Some clients send pings
		 *	with an off-by-one length (confused with strings in C).
		 */
		if ((inlen == 1) && (*p == '\0')) {
			inlen--;
			break;
		}

		switch (*p) {
		case '\\':
		case '\r':
		case '\n':
		case '\t':
		case '"':
			outlen += 2;
			p++;
			inlen--;
			continue;

		default:
			break;
		}

		utf8 = fr_utf8_char(p);
		if (utf8 == 0) {
			outlen += 4;
			p++;
			inlen--;
			continue;
		}

		do {
			outlen++;
			p++;
			inlen--;
		} while (--utf8 > 0);
	}

	return outlen;
}

/** Print the value of an attribute to a string
 *
 */
size_t vp_data_prints_value(char *out, size_t outlen,
			    DICT_ATTR const *da, value_data_t const *data, size_t data_len, int8_t quote)
{
	DICT_VALUE	*v;
	char		buf[1024];	/* Interim buffer to use with poorly behaved printing functions */
	char const	*a = NULL;
	time_t		t;
	struct tm	s_tm;

	size_t		len = 0, freespace = outlen;

	if (!data) return 0;
	if (outlen == 0) return data_len;

	*out = '\0';

	switch (da->type) {
	case PW_TYPE_STRING:
		/* need to copy the escaped value, but quoted */
		if (quote > 0) {
			if (freespace < 3) {
				return data_len + 2;
			}

			*out++ = (char) quote;
			freespace--;

			len = fr_print_string(data->strvalue, data_len, out, freespace);
			/* always terminate the quoted string with another quote */
			if (len >= (freespace - 1)) {
				out[outlen - 2] = (char) quote;
				out[outlen - 1] = '\0';
				return len + 2;
			}
			out += len;
			freespace -= len;

			*out++ = (char) quote;
			freespace--;
			*out = '\0';

			return len + 2;
		}

		/* xlat.c - need to copy raw value verbatim */
		else if (quote < 0) {
			if (outlen > data_len) {
				memcpy(out, data->strvalue, data_len + 1);
				return data_len;
			}

			memcpy(out, data->strvalue, outlen);
			out[outlen - 1] = '\0';
			return data_len;	/* not a typo */
		}

		return fr_print_string(data->strvalue, data_len, out, outlen);

	case PW_TYPE_INTEGER:
	case PW_TYPE_BYTE:
	case PW_TYPE_SHORT:
		/* Normal, non-tagged attribute */
		if ((v = dict_valbyattr(da->attr, da->vendor, data->integer)) != NULL) {
			a = v->name;
			len = strlen(a);
		} else {
			/* should never be truncated */
			len = snprintf(buf, sizeof(buf), "%u", data->integer);
			a = buf;
		}
		break;

	case PW_TYPE_INTEGER64:
		return snprintf(out, outlen, "%" PRIu64, data->integer64);

	case PW_TYPE_DATE:
		t = data->date;
		if (quote > 0) {
			len = strftime(buf, sizeof(buf) - 1, "%%%b %e %Y %H:%M:%S %Z%%", localtime_r(&t, &s_tm));
			buf[0] = (char) quote;
			buf[len - 1] = (char) quote;
			buf[len] = '\0';
		} else {
			len = strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S %Z", localtime_r(&t, &s_tm));
		}
		a = buf;
		break;

	case PW_TYPE_SIGNED: /* Damned code for 1 WiMAX attribute */
		len = snprintf(buf, sizeof(buf), "%d", data->sinteger);
		a = buf;
		break;

	case PW_TYPE_IPV4_ADDR:
		a = inet_ntop(AF_INET, &(data->ipaddr), buf, sizeof(buf));
		len = strlen(buf);
		break;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		print_abinary(buf, sizeof(buf), (uint8_t const *) data->filter, len, quote);
		a = buf;
		len = strlen(buf);
		break;
#else
	/* FALL THROUGH */
#endif
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
	{
		size_t max;

		/* Return the number of bytes we would have written */
		len = (data_len * 2) + 2;
		if (freespace <= 1) {
			return len;
		}

		*out++ = '0';
		freespace--;

		if (freespace <= 1) {
			*out = '\0';
			return len;
		}
		*out++ = 'x';
		freespace--;

		if (freespace <= 2) {
			*out = '\0';
			return len;
		}

		/* Get maximum number of bytes we can encode given freespace */
		max = ((freespace % 2) ? freespace - 1 : freespace - 2) / 2;
		fr_bin2hex(out, data->octets, (data_len > max) ? max : data_len);
	}
		return len;

	case PW_TYPE_IFID:
		a = ifid_ntoa(buf, sizeof(buf), data->ifid);
		len = strlen(buf);
		break;

	case PW_TYPE_IPV6_ADDR:
		a = inet_ntop(AF_INET6, &data->ipv6addr, buf, sizeof(buf));
		len = strlen(buf);
		break;

	case PW_TYPE_IPV6_PREFIX:
	{
		struct in6_addr addr;

		/*
		 *	Alignment issues.
		 */
		memcpy(&addr, &(data->ipv6prefix[2]), sizeof(addr));

		a = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
		if (a) {
			char *p = buf;

			len = strlen(buf);
			p += len;
			len += snprintf(p, sizeof(buf) - len, "/%u", (unsigned int) data->ipv6prefix[1]);
		}
	}
		break;

	case PW_TYPE_IPV4_PREFIX:
	{
		struct in_addr addr;

		/*
		 *	Alignment issues.
		 */
		memcpy(&addr, &(data->ipv4prefix[2]), sizeof(addr));

		a = inet_ntop(AF_INET, &addr, buf, sizeof(buf));
		if (a) {
			char *p = buf;

			len = strlen(buf);
			p += len;
			len += snprintf(p, sizeof(buf) - len, "/%u", (unsigned int) (data->ipv4prefix[1] & 0x3f));
		}
	}
		break;

	case PW_TYPE_ETHERNET:
		return snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
				data->ether[0], data->ether[1],
				data->ether[2], data->ether[3],
				data->ether[4], data->ether[5]);

	default:
		a = "UNKNOWN-TYPE";
		len = strlen(a);
		break;
	}

	if (a) strlcpy(out, a, outlen);

	return len;	/* Return the number of bytes we would of written (for truncation detection) */
}

/** Print the value of an attribute to a string
 *
 * @param[out] out Where to write the string.
 * @param[in] outlen Size of outlen (must be at least 3 bytes).
 * @param[in] vp to print.
 * @param[in] quote Char to add before and after printed value, if 0 no char will be added, if < 0 raw string will be
 *	added.
 * @return the length of data written to out, or a value >= outlen on truncation.
 */
size_t vp_prints_value(char *out, size_t outlen, VALUE_PAIR const *vp, int8_t quote)
{
	VERIFY_VP(vp);

	return vp_data_prints_value(out, outlen, vp->da, &vp->data, vp->length, quote);
}

char *vp_aprint_type(TALLOC_CTX *ctx, PW_TYPE type)
{
	switch (type) {
	case PW_TYPE_STRING :
		return talloc_typed_strdup(ctx, "_");

	case PW_TYPE_INTEGER64:
	case PW_TYPE_SIGNED:
	case PW_TYPE_BYTE:
	case PW_TYPE_SHORT:
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE :
		return talloc_typed_strdup(ctx, "0");

	case PW_TYPE_IPV4_ADDR :
		return talloc_typed_strdup(ctx, "?.?.?.?");

	case PW_TYPE_IPV4_PREFIX:
		return talloc_typed_strdup(ctx, "?.?.?.?/?");

	case PW_TYPE_IPV6_ADDR:
		return talloc_typed_strdup(ctx, "[:?:]");

	case PW_TYPE_IPV6_PREFIX:
		return talloc_typed_strdup(ctx, "[:?:]/?");

	case PW_TYPE_OCTETS:
		return talloc_typed_strdup(ctx, "??");

	case PW_TYPE_ETHERNET:
		return talloc_typed_strdup(ctx, "??:??:??:??:??:??:??:??");

#ifdef WITH_ASCEND_BINARY
	case PW_TYPE_ABINARY:
		return talloc_typed_strdup(ctx, "??");
#endif

	default :
		break;
	}

	return talloc_typed_strdup(ctx, "<UNKNOWN-TYPE>");
}

/**  Prints attribute values escaped suitably for use as JSON values
 *
 *  Returns < 0 if the buffer may be (or have been) too small to write the encoded
 *  JSON value to.
 *
 * @param out Where to write the string.
 * @param outlen Lenth of output buffer.
 * @param vp to print.
 * @return the length of data written to out, or a value >= outlen on truncation.
 */
size_t vp_prints_value_json(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const	*q;
	size_t		len, freespace = outlen;

	if (!vp->da->flags.has_tag) {
		switch (vp->da->type) {
		case PW_TYPE_INTEGER:
		case PW_TYPE_BYTE:
		case PW_TYPE_SHORT:
			if (vp->da->flags.has_value) break;

			return snprintf(out, freespace, "%u", vp->vp_integer);

		case PW_TYPE_SIGNED:
			return snprintf(out, freespace, "%d", vp->vp_signed);

		default:
			break;
		}
	}

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;

	switch (vp->da->type) {
	case PW_TYPE_STRING:
		for (q = vp->vp_strvalue; q < vp->vp_strvalue + vp->length; q++) {
			/* Indicate truncation */
			if (freespace < 3) return outlen + 1;

			if (*q == '"') {
				*out++ = '\\';
				*out++ = '"';
				freespace -= 2;
			} else if (*q == '\\') {
				*out++ = '\\';
				*out++ = '\\';
				freespace -= 2;
			} else if (*q == '/') {
				*out++ = '\\';
				*out++ = '/';
				freespace -= 2;
			} else if (*q >= ' ') {
				*out++ = *q;
				freespace--;
			} else {
				*out++ = '\\';
				freespace--;

				switch (*q) {
				case '\b':
					*out++ = 'b';
					freespace--;
					break;

				case '\f':
					*out++ = 'f';
					freespace--;
					break;

				case '\n':
					*out++ = 'b';
					freespace--;
					break;

				case '\r':
					*out++ = 'r';
					freespace--;
					break;

				case '\t':
					*out++ = 't';
					freespace--;
					break;
				default:
					len = snprintf(out, freespace, "u%04X", *q);
					if (is_truncated(len, freespace)) return (outlen - freespace) + len;
					out += len;
					freespace -= len;
				}
			}
		}
		break;

	default:
		len = vp_prints_value(out, freespace, vp, 0);
		if (is_truncated(len, freespace)) return (outlen - freespace) + len;
		out += len;
		freespace -= len;
		break;
	}

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;
	*out = '\0'; // We don't increment out, because the nul byte should not be included in the length

	return outlen - freespace;
}

/*
 *  This is a hack, and has to be kept in sync with tokens.h
 */
static char const *vp_tokens[] = {
  "?",				/* T_OP_INVALID */
  "EOL",			/* T_EOL */
  "{",
  "}",
  "(",
  ")",
  ",",
  ";",
  "++",
  "+=",
  "-=",
  ":=",
  "=",
  "!=",
  ">=",
  ">",
  "<=",
  "<",
  "=~",
  "!~",
  "=*",
  "!*",
  "==",
  "#",
  "<BARE-WORD>",
  "<\"STRING\">",
  "<'STRING'>",
  "<`STRING`>"
};

extern int const fr_attr_max_tlv;
extern int const fr_attr_shift[];
extern int const fr_attr_mask[];


/** Print one attribute and value to a string
 *
 * Print a VALUE_PAIR in the format:
@verbatim
	<attribute_name>[:tag] <op> <value>
@endverbatim
 * to a string.
 *
 * @param out Where to write the string.
 * @param outlen Lenth of output buffer.
 * @param vp to print.
 * @return the length of data written to out, or a value >= outlen on truncation.
 */
size_t vp_prints(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const	*token = NULL;
	size_t		len, freespace = outlen;

	if (!out) return 0;

	*out = '\0';
	if (!vp || !vp->da) return 0;

	VERIFY_VP(vp);

	if ((vp->op > T_OP_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = vp_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if (vp->da->flags.has_tag && (vp->tag != TAG_ANY)) {
		len = snprintf(out, freespace, "%s:%d %s ", vp->da->name, vp->tag, token);
	} else {
		len = snprintf(out, freespace, "%s %s ", vp->da->name, token);
	}

	if (is_truncated(len, freespace)) return len;
	out += len;
	freespace -= len;

	len = vp_prints_value(out, freespace, vp, '\'');
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
void vp_print(FILE *fp, VALUE_PAIR const *vp)
{
	char	buf[1024];
	char	*p = buf;
	size_t	len;

	VERIFY_VP(vp);

	*p++ = '\t';
	len = vp_prints(p, sizeof(buf) - 1, vp);
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


/** Print a list of attributes and values
 *
 * @param fp to output to.
 * @param vp to print.
 */
void vp_printlist(FILE *fp, VALUE_PAIR const *vp)
{
	vp_cursor_t cursor;
	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		vp_print(fp, vp);
	}
}


/** Print one attribute value to a string
 *
 * @param ctx to allocate string in.
 * @param vp to print.
 * @param escape PW_TYPE_STRING attribute values.
 * @return a talloced buffer with the attribute operator and value.
 */
char *vp_aprint_value(TALLOC_CTX *ctx, VALUE_PAIR const *vp, bool escape)
{
	char *p;

	switch (vp->da->type) {
	case PW_TYPE_STRING:
	{
		size_t len, ret;

		if (!escape) {
			p = talloc_memdup(ctx, vp->vp_strvalue, vp->length + 1);
			if (!p) return NULL;
			talloc_set_type(p, char);
			return p;
		}

		/* Gets us the size of the buffer we need to alloc */
		len = fr_print_string_len(vp->vp_strvalue, vp->length);
		p = talloc_array(ctx, char, len + 1); 	/* +1 for '\0' */
		if (!p) return NULL;

		ret = fr_print_string(vp->vp_strvalue, vp->length, p, len + 1);
		if (!fr_assert(ret == len)) {
			talloc_free(p);
			return NULL;
		}
		break;
	}

	case PW_TYPE_BYTE:
	case PW_TYPE_SHORT:
	case PW_TYPE_INTEGER:
		{
			DICT_VALUE *dv;

			dv = dict_valbyattr(vp->da->attr, vp->da->vendor,
					    vp->vp_integer);
			if (dv) {
				p = talloc_typed_strdup(ctx, dv->name);
			} else {
				p = talloc_typed_asprintf(ctx, "%u", vp->vp_integer);
			}
		}
		break;

	case PW_TYPE_SIGNED:
		p = talloc_typed_asprintf(ctx, "%d", vp->vp_signed);
		break;

	case PW_TYPE_INTEGER64:
		p = talloc_typed_asprintf(ctx, "%" PRIu64 , vp->vp_integer64);
		break;

	case PW_TYPE_ETHERNET:
		p = talloc_typed_asprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
				    vp->vp_ether[0], vp->vp_ether[1],
				    vp->vp_ether[2], vp->vp_ether[3],
				    vp->vp_ether[4], vp->vp_ether[5]);
		break;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		p = talloc_array(ctx, char, 128);
		if (!p) return NULL;
		print_abinary(p, 128, (uint8_t *) &vp->vp_filter, vp->length, 0);
		break;
#else
		  /* FALL THROUGH */
#endif

	case PW_TYPE_OCTETS:
		p = talloc_array(ctx, char, 1 + vp->length * 2);
		if (!p) return NULL;
		fr_bin2hex(p, vp->vp_octets, vp->length);
		break;

	case PW_TYPE_DATE:
	{
		time_t t;
		struct tm s_tm;

		t = vp->vp_date;

		p = talloc_array(ctx, char, 64);
		strftime(p, 64, "%b %e %Y %H:%M:%S %Z",
			 localtime_r(&t, &s_tm));
		break;
	}

	/*
	 *	We need to use the proper inet_ntop functions for IP
	 *	addresses, else the output might not match output of
	 *	other functions, which makes testing difficult.
	 *
	 *	An example is tunnelled ipv4 in ipv6 addresses.
	 */
	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_IPV4_PREFIX:
		{
			char buff[INET_ADDRSTRLEN  + 4]; // + /prefix

			buff[0] = '\0';
			vp_prints_value(buff, sizeof(buff), vp, 0);

			p = talloc_typed_strdup(ctx, buff);
		}
		break;

	case PW_TYPE_IPV6_ADDR:
	case PW_TYPE_IPV6_PREFIX:
		{
			char buff[INET6_ADDRSTRLEN + 4]; // + /prefix

			buff[0] = '\0';
			vp_prints_value(buff, sizeof(buff), vp, 0);

			p = talloc_typed_strdup(ctx, buff);
		}
		break;

	case PW_TYPE_IFID:
		p = talloc_typed_asprintf(ctx, "%x:%x:%x:%x",
				    (vp->vp_ifid[0] << 8) | vp->vp_ifid[1],
				    (vp->vp_ifid[2] << 8) | vp->vp_ifid[3],
				    (vp->vp_ifid[4] << 8) | vp->vp_ifid[5],
				    (vp->vp_ifid[6] << 8) | vp->vp_ifid[7]);
		break;

	default:
		p = NULL;
		break;
	}

	return p;
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
 * @param escape PW_TYPE_STRING attribute values.
 * @return a talloced buffer with the attribute operator and value.
 */
char *vp_aprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, bool escape)
{
	char const	*token = NULL;
	char 		*pair, *value;

	if (!vp || !vp->da) return 0;

	VERIFY_VP(vp);

	if ((vp->op > T_OP_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = vp_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	value = vp_aprint_value(ctx, vp, escape);
	pair = vp->da->flags.has_tag ?
	       talloc_asprintf(ctx, "%s:%d %s %s", vp->da->name, vp->tag, token, value) :
	       talloc_asprintf(ctx, "%s %s %s", vp->da->name, token, value);
	talloc_free(value);

	return pair;
}


