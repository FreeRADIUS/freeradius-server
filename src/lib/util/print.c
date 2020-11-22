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

/** Functions to produce and parse the FreeRADIUS presentation format
 *
 * @file src/lib/util/print.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>

#include <ctype.h>
#include <string.h>
#include <talloc.h>

/** Checks for utf-8, taken from http://www.w3.org/International/questions/qa-forms-utf-8
 *
 * @param[in] str	input string.
 * @param[in] inlen	length of input string.  May be -1 if str
 *			is \0 terminated.
 * @return
 *	- 0 if the character is invalid.
 *	- >0 the number of bytes the character consists of.
 */
inline size_t fr_utf8_char(uint8_t const *str, ssize_t inlen)
{
	if (inlen == 0) return 0;

	if (inlen < 0) inlen = 4;	/* longest char */

	if (*str < 0x20) return 0;

	if (*str <= 0x7e) return 1;	/* 1 */

	if (*str <= 0xc1) return 0;

	if (inlen < 2) return 0;

	if ((str[0] >= 0xc2) &&		/* 2 */
	    (str[0] <= 0xdf) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf)) {
		return 2;
	}

	if (inlen < 3) return 0;

	if ((str[0] == 0xe0) &&		/* 3 */
	    (str[1] >= 0xa0) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xe1) &&		/* 4a */
	    (str[0] <= 0xec) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xee) &&		/* 4b */
	    (str[0] <= 0xef) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] == 0xed) &&		/* 5 */
	    (str[1] >= 0x80) &&
	    (str[1] <= 0x9f) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if (inlen < 4) return 0;

	if ((str[0] == 0xf0) &&		/* 6 */
	    (str[1] >= 0x90) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}

	if ((str[0] >= 0xf1) &&		/* 6 */
	    (str[0] <= 0xf3) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}


	if ((str[0] == 0xf4) &&		/* 7 */
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

/** Validate a complete UTF8 string
 *
 * @param[in] str	input string.
 * @param[in] inlen	length of input string.  May be -1 if str
 *			is \0 terminated.
 * @return The number of bytes validated.  If ret == inlen the entire
 *	   string is valid.  Else ret gives the offset at which the
 *	   first invalid byte sequence was found.
 */
ssize_t fr_utf8_str(uint8_t const *str, ssize_t inlen)
{
	uint8_t const *p, *end;
	size_t len;

	len = inlen < 0 ? strlen((char const *)str) : (size_t) inlen;

	p = str;
	end = p + len;

	do {
		size_t clen;

		clen = fr_utf8_char(p, end - p);
		if (clen == 0) return end - p;
		p += clen;
	} while (p < end);

	return inlen;
}

/** Return a pointer to the first UTF8 char in a string.
 *
 * @param[out] out_chr_len	Where to write the length of the multibyte char passed in chr (may be NULL).
 * @param[in] str		Haystack.
 * @param[in] inlen		Length of string (in bytes).  Pass -1 to determine the length of the string.
 * @param[in] chr		Multibyte needle.
 * @return
 *	- Position of chr in str.
 *	- NULL if not found.
 */
char const *fr_utf8_strchr(int *out_chr_len, char const *str, ssize_t inlen, char const *chr)
{
	char const	*p = str, *end;
	int		needle_len;

	if (inlen < 0) inlen = strlen(str);

	end = str + inlen;

	/*
	 *	Figure out how big the multibyte sequence
	 *	we're looking for is.
	 */
	needle_len = fr_utf8_char((uint8_t const *)chr, -1);
	if (needle_len == 0) needle_len = 1;	/* Invalid UTF8 sequence - ignore - needle is one byte */
	if (out_chr_len) *out_chr_len = needle_len;

	/*
	 *	Loop over the input sequence, advancing
	 *      UTF8 sequence by utf8 seqnce.
	 */
	while (p < end) {
		int schr_len;

		schr_len = fr_utf8_char((uint8_t const *)p, end - p);
		if (schr_len == 0) schr_len = 1;	/* Invalid UTF8 sequence - ignore - advance by 1 */
		if (schr_len != needle_len) goto next;

		/*
		 *	See if this matches out multibyte needle
		 */
		if (memcmp(p, chr, schr_len) == 0) return p;
	next:
		p += schr_len;
	}

	return NULL;
}

/** Escape any non printable or non-UTF8 characters in the input string
 *
 * @note Return value should be checked with is_truncated
 * @note Will always \0 terminate unless outlen == 0.
 *
 * @param[out] out	where to write the escaped string.
 * @param[out] outlen	the length of the buffer pointed to by out.
 * @param[in] in	string to escape.
 * @param[in] inlen	length of string to escape (lets us deal with embedded NULs)
 * @param[in] quote	the quotation character
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t fr_snprint(char *out, size_t outlen, char const *in, ssize_t inlen, char quote)
{
	uint8_t const	*p = (uint8_t const *) in;
	size_t		utf8;
	size_t		used;
	size_t		freespace;

	/* No input, so no output... */
	if (!in) {
		if (out && outlen) *out = '\0';
		return 0;
	}

	/* Figure out the length of the input string */
	if (inlen < 0) inlen = strlen(in);

	/*
	 *	No quotation character, just use memcpy, ensuring we
	 *	don't overflow the output buffer.
	 */
	if (!quote) {
		if (!out) return inlen;

		if ((size_t)inlen >= outlen) {
			memcpy(out, in, outlen - 1);
			out[outlen - 1] = '\0';
		} else {
			memcpy(out, in, inlen);
			out[inlen] = '\0';
		}

		return inlen;
	}

	/*
	 *	Check the output buffer and length.  Zero both of them
	 *	out if either are zero.
	 */
	freespace = outlen;
	if (freespace == 0) out = NULL;
	if (!out) freespace = 0;

	used = 0;

	while (inlen > 0) {
		int sp = 0;

		/*
		 *	Always escape the quotation character.
		 */
		if (*p == quote) {
			sp = quote;
			goto do_escape;
		}

		/*
		 *	Escape the backslash ONLY for single quoted strings.
		 */
		if (quote == '\'') {
			if (*p == '\\') {
				sp = '\\';
			}
			goto do_escape;
		}

		/*
		 *	Try to convert 0x0a --> \r, etc.
		 *	Backslashes get handled specially.
		 */
		switch (*p) {
		case '\r':
			sp = 'r';
			break;

		case '\n':
			sp = 'n';
			break;

		case '\t':
			sp = 't';
			break;

		case '\\':
			sp = '\\';
			break;

		default:
			sp = '\0';
			break;
		} /* escape the character at *p */

	do_escape:
		if (sp) {
			if ((freespace > 0) && (freespace <= 2)) {
				if (out) out[used] = '\0';
				out = NULL;
				freespace = 0;

			} else if (freespace > 2) { /* room for char AND trailing zero */
				if (out) {
					out[used] = '\\';
					out[used + 1] = sp;
				}
				freespace -= 2;
			}

			used += 2;
			p++;
			inlen--;
			continue;
		}

		/*
		 *	All strings are UTF-8 clean.
		 */
		utf8 = fr_utf8_char(p, inlen);

		/*
		 *	If we have an invalid UTF-8 character, it gets
		 *	copied over as a 1-byte character for single
		 *	quoted strings.  Which means that the output
		 *	isn't strictly UTF-8, but oh well...
		 *
		 *	For double quoted strints, the invalid
		 *	characters get escaped as octal encodings.
		 */
		if (utf8 == 0) {
			if (quote == '\'') {
				utf8 = 1;

			} else {
				if ((freespace > 0) && (freespace <= 4)) {
					if (out) out[used] = '\0';
					out = NULL;
					freespace = 0;

				} else if (freespace > 4) { /* room for char AND trailing zero */
					if (out) snprintf(out + used, freespace, "\\%03o", *p);
					freespace -= 4;
				}

				used += 4;
				p++;
				inlen--;
				continue;
			}
		}

		if ((freespace > 0) && (freespace <= utf8)) {
			if (out) out[used] = '\0';
			out = NULL;
			freespace = 0;

		} else if (freespace > utf8) { /* room for char AND trailing zero */
			if (out) memcpy(out + used, p, utf8);
			freespace -= utf8;
		}

		used += utf8;
		p += utf8;
		inlen -= utf8;
	}

	/*
	 *	Ensure that the output buffer is always zero terminated.
	 */
	if (out && freespace) out[used] = '\0';

	return used;
}

/** Find the length of the buffer required to fully escape a string with fr_prints
 *
 * Were assuming here that's it's cheaper to figure out the length and do one
 * alloc than repeatedly expand the buffer when we find extra chars which need
 * to be added.
 *
 * @param in string to calculate the escaped length for.
 * @param inlen length of the input string, if < 0 strlen will be used to check the length.
 * @param[in] quote the quotation character.
 * @return the size of buffer required to hold the escaped string including the NUL byte.
 */
size_t fr_snprint_len(char const *in, ssize_t inlen, char quote)
{
	return fr_snprint(NULL, 0, in, inlen, quote) + 1;
}

/** Escape string that may contain binary data, and write it to a new buffer
 *
 * This is useful in situations where we expect printable strings as input,
 * but under some conditions may get binary data. A good example is libldap
 * and the arrays of struct berval ldap_get_values_len returns.
 *
 * @param[in] ctx	To allocate new buffer in.
 * @param[in] in	String to escape.
 * @param[in] inlen	Length of string. Should be >= 0 if the data may contain
 *			embedded \0s. Must be >= 0 if data may not be \0 terminated.
 *			If < 0 inlen will be calculated using strlen.
 * @param[in] quote	the quotation character.
 * @return new		buffer holding the escaped string.
 */
char *fr_asprint(TALLOC_CTX *ctx, char const *in, ssize_t inlen, char quote)
{
	size_t len, ret;
	char *out;

	len = fr_snprint_len(in, inlen, quote);

	out = talloc_array(ctx, char, len);
	ret = fr_snprint(out, len, in, inlen, quote);
	/*
	 *	This is a fatal error, but fr_cond_assert is the strongest
	 *	assert we're allowed to use in library functions.
	 */
	if (!fr_cond_assert(ret == (len - 1))) {
		talloc_free(out);
		return NULL;
	}

	return out;
}

DIAG_OFF(format-nonliteral)
/** Special version of vasprintf which implements custom format specifiers
 *
 * @todo Do something sensible with 'n$', though it's probably not actually used
 *	anywhere in our code base.
 *
 * - %pV prints a value box as a string.
 * - %pM prints a list of value boxes, concatenating them.
 * - %pH prints a value box as a hex string.
 * - %pP prints a fr_pair_t.
 *
 * This breaks strict compatibility with printf but allows us to continue using
 * the static format string and argument type validation.
 *
 * This same idea is used in Linux for the printk function.
 *
 * @param[in] ctx	to allocate buffer in.
 * @param[in] fmt	string.
 * @param[in] ap	variadic argument list.
 * @return
 *	- The result of string interpolation.
 *	- NULL if OOM.
 */
char *fr_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap)
{
	char const	*p = fmt, *end = p + strlen(fmt), *fmt_p = p, *fmt_q = p;
	char		*out = NULL, *out_tmp;
	va_list		ap_p, ap_q;

	out = talloc_strdup(ctx, "");
	va_copy(ap_p, ap);
	va_copy(ap_q, ap_p);

	do {
		char const	*q;
		char		len[2] = { '\0', '\0' };
		char		*subst = NULL;

		if ((*p != '%') || (*++p == '%')) {
			fmt_q = p + 1;
			continue;	/* literal char */
		}

		/*
		 *	Check for parameter field
		 */
		for (q = p; isdigit(*q); q++);
		if ((q != p) && (*q == '$')) {
			p = q + 1;
		}

		/*
		 *	Check for flags
		 */
		do {
			switch (*p) {
			case '-':
				continue;

			case '+':
				continue;

			case ' ':
				continue;

			case '0':
				continue;

			case '#':
				continue;

			default:
				goto done_flags;
			}
		} while (++p < end);
	done_flags:

		/*
		 *	Check for width field.  First for strings, and
		 *	then for other parameters.
		 */
		if ((*p == '.') && (*(p + 1) == '*') && (*(p + 2) == 's')) {
			(void) va_arg(ap_q, int);
			p += 2;
		} else if (*p == '*') {
			(void) va_arg(ap_q, int);
			p++;
		} else {
			for (q = p; isdigit(*q); q++);
			p = q;
		}

		/*
		 *	Check for precision field
		 */
		if (*p == '.') {
			char *r;

			p++;
			(void) strtoul(p, &r, 10);
			p = r;
		}

		/*
		 *	Length modifiers
		 */
		switch (*p) {
		case 'h':
		case 'l':
			len[0] = *p++;
			if ((*p == 'h') || (*p == 'l')) len[1] = *p++;
			break;

		case 'L':
		case 'z':
		case 'j':
		case 't':
			len[0] = *p++;
			break;
		}

		/*
		 *	Types
		 */
		switch (*p) {
		case 'i':								/* int */
		case 'd':								/* int */
		case 'u':								/* unsigned int */
		case 'x':								/* unsigned int */
		case 'X':								/* unsigned int */
		case 'o':								/* unsigned int */
			switch (len[0]) {
			case 'h':
				if (len[1] == 'h') {					/* char (promoted to int) */
					(void) va_arg(ap_q, int);
				} else {
					(void) va_arg(ap_q, int);			/* short (promoted to int) */
				}
				break;

			case 'l':
				if ((*p == 'i') || (*p == 'd')) {
					if (len[1] == 'l') {
						(void) va_arg(ap_q, long);		/* long */
					} else {
						(void) va_arg(ap_q, long long);		/* long long */
					}
				} else {
					if (len[1] == 'l') {
						(void) va_arg(ap_q, unsigned long);	/* unsigned long */
					} else {
						(void) va_arg(ap_q, unsigned long long);/* unsigned long long */
					}
				}
				break;

			case 'z':
				(void) va_arg(ap_q, size_t);				/* size_t */
				break;

			case 'j':
				(void) va_arg(ap_q, intmax_t);				/* intmax_t */
				break;

			case 't':
				(void) va_arg(ap_q, ptrdiff_t);				/* ptrdiff_t */
				break;

			case '\0':	/* no length modifier */
				if ((*p == 'i') || (*p == 'd')) {
					(void) va_arg(ap_q, int);			/* int */
				} else {
					(void) va_arg(ap_q, unsigned int);		/* unsigned int */
				}
			}
			break;

		case 'f':								/* double */
		case 'F':								/* double */
		case 'e':								/* double */
		case 'E':								/* double */
		case 'g':								/* double */
		case 'G':								/* double */
		case 'a':								/* double */
		case 'A':								/* double */
			switch (len[0]) {
			case 'L':
				(void) va_arg(ap_q, long double);			/* long double */
				break;

			case 'l':	/* does nothing */
			default:	/* no length modifier */
				(void) va_arg(ap_q, double);				/* double */
			}
			break;

		case 's':
			(void) va_arg(ap_q, char *);					/* char * */
			break;

		case 'c':
			(void) va_arg(ap_q, int);					/* char (promoted to int) */
			break;

		case 'p':
			/*
			 *	subst types
			 */
			switch (*(p + 1)) {
			case 'V':
			case 'R':
			{
				fr_value_box_t const *in = va_arg(ap_q, fr_value_box_t const *);
				fr_sbuff_escape_rules_t const *e_rules = NULL;

				if (*(p + 1) == 'V') e_rules = &fr_value_escape_double;

				/*
				 *	Allocations that are not part of the output
				 *	string need to occur in the NULL ctx so we don't fragment
				 *	any pool associated with it.
				 */
				if (in) {
					fr_value_box_aprint(NULL, &subst, in, e_rules);
					if (!subst) {
						talloc_free(out);
						va_end(ap_p);
						va_end(ap_q);
						return NULL;
					}
				} else {
					subst = talloc_typed_strdup(NULL, "(null)");
				}

			do_splice:
				p++;

				/*
				 *	Pass part of a format string to printf
				 */
				if (fmt_q != fmt_p) {
					char *sub_fmt;

					sub_fmt = talloc_strndup(NULL, fmt_p, fmt_q - fmt_p);
					out_tmp = talloc_vasprintf_append_buffer(out, sub_fmt, ap_p);
					talloc_free(sub_fmt);
					if (!out_tmp) {
					oom:
						fr_strerror_printf("Out of memory");
						talloc_free(out);
						talloc_free(subst);
						va_end(ap_p);
						va_end(ap_q);
						return NULL;
					}
					out = out_tmp;

					out_tmp = talloc_strdup_append_buffer(out, subst);
					TALLOC_FREE(subst);
					if (!out_tmp) goto oom;
					out = out_tmp;

					va_end(ap_p);		/* one time use only */
				} else {
					out_tmp = talloc_strdup_append_buffer(out, subst);
					TALLOC_FREE(subst);
					if (!out_tmp) goto oom;
					out = out_tmp;
				}

				va_copy(ap_p, ap_q);	/* already advanced to the next argument */

				fmt_p = p + 1;
			}
				break;

			case 'H':
			{
				fr_value_box_t const *in = va_arg(ap_q, fr_value_box_t const *);

				if (!in) {
					subst = talloc_strdup(NULL, "(null)");
					if (!subst) goto oom;

					goto do_splice;
				}

				switch (in->type) {
				case FR_TYPE_OCTETS:
					if (in->vb_octets) {
						fr_abin2hex(NULL, &subst, &FR_DBUFF_TMP(in->vb_octets, in->vb_length));
					} else {
						subst = talloc_strdup(NULL, "");
					}
					break;

				case FR_TYPE_STRING:
					fr_abin2hex(NULL, &subst, &FR_DBUFF_TMP((uint8_t const *)in->vb_strvalue, in->vb_length));
					break;

				default:
				{
					fr_value_box_t dst;

					/*
					 *	Convert the boxed value into a octets buffer
					 */
					if (fr_value_box_cast(NULL, &dst, FR_TYPE_OCTETS, NULL, in) < 0) {
						subst = talloc_strdup(NULL, fr_strerror()); /* splice in the error */
						if (!subst) goto oom;
					}

					fr_abin2hex(NULL, &subst, &FR_DBUFF_TMP((uint8_t const *)dst.vb_octets, dst.vb_length));
					fr_value_box_clear(&dst);
					break;
				}
				}
			}
				goto do_splice;

			case 'M':
			{
				fr_value_box_t const *in = va_arg(ap_q, fr_value_box_t const *);

				if (!in) {
					subst = talloc_strdup(NULL, "(null)");
					goto do_splice;
				}

				subst = fr_value_box_list_aprint(NULL, in, NULL, &fr_value_escape_double);
			}
				goto do_splice;

			case 'P':
			{
				fr_pair_t const *in = va_arg(ap_q, fr_pair_t const *);

				if (!in) {
					subst = talloc_strdup(NULL, "(null)");
					goto do_splice;
				}

				VP_VERIFY(in);
				fr_pair_aprint(NULL, &subst, NULL, in);
			}
				goto do_splice;

			default:
				(void) va_arg(ap_q, void *);				/* void * */
			}
			break;

		case 'n':
			(void) va_arg(ap_q, int *);					/* int * */
			break;

		default:
			break;
		}
		fmt_q = p + 1;
	} while (++p < end);

	/*
	 *	Print out the rest of the format string.
	 */
	if (*fmt_p) {
		out_tmp = talloc_vasprintf_append_buffer(out, fmt_p, ap_p);
		if (!out_tmp) goto oom;
		out = out_tmp;
	}

	va_end(ap_p);
	va_end(ap_q);

	/*
	 *	One of the above talloc calls sets the type to
	 *	be the string.  We correct this here so we
	 *	don't trigger talloc_aborts later...
	 */
	talloc_set_type(out, char);

	return out;
}
DIAG_ON(format-nonliteral)

/** Special version of asprintf which implements custom format specifiers
 *
 * @copybrief fr_vasprintf
 *
 * @param[in] ctx	to allocate buffer in.
 * @param[in] fmt	string.
 * @param[in] ...	variadic argument list.
 * @return
 *	- The result of string interpolation.
 */
char *fr_asprintf(TALLOC_CTX *ctx, char const *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = fr_vasprintf(ctx, fmt, ap);
	va_end(ap);

	return ret;
}

/** Special version of fprintf which implements custom format specifiers
 *
 * @copybrief fr_vasprintf
 *
 * @param[in] fp	to write the result of fmt string.
 * @param[in] fmt	string.
 * @param[in] ...	variadic argument list.
 * @return
 *   - On success, the number of bytes written is returned (zero indicates nothing was written).
 *   - On error, -1 is returned, and errno is set appropriately
 */
ssize_t fr_fprintf(FILE *fp, char const *fmt, ...)
{
	va_list ap;
	char *buf;
	int ret;

	if (!fp) {
		fr_strerror_printf("Invalid 'fp'");
		return -1;
	}

	va_start(ap, fmt);
	buf = fr_vasprintf(NULL, fmt, ap);
	va_end(ap);

	ret = fputs(buf, fp);

	TALLOC_FREE(buf);

	return ret;
}
