/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/ldap/util.c
 * @brief Utility functions to escape and parse DNs
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2017 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/hex.h>

#include <stdarg.h>
#include <ctype.h>

static const char specials[] = ",+\"\\<>;*=()";
static const char hextab[] = "0123456789abcdef";

/** Converts "bad" strings into ones which are safe for LDAP
 *
 * @note RFC 4515 says filter strings can only use the @verbatim \<hex><hex> @endverbatim
 *	format, whereas RFC 4514 indicates that some chars in DNs, may be escaped simply
 *	with a backslash. For simplicity, we always use the hex escape sequences.
 *	In other areas where we're doing DN comparison, the DNs need to be normalised first
 *	so that they both use only hex escape sequences.
 *
 * @note This is a callback for xlat operations.
 *
 * Will escape any characters in input strings that would cause the string to be interpreted
 * as part of a DN and or filter. Escape sequence is @verbatim \<hex><hex> @endverbatim.
 *
 * @param request The current request.
 * @param out Pointer to output buffer.
 * @param outlen Size of the output buffer.
 * @param in Raw unescaped string.
 * @param arg Any additional arguments (unused).
 */
size_t fr_ldap_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{

	size_t left = outlen;

	if (*in && ((*in == ' ') || (*in == '#'))) goto encode;

	while (*in) {
		/*
		 *	Encode unsafe characters.
		 */
		if (memchr(specials, *in, sizeof(specials) - 1)) {
		encode:
			/*
			 *	Only 3 or less bytes available.
			 */
			if (left <= 3) break;

			*out++ = '\\';
			*out++ = hextab[(*in >> 4) & 0x0f];
			*out++ = hextab[*in & 0x0f];
			in++;
			left -= 3;

			continue;
		}

		if (left <= 1) break;

		/*
		 *	Doesn't need encoding
		 */
		*out++ = *in++;
		left--;
	}

	*out = '\0';

	return outlen - left;
}

/** Converts escaped DNs and filter strings into normal
 *
 * @note RFC 4515 says filter strings can only use the @verbatim \<hex><hex> @endverbatim
 *	format, whereas RFC 4514 indicates that some chars in DNs, may be escaped simply
 *	with a backslash..
 *
 * Will unescape any special characters in strings, or @verbatim \<hex><hex> @endverbatim
 * sequences.
 *
 * @param request The current request.
 * @param out Pointer to output buffer.
 * @param outlen Size of the output buffer.
 * @param in Escaped string string.
 * @param arg Any additional arguments (unused).
 */
size_t fr_ldap_unescape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char const *p;
	char *c1, *c2, c3;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = in;
	while (*p && (--freespace > 0)) {
		if (*p != '\\') {
		next:
			*out++ = *p++;
			continue;
		}

		p++;

		/* It's an escaped special, just remove the slash */
		if (memchr(specials, *in, sizeof(specials) - 1)) {
			*out++ = *p++;
			continue;
		}

		/* Is a hex sequence */
		if (!(c1 = memchr(hextab, tolower(p[0]), 16)) ||
		    !(c2 = memchr(hextab, tolower(p[1]), 16))) goto next;
		c3 = ((c1 - hextab) << 4) + (c2 - hextab);

		*out++ = c3;
		p += 2;
	}

	*out = '\0';

	return outlen - freespace;
}


/** Check whether a string looks like a DN
 *
 * @param[in] in Str to check.
 * @param[in] inlen Length of string to check.
 * @return
 *	- true if string looks like a DN.
 *	- false if string does not look like DN.
 */
bool fr_ldap_util_is_dn(char const *in, size_t inlen)
{
	char const *p;

	char want = '=';
	bool too_soon = true;
	int comp = 1;

	for (p = in; inlen > 0; p++, inlen--) {
		if (p[0] == '\\') {
			char c;

			too_soon = false;

			/*
			 *	Invalid escape sequence, not a DN
			 */
			if (inlen < 2) return false;

			/*
			 *	Double backslash, consume two chars
			 */
			if (p[1] == '\\') {
				inlen--;
				p++;
				continue;
			}

			/*
			 *	Special, consume two chars
			 */
			switch (p[1]) {
			case ' ':
			case '#':
			case '=':
			case '"':
			case '+':
			case ',':
			case ';':
			case '<':
			case '>':
			case '\'':
				inlen -= 1;
				p += 1;
				continue;

			default:
				break;
			}

			/*
			 *	Invalid escape sequence, not a DN
			 */
			if (inlen < 3) return false;

			/*
			 *	Hex encoding, consume three chars
			 */
			if (fr_hex2bin(&FR_DBUFF_TMP((uint8_t *) &c, 1), &FR_SBUFF_IN(p + 1, 2)) == 1) {
				inlen -= 2;
				p += 2;
				continue;
			}

			/*
			 *	Invalid escape sequence, not a DN
			 */
			return false;
		}

		switch (*p) {
		case '=':
			if (too_soon || (*p != want)) return false;	/* Too soon after last , or = */
			want = ',';
			too_soon = true;
			break;

		case ',':
			if (too_soon || (*p != want)) return false;	/* Too soon after last , or = */
			want = '=';
			too_soon = true;
			comp++;
			break;

		default:
			too_soon = false;
			break;
		}
	}

	/*
	 *	If the string ended with , or =, or the number
	 *	of components was less than 2
	 *
	 *	i.e. we don't have <attr>=<val>,<attr>=<val>
	 */
	if (too_soon || (comp < 2)) return false;

	return true;
}

/** Parse a subset (just server side sort for now) of LDAP URL extensions
 *
 * @param[out] sss		Where to write a pointer to the server side sort control
 *				we created.
 * @param[in] request		The current request.
 * @param[in] conn		Handle to allocate controls under.
 * @param[in] extensions	A NULL terminated array of extensions.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_parse_url_extensions(LDAPControl **sss, REQUEST *request, fr_ldap_connection_t *conn, char **extensions)
{
	int i;

	*sss = NULL;

	if (!extensions) return 0;

	/*
	 *	Parse extensions in the LDAP URL
	 */
	for (i = 0; extensions[i]; i++) {
		char *p;
		bool is_critical = false;

		p = extensions[i];
		if (*p == '!') {
			is_critical = true;
			p++;
		}

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
		/*
		 *	Server side sort control
		 */
		if (strncmp(p, "sss", 3) == 0) {
			LDAPSortKey	**keys;
			int		ret;

			p += 3;
			p = strchr(p, '=');
			if (!p) {
				REDEBUG("Server side sort extension must be in the format \"[!]sss=<key>[,key]\"");
				return -1;
			}
			p++;

			ret = ldap_create_sort_keylist(&keys, p);
			if (ret != LDAP_SUCCESS) {
				REDEBUG("Invalid server side sort value \"%s\": %s", p, ldap_err2string(ret));
				return -1;
			}

			if (*sss) ldap_control_free(*sss);

			ret = ldap_create_sort_control(conn->handle, keys, is_critical ? 1 : 0, sss);
			ldap_free_sort_keylist(keys);
			if (ret != LDAP_SUCCESS) {
				ERROR("Failed creating server sort control: %s", ldap_err2string(ret));
				return -1;
			}

			continue;
		}
#endif

		RWDEBUG("URL extension \"%s\" ignored", p);
	}

	return 0;
}

/** Convert a berval to a talloced string
 *
 * The ldap_get_values function is deprecated, and ldap_get_values_len
 * does not guarantee the berval buffers it returns are \0 terminated.
 *
 * For some cases this is fine, for others we require a \0 terminated
 * buffer (feeding DNs back into libldap for example).
 *
 * @param ctx to allocate in.
 * @param in Berval to copy.
 * @return \0 terminated buffer containing in->bv_val.
 */
char *fr_ldap_berval_to_string(TALLOC_CTX *ctx, struct berval const *in)
{
	char *out;

	out = talloc_array(ctx, char, in->bv_len + 1);
	if (!out) return NULL;

	memcpy(out, in->bv_val, in->bv_len);
	out[in->bv_len] = '\0';

	return out;
}

/** Convert a berval to a talloced buffer
 *
 * @param ctx to allocate in.
 * @param in Berval to copy.
 * @return buffer containing in->bv_val.
 */
uint8_t *fr_ldap_berval_to_bin(TALLOC_CTX *ctx, struct berval const *in)
{
	uint8_t *out;

	out = talloc_array(ctx, uint8_t, in->bv_len + 1);
	if (!out) return NULL;

	memcpy(out, in->bv_val, in->bv_len);

	return out;
}

/** Normalise escape sequences in a DN
 *
 * Characters in a DN can either be escaped as
 * @verbatim \<hex><hex> @endverbatim or @verbatim \<special> @endverbatim
 *
 * The LDAP directory chooses how characters are escaped, which can make
 * local comparisons of DNs difficult.
 *
 * Here we search for hex sequences that match special chars, and convert
 * them to the @verbatim \<special> @endverbatim form.
 *
 * @note the resulting output string will only ever be shorter than the
 *       input, so it's fine to use the same buffer for both out and in.
 *
 * @param out Where to write the normalised DN.
 * @param in The input DN.
 * @return The number of bytes written to out.
 */
size_t fr_ldap_util_normalise_dn(char *out, char const *in)
{
	char const *p;
	char *o = out;

	for (p = in; *p != '\0'; p++) {
		if (p[0] == '\\') {
			char c;

			/*
			 *	Double backslashes get processed specially
			 */
			if (p[1] == '\\') {
				p += 1;
				*o++ = p[0];
				*o++ = p[1];
				continue;
			}

			/*
			 *	Hex encodings that have an alternative
			 *	special encoding, get rewritten to the
			 *	special encoding.
			 */
			if (fr_hex2bin(&FR_DBUFF_TMP((uint8_t *) &c, 1), &FR_SBUFF_IN(p + 1, 2)) == 1) {
				switch (c) {
				case ' ':
				case '#':
				case '=':
				case '"':
				case '+':
				case ',':
				case ';':
				case '<':
				case '>':
				case '\'':
					*o++ = '\\';
					*o++ = c;
					p += 2;
					continue;

				default:
					break;
				}
			}
		}
		*o++ = *p;
	}
	*o = '\0';

	return o - out;
}

/** Find the place at which the two DN strings diverge
 *
 * Returns the length of the non matching string in full.
 *
 * @param full DN.
 * @param part Partial DN as returned by ldap_parse_result.
 * @return
 *	- Length of the portion of full which wasn't matched
 *	- -1 on failure.
 */
size_t fr_ldap_common_dn(char const *full, char const *part)
{
	size_t f_len, p_len, i;

	if (!full) return -1;

	f_len = strlen(full);

	if (!part) return -1;

	p_len = strlen(part);
	if (!p_len) return f_len;

	if ((f_len < p_len) || !f_len) return -1;

	for (i = 0; i < p_len; i++) if (part[p_len - i] != full[f_len - i]) return -1;

	return f_len - p_len;
}

/** Combine and expand filters
 *
 * @param request Current request.
 * @param out Where to write the expanded string.
 * @param outlen Length of output buffer.
 * @param sub Array of subfilters (may contain NULLs).
 * @param sublen Number of potential subfilters in array.
 * @return length of expanded data.
 */
ssize_t fr_ldap_xlat_filter(REQUEST *request, char const **sub, size_t sublen, char *out, size_t outlen)
{
	char buffer[LDAP_MAX_FILTER_STR_LEN + 1];
	char const *in = NULL;
	char *p = buffer;

	ssize_t len = 0;

	unsigned int i;
	int cnt = 0;

	/*
	 *	Figure out how many filter elements we need to integrate
	 */
	for (i = 0; i < sublen; i++) {
		if (sub[i] && *sub[i]) {
			in = sub[i];
			cnt++;
		}
	}

	if (!cnt) {
		out[0] = '\0';
		return 0;
	}

	if (cnt > 1) {
		if (outlen < 3) {
			goto oob;
		}

		p[len++] = '(';
		p[len++] = '&';

		for (i = 0; i < sublen; i++) {
			if (sub[i] && (*sub[i] != '\0')) {
				len += strlcpy(p + len, sub[i], outlen - len);

				if ((size_t) len >= outlen) {
					oob:
					REDEBUG("Out of buffer space creating filter");

					return -1;
				}
			}
		}

		if ((outlen - len) < 2) {
			goto oob;
		}

		p[len++] = ')';
		p[len] = '\0';

		in = buffer;
	}

	len = xlat_eval(out, outlen, request, in, fr_ldap_escape_func, NULL);
	if (len < 0) {
		REDEBUG("Failed creating filter");

		return -1;
	}

	return len;
}
