/*
 *   This program is free software; you can redistribute it and/or modify
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
#include <freeradius-devel/util/base16.h>

#include <freeradius-devel/util/value.h>

#include <stdarg.h>

/* RFC 4514 DN attribute value special characters */
static const char dn_specials[] = ",+\"\\<>;*=()";
static const char hextab[] = "0123456789abcdef";
static const bool escapes[SBUFF_CHAR_CLASS] = {
	[' '] = true,
	['#'] = true,
	['='] = true,
	['"'] = true,
	['+'] = true,
	[','] = true,
	[';'] = true,
	['<'] = true,
	['>'] = true,
	['\''] = true
};

/* RFC 4515 filter assertion value special characters */
static const char filter_specials[] = "*()\\";
;

/** Escape a string for use as an RFC 4514 DN attribute value
 *
 * Escapes characters that have special meaning in DNs.  Leading space and
 * '#' are also escaped as required by RFC 4514.
 * Escape sequence is @verbatim \<hex><hex> @endverbatim.
 *
 * @param request The current request.
 * @param out Pointer to output buffer.
 * @param outlen Size of the output buffer.
 * @param in Raw unescaped string.
 * @param arg Any additional arguments (unused).
 */
size_t fr_ldap_dn_escape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	size_t left = outlen;

	if ((*in == ' ') || (*in == '#')) goto encode;

	while (*in) {
		/*
		 *	Encode unsafe characters.
		 */
		if (memchr(dn_specials, *in, sizeof(dn_specials) - 1)) {
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

int fr_ldap_dn_box_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	size_t			len;

	fr_assert(!fr_value_box_is_safe_for(vb, fr_ldap_dn_box_escape));

	if ((vb->type != FR_TYPE_STRING) && (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0)) {
		return -1;
	}

	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->vb_length * 3, vb->vb_length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped DN");
		return -1;
	}

	len = fr_ldap_dn_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, NULL);

	/*
	 *	If the returned length is unchanged, the value was already safe
	 */
	if (len == vb->vb_length) {
		talloc_free(fr_sbuff_buff(&sbuff));
	} else {
		fr_sbuff_trim_talloc(&sbuff, len);
		fr_value_box_strdup_shallow_replace(vb, fr_sbuff_buff(&sbuff), len);
	}

	return 0;
}

/** Escape a string for use as an RFC 4515 filter assertion value
 *
 * Escapes only the characters that MUST be escaped in filter assertion values
 * per RFC 4515: '*', '(', ')', '\'.  Other characters (including ',', '+',
 * '=') must NOT be escaped -- some LDAP implementations do not decode
 * non-required \HH sequences in assertion values and will fail to match.
 * Escape sequence is @verbatim \<hex><hex> @endverbatim.
 *
 * @param request The current request.
 * @param out Pointer to output buffer.
 * @param outlen Size of the output buffer.
 * @param in Raw unescaped string.
 * @param arg Any additional arguments (unused).
 */
size_t fr_ldap_filter_escape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	size_t left = outlen;

	while (*in) {
		if (memchr(filter_specials, *in, sizeof(filter_specials) - 1)) {
			if (left <= 3) break;

			*out++ = '\\';
			*out++ = hextab[(*in >> 4) & 0x0f];
			*out++ = hextab[*in & 0x0f];
			in++;
			left -= 3;

			continue;
		}

		if (left <= 1) break;

		*out++ = *in++;
		left--;
	}

	*out = '\0';

	return outlen - left;
}

int fr_ldap_filter_box_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	fr_assert(!fr_value_box_is_safe_for(vb, fr_ldap_filter_box_escape));

	if ((vb->type != FR_TYPE_STRING) && (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0)) {
		return -1;
	}

	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->vb_length * 3, vb->vb_length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped filter");
		return -1;
	}

	len = fr_ldap_filter_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, NULL);

	if (len == vb->vb_length) {
		talloc_free(fr_sbuff_buff(&sbuff));
	} else {
		fr_sbuff_trim_talloc(&sbuff, len);
		fr_value_box_strdup_shallow_replace(vb, fr_sbuff_buff(&sbuff), len);
	}

	return 0;
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
size_t fr_ldap_uri_unescape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char const *p;
	char const *c1, *c2;
	char c3;
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
		if (memchr(dn_specials, *p, sizeof(dn_specials) - 1)) {
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
			if (escapes[(uint8_t) p[1]]) {
				inlen -= 1;
				p += 1;
				continue;
			}

			/*
			 *	Invalid escape sequence, not a DN
			 */
			if (inlen < 3) return false;

			/*
			 *	Hex encoding, consume three chars
			 */
			if (fr_base16_decode(NULL, &FR_DBUFF_TMP((uint8_t *) &c, 1), &FR_SBUFF_IN(p + 1, 2), false) == 1) {
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

/** Parse a subset (just server side sort and virtual list view for now) of LDAP URL extensions
 *
 * @param[out] sss		Array of LDAPControl * pointers to add controls to.
 * @param[in] sss_len		How many elements remain in the sss array.
 * @param[in] extensions	A NULL terminated array of extensions.
 * @return
 *	- >0 the number of controls added.
 *	- 0 if no controls added.
 *	- -1 on failure.
 */
int fr_ldap_parse_url_extensions(LDAPControl **sss, size_t sss_len, char *extensions[])
{
	LDAPControl **sss_p = sss, **sss_end = sss_p + sss_len;
	int i;

	if (!extensions) {
		*sss_p = NULL;
		return 0;
	}

	/*
	 *	Parse extensions in the LDAP URL
	 */
	for (i = 0; extensions[i]; i++) {
		fr_sbuff_t	sbuff = FR_SBUFF_IN(extensions[i], strlen(extensions[i]));
		bool		is_critical = false;

		if (sss_p == sss_end) {
			fr_strerror_printf("Too many extensions.  Maximum is %ld", sss_len);
			goto error;
		}

		if (fr_sbuff_next_if_char(&sbuff, '!')) is_critical = true;

		/*
		 *	Server side sort control
		 */
		if (fr_sbuff_adv_past_str(&sbuff, "sss", 3)) {
			LDAPSortKey	**keys;
			int		ret;

			if (!fr_sbuff_next_if_char(&sbuff, '=')) {
				LDAPControl **s;
				fr_strerror_const("Server side sort extension must be "
						  "in the format \"[!]sss=<key>[,key]\"");
			error:
				s = sss;
				while (s < sss_p) {
					if (*s) ldap_control_free(*s);
					s++;
				}
				return -1;
			}

			ret = ldap_create_sort_keylist(&keys, fr_sbuff_current(&sbuff));
			if (ret != LDAP_SUCCESS) {
				fr_strerror_printf("Invalid server side sort value \"%s\": %s",
						   fr_sbuff_current(&sbuff), ldap_err2string(ret));
				goto error;
			}

			if (*sss_p) ldap_control_free(*sss_p);

			ret = ldap_create_sort_control(fr_ldap_handle_thread_local(), keys, is_critical ? 1 : 0, sss_p);
			ldap_free_sort_keylist(keys);
			if (ret != LDAP_SUCCESS) {
				fr_strerror_printf("Failed creating server sort control: %s",
						   ldap_err2string(ret));
				goto error;
			}
			sss_p++;
			*sss_p = NULL;	/* Terminate */
			continue;
		}

		if (fr_sbuff_adv_past_str(&sbuff, "vlv", 3)) {
			LDAPVLVInfo     vlvinfo;
			uint32_t	ext_value;
			struct berval	attr_value;
			int		ret;

			if (!fr_sbuff_next_if_char(&sbuff, '=')) {
			vlv_error:
				fr_strerror_const("Virtual list view extension must be "
						  "in the format \"[!]vlv=<before>/<after>(/<offset>/<count>|:<value>)");
				goto error;
			}

			vlvinfo.ldvlv_context = NULL;

			if (fr_sbuff_out(NULL, &ext_value, &sbuff) <= 0) goto vlv_error;
			if (!fr_sbuff_next_if_char(&sbuff, '/')) goto vlv_error;
			vlvinfo.ldvlv_before_count = ext_value;

			if (fr_sbuff_out(NULL, &ext_value, &sbuff) <= 0) goto vlv_error;
			vlvinfo.ldvlv_after_count = ext_value;

			/* offset/count syntax */
			if (fr_sbuff_next_if_char(&sbuff, '/')) {
				/* Ensure attrvalue is null - this is how the type of vlv control is determined */
				vlvinfo.ldvlv_attrvalue = NULL;

				if (fr_sbuff_out(NULL, &ext_value, &sbuff) <= 0) goto vlv_error;
				if (!fr_sbuff_next_if_char(&sbuff, '/')) goto error;
				vlvinfo.ldvlv_offset = ext_value;

				if (fr_sbuff_out(NULL, &ext_value, &sbuff) <= 0) goto vlv_error;
				vlvinfo.ldvlv_count = ext_value;

			/* greaterThanOrEqual attribute syntax*/
			} else if (fr_sbuff_next_if_char(&sbuff, ':')) {
				attr_value.bv_val = fr_sbuff_current(&sbuff);
				attr_value.bv_len = fr_sbuff_remaining(&sbuff);
				vlvinfo.ldvlv_attrvalue = &attr_value;

			} else goto error;

			ret = ldap_create_vlv_control(fr_ldap_handle_thread_local(), &vlvinfo, sss_p);

			if (ret != LDAP_SUCCESS) {
				fr_strerror_printf("Failed creating virtual list view control: %s",
						   ldap_err2string(ret));
				goto error;
			}

			sss_p++;
			*sss_p = NULL;	/* Terminate */
			continue;
		}

		fr_strerror_printf("URL extension \"%s\" not supported", extensions[i]);
		return -1;
	}

	return (sss_end - sss_p);
}

/** Release value iteration state
 *
 * Must be called once for every fr_ldap_value_iter_init, whether
 * iteration completed or not.
 *
 * @param[in] iter	to release.
 */
void fr_ldap_value_iter_done(fr_ldap_value_iter_t *iter)
{
	ber_free(iter->ber, 0);
	iter->ber = NULL;
}

/** Return the next value of the iterated attribute
 *
 * @param[out] err	Set to -1 if the entry could not be parsed.
 *			Untouched otherwise.  May be NULL.
 * @param[in] iter	to advance.
 * @return
 *	- The next value.
 *	- NULL when the values are exhausted, or the entry could not be
 *	  parsed.
 */
struct berval *fr_ldap_value_iter_next(int *err, fr_ldap_value_iter_t *iter)
{
	if (iter->end) return NULL;

	if (ber_scanf(iter->ber, "m", &iter->value) == LBER_ERROR) {
		fr_strerror_const("Malformed search result entry");
		iter->end = true;
		if (err) *err = -1;
		return NULL;
	}

	if (ber_next_element(iter->ber, &iter->len, iter->last) == LBER_DEFAULT) iter->end = true;

	return &iter->value;
}

/** Start an in place iteration over an attribute's values in an entry
 *
 * The returned values point into the result message the entry belongs
 * to, nothing is copied, and the values remain valid until the result
 * message is freed with ldap_msgfree.
 *
 * @param[out] err	Set to -1 if the entry could not be parsed.
 *			Untouched otherwise.  May be NULL.
 * @param[out] iter	to initialise.  Release with fr_ldap_value_iter_done.
 * @param[in] handle	the entry was received on.
 * @param[in] entry	whose values to iterate.
 * @param[in] attr	to find.
 * @return
 *	- The attribute's first value.
 *	- NULL if the entry does not contain the attribute, or could not
 *	  be parsed.
 */
struct berval *fr_ldap_value_iter_init(int *err, fr_ldap_value_iter_t *iter, LDAP *handle, LDAPMessage *entry,
				       char const *attr)
{
	struct berval	dn, name;
	size_t		attr_len = strlen(attr);
	ber_len_t	remaining;

	*iter = (fr_ldap_value_iter_t){};

	if (ldap_get_dn_ber(handle, entry, &iter->ber, &dn) != LDAP_SUCCESS) {
	error:
		fr_strerror_const("Malformed search result entry");
		iter->end = true;
		if (err) *err = -1;
		return NULL;
	}

	for (;;) {
		if (ber_get_option(iter->ber, LBER_OPT_BER_REMAINING_BYTES, &remaining) != LBER_OPT_SUCCESS) goto error;
		if (remaining == 0) break;

		if (ber_scanf(iter->ber, "{m" /*}*/, &name) == LBER_ERROR) goto error;

		if ((name.bv_len != attr_len) || (strncasecmp(name.bv_val, attr, attr_len) != 0)) {
			if (ber_scanf(iter->ber, "x") == LBER_ERROR) goto error;
			continue;
		}

		if (ber_first_element(iter->ber, &iter->len, &iter->last) != LBER_DEFAULT) iter->found = true;
		break;
	}
	if (!iter->found) {
		iter->end = true;
		return NULL;
	}

	return fr_ldap_value_iter_next(err, iter);
}

/** Free the ber held by an allocated value iterator
 *
 */
static int _fr_ldap_value_iter_free(fr_ldap_value_iter_t *iter)
{
	fr_ldap_value_iter_done(iter);

	return 0;
}

/** Allocate a value iterator, released when the iterator is freed
 *
 * Behaves as fr_ldap_value_iter_init, with the ber memory freed by a
 * talloc destructor, so the iteration state is released when the
 * iterator or any of its talloc ancestors are freed.
 *
 * @param[out] err	Set to -1 if the entry could not be parsed.
 *			Untouched otherwise.  May be NULL.
 * @param[out] out	The allocated iterator.
 * @param[in] ctx	to allocate the iterator in.
 * @param[in] handle	the entry was received on.
 * @param[in] entry	whose values to iterate.
 * @param[in] attr	to find.
 * @return
 *	- The attribute's first value.
 *	- NULL if the entry does not contain the attribute, or could not
 *	  be parsed.
 */
struct berval *fr_ldap_value_iter_alloc(int *err, fr_ldap_value_iter_t **out, TALLOC_CTX *ctx,
					LDAP *handle, LDAPMessage *entry, char const *attr)
{
	fr_ldap_value_iter_t	*iter;
	struct berval		*value;

	MEM(iter = talloc(ctx, fr_ldap_value_iter_t));

	value = fr_ldap_value_iter_init(err, iter, handle, entry, attr);
	talloc_set_destructor(iter, _fr_ldap_value_iter_free);
	*out = iter;

	return value;
}

/** Sum the lengths of an attribute's values across every entry of a result
 *
 * The values are read in place from the result message, no arrays are
 * allocated and no values are copied.
 *
 * @param[out] num		Number of values found.
 * @param[out] strings_len	Total length of the values, including a NUL
 *				byte for each.
 * @param[in] handle		the result was received on.
 * @param[in] result		Head of the result message chain.
 * @param[in] attr		whose values to measure.
 * @return
 *	- 0 on success.
 *	- -1 if an entry could not be parsed.
 */
int fr_ldap_result_values_len(size_t *num, size_t *strings_len, LDAP *handle, LDAPMessage *result, char const *attr)
{
	LDAPMessage	*entry;

	*num = 0;
	*strings_len = 0;

	for (entry = ldap_first_entry(handle, result); entry; entry = ldap_next_entry(handle, entry)) {
		fr_ldap_value_iter_t	iter;
		struct berval		*value;
		int			err = 0;

		for (value = fr_ldap_value_iter_init(&err, &iter, handle, entry, attr);
		     value;
		     value = fr_ldap_value_iter_next(&err, &iter)) {
			*strings_len += value->bv_len + 1;
			(*num)++;
		}
		fr_ldap_value_iter_done(&iter);
		if (unlikely(err < 0)) return -1;
	}

	return 0;
}

/** Copy an attribute's values from every entry of a result into a string list
 *
 * The list, its pointer array and every string come from a single talloc
 * pool.  The values are read in place from the result message, the only
 * copies made are the strings in the list.
 *
 * @param[in] ctx	to allocate the list in.
 * @param[in] handle	the result was received on.
 * @param[in] result	Head of the result message chain.
 * @param[in] attr	whose values to copy.  May be NULL, in which case
 *			only the extra slots are allocated.
 * @param[in] extra	Leading pointer array slots to leave NULL, for the
 *			caller to fill with strings not copied into the pool.
 * @return
 *	- List of the attribute's values.  Empty if the result holds no
 *	  values for the attribute.
 *	- NULL if an entry could not be parsed.
 */
talloc_str_list_t *fr_ldap_str_list_afrom_result(TALLOC_CTX *ctx, LDAP *handle, LDAPMessage *result,
						 char const *attr, size_t extra)
{
	talloc_str_list_t	*list = NULL;
	LDAPMessage		*entry;
	size_t			num = 0, strings_len = 0;

	if (attr) {
		if (unlikely(fr_ldap_result_values_len(&num, &strings_len, handle, result, attr) < 0)) return NULL;
	}

	MEM(list = talloc_str_list_alloc(ctx, num + extra, strings_len));
	list->p += extra;

	if (num == 0) return list;

	for (entry = ldap_first_entry(handle, result); entry; entry = ldap_next_entry(handle, entry)) {
		fr_ldap_value_iter_t	iter;
		struct berval		*value;
		int			err = 0;

		for (value = fr_ldap_value_iter_init(&err, &iter, handle, entry, attr);
		     value;
		     value = fr_ldap_value_iter_next(&err, &iter)) {
			MEM(talloc_str_list_append(list, value->bv_val, value->bv_len));
		}
		fr_ldap_value_iter_done(&iter);
		if (unlikely(err < 0)) {
			talloc_free(list);
			return NULL;
		}
	}

	return list;
}

/** Find an attribute in an entry, returning its first value referenced in place
 *
 * The value points into the result message the entry belongs to, nothing
 * is allocated and nothing needs freeing.  The value remains valid until
 * the result message is freed with ldap_msgfree.
 *
 * @param[out] out	First value of the attribute.  Untouched when the
 *			attribute is not found.
 * @param[in] handle	the entry was received on.
 * @param[in] entry	to search.
 * @param[in] attr	to find.
 * @return
 *	- The number of values the attribute has.
 *	- 0 if the entry does not contain the attribute.
 *	- -1 if the entry could not be parsed.
 */
int fr_ldap_entry_value_find(struct berval *out, LDAP *handle, LDAPMessage *entry, char const *attr)
{
	fr_ldap_value_iter_t	iter;
	struct berval		*value;
	int			num = 0, err = 0;

	for (value = fr_ldap_value_iter_init(&err, &iter, handle, entry, attr);
	     value;
	     value = fr_ldap_value_iter_next(&err, &iter)) {
		if (num == 0) *out = *value;
		num++;
	}
	fr_ldap_value_iter_done(&iter);
	if (unlikely(err < 0)) return -1;

	return num;
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

	out = talloc_array(ctx, uint8_t, in->bv_len);
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
			char c = '\0';

			/*
			 *	Double backslashes get passed through as-is.
			 *	Copy both and let the for loop advance past the second.
			 */
			if (p[1] == '\\') {
				*o++ = p[0];
				*o++ = p[1];
				p++;
				continue;
			}

			/*
			 *	Hex encodings that have an alternative
			 *	special encoding, get rewritten to the
			 *	special encoding.
			 */
			if (fr_base16_decode(NULL, &FR_DBUFF_TMP((uint8_t *) &c, 1), &FR_SBUFF_IN(p + 1, 2), false) == 1 &&
			    escapes[(uint8_t) c]) {
				*o++ = '\\';
				*o++ = c;
				p += 2;
				continue;
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

	for (i = 0; i < p_len; i++) if (part[p_len - 1 - i] != full[f_len - 1 - i]) return -1;

	return f_len - p_len;
}

/** Build a filter matching a set of objects by DN
 *
 * Produces `(|(<dn_attr>=<dn>)...)`, ANDed with filter if one is given.
 * DN values are escaped.
 *
 * @param[in] ctx	to allocate the filter string in.
 * @param[in] dn_attr	Attribute which matches an object's own DN,
 *			e.g. entryDN or distinguishedName.
 * @param[in] filter	Optional filter to AND with the DN set, may be NULL.
 * @param[in] dn_list	NULL terminated list of DNs to match, no empty strings.
 * @return The filter string.
 */
char *fr_ldap_filter_afrom_dn_list(TALLOC_CTX *ctx, char const *dn_attr, char const *filter,
			       char const * const *dn_list)
{
	char			*out;
	char const * const	*dn_p;

	MEM(out = talloc_typed_strdup(ctx, "(|"));
	for (dn_p = dn_list; *dn_p; dn_p++) {
		char	*escaped;
		size_t	len;

		len = (strlen(*dn_p) * 3) + 1;
		MEM(escaped = talloc_array(ctx, char, len));
		fr_ldap_filter_escape_func(NULL, escaped, len, *dn_p, NULL);
		MEM(out = talloc_asprintf_append_buffer(out, "(%s=%s)", dn_attr, escaped));
		talloc_free(escaped);
	}
	MEM(out = talloc_strdup_append_buffer(out, ")"));

	if (filter && *filter) {
		char *combined;

		MEM(combined = talloc_typed_asprintf(ctx, "(&%s%s)", filter, out));
		talloc_free(out);
		return combined;
	}

	return out;
}

/** Combine filters and tokenize to a tmpl
 *
 * @param ctx		To allocate combined filter in
 * @param t_rules	Rules for parsing combined filter.
 * @param sub		Array of subfilters (may contain NULLs).
 * @param sublen	Number of potential subfilters in array.
 * @param out		Where to write a pointer to the resulting tmpl.
 * @return length of combined data.
 */
int fr_ldap_filter_to_tmpl(TALLOC_CTX *ctx, tmpl_rules_t const *t_rules, char const **sub, size_t sublen, tmpl_t **out)
{
	char		*buffer = NULL;
	char const	*in = NULL;
	ssize_t		len = 0;
	size_t		i;
	int		cnt = 0;
	tmpl_t		*parsed;

	*out = NULL;

	/*
	 *	Figure out how many filter elements we need to integrate
	 */
	for (i = 0; i < sublen; i++) {
		if (sub[i] && *sub[i]) {
			in = sub[i];
			cnt++;
			len += strlen(sub[i]);
		}
	}

	if (!cnt) return 0;

	if (cnt > 1) {
		/*
		 *	Allocate a buffer large enough, allowing for (& ... ) plus trailing '\0'
		 */
		buffer = talloc_array(ctx, char, len + 4);

		strcpy(buffer, "(&");
		for (i = 0; i < sublen; i++) {
			if (sub[i] && (*sub[i] != '\0')) {
				strcat(buffer, sub[i]);
			}
		}
		strcat(buffer, ")");
		in = buffer;
	}

	len = tmpl_afrom_substr(ctx, &parsed, &FR_SBUFF_IN_STR(in), T_DOUBLE_QUOTED_STRING, NULL, t_rules);

	talloc_free(buffer);

	if (len < 0) {
		EMARKER(in, -len, fr_strerror());
		return -1;
	}

	*out = parsed;
	return 0;
}

/** Check that a particular attribute is included in an attribute list
 *
 * @param[in] attrs	list to check
 * @param[in] attr	to look for
 * @return
 *	- 1 if attr is in list
 *	- 0 if attr is missing
 *	- -1 if checks not possible
 */
int fr_ldap_attrs_check(char const **attrs, char const *attr)
{
	size_t		len, i;

	if (!attr) return -1;

	len = talloc_array_length(attrs);

	for (i = 0; i < len; i++) {
		if (!attrs[i]) continue;
		if (strcasecmp(attrs[i], attr) == 0) return 1;
		if (strcasecmp(attrs[i], "*") == 0) return 1;
	}

	return 0;
}

/** Check an LDAP server entry in URL format is valid
 *
 * @param[in,out] handle_config	LDAP handle config being built
 * @param[in] server		string to parse
 * @param[in] cs		in which the server is defined
 * @return
 *	- 0 for valid server definition
 *	- -1 for invalid server definition
 */
int fr_ldap_server_url_check(fr_ldap_config_t *handle_config, char const *server, CONF_SECTION const *cs)
{
	LDAPURLDesc	*ldap_url;
	bool		set_port_maybe = true;
	int		default_port = LDAP_PORT;
	char const	*p;
	char		*url;
	CONF_ITEM	*ci = (CONF_ITEM *)cf_pair_find(cs, "server");

	if (ldap_url_parse(server, &ldap_url)) {
		cf_log_err(ci, "Parsing LDAP URL \"%s\" failed", server);
	ldap_url_error:
		ldap_free_urldesc(ldap_url);
		return -1;
	}

	if (ldap_url->lud_dn && (ldap_url->lud_dn[0] != '\0')) {
		cf_log_err(ci, "Base DN cannot be specified via server URL");
		goto ldap_url_error;
	}

	if (ldap_url->lud_attrs && ldap_url->lud_attrs[0]) {
		cf_log_err(ci, "Attribute list cannot be speciried via server URL");
		goto ldap_url_error;
	}

	/*
	 *	ldap_url_parse sets this to base by default.
	 */
	if (ldap_url->lud_scope != LDAP_SCOPE_BASE) {
		cf_log_err(ci, "Scope cannot be specified via server URL");
		goto ldap_url_error;
	}
	ldap_url->lud_scope = -1;	/* Otherwise LDAP adds ?base */

	/*
	 *	The public ldap_url_parse function sets the default
	 *	port, so we have to discover whether a port was
	 *	included ourselves.
	 */
	if ((p = strchr(server, ']')) && (p[1] == ':')) {			/* IPv6 */
		set_port_maybe = false;
	} else if ((p = strchr(server, ':')) && (strchr(p+1, ':') != NULL)) {	/* IPv4 */
		set_port_maybe = false;
	}

	/*
	 *	Figure out the default port from the URL
	 */
	if (ldap_url->lud_scheme) {
		if (strcmp(ldap_url->lud_scheme, "ldaps") == 0) {
			if (handle_config->start_tls == true) {
				cf_log_err(ci, "ldaps:// scheme is not compatible with 'start_tls'");
				goto ldap_url_error;
			}
			default_port = LDAPS_PORT;
			handle_config->tls_mode = LDAP_OPT_X_TLS_HARD;
		} else if (strcmp(ldap_url->lud_scheme, "ldapi") == 0) {
			set_port_maybe = false;
		}
	}

	if (set_port_maybe) {
		/*
		 *	URL port overrides configured port.
		 */
		ldap_url->lud_port = handle_config->port;

		/*
		 *	If there's no URL port, then set it to the default
		 *	this is so debugging messages show explicitly
		 *	the port we're connecting to.
		 */
		if (!ldap_url->lud_port) ldap_url->lud_port = default_port;
	}

	url = ldap_url_desc2str(ldap_url);
	if (!url) {
		cf_log_err(ci, "Failed recombining URL components");
		goto ldap_url_error;
	}
	handle_config->server = talloc_asprintf_append(handle_config->server, "%s ", url);

	ldap_free_urldesc(ldap_url);
	ldap_memfree(url);
	return (0);
}

/** Check an LDAP server config in server:port format is valid
 *
 * @param[in,out] handle_config	LDAP handle config being built
 * @param[in] server		string to parse
 * @param[in] cs		in which the server is defined
 * @return
 *	- 0 for valid server definition
 *	- -1 for invalid server definition
 */
int fr_ldap_server_config_check(fr_ldap_config_t *handle_config, char const *server, CONF_SECTION *cs)
{
	char	const *p;
	char	*q;
	int	port = 0;
	size_t	len;

	port = handle_config->port;

	/*
	 *	We don't support URLs if the library didn't provide
	 *	URL parsing functions.
	 */
	if (strchr(server, '/')) {
		CONF_ITEM	*ci;
	bad_server_fmt:
		ci = (CONF_ITEM *)cf_pair_find(cs, "server");
		cf_log_err(ci, "Invalid 'server' entry, must be in format <server>[:<port>] or "
			       "an ldap URI (ldap|cldap|ldaps|ldapi)://<server>:<port>");
		return -1;
	}

	p = strrchr(server, ':');
	if (p) {
		port = (int)strtol((p + 1), &q, 10);
		if ((p == server) || ((p + 1) == q) || (*q != '\0')) goto bad_server_fmt;
		len = p - server;
	} else {
		len = strlen(server);
	}
	if (port == 0) port = LDAP_PORT;

	handle_config->server = talloc_asprintf_append(handle_config->server, "ldap://%.*s:%i ",
						       (int)len, server, port);
	return 0;
}

/** Translate the error code emitted from ldap_url_parse and friends into something accessible with fr_strerror()
 *
 * @param[in] ldap_url_err	The error code returned
 */
char const *fr_ldap_url_err_to_str(int ldap_url_err)
{
	switch (ldap_url_err) {
	case LDAP_URL_SUCCESS:
		return "success";

	case LDAP_URL_ERR_MEM:
		return "no memory";

	case LDAP_URL_ERR_PARAM:
		return "parameter is bad";

	case LDAP_URL_ERR_BADSCHEME:
		return "URL doesn't begin with \"[c]ldap[si]://\"";

	case LDAP_URL_ERR_BADENCLOSURE:
		return "URL is missing trailing \">\"";

	case LDAP_URL_ERR_BADURL:
		return "URL is bad";

	case LDAP_URL_ERR_BADHOST:
		return "host/port is bad";

	case LDAP_URL_ERR_BADATTRS:
		return "bad (or missing) attributes";

	case LDAP_URL_ERR_BADSCOPE:
		return "scope string is invalid (or missing)";

	case LDAP_URL_ERR_BADFILTER:
		return "bad or missing filter";

	case LDAP_URL_ERR_BADEXTS:
		return "bad or missing extensions";

	default:
		return "unknown reason";
	}
}

/** Dump out the contents of an LDAPMessage
 *
 * Intended to be called from a debugger.
 *
 * @param[in] entry	LDAPMessage to dump.
 */
void fr_ldap_entry_dump(LDAPMessage *entry)
{
	char		*dn;
	BerElement	*ber = NULL;
	char		*attr;
	struct berval	**vals;
	int		i;
	LDAP		*ld = fr_ldap_handle_thread_local();
	int		msgtype;

	msgtype = ldap_msgtype(entry);
	switch (msgtype) {
	case LDAP_RES_SEARCH_ENTRY:
		dn = ldap_get_dn(ld, entry);
		if (dn) {
			DEBUG("dn: %s", dn);
			ldap_memfree(dn);
		}

		for (attr = ldap_first_attribute(ld, entry, &ber);
		     attr != NULL;
		     attr = ldap_next_attribute(ld, entry, ber)) {
			vals = ldap_get_values_len(ld, entry, attr);
			if (!vals) {
				DEBUG("%s: no values", attr);
				ldap_memfree(attr);
				continue;
			}

			for (i = 0; vals[i] != NULL; i++) {
				bool binary = false;
				ber_len_t j;

				for (j = 0; j < vals[i]->bv_len; j++) {
					char c = vals[i]->bv_val[j];
					if ((c < 32) || (c > 126)) {
						binary = true;
						break;
					}
				}

				if (binary) {
					DEBUG("%s[%u]: %pV", attr, i, fr_box_octets((uint8_t *)vals[i]->bv_val, vals[i]->bv_len));
					continue;
				}

				DEBUG("%s[%u]: %pV", attr, i, fr_box_strvalue_len(vals[i]->bv_val, vals[i]->bv_len));
			}

			ldap_value_free_len(vals);
			ldap_memfree(attr);
		     }
		break;

	case LDAP_RES_SEARCH_RESULT:
	case LDAP_RES_BIND:
	case LDAP_RES_MODIFY:
	case LDAP_RES_ADD:
	case LDAP_RES_DELETE:
	case LDAP_RES_COMPARE:
	case LDAP_RES_EXTENDED:
	{
		int rc;
		char *matched = NULL;
		char *errmsg  = NULL;
		char **refs   = NULL;

		rc = ldap_parse_result(ld, entry, &msgtype, &matched, &errmsg, &refs, NULL, 0);
		if (rc != LDAP_SUCCESS) {
			DEBUG("failed to parse result: %s", ldap_err2string(rc));
			break;
		}

		DEBUG("result code: %d (%s)", msgtype, ldap_err2string(msgtype));

		if (matched && *matched) {
			DEBUG("matched DN: %s", matched);
		}
		if (errmsg && *errmsg) {
			DEBUG("error message: %s", errmsg);
		}
		if (refs) {
			for (i = 0; refs[i] != NULL; i++) {
				DEBUG("referral: %s", refs[i]);
			}
		}

		if (matched) ldap_memfree(matched);
		if (errmsg) ldap_memfree(errmsg);
		if (refs) ldap_memvfree((void **)refs);
	}
		break;

	default:
		DEBUG("unhandled LDAP message type: %d", msgtype);
		break;
	}

	if (ber) ber_free(ber, 0);
}
