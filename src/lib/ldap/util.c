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
#include <freeradius-devel/util/base16.h>

#include <stdarg.h>
#include <ctype.h>

static const char specials[] = ",+\"\\<>;*=()";
static const char hextab[] = "0123456789abcdef";
static const bool escapes[UINT8_MAX + 1] = {
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
size_t fr_ldap_uri_escape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	size_t left = outlen;

	if ((*in == ' ') || (*in == '#')) goto encode;

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

int fr_ldap_box_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	size_t			len;
	fr_value_box_entry_t	entry;

	if (fr_value_box_is_safe_for(vb, fr_ldap_box_escape)) return 0;

	if ((vb->type != FR_TYPE_STRING) && (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0)) {
		fr_value_box_clear_value(vb);
		return -1;
	}

	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->vb_length * 3, vb->vb_length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped filter");
		return -1;
	}

	len = fr_ldap_uri_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, NULL);

	/*
	 *	If the returned length is unchanged, the value was already safe
	 */
	if (len == vb->vb_length) {
		talloc_free(fr_sbuff_buff(&sbuff));
	} else {
		entry = vb->entry;
		fr_sbuff_trim_talloc(&sbuff, len);
		fr_value_box_clear_value(vb);
		fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), vb->tainted);
		vb->entry = entry;
	}

	fr_value_box_mark_safe_for(vb, fr_ldap_box_escape);

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
		if (memchr(specials, *p, sizeof(specials) - 1)) {
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

/** Parse a subset (just server side sort for now) of LDAP URL extensions
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
		char *p;
		bool is_critical = false;

		p = extensions[i];
		if (*p == '!') {
			is_critical = true;
			p++;
		}

		/*
		 *	Server side sort control
		 */
		if (strncmp(p, "sss", 3) == 0) {
			LDAPSortKey	**keys;
			int		ret;

			p += 3;
			p = strchr(p, '=');
			if (!p) {
				fr_strerror_const("Server side sort extension must be "
						  "in the format \"[!]sss=<key>[,key]\"");
				return -1;
			}
			p++;

			ret = ldap_create_sort_keylist(&keys, p);
			if (ret != LDAP_SUCCESS) {
				fr_strerror_printf("Invalid server side sort value \"%s\": %s",
						   p, ldap_err2string(ret));
				return -1;
			}

			if (*sss_p) ldap_control_free(*sss_p);

			ret = ldap_create_sort_control(fr_ldap_handle_thread_local(), keys, is_critical ? 1 : 0, sss_p);
			ldap_free_sort_keylist(keys);
			if (ret != LDAP_SUCCESS) {
				fr_strerror_printf("Failed creating server sort control: %s",
						   ldap_err2string(ret));
				return -1;
			}
			sss_p++;

			continue;
		}

		fr_strerror_printf("URL extension \"%s\" not supported", p);
		return -1;
	}

	*sss_p = NULL;	/* Terminate */

	return (sss_end - sss_p);
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

	for (i = 0; i < p_len; i++) if (part[p_len - i] != full[f_len - i]) return -1;

	return f_len - p_len;
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

	len = tmpl_afrom_substr(ctx, &parsed, &FR_SBUFF_IN(in, strlen(in)), T_DOUBLE_QUOTED_STRING, NULL, t_rules);

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
	char		*p, *url;
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
