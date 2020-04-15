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
 * @file rlm_escape.c
 * @brief Register escape/unescape xlat functions.
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/server/base.h>

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const *xlat_name;
	char const *allowed_chars;
} rlm_escape_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("safe_characters", FR_TYPE_STRING, rlm_escape_t, allowed_chars), .dflt = "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },
	CONF_PARSER_TERMINATOR
};

static char const hextab[] = "0123456789abcdef";

/** Equivalent to the old safe_characters functionality in rlm_sql but with utf8 support
 *
 * Example:
@verbatim
"%{escape:<img>foo.jpg</img>}" == "=60img=62foo.jpg=60/img=62"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t escape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   void const *mod_inst, UNUSED void const *xlat_inst,
			   UNUSED REQUEST *request, char const *fmt)
{
	rlm_escape_t const	*inst = mod_inst;
	char const		*p = fmt;
	char			*out_p = *out;
	size_t			freespace = outlen;
	size_t			len = talloc_array_length(inst->allowed_chars) - 1;

	while (p[0]) {
		int chr_len = 1;
		int ret = 1;	/* -Werror=uninitialized */

		if (fr_utf8_strchr(&chr_len, inst->allowed_chars, len, p) == NULL) {
			/*
			 *	'=' 1 + ([hex]{2}) * chr_len)
			 */
			if (freespace <= (size_t)(1 + (chr_len * 3))) break;

			switch (chr_len) {
			case 4:
				ret = snprintf(out_p, freespace, "=%02X=%02X=%02X=%02X",
					       (uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2], (uint8_t)p[3]);
				break;

			case 3:
				ret = snprintf(out_p, freespace, "=%02X=%02X=%02X",
					       (uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2]);
				break;

			case 2:
				ret = snprintf(out_p, freespace, "=%02X=%02X", (uint8_t)p[0], (uint8_t)p[1]);
				break;

			case 1:
				ret = snprintf(out_p, freespace, "=%02X", (uint8_t)p[0]);
				break;
			}

			p += chr_len;
			out_p += ret;
			freespace -= ret;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (freespace <= 1) break;

		/*
		 *	Allowed character (copy whole mb chars at once)
		 */
		memcpy(out_p, p, chr_len);
		out_p += chr_len;
		p += chr_len;
		freespace -= chr_len;
	}
	*out_p = '\0';

	return outlen - freespace;
}

/** Equivalent to the old safe_characters functionality in rlm_sql
 *
 * Example:
@verbatim
"%{unescape:=60img=62foo.jpg=60/img=62}" == "<img>foo.jpg</img>"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t unescape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     UNUSED REQUEST *request, char const *fmt)
{
	char const *p;
	char *out_p = *out;
	char *c1, *c2, c3;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (*p != '=') {
		next:

			*out_p++ = *p++;
			continue;
		}

		/* Is a = char */

		if (!(c1 = memchr(hextab, tolower(*(p + 1)), 16)) ||
		    !(c2 = memchr(hextab, tolower(*(p + 2)), 16))) goto next;
		c3 = ((c1 - hextab) << 4) + (c2 - hextab);

		*out_p++ = c3;
		p += 3;
	}

	*out_p = '\0';

	return outlen - freespace;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_escape_t	*inst = instance;
	char		*unescape;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	MEM(unescape = talloc_asprintf(NULL, "un%s", inst->xlat_name));
	xlat_register(inst, inst->xlat_name, escape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, unescape, unescape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	talloc_free(unescape);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_escape;
module_t rlm_escape = {
	.magic		= RLM_MODULE_INIT,
	.name		= "escape",
	.inst_size	= sizeof(rlm_escape_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
};
