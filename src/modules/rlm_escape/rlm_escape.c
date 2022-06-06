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

#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const *allowed_chars;
} rlm_escape_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("safe_characters", FR_TYPE_STRING, rlm_escape_t, allowed_chars), .dflt = "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },
	CONF_PARSER_TERMINATOR
};

static char const hextab[] = "0123456789abcdef";

static xlat_arg_parser_t const escape_xlat_arg = { .required = true, .concat = true, .type = FR_TYPE_STRING };

/** Equivalent to the old safe_characters functionality in rlm_sql but with utf8 support
 *
 * Example:
@verbatim
"%{escape:<img>foo.jpg</img>}" == "=60img=62foo.jpg=60/img=62"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t escape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *in)
{
	rlm_escape_t const	*inst = talloc_get_type_abort(xctx->mctx->inst->data, rlm_escape_t);
	fr_value_box_t		*arg = fr_dlist_head(in);
	char const		*p = arg->vb_strvalue;
	size_t			len;
	fr_value_box_t		*vb;
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	int			i;

	len = talloc_array_length(inst->allowed_chars) - 1;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	We don't know how long the final escaped string
	 *	will be - assign something twice as long as the input
	 *	as a starting point.  The maximum length would be 12
	 *	times the original if every character is 4 byte UTF8.
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, arg->length * 2, arg->length * 12)) {
	error:
		RPEDEBUG("Failed to allocated buffer for escaped string");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	while (p[0]) {
		int chr_len = 1;

		if (fr_utf8_strchr(&chr_len, inst->allowed_chars, len, p) == NULL) {
			/*
			 *	'=' 1 + ([hex]{2}) * chr_len)
			 */
			for (i = 0; i < chr_len; i++) {
				if (fr_sbuff_in_sprintf(&sbuff, "=%02X", (uint8_t)p[i]) < 0)
					goto error;
			}

			p += chr_len;
			continue;
		}

		/*
		 *	Allowed character (copy whole mb chars at once)
		 */
		if (fr_sbuff_in_bstrncpy(&sbuff, p, chr_len) < 0)
			goto error;
		p += chr_len;
	}

	fr_sbuff_trim_talloc(&sbuff, SIZE_MAX);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), arg->tainted);

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const unescape_xlat_arg = { .required = true, .concat = true, .type = FR_TYPE_STRING };

/** Equivalent to the old safe_characters functionality in rlm_sql
 *
 * Example:
@verbatim
"%{unescape:=60img=62foo.jpg=60/img=62}" == "<img>foo.jpg</img>"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unescape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*arg = fr_dlist_head(in);
	char const	*p, *end;
	char		*out_p;
	char		*c1, *c2, c3;
	fr_sbuff_t	sbuff;
	fr_value_box_t	*vb;

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_bstr_alloc(ctx, &out_p, vb, NULL, arg->length, arg->tainted) < 0) {
		talloc_free(vb);
		RPEDEBUG("Failed allocating space for unescaped string");
		return XLAT_ACTION_FAIL;
	}
	sbuff = FR_SBUFF_IN(out_p, arg->length);

	p = arg->vb_strvalue;
	end = p + arg->length;
	while (*p) {
		if (*p != '=') {
		next:

			(void) fr_sbuff_in_char(&sbuff, *p++);
			continue;
		}

		/* Is a = char */

		if (((end - p) < 2) ||
		    !(c1 = memchr(hextab, tolower(*(p + 1)), 16)) ||
		    !(c2 = memchr(hextab, tolower(*(p + 2)), 16))) goto next;
		c3 = ((c1 - hextab) << 4) + (c2 - hextab);

		(void) fr_sbuff_in_char(&sbuff, c3);
		p += 3;
	}

	fr_value_box_strtrim(ctx, vb);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
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
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	char		*unescape;
	xlat_t		*xlat;

	MEM(unescape = talloc_asprintf(NULL, "un%s", mctx->inst->name));
	xlat = xlat_register_module(NULL, mctx, mctx->inst->name, escape_xlat, XLAT_FLAG_PURE);
	xlat_func_mono(xlat, &escape_xlat_arg);

	xlat = xlat_register_module(NULL, mctx, unescape, unescape_xlat, XLAT_FLAG_PURE);
	xlat_func_mono(xlat, &unescape_xlat_arg);
	talloc_free(unescape);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_escape;
module_rlm_t rlm_escape = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "escape",
		.inst_size	= sizeof(rlm_escape_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap
	}
};
