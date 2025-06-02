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
 * @file rlm_json.c
 * @brief Parses JSON responses
 *
 * @author Matthew Newton
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015,2021 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "json.h"
#include <ctype.h>

#ifndef HAVE_JSON
#  error "rlm_json should not be built unless json-c is available"
#endif


static CONF_PARSER const json_format_attr_config[] = {
	{ "prefix", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_json_t, attr_prefix), NULL },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const json_format_value_config[] = {
	{ "single_value_as_array", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_json_t, value_as_array), "no" },
	{ "enum_as_integer", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_json_t, enum_as_int), "no" },
	{ "dates_as_integer", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_json_t, dates_as_int), "no" },
	{ "always_string", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_json_t, always_string), "no" },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const fr_json_format_config[] = {
	{ "output_mode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_json_t, output_mode_str), "object" },
	{ "attribute", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) json_format_attr_config },
	{ "value", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) json_format_value_config },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const module_config[] = {
	{ "encode", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) fr_json_format_config },

	CONF_PARSER_TERMINATOR
};


/** Convert given attributes to a JSON document
 *
 * Usage is `%{json_encode:attr tmpl list}`
 *
 * @ingroup xlat_functions
 *
 * @param instance module instance
 * @param request the current request
 * @param fmt input to the xlat
 * @param out where to write the output
 * @param outlen space available for the output
 * @return length of output generated
 */
static ssize_t json_encode_xlat(void * instance, REQUEST *request, char const *fmt,
				      char *out, size_t outlen)
{
	rlm_json_t const	*inst = instance;
	ssize_t			slen;
	vp_tmpl_t		*vpt = NULL;
	VALUE_PAIR		*json_vps = NULL, *vps;
	bool			negate;
	char const		*p = fmt;
	char			*json_str = NULL;
	char			*buf;


	/*
	 * Iterate through the list of attribute templates in the xlat. For each
	 * one we either add it to the list of attributes for the JSON document
	 * or, if prefixed with '!', remove from the JSON list.
	 */

	p = fmt;

	while (isspace((uint8_t) *p)) p++;
	if (*p == '\0') return -1;

	while (*p) {
		while (isspace((uint8_t) *p)) p++;

		if (*p == '\0') break;

		negate = false;

		/* Check if we should be removing attributes */
		if (*p == '!') {
			p++;
			negate = true;
		}

		if (*p == '\0') {
			/* May happen e.g. with '!' on its own at the end */
			REMARKER(fmt, (p - fmt), "Missing attribute name");
		error:
			fr_pair_list_free(&json_vps);
			talloc_free(vpt);
			return -1;
		}


		/* Decode next attr template */
		slen = tmpl_afrom_attr_substr(request, &vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);

		if (slen <= 0) {
			REMARKER(fmt, (p - fmt) -slen, fr_strerror());
			goto error;
		}

		/*
		 * Get attributes from the template.
		 * Missing attribute isn't an error (so -1, not 0).
		 */
		if (tmpl_copy_vps(request, &vps, request, vpt) < -1) {
			REDEBUG("Error copying attributes");
			goto error;
		}

		if (negate) {
			/* Remove all template attributes from JSON list */
			for (VALUE_PAIR *vp = vps;
			     vp;
			     vp = vp->next) {
				fr_pair_delete_by_da(&json_vps, vp->da);
			}

			fr_pair_list_free(&vps);
		} else {
			/* Add template VPs to JSON list */
			fr_pair_add(&json_vps, vps);
		}

		TALLOC_FREE(vpt);

		/* Jump forward to next attr */
		p += slen;

		if (*p != '\0' && !isspace((uint8_t)*p)) {
			REMARKER(fmt, (p - fmt), "Missing whitespace");
			goto error;
		}
	}

	/*
	 * Given the list of attributes we now have in json_vps,
	 * convert them into a JSON document and append it to the
	 * return cursor.
	 */
	MEM(buf = talloc_zero_array(request, char, 8192));

	json_str = fr_json_afrom_pair_list(request, json_vps, inst);
	if (!json_str) {
		REDEBUG("Failed to generate JSON string");
		goto error;
	}

	slen = snprintf(out, outlen, "%s", json_str);

	fr_pair_list_free(&json_vps);

	return slen;
}


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_json_t		*inst = talloc_get_type_abort(instance, rlm_json_t);
	char 			*name;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	name = talloc_asprintf(inst, "%s_encode", inst->name);
	xlat_register(name, json_encode_xlat, NULL, inst);
	talloc_free(name);

	/*
	 *	Check the output format type and warn on unused
	 *	format options
	 */
	inst->output_mode = fr_str2int(fr_json_format_table, inst->output_mode_str, JSON_MODE_UNSET);
	if (inst->output_mode == JSON_MODE_UNSET) {
		cf_log_err_cs(conf, "output_mode value \"%s\" is invalid", inst->output_mode_str);
		return -1;
	}
	fr_json_format_verify(inst, true);

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
extern module_t rlm_json;
module_t rlm_json = {
	.magic		= RLM_MODULE_INIT,
	.name		= "json",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_json_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
};
