/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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

/*
 * $Id$
 *
 * @brief Workarounds for missing functions in older json-c libraries.
 * @file json_missing.c
 *
 * @copyright 2013-2014 Aaron Hurt <ahurt@anbcs.com>
 */

RCSID("$Id$");

#include <string.h>

#include "jsonc_missing.h"

#ifndef HAVE_JSON_C_VERSION
	const char *json_c_version(void) {
		return "Unknown (less than 0.10) - Please upgrade";
	}
#endif

#ifndef HAVE_JSON_OBJECT_GET_STRING_LEN
int json_object_get_string_len(json_object *obj) {
	if (json_object_get_type(obj) != json_type_string)
		return 0;
	return (int)strlen(json_object_to_json_string(obj));
}
#endif

#ifndef HAVE_JSON_OBJECT_OBJECT_GET_EX
int json_object_object_get_ex(struct json_object *jso, const char *key, struct json_object **value) {
	struct json_object *jobj;

	if ((jso == NULL) || (key == NULL)) return 0;
	if (value != NULL) *value = NULL;

	switch (json_object_get_type(jso)) {
	case json_type_object:
		jobj = json_object_object_get(jso, key);
		if (jobj == NULL) return 0;

		if (value != NULL) *value = jobj;
		return 1;

	default:
		if (value != NULL) *value = NULL;
		return 0;
	}
}
#endif

#ifndef HAVE_JSON_TOKENER_PARSE_VERBOSE
struct json_object* json_tokener_parse_verbose(const char *str, enum json_tokener_error *error) {
	struct json_tokener* tok;
	struct json_object* obj;

	tok = json_tokener_new();
	if (!tok)
		return NULL;
	obj = json_tokener_parse_ex(tok, str, -1);
	*error = tok->err;
	if(tok->err != json_tokener_success) {
		if (obj != NULL)
			json_object_put(obj);
		obj = NULL;
	}

	json_tokener_free(tok);
	return obj;
}
#endif

#ifndef HAVE_JSON_TOKENER_GET_ERROR
enum json_tokener_error json_tokener_get_error(json_tokener *tok) {
	return tok->err;
}
#endif

#ifndef HAVE_JSON_TOKENER_ERROR_DESC
const char *json_tokener_error_desc(enum json_tokener_error jerr) {
	int jerr_int = (int)jerr;
	if (json_tokener_errors[jerr_int] == NULL)
		return "Unknown error, invalid json_tokener_error value passed to json_tokener_error_desc()";
	return json_tokener_errors[jerr_int];
}
#endif
