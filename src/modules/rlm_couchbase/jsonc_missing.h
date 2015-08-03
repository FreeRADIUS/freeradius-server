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

/**
 * $Id$
 *
 * @brief Function prototypes for missing functions in older json-c libraries.
 * @file jsonc_missing.h
 *
 * @author Aaron Hurt <ahurt@anbcs.com>
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

#ifndef _jsonc_missing_h_
#define _jsonc_missing_h_

RCSIDH(jsonc_missing_h, "$Id$")

#include "config.h"

#if defined(HAVE_JSONMC_JSON_H)
#  include <json-c/json.h>
#elif defined(HAVE_JSON_JSON_H)
#  include <json/json.h>
#endif

#ifndef HAVE_JSON_C_VERSION
const char *json_c_version(void);
#endif

#ifndef HAVE_JSON_OBJECT_OBJECT_GET_EX
#  include <json/json_object_private.h>
#endif

#ifndef HAVE_JSON_OBJECT_GET_STRING_LEN
int json_object_get_string_len(struct json_object *obj);
#endif

#ifndef HAVE_JSON_OBJECT_OBJECT_GET_EX
int json_object_object_get_ex(struct json_object* jso, const char *key, struct json_object **value);
#endif

#ifndef HAVE_JSON_TOKENER_ERROR_DESC
const char *json_tokener_error_desc(enum json_tokener_error jerr);
#endif

#ifndef HAVE_JSON_TOKENER_GET_ERROR
enum json_tokener_error json_tokener_get_error(json_tokener *tok);
#endif

/* correct poor const handling within json-c library */
#ifdef json_object_object_foreach
#  undef json_object_object_foreach
#endif

/* redefine with correct handling of const pointers */
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#  define json_object_object_foreach(obj, key, val) \
	char *key = NULL; \
	struct json_object *val = NULL; \
	union ctn_u {const void *cdata; void *data; } ctn; \
	for (struct lh_entry *entry = json_object_get_object(obj)->head; \
		({ if (entry) { key = (char *)entry->k; ctn.cdata = entry->v; \
		val = (struct json_object *)ctn.data; }; entry; }); \
		entry = entry->next)
#else /* ANSI C or MSC */
#  define json_object_object_foreach(obj,key,val) \
	char *key = NULL; \
	struct json_object *val = NULL; \
	struct lh_entry *entry; \
	union ctn_u {const void *cdata; void *data; } ctn; \
	for (entry = json_object_get_object(obj)->head; \
		(entry ? (key = (char *)entry->k, ctn.cdata = entry->v, \
		val = (struct json_object *)ctn.data, entry) : 0); entry = entry->next)
#endif /* defined(__GNUC__) && !defined(__STRICT_ANSI__) */
#endif /* _jsonc_missing_h_ */
