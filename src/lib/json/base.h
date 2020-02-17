#pragma once
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
 * @file lib/json/base.h
 * @brief Implements the evaluation and parsing functions for the FreeRADIUS version of jpath.
 *
 * @author Arran Cudbard-Bell
 * @author Matthew Newton
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015,2020 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
RCSIDH(json_h, "$Id$")

#include "config.h"

#ifdef HAVE_JSON
#  if defined(HAVE_JSONMC_JSON_H)
#    include <json-c/json.h>
#  elif defined(HAVE_JSON_JSON_H)
#    include <json/json.h>
#  else
#    error "Need json-c headers"
#  endif
#  include "json_missing.h"

#  include <freeradius-devel/server/base.h>

extern fr_table_num_sorted_t const fr_json_format_table[];
extern size_t fr_json_format_table_len;

/** List of possible JSON format output modes.
 *
 * @see fr_json_format_s
 */
typedef enum {
	JSON_MODE_UNSET = 0,
	JSON_MODE_OBJECT,
	JSON_MODE_OBJECT_SIMPLE,
	JSON_MODE_ARRAY,
	JSON_MODE_ARRAY_OF_VALUES,
	JSON_MODE_ARRAY_OF_NAMES
} json_mode_type_t;


/** Attribute formatting options for fr_json_afrom_pair_list()
 *
 * Controls how attributes are formatted in JSON documents
 * produced from fr_json_afrom_pair_list().
 *
 * **prefix** adds a string prefix to all attribute names in the
 * JSON document, with a colon delimiter.
 *
 * Example, when prefix is NULL:
@verbatim
{"User-Name":{"type":"string","value":["john"]}}
@endverbatim
 *
 * Example, when prefix is set to `foo`:
@verbatim
{"foo:User-Name":{"type":"string","value":["john"]}}
@endverbatim
 *
 * @see struct fr_json_format_s
 *
 */
typedef struct {
	char const *prefix;	//!< Prefix to add to all attribute names
} fr_json_format_attr_t;


/** Value formatting options for fr_json_afrom_pair_list()
 *
 * Controls how values are formatted in JSON documents
 * produced from fr_json_afrom_pair_list().
 *
 * Not all these options are valid for all output modes.
 * @see fr_json_format_verify(), fr_json_format_s
 *
 *
 * If an attribute appears only once then the value will normally
 * be written as an object. When an attribute appears more than
 * once then the values will be added as an array instead. Setting
 * **value_as_array** will ensure that values are always written as
 * an array, even if containing only a single entry.
 *
 * Example with output_mode `JSON_MODE_OBJECT_SIMPLE` and `value_as_array` is false:
@verbatim
{"User-Name":"john","Filter-Id":["f1","f2"]}
@endverbatim
 *
 * Example with output_mode `JSON_MODE_OBJECT_SIMPLE` and `value_as_array` is true:
@verbatim
{"User-Name":["john"],"Filter-Id":["f1","f2"]}
@endverbatim
 *
 *
 * Set **enum_as_int** to write enumerated values in their integer form.
 *
 * When false, the string form is output:
@verbatim
{"Service-Type":{"type":"uint32","value":"Login-User"}}
@endverbatim
 *
 * When true, the integer is output:
@verbatim
{"Service-Type":{"type":"uint32","value":1}}
@endverbatim
 *
 *
 * Numeric data types will usually be written to the JSON document
 * as numbers. **always_string** ensures that all values are written as
 * strings:
 *
 * Example when `always_string` is false:
@verbatim
{"NAS-Port":{"type":"uint32","value":999}}
@endverbatim
 *
 * Example when `always_string` is true:
@verbatim
{"NAS-Port":{"type":"uint32","value":"999"}}
@endverbatim
 *
 */
typedef struct {
	bool	value_as_array;	//!< Use JSON array for multiple attribute values.
	bool	enum_as_int;	//!< Output enums as value, not their string representation.
	bool	always_string;	//!< Output all data types as strings.
} fr_json_format_value_t;


/** JSON document formatting options
 *
 * These options control the format of JSON document which is
 * produced by fr_json_afrom_pair_list().
 *
 * The **output_mode** determines the format of JSON that is created:
 *
 * When JSON_MODE_OBJECT:
@verbatim
{
	"<attribute0>": {
		"type":"<str-type0>",
		"value":["value0"]
	},
	"<attribute1>": {
		"type":"<str-type1>",
		"value":["value1.0", "value1.1"]
	},
	"<attribute2>": {
		"type":"<int-type2>",
		"value":[2]
	},
}
@endverbatim
 *
 * When JSON_MODE_OBJECT_SIMPLE:
@verbatim
{
	"<attribute0>":"<value0>",
	"<attribute1>":["<value1.0>","<value1.1>"],
	"<attribute2>":2
}
@endverbatim
 *
 * When JSON_MODE_ARRAY:
@verbatim
[
	{"name":"<attribute0>","type":"<str-type0>","value":"<value0>"},
	{"name":"<attribute1>","type":"<str-type1>","value":"<value1.0>"},
	{"name":"<attribute1>","type":"<str-type1>","value":"<value1.1>"},
	{"name":"<attribute2>","type":"<int-type2>","value":2}
]
@endverbatim
 *
 * When JSON_MODE_ARRAY_OF_VALUES:
@verbatim
[
	<value0>,
	<value1.0>,
	<value1.1>,
	<value2>
]
@endverbatim
 *
 * When JSON_MODE_ARRAY_OF_NAMES:
@verbatim
[
	<attribute0>,
	<attribute1>,
	<attribute1>,
	<attribute2>
]
@endverbatim
 *
 */
struct fr_json_format_s {
	char const		*output_mode_str;	//!< For CONF_PARSER only.

	json_mode_type_t	output_mode;		//!< Determine the format of JSON document
							//!< to generate.

	fr_json_format_attr_t	attr;			//!< Formatting options for attribute names.
	fr_json_format_value_t	value;			//!< Formatting options for attribute values.

	bool			include_type;		//!< Include attribute type where possible.
};

typedef struct fr_json_format_s fr_json_format_t;


/* jpath .c */
typedef struct fr_jpath_node fr_jpath_node_t;

size_t		fr_jpath_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				     char const *in, UNUSED void *arg);

int		fr_jpath_evaluate_leaf(TALLOC_CTX *ctx, fr_value_box_t **out,
				       fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				       json_object *root, fr_jpath_node_t const *jpath);

char		*fr_jpath_asprint(TALLOC_CTX *ctx, fr_jpath_node_t const *head);

ssize_t		fr_jpath_parse(TALLOC_CTX *ctx, fr_jpath_node_t **head, char const *in, size_t inlen);

/* json.c */
int		fr_json_object_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, json_object *object,
					    fr_dict_attr_t const *enumv, bool tainted);

json_object	*json_object_from_value_box(TALLOC_CTX *ctx, fr_value_box_t const *data);

char		*fr_json_from_string(TALLOC_CTX *ctx, char const *s, bool include_quotes);

size_t    	fr_json_from_pair(char *out, size_t outlen, VALUE_PAIR const *vp);

void		fr_json_version_print(void);

char		*fr_json_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
					 fr_json_format_t const *format);
#endif
