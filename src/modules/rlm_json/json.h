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
 * @copyright 2015,2021 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
RCSIDH(json_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include "config.h"

#ifdef HAVE_JSON

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif

#  if defined(HAVE_JSONMC_JSON_H)
#    include <json-c/json.h>
#  elif defined(HAVE_JSON_JSON_H)
#    include <json/json.h>
#  else
#    error "Need json-c headers"
#  endif

#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

/* for json-c < 0.13 */
#ifndef HAVE_JSON_OBJECT_OBJECT_ADD_EX
#  define json_object_object_add_ex(_obj, _key, _val, _opt) json_object_object_add(_obj, _key, _val)
#endif

#  include <freeradius-devel/radiusd.h>

extern const FR_NAME_NUMBER fr_json_format_table[];

/** List of possible JSON format output modes.
 *
 */
typedef enum {
	JSON_MODE_UNSET = 0,
	JSON_MODE_OBJECT,
	JSON_MODE_OBJECT_SIMPLE,
	JSON_MODE_ARRAY,
	JSON_MODE_ARRAY_OF_VALUES,
	JSON_MODE_ARRAY_OF_NAMES
} json_mode_type_t;

/** rlm_json module instance
 *
 */
typedef struct {
	char const		*attr_prefix;	//!< Prefix to add to all attribute names
	bool			value_as_array;	//!< Use JSON array for multiple attribute values.
	bool			enum_as_int;	//!< Output enums as value, not their string representation.
	bool			dates_as_int;	//!< Output dates as epoch seconds, not their string representation.
	bool			always_string;	//!< Output all data types as strings.


	char const		*output_mode_str;	//!< For CONF_PARSER only.
	json_mode_type_t	output_mode;	//!< Determine the format of JSON document to generate.

	bool			include_type;	//!< Include attribute type where possible.

	char const		*name;
} rlm_json_t;


json_object	*json_object_from_attr_value(TALLOC_CTX *ctx, VALUE_PAIR const *vp, bool always_string, bool enum_as_int, bool dates_as_int);
void		fr_json_version_print(void);
char		*fr_json_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
					 rlm_json_t const *format);
bool		fr_json_format_verify(rlm_json_t const *inst, bool verbose);
char		*fr_json_from_string(TALLOC_CTX *ctx, char const *s, bool include_quotes);
#endif
