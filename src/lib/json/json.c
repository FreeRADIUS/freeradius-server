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
 * @file json.c
 * @brief Common functions for working with json-c
 *
 * @author Arran Cudbard-Bell
 * @author Matthew Newton
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015,2020 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>
#include "base.h"

fr_table_num_sorted_t const fr_json_format_table[] = {
	{ L("array"),		JSON_MODE_ARRAY		},
	{ L("array_of_names"),	JSON_MODE_ARRAY_OF_NAMES	},
	{ L("array_of_values"),	JSON_MODE_ARRAY_OF_VALUES	},
	{ L("object"),		JSON_MODE_OBJECT		},
	{ L("object_simple"),	JSON_MODE_OBJECT_SIMPLE	},
};
size_t fr_json_format_table_len = NUM_ELEMENTS(fr_json_format_table);

static fr_json_format_t const default_json_format = {
	.attr = { .prefix = NULL },
	.value = { .value_is_always_array = true },
	.output_mode = JSON_MODE_OBJECT
};

static conf_parser_t const json_format_attr_config[] = {
	{ FR_CONF_OFFSET("prefix", fr_json_format_attr_t, prefix) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t const json_format_value_config[] = {
	{ FR_CONF_OFFSET("single_value_as_array", fr_json_format_value_t, value_is_always_array), .dflt = "no" },
	{ FR_CONF_OFFSET("enum_as_integer", fr_json_format_value_t, enum_as_int), .dflt = "no" },
	{ FR_CONF_OFFSET("always_string", fr_json_format_value_t, always_string), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

conf_parser_t const fr_json_format_config[] = {
	{ FR_CONF_OFFSET("output_mode", fr_json_format_t, output_mode_str), .dflt = "object" },
	{ FR_CONF_OFFSET_SUBSECTION("attribute", 0, fr_json_format_t, attr, json_format_attr_config) },
	{ FR_CONF_OFFSET_SUBSECTION("value", 0, fr_json_format_t, value, json_format_value_config) },

	CONF_PARSER_TERMINATOR
};

static inline CC_HINT(always_inline)
void json_object_put_assert(json_object *obj)
{
	int ret;

	ret = json_object_put(obj);
	if (ret == 1) return;

	fr_assert_fail("json_object_put did not free object (returned %u), likely leaking memory", ret);
}

/** Convert json object to fr_value_box_t
 *
 * @param[in] ctx	to allocate any value buffers in (should usually be the same as out).
 * @param[in] out	Where to write value.  Must be initialised.
 * @param[in] object	to convert.
 * @param[in] enumv	Any string values are assumed to be in PRESENTATION format, meaning
 *			that if an enumv is specified, they'll be checked against the list
 *			of aliases for that enumeration, and possibly converted into one of
 *			the enumeration values (which may not be a string).
 * @param[in] tainted	Whether the data source is untrusted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_json_object_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, json_object *object,
				fr_dict_attr_t const *enumv, bool tainted)
{
	switch (json_object_get_type(object)) {
	case json_type_string:
	{
		char const	*value;
		size_t		len;
		fr_dict_enum_value_t	*found;

		value = json_object_get_string(object);
		len = json_object_get_string_len(object);

		if (!enumv) goto no_enumv;

		if (fr_dict_valid_name(value, len) < 0) goto no_enumv;

		/*
		 *	If an alias exists, use that value instead
		 */
		found = fr_dict_enum_by_name(enumv, value, len);
		if (found) {
			if (fr_value_box_copy(ctx, out, found->value) < 0) return -1;
			return 0;
		}

	no_enumv:
		/*
		 *	Just copy the string to the box.
		 */
		fr_value_box_bstrndup(out, out, NULL, value, len, tainted);
	}
		break;

	case json_type_double:
		fr_value_box(out, json_object_get_double(object), tainted);
		break;

	case json_type_int:
	{
#ifdef HAVE_JSON_OBJECT_GET_INT64
		int64_t num;
#else
		int32_t num;
#endif

#ifndef HAVE_JSON_OBJECT_GET_INT64
		num = json_object_get_int(object);
#else
		num = json_object_get_int64(object);
		if (num < INT32_MIN) {			/* 64bit signed*/
			fr_value_box(out, (int64_t)num, tainted);
		} else if (num > UINT32_MAX) {		/* 64bit unsigned */
			fr_value_box(out, (uint64_t)num, tainted);
		} else
#endif
		if (num < INT16_MIN) {			/* 32bit signed */
			fr_value_box(out, (int32_t)num, tainted);
		} else if (num < INT8_MIN) {		/* 16bit signed */
			fr_value_box(out, (int16_t)num, tainted);
		} else if (num < 0) {			/* 8bit signed */
			fr_value_box(out, (int8_t)num, tainted);
		} else if (num > UINT16_MAX) {		/* 32bit unsigned */
			fr_value_box(out, (uint32_t)num, tainted);
		} else if (num > UINT8_MAX) {		/* 16bit unsigned */
			fr_value_box(out, (uint16_t)num, tainted);
		} else {				/* 8bit unsigned */
			fr_value_box(out, (uint8_t)num, tainted);
		}
	}
		break;

	case json_type_boolean:
		/* Must be cast to bool for correct generic case selection */
		fr_value_box(out, ((bool)(json_object_get_boolean(object) > 0)), tainted);
		break;

	case json_type_null:
	case json_type_array:
	case json_type_object:
	{
		char const *value = json_object_to_json_string(object);

		fr_value_box_bstrndup(out, out, NULL, value, strlen(value), tainted);
	}
		break;
	}

	out->tainted = tainted;

	return 0;
}

/** Convert boxed value_box to a JSON object
 *
 * @param[in] data	to convert.
 */
json_object *json_object_from_value_box(fr_value_box_t const *data)
{
	/*
	 *	We're converting to PRESENTATION format
	 *	so any attributes with enumeration values
	 *	should be converted to string types.
	 */
	if (data->enumv) {
		fr_dict_enum_value_t *enumv;

		enumv = fr_dict_enum_by_value(data->enumv, data);
		if (enumv) return json_object_new_string(enumv->name);
	}

	switch (data->type) {
	default:
	do_string:
	{
		char		buffer[64];
		fr_sbuff_t	sbuff = FR_SBUFF_IN(buffer, sizeof(buffer));

		if (fr_value_box_print(&sbuff, data, NULL) <= 0) return NULL;

		return json_object_new_string_len(buffer, fr_sbuff_used(&sbuff));
	}

	case FR_TYPE_STRING:
		return json_object_new_string_len(data->vb_strvalue, data->vb_length);

	case FR_TYPE_OCTETS:
		return json_object_new_string_len((char const *)data->vb_octets, data->vb_length);

	case FR_TYPE_BOOL:
		return json_object_new_boolean(data->vb_uint8);

	case FR_TYPE_UINT8:
		return json_object_new_int(data->vb_uint8);

	case FR_TYPE_UINT16:
		return json_object_new_int(data->vb_uint16);

#ifdef HAVE_JSON_OBJECT_GET_INT64
	case FR_TYPE_UINT32:
		return json_object_new_int64((int64_t)data->vb_uint64);	/* uint32_t (max) > int32_t (max) */

	case FR_TYPE_UINT64:
		if (data->vb_uint64 > INT64_MAX) goto do_string;
		return json_object_new_int64(data->vb_uint64);
#else
	case FR_TYPE_UINT32:
		if (data->vb_uint32 > INT32_MAX) goto do_string;
		return json_object_new_int(data->vb_uint32);
#endif

	case FR_TYPE_INT8:
		return json_object_new_int(data->vb_int8);

	case FR_TYPE_INT16:
		return json_object_new_int(data->vb_int16);

	case FR_TYPE_INT32:
		return json_object_new_int(data->vb_int32);

#ifdef HAVE_JSON_OBJECT_GET_INT64
	case FR_TYPE_INT64:
		return json_object_new_int64(data->vb_int64);

	case FR_TYPE_SIZE:
		return json_object_new_int64(data->vb_size);
#endif

	case FR_TYPE_STRUCTURAL:
		return NULL;
	}
}

/** Print a value box as its equivalent JSON format without going via a struct json_object (in most cases)
 *
 * @param[out] out		buffer to write to.
 * @param[in] vb		to print.
 * @param[in] include_quotes	whether we should wrap string values,
 *				or non-native types like IPv4 addresses in quotes.
 * @return
 *	- <0 on error.
 *	- >= number of bytes written.
 */
fr_slen_t fr_json_str_from_value(fr_sbuff_t *out, fr_value_box_t *vb, bool include_quotes)
{
	fr_sbuff_t our_out = FR_SBUFF(out);

	switch (vb->type) {
	case FR_TYPE_NULL:
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "null");
		break;

	case FR_TYPE_BOOL:
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, vb->vb_bool ? "true" : "false");
		break;

	/*
	 *	This is identical to JSON-C's escaping function
	 *	but we avoid creating JSON objects just to be able
	 *	to escape strings.
	 */
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
	{
		char const *last_app, *p, *end;

		if (include_quotes) FR_SBUFF_IN_CHAR_RETURN(&our_out, '"');

		last_app = p = vb->vb_strvalue;
		end = p + vb->vb_length;

		while (p < end) {
			if (*p < ' ') {
				if (p > last_app) FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, last_app, p - last_app);

				switch (*p) {
				case '\b':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\b");
					break;

				case '\n':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\n");
					break;

				case '\r':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\r");
					break;

				case '\t':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\t");
					break;

				case '\f':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\f");
					break;

				case '"':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\\"");
					break;

				case '\\':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\\\");
					break;

				case '/':
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\/");
					break;

				default:
					FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "\\u00");
					fr_base16_encode(&our_out, &FR_DBUFF_TMP((uint8_t const *)p, 1));
				}

				last_app = p + 1;
			}
			p++;
		}
		if (end > last_app) FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, last_app, end - last_app);
		if (include_quotes) FR_SBUFF_IN_CHAR_RETURN(&our_out, '"');
	}
		break;

	case FR_TYPE_UINT8:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", vb->vb_uint8);
		break;

	case FR_TYPE_UINT16:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", vb->vb_uint16);
		break;

	case FR_TYPE_UINT32:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", vb->vb_uint32);
		break;

	case FR_TYPE_UINT64:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", vb->vb_uint64);
		break;

	case FR_TYPE_INT8:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%i", vb->vb_int8);
		break;

	case FR_TYPE_INT16:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%i", vb->vb_int16);
		break;

	case FR_TYPE_INT32:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%i", vb->vb_int32);
		break;

	case FR_TYPE_INT64:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%i", vb->vb_int64);
		break;

	case FR_TYPE_SIZE:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zu", vb->vb_size);
		break;

	/*
	 *	It's too complex to replicate the float/double printing
	 *	here, so pass it off to JSON-C's printing functions.
	 */
	case FR_TYPE_FLOAT32:
	{
		struct json_object *obj;
		fr_slen_t slen;

		obj = json_object_new_double((double)vb->vb_float32);
		if (unlikely(obj == NULL)) return -1;
		slen = fr_sbuff_in_strcpy(&our_out, json_object_to_json_string(obj));
		json_object_put_assert(obj);
		return slen;
	}

	case FR_TYPE_FLOAT64:
	{
		struct json_object *obj;
		fr_slen_t slen;

		obj = json_object_new_double((double)vb->vb_float64);
		if (unlikely(obj == NULL)) return -1;
		slen = fr_sbuff_in_strcpy(&our_out, json_object_to_json_string(obj));
		json_object_put_assert(obj);
		return slen;
	}

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
	{
		fr_slen_t slen;

		if (include_quotes) FR_SBUFF_IN_CHAR_RETURN(&our_out, '"');
		slen = fr_value_box_print(&our_out, vb, NULL);
		if (include_quotes) FR_SBUFF_IN_CHAR_RETURN(&our_out, '"');
		if (slen < 0) return slen;
	}
		break;

	case FR_TYPE_STRUCTURAL:
		fr_strerror_const("Structural boxes not yet supported");
		return -1;

	case FR_TYPE_VOID:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_MAX:
		fr_strerror_printf("Box type %s cannot be converted to string", fr_type_to_str(vb->type));
		return -1;
	}

	return fr_sbuff_set(out, &our_out);
}

/** Print JSON-C version
 *
 */
void fr_json_version_print(void)
{
#ifdef HAVE_JSON_C_VERSION
	INFO("libfreeradius-json: json-c version: %s", json_c_version());
#else
	INFO("libfreeradius-json: json-c version: Unknown (less than 0.10) - Please upgrade");
#endif
}


/** Convert fr_pair_t into a JSON object
 *
 * If format.value.enum_as_int is set, and the given VP is an enum
 * value, the integer value is returned as a json_object rather
 * than the text representation.
 *
 * If format.value.always_string is set then a numeric value pair
 * will be returned as a JSON string object.
 *
 * @param[in] ctx	Talloc context.
 * @param[out] out	returned json object.
 * @param[in] vp	to get the value of.
 * @param[in] format	format definition, or NULL.
 * @return
 *	- 1 if 'out' is the integer enum value, 0 otherwise
 *	- -1 on error.
 */
static int json_afrom_value_box(TALLOC_CTX *ctx, json_object **out,
				fr_pair_t *vp, fr_json_format_t const *format)
{
	struct json_object	*obj;
	fr_value_box_t const	*vb;
	fr_value_box_t		vb_str = FR_VALUE_BOX_INITIALISER_NULL(vb_str);
	int			is_enum = 0;

	fr_assert(vp);

	vb = &vp->data;

	if (format && format->value.enum_as_int) {
		is_enum = fr_pair_value_enum_box(&vb, vp);
		fr_assert(is_enum >= 0);
	}

	if (format && format->value.always_string) {
		if (fr_value_box_cast(ctx, &vb_str, FR_TYPE_STRING, NULL, vb) < 0) {
			return -1;
		}

		vb = &vb_str;
	}

	MEM(obj = json_object_from_value_box(vb));

	if (format && format->value.always_string) {
		fr_value_box_clear(&vb_str);
	}

	*out = obj;
	return is_enum;
}


/** Get attribute name with optional prefix
 *
 * If the format "attr.prefix" string is set then prepend this
 * to the given attribute name, otherwise just return name alone.
 *
 * @param[out] out sbuff to write the new name
 * @param[in] da dictionary attribute to get name of
 * @param[in] format json format structure
 * @return length of attribute name
 */
static inline ssize_t attr_name_with_prefix(fr_sbuff_t *out, fr_dict_attr_t const *da, fr_json_format_t const *format)
{
	fr_sbuff_t our_out;

	if (!out) return 0;

	our_out = FR_SBUFF(out);

	if (format->attr.prefix) {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, format->attr.prefix);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ':');
	}

	FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, da->name, da->name_len);

	FR_SBUFF_SET_RETURN(out, &our_out);
}


/** Verify that the options in fr_json_format_t are valid
 *
 * Warnings are optional, will fatal error if the format is corrupt.
 *
 * @param[in] format	the format structure to check
 * @param[in] verbose	print out warnings if set
 * @return		true if format is good, otherwise false
 */
bool fr_json_format_verify(fr_json_format_t const *format, bool verbose)
{
	bool ret = true;

	fr_assert(format);

	switch (format->output_mode) {
	case JSON_MODE_OBJECT:
	case JSON_MODE_OBJECT_SIMPLE:
	case JSON_MODE_ARRAY:
		/* all options are valid */
		return true;
	case JSON_MODE_ARRAY_OF_VALUES:
		if (format->attr.prefix) {
			if (verbose) WARN("attribute name prefix not valid in output_mode 'array_of_values' and will be ignored");
			ret = false;
		}
		if (format->value.value_is_always_array) {
			if (verbose) WARN("'value_is_always_array' not valid in output_mode 'array_of_values' and will be ignored");
			ret = false;
		}
		return ret;
	case JSON_MODE_ARRAY_OF_NAMES:
		if (format->value.value_is_always_array) {
			if (verbose) WARN("'value_is_always_array' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		if (format->value.enum_as_int) {
			if (verbose) WARN("'enum_as_int' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		if (format->value.always_string) {
			if (verbose) WARN("'always_string' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		return ret;
	default:
		ERROR("JSON format output mode is invalid");
	}

	/* If we get here, something has gone wrong */
	fr_assert(0);

	return false;
}

#define INVALID_TYPE \
do { \
	fr_assert(0); \
	fr_strerror_printf("Invalid type %s for attribute %s", fr_type_to_str(vp->vp_type), vp->da->name); \
	return NULL; \
} while (0)

/** Returns a JSON object representation of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "object" format, JSON_MODE_OBJECT.
 * @see fr_json_format_s
 *
@verbatim
{
	"<attribute0>":{
		"type":"<type0>",
		"value":[<value0>,<value1>,<valueN>]		// if value_is_always_array is true
	},							// or
	"<attribute1>":{
		"type":"<type1>",
		"value":<value0>				// if value_is_always_array is false
								// and there is only one value
	},
	"<attributeN>":{
		"type":"<typeN>",
		"value":[...]
	}
}
@endverbatim
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static json_object *json_object_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
						fr_json_format_t const *format)
{
	fr_pair_t		*vp;
	struct json_object	*obj;
	char			buf[FR_DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(format);
	fr_assert(format->output_mode == JSON_MODE_OBJECT);

	MEM(obj = json_object_new_object());

	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		fr_sbuff_t		attr_name;
		struct json_object	*vp_object, *values, *value, *type_name;

		if (vp->vp_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init_in(&attr_name, buf, sizeof(buf) - 1);
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
				fr_strerror_const("Failed to convert attribute value to JSON object");
			error:
				json_object_put_assert(obj);

				return NULL;
			}
			break;
		/*
		 *	For nested attributes we recurse.  The nesting is represented
		 *	as a table, either as the single value, or as an element in
		 *	an array.
		 *
		 *	...
		 *	"value" : { "nested_attr" : { "type" : "<nested_type>", "value" : "<nested_attr_value>" } }
		 *	...
		 *
		 *	...
		 *	"value" : [ { "nested_attr" : { "type" : "<nested_type>", "value" : "<nested_attr_value>" } } ]
		 *	...
		 *
		 *	The formatting of nested attributes and their structure is
		 *	identical to top level attributes.
		 */
		case FR_TYPE_STRUCTURAL:
			value = json_object_afrom_pair_list(ctx, &vp->vp_group, format);
			break;

		default:
			INVALID_TYPE;
		}

		/*
		 *	Look in the table to see if we already have a key for the attribute
		 *	we're working on.
		 *
		 *	If we don't we create a new object in either the form:
		 *
		 *	"<attribute>": {
		 *		"type": "<type>",
		 *		"value": [<value>]		// if value_is_always_array is true
		 *						// or
		 *		"value": <value>		// if value_is_always_array is false
		 *						// and there is only one value
		 *	}
		 */
		if (!json_object_object_get_ex(obj, fr_sbuff_start(&attr_name), &vp_object)) {
			/*
			 *	Wasn't there, so create a new object for this attribute.
			 */
			MEM(vp_object = json_object_new_object());
			json_object_object_add(obj, fr_sbuff_start(&attr_name), vp_object);

			/*
			 *	Add "type" to newly created keys.
			 */
			MEM(type_name = json_object_new_string(fr_type_to_str(vp->vp_type)));
			json_object_object_add_ex(vp_object, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);

			/*
			 *	Create a "value" array to hold any attribute values for this attribute...
			 */
			if (format->value.value_is_always_array) {
				MEM(values = json_object_new_array());
				json_object_object_add_ex(vp_object, "value", values, JSON_C_OBJECT_KEY_IS_CONSTANT);
				json_object_array_add(values, value);
				continue;
			}

			/*
			 *	...or just add the value directly.
			 */
			json_object_object_add_ex(vp_object, "value", value, JSON_C_OBJECT_KEY_IS_CONSTANT);

			continue;	/* Next attribute! */
		}

		/*
		 *	Find the 'values' array to add the current value to.
		 */
		if (!fr_cond_assert(json_object_object_get_ex(vp_object, "value", &values))) {
			fr_strerror_const("Inconsistent JSON tree");
			goto error;
		}

		/*
		 *	If value_is_always_array is no set then "values" may not be an array, so it will
		 *	need converting to an array to add this extra attribute.
		 */
		if (!format->value.value_is_always_array) {
			json_type		type;
			struct json_object	*convert_value = values;

			/* Check "values" type */
			type = json_object_get_type(values);

			/* It wasn't an array, so turn it into one with the old value as the first entry */
			if (type != json_type_array) {
				MEM(values = json_object_new_array());
				json_object_array_add(values, json_object_get(convert_value));
				json_object_object_del(vp_object, "value");
				json_object_object_add_ex(vp_object, "value", values,
								JSON_C_OBJECT_KEY_IS_CONSTANT);
			}
		}
		json_object_array_add(values, value);
	}

	return obj;
}


/** Returns a JSON object representation of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "simple object" format, JSON_MODE_OBJECT_SIMPLE.
 * @see fr_json_format_s
 *
@verbatim
{
	"<attribute0>":[<value0>,<value1>,<valueN>]	// if value_is_always_array is true
							// or
	"<attribute1>":<value0>				// if value_is_always_array is false,
							// and there is only one value
	"<attributeN>":[<value0>,<value1>,<valueN>]
}
@endverbatim
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static json_object *json_smplobj_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
						 fr_json_format_t const *format)
{
	fr_pair_t		*vp;
	struct json_object	*obj;
	char			buf[FR_DICT_ATTR_MAX_NAME_LEN + 32];
	json_type		type;

	/* Check format and type */
	fr_assert(format);
	fr_assert(format->output_mode == JSON_MODE_OBJECT_SIMPLE);

	MEM(obj = json_object_new_object());

	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		fr_sbuff_t		attr_name;
		struct json_object	*vp_object, *value;
		struct json_object	*values = NULL;
		bool			add_single = false;

		if (vp->vp_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init_in(&attr_name, buf, sizeof(buf) - 1);
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
				fr_strerror_const("Failed to convert attribute value to JSON object");
				json_object_put_assert(obj);

				return NULL;
			}
			break;
		/*
		 *	For nested attributes we recurse.  The nesting is represented
		 *	as a table, either as the single value, or as an element in
		 *	an array.
		 *
		 *	...
		 *	"<parent>" : { "<nested_attr>" : <nested_attr_value> }
		 *	...
		 *
		 *	...
		 *	"<parent>" : [ { "<nested_attr>" : "<nested_attr_value>" } ]
		 *	...
		 *
		 *	The formatting of nested attributes and their structure is
		 *	identical to top level attributes.
		 */
		case FR_TYPE_STRUCTURAL:
			value = json_smplobj_afrom_pair_list(ctx, &vp->vp_group, format);
			break;

		default:
			INVALID_TYPE;
		}

		/*
		 *	See if we already have a key in the table we're working on,
		 *	if not then create a new one.
		 */
		if (!json_object_object_get_ex(obj, fr_sbuff_start(&attr_name), &vp_object)) {
			if (format->value.value_is_always_array) {
				/*
				 *	We have been asked to ensure /all/ values are lists,
				 *	even if there's only one attribute.
				 */
				MEM(values = json_object_new_array());
				json_object_object_add(obj, fr_sbuff_start(&attr_name), values);
			} else {
				/*
				 *	Deal with it later on.
				 */
				add_single = true;
			}
		/*
		 *	If we do have the key already, get its value array.
		 */
		} else {
			type = json_object_get_type(vp_object);

			if (type == json_type_array) {
				values = vp_object;
			} else {
				/*
				 *	We've seen one of these before, but didn't add
				 *	it as an array the first time. Sort that out.
				 */
				MEM(values = json_object_new_array());
				json_object_array_add(values, json_object_get(vp_object));

				/*
				 *	Existing key will have refcount decremented
				 *	and will be freed if this drops to zero.
				 */
				json_object_object_add(obj, fr_sbuff_start(&attr_name), values);
			}
		}

		if (add_single) {
			/*
			 *	Only ever used the first time adding a new
			 *	attribute when "value_is_always_array" is not set.
			 */
			json_object_object_add(obj, fr_sbuff_start(&attr_name), value);
		} else {
			/*
			 *	Otherwise we're always appending to a JSON array.
			 */
			json_object_array_add(values, value);
		}
	}

	return obj;
}


/** Returns a JSON array representation of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "array" format, JSON_MODE_ARRAY.
 * @see fr_json_format_s
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_array_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
						      fr_json_format_t const *format)
{
	fr_pair_t		*vp;
	struct json_object	*obj;
	struct json_object	*seen_attributes = NULL;
	char			buf[FR_DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(format);
	fr_assert(format->output_mode == JSON_MODE_ARRAY);

	MEM(obj = json_object_new_array());

	/*
	 *	If attribute values should be in a list format, then keep track
	 *	of the attributes we've previously seen in a JSON object.
	 */
	if (format->value.value_is_always_array) {
		seen_attributes = json_object_new_object();
	}

	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		fr_sbuff_t		attr_name;
		struct json_object	*name, *value, *type_name;
		struct json_object	*values = NULL;
		struct json_object	*attrobj = NULL;
		bool			already_seen = false;

		if (vp->vp_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init_in(&attr_name, buf, sizeof(buf) - 1);
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
				fr_strerror_const("Failed to convert attribute value to JSON object");
				json_object_put_assert(obj);
				return NULL;
			}
			break;

		case FR_TYPE_STRUCTURAL:
			value = json_array_afrom_pair_list(ctx, &vp->vp_group, format);
			break;

		default:
			INVALID_TYPE;
		}

		if (format->value.value_is_always_array) {
			/*
			 *	Try and find this attribute in the "seen_attributes" object. If it is
			 *	there then get the "values" array to add this attribute value to.
			 */
			already_seen = json_object_object_get_ex(seen_attributes, fr_sbuff_start(&attr_name), &values);
		}

		/*
		 *	If we're adding all attributes to the toplevel array, or we're adding values
		 *	to an array of an existing attribute but haven't seen it before, then we need
		 *	to create a new JSON object for this attribute.
		 */
		if (!format->value.value_is_always_array || !already_seen) {
			/*
			 * Create object and add it to top-level array
			 */
			MEM(attrobj = json_object_new_object());
			json_object_array_add(obj, attrobj);

			/*
			 * Add the attribute name in the "name" key and the type in the "type" key
			 */
			MEM(name = json_object_new_string(fr_sbuff_start(&attr_name)));
			json_object_object_add_ex(attrobj, "name", name, JSON_C_OBJECT_KEY_IS_CONSTANT);

			MEM(type_name = json_object_new_string(fr_type_to_str(vp->vp_type)));
			json_object_object_add_ex(attrobj, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);
		}

		if (format->value.value_is_always_array) {
			/*
			 *	We're adding values to an array for the first copy of this attribute
			 *	that we saw. First time around we need to create an array.
			 */
			if (!already_seen) {
				MEM(values = json_object_new_array());
				/*
				 * Add "value":[] key to the attribute object
				 */
				json_object_object_add_ex(attrobj, "value", values, JSON_C_OBJECT_KEY_IS_CONSTANT);

				/*
				 * Also add to "seen_attributes" to check later
				 */
				json_object_object_add(seen_attributes, fr_sbuff_start(&attr_name), json_object_get(values));
			}

			/*
			 *	Always add the value to the respective "values" array.
			 */
			json_object_array_add(values, value);
		} else {
			/*
			 * This is simpler; just add a "value": key to the attribute object.
			 */
			json_object_object_add_ex(attrobj, "value", value, JSON_C_OBJECT_KEY_IS_CONSTANT);
		}

	}

	/*
	 *	No longer need the "seen_attributes" object, it was just used for tracking.
	 */
	if (format->value.value_is_always_array) {
		json_object_put_assert(seen_attributes);
	}

	return obj;
}


/** Returns a JSON array of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "array_of_values" format,
 * JSON_MODE_ARRAY_OF_VALUES, listing just the attribute values.
 * @see fr_json_format_s
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_value_array_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
							    fr_json_format_t const *format)
{
	fr_pair_t		*vp;
	struct json_object	*obj;

	/* Check format and type */
	fr_assert(format);
	fr_assert(format->output_mode == JSON_MODE_ARRAY_OF_VALUES);

	MEM(obj = json_object_new_array());

	/*
	 *	This array format is very simple - just add all the
	 *	attribute values to the array in order.
	 */
	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		struct json_object	*value;

		if (vp->vp_raw) continue;

		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
				fr_strerror_const("Failed to convert attribute value to JSON object");
				json_object_put_assert(obj);
				return NULL;
			}
			break;

		case FR_TYPE_STRUCTURAL:
			value = json_value_array_afrom_pair_list(ctx, &vp->vp_group, format);
			break;

		default:
			INVALID_TYPE;
		}

		json_object_array_add(obj, value);
	}

	return obj;
}


/** Returns a JSON array of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "array_of_names" format,
 * JSON_MODE_ARRAY_OF_NAMES, listing just the attribute names.
 * @see fr_json_format_s
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_attr_array_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
							   fr_json_format_t const *format)
{
	fr_pair_t		*vp;
	struct json_object	*obj;
	char			buf[FR_DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(format);
	fr_assert(format->output_mode == JSON_MODE_ARRAY_OF_NAMES);

	MEM(obj = json_object_new_array());

	/*
	 *	Add all the attribute names to the array in order.
	 */
	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		struct json_object	*value;
		fr_sbuff_t		attr_name;

		if (vp->vp_raw) continue;

		fr_sbuff_init_in(&attr_name, buf, sizeof(buf) - 1);
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}
		value = json_object_new_string(fr_sbuff_start(&attr_name));

		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			break;

		case FR_TYPE_STRUCTURAL:
			json_object_array_add(obj, value);
			value = json_attr_array_afrom_pair_list(ctx, &vp->vp_group, format);
			break;

		default:
			INVALID_TYPE;
		}

		json_object_array_add(obj, value);
	}

	return obj;
}


/** Returns a JSON string of a list of value pairs
 *
 * The result is a talloc-ed string, freeing the string is
 * the responsibility of the caller.
 *
 * The 'format' struct contains settings to configure the output
 * JSON document format.
 * @see fr_json_format_s
 *
 * Default output, when format is NULL, is:
@verbatim
{
	"<attribute0>":{
		"type":"<type0>",
		"value":[<value0>,<value1>,<valueN>]
	},
	"<attribute1>":{
		"type":"<type1>",
		"value":[...]
	},
	"<attributeN>":{
		"type":"<typeN>",
		"value":[...]
	}
}
@endverbatim
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] format	Formatting control, can be NULL to use default format.
 * @return JSON string representation of the value pairs
 */
char *fr_json_afrom_pair_list(TALLOC_CTX *ctx, fr_pair_list_t *vps,
			      fr_json_format_t const *format)
{
	struct json_object	*obj = NULL;
	const char		*p;
	char			*out;

	if (!format) format = &default_json_format;

	switch (format->output_mode) {
	case JSON_MODE_OBJECT:
		MEM(obj = json_object_afrom_pair_list(ctx, vps, format));
		break;
	case JSON_MODE_OBJECT_SIMPLE:
		MEM(obj = json_smplobj_afrom_pair_list(ctx, vps, format));
		break;
	case JSON_MODE_ARRAY:
		MEM(obj = json_array_afrom_pair_list(ctx, vps, format));
		break;
	case JSON_MODE_ARRAY_OF_VALUES:
		MEM(obj = json_value_array_afrom_pair_list(ctx, vps, format));
		break;
	case JSON_MODE_ARRAY_OF_NAMES:
		MEM(obj = json_attr_array_afrom_pair_list(ctx, vps, format));
		break;
	default:
		/* This should never happen */
		fr_assert(0);
	}

	/*
	 *	p is a buff inside obj, and will be freed
	 *	when it is freed.
	 */
	MEM(p = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
	MEM(out = talloc_typed_strdup(ctx, p));

	/*
	 * Free the JSON structure, it's not needed any more
	 */
	json_object_put_assert(obj);

	return out;
}
