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
 * @copyright 2015,2020 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
#include <freeradius-devel/util/debug.h>
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
	.value = { .value_as_array = true },
};

static CONF_PARSER const json_format_attr_config[] = {
	{ FR_CONF_OFFSET("prefix", FR_TYPE_STRING, fr_json_format_attr_t, prefix) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const json_format_value_config[] = {
	{ FR_CONF_OFFSET("single_value_as_array", FR_TYPE_BOOL, fr_json_format_value_t, value_as_array), .dflt = "no" },
	{ FR_CONF_OFFSET("enum_as_integer", FR_TYPE_BOOL, fr_json_format_value_t, enum_as_int), .dflt = "no" },
	{ FR_CONF_OFFSET("always_string", FR_TYPE_BOOL, fr_json_format_value_t, always_string), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

CONF_PARSER const fr_json_format_config[] = {
	{ FR_CONF_OFFSET("output_mode", FR_TYPE_STRING, fr_json_format_t, output_mode_str), .dflt = "object" },
	{ FR_CONF_OFFSET("attribute", FR_TYPE_SUBSECTION, fr_json_format_t, attr),
		.subcs = (void const *) json_format_attr_config },
	{ FR_CONF_OFFSET("value", FR_TYPE_SUBSECTION, fr_json_format_t, value),
		.subcs = (void const *) json_format_value_config },

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
		fr_value_box_bstrndup(ctx, out, NULL, value, len, tainted);
	}
		break;

	case json_type_double:
		fr_value_box_shallow(out, json_object_get_double(object), tainted);
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
			fr_value_box_shallow(out, (int64_t)num, tainted);
		} else if (num > UINT32_MAX) {		/* 64bit unsigned */
			fr_value_box_shallow(out, (uint64_t)num, tainted);
		} else
#endif
		if (num < INT16_MIN) {			/* 32bit signed */
			fr_value_box_shallow(out, (int32_t)num, tainted);
		} else if (num < INT8_MIN) {		/* 16bit signed */
			fr_value_box_shallow(out, (int16_t)num, tainted);
		} else if (num < 0) {			/* 8bit signed */
			fr_value_box_shallow(out, (int8_t)num, tainted);
		} else if (num > UINT16_MAX) {		/* 32bit unsigned */
			fr_value_box_shallow(out, (uint32_t)num, tainted);
		} else if (num > UINT8_MAX) {		/* 16bit unsigned */
			fr_value_box_shallow(out, (int16_t)num, tainted);
		} else {				/* 8bit unsigned */
			fr_value_box_shallow(out, (int8_t)num, tainted);
		}
	}
		break;

	case json_type_boolean:
		/* Must be cast to bool for correct generic case selection */
		fr_value_box_shallow(out, ((bool)(json_object_get_boolean(object) > 0)), tainted);
		break;

	case json_type_null:
	case json_type_array:
	case json_type_object:
	{
		char const *value = json_object_to_json_string(object);

		fr_value_box_bstrndup(ctx, out, NULL, value, strlen(value), tainted);
	}
		break;
	}

	out->tainted = tainted;

	return 0;
}

/** Convert boxed value_box to a JSON object
 *
 * @param[in] ctx	to allocate temporary buffers in
 * @param[in] data	to convert.
 */
json_object *json_object_from_value_box(TALLOC_CTX *ctx, fr_value_box_t const *data)
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
		char		*p;
		json_object	*obj;

		fr_value_box_aprint(ctx, &p, data, NULL);
		if (!p) return NULL;

		obj = json_object_new_string_len(p, talloc_array_length(p) - 1);
		talloc_free(p);

		return obj;
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
		return json_object_new_in(data->vb_uint32);
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
	}
}

/** Escapes string for use as a JSON string
 *
 * @param ctx Talloc context to allocate this string
 * @param s Input string
 * @param include_quotes Include the surrounding quotes of JSON strings
 * @return New allocated character string, or NULL if something failed.
 */
char *fr_json_from_string(TALLOC_CTX *ctx, char const *s, bool include_quotes)
{
	char const *p;
	char *out = NULL;
	struct json_object *json;
	int len;

	json = json_object_new_string(s);
	if (!json) return NULL;

	if ((p = json_object_to_json_string(json))) {
		if (include_quotes) {
			out = talloc_typed_strdup(ctx, p);
		} else {
			len = strlen(p);
			out = talloc_bstrndup(ctx, p + 1, len - 2);	/* to_json_string adds quotes (") */
		}
	}

	/*
	 * Free the JSON structure, it's not needed any more
	 */
	json_object_put_assert(json);

	return out;
}

/** Prints attribute as string, escaped suitably for use as JSON string
 *
 *  Returns < 0 if the buffer may be (or have been) too small to write the encoded
 *  JSON value to.
 *
 * @param out Where to write the string.
 * @param outlen Length of output buffer.
 * @param vp to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
size_t fr_json_from_pair(char *out, size_t outlen, fr_pair_t const *vp)
{
	ssize_t slen;
	size_t freespace = outlen;

	switch (vp->vp_type) {
	case FR_TYPE_UINT32:
		if (vp->da->flags.has_value) break;

		return snprintf(out, freespace, "%u", vp->vp_uint32);

	case FR_TYPE_UINT16:
		if (vp->da->flags.has_value) break;

		return snprintf(out, freespace, "%u", (unsigned int) vp->vp_uint16);

	case FR_TYPE_UINT8:
		if (vp->da->flags.has_value) break;

		return snprintf(out, freespace, "%u", (unsigned int) vp->vp_uint8);

	case FR_TYPE_INT32:
		return snprintf(out, freespace, "%d", vp->vp_int32);

	default:
		break;
	}

	if (vp->vp_type == FR_TYPE_STRING) {
		char *tmp = fr_json_from_string(NULL, vp->vp_strvalue, true);
		/* Indicate truncation */
		if (!tmp) return outlen + 1;
		slen = strlen(tmp);
		if (freespace <= (size_t)slen) return outlen + 1;

		strcpy(out, tmp);
		talloc_free(tmp);

		return slen;
	}

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;

	slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(out, freespace), vp, T_BARE_WORD);
	if (slen < 0) return slen;

	out += (size_t)slen;
	freespace -= (size_t)slen;

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;
	*out = '\0'; // We don't increment out, because the nul byte should not be included in the length

	return outlen - freespace;
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
	fr_value_box_t		vb_str;
	int			is_enum = 0;

	fr_assert(vp);

	vb = &vp->data;

	if (format && format->value.enum_as_int) {
		is_enum = fr_pair_value_enum_box(&vb, vp);
		fr_assert(is_enum >= 0);
	}

	if (format && format->value.always_string) {
		if (fr_value_box_cast(ctx, &vb_str, FR_TYPE_STRING, NULL, vb) == 0) {
			vb = &vb_str;
		} else {
			return -1;
		}
	}

	MEM(obj = json_object_from_value_box(ctx, vb));

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
	fr_sbuff_t our_out = FR_SBUFF(out);

	if (!out) return 0;

	if (format->attr.prefix) {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, format->attr.prefix);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ':');
	}

	FR_DICT_ATTR_OID_PRINT_RETURN(&our_out, NULL, da, false);

	return fr_sbuff_set(out, &our_out);
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
		if (format->value.value_as_array) {
			if (verbose) WARN("'value_as_array' not valid in output_mode 'array_of_values' and will be ignored");
			ret = false;
		}
		return ret;
	case JSON_MODE_ARRAY_OF_NAMES:
		if (format->value.value_as_array) {
			if (verbose) WARN("'value_as_array' not valid in output_mode 'array_of_names' and will be ignored");
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


/** Returns a JSON object representation of a list of value pairs
 *
 * The result is a struct json_object, which should be free'd with
 * json_object_put() by the caller. Intended to only be called by
 * fr_json_afrom_pair_list().
 *
 * This function generates the "object" format, JSON_MODE_OBJECT.
 * @see fr_json_format_s
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

		if (vp->da->flags.is_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init(&attr_name, buf, sizeof(buf));
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
			fr_strerror_const("Failed to convert attribute value to JSON object");
		error:
			json_object_put_assert(obj);

			return NULL;
		}

		/*
		 *	Look in the table to see if we already have
		 *	a key for the attribute we're working on.
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
			MEM(type_name = json_object_new_string(fr_table_str_by_value(fr_value_box_type_table,
										     vp->vp_type, "<INVALID>")));
			json_object_object_add_ex(vp_object, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);

			/*
			 *	Create a "value" array to hold any attribute values for this attribute...
			 */
			if (format->value.value_as_array) {
				MEM(values = json_object_new_array());
				json_object_object_add_ex(vp_object, "value", values, JSON_C_OBJECT_KEY_IS_CONSTANT);
			} else {
				/*
				 *	...unless this is the first time we've seen the attribute and
				 *	value_as_array is false, in which case just add the value directly
				 *	and move on to the next attribute.
				 */
				json_object_object_add_ex(vp_object, "value", value, JSON_C_OBJECT_KEY_IS_CONSTANT);
				continue;
			}
		} else {
			/*
			 *	Find the 'values' array to add the current value to.
			 */
			if (!fr_cond_assert(json_object_object_get_ex(vp_object, "value", &values))) {
				fr_strerror_const("Inconsistent JSON tree");
				goto error;
			}

			/*
			 *	If value_as_array is no set then "values" may not be an array, so it will
			 *	need converting to an array to add this extra attribute.
			 */
			if (!format->value.value_as_array) {
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
		}

		/*
		 *	Append to the JSON array.
		 */
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

		if (vp->da->flags.is_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init(&attr_name, buf, sizeof(buf));
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
			fr_strerror_const("Failed to convert attribute value to JSON object");

			json_object_put_assert(obj);
			return NULL;
		}

		/*
		 *	See if we already have a key in the table we're working on,
		 *	if not then create a new one.
		 */
		if (!json_object_object_get_ex(obj, fr_sbuff_start(&attr_name), &vp_object)) {
			if (format->value.value_as_array) {
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
				 *	and will be freed if thise drops to zero.
				 */
				json_object_object_add(obj, fr_sbuff_start(&attr_name), values);
			}
		}

		if (add_single) {
			/*
			 *	Only ever used the first time adding a new
			 *	attribute when "value_as_array" is not set.
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
	if (format->value.value_as_array) {
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

		if (vp->da->flags.is_raw) continue;

		/*
		 *	Get attribute name and value.
		 */
		fr_sbuff_init(&attr_name, buf, sizeof(buf));
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
			fr_strerror_const("Failed to convert attribute value to JSON object");
			json_object_put_assert(obj);
			return NULL;
		}

		if (format->value.value_as_array) {
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
		if (!format->value.value_as_array || !already_seen) {
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

			MEM(type_name = json_object_new_string(fr_table_str_by_value(fr_value_box_type_table,
										     vp->vp_type, "<INVALID>")));
			json_object_object_add_ex(attrobj, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);
		}

		if (format->value.value_as_array) {
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
	if (format->value.value_as_array) {
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

		if (vp->da->flags.is_raw) continue;

		if (json_afrom_value_box(ctx, &value, vp, format) < 0) {
			fr_strerror_const("Failed to convert attribute value to JSON object");
			json_object_put_assert(obj);
			return NULL;
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
static struct json_object *json_attr_array_afrom_pair_list(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps,
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
		fr_sbuff_t		attr_name;
		struct json_object	*value;

		if (vp->da->flags.is_raw) continue;

		fr_sbuff_init(&attr_name, buf, sizeof(buf));
		if (attr_name_with_prefix(&attr_name, vp->da, format) < 0) {
			return NULL;
		}

		value = json_object_new_string(fr_sbuff_start(&attr_name));

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
