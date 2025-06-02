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
 * @author Matthew Newton
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015,2021 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */

#include <freeradius-devel/rad_assert.h>
#include "json.h"

#ifndef HAVE_JSON
#  error "rlm_json should not be built unless json-c is available"
#endif


const FR_NAME_NUMBER fr_json_format_table[] = {
	{ "array",		JSON_MODE_ARRAY			},
	{ "array_of_names",	JSON_MODE_ARRAY_OF_NAMES	},
	{ "array_of_values",	JSON_MODE_ARRAY_OF_VALUES	},
	{ "object",		JSON_MODE_OBJECT		},
	{ "object_simple",	JSON_MODE_OBJECT_SIMPLE		},

	{ NULL,			-1				}
};

static inline CC_HINT(always_inline)
void json_object_put_assert(json_object *obj)
{
	int ret;

	ret = json_object_put(obj);
	if (ret == 1) return;

	rad_assert(0);
}


/** Given a VALUE_PAIR, create the correct JSON object based on the data type
 *
 * @param[in] ctx to allocate temporary buffers in
 * @param[in] vp VALUE_PAIR to convert.
 * @param[in] always_string create all values as strings
 * @param[in] enum_as_int output enum attribute values as integers not strings
 * @param[in] dates_as_int output date values as seconds since the epoch
 * @return Newly allocated JSON object, or NULL on error
 */
json_object *json_object_from_attr_value(TALLOC_CTX *ctx, VALUE_PAIR const *vp, bool always_string, bool enum_as_int, bool dates_as_int)
{
	char buf[2048];
	ssize_t len;

	/*
	 *  We're converting to PRESENTATION format
	 *  so any attributes with enumeration values
	 *  should be converted to string types, unless
	 *  enum_as_int is set.
	 */

#define RETURN_ENUM_OR_STRING(_type) \
	if (always_string) { \
		len = snprintf(buf, sizeof(buf), "%d", vp->vp_ ## _type); \
		return json_object_new_string_len(buf, len); \
	} \
	return json_object_new_int(vp->vp_ ## _type)

	/*
	 *  Handle enumeration values first
	 */
	if (vp->da->flags.has_value) {
		if (enum_as_int) {
			switch (vp->da->type) {
			default:
				break;

			case PW_TYPE_BYTE:
				RETURN_ENUM_OR_STRING(byte);

			case PW_TYPE_SHORT:
				RETURN_ENUM_OR_STRING(short);

			case PW_TYPE_INTEGER:
				RETURN_ENUM_OR_STRING(integer);
			}
		} else {
			always_string = true;
		}
	}

	/*
	 *  We handle dates as epoch seconds here and dates as strings later.
	 */
	if (vp->da->type == PW_TYPE_DATE && dates_as_int)
		return json_object_new_int(vp->vp_date);

	/*
	 *  If always_string is set then we print everything to a string and
	 *  return a JSON string object.
	 */
	if (always_string) {
		char		*p;
		char		*quoted_string;
		json_object	*obj = NULL;

	do_string:
		p = vp_aprints_value(ctx, vp, '\0');
		if (!p) return NULL;

		quoted_string = fr_json_from_string(ctx, p, false);
		if (!quoted_string) {
			talloc_free(p);
			return NULL;
		}

		obj = json_object_new_string(quoted_string);
		talloc_free(p);

		return obj;
	}

	/*
	 *  Otherwise use the correct JSON object function depending on the
	 *  attribute value type.
	 */
	switch (vp->da->type) {
	default:
		goto do_string;

	case PW_TYPE_BOOLEAN:
		return json_object_new_boolean(vp->vp_byte);

	case PW_TYPE_BYTE:
		return json_object_new_int(vp->vp_byte);

	case PW_TYPE_SHORT:
		return json_object_new_int(vp->vp_short);

#ifdef HAVE_JSON_OBJECT_GET_INT64
	case PW_TYPE_INTEGER:
		return json_object_new_int64((int64_t)vp->vp_integer64);	/* uint32_t (max) > int32_t (max) */

	case PW_TYPE_INTEGER64:
		if (vp->vp_integer64 > INT64_MAX) goto do_string;
		return json_object_new_int64(vp->vp_integer64);
#else
	case PW_TYPE_INTEGER:
		if (vp->vp_integer > INT32_MAX) goto do_string;
		return json_object_new_int(vp->vp_integer);
#endif

	case PW_TYPE_SIGNED:
		return json_object_new_int(vp->vp_signed);
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


/** Convert VALUE_PAIR into a JSON object
 *
 * If inst.enum_as_int is set, and the given VP is an enum
 * value, the integer value is returned as a json_object rather
 * than the text representation.
 *
 * If inst.always_string is set then a numeric value pair
 * will be returned as a JSON string object.
 *
 * @param[in] ctx	Talloc context.
 * @param[out] out	returned json object.
 * @param[in] vp	to get the value of.
 * @param[in] inst	format definition, or NULL.
 * @return
 *	- 1 if 'out' is the integer enum value, 0 otherwise
 *	- -1 on error.
 */
static int json_afrom_value_pair(TALLOC_CTX *ctx, json_object **out,
				 VALUE_PAIR *vp, rlm_json_t const *inst)
{
	struct json_object	*obj;
	int			is_enum = 0;

	fr_assert(vp);
	fr_assert(inst);

	MEM(obj = json_object_from_attr_value(ctx, vp, inst->always_string, inst->enum_as_int, inst->dates_as_int));

	*out = obj;
	return is_enum;
}


/** Add prefix to attribute name
 *
 * If the format "attr.prefix" string is set then prepend this
 * to the given attribute name, otherwise return name unchanged.
 *
 * @param[out] buf where to write the new name, if set
 * @param[in] buf_len length of buf
 * @param[in] name original attribute name
 * @param[in] inst json format structure
 * @return pointer to name, or buf if the prefix was added
 */
static inline char const *attr_name_with_prefix(char *buf, size_t buf_len, const char *name, rlm_json_t const *inst)
{
	int len;

	if (!inst->attr_prefix) return name;

	len = snprintf(buf, buf_len, "%s:%s", inst->attr_prefix, name);

	if (len == (int)strlen(buf)) {
		return buf;
	}

	return name;
}


/** Verify that the options in rlm_json_t are valid
 *
 * Warnings are optional, will fatal error if the format is corrupt.
 *
 * @param[in] inst	the format structure to check
 * @param[in] verbose	print out warnings if set
 * @return		true if format is good, otherwise false
 */
bool fr_json_format_verify(rlm_json_t const *inst, bool verbose)
{
	bool ret = true;

	fr_assert(inst);

	switch (inst->output_mode) {
	case JSON_MODE_OBJECT:
	case JSON_MODE_OBJECT_SIMPLE:
	case JSON_MODE_ARRAY:
		/* all options are valid */
		return true;
	case JSON_MODE_ARRAY_OF_VALUES:
		if (inst->attr_prefix) {
			if (verbose) WARN("attribute name prefix not valid in output_mode 'array_of_values' and will be ignored");
			ret = false;
		}
		if (inst->value_as_array) {
			if (verbose) WARN("'value_as_array' not valid in output_mode 'array_of_values' and will be ignored");
			ret = false;
		}
		return ret;
	case JSON_MODE_ARRAY_OF_NAMES:
		if (inst->value_as_array) {
			if (verbose) WARN("'value_as_array' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		if (inst->enum_as_int) {
			if (verbose) WARN("'enum_as_int' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		if (inst->dates_as_int) {
			if (verbose) WARN("'dates_as_int' not valid in output_mode 'array_of_names' and will be ignored");
			ret = false;
		}
		if (inst->always_string) {
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
 * @param[in] inst	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static json_object *json_object_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
						rlm_json_t const *inst)
{
	VALUE_PAIR		*vp;
	struct json_object	*obj;
	char			buf[DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(inst);
	fr_assert(inst->output_mode == JSON_MODE_OBJECT);

	MEM(obj = json_object_new_object());

	for (vp = vps;
	     vp;
	     vp = vp->next) {
		char const		*attr_name;
		struct json_object	*vp_object, *values, *value, *type_name;

		/*
		 *	Get attribute name and value.
		 */
		attr_name = attr_name_with_prefix(buf, sizeof(buf), vp->da->name, inst);

		if (json_afrom_value_pair(ctx, &value, vp, inst) < 0) {
			fr_strerror_printf("Failed to convert attribute value to JSON object");
		error:
			json_object_put_assert(obj);

			return NULL;
		}

		/*
		 *	Look in the table to see if we already have
		 *	a key for the attribute we're working on.
		 */
		if (!json_object_object_get_ex(obj, attr_name, &vp_object)) {
			/*
			 *	Wasn't there, so create a new object for this attribute.
			 */
			MEM(vp_object = json_object_new_object());
			json_object_object_add(obj, attr_name, vp_object);

			/*
			 *	Add "type" to newly created keys.
			 */
			MEM(type_name = json_object_new_string(fr_int2str(dict_attr_types, vp->da->type, "<INVALID>")));
			json_object_object_add_ex(vp_object, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);

			/*
			 *	Create a "value" array to hold any attribute values for this attribute...
			 */
			if (inst->value_as_array) {
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
			if (!json_object_object_get_ex(vp_object, "value", &values)) {
				fr_strerror_printf("Inconsistent JSON tree");
				goto error;
			}

			/*
			 *	If value_as_array is no set then "values" may not be an array, so it will
			 *	need converting to an array to add this extra attribute.
			 */
			if (!inst->value_as_array) {
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
 * @param[in] inst	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static json_object *json_smplobj_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
						 rlm_json_t const *inst)
{
	VALUE_PAIR		*vp;
	struct json_object	*obj;
	char			buf[DICT_ATTR_MAX_NAME_LEN + 32];
	json_type		type;

	/* Check format and type */
	fr_assert(inst);
	fr_assert(inst->output_mode == JSON_MODE_OBJECT_SIMPLE);

	MEM(obj = json_object_new_object());

	for (vp = vps;
	     vp;
	     vp = vp->next) {
		char const		*attr_name;
		struct json_object	*vp_object, *value;
		struct json_object	*values = NULL;
		bool			add_single = false;

		/*
		 *	Get attribute name and value.
		 */
		attr_name = attr_name_with_prefix(buf, sizeof(buf), vp->da->name, inst);

		if (json_afrom_value_pair(ctx, &value, vp, inst) < 0) {
			fr_strerror_printf("Failed to convert attribute value to JSON object");

			json_object_put_assert(obj);
			return NULL;
		}

		/*
		 *	See if we already have a key in the table we're working on,
		 *	if not then create a new one.
		 */
		if (!json_object_object_get_ex(obj, attr_name, &vp_object)) {
			if (inst->value_as_array) {
				/*
				 *	We have been asked to ensure /all/ values are lists,
				 *	even if there's only one attribute.
				 */
				MEM(values = json_object_new_array());
				json_object_object_add(obj, attr_name, values);
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
				json_object_object_add(obj, attr_name, values);
			}
		}

		if (add_single) {
			/*
			 *	Only ever used the first time adding a new
			 *	attribute when "value_as_array" is not set.
			 */
			json_object_object_add(obj, attr_name, value);
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
 * @param[in] inst	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_array_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
						      rlm_json_t const *inst)
{
	VALUE_PAIR		*vp;
	struct json_object	*obj;
	struct json_object	*seen_attributes = NULL;
	char			buf[DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(inst);
	fr_assert(inst->output_mode == JSON_MODE_ARRAY);

	MEM(obj = json_object_new_array());

	/*
	 *	If attribute values should be in a list format, then keep track
	 *	of the attributes we've previously seen in a JSON object.
	 */
	if (inst->value_as_array) {
		seen_attributes = json_object_new_object();
	}

	for (vp = vps;
	     vp;
	     vp = vp->next) {
		char const		*attr_name;
		struct json_object	*name, *value, *type_name;
		struct json_object	*values = NULL;
		struct json_object	*attrobj = NULL;
		bool			already_seen = false;

		/*
		 *	Get attribute name and value.
		 */
		attr_name = attr_name_with_prefix(buf, sizeof(buf), vp->da->name, inst);

		if (json_afrom_value_pair(ctx, &value, vp, inst) < 0) {
			fr_strerror_printf("Failed to convert attribute value to JSON object");
			json_object_put_assert(obj);
			return NULL;
		}

		if (inst->value_as_array) {
			/*
			 *	Try and find this attribute in the "seen_attributes" object. If it is
			 *	there then get the "values" array to add this attribute value to.
			 */
			already_seen = json_object_object_get_ex(seen_attributes, attr_name, &values);
		}

		/*
		 *	If we're adding all attributes to the toplevel array, or we're adding values
		 *	to an array of an existing attribute but haven't seen it before, then we need
		 *	to create a new JSON object for this attribute.
		 */
		if (!inst->value_as_array || !already_seen) {
			/*
			 * Create object and add it to top-level array
			 */
			MEM(attrobj = json_object_new_object());
			json_object_array_add(obj, attrobj);

			/*
			 * Add the attribute name in the "name" key and the type in the "type" key
			 */
			MEM(name = json_object_new_string(attr_name));
			json_object_object_add_ex(attrobj, "name", name, JSON_C_OBJECT_KEY_IS_CONSTANT);

			MEM(type_name = json_object_new_string(fr_int2str(dict_attr_types, vp->da->type, "<INVALID>")));
			json_object_object_add_ex(attrobj, "type", type_name, JSON_C_OBJECT_KEY_IS_CONSTANT);
		}

		if (inst->value_as_array) {
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
				json_object_object_add(seen_attributes, attr_name, json_object_get(values));
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
	if (inst->value_as_array) {
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
 * @param[in] inst	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_value_array_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
							    rlm_json_t const *inst)
{
	VALUE_PAIR		*vp;
	struct json_object	*obj;

	/* Check format and type */
	fr_assert(inst);
	fr_assert(inst->output_mode == JSON_MODE_ARRAY_OF_VALUES);

	MEM(obj = json_object_new_array());

	/*
	 *	This array format is very simple - just add all the
	 *	attribute values to the array in order.
	 */
	for (vp = vps;
	     vp;
	     vp = vp->next) {
		struct json_object	*value;

		if (json_afrom_value_pair(ctx, &value, vp, inst) < 0) {
			fr_strerror_printf("Failed to convert attribute value to JSON object");
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
 * @param[in] inst	Formatting control, must be set.
 * @return JSON object with the generated representation.
 */
static struct json_object *json_attr_array_afrom_pair_list(UNUSED TALLOC_CTX *ctx, VALUE_PAIR *vps,
							   rlm_json_t const *inst)
{
	VALUE_PAIR		*vp;
	struct json_object	*obj;
	char			buf[DICT_ATTR_MAX_NAME_LEN + 32];

	/* Check format and type */
	fr_assert(inst);
	fr_assert(inst->output_mode == JSON_MODE_ARRAY_OF_NAMES);

	MEM(obj = json_object_new_array());

	/*
	 *	Add all the attribute names to the array in order.
	 */
	for (vp = vps;
	     vp;
	     vp = vp->next) {
		char const		*attr_name;
		struct json_object	*value;

		attr_name = attr_name_with_prefix(buf, sizeof(buf), vp->da->name, inst);
		value = json_object_new_string(attr_name);

		json_object_array_add(obj, value);
	}

	return obj;
}


/** Returns a JSON string of a list of value pairs
 *
 * The result is a talloc-ed string, freeing the string is
 * the responsibility of the caller.
 *
 * The 'inst' format struct contains settings to configure the output
 * JSON document format.
 * @see fr_json_format_s
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] inst	Formatting control, can be NULL to use default format.
 * @return JSON string representation of the value pairs
 */
char *fr_json_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR *vps,
			      rlm_json_t const *inst)
{
	struct json_object	*obj = NULL;
	const char		*p;
	char			*out;

	rad_assert(inst);

	switch (inst->output_mode) {
	case JSON_MODE_OBJECT:
		MEM(obj = json_object_afrom_pair_list(ctx, vps, inst));
		break;
	case JSON_MODE_OBJECT_SIMPLE:
		MEM(obj = json_smplobj_afrom_pair_list(ctx, vps, inst));
		break;
	case JSON_MODE_ARRAY:
		MEM(obj = json_array_afrom_pair_list(ctx, vps, inst));
		break;
	case JSON_MODE_ARRAY_OF_VALUES:
		MEM(obj = json_value_array_afrom_pair_list(ctx, vps, inst));
		break;
	case JSON_MODE_ARRAY_OF_NAMES:
		MEM(obj = json_attr_array_afrom_pair_list(ctx, vps, inst));
		break;
	default:
		/* This should never happen */
		rad_assert(0);
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
