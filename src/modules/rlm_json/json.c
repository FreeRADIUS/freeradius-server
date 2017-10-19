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
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2015 The FreeRADIUS Server Project
 */
#include <freeradius-devel/rad_assert.h>
#include "json.h"

/** Convert json object to fr_value_box_t
 *
 * @param[in] ctx	to allocate any value buffers in (should usually be the same as out).
 * @param[in] out	Where to write value_box.
 * @param[in] object	to convert.
 * @param[in] dst_type	FreeRADIUS type to convert to.
 * @param[in] dst_enumv	Enumeration values to allow string to integer conversions.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_json_object_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, json_object *object,
				fr_type_t dst_type, fr_dict_attr_t const *dst_enumv)
{
	fr_value_box_t in;

	memset(&in, 0, sizeof(in));

	switch (fr_json_object_get_type(object)) {
	case json_type_string:
		in.type = FR_TYPE_STRING;
		in.vb_strvalue = json_object_get_string(object);
		in.datum.length = json_object_get_string_len(object);
		break;

	case json_type_double:
		in.type = FR_TYPE_FLOAT64;
		in.vb_float64 = json_object_get_double(object);
		break;

	case json_type_int:
	{
#ifdef HAVE_JSON_OBJECT_GET_INT64
		int64_t num;
#else
		int32_t num;
#endif
#ifndef HAVE_JSON_OBJECT_GET_INT64
		if (dst_type == FR_TYPE_UINT64) {
			fr_strerror_printf("64bit integers are not supported by linked json-c.  "
					   "Upgrade to json-c > 0.10 to use this feature");
			return -1;
		}
#endif

#ifndef HAVE_JSON_OBJECT_GET_INT64
		num = json_object_get_int(object);
#else
		num = json_object_get_int64(object);
		if (num < INT32_MIN) {		/* 64bit signed (not supported)*/
			fr_strerror_printf("Signed 64bit integers are not supported");
			return -1;
		}
		if (num > UINT32_MAX) {		/* 64bit unsigned (supported) */
			in.type = FR_TYPE_UINT64;
			in.vb_uint64 = (uint64_t) num;
		} else
#endif
		if (num < 0) {			/* 32bit signed (supported) */
			in.type = FR_TYPE_INT32;
			in.vb_int32 = num;
		} else if (num > UINT16_MAX) {	/* 32bit unsigned (supported) */
			in.type = FR_TYPE_UINT32;
			in.vb_uint32 = (uint32_t) num;
		} else if (num > UINT8_MAX) {	/* 16bit unsigned (supported) */
			in.type = FR_TYPE_UINT16;
			in.vb_uint16 = (uint16_t) num;
		} else {		/* 8bit unsigned (supported) */
			in.type = FR_TYPE_UINT8;
			in.vb_uint8 = (uint8_t) num;
		}
	}
		break;

	case json_type_boolean:
		in.type = FR_TYPE_BOOL;
		in.datum.boolean = json_object_get_boolean(object);
		break;

	case json_type_null:
	case json_type_array:
	case json_type_object:
		in.type = FR_TYPE_STRING;
		in.vb_strvalue = json_object_to_json_string(object);
		in.datum.length = strlen(in.vb_strvalue);
		break;
	}

	if (fr_value_box_cast(ctx, out, dst_type, dst_enumv, &in) < 0) return -1;

	return 0;
}

/** Convert boxed value_box to a JSON object
 *
 * @param[in] ctx	to allocate temporary buffers in
 * @param[in] data	to convert.
 */
json_object *json_object_from_value_box(TALLOC_CTX *ctx, fr_value_box_t const *data)
{
	switch (data->type) {
	default:
	do_string:
	{
		char		*p;
		json_object	*obj;

		p = fr_value_box_asprint(ctx, data, '\0');
		if (!p) return NULL;

		obj = json_object_new_string(p);
		talloc_free(p);

		return obj;
	}

	case FR_TYPE_BOOL:
		return json_object_new_boolean(data->vb_uint8);

	case FR_TYPE_UINT8:
		return json_object_new_int(data->vb_uint8);

	case FR_TYPE_UINT16:
		return json_object_new_int(data->vb_uint16);

	case FR_TYPE_UINT32:
		return json_object_new_int64((int64_t)data->vb_uint64);	/* uint32_t (max) > int32_t (max) */

	case FR_TYPE_UINT64:
		if (data->vb_uint64 > INT64_MAX) goto do_string;
		return json_object_new_int64(data->vb_uint64);

	case FR_TYPE_INT32:
		return json_object_new_int(data->vb_int32);
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
			out = talloc_strdup(ctx, p);
		} else {
			len = strlen(p) - 1;
			out = talloc_strndup(ctx, p+1, len);
			if (out) out[len-1] = '\0';
		}
	}

	json_object_put(json);
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
size_t fr_json_from_pair(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	size_t len, freespace = outlen;

	if (!vp->da->flags.has_tag) {
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
	}

	if (vp->vp_type == FR_TYPE_STRING) {
		char *tmp = fr_json_from_string(NULL, vp->vp_strvalue, true);

		/* Indicate truncation */
		if (!tmp) return outlen + 1;
		len = strlen(tmp);
		if (freespace <= len) return outlen + 1;

		strcpy(out, tmp);
		talloc_free(tmp);

		return len;
	}

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;

	len = fr_pair_value_snprint(out, freespace, vp, 0);
	if (is_truncated(len, freespace)) return (outlen - freespace) + len;
	out += len;
	freespace -= len;

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

/** Returns a JSON string of a list of value pairs
 *
 *  The result is a talloc-ed string, freeing the string is the responsibility
 *  of the caller.
 *
 * Output format is:
@verbatim
{
	"<attribute0>":{
		"type":"<type0>",
		"value":[<value0>,<value1>,<valueN>],
		"mapping":[<enumv0>,<enumv1>,<enumvN>]
	},
	"<attribute1>":{
		"type":"<type1>",
		"value":[...]
	},
	"<attributeN>":{
		"type":"<typeN>",
		"value":[...]
	},
}
@endverbatim
 *
 * @note Mapping element is only present for attributes with enumerated values.
 *
 * @param[in] ctx	Talloc context.
 * @param[in] vps	a list of value pairs.
 * @param[in] prefix	The prefix to use, can be NULL to skip the prefix.
 * @return JSON string representation of the value pairs
 */
const char *fr_json_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR **vps, const char *prefix)
{
	fr_cursor_t		cursor;
	VALUE_PAIR 		*vp;
	struct json_object	*obj;
	const char		*p;
	char			buf[FR_DICT_ATTR_MAX_NAME_LEN + 32];

	MEM(obj = json_object_new_object());

	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		char const		*name_with_prefix;
		fr_dict_enum_t const	*dv;
		struct json_object	*vp_object, *values, *value, *type_name;

		name_with_prefix = vp->da->name;
		if (prefix) {
			int len = snprintf(buf, sizeof(buf), "%s:%s", prefix, vp->da->name);
			if (len == (int)strlen(buf)) {
				name_with_prefix = buf;
			}
		}

		/*
		 *	See if we already have a key in the table we're working on,
		 *	if we don't, create a new one...
		 */
		if (!json_object_object_get_ex(obj, name_with_prefix, &vp_object)) {
			MEM(vp_object = json_object_new_object());
			json_object_object_add(obj, name_with_prefix, vp_object);

			MEM(type_name = json_object_new_string(fr_int2str(dict_attr_types, vp->vp_type, "<INVALID>")));
			json_object_object_add(vp_object, "type", type_name);

			MEM(values = json_object_new_array());
			json_object_object_add(vp_object, "value", values);
		/*
		 *	If we do, get its value array...
		 */
		} else if (!rad_cond_assert(json_object_object_get_ex(vp_object, "value", &values))) {
			fr_strerror_printf("Inconsistent JSON tree");
			json_object_put(obj);

			return NULL;
		}

		MEM(value = json_object_from_value_box(ctx, &vp->data));
		json_object_array_add(values, value);

		/*
		 *	Add a mapping array
		 */
		if (vp->da->flags.has_value) {
			struct json_object *mapping;

			if (!json_object_object_get_ex(vp_object, "mapping", &mapping)) {
				MEM(mapping = json_object_new_array());
				json_object_object_add(vp_object, "mapping", mapping);
			}

			dv = fr_dict_enum_by_value(NULL, vp->da, &vp->data);
			if (dv) {
				struct json_object *mapped_value;

				/* Add to mapping array */
				MEM(mapped_value = json_object_new_string(dv->alias));
				json_object_array_add(mapping, mapped_value);
			/*
			 *	Add NULL value to mapping array
			 */
			} else {
				if (json_object_object_get_ex(vp_object, "mapping", &mapping)) {
					json_object_array_add(mapping, NULL);
				}
			}
		}
	}

	MEM(p = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
	MEM(p = talloc_strdup(ctx, p));

	json_object_put(obj);	/* Should also free string buff from above */

	return p;
}

