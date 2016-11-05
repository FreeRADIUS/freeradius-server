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
 * @copyright 2015  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015  Network RADIUS SARL <info@networkradius.com>
 * @copyright 2015  The FreeRADIUS Server Project
 */
#include <freeradius-devel/rad_assert.h>
#include "json.h"

/** Convert json object to value_data_t
 *
 * @param ctx to allocate any value buffers in (should usually be the same as out).
 * @param out Where to write value_data.
 * @param object to convert.
 * @param dst_type FreeRADIUS type to convert to.
 * @param dst_enumv Enumeration values to allow string to integer conversions.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_json_object_to_value_data(TALLOC_CTX *ctx, value_data_t *out, json_object *object,
				 PW_TYPE dst_type, fr_dict_attr_t const *dst_enumv)
{
	PW_TYPE src_type = PW_TYPE_INVALID;
	value_data_t in;

	memset(&in, 0, sizeof(in));

	switch (fr_json_object_get_type(object)) {
	case json_type_string:
		src_type = PW_TYPE_STRING;
		in.strvalue = json_object_get_string(object);
		in.length = json_object_get_string_len(object);
		break;

	case json_type_double:
		src_type = PW_TYPE_DECIMAL;
		in.decimal = json_object_get_double(object);
		in.length = sizeof(in.decimal);
		break;

	case json_type_int:
	{
#ifdef HAVE_JSON_OBJECT_GET_INT64
		int64_t num;
#else
		int32_t num;
#endif
#ifndef HAVE_JSON_OBJECT_GET_INT64
		if (dst_type == PW_TYPE_INTEGER64) {
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
			src_type = PW_TYPE_INTEGER64;
			in.integer64 = (uint64_t) num;
			in.length = sizeof(in.integer64);
		} else
#endif
		if (num < 0) {			/* 32bit signed (supported) */
			src_type = PW_TYPE_SIGNED;
			in.sinteger = num;
			in.length = sizeof(in.sinteger);
		} else if (num > UINT16_MAX) {	/* 32bit unsigned (supported) */
			src_type = PW_TYPE_INTEGER;
			in.integer = (uint32_t) num;
			in.length = sizeof(in.integer);
		} else if (num > UINT8_MAX) {	/* 16bit unsigned (supported) */
			src_type = PW_TYPE_SHORT;
			in.ushort = (uint16_t) num;
			in.length = sizeof(in.ushort);
		} else if (num >= 0) {		/* 8bit unsigned (supported) */
			src_type = PW_TYPE_BYTE;
			in.byte = (uint8_t) num;
			in.length = sizeof(in.byte);
		} else {
			rad_assert(0);
			return -1;
		}
	}
		break;

	case json_type_boolean:
		src_type = PW_TYPE_BOOLEAN;
		in.boolean = json_object_get_boolean(object);
		in.length = sizeof(in.boolean);
		break;

	case json_type_null:
	case json_type_array:
	case json_type_object:
		src_type = PW_TYPE_STRING;
		in.strvalue = json_object_to_json_string(object);
		in.length = strlen(in.strvalue);
		break;
	}

	if (src_type == dst_type) {
		if (value_data_copy(ctx, out, src_type, &in) < 0) return -1;
	} else {
		if (value_data_cast(ctx, out, dst_type, dst_enumv, src_type, NULL, &in) < 0) return -1;
	}
	return 0;
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
	size_t		len, freespace = outlen;

	if (!vp->da->flags.has_tag) {
		switch (vp->da->type) {
		case PW_TYPE_INTEGER:
			if (vp->da->flags.has_value) break;

			return snprintf(out, freespace, "%u", vp->vp_integer);

		case PW_TYPE_SHORT:
			if (vp->da->flags.has_value) break;

			return snprintf(out, freespace, "%u", (unsigned int) vp->vp_short);

		case PW_TYPE_BYTE:
			if (vp->da->flags.has_value) break;

			return snprintf(out, freespace, "%u", (unsigned int) vp->vp_byte);

		case PW_TYPE_SIGNED:
			return snprintf(out, freespace, "%d", vp->vp_signed);

		default:
			break;
		}
	}

	if (vp->da->type == PW_TYPE_STRING) {
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

static void json_array_add_vp(TALLOC_CTX *ctx, json_object *arr, VALUE_PAIR *vp) {
	json_object *to_add = NULL;
	char *stringified_value;

	switch (vp->da->type) {
		case PW_TYPE_INTEGER:
			to_add = json_object_new_int(vp->vp_integer);
			break;
		case PW_TYPE_SHORT:
			to_add = json_object_new_int(vp->vp_short);
			break;
		case PW_TYPE_BYTE:
			to_add = json_object_new_int(vp->vp_byte);
			break;
		case PW_TYPE_SIGNED:
			to_add = json_object_new_int(vp->vp_signed);
			break;
		case PW_TYPE_INTEGER64:
			to_add = json_object_new_int64(vp->vp_integer64);
			break;
		case PW_TYPE_BOOLEAN:
			to_add = json_object_new_boolean(vp->vp_byte);
			break;
		default:
			MEM(stringified_value = fr_pair_value_asprint(ctx, vp, '\0'));
			to_add = json_object_new_string(stringified_value);
			talloc_free(stringified_value);
			break;
	}
	MEM(to_add);
	json_object_array_add(arr, to_add);
}

/** Returns a JSON string of a list of value pairs
 *
 *  The result is a talloc-ed string, freeing the string is the responsibility
 *  of the caller.
 *
 * @param ctx Talloc context
 * @param vps The list of value pairs
 * @param prefix The prefix to use, can be NULL to skip the prefix
 * @return JSON string representation of the value pairs
 */
const char *fr_json_from_pair_list(TALLOC_CTX *ctx, VALUE_PAIR **vps, const char *prefix) {
	TALLOC_CTX *local_ctx;
	vp_cursor_t cursor;
	struct json_object *obj, *vp_object, *values, *type_name;
	fr_dict_enum_t const *dv;
	VALUE_PAIR *vp;
	const char *name_with_prefix;
	const char *res = NULL;

	MEM(local_ctx = talloc_pool(ctx, 1024));
	MEM(obj = json_object_new_object());

	for (vp = fr_cursor_init(&cursor, vps); vp; vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);

		if (prefix) {
			MEM(name_with_prefix = talloc_asprintf(local_ctx, "%s:%s", prefix, vp->da->name));
		} else {
			name_with_prefix = vp->da->name;
		}

		if (json_object_object_get_ex(obj, name_with_prefix, &vp_object)) {
			if (!json_object_object_get_ex(vp_object, "value", &values)) {
				ERROR("Something is broken in the rlm_json encoder");
				goto error;
			}
		} else {
			MEM(vp_object = json_object_new_object());
			json_object_object_add(obj, name_with_prefix, vp_object);

			MEM(type_name = json_object_new_string(fr_int2str(dict_attr_types, vp->da->type, "<INVALID>")));
			json_object_object_add(vp_object, "type", type_name);

			MEM(values = json_object_new_array());
			json_object_object_add(vp_object, "value", values);
		}

		json_array_add_vp(local_ctx, values, vp);

		dv = fr_dict_enum_by_da(NULL, vp->da, vp->vp_integer);
		if (dv) {
			struct json_object *mapping, *mapped_value;

			// Fetch mapping array
			if (!json_object_object_get_ex(vp_object, "mapping", &mapping)) {
				int i;

				// Create if not found
				MEM(mapping = json_object_new_array());
				json_object_object_add(vp_object, "mapping", mapping);

				// Add NULL values for every entry in values
				for (i=0; i<json_object_array_length(values)-1; i++) {
					json_object_array_add(mapping, NULL);
				}
			}

			// Add to mapping array
			MEM(mapped_value = json_object_new_string(dv->name));
			json_object_array_add(mapping, mapped_value);
		} else {
			struct json_object *mapping;

			// Add NULL value to mapping array, if exists
			if (json_object_object_get_ex(vp_object, "mapping", &mapping)) {
				json_object_array_add(mapping, NULL);
			}
		}
	}
	MEM(res = talloc_strdup(ctx, json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN)));

error:
	talloc_free(local_ctx);
	json_object_put(obj);

	return res;
}

