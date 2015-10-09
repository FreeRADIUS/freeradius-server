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
				 PW_TYPE dst_type, DICT_ATTR const *dst_enumv)
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

/** Prints attribute as string, escaped suitably for use as JSON string
 *
 *  Returns < 0 if the buffer may be (or have been) too small to write the encoded
 *  JSON value to.
 *
 * @param out Where to write the string.
 * @param outlen Lenth of output buffer.
 * @param vp to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
size_t fr_json_from_pair(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const	*q;
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

	/* Indicate truncation */
	if (freespace < 2) return outlen + 1;
	*out++ = '"';
	freespace--;

	switch (vp->da->type) {
	case PW_TYPE_STRING:
		for (q = vp->vp_strvalue; q < vp->vp_strvalue + vp->vp_length; q++) {
			/* Indicate truncation */
			if (freespace < 3) return outlen + 1;

			if (*q == '"') {
				*out++ = '\\';
				*out++ = '"';
				freespace -= 2;
			} else if (*q == '\\') {
				*out++ = '\\';
				*out++ = '\\';
				freespace -= 2;
			} else if (*q == '/') {
				*out++ = '\\';
				*out++ = '/';
				freespace -= 2;
			} else if (*q >= ' ') {
				*out++ = *q;
				freespace--;
			} else {
				*out++ = '\\';
				freespace--;

				switch (*q) {
				case '\b':
					*out++ = 'b';
					freespace--;
					break;

				case '\f':
					*out++ = 'f';
					freespace--;
					break;

				case '\n':
					*out++ = 'b';
					freespace--;
					break;

				case '\r':
					*out++ = 'r';
					freespace--;
					break;

				case '\t':
					*out++ = 't';
					freespace--;
					break;
				default:
					len = snprintf(out, freespace, "u%04X", *q);
					if (is_truncated(len, freespace)) return (outlen - freespace) + len;
					out += len;
					freespace -= len;
				}
			}
		}
		break;

	default:
		len = fr_pair_value_snprint(out, freespace, vp, 0);
		if (is_truncated(len, freespace)) return (outlen - freespace) + len;
		out += len;
		freespace -= len;
		break;
	}

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
	static bool done_version;

	if (!done_version) {
		done_version = true;

#ifdef HAVE_JSON_C_VERSION
		INFO("libfreeradius-json: json-c version: %s", json_c_version());
#else
		INFO("libfreeradius-json: json-c version: Unknown (less than 0.10) - Please upgrade");
#endif
	}
}

