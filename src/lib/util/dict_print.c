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

/** Print dictionary attributes, flags, etc...
 *
 * @file src/lib/util/dict_print.c
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <ctype.h>

ssize_t fr_dict_snprint_flags(char *out, size_t outlen, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	char *p = out, *end = p + outlen;
	size_t len;

	out[0] = '\0';

#define FLAG_SET(_flag) \
do { \
	if (flags->_flag) {\
		p += strlcpy(p, STRINGIFY(_flag)",", end - p);\
		if (p >= end) return -1;\
	}\
} while (0)

	FLAG_SET(is_root);
	FLAG_SET(is_unknown);
	FLAG_SET(is_raw);
	FLAG_SET(internal);
	FLAG_SET(has_tag);
	FLAG_SET(array);
	FLAG_SET(has_value);
	FLAG_SET(concat);
	FLAG_SET(virtual);

	if (flags->subtype) {
		p += snprintf(p, end - p, "encrypt=%i,", flags->subtype);
		if (p >= end) return -1;
	}

	if (flags->length) {
		p += snprintf(p, end - p, "length=%i,", flags->length);
		if (p >= end) return -1;
	}

	if (flags->extra) {
		switch (type) {
		case FR_TYPE_EXTENDED:
			p += snprintf(p, end - p, "long,");
			break;

		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
			p += snprintf(p, end - p, "key,");
			break;

		default:
			break;
		}

		if (p >= end) return -1;
	}

	/*
	 *	Print out the date precision.
	 */
	if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
		char const *precision = fr_table_str_by_value(date_precision_table, flags->type_size, "?");

		p += strlcpy(p, precision, end - p);
		if (p >= end) return -1;
	}

	if (!out[0]) return -1;

	/*
	 *	Trim the comma
	 */
	len = strlen(out);
	if (out[len - 1] == ',') out[len - 1] = '\0';

	return len;
}

/** Build the tlv_stack for the specified DA and encode the path in OID form
 *
 * @param[out] need		How many bytes we would need to print the
 *				next part of the string.
 * @param[out] out		Where to write the OID.
 * @param[in] outlen		Length of the output buffer.
 * @param[in] ancestor		If not NULL, only print OID portion between
 *				ancestor and da.
 * @param[in] da		to print OID string for.
 * @return
 *	- The number of bytes written to the buffer.  If truncation has occurred
 *	  *need will be > 0.
 */
size_t fr_dict_print_attr_oid(size_t *need, char *out, size_t outlen,
			      fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da)
{
	size_t			len;
	char			*p = out, *end = p + outlen;
	int			i;
	int			depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];

	RETURN_IF_NO_SPACE_INIT(need, 1, p, out, end);

	/*
	 *	If the ancestor and the DA match, there's
	 *	no OID string to print.
	 */
	if (ancestor == da) {
		out[0] = '\0';
		return 0;
	}

	fr_proto_tlv_stack_build(tlv_stack, da);

	if (ancestor) {
		if (tlv_stack[ancestor->depth - 1] != ancestor) {
			fr_strerror_printf("Attribute \"%s\" is not a descendent of \"%s\"", da->name, ancestor->name);
			return -1;
		}
		depth = ancestor->depth;
	}

	/*
	 *	We don't print the ancestor, we print the OID
	 *	between it and the da.
	 */
	len = snprintf(p, end - p, "%u", tlv_stack[depth]->attr);
	RETURN_IF_TRUNCATED(need, len, p, out, end);

	for (i = depth + 1; i < (int)da->depth; i++) {
		len = snprintf(p, end - p, ".%u", tlv_stack[i]->attr);
		RETURN_IF_TRUNCATED(need, len, p, out, end);
	}

	return p - out;
}



void fr_dict_print(fr_dict_attr_t const *da, int depth)
{
	char buff[256];
	unsigned int i;
	char const *name;

	fr_dict_snprint_flags(buff, sizeof(buff), da->type, &da->flags);

	switch (da->type) {
	case FR_TYPE_VSA:
		name = "VSA";
		break;

	case FR_TYPE_EXTENDED:
		name = "EXTENDED";
		break;

	case FR_TYPE_TLV:
		name = "TLV";
		break;

	case FR_TYPE_VENDOR:
		name = "VENDOR";
		break;

	case FR_TYPE_STRUCT:
		name = "STRUCT";
		break;

	case FR_TYPE_GROUP:
		name = "GROUP";
		break;

	default:
		name = "ATTRIBUTE";
		break;
	}

	printf("%u%.*s%s \"%s\" vendor: %x (%u), num: %x (%u), type: %s, flags: %s\n", da->depth, depth,
	       "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", name, da->name,
	       fr_dict_vendor_num_by_da(da), fr_dict_vendor_num_by_da(da), da->attr, da->attr,
	       fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"), buff);

	if (da->children) for (i = 0; i < talloc_array_length(da->children); i++) {
		if (da->children[i]) {
			fr_dict_attr_t const *bin;

			for (bin = da->children[i]; bin; bin = bin->next) fr_dict_print(bin, depth + 1);
		}
	}
}
