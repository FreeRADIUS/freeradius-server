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

ssize_t fr_dict_snprint_flags(fr_sbuff_t *out, fr_dict_t const *dict, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

#define FLAG_SET(_flag) if (flags->_flag) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, STRINGIFY(_flag)",")

	FLAG_SET(is_root);
	FLAG_SET(is_unknown);
	FLAG_SET(is_raw);
	FLAG_SET(internal);
	FLAG_SET(array);
	FLAG_SET(has_value);
	FLAG_SET(virtual);

	if (dict && !flags->extra && flags->subtype) {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, fr_table_str_by_value(dict->subtype_table, flags->subtype, "?"));
	}

	if (flags->length) FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "length=%i,", flags->length);
	if (flags->extra) {
		switch (flags->subtype) {
		case FLAG_KEY_FIELD:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "key,");
			break;

		case FLAG_LENGTH_UINT16:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "length=uint16,");
			break;

		default:
			break;
		}
	}

	/*
	 *	Print out the date precision.
	 */
	if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out,
					  fr_table_str_by_value(date_precision_table, flags->type_size, "?"));
	}

	fr_sbuff_in_trim(&our_out, ',');

	return fr_sbuff_set(out, &our_out);
}

/** Build the da_stack for the specified DA and encode the path in OID form
 *
 * @param[out] out		Where to write the OID.
 * @param[in] ancestor		If not NULL, only print OID portion between ancestor and da.
 * @param[in] da		to print OID string for.
 * @return
 *	- >0 The number of bytes written to the buffer.
 *	- <= 0 The number of bytes we would have needed to write the
 *        next OID component.
 */
ssize_t fr_dict_print_attr_oid(fr_sbuff_t *out, fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da)
{
	int			i;
	int			depth = 0;
	fr_da_stack_t		da_stack;
	fr_sbuff_t		our_out = FR_SBUFF_NO_ADVANCE(out);

	/*
	 *	If the ancestor and the DA match, there's
	 *	no OID string to print.
	 */
	if ((ancestor == da) || (da->depth == 0)) return 0;

	fr_proto_da_stack_build(&da_stack, da);

	if (ancestor) {
		if (da_stack.da[ancestor->depth - 1] != ancestor) {
			fr_strerror_printf("Attribute \"%s\" is not a descendent of \"%s\"", da->name, ancestor->name);
			return -1;
		}
		depth = ancestor->depth;
	}

	/*
	 *	We don't print the ancestor, we print the OID
	 *	between it and the da.
	 */
	FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", da_stack.da[depth]->attr);
	for (i = depth + 1; i < (int)da->depth; i++) FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%u", da_stack.da[i]->attr);

	return fr_sbuff_set(out, &our_out);
}


typedef struct {
	fr_dict_t const *dict;
	char buff[256];
} fr_dict_print_t;

static int dict_print(void *ctx_in, fr_dict_attr_t const *da, int depth)
{
	char const	*name;
	fr_dict_print_t	*ctx = (fr_dict_print_t *) ctx_in;

	fr_dict_snprint_flags(&FR_SBUFF_OUT(ctx->buff, sizeof(ctx->buff)), ctx->dict, da->type, &da->flags);

	switch (da->type) {
	case FR_TYPE_VSA:
		name = "VSA";
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
		if (da->parent && da->parent->type == FR_TYPE_STRUCT) {
			name = "MEMBER";
			break;
		}

		name = "ATTRIBUTE";
		break;
	}

	printf("%u%.*s%s \"%s\" vendor: %x (%u), num: %x (%u), type: %s, flags: %s\n", da->depth, depth,
	       "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", name, da->name,
	       fr_dict_vendor_num_by_da(da), fr_dict_vendor_num_by_da(da), da->attr, da->attr,
	       fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"), ctx->buff);

	return 0;
}


void fr_dict_print(fr_dict_t const *dict, fr_dict_attr_t const *da)
{
	fr_dict_print_t ctx;

	ctx.dict = dict;

	(void) fr_dict_walk(da, &ctx, dict_print);
}
