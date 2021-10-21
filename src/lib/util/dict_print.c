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

ssize_t fr_dict_attr_flags_print(fr_sbuff_t *out, fr_dict_t const *dict, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);

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
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ',');
	}

	if (flags->length) {
		switch (type) {
		case FR_TYPE_FIXED_SIZE:
			/*
			 *	Bit fields are in the dicts as various
			 *	`uint*` types.  But with special flags
			 *	saying they're bit fields.
			 */
			if (flags->extra && (flags->subtype == FLAG_BIT_FIELD)) {
				FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "bit[%u],", flags->length);
			}
			break;

		default:
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "length=%i,", flags->length);
			break;
		}
	}
	if (flags->extra) {
		switch (flags->subtype) {
		case FLAG_KEY_FIELD:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "key,");
			break;

		case FLAG_LENGTH_UINT16:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "length=uint16,");
			break;

		case FLAG_BIT_FIELD:
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
					  fr_table_str_by_value(date_precision_table, flags->flag_time_res, "?"));
	}

	fr_sbuff_trim(&our_out, (bool[UINT8_MAX + 1]){ [','] = true });

	return fr_sbuff_set(out, &our_out);
}

/** Build the da_stack for the specified DA and encode the path by name in OID form
 *
 * @param[out] out		Where to write the OID.
 * @param[in] ancestor		If not NULL, only print OID portion between ancestor and da.
 * @param[in] da		to print OID string for.
 * @param[in] numeric		print the OID components as numbers, not attribute names.
 * @return
 *	- >0 The number of bytes written to the buffer.
 *	- <= 0 The number of bytes we would have needed to write the
 *        next OID component.
 */
ssize_t fr_dict_attr_oid_print(fr_sbuff_t *out,
			       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da, bool numeric)
{
	int			i;
	int			depth = 0;
	fr_da_stack_t		da_stack;
	fr_sbuff_t		our_out = FR_SBUFF(out);

	/*
	 *	If the ancestor and the DA match, there's
	 *	no OID string to print.
	 */
	if ((ancestor == da) || (da->depth == 0)) return 0;

	fr_proto_da_stack_build(&da_stack, da);

	if (ancestor) {
		if (da_stack.da[ancestor->depth - 1] != ancestor) {
			fr_strerror_printf("Attribute '%s' is not a descendent of \"%s\"", da->name, ancestor->name);
			return 0;
		}
		depth = ancestor->depth;
	}

	/*
	 *	We don't print the ancestor, we print the OID
	 *	between it and the da.
	 */
	if (numeric) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", da_stack.da[depth]->attr);
		for (i = depth + 1; i < (int)da->depth; i++) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", da_stack.da[i]->attr);
		}
	} else {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, da_stack.da[depth]->name);
		for (i = depth + 1; i < (int)da->depth; i++) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			FR_SBUFF_IN_STRCPY_RETURN(&our_out, da_stack.da[i]->name);
		}
	}
	return fr_sbuff_set(out, &our_out);
}

typedef struct {
	fr_dict_t const		*dict;
	char			prefix[256];
	char			flags[256];
	char			oid[256];
	unsigned int		start_depth;
} fr_dict_attr_debug_t;

static int dict_attr_debug(fr_dict_attr_t const *da, void *uctx)
{
	fr_dict_attr_debug_t 		*our_uctx = uctx;
	fr_hash_iter_t			iter;
	fr_dict_enum_value_t const		*enumv;
	fr_dict_attr_ext_enumv_t 	*ext;

	fr_dict_attr_flags_print(&FR_SBUFF_OUT(our_uctx->flags, sizeof(our_uctx->flags)),
			      our_uctx->dict, da->type, &da->flags);

	snprintf(our_uctx->prefix, sizeof(our_uctx->prefix),
		 "[%02i] 0x%016" PRIxPTR "%*s",
		 da->depth,
		 (unsigned long)da,
		 (da->depth - our_uctx->start_depth) * 4, "");

	FR_FAULT_LOG("%s%s(%u) %s %s",
		     our_uctx->prefix,
		     da->name,
		     da->attr,
		     fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"),
		     our_uctx->flags);

	dict_attr_ext_debug(our_uctx->prefix, da);	/* Print all the extension debug info */

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext || !ext->name_by_value) return 0;

	for (enumv = fr_hash_table_iter_init(ext->name_by_value, &iter);
	     enumv;
	     enumv = fr_hash_table_iter_next(ext->name_by_value, &iter)) {
	     	char *value = fr_asprintf(NULL, "%pV", enumv->value);

		FR_FAULT_LOG("%s    %s -> %s",
			     our_uctx->prefix,
			     enumv->name,
			     value);
		talloc_free(value);
	}

	return 0;
}

void fr_dict_namespace_debug(fr_dict_attr_t const *da)
{
	fr_dict_attr_debug_t    uctx = { .dict = fr_dict_by_da(da), .start_depth = da->depth };
	fr_hash_table_t		*namespace;
	fr_hash_iter_t		iter;
	fr_dict_attr_t		*our_da;

	namespace = dict_attr_namespace(da);
	if (!namespace) {
		FR_FAULT_LOG("%s does not have namespace", da->name);
		return;
	}

	for (our_da = fr_hash_table_iter_init(namespace, &iter);
	     our_da;
	     our_da = fr_hash_table_iter_next(namespace, &iter)) {
		dict_attr_debug(our_da, &uctx);
	}
}

void fr_dict_attr_debug(fr_dict_attr_t const *da)
{
	fr_dict_attr_debug_t	uctx = { .dict = fr_dict_by_da(da), .start_depth = da->depth };

	dict_attr_debug(da, &uctx);
	(void)fr_dict_walk(da, dict_attr_debug, &uctx);
}

void fr_dict_debug(fr_dict_t const *dict)
{
	fr_dict_attr_debug(fr_dict_root(dict));
}

static int dict_attr_export(fr_dict_attr_t const *da, void *uctx)
{
	fr_dict_attr_debug_t 		*our_uctx = uctx;

	(void) fr_dict_attr_oid_print(&FR_SBUFF_OUT(our_uctx->prefix, sizeof(our_uctx->prefix)),
				      NULL, da, false);
	(void) fr_dict_attr_oid_print(&FR_SBUFF_OUT(our_uctx->oid, sizeof(our_uctx->oid)),
				      NULL, da, true);
	*our_uctx->flags = 0;	/* some attributes don't have flags */
	fr_dict_attr_flags_print(&FR_SBUFF_OUT(our_uctx->flags, sizeof(our_uctx->flags)),
				 our_uctx->dict, da->type, &da->flags);

	FR_FAULT_LOG("ATTRIBUTE\t%-40s\t%-20s\t%s\t%s",
		     our_uctx->prefix,
		     our_uctx->oid,
		     fr_table_str_by_value(fr_value_box_type_table, da->type, "???"),
		     our_uctx->flags);

	return 0;
}

static void fr_dict_attr_export(fr_dict_attr_t const *da)
{
	fr_dict_attr_debug_t	uctx = { .dict = fr_dict_by_da(da), .start_depth = da->depth };

	dict_attr_export(da, &uctx);
	(void)fr_dict_walk(da, dict_attr_export, &uctx);
}

/** Export in the standard form: ATTRIBUTE name oid flags
 *
 */
void fr_dict_export(fr_dict_t const *dict)
{
	fr_dict_attr_export(fr_dict_root(dict));
}
