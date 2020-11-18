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

/** Validation framework to allow protocols to set custom validation rules
 *
 * @file src/lib/util/dict_validate.c
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>

/** Validate a set of flags
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] attr		number.
 * @param[in] type		of attribute.
 * @param[in] flags		to check in the attribute.
 * @return
 *	- true if attribute definition is valid.
 *	- false if attribute definition is not valid.
 */
bool dict_attr_flags_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
			   char const *name, int *attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	int bit;
	uint32_t all_flags;
	uint32_t shift_is_root, shift_internal;
	uint32_t shift_array, shift_has_value;
	uint32_t shift_virtual, shift_subtype, shift_extra;
	fr_dict_attr_t const *v;

	/*
	 *	Convert the 1-bit fields into bits numbers, so that we
	 *	can check them in parallel.
	 */
	all_flags = 0;
	bit = 0;

#define SET_FLAG(_flag) do { shift_ ## _flag = 1 << bit; if (flags->_flag) {all_flags |= (1 << bit); } bit++; } while (0)
	SET_FLAG(is_root);
	SET_FLAG(internal);
	SET_FLAG(array);
	SET_FLAG(has_value);
	SET_FLAG(virtual);
	SET_FLAG(extra);

	shift_subtype = (1 << bit);
	if (flags->subtype) {
		all_flags |= (1 << bit);
	}

#define FORBID_OTHER_FLAGS(_flag) do { if (all_flags & ~shift_ ## _flag) { fr_strerror_printf("The '" STRINGIFY(_flag) "' flag cannot be used with any other flag"); return false; } } while (0)
#define ALLOW_FLAG(_flag) do { all_flags &= ~shift_ ## _flag; } while (0)

	// is_root
	// is_unknown
	// is_raw
	// internal
	// array
	// has_value
	// virtual
	// extra
	// encrypt
	// length
	// type_size

	if (flags->is_root) {
		FORBID_OTHER_FLAGS(is_root);
	}

	if (flags->is_unknown) {
		fr_strerror_printf("The 'unknown' flag cannot be set for attributes in the dictionary.");
		return false;
	}

	if (flags->is_raw) {
		fr_strerror_printf("The 'raw' flag cannot be set for attributes in the dictionary.");
		return false;
	}

	/*
	 *	Only some data types can be in arrays.
	 */
	if (flags->array) {
		switch (type) {
		default:
			fr_strerror_printf("The 'array' flag cannot be used with attributes of type '%s'",
					   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
			return false;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_DATE:
		case FR_TYPE_TIME_DELTA:
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			break;
		}

		/*
		 *	DHCPv6 has arrays of string / octets, prefixed
		 *	with a uint16 field of "length".  Also, arrays of dns_labels.
		 */
		ALLOW_FLAG(extra);
		ALLOW_FLAG(subtype);

		FORBID_OTHER_FLAGS(array);
	}

	/*
	 *	'has_value' should only be set internally.  If the
	 *	caller sets it, we still sanity check it.
	 */
	if (flags->has_value) {
		if (type != FR_TYPE_UINT32) {
			fr_strerror_printf("The 'has_value' flag can only be used with attributes "
					   "of type 'integer'");
			return false;
		}

		FORBID_OTHER_FLAGS(has_value);
	}

	/*
	 *	virtual attributes are special.
	 */
	if (flags->virtual) {
		if (!parent->flags.is_root) {
			fr_strerror_printf("The 'virtual' flag can only be used for normal attributes");
			return false;
		}

		if (attr && !flags->internal && (*attr <= (1 << (8 * parent->flags.type_size)))) {
			fr_strerror_printf("The 'virtual' flag can only be used for non-protocol attributes");
			return false;
		}

		ALLOW_FLAG(internal);
		FORBID_OTHER_FLAGS(virtual);
	}

	/*
	 *	The "extra" flag is a grab-bag of stuff, depending on
	 *	the data type.
	 */
	if (flags->extra) {
		if ((flags->subtype != FLAG_KEY_FIELD) && (flags->subtype != FLAG_LENGTH_UINT16) &&
		    (flags->subtype != FLAG_BIT_FIELD) && (flags->subtype != FLAG_HAS_REF)) {
			fr_strerror_printf("The 'key' and 'length' flags cannot be used with any other flags.");
			return false;
		}

		switch (type) {
		case FR_TYPE_BOOL:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_UINT64:
			if ((flags->subtype != FLAG_KEY_FIELD) && (flags->subtype != FLAG_BIT_FIELD)) {
				fr_strerror_printf("Invalid type for extra flag.");
				return false;
			}

			if (parent->type != FR_TYPE_STRUCT) {
				fr_strerror_printf("The 'key' flag can only be used inside of a 'struct'.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_OCTETS:
			if (flags->length != 0) {
				fr_strerror_printf("Cannot use [..] and length=uint16");
				return false;
			}
			FALL_THROUGH;

		case FR_TYPE_STRING:
			if (flags->subtype != FLAG_LENGTH_UINT16) {
				fr_strerror_printf("Invalid type for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(array);
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_STRUCT:
			if (flags->subtype != FLAG_LENGTH_UINT16) {
				fr_strerror_printf("Invalid type for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			/* @todo - allow arrays of struct? */
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_TLV:
			if (flags->subtype != FLAG_HAS_REF) {
				fr_strerror_printf("Invalid type for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			/* @todo - allow arrays of struct? */
			ALLOW_FLAG(subtype);
			break;

		default:
			fr_strerror_printf("Type %s cannot hold extra flags",
					   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"));
			return false;
		}

		if ((flags->subtype == FLAG_LENGTH_UINT16) &&
		    ((type != FR_TYPE_STRING) && (type != FR_TYPE_OCTETS) && (type != FR_TYPE_STRUCT))) {
			fr_strerror_printf("The 'length' flag cannot be used used with type %s",
					   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
			return false;
		}

		FORBID_OTHER_FLAGS(extra);
	}

	/*
	 *	Force "length" for fixed-size data types which aren't
	 *	bit fields.  Check / set "length" and "type_size" for
	 *	other types.
	 */
	if (!flags->extra || (flags->subtype != FLAG_BIT_FIELD)) switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_BOOL:
		flags->length = 1;
		break;

	case FR_TYPE_UINT16:
		flags->length = 2;
		break;

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (!flags->length) flags->length = 4;

		if ((flags->length != 2) && (flags->length != 4) && (flags->length != 8)) {
			fr_strerror_printf("Invalid length %u for attribute of type '%s'",
					   flags->length, fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
		}

		if ((flags->type_size != FR_TIME_RES_SEC) &&
		    (flags->type_size != FR_TIME_RES_MSEC) &&
		    (flags->type_size != FR_TIME_RES_USEC) &&
		    (flags->type_size != FR_TIME_RES_NSEC)) {
			fr_strerror_printf("Invalid precision for attribute of type '%s'",
					   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
		}
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_INT32:
		flags->length = 4;
		break;

	case FR_TYPE_UINT64:
		flags->length = 8;
		break;

	case FR_TYPE_SIZE:
		flags->length = sizeof(size_t);
		break;

	case FR_TYPE_ETHERNET:
		flags->length = 6;
		break;

	case FR_TYPE_IFID:
		flags->length = 8;
		break;

	case FR_TYPE_IPV6_ADDR:
		flags->length = 16;
		break;

	case FR_TYPE_STRUCT:
		ALLOW_FLAG(internal);
		if (all_flags) {
			fr_strerror_printf("Invalid flag for attribute of type 'struct'");
			return false;
		}
		break;

	case FR_TYPE_VENDOR:
		if (parent->type != FR_TYPE_VSA) {
			fr_strerror_printf("Attributes of type 'vendor' MUST have a parent of type 'vsa' "
					   "instead of '%s'",
					   fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
			return false;
		}

		if (flags->length) {
			if ((flags->length != 1) &&
			    (flags->length != 2) &&
			    (flags->length != 4)) {
				fr_strerror_printf("The 'length' flag can only be used for attributes of type 'vendor' with lengths of 1,2 or 4");
				return false;
			}

			break;
		}

		/*
		 *	Set the length / type_size of vendor
		 *	attributes from the vendor definition.
		 */
		flags->type_size = 1;
		flags->length = 1;
		if (attr) {
			fr_dict_vendor_t const *dv;

			dv = fr_dict_vendor_by_num(dict, *attr);
			if (dv) {
				flags->type_size = dv->type;
				flags->length = dv->length;
			}
		}
		break;

	case FR_TYPE_TLV:
		if (flags->length) {
			if ((flags->length != 1) &&
			    (flags->length != 2) &&
			    (flags->length != 4)) {
				fr_strerror_printf("The 'length' flag can only be used for attributes of type 'tlv' with lengths of 1,2 or 4");
				return false;
			}

			break;
		}

		/*
		 *	Length isn't set, set it and type_size from
		 *	the parent.
		 */
		for (v = parent; v != NULL; v = v->parent) {
			if ((v->type == FR_TYPE_TLV) || (v->type == FR_TYPE_VENDOR)) {
				break;
			}
		}

		/*
		 *	root is always FR_TYPE_TLV, so we're OK.
		 */
		if (!v) {
			fr_strerror_printf("Attributes of type '%s' require a parent attribute",
					   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"));
			return false;
		}

		/*
		 *	Over-ride whatever was there before, so we
		 *	don't have multiple formats of VSAs.
		 */
		flags->type_size = v->flags.type_size;
		flags->length = v->flags.length;
		break;

		/*
		 *	'octets[n]' can only be used in a few limited situations.
		 */
	case FR_TYPE_OCTETS:
		if (flags->length) {
			/*
			 *	Internal attributes can use octets[n]
			 *	MS-MPPE-Keys use octets[18],encrypt=1
			 *	EAP-SIM-RAND uses array
			 */
			ALLOW_FLAG(internal);
			ALLOW_FLAG(subtype);
			ALLOW_FLAG(array);

			if (all_flags) {
				fr_strerror_printf("The 'octets[...]' syntax cannot be used any other flag");
				return false;
			}

			if (flags->length > 253) {
				fr_strerror_printf("Invalid length %d", flags->length);
				return false;
			}
		}
		break;

	case FR_TYPE_COMBO_IP_ADDR:
		if (strcasecmp(dict->root->name, "RADIUS") != 0) {
			fr_strerror_printf("The 'combo-ip' type can only be used in the RADIUS dictionary.");
			return false;
		}

		/*
		 *	RFC 6929 says that this is a terrible idea.
		 */
		for (v = parent; v != NULL; v = v->parent) {
			if (v->type == FR_TYPE_VSA) {
				break;
			}
		}

		if (!v) {
			fr_strerror_printf("Attributes of type 'combo-ip' can only be used in VSA dictionaries");
			return false;
		}
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_COMBO_IP_PREFIX:
		fr_strerror_printf("Attributes of type '%s' cannot be used in dictionaries",
				   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"));
		return false;

	default:
		break;
	}

	/*
	 *	type_size is used to limit the maximum attribute number, so it's checked first.
	 */
	if (flags->type_size) {
		if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
			if ((flags->type_size != FR_TIME_RES_SEC) &&
			    (flags->type_size != FR_TIME_RES_USEC) &&
			    (flags->type_size != FR_TIME_RES_MSEC) &&
			    (flags->type_size != FR_TIME_RES_NSEC)) {
				fr_strerror_printf("Invalid precision specifier %d for attribute of type 'date'",
					flags->type_size);
				return false;
			}
		} else if (!flags->extra) {
			if ((type != FR_TYPE_TLV) && (type != FR_TYPE_VENDOR)) {
				fr_strerror_printf("The 'format=' flag can only be used with attributes of type 'tlv'");
				return false;
			}

			if ((flags->type_size != 1) &&
			    (flags->type_size != 2) &&
			    (flags->type_size != 4)) {
				fr_strerror_printf("The 'format=' flag can only be used with attributes of type size 1,2 or 4");
				return false;
			}
		}
	}

	/*
	 *	Check flags against the parent attribute.
	 */
	switch (parent->type) {
	case FR_TYPE_STRUCT:
		ALLOW_FLAG(extra);
		ALLOW_FLAG(subtype);
		if (all_flags) {
			fr_strerror_printf("Invalid flag for attribute inside of a 'struct'");
			return false;
		}

		if (!attr) break;

		/*
		 *	If we have keyed structs, then the first
		 *	member can be variable length.
		 *
		 *	For subsequent children, have each one check
		 *	the previous child.
		 */
		if (*attr != 1) {
			int i;
			fr_dict_attr_t const *sibling;

			sibling = fr_dict_attr_child_by_num(parent, (*attr) - 1);
			if (!sibling) {
				fr_strerror_printf("Child %s of 'struct' type attribute %s MUST be numbered consecutively %u.",
					name, parent->name, *attr);
				return false;
			}

			/*
			 *	@todo - allow dns_label encoding as
			 *	the first member.
			 */
			if ((dict_attr_sizes[sibling->type][1] == ~(size_t) 0) &&
			    !((sibling->type == FR_TYPE_OCTETS) &&
			      (sibling->flags.length > 0))) {
				fr_strerror_printf("Only the last child of a 'struct' attribute can have variable length");
				return false;
			}

			/*
			 *	Check for bad key fields, or multiple
			 *	key fields.  Yes, this is O(N^2), but
			 *	the structs are small.
			 */
			if (flags->extra) {
				for (i = 1; i < *attr; i++) {
					sibling = fr_dict_attr_child_by_num(parent, i);
					if (!sibling) {
						fr_strerror_printf("Child %d of 'struct' type attribute %s does not exist.",
								   i, parent->name);
						return false;
					}

					if (!da_is_key_field(sibling)) continue;

					fr_strerror_printf("Duplicate key attributes '%s' and '%s' in 'struct' type attribute %s are forbidden",
							   name, sibling->name, parent->name);
					return false;
				}
			}
		}
		break;

	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
		break;

		/*
		 *	"key" fields inside of a STRUCT can have
		 *	children, even if they are integer data type.
		 */
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
		if (da_is_key_field(parent)) break;
		FALL_THROUGH;

	default:
		fr_strerror_printf("Attributes of type '%s' cannot have child attributes",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
		return false;
	}

	return true;
}


/** Validate a new attribute definition
 *
 * @todo we need to check length of none vendor attributes.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] attr		number.
 * @param[in] type		of attribute.
 * @param[in] flags		to set in the attribute.
 * @return
 *	- true if attribute definition is valid.
 *	- false if attribute definition is not valid.
 */
bool dict_attr_fields_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
			    char const *name, int *attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	fr_dict_attr_t const	*v;

	if (!fr_cond_assert(parent)) return false;

	if (fr_dict_valid_name(name, -1) <= 0) return false;

	/******************** sanity check attribute number ********************/

	if (parent->flags.is_root) {
		static unsigned int max_attr = UINT8_MAX + 1;

		if (*attr == -1) {
			flags->internal = 1;

			v = fr_dict_attr_by_name(NULL, fr_dict_root(dict), name);
			if (v) {
				/*
				 *	Exact duplicates are allowed.  The caller will take care of
				 *	not inserting the duplicate attribute.
				 */
				if ((v->type == type) && (memcmp(&v->flags, flags, sizeof(*flags)) == 0)) {
					return true;
				}

				fr_strerror_printf("Conflicting definition for attribute %s", name);
				return false;
			}
			*attr = ++max_attr;

		} else if (*attr <= 0) {
			fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", *attr);
			return false;

		} else if ((unsigned int) *attr > max_attr) {
			max_attr = *attr;
		}

		/*
		 *	Auto-set internal flags for raddb/dictionary.
		 *	So that the end user doesn't have to know
		 *	about internal implementation of the server.
		 */
		if ((parent->flags.type_size == 1) &&
		    (*attr >= 3000) && (*attr < 4000)) {
			flags->internal = true;
		}
	}

	/*
	 *	Any other negative attribute number is wrong.
	 */
	if (*attr < 0) {
		fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", *attr);
		return false;
	}

	/*
	 *	Check the flags, data types, and parent data types and flags.
	 */
	if (!dict_attr_flags_valid(dict, parent, name, attr, type, flags)) return false;

#if 0
	if (parent->type == FR_TYPE_STRUCT) {
		/*
		 *	@todo - check PREVIOUS element.  if it's non-fixed size, then error out.
		 *	Move validation code from dict_read_process_member() to here
		 */
		switch (type) {
		case FR_TYPE_FIXED_SIZE:
			break;

		case FR_TYPE_TLV:
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			if (flags->length != 0) {
				fr_strerror_printf("The 'octets' type MUST be fixed-width when used inside of a 'struct'");
				return false;
			}
			break;

		default:
			break;
		}
	}
#endif

	/*
	 *	If attributes have number greater than 255, do sanity
	 *	checks on their values, to ensure that they fit within
	 *	the parent type.
	 *
	 *	We assume that the root attribute is of type TLV, with
	 *	the appropriate flags set for attributes in this
	 *	space.
	 */
	if ((*attr > UINT8_MAX) && !flags->internal) {
		for (v = parent; v != NULL; v = v->parent) {
			if ((v->type == FR_TYPE_TLV) || (v->type == FR_TYPE_VENDOR)) {
				if ((v->flags.type_size < 4) &&
				    (*attr >= (1 << (8 * v->flags.type_size)))) {
					fr_strerror_printf("Attributes must have value between 1..%u",
							   (1 << (8 * v->flags.type_size)) - 1);
					return false;
				}
				break;
			}
		}
	}

	/*
	 *	Run protocol-specific validation functions.
	 */
	if (dict->attr_valid) return dict->attr_valid(dict, parent, name, *attr, type, flags);

	return true;
}
