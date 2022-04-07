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
	bit = -1;

#define SET_FLAG(_flag) do { shift_ ## _flag = 1 << ++bit; if (flags->_flag) all_flags |= (1 << bit); } while (0)
	SET_FLAG(is_root);
	SET_FLAG(internal);
	SET_FLAG(array);
	SET_FLAG(has_value);
	SET_FLAG(virtual);
	SET_FLAG(extra);
	SET_FLAG(subtype);

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
		fr_strerror_const("The 'unknown' flag cannot be set for attributes in the dictionary.");
		return false;
	}

	if (flags->is_raw) {
		fr_strerror_const("The 'raw' flag cannot be set for attributes in the dictionary.");
		return false;
	}

	/*
	 *	Only some data types can be in arrays, because we need
	 *	to be able to decode the various array members.
	 */
	if (flags->array) {
		if (!flags->is_known_width) switch (type) {
		default:
			fr_strerror_printf("The 'array' flag cannot be used with attributes of type '%s'",
					   fr_type_to_str(type));
			return false;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_IPV6_PREFIX:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_DATE:
		case FR_TYPE_TIME_DELTA:
			break;

		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			if (!flags->length) {
				fr_strerror_const("Variable length attributes cannot be marked as 'array'");
				return false;
			}

			flags->is_known_width = 1;
			break;

		case FR_TYPE_STRUCT:
			/*
			 *	If we have arrays of structs, then the structure MUST be known width.
			 */
			flags->is_known_width = 1;
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
			fr_strerror_const("The 'virtual' flag can only be used for normal attributes");
			return false;
		}

		if (attr && !flags->internal && (*attr <= (1 << (8 * parent->flags.type_size)))) {
			fr_strerror_const("The 'virtual' flag can only be used for non-protocol attributes");
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
		if ((flags->subtype != FLAG_KEY_FIELD) && (flags->subtype != FLAG_BIT_FIELD) &&
		    (flags->subtype != FLAG_LENGTH_UINT8) && (flags->subtype != FLAG_LENGTH_UINT16)) {
			fr_strerror_const("The 'key' and 'length' flags cannot be used with any other flags.");
			return false;
		}

		switch (type) {
		case FR_TYPE_BOOL:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_UINT64:
			if ((flags->subtype != FLAG_KEY_FIELD) && (flags->subtype != FLAG_BIT_FIELD)) {
				fr_strerror_const("Invalid type (not 'key' field or 'bit' field) for extra flag.");
				return false;
			}

			if (parent->type != FR_TYPE_STRUCT) {
				fr_strerror_const("The 'key' flag can only be used inside of a 'struct'.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_OCTETS:
			if (flags->length != 0) {
				fr_strerror_const("Cannot use [..] and length=uint16");
				return false;
			}
			FALL_THROUGH;

		case FR_TYPE_STRING:
			/*
			 *	We can do arrays of variable-length types, so long as they have a "length="
			 *	modifier.
			 *
			 *	But any other modifier is foridden, including the use of "length=" outside of
			 *	the context of arrays.
			 */
			if (flags->array) {
				ALLOW_FLAG(array);

				if ((flags->subtype != FLAG_LENGTH_UINT8) && (flags->subtype != FLAG_LENGTH_UINT16)) goto invalid_extra;
			} else if (flags->subtype) {
			invalid_extra:
				fr_strerror_const("Invalid type (not 'length=...') for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_STRUCT:
			if ((flags->subtype != FLAG_LENGTH_UINT8) && (flags->subtype != FLAG_LENGTH_UINT16)) {
				fr_strerror_const("Invalid type (not 'length=...') for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(subtype);
			ALLOW_FLAG(array);
			break;

		case FR_TYPE_TLV:
			ALLOW_FLAG(extra);
			/* @todo - allow arrays of struct? */
			ALLOW_FLAG(subtype);
			break;

		default:
			fr_strerror_printf("Type %s cannot hold extra flags",
					   fr_type_to_str(type));
			return false;
		}

		if (((flags->subtype == FLAG_LENGTH_UINT8) || (flags->subtype == FLAG_LENGTH_UINT16)) &&
		    ((type != FR_TYPE_STRING) && (type != FR_TYPE_OCTETS) && (type != FR_TYPE_STRUCT))) {
			fr_strerror_printf("The 'length' flag cannot be used used with type %s",
					   fr_type_to_str(type));
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
					   flags->length, fr_type_to_str(type));
			return false;
		}

		if ((flags->flag_time_res != FR_TIME_RES_SEC) &&
		    (flags->flag_time_res != FR_TIME_RES_MSEC) &&
		    (flags->flag_time_res != FR_TIME_RES_USEC) &&
		    (flags->flag_time_res != FR_TIME_RES_NSEC)) {
			fr_strerror_printf("Invalid precision for attribute of type '%s'",
					   fr_type_to_str(type));
			return false;
		}
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_INT32:
	case FR_TYPE_FLOAT32:
		flags->length = 4;
		break;

	case FR_TYPE_UINT64:
	case FR_TYPE_FLOAT64:
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
	case FR_TYPE_COMBO_IP_ADDR:
		flags->length = 16;
		break;

	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_PREFIX:
		flags->length = 17;
		break;

	case FR_TYPE_STRUCT:
		ALLOW_FLAG(internal);
		ALLOW_FLAG(array);
		if (all_flags) {
			fr_strerror_const("Invalid flag for attribute of type 'struct'");
			return false;
		}
		break;

	case FR_TYPE_VENDOR:
		if (parent->type != FR_TYPE_VSA) {
			fr_strerror_printf("Attributes of type 'vendor' MUST have a parent of type 'vsa' "
					   "instead of '%s'",
					   fr_type_to_str(parent->type));
			return false;
		}

		if (flags->length) {
			if ((flags->length != 1) &&
			    (flags->length != 2) &&
			    (flags->length != 4)) {
				fr_strerror_const("The 'length' flag can only be used for attributes of type 'vendor' with lengths of 1,2 or 4");
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
				fr_strerror_const("The 'length' flag can only be used for attributes of type 'tlv' with lengths of 1,2 or 4");
				return false;
			}

			break;
		}

		/*
		 *	Find an appropriate parent to copy the
		 *	TLV-specific fields from.
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
					   fr_type_to_str(type));
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
				fr_strerror_const("The 'octets[...]' syntax cannot be used any other flag");
				return false;
			}

			if (flags->length > 253) {
				fr_strerror_printf("Invalid length %d", flags->length);
				return false;
			}
		}
		break;

	case FR_TYPE_NULL:
		fr_strerror_printf("Attributes of type '%s' cannot be used in dictionaries",
				   fr_type_to_str(type));
		return false;

	default:
		break;
	}

	/*
	 *	type_size is used to limit the maximum attribute number, so it's checked first.
	 */
	if (flags->type_size) {
		if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
			/*
			 *	Already checked above, but what the heck.
			 */
			if ((flags->flag_time_res != FR_TIME_RES_SEC) &&
			    (flags->flag_time_res != FR_TIME_RES_USEC) &&
			    (flags->flag_time_res != FR_TIME_RES_MSEC) &&
			    (flags->flag_time_res != FR_TIME_RES_NSEC)) {
				fr_strerror_printf("Invalid precision for attribute of type '%s'",
						   fr_type_to_str(type));
				return false;
			}
		} else if (!flags->extra) {
			if ((type != FR_TYPE_TLV) && (type != FR_TYPE_VENDOR)) {
				fr_strerror_const("The 'format=' flag can only be used with attributes of type 'tlv'");
				return false;
			}

			if ((flags->type_size != 1) &&
			    (flags->type_size != 2) &&
			    (flags->type_size != 4)) {
				fr_strerror_const("The 'format=' flag can only be used with attributes of type size 1,2 or 4");
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

		if (parent->flags.is_known_width && !flags->is_known_width && !flags->length) {
			fr_strerror_const("Variable-sized fields cannot be used within a 'struct' which is 'array'");
			return false;
		}

		if (flags->array) {
			switch (type) {
			case FR_TYPE_FIXED_SIZE:
				ALLOW_FLAG(array);
				break;

			default:
				if (flags->is_known_width) ALLOW_FLAG(array);
				break;
			}
		}

		if (all_flags) {
			fr_strerror_const("Invalid flag for attribute inside of a 'struct'");
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
				fr_strerror_printf("Child \"%s\" of 'struct' ttribute \"%s\" MUST be "
						   "numbered consecutively %u.",
						   name, parent->name, *attr);
				return false;
			}

			/*
			 *	Variable sized elements cannot have anything after them in a struct.
			 */
			if (!sibling->flags.length && !sibling->flags.is_known_width) {
				fr_strerror_const("No other field can follow a struct MEMBER which is variable sized");
				return false;
			}

			/*
			 *	The same goes for arrays.
			 */
			if (sibling->flags.array) {
				fr_strerror_const("No other field can follow a struct MEMBER which is 'array'");
				return false;
			}

			/*
			 *	Check for bad key fields, or multiple
			 *	key fields.  Yes, this is O(N^2), but
			 *	the structs are small.
			 */
			if (flags->extra && (flags->subtype == FLAG_KEY_FIELD)) {
				for (i = 1; i < *attr; i++) {
					sibling = fr_dict_attr_child_by_num(parent, i);
					if (!sibling) {
						fr_strerror_printf("Child %d of 'struct' type attribute %s does not exist.",
								   i, parent->name);
						return false;
					}

					if (!fr_dict_attr_is_key_field(sibling)) continue;

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
		if (fr_dict_attr_is_key_field(parent)) break;
		FALL_THROUGH;

	default:
		fr_strerror_printf("Attributes of type '%s' cannot have child attributes",
				   fr_type_to_str(type));
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
		/*
		 *	The value -1 is the special flag for "self
		 *	allocated" numbers.  i.e. we want an
		 *	attribute, but we don't care what the number
		 *	is.
		 */
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
			*attr = ++dict->self_allocated;

		} else if (*attr <= 0) {
			fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", *attr);
			return false;

		} else if ((unsigned int) *attr > dict->self_allocated) {
			dict->self_allocated = *attr;
		}

		/*
		 *	If the attribute is outside of the bounds of
		 *	the type size, then it MUST be an internal
		 *	attribute.  Set the flag in this attribute, so
		 *	that the encoder doesn't have to do complex
		 *	checks.
		 */
		if ((uint64_t) *attr >= (((uint64_t)1) << (8 * parent->flags.type_size))) flags->internal = true;
	}

	/*
	 *	Any other negative attribute number is wrong.
	 */
	if (*attr < 0) {
		fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", *attr);
		return false;
	}

	/*
	 *	Initialize the length field, which is needed for the attr_valid() callback.
	 */
	if (!flags->length) {
		fr_value_box_t box;

		fr_value_box_init(&box, type, NULL, false);
		flags->length = fr_value_box_network_length(&box);
	}

	if (type == FR_TYPE_STRUCT) flags->is_known_width |= flags->array;

	/*
	 *	Run protocol-specific validation functions, BEFORE we
	 *	do the rest of the checks.
	 */
	if (dict->attr_valid && !dict->attr_valid(dict, parent, name, *attr, type, flags)) return false;

	/*
	 *	Check the flags, data types, and parent data types and flags.
	 */
	if (!dict_attr_flags_valid(dict, parent, name, attr, type, flags)) return false;

	return true;
}
