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
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>

/** Validate a set of flags
 *
 * @param[in] da		to check.
 * @return
 *	- true if attribute definition is valid.
 *	- false if attribute definition is not valid.
 */
bool dict_attr_flags_valid(fr_dict_attr_t *da)
{
	int bit;
	uint32_t all_flags;
	uint32_t shift_is_root, shift_internal;
	uint32_t shift_array, shift_has_value;
	uint32_t shift_subtype, shift_extra;
	uint32_t shift_counter;
	fr_dict_t		*dict = da->dict;
	fr_dict_attr_t const	*parent = da->parent;
	char const		*name = da->name;
	int			attr = da->attr;
	fr_type_t		type = da->type;
	fr_dict_attr_flags_t	*flags = &da->flags;

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
	SET_FLAG(extra);
	SET_FLAG(counter);
	SET_FLAG(subtype);

#define FORBID_OTHER_FLAGS(_flag, _allowed) \
	do { \
		if (all_flags & ~shift_ ## _flag & ~(_allowed)) { \
			fr_strerror_printf("The '" STRINGIFY(_flag) "' flag cannot be used with any other flag (%u) %s[%d]", all_flags, da->filename, da->line); \
			return false; \
		} \
	} while (0)

#define ALLOW_FLAG(_flag) do { all_flags &= ~shift_ ## _flag; } while (0)

	// is_root
	// is_unknown
	// internal
	// array
	// has_value
	// extra
	// encrypt
	// length
	// type_size

	if (flags->is_root) {
		FORBID_OTHER_FLAGS(is_root, 0);
	}

	if (flags->is_unknown) {
		fr_strerror_const("The 'unknown' flag cannot be set for attributes in the dictionary.");
		return false;
	}

	if (flags->local != parent->flags.local) {
		fr_strerror_const("Cannot mix local variables with non-local attributes");
		return false;
	}

	if (flags->local && (flags->is_unknown || flags->is_raw)) {
		fr_strerror_const("Local variables cannot be 'raw' or unknown");
		return false;
	}

	/*
	 *	"flat" attributes can only go into a group.
	 */
	if ((flags->allow_flat) && (type != FR_TYPE_GROUP)) {
		fr_strerror_printf("Cannot set the 'flat' flag for data type %s", fr_type_to_str(type));
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

		case FR_TYPE_ATTR:
			flags->is_known_width = 1;
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

		FORBID_OTHER_FLAGS(array, 0);
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

		FORBID_OTHER_FLAGS(has_value, shift_internal);
	}

	/*
	 *	Sanity check aliases.
	 */
	if (flags->is_alias) {
		fr_dict_attr_ext_ref_t *ext;

		ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
		if (!ext) {
			fr_strerror_const("ALIAS is missing extension");
			return false;
		}

		if (!ext->ref) {
			fr_strerror_const("ALIAS is missing ref");
			return false;
		}

		if (da->parent->type == FR_TYPE_STRUCT) {
			fr_strerror_const("ALIAS cannot be added to a data type 'struct'");
			return false;
		}

		fr_assert(!da->flags.is_unknown);
		fr_assert(!da->flags.is_raw);
		fr_assert(!da->flags.array);
		fr_assert(!da->flags.is_known_width);
		fr_assert(!da->flags.has_value);
		fr_assert(!da->flags.counter);
		fr_assert(!da->flags.secret);
		fr_assert(!da->flags.unsafe);
		fr_assert(!da->flags.is_ref_target);
		fr_assert(!da->flags.local);
		fr_assert(!da->flags.has_fixup);
	}

	/*
	 *	The "extra" flag is a grab-bag of stuff, depending on
	 *	the data type.
	 */
	if (flags->extra) {
		if (!fr_dict_attr_is_key_field(da) && !da_is_length_field(da) && !da_is_bit_field(da)) {
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
		case FR_TYPE_STRING:
			if (flags->length != 0) {
				fr_strerror_const("Cannot use [..] and length=uint...");
				return false;
			}

			/*
			 *	We can do arrays of variable-length types, so long as they have a "length="
			 *	modifier.
			 *
			 *	But any other modifier is foridden, including the use of "length=" outside of
			 *	the context of arrays.
			 */
			if (flags->array) {
				ALLOW_FLAG(array);

				if (!da_is_length_field(da)) {
					goto invalid_extra;
				}

			} else if (da_is_length_field(da)) {
				/* this is allowed */

			} else if (flags->subtype) {
			invalid_extra:
				fr_strerror_const("Invalid type (not 'length=...') for extra flag.");
				return false;
			}

			ALLOW_FLAG(extra);
			ALLOW_FLAG(subtype);
			break;

		case FR_TYPE_STRUCT:
			if (!da_is_length_field(da)) {
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

		if (da_is_length_field(da) &&
		    ((type != FR_TYPE_STRING) && (type != FR_TYPE_OCTETS) && (type != FR_TYPE_STRUCT))) {
			fr_strerror_printf("The 'length' flag cannot be used used with type %s",
					   fr_type_to_str(type));
			return false;
		}

		FORBID_OTHER_FLAGS(extra, 0);
	}

	/*
	 *	Force "length" for fixed-size data types which aren't
	 *	bit fields.  Check / set "length" and "type_size" for
	 *	other types.
	 */
	if (!flags->extra || (flags->subtype != FLAG_BIT_FIELD)) switch (type) {
	case FR_TYPE_INT8:
	case FR_TYPE_UINT8:
	case FR_TYPE_BOOL:
		flags->length = 1;
		break;

	case FR_TYPE_INT16:
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
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_INT32:
	case FR_TYPE_UINT32:
	case FR_TYPE_FLOAT32:
		flags->length = 4;
		break;

	case FR_TYPE_INT64:
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
		if (dict->string_based) break;

		if (parent->type != FR_TYPE_VSA) {
			fr_strerror_printf("Attributes of type 'vendor' MUST have a parent of type 'vsa' "
					   "instead of '%s'",
					   fr_type_to_str(parent->type));
			return false;
		}

		if ((flags->length != 1) &&
		    (flags->length != 2) &&
		    (flags->length != 4)) {
			fr_strerror_const("The 'length' flag can only be used for attributes of type 'vendor' with lengths of 1,2 or 4");
			return false;
		}
		break;

	case FR_TYPE_TLV:
		if ((flags->length != 1) &&
		    (flags->length != 2) &&
		    (flags->length != 4)) {
			fr_strerror_const("The 'length' flag can only be used for attributes of type 'tlv' with lengths of 1,2 or 4");
			return false;
		}
		break;

		/*
		 *	'octets[n]' can only be used in a few limited situations.
		 */
	case FR_TYPE_OCTETS:
		if (flags->length) {
			/*
			 *	Internal attributes can use octets[n]
			 *	MS-MPPE-Keys use octets[18],encrypt=User-Password
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

	case FR_TYPE_UNION:
		if (parent->type != FR_TYPE_STRUCT) {
			fr_strerror_printf("Attributes of type 'union' must have a parent of type 'struct', not of type '%s'",
					   fr_type_to_str(parent->type));
			return false;
		}

		/*
		 *	If the UNION is missing a key extension, then the children of the UNION cannot find
		 *	the key field in the parent STRUCT.
		 */
		if (!fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_KEY)) {
			fr_strerror_const("Attribute of type 'union' is missing 'key=...'");
			return false;
		}
		break;

	case FR_TYPE_NULL:
	case FR_TYPE_INTERNAL:
		fr_strerror_printf("Attributes of type '%s' cannot be used in dictionaries",
				   fr_type_to_str(type));
		return false;

		/*
		 *	These types are encoded differently in each protocol.
		 */
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_ATTR:
	case FR_TYPE_STRING:
	case FR_TYPE_VSA:
	case FR_TYPE_GROUP:
		break;
	}

	/*
	 *	type_size is used to limit the maximum attribute number, so it's checked first.
	 */
	if (flags->type_size) {
		if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
			/*
			 *	Allow all time res here
			 */
		} else if (!flags->extra) {
			if ((type != FR_TYPE_TLV) && (type != FR_TYPE_VENDOR)) {
				fr_strerror_printf("The 'format=' flag can only be used with attributes of type 'tlv', and not type '%s'", fr_type_to_str(type));
				return false;
			}

			if ((flags->type_size != 1) &&
			    (flags->type_size != 2) &&
			    (flags->type_size != 4)) {
				fr_strerror_printf("The 'format=' flag can only be used with attributes of type size 1,2 or 4, not %i", flags->type_size);
				return false;
			}
		}
	}

	/*
	 *	Counters can be time deltas, or unsigned integers.
	 *	For other data types, we don't know how to
	 *	automatically add two counters.
	 */
	if (flags->counter) {
		if ((type == FR_TYPE_TIME_DELTA) || (fr_type_is_integer(type) && !fr_type_is_signed(type))) {
			ALLOW_FLAG(counter);
		} else {
			fr_strerror_printf("The 'counter' flag cannot be used with '%s'", fr_type_to_str(type));
			return false;
		}
	}

	/*
	 *	Check flags against the parent attribute.
	 */
	switch (parent->type) {
	case FR_TYPE_STRUCT:
		ALLOW_FLAG(extra);
		ALLOW_FLAG(subtype);

		/*
		 *	If our parent is known width, then the children have to be known width, UNLESS
		 *	either this child or its parent has a "length" prefix.
		 */
		if (parent->flags.is_known_width && !flags->is_known_width && !flags->length &&
		    !da_is_length_field(da) && !da_is_length_field(parent)) {
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
		if (attr != 1) {
			int i;
			fr_dict_attr_t const *sibling;

			sibling = fr_dict_attr_child_by_num(parent, (attr) - 1);

			/*
			 *	sibling might not exist, if it's a deferred 'tlv clone=...'
			 */

			/*
			 *	Variable sized elements cannot have anything after them in a struct.
			 */
			if (sibling && !sibling->flags.length && !sibling->flags.is_known_width) {
				fr_strerror_const("No other field can follow a struct MEMBER which is variable sized");
				return false;
			}

			/*
			 *	The same goes for arrays.
			 */
			if (sibling && sibling->flags.array) {
				fr_strerror_const("No other field can follow a struct MEMBER which is 'array'");
				return false;
			}

			/*
			 *	Check for bad key fields, or multiple
			 *	key fields.  Yes, this is O(N^2), but
			 *	the structs are small.
			 */
			if (fr_dict_attr_is_key_field(da)) {
				for (i = 1; i < attr; i++) {
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

	case FR_TYPE_VSA:
		if ((type != FR_TYPE_VENDOR) && !flags->internal) {
			fr_strerror_printf("Attributes of type '%s' cannot be children of the 'vsa' type",
					   fr_type_to_str(type));
			return false;
		}
		break;

	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
		break;

	case FR_TYPE_UNION:
		if (!((da->type == FR_TYPE_STRUCT) || (da->type == FR_TYPE_TLV) || fr_type_is_leaf(da->type))) {
			fr_strerror_printf("Attributes of type '%s' cannot be children of the 'union' type",
					   fr_type_to_str(type));
			return false;
		}
		break;

	default:
		fr_strerror_printf("Attributes of type '%s' cannot have child attributes",
				   fr_type_to_str(parent->type));
		return false;
	}

	return true;
}


/** Validate a new attribute definition
 *
 * @todo we need to check length of none vendor attributes.
 *
 * @param[in] da	to validate.
 * @return
 *	- true if attribute definition is valid.
 *	- false if attribute definition is not valid.
 */
bool dict_attr_valid(fr_dict_attr_t *da)
{
	if (!fr_cond_assert(da->parent)) return false;

	if (fr_dict_valid_name(da->name, -1) <= 0) return false;

	/*
	 *	Run protocol-specific validation functions, BEFORE we
	 *	do the rest of the checks.
	 */
	if (da->dict->proto->attr.valid && !da->dict->proto->attr.valid(da)) return false;

	/*
	 *	Check the flags, data types, and parent data types and flags.
	 */
	if (!dict_attr_flags_valid(da)) return false;

	return true;
}
