/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/der/decode.c
 * @brief Functions to decode DER encoded data.
 *
 * @author Ethan Thompson (ethan.thompson@inkbridge.io)
 *
 * @copyright (C) 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/table.h>

#include "der.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_der;

extern fr_dict_autoload_t libfreeradius_der_dict[];
fr_dict_autoload_t	  libfreeradius_der_dict[] = { { .out = &dict_der, .proto = "der" }, { NULL } };

extern fr_dict_attr_autoload_t libfreeradius_der_dict_attr[];
fr_dict_attr_autoload_t	       libfreeradius_der_dict_attr[] = {
	       { NULL }
};

static fr_table_num_sorted_t const tag_name_to_number[] = {
	{ L("bitstring"),		FR_DER_TAG_BITSTRING },
	{ L("bmpstring"),		FR_DER_TAG_BMP_STRING },
	{ L("boolean"),			FR_DER_TAG_BOOLEAN },
	{ L("choice"),			FR_DER_TAG_CHOICE },
	{ L("enumerated"),		FR_DER_TAG_ENUMERATED },
	{ L("generalizedtime"),		FR_DER_TAG_GENERALIZED_TIME },
	{ L("generalstring"),		FR_DER_TAG_GENERAL_STRING },
	{ L("ia5string"),		FR_DER_TAG_IA5_STRING },
	{ L("integer"),			FR_DER_TAG_INTEGER },
	{ L("null"),			FR_DER_TAG_NULL },
	{ L("octetstring"),		FR_DER_TAG_OCTETSTRING },
	{ L("oid"),			FR_DER_TAG_OID },
	{ L("printablestring"),		FR_DER_TAG_PRINTABLE_STRING },
	{ L("sequence"),		FR_DER_TAG_SEQUENCE },
	{ L("set"),			FR_DER_TAG_SET },
	{ L("t61string"),		FR_DER_TAG_T61_STRING },
	{ L("universalstring"),		FR_DER_TAG_UNIVERSAL_STRING },
	{ L("utctime"),			FR_DER_TAG_UTC_TIME },
	{ L("utf8string"),		FR_DER_TAG_UTF8_STRING },
	{ L("visiblestring"),		FR_DER_TAG_VISIBLE_STRING },
};
static size_t tag_name_to_number_len = NUM_ELEMENTS(tag_name_to_number);


char const *fr_der_tag_to_str(fr_der_tag_t tag)
{
	return fr_table_str_by_value(tag_name_to_number, tag, "???");
}

static const uint64_t der_tags_compatible[FR_DER_TAG_MAX] = {
	[FR_DER_TAG_UTC_TIME] = (1 << FR_DER_TAG_GENERALIZED_TIME),
	[FR_DER_TAG_GENERALIZED_TIME] = (1 << FR_DER_TAG_UTC_TIME),
};

bool fr_der_tags_compatible(fr_der_tag_t tag1, fr_der_tag_t tag2)
{
	return (der_tags_compatible[tag1] & (1 << (uint64_t) tag2)) != 0;
}

/*
 *	Create a mapping between FR_TYPE_* and valid FR_DER_TAG_*'s
 */
static const bool *fr_type_to_der_tags[FR_DER_TAG_MAX] = {
	[FR_TYPE_BOOL] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BOOLEAN] = true,
		[FR_DER_TAG_INTEGER] = true,
		[FR_DER_TAG_NULL] = true,
	},
	[FR_TYPE_INT64] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_INTEGER] = true,
		[FR_DER_TAG_ENUMERATED] = true,
	},
	[FR_TYPE_OCTETS] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
		[FR_DER_TAG_OCTETSTRING] = true,
	},
	[FR_TYPE_STRING] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_OID] = true,
		[FR_DER_TAG_UTF8_STRING] = true,
		[FR_DER_TAG_PRINTABLE_STRING] = true,
		[FR_DER_TAG_T61_STRING] = true,
		[FR_DER_TAG_IA5_STRING] = true,
		[FR_DER_TAG_VISIBLE_STRING] = true,
		[FR_DER_TAG_GENERAL_STRING] = true,
		[FR_DER_TAG_UNIVERSAL_STRING] = true,
	},
	[FR_TYPE_DATE] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_UTC_TIME] = true,
		[FR_DER_TAG_GENERALIZED_TIME] = true,
	},
	[FR_TYPE_TLV] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_SEQUENCE] = true,
		[FR_DER_TAG_SET] = true,
	},
	[FR_TYPE_STRUCT] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
		[FR_DER_TAG_SEQUENCE] = true,
		[FR_DER_TAG_SET] = true,
	},
	[FR_TYPE_GROUP] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_SEQUENCE] = true,
		[FR_DER_TAG_SET] = true,
	},
};

/*
 *	Return true if the given type can be encoded as the given tag.
 * 		@param[in] type The fr_type to check.
 * 		@param[in] tag The der tag to check.
 * 		@return true if the type can be encoded as the given tag.
 */
bool fr_type_to_der_tag_valid(fr_type_t type, fr_der_tag_t tag)
{
	if (!fr_type_to_der_tags[type]) return false;

	return fr_type_to_der_tags[type][tag];
}


int fr_der_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_der_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_der_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_der_dict);
		goto fail;
	}

	return 0;
}

void fr_der_global_free(void)
{
	if (--instance_count != 0) return;

	fr_dict_autofree(libfreeradius_der_dict);
}

#if 0
static int dict_flag_class(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static const fr_table_num_sorted_t table[] = {
		{ L("application"),	FR_DER_CLASS_APPLICATION },
		{ L("context-specific"), FR_DER_CLASS_CONTEXT },
		{ L("private"),		FR_DER_CLASS_PRIVATE },
		{ L("universal"),	FR_DER_CLASS_UNIVERSAL },
	};
	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_class_t   tag_class;

	if (flags->class) {
		fr_strerror_printf("Attribute already has a 'class' defined");
		return -1;
	}

	tag_class = fr_table_value_by_str(table, value, FR_DER_CLASS_INVALID);
	if (tag_class == FR_DER_CLASS_INVALID) {
		fr_strerror_printf("Invalid value in 'class=%s'", value);
		return -1;
	}

	flags->class = tag_class;

	return 0;
}
#endif

static int dict_flag_has_default(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->has_default = true;

	return 0;
}

static int dict_flag_der_type(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_t     der_type;

	der_type = fr_table_value_by_str(tag_name_to_number, value, FR_DER_TAG_INVALID);
	if (der_type == FR_DER_TAG_INVALID) {
		fr_strerror_printf("Unknown type in 'der_type=%s'", value);
		return -1;
	}

	/*
	 *	The DER type and FreeRADIUS type must be compatible.
	 *
	 *	Except for some der_type=integer, such as a
	 *	certificate serialNumber.  Those are too large for us
	 *	to represent in 64 bits, so we just treat them as
	 *	'octets'.
	 */
	if (!fr_type_to_der_tag_valid((*da_p)->type, der_type) &&
	    (der_type != FR_DER_TAG_INTEGER) && ((*da_p)->type != FR_TYPE_OCTETS)) {
		fr_strerror_printf("Attribute type %s is not compatible with 'der_type=%s'",
				   fr_type_to_str((*da_p)->type), value);
		return -1;
	}

	flags->der_type = der_type;

	return 0;
}

static int dict_flag_sequence_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_t     type;

	if (flags->is_set_of) {
		fr_strerror_const("Cannot be both 'sequence_of=...' and 'set_of=...'");
		return -1;
	}

	if (flags->der_type != FR_DER_TAG_SEQUENCE) {
		fr_strerror_printf("Cannot use 'sequence_of=...' for DER type '%s'", fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	if (strcmp(value, "oid_and_value") == 0) {
		(*da_p)->type = FR_TYPE_GROUP;
		flags->is_pair = true;
		return 0;
	}

	type = fr_table_value_by_str(tag_name_to_number, value, FR_DER_TAG_INVALID);
	if (type == FR_DER_TAG_INVALID) {
		fr_strerror_printf("Unknown type in 'sequence_of=%s'", value);
		return -1;
	}

	flags->sequence_of = type;
	flags->is_sequence_of = true;

	return 0;
}

static int dict_flag_set_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_t     type;

	if (flags->is_sequence_of) {
		fr_strerror_const("Cannot be both 'sequence_of=...' and 'set_of=...'");
		return -1;
	}

	if (flags->der_type != FR_DER_TAG_SET) {
		fr_strerror_printf("Cannot use 'set_of=...' for DER type '%s'", fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	if (strcmp(value, "oid_and_value") == 0) {
		(*da_p)->type = FR_TYPE_GROUP;
		flags->is_pair = true;
		return 0;
	}

	type = fr_table_value_by_str(tag_name_to_number, value, FR_DER_TAG_INVALID);
	if (type == FR_DER_TAG_INVALID) {
		fr_strerror_printf("Unknown type in 'set_of=%s'", value);
		return -1;
	}

	flags->set_of = type;
	flags->is_set_of = true;

	return 0;
}

static int dict_flag_is_extensions(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_extensions = true;

	return 0;
}

static int dict_flag_is_oid_leaf(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_oid_leaf = true;

	return 0;
}

static int dict_flag_max(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	unsigned long num;
	char *end = NULL;

	num = strtoul(value, &end, 10);
	if (*end || !num) {
		fr_strerror_printf("Invalid value in 'max=%s'", value);
		return -1;
	}

	flags->max = num;

	return 0;
}

static int dict_flag_option(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	unsigned long num;
	char *end = NULL;

	/*
	 *	In the interest of laziness, allow a bare 'option', so
	 *	that we don't have to give an attribute number, and
	 *	then also duplicate that numbr in 'option='.
	 */
	if (!value) {
		if (!(*da_p)->state.attr_set || (*da_p)->attr > 0x1f) {
			fr_strerror_printf("Missing value for 'option='");
			return -1;
		}

		flags->class = FR_DER_CLASS_CONTEXT;
		flags->option = (*da_p)->attr;
		return 0;
	}

	/*
	 *	We limit the allowed options (tag numbers) to ones
	 *	which fit into the 5 bits of the first byte.  We don't
	 *	support continued tags.
	 */
	num = strtoul(value, &end, 10);
	if ((num > 0x1f) || *end) {
		fr_strerror_printf("Invalid value in 'option=%s'", value);
		return -1;
	}

	flags->class = FR_DER_CLASS_CONTEXT;
	flags->option = num;

	return 0;
}

static const fr_dict_flag_parser_t  der_flags[] = {
//	{ L("class"),		{ .func = dict_flag_class } },
	{ L("der_type"),	{ .func = dict_flag_der_type, .needs_value = true } },
	{ L("has_default"),	{ .func = dict_flag_has_default } },
	{ L("is_extensions"),	{ .func = dict_flag_is_extensions } },
	{ L("is_oid_leaf"),	{ .func = dict_flag_is_oid_leaf } },
	{ L("max"),		{ .func = dict_flag_max, .needs_value = true } },
	{ L("option"),		{ .func = dict_flag_option} },
	{ L("sequence_of"),	{ .func = dict_flag_sequence_of, .needs_value = true } },
	{ L("set_of"),		{ .func = dict_flag_set_of, .needs_value = true } },
};

static bool type_parse(fr_type_t *type_p,fr_dict_attr_t **da_p, char const *name)
{
	static const fr_table_num_sorted_t type_table[] = {
		{ L("bitstring"),	FR_TYPE_OCTETS },
//		{ L("bmpstring"),	FR_TYPE_OCTETS },
		{ L("boolean"),		FR_TYPE_BOOL },
		{ L("choice"),		FR_TYPE_TLV },
		{ L("enumerated"),	FR_TYPE_INT64 },
		{ L("generalizedtime"),	FR_TYPE_DATE },
		{ L("generalstring"),	FR_TYPE_STRING },
		{ L("ia5string"),	FR_TYPE_STRING },
		{ L("integer"),		FR_TYPE_INT64 },
		{ L("null"),		FR_TYPE_BOOL },
		{ L("octetstring"),	FR_TYPE_OCTETS },
		{ L("oid"),		FR_TYPE_STRING },
		{ L("printablestring"),	FR_TYPE_STRING },
		{ L("sequence"),	FR_TYPE_TLV },
		{ L("set"),		FR_TYPE_TLV },
		{ L("t61string"),	FR_TYPE_STRING },
		{ L("universalstring"),	FR_TYPE_STRING },
		{ L("utctime"),		FR_TYPE_DATE },
		{ L("utf8string"),	FR_TYPE_STRING },
		{ L("visiblestring"),	FR_TYPE_STRING },
		{ L("x509_extensions"),	FR_TYPE_GROUP }
	};
	static size_t type_table_len = NUM_ELEMENTS(type_table);

	static const fr_table_num_sorted_t der_tag_table[] = {
		{ L("bitstring"),	FR_DER_TAG_BITSTRING },
//		{ L("bmpstring"),	FR_DER_TAG_BMP_STRING },
		{ L("boolean"),		FR_DER_TAG_BOOLEAN },
		{ L("choice"),		FR_DER_TAG_SEQUENCE },
		{ L("enumerated"),	FR_DER_TAG_ENUMERATED },
		{ L("generalizedtime"),	FR_DER_TAG_GENERALIZED_TIME },
		{ L("generalstring"),	FR_DER_TAG_GENERAL_STRING },
		{ L("ia5string"),	FR_DER_TAG_IA5_STRING },
		{ L("integer"),		FR_DER_TAG_INTEGER },
		{ L("null"),		FR_DER_TAG_NULL },
		{ L("octetstring"),	FR_DER_TAG_OCTETSTRING },
		{ L("oid"),		FR_DER_TAG_OID },
		{ L("printablestring"),	FR_DER_TAG_PRINTABLE_STRING },
		{ L("sequence"),	FR_DER_TAG_SEQUENCE },
		{ L("set"),		FR_DER_TAG_SET },
		{ L("t61string"),	FR_DER_TAG_T61_STRING },
		{ L("universalstring"),	FR_DER_TAG_UNIVERSAL_STRING },
		{ L("utctime"),		FR_DER_TAG_UTC_TIME },
		{ L("utf8string"),	FR_DER_TAG_UTF8_STRING },
		{ L("visiblestring"),	FR_DER_TAG_VISIBLE_STRING },
		{ L("x509_extensions"),	FR_DER_TAG_SEQUENCE }
	};
	static size_t der_tag_table_len = NUM_ELEMENTS(der_tag_table);

	fr_der_attr_flags_t	*flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_t	der_type;
	fr_type_t		fr_type;

	/*
	 *	To avoid confusion, we want to use the DER names where
	 *	possible.
	 *
	 *	We only use the FreeRADIUS names where we don't have a
	 *	choice. :(
	 */
	switch (*type_p) {
	case FR_TYPE_TLV:
		fr_strerror_const("Cannot use 'tlv' in DER.  Please use 'sequence'");
		return false;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_VOID:
	case FR_TYPE_MAX:
		fr_strerror_printf("Cannot use type '%s' in the DER dictionaries",
				   fr_type_to_str(*type_p));
		return false;

		/*
		 *	We allow integers for now.  They may be
		 *	internal, or they may be inside of a struct.
		 */
	default:
		break;
	}

	/*
	 *	Convert the DER data type to the underlying FreeRADIUS
	 *	data type.
	 *
	 *	If we don't know anything about the data type then
	 *	it's either bad, or a data type which we don't care
	 *	about.  We set the der_type, and then return to the
	 *	caller.  It will check *type_p, which is likely
	 *	FR_TYPE_NULL, and will print an error.
	 *
	 *	"return true" here means "I dunno, you deal with it".
	 */
	fr_type = fr_table_value_by_str(type_table, name, FR_TYPE_MAX);
	if (fr_type == FR_TYPE_MAX) {
		flags->der_type = fr_type_to_der_tag_default(*type_p);
		return true;
	}

	/*
	 *	Now that we've converted the DER type to the
	 *	underlying FreeRADIUS type, we get the corresponding
	 *	DER type.  This MUST exist, as the two tables MUST
	 *	have the same names.
	 *
	 *	@todo - arguably they should be in one table....
	 */
	der_type = fr_table_value_by_str(der_tag_table, name, FR_DER_TAG_INVALID);
	fr_assert(der_type != FR_DER_TAG_INVALID);

	/*
	 *	The der type is set only if there are extra flags seen
	 *	and parsed by attr_valid().
	 */
	fr_assert(flags->der_type == FR_DER_TAG_INVALID);

	/*
	 *	Only now do we update the output data type.  From here
	 *	on in, any validation failure will return 'false', and
	 *	not 'true'.
	 */
	*type_p = fr_type;
	flags->der_type = der_type;

	/*
	 *	If it is a collection of x509 extensions, we will set
	 * 	a few other flags as per RFC 5280.
	 */
	if (strcmp(name, "x509_extensions") == 0) {
		flags->is_extensions = true;

		flags->class = FR_DER_CLASS_CONTEXT;
		flags->option = 3;

		flags->is_sequence_of = true;
		flags->sequence_of = FR_DER_TAG_SEQUENCE;
	}

	flags->is_choice = (strcmp(name, "choice") == 0);

	return true;
}

static const fr_der_tag_t fr_type_to_der_tag_defaults[FR_TYPE_MAX + 1] = {
	[FR_TYPE_BOOL]		= FR_DER_TAG_BOOLEAN,
	[FR_TYPE_UINT8]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT16]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT32]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT64]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT8]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT16]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT32]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT64]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_OCTETS]	= FR_DER_TAG_OCTETSTRING,
	[FR_TYPE_STRING]	= FR_DER_TAG_UTF8_STRING,
	[FR_TYPE_DATE]		= FR_DER_TAG_GENERALIZED_TIME,
	[FR_TYPE_TLV]		= FR_DER_TAG_SEQUENCE,
	[FR_TYPE_STRUCT]	= FR_DER_TAG_SEQUENCE,
	[FR_TYPE_GROUP]		= FR_DER_TAG_SEQUENCE,
};

fr_der_tag_t fr_type_to_der_tag_default(fr_type_t type)
{
	return fr_type_to_der_tag_defaults[type];
}

static bool attr_valid(fr_dict_attr_t *da)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(da->parent, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	if (flags->is_sequence_of || flags->is_set_of) {
		fr_der_tag_t of_type = (flags->is_sequence_of ?
					flags->sequence_of :
					flags->set_of);

		if ((unlikely(of_type != FR_DER_TAG_CHOICE)) &&
		    unlikely(fr_type_to_der_tags[da->type][of_type] == false)) {
			fr_strerror_printf("Attribute %s of type %s is not allowed in a sequence/set-of %s",
					   da->name, fr_type_to_str(da->type),
					   fr_table_str_by_value(tag_name_to_number, of_type, "<INVALID>"));
			return false;
		}
	}

	flags = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	if (flags->is_choice && unlikely(!fr_type_is_tlv(da->type))) {
		fr_strerror_printf("Attribute %s of type %s is not allowed represent a collection of choices.",
				   da->name, fr_type_to_str(da->type));
		return false;
	}

	/*
	 *	The DER encoder / decoder assume that all pairs are FR_TYPE_INT64.
	 *
	 *	The "on the wire" DER data has variable-sized encoding for integers,
	 *	and drops leading zeros.
	 *
	 *	For consistency, we disallow data types which the
	 *	encoder/decoder don't handle.  Except for data types
	 *	in structs, because the struct encoder/decoder takes
	 *	care of those.
	 */
	if (fr_type_is_integer_except_bool(da->type) &&
	    !da->flags.internal &&
	    (da->type != FR_TYPE_INT64) &&
	    (da->type != FR_TYPE_DATE) && (da->type != FR_TYPE_TIME_DELTA) &&
	    (da->parent->type != FR_TYPE_STRUCT)) {
		fr_strerror_printf("All integers in DER must be 'int64', and not '%s'",
				   fr_type_to_str(da->type));
		return false;
	}

	if (flags->is_extensions) {
		if (da->type != FR_TYPE_GROUP) {
			fr_strerror_printf("Extensions must be type 'group', and not '%s'",
					   fr_type_to_str(da->type));
			return false;
		}

		/*
		 *	Avoid run-time checks.
		 */
		if (!flags->max) flags->max = UINT64_MAX;
	}

	/*
	 *	Either complain on invalid 'max', or set it to the maximum.
	 */
	if ((flags->der_type != FR_DER_TAG_SET) && (flags->der_type != FR_DER_TAG_SEQUENCE)) {
		if (!flags->max) {
			flags->max = DER_MAX_STR;

		} else if (flags->max > DER_MAX_STR) {
			fr_strerror_printf("Invalid value of 'max' for DER type '%s'",
					   fr_der_tag_to_str(flags->der_type));
			return false;
		}
	}

	/*
	 *	Packed structures can only be bit strings, they can't be sequences or sets.
	 */
	if ((da->type == FR_TYPE_STRUCT) && (flags->der_type != FR_DER_TAG_BITSTRING)) {
		fr_strerror_printf("A 'struct' must be encoded as 'bitstring', and not as '%s'",
				   fr_der_tag_to_str(flags->der_type));
		return false;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_der_dict_protocol;
fr_dict_protocol_t	  libfreeradius_der_dict_protocol = {
	       .name		    = "der",
	       .default_type_size   = 4,
	       .default_type_length = 4,
	       .attr = {
		       .flags = {
			       .table    = der_flags,
			       .table_len = NUM_ELEMENTS(der_flags),
			       .len	   = sizeof(fr_der_attr_flags_t),
		       },
		       .type_parse = type_parse,
		       .valid = attr_valid
	       },

	       .init 	= fr_der_global_init,
	       .free	= fr_der_global_free,

	       // .decode = fr_der_decode_foreign,
	       // .encode = fr_der_encode_foreign,
};
