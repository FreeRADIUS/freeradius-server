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

fr_der_tag_constructed_t tag_labels[] = {
	[FR_DER_TAG_BOOLEAN]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_INTEGER]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_BITSTRING]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_OCTETSTRING]      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_NULL]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_OID]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_ENUMERATED]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_UTF8_STRING]      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_SEQUENCE]	      = FR_DER_TAG_CONSTRUCTED,
	[FR_DER_TAG_SET]	      = FR_DER_TAG_CONSTRUCTED,
	[FR_DER_TAG_PRINTABLE_STRING] = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_T61_STRING]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_IA5_STRING]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_UTC_TIME]	      = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_GENERALIZED_TIME] = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_VISIBLE_STRING]   = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_GENERAL_STRING]   = FR_DER_TAG_PRIMITIVE,
	[FR_DER_TAG_UNIVERSAL_STRING] = FR_DER_TAG_PRIMITIVE,
};

fr_table_num_sorted_t const tag_name_to_number[] = {
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

/*
 *	Create a mapping between FR_TYPE_* and valid FR_DER_TAG_*'s
 */
static const bool *fr_type_to_der_tags[] = {
	[FR_TYPE_MAX] = NULL,
	[FR_TYPE_BOOL] = (bool []){[FR_DER_TAG_BOOLEAN] = true,
				   [FR_DER_TAG_INTEGER] = true,
				   [FR_DER_TAG_NULL] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT8] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT16] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT32] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT64] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT8] = (bool []){[FR_DER_TAG_INTEGER] = true,
				   [FR_DER_TAG_ENUMERATED] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT16] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT32] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT64] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_OCTETS] = (bool []){[FR_DER_TAG_BITSTRING] = true,
				     [FR_DER_TAG_OCTETSTRING] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_STRING] = (bool []){[FR_DER_TAG_OID] = true,
				     [FR_DER_TAG_UTF8_STRING] = true,
				     [FR_DER_TAG_PRINTABLE_STRING] = true,
				     [FR_DER_TAG_T61_STRING] = true,
				     [FR_DER_TAG_IA5_STRING] = true,
				     [FR_DER_TAG_VISIBLE_STRING] = true,
				     [FR_DER_TAG_GENERAL_STRING] = true,
				     [FR_DER_TAG_UNIVERSAL_STRING] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_DATE] = (bool []){[FR_DER_TAG_UTC_TIME] = true,
				   [FR_DER_TAG_GENERALIZED_TIME] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_TLV] = (bool []){[FR_DER_TAG_SEQUENCE] = true,
				  [FR_DER_TAG_SET] = true,
				  [FR_DER_TAG_MAX] = false},
	[FR_TYPE_STRUCT] = (bool []){[FR_DER_TAG_BITSTRING] = true,
				     [FR_DER_TAG_SEQUENCE] = true,
				     [FR_DER_TAG_SET] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_GROUP] = (bool []){[FR_DER_TAG_SEQUENCE] = true,
				    [FR_DER_TAG_SET] = true,
				    [FR_DER_TAG_MAX] = false}
};

/*
 *	Return true if the given type can be encoded as the given tag.
 * 		@param[in] type The fr_type to check.
 * 		@param[in] tag The der tag to check.
 * 		@return true if the type can be encoded as the given tag.
 */
bool fr_type_to_der_tag_valid(fr_type_t type, fr_der_tag_num_t tag)
{
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

static int dict_flag_tagnum(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	unsigned long num;
	char *end = NULL;

	num = strtoul(value, &end, 10);
	if ((num > 255) || *end) {
		fr_strerror_printf("Invalid tag number '%s'", value);
		return -1;
	}

	flags->tagnum = num;

	return 0;
}

static int dict_flag_class(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("application"),	FR_DER_CLASS_APPLICATION },
		{ L("context-specific"), FR_DER_CLASS_CONTEXT },
		{ L("private"),		FR_DER_CLASS_PRIVATE },
		{ L("universal"),	FR_DER_CLASS_UNIVERSAL },
	};
	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_class_t   tag_class;

	tag_class = fr_table_value_by_str(table, value, FR_DER_CLASS_INVALID);
	if (tag_class == FR_DER_CLASS_INVALID) {
		fr_strerror_printf("Invalid tag class '%s'", value);
		return -1;
	}

	flags->class = tag_class;

	return 0;
}

static int dict_flag_has_default(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->has_default = true;

	return 0;
}

static int dict_flag_der_type(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     der_type;

	der_type = fr_table_value_by_str(tag_name_to_number, value, UINT8_MAX);
	if (der_type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag der_type '%s'", value);
		return -1;
	}

	flags->der_type = der_type;

	return 0;
}

static int dict_flag_sequence_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     type;

	type = fr_table_value_by_str(tag_name_to_number, value, UINT8_MAX);
	if (type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag type '%s'", value);
		return -1;
	}

	flags->sequence_of = type;
	flags->is_sequence_of = true;

	return 0;
}

static int dict_flag_set_of(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_tag_num_t     type;

	type = fr_table_value_by_str(tag_name_to_number, value, UINT8_MAX);
	if (type == UINT8_MAX) {
		fr_strerror_printf("Invalid tag type '%s'", value);
		return -1;
	}

	flags->set_of = type;
	flags->is_set_of = true;

	return 0;
}

static int dict_flag_is_pair(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_pair = true;

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

static int dict_flag_is_pairs(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_pairs = true;

	return 0;
}

static int dict_flag_is_choice(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->is_choice = true;

	return 0;
}

static int dict_flag_max(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	if (!isdigit((int64_t) *value)) {
		fr_strerror_printf("Invalid max value '%s'", value);
		return -1;
	}

	flags->max = (int64_t)atoll(value);

	return 0;
}

static int dict_flag_option(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	flags->class = FR_DER_CLASS_CONTEXT;

	if (!isdigit((uint8_t) *value)) {
		fr_strerror_printf("Invalid option value '%s'", value);
		return -1;
	}
	flags->tagnum = (uint8_t)atoi(value);

	return 0;
}

static fr_dict_flag_parser_t const der_flags[] = {
	{ L("class"),		{ .func = dict_flag_class } },
	{ L("der_type"),	{ .func = dict_flag_der_type, .needs_value = true } },
	{ L("has_default"),	{ .func = dict_flag_has_default } },
	{ L("is_choice"),	{ .func = dict_flag_is_choice } },
	{ L("is_extensions"),	{ .func = dict_flag_is_extensions } },
	{ L("is_oid_leaf"),	{ .func = dict_flag_is_oid_leaf } },
	{ L("is_pair"),		{ .func = dict_flag_is_pair } },
	{ L("is_pairs"),	{ .func = dict_flag_is_pairs } },
	{ L("max"),		{ .func = dict_flag_max } },
	{ L("option"),		{ .func = dict_flag_option } },
	{ L("sequence_of"),	{ .func = dict_flag_sequence_of } },
	{ L("set_of"),		{ .func = dict_flag_set_of } },
	{ L("tagnum"),		{ .func = dict_flag_tagnum } }
};

static bool attr_type(fr_type_t *type ,fr_dict_attr_t **da_p, char const *name)
{
	static fr_table_num_sorted_t const type_table[] = {
		{ L("bitstring"),	FR_TYPE_OCTETS },
		{ L("boolean"),		FR_TYPE_BOOL },
		{ L("choice"),		FR_TYPE_TLV },
		{ L("enumerated"),	FR_TYPE_INT64 },
		{ L("generalizedtime"),	FR_TYPE_DATE },
		{ L("generalstring"),	FR_TYPE_STRING },
		{ L("ia5string"),	FR_TYPE_STRING },
		{ L("null"),		FR_TYPE_NULL },
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

	static fr_table_num_sorted_t const der_tag_table[] = {
		{ L("bitstring"),	FR_DER_TAG_BITSTRING },
		{ L("bmpstring"),	FR_DER_TAG_BMP_STRING },
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
	fr_der_tag_num_t	der_type;

	*type = fr_table_value_by_str(type_table, name, UINT8_MAX);
	if (*type == UINT8_MAX) {
		fr_strerror_printf("Invalid type '%s'", name);
		return false;
	}

	/*
	 *	Make sure to set the der_type flag
	 * 	This will ensure the attribute it encoded with the correct type
	 */
	der_type = fr_table_value_by_str(der_tag_table, name, UINT8_MAX);
	if (der_type == UINT8_MAX) {
		fr_strerror_printf("Invalid der_type '%s'", name);
		return false;
	}

	flags->der_type = der_type;

	/*
	 *	If it is a collection of x509 extensions, we will set a few other flags
	 * 	as per RFC 5280.
	 */
	if (*type == FR_TYPE_GROUP) {
		dict_flag_is_extensions(da_p, "true", NULL);
		dict_flag_tagnum(da_p, "3", NULL);
		dict_flag_class(da_p, "context-specific", NULL);
		dict_flag_sequence_of(da_p, "sequence", NULL);
	}

	flags->is_choice = (strcmp(name, "choice") == 0);

	return true;
}

static const int fr_type_to_der_tag_defaults[] = {
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

fr_der_tag_num_t fr_type_to_der_tag_default(fr_type_t type)
{
	return fr_type_to_der_tag_defaults[type];
}

static bool attr_valid(fr_dict_attr_t *da)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	if (fr_der_flag_is_sequence_of(da->parent) ||
	    fr_der_flag_is_set_of(da->parent)) {
		uint8_t of_type = (fr_der_flag_is_sequence_of(da->parent) ?
				   fr_der_flag_sequence_of(da->parent) :
				   fr_der_flag_set_of(da->parent));

		if ((unlikely(of_type != FR_DER_TAG_CHOICE)) &&
		    unlikely(fr_type_to_der_tags[da->type][of_type] == false)) {
			fr_strerror_printf("Attribute %s of type %s is not allowed in a sequence/set-of %s",
					   da->name, fr_type_to_str(da->type),
					   fr_table_str_by_value(tag_name_to_number, of_type, "<INVALID>"));
			return false;
		}
	}

	if (fr_der_flag_is_choice(da) && unlikely(!fr_type_is_tlv(da->type))) {
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
	if (fr_type_is_integer_except_bool(da->type) && (da->type != FR_TYPE_INT64) &&
	    (da->type != FR_TYPE_DATE) && (da->type != FR_TYPE_TIME_DELTA) &&
	    (da->parent->type != FR_TYPE_STRUCT)) {
		fr_strerror_printf("All integers in DER must be 'int64', and not '%s'",
				   fr_type_to_str(da->type));
		return false;
	}

	/*
	 *	The der type is already set, we don't need to do more.
	 */
	if (flags->der_type != FR_DER_TAG_INVALID) return true;

	flags->der_type = fr_type_to_der_tag_defaults[da->type];

	/*
	 *	Not all FreeRADIUS types map to DER types.  Ones like
	 *	VSA are not supported.
	 */
	if (flags->der_type == FR_DER_TAG_INVALID) {
		fr_strerror_printf("Invalid data type '%s' is not supported by DER",
				  fr_type_to_str(da->type));
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
		       .type_parse = attr_type,
		       .valid = attr_valid
	       },

	       .init 	= fr_der_global_init,
	       .free	= fr_der_global_free,

	       // .decode = fr_der_decode_foreign,
	       // .encode = fr_der_encode_foreign,
};
