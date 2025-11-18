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
#include <freeradius-devel/util/dict_ext_priv.h>

#include "attrs.h"
#include "der.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_der;
//fr_dict_attr_t const *attr_oid_tree;

extern fr_dict_autoload_t libfreeradius_der_dict[];
fr_dict_autoload_t	  libfreeradius_der_dict[] = {
	{ .out = &dict_der, .proto = "der" },

	DICT_AUTOLOAD_TERMINATOR
};

extern fr_dict_attr_autoload_t libfreeradius_der_dict_attr[];
fr_dict_attr_autoload_t	       libfreeradius_der_dict_attr[] = {
//	{ .out = &attr_oid_tree, .name = "OID-Tree", .type = FR_TYPE_TLV, .dict = &dict_der },
	DICT_AUTOLOAD_TERMINATOR
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

#define ALL_STRINGS ((1 << FR_DER_TAG_BMP_STRING) | (1 << FR_DER_TAG_GENERAL_STRING) | \
		     (1 << FR_DER_TAG_IA5_STRING) | (1 << FR_DER_TAG_PRINTABLE_STRING) | \
		     (1 << FR_DER_TAG_T61_STRING) | (1 << FR_DER_TAG_UTF8_STRING) | \
		     (1 << FR_DER_TAG_VISIBLE_STRING))

static const uint64_t der_tags_compatible[FR_DER_TAG_MAX] = {
	[FR_DER_TAG_UTC_TIME] = (1 << FR_DER_TAG_GENERALIZED_TIME),
	[FR_DER_TAG_GENERALIZED_TIME] = (1 << FR_DER_TAG_UTC_TIME),

	[FR_DER_TAG_BMP_STRING] = ALL_STRINGS,
	[FR_DER_TAG_GENERAL_STRING] = ALL_STRINGS,
	[FR_DER_TAG_IA5_STRING] = ALL_STRINGS,
	[FR_DER_TAG_PRINTABLE_STRING] = ALL_STRINGS,
	[FR_DER_TAG_T61_STRING] = ALL_STRINGS,
	[FR_DER_TAG_UTF8_STRING] = ALL_STRINGS,
	[FR_DER_TAG_VISIBLE_STRING] = ALL_STRINGS,
};

bool fr_der_tags_compatible(fr_der_tag_t tag1, fr_der_tag_t tag2)
{
	return (der_tags_compatible[tag1] & (1 << (uint64_t) tag2)) != 0;
}

/*
 *	Create a mapping between FR_TYPE_* and valid FR_DER_TAG_*'s
 */
static const bool *fr_type_to_der_tags[FR_DER_TAG_MAX] = {
	[FR_TYPE_IPV4_ADDR] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
	},

	[FR_TYPE_IPV4_PREFIX] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
	},

	[FR_TYPE_IPV6_ADDR] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
	},

	[FR_TYPE_IPV6_PREFIX] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_BITSTRING] = true,
	},

	[FR_TYPE_COMBO_IP_ADDR] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_OCTETSTRING] = true,
	},

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
	},
	[FR_TYPE_GROUP] = (bool [FR_DER_TAG_MAX]) {
		[FR_DER_TAG_SEQUENCE] = true,
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

/*
 *	Allow setting class of APPLICATION and PRIVATE.
 */
static int dict_flag_class(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static const fr_table_num_sorted_t table[] = {
		{ L("application"),	FR_DER_CLASS_APPLICATION },
		{ L("private"),		FR_DER_CLASS_PRIVATE },
	};
	static size_t table_len = NUM_ELEMENTS(table);

	fr_der_attr_flags_t *flags;
	fr_der_tag_class_t   tag_class;

	flags = fr_dict_attr_ext((*da_p)->parent, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	if (flags->der_type != FR_DER_TAG_SEQUENCE) {
		fr_strerror_printf("Cannot use 'class' for attribute %s DER type %s - the parent must be 'sequence'",
				   (*da_p)->parent->name, fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	if ((*da_p)->attr >= FR_DER_TAG_VALUE_MAX) {
		fr_strerror_printf("Cannot use 'class' for attribute %s - the attribute number must be 0..30",
				   (*da_p)->parent->name);
		return -1;
	}

	flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	if (flags->class) {
		fr_strerror_printf("Attribute %s already has a 'class' defined", (*da_p)->name);
		return -1;
	}

	tag_class = fr_table_value_by_str(table, value, FR_DER_CLASS_INVALID);
	if (tag_class == FR_DER_CLASS_INVALID) {
		fr_strerror_printf("Unknown or invalid name in 'class=%s'", value);
		return -1;
	}

	flags->class = tag_class;

	return 0;
}

static int dict_flag_default_value(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	if (!fr_type_is_leaf((*da_p)->type)) {
		fr_strerror_printf("Cannot set 'default=...' for attribute %s DER type %s",
				   (*da_p)->name, fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	/*
	 *	The default values are parented from the dict root.  That way we don't need to copy the values
	 *	when we clone the attribute, we can just copy the pointer.
	 */
	flags->default_value = fr_value_box_alloc(fr_dict_unconst((*da_p)->dict), (*da_p)->type, NULL);
	if (!flags->default_value) return -1;

	if (fr_value_box_from_str(flags->default_value, flags->default_value, (*da_p)->type, NULL,
				  value, strlen(value), NULL) < 0) {
		fr_strerror_printf("Failed parsing 'value=...' - %s", fr_strerror());
		return -1;
	}

	flags->has_default_value = true;

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
		flags->is_oid_and_value = true;
		flags->is_sequence_of = true;
		flags->sequence_of = FR_DER_TAG_SEQUENCE;
		return fr_dict_attr_set_group(da_p);
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
		flags->is_oid_and_value = true;
		flags->is_sequence_of = true;
		flags->sequence_of = FR_DER_TAG_SEQUENCE;
		return fr_dict_attr_set_group(da_p);
	}

	type = fr_table_value_by_str(tag_name_to_number, value, FR_DER_TAG_INVALID);
	if (type == FR_DER_TAG_INVALID) {
		fr_strerror_printf("Unknown type in 'set_of=%s'", value);
		return -1;
	}

	/*
	 *	The "choice" can only be used for sequence.
	 */
	if (type == FR_DER_TAG_CHOICE) {
		fr_strerror_printf("Invalid type in 'set_of=%s' - 'choice' can only be used for sequences", value);
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

	/*
	 *	is_oid_leaf is perhaps better as a property of the _parent_ sequence.  It ensures that we only
	 *	walk through the sequences children once.
	 */
	if (fr_der_flag_der_type((*da_p)->parent) != FR_DER_TAG_SEQUENCE) {
		fr_strerror_printf("Cannot set 'is_oid_leaf' for parent %s of DER type %s",
				   (*da_p)->parent->name, fr_der_tag_to_str(fr_der_flag_der_type((*da_p)->parent)));
		return -1;
	}

	flags->is_oid_leaf = true;

	return 0;
}

/*
 *	size=MIN..MAX
 */
static int dict_flag_size(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	unsigned long num;
	char const *p = value;
	char *end = NULL;

	if (fr_type_is_leaf((*da_p)->type) && !fr_type_is_variable_size((*da_p)->type)) {
		fr_strerror_printf("Cannot use 'size=...' for type '%s'", fr_type_to_str((*da_p)->type));
		return -1;
	}

	/*
	 *	size=..max
	 */
	if ((p[0] == '.') && (p[1] == '.')) goto check_max;

	num = strtoul(p, &end, 10);
	if (num == ULONG_MAX) {
	invalid:
		fr_strerror_printf("Invalid value in 'size=%s'", value);
		return -1;
	}

	if (num > UINT8_MAX) {
		fr_strerror_printf("Invalid value in 'size=%s' - 'min' value is too large", value);
		return -1;
	}

	/*
	 *	size=4
	 *
	 *	Fixed size, but not size=0.
	 */
	if (!*end) {
		if (!num) goto invalid;

		/*
		 *	printablestring	size=2
		 *
		 *	instead of string[2] der_type=printablestring
		 */
		if (((*da_p)->type == FR_TYPE_OCTETS) || ((*da_p)->type == FR_TYPE_STRING)) {
			(*da_p)->flags.is_known_width = !fr_type_is_structural((*da_p)->type);
			(*da_p)->flags.length = num;
			return 0;
		}

		/*
		 *	Sets and sequences can have a fixed number of elements.
		 */
		flags->min = flags->max = num;
		return 0;
	}

	if ((end[0] != '.') || (end[1] != '.')) {
		fr_strerror_printf("Invalid value in 'size=%s' - unexpected data after 'min'", value);
		return -1;
	}

	flags->min = num;

	/*
	 *	size=1..
	 *
	 *	Sets the minimum, but not the maximum.
	 */
	p = end + 2;
	if (!*p) return 0;

check_max:
	num = strtoul(p, &end, 10);
	if (num == ULONG_MAX) goto invalid;

	if (*end) {
		fr_strerror_printf("Invalid value in 'size=%s' - unexpected data after 'max'", value);
		return -1;
	}

	flags->max = num;

	return 0;
}

static int dict_flag_max(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	unsigned long num;
	char *end = NULL;

	num = strtoul(value, &end, 10);
	if (*end || !num || (num == ULONG_MAX)) {
		fr_strerror_printf("Invalid value in 'max=%s'", value);
		return -1;
	}

	flags->max = num;

	return 0;
}

static int dict_flag_option(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags;
	unsigned long num;
	char *end = NULL;

	/*
	 *	Only SET and SEQUENCE can have tagged types.
	 */
	flags = fr_dict_attr_ext((*da_p)->parent, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	if (!(*da_p)->parent->flags.is_root &&
	    (flags->der_type != FR_DER_TAG_SEQUENCE) && (flags->der_type != FR_DER_TAG_SET)) {
		fr_strerror_printf("Cannot use 'option' for attribute %s DER type %s - the parent must be 'sequence' or 'set'",
				   (*da_p)->parent->name, fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	/*
	 *	In the interest of laziness, allow a bare 'option', so
	 *	that we don't have to give an attribute number, and
	 *	then also duplicate that number in 'option='.
	 */
	if (!value) {
		if (!(*da_p)->state.attr_set || (*da_p)->attr > 0x1f) {
			fr_strerror_printf("Missing value for 'option='");
			return -1;
		}

		num = (*da_p)->attr;
		goto check;
	}

	/*
	 *	ATTRIBUTE can't have 'option='.
	 */
	if ((*da_p)->state.attr_set) {
		fr_strerror_printf("Cannot use 'option=%s' for attribute %s, just use 'option'", value, (*da_p)->name);
		return -1;
	}

	/*
	 *	We limit the allowed options (tag numbers) to ones
	 *	which fit into the 5 bits of the first byte.  We don't
	 *	support continued tags.
	 */
	num = strtoul(value, &end, 10);
	if ((num == ULONG_MAX) || *end) {
		fr_strerror_printf("Invalid value in 'option=%s'", value);
		return -1;
	}

check:
	if (num >= FR_DER_TAG_VALUE_MAX) {
		fr_strerror_printf("Option value '%lu' is larger than 30", num);
		return -1;
	}

	flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	flags->class = FR_DER_CLASS_CONTEXT;
	flags->option = num;
	flags->is_option = true;

	return 0;
}

static int dict_flag_optional(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	fr_der_attr_flags_t *flags;

	/*
	 *	Only SET and SEQUENCE can have optional elements.
	 */
	flags = fr_dict_attr_ext((*da_p)->parent, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	if (!(*da_p)->parent->flags.is_root &&
	    (flags->der_type != FR_DER_TAG_SEQUENCE) && (flags->der_type != FR_DER_TAG_SET)) {
		fr_strerror_printf("Cannot use 'optional' for attribute %s DER type %s - the parent must be 'sequence' or 'set'",
				   (*da_p)->parent->name, fr_der_tag_to_str(flags->der_type));
		return -1;
	}

	flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	flags->optional = true;

	return 0;
}

static const fr_dict_flag_parser_t  der_flags[] = {
	{ L("class"),		{ .func = dict_flag_class } },
	{ L("default"),		{ .func = dict_flag_default_value,.needs_value = true } },
	{ L("der_type"),	{ .func = dict_flag_der_type, .needs_value = true } },
	{ L("is_extensions"),	{ .func = dict_flag_is_extensions } },
	{ L("is_oid_leaf"),	{ .func = dict_flag_is_oid_leaf } },
	{ L("max"),		{ .func = dict_flag_max, .needs_value = true } },
	{ L("option"),		{ .func = dict_flag_option} },
	{ L("optional"),       	{ .func = dict_flag_optional} },
	{ L("sequence_of"),	{ .func = dict_flag_sequence_of, .needs_value = true } },
	{ L("set_of"),		{ .func = dict_flag_set_of, .needs_value = true } },
	{ L("size"),		{ .func = dict_flag_size, .needs_value=true } },
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

	default:
	invalid_type:
		fr_strerror_printf("Cannot use type '%s' in the DER dictionaries",
				   fr_type_to_str(*type_p));
		return false;

		/*
		 *	We allow all integer types.  They may be
		 *	internal, or they may be inside of a struct.
		 */
	case FR_TYPE_NULL:
	case FR_TYPE_INTEGER:
	case FR_TYPE_VARIABLE_SIZE:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_STRUCT:
	case FR_TYPE_GROUP:
	case FR_TYPE_ATTR:
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
		if (!flags->der_type) goto invalid_type;
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
		flags->is_option = true;

		flags->is_sequence_of = true;
		flags->sequence_of = FR_DER_TAG_SEQUENCE;
	}

	/*
	 *	If this is a choice, then the children MUST have a limited option.
	 */
	flags->is_choice = (strcmp(name, "choice") == 0);

	return true;
}

static const fr_der_tag_t fr_type_to_der_tag_defaults[FR_TYPE_MAX + 1] = {
	[FR_TYPE_OCTETS]	= FR_DER_TAG_OCTETSTRING,
	[FR_TYPE_STRING]	= FR_DER_TAG_UTF8_STRING,

	[FR_TYPE_IPV4_ADDR]	= FR_DER_TAG_BITSTRING,
	[FR_TYPE_IPV4_PREFIX]	= FR_DER_TAG_BITSTRING,
	[FR_TYPE_IPV6_ADDR]	= FR_DER_TAG_BITSTRING,
	[FR_TYPE_IPV6_PREFIX]	= FR_DER_TAG_BITSTRING,

	[FR_TYPE_COMBO_IP_ADDR] = FR_DER_TAG_OCTETSTRING,

	[FR_TYPE_BOOL]		= FR_DER_TAG_BOOLEAN,

	[FR_TYPE_UINT8]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT16]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT32]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT64]	= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT8]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT16]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT32]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_INT64]		= FR_DER_TAG_INTEGER,
	[FR_TYPE_DATE]		= FR_DER_TAG_GENERALIZED_TIME,
	[FR_TYPE_TLV]		= FR_DER_TAG_SEQUENCE,
	[FR_TYPE_STRUCT]	= FR_DER_TAG_BITSTRING,
	[FR_TYPE_GROUP]		= FR_DER_TAG_SEQUENCE,
};

fr_der_tag_t fr_type_to_der_tag_default(fr_type_t type)
{
	return fr_type_to_der_tag_defaults[type];
}

static bool attr_valid(fr_dict_attr_t *da)
{
	fr_der_attr_flags_t *flags = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_der_attr_flags_t *parent;

	/*
	 *	sequence_of=oid_and_value has to have a reference to the OID tree.
	 *
	 *	Group refs are added as unresolved refs, see dict_flag_ref(), and are resolved later
	 *	in dict_fixup_group_apply().
	 *
	 *	@todo - have a function called from dict_attr_finalize() ?
	 */
#if 0
	if (flags->is_oid_and_value) {
		fr_dict_attr_t const *ref;

		fr_assert(da->type == FR_TYPE_GROUP);

		if (!fr_dict_attr_ref(da)) {
			(void) dict_attr_ref_set(da, attr_oid_tree, FR_DICT_ATTR_REF_ALIAS);
		}
	}
#endif

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

#if 0
		/*
		 *	Group refs are added as unresolved refs, see dict_flag_ref(), and are resolved later
		 *	in dict_fixup_group_apply().
		 *
		 *	@todo - have a function called from dict_attr_finalize() ?
		 */
		if (!fr_dict_attr_ref(da)) {
			fr_strerror_const("Attribute is 'x509_extensions', but is missing 'ref=OID-Tree'");
			return false;
		}
#endif

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
	 *	Set the restriction types, which make the run-time decoding a lot easier.
	 */
	if (flags->is_set_of) {
		flags->restrictions = (1 << flags->set_of);
	}

	if (flags->is_sequence_of) {
		/*
		 *	If the sequence isn't a choice, it has to be a sequence of one thing.
		 *
		 *	If the sequence is group, then it has to be a sequence of sequences.
		 *
		 *	If the sequence is a TLV, then the children will update the restrictions.
		 */
		if (flags->sequence_of != FR_DER_TAG_CHOICE) {
			flags->restrictions = (1 << flags->sequence_of);

		} else if (da->type == FR_TYPE_GROUP) {
#ifndef NDEBUG
			fr_dict_attr_t const *ref;

			ref = fr_dict_attr_ref(da);
			if (ref) {
				fr_assert(fr_der_flag_der_type(ref) == FR_DER_TAG_SEQUENCE);
			}
#endif

			/*
			 *	A group of choices is really a sequence of sequences.  i.e. x509extensions
			 *	contain only a sequence, as does sequence_of=oid_and_value.
			 */
			flags->restrictions = (1 << FR_DER_TAG_SEQUENCE);

		} else {
			/*
			 *	The children will update our restriction types.
			 */
			fr_assert(da->type == FR_TYPE_TLV);
		}
	}

	/*
	 *	If the parent is a choice, then the child MUST have a limited set of options / tags.
	 */
	parent = fr_dict_attr_ext(da->parent, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	/*
	 *	The attribute was defined with the full OID, and no 'option' flag.  Add it manually.
	 */
	if ((parent->is_choice && !flags->is_option) ||
	    (flags->class == FR_DER_CLASS_PRIVATE) || (flags->class == FR_DER_CLASS_APPLICATION)) {
		fr_assert(da->attr < FR_DER_TAG_VALUE_MAX);

		if (!flags->class) flags->class = FR_DER_CLASS_CONTEXT;
		flags->option = da->attr;
		flags->is_option = true;
	}

	/*
	 *	Can't have duplicates.
	 */
	if (flags->is_option) {
		if ((parent->restrictions & (1 << flags->option)) != 0) {
			fr_strerror_printf("Parent %s already has a child with option %u - duplicates are not allowed",
					   da->parent->name, flags->option);
			return false;
		}

		parent->restrictions |= (1 << flags->option);

	} else if (parent->is_sequence_of && (parent->sequence_of == FR_DER_TAG_CHOICE)) {
		fr_assert(flags->der_type < FR_DER_TAG_VALUE_MAX);

		flags->class = FR_DER_CLASS_CONTEXT;
//		flags->option = flags->der_type;

		if ((parent->restrictions & (1 << flags->der_type)) != 0) {
			fr_strerror_printf("Parent %s already has a child with tag %s - duplicates are not allowed",
					   da->parent->name, fr_der_tag_to_str(flags->der_type));
			return false;
		}

		parent->restrictions |= (1 << flags->der_type);

	} else if (parent->is_sequence_of) {
		if (flags->der_type != parent->sequence_of) {
			fr_strerror_printf("Parent %s is a sequence_of=%s - a child cannot be %s",
					   da->parent->name, fr_der_tag_to_str(parent->set_of),
					   fr_der_tag_to_str(flags->der_type));
			return false;
		}

		/*
		 *	A sequence can sometimes have mixed tags && options.
		 */
		fr_assert(!flags->is_option);

	} else if (parent->is_set_of) {
		if (flags->der_type != parent->set_of) {
			fr_strerror_printf("Parent %s is a set_of=%s - a child cannot be %s",
					   da->parent->name, fr_der_tag_to_str(parent->set_of),
					   fr_der_tag_to_str(flags->der_type));
			return false;
		}
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
