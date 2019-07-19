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

/** Multi-protocol AVP dictionary API
 *
 * @file src/lib/util/dict.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "dict.h"

#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>

#include <ctype.h>
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#define MAX_ARGV (16)

#define DICT_POOL_SIZE		(1024 * 1024 * 2)
#define DICT_FIXUP_POOL_SIZE	(1024 * 1024 * 1)

static TALLOC_CTX	*dict_ctx;
static fr_hash_table_t	*protocol_by_name = NULL;	//!< Hash containing names of all the registered protocols.
static fr_hash_table_t	*protocol_by_num = NULL;	//!< Hash containing numbers of all the registered protocols.
static char		*default_dict_dir;		//!< The default location for loading dictionaries if one
							///< wasn't provided.

/** Magic internal dictionary
 *
 * Internal dictionary is checked in addition to the protocol dictionary
 * when resolving attribute names.
 *
 * This is because internal attributes are valid for every
 * protocol.
 */
fr_dict_t	*fr_dict_internal = NULL;	//!< Internal server dictionary.

typedef struct dict_enum_fixup_s dict_enum_fixup_t;

/** A temporary enum value, which we'll resolve later
 *
 */
struct dict_enum_fixup_s {
	char			*attribute;		//!< we couldn't find (and will need to resolve later).
	char			*alias;			//!< Raw enum name.
	char			*value;			//!< Raw enum value.  We can't do anything with this until
							//!< we know the attribute type, which we only find out later.

	dict_enum_fixup_t	*next;			//!< Next in the linked list of fixups.
};

/** Vendors and attribute names
 *
 * It's very likely that the same vendors will operate in multiple
 * protocol spaces, but number their attributes differently, so we need
 * per protocol dictionaries.
 *
 * There would also be conflicts for DHCP(v6)/RADIUS attributes etc...
 */
struct fr_dict {
	bool			in_protocol_by_name;	//!< Whether the dictionary has been inserted into the
							///< protocol_by_name hash.
	bool			in_protocol_by_num;	//!< Whether the dictionary has been inserted into the
							//!< protocol_by_num table.

	bool			autoloaded;		//!< manual vs autoload

	fr_hash_table_t		*vendors_by_name;	//!< Lookup vendor by name.
	fr_hash_table_t		*vendors_by_num;	//!< Lookup vendor by PEN.

	fr_hash_table_t		*attributes_by_name;	//!< Allow attribute lookup by unique name.

	fr_hash_table_t		*attributes_combo;	//!< Lookup variants of polymorphic attributes.

	fr_hash_table_t		*values_by_da;		//!< Lookup an attribute enum by its value.
	fr_hash_table_t		*values_by_alias;	//!< Lookup an attribute enum by its alias name.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.

	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce allocs.
							///< in the dictionary.
};

/** Map data types to min / max data sizes
 */
size_t const dict_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]	= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]	= {0, ~0},
	[FR_TYPE_OCTETS]	= {0, ~0},

	[FR_TYPE_IPV4_ADDR]	= {4, 4},
	[FR_TYPE_IPV4_PREFIX]	= {6, 6},
	[FR_TYPE_IPV6_ADDR]	= {16, 16},
	[FR_TYPE_IPV6_PREFIX]	= {2, 18},
	[FR_TYPE_COMBO_IP_ADDR]	= {4, 16},
	[FR_TYPE_IFID]		= {8, 8},
	[FR_TYPE_ETHERNET]	= {6, 6},

	[FR_TYPE_BOOL]		= {1, 1},
	[FR_TYPE_UINT8]		= {1, 1},
	[FR_TYPE_UINT16]	= {2, 2},
	[FR_TYPE_UINT32]	= {4, 4},
	[FR_TYPE_UINT64]	= {8, 8},
	[FR_TYPE_SIZE]		= {sizeof(size_t), sizeof(size_t)},
	[FR_TYPE_INT32]		= {4, 4},

	[FR_TYPE_DATE]		= {4, 4},
	[FR_TYPE_ABINARY]	= {32, ~0},

	[FR_TYPE_TLV]		= {2, ~0},
	[FR_TYPE_STRUCT]	= {1, ~0},

	[FR_TYPE_EXTENDED]	= {1, ~0},

	[FR_TYPE_VSA]		= {4, ~0},
	[FR_TYPE_EVS]		= {6, ~0},

	[FR_TYPE_MAX]		= {~0, 0}	//!< Ensure array covers all types.
};

/** Characters allowed in dictionary names
 *
 */
bool const fr_dict_attr_allowed_chars[UINT8_MAX] = {
	['-'] = true, ['.'] = true, ['/'] = true, ['_'] = true,
	['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true,
	['5'] = true, ['6'] = true, ['7'] = true, ['8'] = true, ['9'] = true,
	['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true, ['E'] = true,
	['F'] = true, ['G'] = true, ['H'] = true, ['I'] = true, ['J'] = true,
	['K'] = true, ['L'] = true, ['M'] = true, ['N'] = true, ['O'] = true,
	['P'] = true, ['Q'] = true, ['R'] = true, ['S'] = true, ['T'] = true,
	['U'] = true, ['V'] = true, ['W'] = true, ['X'] = true, ['Y'] = true,
	['Z'] = true,
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true,
	['f'] = true, ['g'] = true, ['h'] = true, ['i'] = true, ['j'] = true,
	['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true, ['o'] = true,
	['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true,
	['u'] = true, ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true,
	['z'] = true
};

/** Structural data types
 *
 */
bool const fr_dict_non_data_types[FR_TYPE_MAX + 1] = {
	[FR_TYPE_TLV] = true,
	[FR_TYPE_STRUCT] = true,
	[FR_TYPE_EXTENDED] = true,
	[FR_TYPE_VSA] = true,
	[FR_TYPE_EVS] = true,
	[FR_TYPE_VENDOR] = true
};

static FR_NAME_NUMBER const date_precision_table[] = {
	{ "seconds",		FR_TIME_RES_SEC },
	{ "milliseconds",	FR_TIME_RES_MSEC },
	{ "microseconds",	FR_TIME_RES_USEC },
	{ "nanoseconds",	FR_TIME_RES_NSEC },

	{ NULL,			0 }
};

/*
 *	Create the hash of the name.
 *
 *	We copy the hash function here because it's substantially faster.
 */
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

/** Set the internal dictionary if none was provided
 *
 * @param _dict		Dict pointer to check/set.
 * @param _ret		Value to return if no dictionaries are available.
 */
#define INTERNAL_IF_NULL(_dict, _ret) \
	do { \
		if (!(_dict)) { \
			_dict = fr_dict_internal; \
			if (unlikely(!(_dict))) { \
				fr_strerror_printf("No dictionaries available for attribute resolution"); \
				return (_ret); \
			} \
		} \
	} while (0)

/** Empty callback for hash table initialization
 *
 */
static int hash_null_callback(UNUSED void *ctx, UNUSED void *data)
{
	return 0;
}

static void hash_pool_free(void *to_free)
{
	talloc_free(to_free);
}

/** Apply a simple (case insensitive) hashing function to the name of an attribute, vendor or protocol
 *
 * @param[in] name	of the attribute, vendor or protocol.
 * @param[in] len	length of the input string.
 *
 * @return the hashed derived from the name.
 */
static uint32_t dict_hash_name(char const *name, size_t len)
{
	uint32_t hash = FNV_MAGIC_INIT;

	char const *p = name, *q = name + len;

	while (p < q) {
		int c = *(unsigned char const *)p;
		if (isalpha(c)) c = tolower(c);

		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t)(c & 0xff);
		p++;
	}

	return hash;
}

/** Wrap name hash function for fr_dict_protocol_t
 *
 * @param[in]	data fr_dict_attr_t to hash.
 * @return the hash derived from the name of the attribute.
 */
static uint32_t dict_protocol_name_hash(void const *data)
{
	char const *name;

	name = ((fr_dict_t const *)data)->root->name;

	return dict_hash_name(name, strlen(name));
}

/** Compare two protocol names
 *
 */
static int dict_protocol_name_cmp(void const *one, void const *two)
{
	fr_dict_t const *a = one;
	fr_dict_t const *b = two;

	return strcasecmp(a->root->name, b->root->name);
}

/** Hash a protocol number
 *
 */
static uint32_t dict_protocol_num_hash(void const *data)
{
	return fr_hash(&(((fr_dict_t const *)data)->root->attr), sizeof(((fr_dict_t const *)data)->root->attr));
}

/** Compare two protocol numbers
 *
 */
static int dict_protocol_num_cmp(void const *one, void const *two)
{
	fr_dict_t const *a = one;
	fr_dict_t const *b = two;

	return a->root->attr - b->root->attr;
}

/** Wrap name hash function for fr_dict_attr_t
 *
 * @param data		fr_dict_attr_t to hash.
 * @return the hash derived from the name of the attribute.
 */
static uint32_t dict_attr_name_hash(void const *data)
{
	char const *name;

	name = ((fr_dict_attr_t const *)data)->name;

	return dict_hash_name(name, strlen(name));
}

/** Compare two attribute names
 *
 */
static int dict_attr_name_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one, *b = two;

	return strcasecmp(a->name, b->name);
}

/** Hash a combo attribute
 *
 */
static uint32_t dict_attr_combo_hash(void const *data)
{
	uint32_t hash;
	fr_dict_attr_t const *attr = data;

	hash = fr_hash(&attr->parent, sizeof(attr->parent));			//-V568
	hash = fr_hash_update(&attr->type, sizeof(attr->type), hash);
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

/** Compare two combo attribute entries
 *
 */
static int dict_attr_combo_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one, *b = two;
	int ret;

	ret = (a->parent < b->parent) - (a->parent > b->parent);
	if (ret != 0) return ret;

	ret = (a->type < b->type) - (a->type > b->type);
	if (ret != 0) return ret;

	return (a->attr > b->attr) - (a->attr < b->attr);
}

/** Wrap name hash function for fr_dict_vendor_t
 *
 * @param data fr_dict_vendor_t to hash.
 * @return the hash derived from the name of the attribute.
 */
static uint32_t dict_vendor_name_hash(void const *data)
{
	char const *name;

	name = ((fr_dict_vendor_t const *)data)->name;

	return dict_hash_name(name, strlen(name));
}

/** Compare two attribute names
 *
 */
static int dict_vendor_name_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return strcasecmp(a->name, b->name);
}

/** Hash a vendor number
 *
 */
static uint32_t dict_vendor_pen_hash(void const *data)
{
	return fr_hash(&(((fr_dict_vendor_t const *)data)->pen),
		       sizeof(((fr_dict_vendor_t const *)data)->pen));
}

/** Compare two vendor numbers
 *
 */
static int dict_vendor_pen_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return a->pen - b->pen;
}

/** Hash a dictionary name
 *
 */
static uint32_t dict_enum_alias_hash(void const *data)
{
	uint32_t hash;
	fr_dict_enum_t const *enumv = data;

	hash = dict_hash_name((void const *)enumv->alias, enumv->alias_len);

	return fr_hash_update(&enumv->da, sizeof(enumv->da), hash);		//-V568
}

/** Compare two dictionary attribute enum values
 *
 */
static int dict_enum_alias_cmp(void const *one, void const *two)
{
	int rcode;
	fr_dict_enum_t const *a = one;
	fr_dict_enum_t const *b = two;

	rcode = a->da - b->da;
	if (rcode != 0) return rcode;

	return strcasecmp(a->alias, b->alias);
}

/** Hash a dictionary enum value
 *
 */
static uint32_t dict_enum_value_hash(void const *data)
{
	uint32_t hash = 0;
	fr_dict_enum_t const *enumv = data;

	hash = fr_hash_update((void const *)&enumv->da, sizeof(void *), hash);	/* Cast to quiet static analysis */
	return fr_hash_update((void const *)enumv->value, sizeof(void *), hash);
}

/** Compare two dictionary enum values
 *
 */
static int dict_enum_value_cmp(void const *one, void const *two)
{
	fr_dict_enum_t const *a = one;
	fr_dict_enum_t const *b = two;

	return fr_value_box_cmp(a->value, b->value);
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
static bool dict_attr_fields_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
				   char const *name, int *attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	fr_dict_attr_t const	*v;

	if (!fr_cond_assert(parent)) return false;

	if (fr_dict_valid_name(name, -1) <= 0) return false;

	/******************** sanity check attribute number ********************/

	if (parent->flags.is_root) {
		static unsigned int max_attr = UINT8_MAX + 1;

		if (*attr == -1) {
			if (fr_dict_attr_by_name(dict, name)) return false; /* exists, don't add it again */
			*attr = ++max_attr;
			flags->internal = 1;

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
	 *	type_size is used to limit the maximum attribute number, so it's checked first.
	 */
	if (flags->type_size) {
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

	/*
	 *	If attributes have number greater than 255, do sanity checks.
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

	/******************** sanity check flags ********************/

	/*
	 *	virtual attributes are special.
	 */
	if (flags->virtual) {
		if (!parent->flags.is_root) {
			fr_strerror_printf("The 'virtual' flag can only be used for normal attributes");
			return false;
		}

		if (*attr <= (1 << (8 * parent->flags.type_size))) {
			fr_strerror_printf("The 'virtual' flag can only be used for non-protocol attributes");
			return false;
		}
	}

	/*
	 *	Tags can only be used in a few limited situations.
	 */
	if (flags->has_tag) {
		if ((type != FR_TYPE_UINT32) && (type != FR_TYPE_STRING)) {
			fr_strerror_printf("The 'has_tag' flag can only be used for attributes of type 'integer' "
					   "or 'string'");
			return false;
		}

		if (!(parent->flags.is_root ||
		      ((parent->type == FR_TYPE_VENDOR) &&
		       (parent->parent && parent->parent->type == FR_TYPE_VSA)))) {
			fr_strerror_printf("The 'has_tag' flag can only be used with RFC and VSA attributes");
			return false;
		}

		if (flags->array || flags->has_value || flags->concat || flags->virtual || flags->length) {
			fr_strerror_printf("The 'has_tag' flag cannot be used with any other flag");
			return false;
		}

		if (flags->encrypt && (flags->encrypt != FLAG_ENCRYPT_TUNNEL_PASSWORD)) {
			fr_strerror_printf("The 'has_tag' flag can only be used with 'encrypt=2'");
			return false;
		}
	}

	/*
	 *	'concat' can only be used in a few limited situations.
	 */
	if (flags->concat) {
		if (type != FR_TYPE_OCTETS) {
			fr_strerror_printf("The 'concat' flag can only be used for attributes of type 'octets'");
			return false;
		}

		if (!parent->flags.is_root) {
			fr_strerror_printf("The 'concat' flag can only be used with RFC attributes");
			return false;
		}

		if (flags->array || flags->internal || flags->has_value || flags->virtual ||
		    flags->encrypt || flags->length) {
			fr_strerror_printf("The 'concat' flag cannot be used any other flag");
			return false;
		}
	}

	/*
	 *	'octets[n]' can only be used in a few limited situations.
	 */
	if (flags->length) {
		if (flags->has_value || flags->virtual) {
			fr_strerror_printf("The 'octets[...]' syntax cannot be used any other flag");
			return false;
		}

		if (flags->length > 253) {
			fr_strerror_printf("Invalid length %d", flags->length);
			return NULL;
		}

		if ((type == FR_TYPE_TLV) || (type == FR_TYPE_VENDOR)) {
			if ((flags->length != 1) &&
			    (flags->length != 2) &&
			    (flags->length != 4)) {
				fr_strerror_printf("The 'length' flag can only be used with attributes of TLV lengths of 1,2 or 4");
				return false;
			}
		} else if (type != FR_TYPE_OCTETS) {
			fr_strerror_printf("The 'length' flag can only be set for attributes of type 'octets' or 'struct'");
			return false;
		}
	}

	/*
	 *	Allow arrays anywhere.
	 */
	if (flags->array) {
		switch (type) {
		default:
			fr_strerror_printf("The 'array' flag cannot be used with attributes of type '%s'",
					   fr_int2str(fr_value_box_type_table, type, "<UNKNOWN>"));
			return false;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_DATE:
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			break;
		}

		if (flags->internal || flags->has_value || flags->encrypt || flags->virtual) {
			fr_strerror_printf("The 'array' flag cannot be used any other flag");
			return false;
		}
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

		if (flags->encrypt || flags->virtual) {
			fr_strerror_printf("The 'has_value' flag cannot be used with any other flag");
			return false;
		}
	}

	if (flags->encrypt) {
		/*
		 *	Stupid hacks for MS-CHAP-MPPE-Keys.  The User-Password
		 *	encryption method has no provisions for encoding the
		 *	length of the data.  For User-Password, the data is
		 *	(presumably) all printable non-zero data.  For
		 *	MS-CHAP-MPPE-Keys, the data is binary crap.  So... we
		 *	MUST specify a length in the dictionary.
		 */
		if ((flags->encrypt == FLAG_ENCRYPT_USER_PASSWORD) && (type != FR_TYPE_STRING)) {
			if (type != FR_TYPE_OCTETS) {
				fr_strerror_printf("The 'encrypt=1' flag can only be used with "
						   "attributes of type 'string'");
				return false;
			}

			if (flags->length == 0) {
				fr_strerror_printf("The 'encrypt=1' flag MUST be used with an explicit length for "
						   "'octets' data types");
				return false;
			}
		}

		if (flags->encrypt > FLAG_ENCRYPT_OTHER) {
			fr_strerror_printf("The 'encrypt' flag can only be 0..4");
			return false;
		}

		/*
		 *	The Tunnel-Password encryption method can be used anywhere.
		 *
		 *	We forbid User-Password and Ascend-Send-Secret
		 *	methods in the extended space.
		 */
		if ((flags->encrypt != FLAG_ENCRYPT_TUNNEL_PASSWORD) && !flags->internal && !parent->flags.internal) {
			for (v = parent; v != NULL; v = v->parent) {
				switch (v->type) {
				case FR_TYPE_EXTENDED:
				case FR_TYPE_EVS:
					fr_strerror_printf("The 'encrypt=%d' flag cannot be used with attributes "
							   "of type '%s'", flags->encrypt,
							   fr_int2str(fr_value_box_type_table, type, "<UNKNOWN>"));
					return false;

				default:
					break;
				}

			}
		}

		switch (type) {
		default:
		encrypt_fail:
			fr_strerror_printf("The 'encrypt' flag cannot be used with attributes of type '%s'",
					   fr_int2str(fr_value_box_type_table, type, "<UNKNOWN>"));
			return false;

		case FR_TYPE_TLV:
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_UINT32:
		case FR_TYPE_OCTETS:
			if (flags->encrypt == FLAG_ENCRYPT_ASCEND_SECRET) goto encrypt_fail;

		case FR_TYPE_STRING:
			break;
		}
	}

	/******************** sanity check data types and parents ********************/

	/*
	 *	Enforce restrictions on which data types can appear where.
	 */
	switch (type) {
	/*
	 *	These types may only be parented from the root of the dictionary
	 */
	case FR_TYPE_EXTENDED:
//	case FR_TYPE_VSA:
		if (!parent->flags.is_root) {
			fr_strerror_printf("Attributes of type '%s' can only be used in the RFC space",
					   fr_int2str(fr_value_box_type_table, type, "?Unknown?"));
			return false;
		}
		break;

	/*
	 *	EVS may only occur under extended and long extended.
	 */
	case FR_TYPE_EVS:
		if (parent->type != FR_TYPE_EXTENDED) {
			fr_strerror_printf("Attributes of type 'evs' MUST have a parent of type 'extended', "
					   "instead of '%s'", fr_int2str(fr_value_box_type_table, parent->type, "?Unknown?"));
			return false;
		}
		break;

	case FR_TYPE_VENDOR:
		if ((parent->type != FR_TYPE_VSA) && (parent->type != FR_TYPE_EVS)) {
			fr_strerror_printf("Attributes of type 'vendor' MUST have a parent of type 'vsa' or "
					   "'evs', instead of '%s'",
					   fr_int2str(fr_value_box_type_table, parent->type, "?Unknown?"));
			return false;
		}

		if (parent->type == FR_TYPE_VSA) {
			fr_dict_vendor_t const *dv;

			dv = fr_dict_vendor_by_num(dict, *attr);
			if (dv) {
				flags->type_size = dv->type;
				flags->length = dv->length;
			} else {
				flags->type_size = 1;
				flags->length = 1;
			}
		} else {
			flags->type_size = 1;
			flags->length = 1;
		}
		break;

	case FR_TYPE_TLV:
		/*
		 *	Ensure that type_size and length are set.
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
					   fr_int2str(fr_value_box_type_table, type, "?Unknown?"));
			return false;
		}

		/*
		 *	Over-ride whatever was there before, so we
		 *	don't have multiple formats of VSAs.
		 */
		flags->type_size = v->flags.type_size;
		flags->length = v->flags.length;
		break;

	case FR_TYPE_COMBO_IP_ADDR:
		/*
		 *	RFC 6929 says that this is a terrible idea.
		 */
		for (v = parent; v != NULL; v = v->parent) {
			if (v->type == FR_TYPE_VSA) {
				break;
			}
		}

		if (!v) {
			fr_strerror_printf("Attributes of type '%s' can only be used in VSA dictionaries",
					   fr_int2str(fr_value_box_type_table, type, "?Unknown?"));
			return false;
		}
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_COMBO_IP_PREFIX:
		fr_strerror_printf("Attributes of type '%s' cannot be used in dictionaries",
				   fr_int2str(fr_value_box_type_table, type, "?Unknown?"));
		return false;

	case FR_TYPE_DATE:
		if (flags->type_size > FR_TIME_RES_NSEC) {
			fr_strerror_printf("Invalid precision '%d' for attribute of type 'date'",
					   flags->type_size);
			return false;
		}
		break;


	default:
		break;
	}

	/*
	 *	Force "length" for data types of fixed length;
	 */
	switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_BOOL:
		flags->length = 1;
		break;

	case FR_TYPE_UINT16:
		flags->length = 2;
		break;

	case FR_TYPE_DATE:
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

	case FR_TYPE_EXTENDED:
		if (!parent->flags.is_root || (*attr < 241)) {
			fr_strerror_printf("Attributes of type 'extended' MUST be "
					   "RFC attributes with value >= 241.");
			return false;
		}
		flags->length = 0;
		break;

	case FR_TYPE_EVS:
		if (*attr != FR_VENDOR_SPECIFIC) {
			fr_strerror_printf("Attributes of type 'evs' MUST have attribute code 26, got %i", *attr);
			return false;
		}

		flags->length = 0;
		break;

		/*
		 *	The length is calculated from the children, not
		 *	input as the flags.
		 */
	case FR_TYPE_STRUCT:
		flags->length = 0;

		if (flags->encrypt != FLAG_ENCRYPT_NONE) {
			fr_strerror_printf("Attributes of type 'struct' MUST NOT be encrypted.");
			return false;
		}

		if (flags->internal || flags->has_tag || flags->array || flags->concat || flags->virtual) {
			fr_strerror_printf("Invalid flag for attribute of type 'struct'");
			return false;
		}
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
	case FR_TYPE_TLV:
		break;

	default:
		break;
	}

	/*
	 *	Validate attribute based on parent.
	 */
	if (parent->type == FR_TYPE_STRUCT) {
		if (flags->encrypt != FLAG_ENCRYPT_NONE) {
			fr_strerror_printf("Attributes inside a 'struct' MUST NOT be encrypted.");
			return false;
		}

		if (flags->internal || flags->has_tag || flags->array || flags->concat || flags->virtual) {
			fr_strerror_printf("Invalid flag for attribute inside a 'struct'");
			return false;
		}

		if (*attr > 1) {
			fr_dict_attr_t const *sibling;

			sibling = fr_dict_attr_child_by_num(parent, (*attr) - 1);
			if (!sibling) {
				fr_strerror_printf("Child %s of 'struct' type attribute %s MUST be numbered consecutively %u.",
					name, parent->name, *attr);
				return false;
			}

			if (dict_attr_sizes[sibling->type][1] == ~(size_t) 0) {
				fr_strerror_printf("Only the last child of a 'struct' attribute can have variable length");
				return false;
			}

		} else {
			/*
			 *	The first child can't be variable length, that's stupid.
			 *
			 *	STRUCTs will have their length filled in later.
			 */
			if ((type != FR_TYPE_STRUCT) && (flags->length == 0)) {
				fr_strerror_printf("Children of 'struct' type attributes MUST have fixed length.");
				return false;
			}
		}
	}

	return true;
}

/** Allocate a dictionary attribute and assign a name
 *
 * @param[in] ctx		to allocate attribute in.
 * @param[in] name		to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
static fr_dict_attr_t *dict_attr_alloc_name(TALLOC_CTX *ctx, char const *name)
{
	fr_dict_attr_t *da;

	if (!name) {
		fr_strerror_printf("No attribute name provided");
		return NULL;
	}

	da = talloc_zero(ctx, fr_dict_attr_t);
	da->name = talloc_typed_strdup(da, name);
	if (!da->name) {
		talloc_free(da);
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	return da;
}

/** Initialise fields in a dictionary attribute structure
 *
 * @param[in] da		to initialise.
 * @param[in] parent		of the attribute, if none, should be
 *				the dictionary root.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] flags		to assign.
 */
static inline void dict_attr_init(fr_dict_attr_t *da,
				  fr_dict_attr_t const *parent, int attr,
				  fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	da->attr = attr;
	da->type = type;
	da->flags = *flags;
	da->parent = parent;
	da->depth = parent ? parent->depth + 1 : 0;
}

/** Allocate a dictionary attribute on the heap
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] parent		of the attribute, if none, should be
 *				the dictionary root.
 * @param[in] name		of the attribute.  If NULL an OID string
 *				will be created and set as the name.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] flags		to assign.
 * @return
 *	- A new fr_dict_attr_t on success.
 *	- NULL on failure.
 */
static fr_dict_attr_t *dict_attr_alloc(TALLOC_CTX *ctx,
				       fr_dict_attr_t const *parent,
				       char const *name, int attr,
				       fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t	*n;

	if (!fr_cond_assert(parent)) return NULL;

	/*
	 *	Allocate a new attribute
	 */
	if (!name) {
		char		buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];
		char		*p = buffer;
		size_t		len;
		fr_dict_attr_t	tmp;

		memset(&tmp, 0, sizeof(tmp));
		dict_attr_init(&tmp, parent, attr, type, flags);

		len = snprintf(p, sizeof(buffer), "Attr-");
		p += len;

		len = fr_dict_print_attr_oid(p, sizeof(buffer) - (p - buffer), NULL, &tmp);
		if (is_truncated(len, sizeof(buffer) - (p - buffer))) {
			fr_strerror_printf("OID string too long for unknown attribute");
			return NULL;
		}

		n = dict_attr_alloc_name(ctx, buffer);
	} else {
		n = dict_attr_alloc_name(ctx, name);
	}

	dict_attr_init(n, parent, attr, type, flags);
	DA_VERIFY(n);

	return n;
}

/** Copy a an existing attribute
 *
 * @param[in] ctx		to allocate new attribute in.
 * @param[in] in		attribute to copy.
 * @return
 *	- A copy of the input fr_dict_attr_t on success.
 *	- NULL on failure.
 */
static fr_dict_attr_t *dict_attr_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *in)
{
	fr_dict_attr_t *n;

	n = dict_attr_alloc_name(ctx, in->name);
	if (!n) return NULL;

	dict_attr_init(n, in->parent, in->attr, in->type, &in->flags);
	DA_VERIFY(n);

	return n;
}

/** Allocate a special "reference" attribute
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] attr		number.
 * @param[in] type		of attribute.
 * @param[in] flags		to set in the attribute.
 * @param[in] ref		This reference attribute is pointing to.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static fr_dict_attr_t *dict_attr_ref_alloc(fr_dict_t *dict, fr_dict_attr_t const *parent,
					   char const *name, int attr, fr_type_t type,
					   fr_dict_attr_flags_t const *flags, fr_dict_attr_t const *ref)
{
	fr_dict_attr_ref_t *ref_n;

	if (!name) {
		fr_strerror_printf("No attribute name provided");
		return NULL;
	}

	ref_n = talloc_zero(dict->pool, fr_dict_attr_ref_t);
	ref_n->tlv.name = talloc_typed_strdup(ref_n, name);
	if (!ref_n->tlv.name) {
		talloc_free(ref_n);
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	dict_attr_init(&ref_n->tlv, parent, attr, type, flags);
	ref_n->dict = fr_dict_by_da(ref);	/* Cache the dictionary */
	ref_n->to = ref;

	return (fr_dict_attr_t *)ref_n;
}

/** Add a protocol to the global protocol table
 *
 * Inserts a protocol into the global protocol table.  Uses the root attributes
 * of the dictionary for comparisons.
 *
 * @param[in] dict of protocol we're inserting.
 * @return
 * 	- 0 on success.
 * 	- -1 on failure.
 */
static int dict_protocol_add(fr_dict_t *dict)
{
	if (!dict->root) return -1;	/* Should always have root */

	if (!fr_hash_table_insert(protocol_by_name, dict)) {
		fr_dict_t *old_proto;

		old_proto = fr_hash_table_finddata(protocol_by_name, dict);
		if (!old_proto) {
			fr_strerror_printf("%s: Failed inserting protocol name %s", __FUNCTION__, dict->root->name);
			return -1;
		}

		if ((strcmp(old_proto->root->name, dict->root->name) == 0) &&
		    (old_proto->root->name == dict->root->name)) {
			fr_strerror_printf("%s: Duplicate protocol name %s", __FUNCTION__, dict->root->name);
			return -1;
		}

		return 0;
	}
	dict->in_protocol_by_name = true;

	if (!fr_hash_table_insert(protocol_by_num, dict)) {
		fr_strerror_printf("%s: Duplicate protocol number %i", __FUNCTION__, dict->root->attr);
		return -1;
	}
	dict->in_protocol_by_num = true;

	return 0;
}

/** Add a vendor to the dictionary
 *
 * Inserts a vendor entry into the vendor hash table.  This must be done before adding
 * attributes under a VSA.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] name		of the vendor.
 * @param[in] num		Vendor's Private Enterprise Number.
 * @return
 * 	- 0 on success.
 * 	- -1 on failure.
 */
static int dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num)
{
	size_t			len;
	fr_dict_vendor_t	*vendor;

	INTERNAL_IF_NULL(dict, -1);

	len = strlen(name);
	if (len >= FR_DICT_VENDOR_MAX_NAME_LEN) {
		fr_strerror_printf("%s: Vendor name too long", __FUNCTION__);
		return -1;
	}

	vendor = talloc_zero(dict, fr_dict_vendor_t);
	vendor->name = talloc_typed_strdup(vendor, name);
	if (!vendor->name) {
		talloc_free(vendor);
		fr_strerror_printf("Out of memory");
		return -1;
	}
	vendor->pen = num;
	vendor->type = vendor->length = 1; /* defaults */

	if (!fr_hash_table_insert(dict->vendors_by_name, vendor)) {
		fr_dict_vendor_t const *old_vendor;

		old_vendor = fr_hash_table_finddata(dict->vendors_by_name, vendor);
		if (!old_vendor) {
			fr_strerror_printf("%s: Failed inserting vendor name %s", __FUNCTION__, name);
			return -1;
		}
		if ((strcmp(old_vendor->name, vendor->name) == 0) && (old_vendor->pen != vendor->pen)) {
			fr_strerror_printf("%s: Duplicate vendor name %s", __FUNCTION__, name);
			return -1;
		}

		/*
		 *	Already inserted.  Discard the duplicate entry.
		 */
		talloc_free(vendor);

		return 0;
	}

	/*
	 *	Insert the SAME pointer (not free'd when this table is
	 *	deleted), into another table.
	 *
	 *	We want this behaviour because we want OLD names for
	 *	the attributes to be read from the configuration
	 *	files, but when we're printing them, (and looking up
	 *	by value) we want to use the NEW name.
	 */
	if (!fr_hash_table_replace(dict->vendors_by_num, vendor)) {
		fr_strerror_printf("%s: Failed inserting vendor %s", __FUNCTION__, name);
		return -1;
	}

	return 0;
}

/** Add a child to a parent.
 *
 * @param[in] parent	we're adding a child to.
 * @param[in] child	to add to parent.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
static inline int dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child)
{
	fr_dict_attr_t const * const *bin;
	fr_dict_attr_t **this;

	/*
	 *	Setup fields in the child
	 */
	child->parent = parent;
	child->depth = parent->depth + 1;

	DA_VERIFY(child);

	/*
	 *	We only allocate the pointer array *if* the parent has children.
	 */
	if (!parent->children) parent->children = talloc_zero_array(parent, fr_dict_attr_t const *, UINT8_MAX + 1);
	if (!parent->children) {
		fr_strerror_printf("Out of memory");
		return -1;
	}
	/*
	 *	Treat the array as a hash of 255 bins, with attributes
	 *	sorted into bins using num % 255.
	 *
	 *	Although the various protocols may define numbers higher than 255:
	 *
	 *	RADIUS/DHCPv4     - 1-255
	 *	Diameter/Internal - 1-4294967295
	 *	DHCPv6            - 1-65535
	 *
	 *	In reality very few will ever use attribute numbers > 500, so for
	 *	the majority of lookups we get O(1) performance.
	 *
	 *	Attributes are inserted into the bin in order of their attribute
	 *	numbers to allow slightly more efficient lookups.
	 */
	bin = &parent->children[child->attr & 0xff];
	for (;;) {
		bool child_is_struct = false;
		bool bin_is_struct = false;

		if (!*bin) break;

		/*
		 *	Workaround for vendors that overload the RFC space.
		 *	Structural attributes always take priority.
		 */
		switch (child->type) {
		case FR_TYPE_STRUCTURAL:
			child_is_struct = true;
			break;

		default:
			break;
		}

		switch ((*bin)->type) {
		case FR_TYPE_STRUCTURAL:
			bin_is_struct = true;
			break;

		default:
			break;
		}

		if (child_is_struct && !bin_is_struct) break;
		else if (fr_dict_vendor_num_by_da(child) <= fr_dict_vendor_num_by_da(*bin)) break;	/* Prioritise RFC attributes */
		else if (child->attr <= (*bin)->attr) break;

		bin = &(*bin)->next;
	}

	memcpy(&this, &bin, sizeof(this));
	child->next = *this;
	*this = child;

	return 0;
}

/** Add an attribute to the name table for the dictionary.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] da		to add to the name lookup tables.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_attr_add_by_name(fr_dict_t *dict, fr_dict_attr_t *da)
{
	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(dict->attributes_by_name, da)) {
		fr_dict_attr_t *a;

		/*
		 *	Find the old name.  If it's the same name and
		 *	but the parent, or number, or type are
		 *	different, that's an error.
		 */
		a = fr_hash_table_finddata(dict->attributes_by_name, da);
		if (a && (strcasecmp(a->name, da->name) == 0)) {
			if ((a->attr != da->attr) || (a->type != da->type) || (a->parent != da->parent)) {
				fr_strerror_printf("Duplicate attribute name \"%s\"", da->name);
			error:
				return -1;
			}
		}

		/*
		 *	Otherwise the attribute has been redefined later
		 *	in the dictionary.
		 *
		 *	The original fr_dict_attr_t remains in the
		 *	dictionary but entry in the name hash table is
		 *	updated to point to the new definition.
		 */
		if (!fr_hash_table_replace(dict->attributes_by_name, da)) {
			fr_strerror_printf("Internal error storing attribute");
			goto error;
		}
	}

	/*
	 *	Insert copies of the attribute into the
	 *	polymorphic attribute table.
	 *
	 *	This allows an abstract attribute type
	 *	like combo IP to be resolved to a
	 *	concrete one later.
	 */
	switch (da->type) {
	case FR_TYPE_COMBO_IP_ADDR:
	{
		fr_dict_attr_t *v4, *v6;

		v4 = dict_attr_acopy(dict->pool, da);
		if (!v4) goto error;
		v4->type = FR_TYPE_IPV4_ADDR;

		v6 = dict_attr_acopy(dict->pool, da);
		if (!v6) goto error;
		v6->type = FR_TYPE_IPV6_ADDR;

		if (!fr_hash_table_replace(dict->attributes_combo, v4)) {
			fr_strerror_printf("Failed inserting IPv4 version of combo attribute");
			goto error;
		}

		if (!fr_hash_table_replace(dict->attributes_combo, v6)) {
			fr_strerror_printf("Failed inserting IPv6 version of combo attribute");
			goto error;
		}
		break;
	}

	case FR_TYPE_COMBO_IP_PREFIX:
	{
		fr_dict_attr_t *v4, *v6;

		v4 = dict_attr_acopy(dict->pool, da);
		if (!v4) goto error;
		v4->type = FR_TYPE_IPV4_PREFIX;

		v6 = dict_attr_acopy(dict->pool, da);
		if (!v6) goto error;
		v6->type = FR_TYPE_IPV6_PREFIX;

		if (!fr_hash_table_replace(dict->attributes_combo, v4)) {
			fr_strerror_printf("Failed inserting IPv4 version of combo attribute");
			goto error;
		}

		if (!fr_hash_table_replace(dict->attributes_combo, v6)) {
			fr_strerror_printf("Failed inserting IPv6 version of combo attribute");
			goto error;
		}
		break;
	}

	default:
		break;
	}

	return 0;
}


/** Add an reference to the dictionary
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] attr		number.
 * @param[in] type		of attribute.
 * @param[in] flags		to set in the attribute.
 * @param[in] ref		The attribute we're referencing.  May be in a foreign
 *				dictionary.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_attr_ref_add(fr_dict_t *dict, fr_dict_attr_t const *parent,
			     char const *name, int attr, fr_type_t type, fr_dict_attr_flags_t const *flags,
			     fr_dict_attr_t const *ref)
{
	fr_dict_attr_t		*n;
	fr_dict_attr_t		*mutable;
	fr_dict_attr_flags_t	our_flags = *flags;

	/*
	 *	Check that the definition is valid.
	 */
	if (!dict_attr_fields_valid(dict, parent, name, &attr, type, &our_flags)) return -1;

	/*
	 *	Check we're not creating a direct loop
	 */
	if (ref->flags.is_reference) {
		fr_dict_attr_ref_t const *to_ref = talloc_get_type_abort_const(ref, fr_dict_attr_ref_t);

		if (to_ref->to == ref) {
			fr_strerror_printf("Circular reference between \"%s\" and \"%s\"", name, ref->name);
			return -1;
		}
	}

	/*
	 *	Check the referenced attribute is a root
	 *	or a TLV attribute.
	 */
	if (!ref->flags.is_root && (ref->type != FR_TYPE_TLV)) {
		fr_strerror_printf("Referenced attribute \"%s\" must be of type '%s' not a 'tlv'", ref->name,
				   fr_int2str(fr_value_box_type_table, ref->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Reference must go from a TLV to a TLV
	 */
	if (type != FR_TYPE_TLV) {
		fr_strerror_printf("Reference attribute must be of type 'tlv', not type '%s'",
				   fr_int2str(fr_value_box_type_table, type, "<INVALID>"));
		return -1;
	}

	n = dict_attr_ref_alloc(dict->pool, parent, name, attr, type, &our_flags, ref);
	if (!n) return -1;

	if (dict_attr_add_by_name(dict, n) < 0) {
	error:
		talloc_free(n);
		return -1;
	}

	/*
	 *	Setup parenting for the attribute
	 */
	memcpy(&mutable, &parent, sizeof(mutable));

	/*
	 *	Add in by number
	 */
	if (dict_attr_child_add(mutable, n) < 0) goto error;

	return 0;
}

/** Add an attribute to the dictionary
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] attr		number.
 * @param[in] type		of attribute.
 * @param[in] flags		to set in the attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_add(fr_dict_t *dict, fr_dict_attr_t const *parent,
		     char const *name, int attr, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t		*n;
	fr_dict_attr_t const	*old;
	fr_dict_attr_t		*mutable;
	fr_dict_attr_flags_t	our_flags = *flags;

	/*
	 *	Check that the definition is valid.
	 */
	if (!dict_attr_fields_valid(dict, parent, name, &attr, type, &our_flags)) return -1;

	/*
	 *	Suppress duplicates.
	 */
#define FLAGS_EQUAL(_x) (old->flags._x == flags->_x)

	old = fr_dict_attr_by_name(dict, name);
	if (old) {
		if ((old->parent == parent) && (old->attr == (unsigned int) attr) && (old->type == type) &&
		    FLAGS_EQUAL(has_tag) && FLAGS_EQUAL(array) && FLAGS_EQUAL(concat) && FLAGS_EQUAL(encrypt)) {
			return 0;
		}

		if (old->parent != parent) {
			fr_strerror_printf_push("Cannot add duplicate name %s with different parent (old %s, new %s)",
						name, old->parent->name, parent->name);
			return -1;
		}

		if (old->attr != (unsigned int) attr) {
			fr_strerror_printf_push("Cannot add duplicate name %s with different number (old %u, new %d)",
						name, old->attr, attr);
			return -1;
		}

		if (old->type != type) {
			fr_strerror_printf_push("Cannot add duplicate name %s with different type (old %s, new %s)",
						name,
						fr_int2str(fr_value_box_type_table, old->type, "?Unknown?"),
						fr_int2str(fr_value_box_type_table, type, "?Unknown?"));
			return -1;
		}

		fr_strerror_printf_push("Cannot add duplicate name %s with different flags",
					name);
		return -1;
	}

	n = dict_attr_alloc(dict->pool, parent, name, attr, type, &our_flags);
	if (!n) return -1;

	if (dict_attr_add_by_name(dict, n) < 0) {
	error:
		talloc_free(n);
		return -1;
	}

	/*
	 *	Setup parenting for the attribute
	 */
	memcpy(&mutable, &parent, sizeof(mutable));

	/*
	 *	Add in by number
	 */
	if (dict_attr_child_add(mutable, n) < 0) goto error;

	return 0;
}

/** Add a value alias
 *
 * Aliases are textual (string) aliases for a given value.
 *
 * Value aliases are not limited to integers, and may be added for any non-structural
 * attribute type.
 *
 * @param[in] da		to add enumeration value to.
 * @param[in] alias		Name of value alias.
 * @param[in] value		to associate with alias.
 * @param[in] coerce		if the type of the value does not match the
 *				type of the da, attempt to cast it to match
 *				the type of the da.  If this is false and there's
 *				a type mismatch, we fail.
 *				We also fail if the value cannot be coerced to
 *				the attribute type.
 * @param[in] takes_precedence	This alias should take precedence over previous
 *				aliases for the same value, when resolving value
 *				to alias.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_enum_add_alias(fr_dict_attr_t const *da, char const *alias,
			   fr_value_box_t const *value,
			   bool coerce, bool takes_precedence)
{
	size_t			len;
	fr_dict_t		*dict;
	fr_dict_enum_t		*enumv = NULL;
	fr_value_box_t		*enum_value = NULL;

	if (!da) {
		fr_strerror_printf("%s: Dictionary attribute not specified", __FUNCTION__);
		return -1;
	}

	if (!*alias) {
		fr_strerror_printf("%s: Empty names are not permitted", __FUNCTION__);
		return -1;
	}

	len = strlen(alias);
	if (len >= FR_DICT_ENUM_MAX_NAME_LEN) {
		fr_strerror_printf("%s: Value name too long", __FUNCTION__);
		return -1;
	}

	dict = fr_dict_by_da(da);

	enumv = talloc_zero(dict->pool, fr_dict_enum_t);
	if (!enumv) {
	oom:
		fr_strerror_printf("%s: Out of memory", __FUNCTION__);
		return -1;
	}
	enumv->alias = talloc_typed_strdup(enumv, alias);
	enumv->alias_len = strlen(alias);
	enum_value = fr_value_box_alloc(enumv, da->type, NULL, false);
	if (!enum_value) goto oom;

	if (da->type != value->type) {
		if (!coerce) {
			fr_strerror_printf("%s: Type mismatch between attribute (%s) and enum (%s)",
					   __FUNCTION__,
					   fr_int2str(fr_value_box_type_table, da->type, "<INVALID>"),
					   fr_int2str(fr_value_box_type_table, value->type, "<INVALID>"));
			return -1;
		}

		if (fr_value_box_cast(enumv, enum_value, da->type, NULL, value) < 0) {
			fr_strerror_printf_push("%s: Failed coercing enum type (%s) to attribute type (%s)",
						__FUNCTION__,
					   	fr_int2str(fr_value_box_type_table, value->type, "<INVALID>"),
					   	fr_int2str(fr_value_box_type_table, da->type, "<INVALID>"));

			return -1;
		}
	} else {
		if (fr_value_box_copy(enum_value, enum_value, value) < 0) {
			fr_strerror_printf_push("%s: Failed copying value into enum", __FUNCTION__);
			return -1;
		}
	}

	enumv->value = enum_value;
	enumv->da = da;

	/*
	 *	Add the value into the dictionary.
	 */
	{
		fr_dict_attr_t *tmp;
		memcpy(&tmp, &enumv, sizeof(tmp));

		if (!fr_hash_table_insert(dict->values_by_alias, tmp)) {
			fr_dict_enum_t *old;

			/*
			 *	Suppress duplicates with the same
			 *	name and value.  There are lots in
			 *	dictionary.ascend.
			 */
			old = fr_dict_enum_by_alias(da, alias, -1);
			if (!fr_cond_assert(old)) return -1;

			if (fr_value_box_cmp(old->value, enumv->value) == 0) {
				talloc_free(enumv);
				return 0;
			}

			fr_strerror_printf("Duplicate VALUE alias \"%s\" for attribute \"%s\". "
					   "Old value was \"%pV\", new value was \"%pV\"", alias, da->name,
					   old->value, enumv->value);
			talloc_free(enumv);
			return -1;
		}
	}

	/*
	 *	There are multiple VALUE's, keyed by attribute, so we
	 *	take care of that here.
	 */
	if (takes_precedence) {
		if (!fr_hash_table_replace(dict->values_by_da, enumv)) {
			fr_strerror_printf("%s: Failed inserting value %s", __FUNCTION__, alias);
			return -1;
		}
	} else {
		(void) fr_hash_table_insert(dict->values_by_da, enumv);
	}

	/*
	 *	Mark the attribute up as having an enumv
	 */
	{
		fr_dict_attr_t *mutable;

		memcpy(&mutable, &da, sizeof(mutable));

		mutable->flags.has_value = 1;
	}

	return 0;
}

/** Add an alias to an integer attribute hashing the alias for the integer value
 *
 */
int fr_dict_enum_add_alias_next(fr_dict_attr_t const *da, char const *alias)
{
	fr_value_box_t	v = {
				.type = da->type
			};
	fr_value_box_t	s = {
				.type = da->type
			};

	if (fr_dict_enum_by_alias(da, alias, -1)) return 0;

	switch (da->type) {
	case FR_TYPE_INT8:
		v.vb_int8 = s.vb_int8 = fr_hash_string(alias) & INT8_MAX;
		break;

	case FR_TYPE_INT16:
		v.vb_int16 = s.vb_int16 = fr_hash_string(alias) & INT16_MAX;
		break;

	case FR_TYPE_INT32:
		v.vb_int32 = s.vb_int32 = fr_hash_string(alias) & INT32_MAX;
		break;

	case FR_TYPE_INT64:
		v.vb_int64 = s.vb_int64 = fr_hash_string(alias) & INT64_MAX;
		break;

	case FR_TYPE_UINT8:
		v.vb_uint8 = s.vb_uint8 = fr_hash_string(alias) & UINT8_MAX;
		break;

	case FR_TYPE_UINT16:
		v.vb_uint16 = s.vb_uint16 = fr_hash_string(alias) & UINT16_MAX;
		break;

	case FR_TYPE_UINT32:
		v.vb_uint32 = s.vb_uint32 = fr_hash_string(alias) & UINT32_MAX;
		break;

	case FR_TYPE_UINT64:
		v.vb_uint64 = s.vb_uint64 = fr_hash_string(alias) & UINT64_MAX;
		break;

	default:
		fr_strerror_printf("Attribute is wrong type for auto-numbering, expected numeric type, got %s",
				   fr_int2str(fr_value_box_type_table, da->type, "?Unknown?"));
		return -1;
	}

	/*
	 *	If there's no existing value, add an enum
	 *	with the hash value of the alias.
	 *
	 *	This helps with debugging as the values
	 *	are consistent.
	 */
	if (!fr_dict_enum_by_value(da, &v)) {
	add:
		return fr_dict_enum_add_alias(da, alias, &v, false, false);
	}

	for (;;) {
		fr_value_box_increment(&v);

		if (fr_value_box_cmp_op(T_OP_CMP_EQ, &v, &s) == 0) {
			fr_strerror_printf("No free integer values for enumeration");
			return -1;
		}

		if (!fr_dict_enum_by_value(da, &v)) goto add;
	}
	/* NEVER REACHED */
}

/** Copy a known or unknown attribute to produce an unknown attribute
 *
 * Will copy the complete hierarchy down to the first known attribute.
 */
fr_dict_attr_t *fr_dict_unknown_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_dict_attr_t *n;
	fr_dict_attr_t const *parent;

	/*
	 *	Allocate an attribute.
	 */
	n = dict_attr_alloc_name(ctx, da->name);
	if (!n) return NULL;

	/*
	 *	We want to have parent / child relationships, AND to
	 *	copy all unknown parents, AND to free the unknown
	 *	parents when this 'da' is freed.  We therefore talloc
	 *	the parent from the 'da'.
	 */
	if (da->parent->flags.is_unknown) {
		parent = fr_dict_unknown_acopy(n, da->parent);
		if (!parent) {
			talloc_free(n);
			return NULL;
		}

	} else {
		parent = da->parent;
	}

	/*
	 *	Initialize the rest of the fields.
	 */
	dict_attr_init(n, parent, da->attr, da->type, &da->flags);

	DA_VERIFY(n);

	return n;
}

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old #fr_dict_attr_t, that is left up to the caller.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] old		unknown attribute to add.
 * @return
 *	- Existing #fr_dict_attr_t if old was found in a dictionary.
 *	- A new entry representing old.
 */
fr_dict_attr_t const *fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent;
	fr_dict_attr_flags_t flags;

	da = fr_dict_attr_by_name(dict, old->name);
	if (da) return da;

	/*
	 *	Define the complete unknown hierarchy
	 */
	if (old->parent && old->parent->flags.is_unknown) {
		parent = fr_dict_unknown_add(dict, old->parent);
		if (!parent) {
			fr_strerror_printf_push("Failed adding parent \"%s\"", old->parent->name);
			return NULL;
		}
	} else {
#ifdef __clang_analyzer__
		if (!old->parent) return NULL;
#endif
		parent = old->parent;
	}

	memcpy(&flags, &old->flags, sizeof(flags));
	flags.is_unknown = false;
	flags.is_raw = true;

	/*
	 *	If this is a vendor, we skip most of the sanity
	 *	checks and add it to the vendor hash, and add it
	 *	as a child attribute to the Vendor-Specific
	 *	container.
	 */
	if (old->type == FR_TYPE_VENDOR) {
		fr_dict_attr_t *mutable, *n;

		if (dict_vendor_add(dict, old->name, old->attr) < 0) return NULL;

		n = dict_attr_alloc(dict->pool, parent, old->name, old->attr, old->type, &flags);

		/*
		 *	Setup parenting for the attribute
		 */
		memcpy(&mutable, &old->parent, sizeof(mutable));
		if (dict_attr_child_add(mutable, n) < 0) return NULL;

		return n;
	}

	/*
	 *	Look up the attribute by number.  If it doesn't exist,
	 *	add it both by name and by number.  If it does exist,
	 *	add it only by name.
	 */
	da = fr_dict_attr_child_by_num(parent, old->attr);
	if (da) {
		fr_dict_attr_t *n;

		n = dict_attr_alloc(dict->pool, parent, old->name, old->attr, old->type, &flags);
		if (!n) return NULL;

		/*
		 *	Add the unknown by NAME.  e.g. if the admin does "Attr-26", we want
		 *	to return "Attr-26", and NOT "Vendor-Specific".  The rest of the server
		 *	is responsible for converting "Attr-26 = 0x..." to an actual attribute,
		 *	if it so desires.
		 */
		if (dict_attr_add_by_name(dict, n) < 0) {
			talloc_free(n);
			return NULL;
		}

		return n;
	}

#ifdef __clang_analyzer__
	if (!old->name) return NULL;
#endif

	/*
	 *	Add the attribute by both name and number.
	 */
	if (fr_dict_attr_add(dict, parent, old->name, old->attr, old->type, &flags) < 0) return NULL;

	/*
	 *	For paranoia, return it by name.
	 */
	return fr_dict_attr_by_name(dict, old->name);
}

/** Free dynamically allocated (unknown attributes)
 *
 * If the da was dynamically allocated it will be freed, else the function
 * will return without doing anything.
 *
 * @param[in] da to free.
 */
void fr_dict_unknown_free(fr_dict_attr_t const **da)
{
	fr_dict_attr_t **tmp;

	if (!da || !*da) return;

	/* Don't free real DAs */
	if (!(*da)->flags.is_unknown) {
		return;
	}

	memcpy(&tmp, &da, sizeof(*tmp));
	talloc_free(*tmp);

	*tmp = NULL;
}

/** Build an unknown vendor, parented by a VSA or EVS attribute
 *
 * This allows us to complete the path back to the dictionary root in the case
 * of unknown attributes with unknown vendors.
 *
 * @note Will return known vendors attributes where possible.  Do not free directly,
 *	use #fr_dict_unknown_free.
 *
 * @param[in] ctx to allocate the vendor attribute in.
 * @param[out] out		Where to write point to new unknown dict attr
 *				representing the unknown vendor.
 * @param[in] parent		of the vendor attribute, either an EVS or VSA attribute.
 * @param[in] vendor		id.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				     fr_dict_attr_t const *parent, unsigned int vendor)
{
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
					.is_raw = true,
					.type_size = true,
					.length = true
				};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	/*
	 *	Vendor attributes can occur under VSA or EVS attributes.
	 */
	switch (parent->type) {
	case FR_TYPE_VSA:
	case FR_TYPE_EVS:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return -1;

		*out = dict_attr_alloc(ctx, parent, NULL, vendor, FR_TYPE_VENDOR, &flags);

		return 0;

	case FR_TYPE_VENDOR:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return -1;
		fr_strerror_printf("Unknown vendor cannot be parented by another vendor");
		return -1;

	default:
		fr_strerror_printf("Unknown vendors can only be parented by 'vsa' or 'evs' "
				   "attributes, not '%s'", fr_int2str(fr_value_box_type_table, parent->type, "?Unknown?"));
		return -1;
	}
}

/** Allocates an unknown attribute
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct EVS or VSA attribute. This is accessible via da->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx		to allocate DA in.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] attr		number.
 * @param[in] vendor		number.
 * @return 0 on success.
 */
fr_dict_attr_t const *fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						   unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t const	*da;
	fr_dict_attr_t		*n;
	fr_dict_attr_t		*new_parent = NULL;
	fr_dict_attr_flags_t	flags = {
		.is_unknown	= true,
		.is_raw		= true,
	};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return NULL;
	}

	/*
	 *	If there's a vendor specified, we check to see
	 *	if the parent is a VSA or EVS, and if it is
	 *	we either lookup the vendor to get the correct
	 *	attribute, or bridge the gap in the tree, with an
	 *	unknown vendor.
	 *
	 *	We need to do the check, as the parent could be
	 *	a TLV, in which case the vendor should be known
	 *	and we don't need to modify the parent.
	 */
	if (vendor && ((parent->type == FR_TYPE_VSA) || (parent->type == FR_TYPE_EVS))) {
		da = fr_dict_attr_child_by_num(parent, vendor);
		if (!da) {
			if (fr_dict_unknown_vendor_afrom_num(ctx, &new_parent, parent, vendor) < 0) return NULL;
			da = new_parent;
		}
		parent = da;

	/*
	 *	Need to clone the unknown hierachy, as unknown
	 *	attributes must parent the complete heirachy,
	 *	and cannot share any parts with any other unknown
	 *	attributes.
	 */
	} else if (parent->flags.is_unknown) {
		new_parent = fr_dict_unknown_acopy(ctx, parent);
		parent = new_parent;
	}

	n = dict_attr_alloc(ctx, parent, NULL, attr, FR_TYPE_OCTETS, &flags);
	if (!n) return NULL;

	/*
	 *	The config files may reference the unknown by name.
	 *	If so, use the pre-defined name instead of an unknown
	 *	one.!
	 */
	da = fr_dict_attr_by_name(fr_dict_by_da(parent), n->name);
	if (da) {
		fr_dict_unknown_free(&parent);
		parent = n;
		fr_dict_unknown_free(&parent);
		return da;
	}

	/*
	 *	Ensure the parent is freed at the same time as the
	 *	unknown DA.  This should be OK as we never parent
	 *	multiple unknown attributes off the same parent.
	 */
	if (new_parent && new_parent->flags.is_unknown) talloc_steal(n, new_parent);

	return n;
}

/** Initialise a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @copybrief fr_dict_unknown_afrom_fields
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[out] out		Where to write the new attribute to.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] num		of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_unknown_attr_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				       fr_dict_attr_t const *parent, unsigned long num)
{
	fr_dict_attr_t		*da;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
					.is_raw = true,
				};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	da = dict_attr_alloc(ctx, parent, NULL, num, FR_TYPE_OCTETS, &flags);
	if (!da) return -1;

	*out = da;

	return 0;
}

/** Create a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @copybrief fr_dict_unknown_afrom_fields
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct EVS or VSA attribute. This is accessible via vp->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx		to alloc new attribute in.
 * @param[out] out		Where to write the head of the chain unknown
 *				dictionary attributes.
 * @param[in] parent		Attribute to use as the root for resolving OIDs in.
 *				Usually the root of a protocol dictionary.
 * @param[in] oid_str		of attribute.
 * @return
 *	- The number of bytes parsed on success.
 *	- <= 0 on failure.  Negative offset indicates parse error position.
 */
ssize_t fr_dict_unknown_afrom_oid_str(TALLOC_CTX *ctx, fr_dict_attr_t **out,
			      	      fr_dict_attr_t const *parent, char const *oid_str)
{
	char const		*p = oid_str, *end = oid_str + strlen(oid_str);
	fr_dict_attr_t const	*our_parent = parent;
	fr_dict_attr_t		*n = NULL, *our_da;
	fr_dict_attr_flags_t	flags = {
		.is_unknown = true,
		.is_raw = true,
	};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	if (fr_dict_valid_oid_str(oid_str, -1) < 0) return -1;

	/*
	 *	All unknown attributes are of the form "Attr-#.#.#.#"
	 */
	if (strncasecmp(p, "Attr-", 5) != 0) {
		fr_strerror_printf("Unknown attribute '%s'", oid_str);
		return 0;
	}
	p += 5;

	/*
	 *	Allocate the final attribute first, so that any
	 *	unknown parents can be freed when this da is freed.
	 *
	 *      See fr_dict_unknown_acopy() for more details.
	 *
	 *	Note also that we copy the input name, even if it is
	 *	not normalized.
	 *
	 *	While the name of this attribute is "Attr-#.#.#", one
	 *	or more of the leading components may, in fact, be
	 *	known.
	 */
	n = dict_attr_alloc_name(ctx, oid_str);

	/*
	 *	While the name of this attribu
	 */
	do {
		unsigned int		num;
		fr_dict_attr_t const	*da = NULL;

		if (fr_dict_oid_component(&num, &p) < 0) {
		error:
			talloc_free(n);
			return -(p - oid_str);
		}

		switch (*p) {
		/*
		 *	Structural attribute
		 */
		case '.':
			if (!our_parent) goto is_root;

			da = fr_dict_attr_child_by_num(our_parent, num);
			if (!da) {	/* Unknown component */
				switch (our_parent->type) {
				case FR_TYPE_EVS:
				case FR_TYPE_VSA:
					da = fr_dict_attr_child_by_num(our_parent, num);
					if (!fr_cond_assert(!da || (da->type == FR_TYPE_VENDOR))) goto error;

					if (!da) {
						if (fr_dict_unknown_vendor_afrom_num(n, &our_da,
										     our_parent, num) < 0) {
							goto error;
						}
						da = our_da;
					}
					break;

				case FR_TYPE_TLV:
				case FR_TYPE_EXTENDED:
				is_root:
					if (dict_unknown_attr_afrom_num(n, &our_da, our_parent, num) < 0) {
						goto error;
					}
					da = our_da;
					break;

				/*
				 *	Can't have a FR_TYPE_STRING inside a
				 *	FR_TYPE_STRING (for example)
				 */
				default:
					fr_strerror_printf("Parent OID component (%s) in \"%.*s\" specified a "
							   "non-structural type (%s)", our_parent->name,
							   (int)(p - oid_str), oid_str,
							   fr_int2str(fr_value_box_type_table,
							   	      our_parent->type, "<INVALID>"));
					goto error;
				}
			}
			our_parent = da;
			break;

		/*
		 *	Leaf attribute
		 */
		case '\0':
			dict_attr_init(n, our_parent, num, FR_TYPE_OCTETS, &flags);
			break;
		}
		p++;
	} while (p < end);

	/*
	 *	@todo - if we really care about normalization, re-print the name here, normalized.
	 */

	DA_VERIFY(n);

	*out = n;

	return end - oid_str;
}

/** Create a dictionary attribute by name embedded in another string
 *
 * Find the first invalid attribute name char in the string pointed to by name.
 *
 * Copy the characters between the start of the name string and the first none
 * #fr_dict_attr_allowed_chars char to a buffer and initialise da as an unknown
 * attribute.
 *
 * @param[in] ctx		To allocate unknown #fr_dict_attr_t in.
 * @param[out] out		Where to write the head of the chain unknown
 *				dictionary attributes.
 * @param[in] parent		Attribute to use as the root for resolving OIDs in.
 *				Usually the root of a protocol dictionary.
 * @param[in] name		string start.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
ssize_t fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx, fr_dict_attr_t **out,
					 fr_dict_attr_t const *parent, char const *name)
{
	char const	*p;
	size_t		len;
	char		buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];
	ssize_t		slen;

	if (!name || !*name) return 0;

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = name; fr_dict_attr_allowed_chars[(uint8_t)*p] || (*p == '.') || (*p == '-'); p++);

	len = p - name;
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		return 0;
	}
	if (len == 0) {
		fr_strerror_printf("Invalid attribute name");
		return 0;
	}
	strlcpy(buffer, name, len + 1);

	slen = fr_dict_unknown_afrom_oid_str(ctx, out, parent, buffer);
	if (slen <= 0) return slen;

	return p - name;
}


/** Check to see if we can convert a nested TLV structure to known attributes
 *
 * @param[in] dict			to search in.
 * @param[in] da			Nested tlv structure to convert.
 * @return
 *	- NULL if we can't.
 *	- Known attribute if we can.
 */
fr_dict_attr_t const *fr_dict_attr_known(fr_dict_t *dict, fr_dict_attr_t const *da)
{
	INTERNAL_IF_NULL(dict, NULL);

	if (!da->flags.is_unknown) return da;	/* It's known */

	if (da->parent) {
		fr_dict_attr_t const *parent;

		parent = fr_dict_attr_known(dict, da->parent);
		if (!parent) return NULL;

		return fr_dict_attr_child_by_num(parent, da->attr);
	}

	if (dict->root == da) return dict->root;
	return NULL;
}

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
	FLAG_SET(is_reference);
	FLAG_SET(internal);
	FLAG_SET(has_tag);
	FLAG_SET(array);
	FLAG_SET(has_value);
	FLAG_SET(concat);
	FLAG_SET(virtual);

	if (flags->encrypt) {
		p += snprintf(p, end - p, "encrypt=%i,", flags->encrypt);
		if (p >= end) return -1;
	}

	if (flags->length) {
		p += snprintf(p, end - p, "length=%i,", flags->length);
		if (p >= end) return -1;
	}

	/*
	 *	Print out the date precision.
	 */
	if (type == FR_TYPE_DATE) {
		char const *precision = fr_int2str(date_precision_table, flags->type_size, "?");

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

	case FR_TYPE_EVS:
		name = "EVS";
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
	       fr_int2str(fr_value_box_type_table, da->type, "?Unknown?"), buff);

	if (da->children) for (i = 0; i < talloc_array_length(da->children); i++) {
		if (da->children[i]) {
			fr_dict_attr_t const *bin;

			for (bin = da->children[i]; bin; bin = bin->next) fr_dict_print(bin, depth + 1);
		}
	}
}

/** Find a common ancestor that two TLV type attributes share
 *
 * @param[in] a			first TLV attribute.
 * @param[in] b			second TLV attribute.
 * @param[in] is_ancestor	Enforce a->b relationship (a is parent or ancestor of b).
 * @return
 *	- Common ancestor if one exists.
 *	- NULL if no common ancestor exists.
 */
fr_dict_attr_t const *fr_dict_parent_common(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor)
{
	unsigned int i;
	fr_dict_attr_t const *p_a, *p_b;

	if (!a || !b) return NULL;

	if (is_ancestor && (b->depth <= a->depth)) return NULL;

	/*
	 *	Find a common depth to work back from
	 */
	if (a->depth > b->depth) {
		p_b = b;
		for (p_a = a, i = a->depth - b->depth; p_a && (i > 0); p_a = p_a->parent, i--);
	} else if (a->depth < b->depth) {
		p_a = a;
		for (p_b = b, i = b->depth - a->depth; p_b && (i > 0); p_b = p_b->parent, i--);
	} else {
		p_a = a;
		p_b = b;
	}

	while (p_a && p_b) {
		if (p_a == p_b) return p_a;

		p_a = p_a->parent;
		p_b = p_b->parent;
	}

	return NULL;
}

/** Process a single OID component
 *
 * @param[out] out		Value of component.
 * @param[in] oid		string to parse.
 * @return
 *	- 0 on success.
 *	- -1 on format error.
 */
int fr_dict_oid_component(unsigned int *out, char const **oid)
{
	char const *p = *oid;
	char *q;
	unsigned long num;

	*out = 0;

	num = strtoul(p, &q, 10);
	if ((p == q) || (num == ULONG_MAX)) {
		fr_strerror_printf("Invalid OID component \"%s\" (%lu)", p, num);
		return -1;
	}

	switch (*q) {
	case '\0':
	case '.':
		*oid = q;
		*out = (unsigned int)num;

		return 0;

	default:
		fr_strerror_printf("Unexpected text after OID component");
		*out = 0;
		return -1;
	}
}

/** Build the tlv_stack for the specified DA and encode the path in OID form
 *
 * @param[out] out		Where to write the OID.
 * @param[in] outlen		Length of the output buffer.
 * @param[in] ancestor		If not NULL, only print OID portion between
 *				ancestor and da.
 * @param[in] da		to print OID string for.
 * @return the number of bytes written to the buffer.
 */
size_t fr_dict_print_attr_oid(char *out, size_t outlen,
			      fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da)
{
	size_t			len;
	char			*p = out, *end = p + outlen;
	int			i;
	int			depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];

	if (!outlen) return 0;

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
	if ((p + len) >= end) return p - out;
	p += len;


	for (i = depth + 1; i < (int)da->depth; i++) {
		len = snprintf(p, end - p, ".%u", tlv_stack[i]->attr);
		if ((p + len) >= end) return p - out;
		p += len;
	}

	return p - out;
}

/** Get the leaf attribute of an OID string
 *
 * @note On error, vendor will be set (if present), parent will be the
 *	maximum depth we managed to resolve to, and attr will be the child
 *	we failed to resolve.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[out] attr		Number we parsed.
 * @param[in,out] parent	attribute (or root of dictionary).
 *				Will be updated to the parent directly beneath the leaf.
 * @param[in] oid		string to parse.
 * @return
 *	- > 0 on success (number of bytes parsed).
 *	- <= 0 on parse error (negative offset of parse error).
 */
ssize_t fr_dict_attr_by_oid(fr_dict_t *dict, fr_dict_attr_t const **parent, unsigned int *attr, char const *oid)
{
	char const		*p = oid;
	unsigned int		num = 0;
	ssize_t			slen;

	if (!*parent) return -1;

	/*
	 *	It's a partial OID.  Grab it, and skip to the next bit.
	 */
	if (p[0] == '.') {
		p++;
	}

	*attr = 0;

	if (fr_dict_oid_component(&num, &p) < 0) return oid - p;

	/*
	 *	Record progress even if we error out.
	 *
	 *	Don't change this, you will break things.
	 */
	*attr = num;

	switch ((*parent)->type) {
	case FR_TYPE_STRUCTURAL:
		break;

	default:
		fr_strerror_printf("Attribute %s (%i) is not a TLV, so cannot contain a child attribute.  "
				   "Error at sub OID \"%s\"", (*parent)->name, (*parent)->attr, oid);
		return 0;	/* We parsed nothing */
	}

	/*
	 *	If it's not a vendor type, it must be between 0..8*type_size
	 *
	 *	@fixme: find the TLV parent, and check it's size
	 */
	if (((*parent)->type != FR_TYPE_VENDOR) && ((*parent)->type != FR_TYPE_VSA) && !(*parent)->flags.is_root &&
	    (num > UINT8_MAX)) {
		fr_strerror_printf("TLV attributes must be between 0..255 inclusive");
		return 0;
	}

	switch (p[0]) {
	/*
	 *	We've not hit the leaf yet, so the attribute must be
	 *	defined already.
	 */
	case '.':
	{
		fr_dict_attr_t const *child;
		p++;

		child = fr_dict_attr_child_by_num(*parent, num);
		if (!child) {
			fr_strerror_printf("Unknown attribute \"%i\" in OID string \"%s\"", num, oid);
			return 0;	/* We parsed nothing */
		}

		/*
		 *	Record progress even if we error out.
		 *
		 *	Don't change this, you will break things.
		 */
		*parent = child;

		slen = fr_dict_attr_by_oid(dict, parent, attr, p);
		if (slen <= 0) return slen - (p - oid);
		return slen + (p - oid);
	}

	/*
	 *	Hit the leaf, this is the attribute we need to define.
	 */
	case '\0':
		*attr = num;
		return p - oid;

	default:
		fr_strerror_printf("Malformed OID string, got trailing garbage '%s'", p);
		return oid - p;
	}
}

/** Return the root attribute of a dictionary
 *
 * @param dict			to return root for.
 * @return the root attribute of the dictionary.
 */
fr_dict_attr_t const *fr_dict_root(fr_dict_t const *dict)
{
	if (!dict) return fr_dict_internal->root;	/* Remove me when dictionaries are done */
	return dict->root;
}

/** Look up a protocol name embedded in another string
 *
 * @param[out] out		the resolve dictionary or NULL if the dictionary
 *				couldn't be resolved.
 * @param[in] name		string start.
 * @param[in] dict_def		The dictionary to return if no dictionary qualifier was found.
 * @return
 *	- 0 and *out != NULL.  Couldn't find a dictionary qualifier, so returned dict_def.
 *	- <= 0 on error and (*out == NULL) (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
ssize_t fr_dict_by_protocol_substr(fr_dict_t const **out, char const *name, fr_dict_t const *dict_def)
{
	fr_dict_attr_t		root;

	fr_dict_t		*dict;
	char const		*p;
	size_t			len;

	if (!protocol_by_name || !name || !*name || !out) return 0;

	memset(&root, 0, sizeof(root));

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = name; fr_dict_attr_allowed_chars[(uint8_t)*p] && (*p != '.'); p++);

	/*
	 *	If what we stopped at wasn't a '.', then there
	 *	can't be a protocol name in this string.
	 */
	if (*p != '.') {
		memcpy(out, &dict_def, sizeof(*out));
		return 0;
	}

	len = p - name;
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		return -(FR_DICT_ATTR_MAX_NAME_LEN);
	}

	root.name = talloc_bstrndup(NULL, name, len);
	if (!root.name) {
		fr_strerror_printf("Out of memory");
		*out = NULL;
		return 0;
	}
	dict = fr_hash_table_finddata(protocol_by_name, &(fr_dict_t){ .root = &root });
	talloc_const_free(root.name);

	if (!dict) {
		fr_strerror_printf("Unknown protocol '%.*s'", (int) len, name);
		*out = NULL;
		return 0;
	}
	*out = dict;

	return p - name;
}

/** Lookup a protocol by its name
 *
 * @param[in] name of the protocol to locate.
 * @return
 * 	- Attribute matching name.
 * 	- NULL if no matching protocolibute could be found.
 */
fr_dict_t *fr_dict_by_protocol_name(char const *name)
{
	if (!protocol_by_name || !name) return NULL;

	return fr_hash_table_finddata(protocol_by_name, &(fr_dict_t){ .root = &(fr_dict_attr_t){ .name = name } });
}

/** Lookup a protocol by its number.
 *
 * Returns the #fr_dict_t belonging to the protocol with the specified number
 * if any have been registered.
 *
 * @param[in] num to search for.
 * @return dictionary representing the protocol (if it exists).
 */
fr_dict_t *fr_dict_by_protocol_num(unsigned int num)
{
	if (!protocol_by_num) return NULL;

	return fr_hash_table_finddata(protocol_by_num, &(fr_dict_t) { .root = &(fr_dict_attr_t){ .attr = num } });
}

/** Dictionary/attribute ctx struct
 *
 */
typedef struct {
	fr_dict_t 		*found_dict;	//!< Dictionary attribute found in.
	fr_dict_attr_t const	*found_da;	//!< Resolved attribute.
	fr_dict_attr_t const	*find;		//!< Attribute to find.
} dict_attr_search_t;

/** Search for an attribute name in all dictionaries
 *
 * @param[in] ctx	Attribute to search for.
 * @param[in] data	Dictionary to search in.
 * @return
 *	- 0 if attribute not found in dictionary.
 *	- 1 if attribute found in dictionary.
 */
static int _dict_attr_find_in_dicts(void *ctx, void *data)
{
	dict_attr_search_t	*search = ctx;
	fr_dict_t		*dict;

	if (!data) return 0;	/* We get called with NULL data */

	dict = talloc_get_type_abort(data, fr_dict_t);

	search->found_da = fr_hash_table_finddata(dict->attributes_by_name, search->find);
	if (!search->found_da) return 0;

	search->found_dict = data;

	return 1;
}

/** Attempt to locate the protocol dictionary containing an attribute
 *
 * @note Unlike fr_dict_by_attr_name, doesn't search through all the dictionaries,
 *	just uses the fr_dict_attr_t hierarchy and the talloc hierarchy to locate
 *	the dictionary (much much faster and more scalable).
 *
 * @param[in] da		To get the containing dictionary for.
 * @return
 *	- The dictionary containing da.
 *	- NULL.
 */
fr_dict_t *fr_dict_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *da_p = da;

	while (da_p->parent) {
		da_p = da_p->parent;
		DA_VERIFY(da_p);
	}

	if (!da_p->flags.is_root) {
		fr_strerror_printf("%s: Attribute %s has not been inserted into a dictionary", __FUNCTION__, da->name);
		return NULL;
	}

	/*
	 *	Parent of the root attribute must
	 *	be the dictionary.
	 */
	return talloc_get_type_abort(talloc_parent(da_p), fr_dict_t);
}

/** Attempt to locate the protocol dictionary containing an attribute
 *
 * @note This is O(n) and will only return the first instance of the dictionary.
 *
 * @param[out] found	the attribute that was resolved from the name. May be NULL.
 * @param[in] name	the name of the attribute.
 * @return
 *	- the dictionary the attribute was found in.
 *	- NULL if an attribute with the specified name wasn't found in any dictionary.
 */
fr_dict_t *fr_dict_by_attr_name(fr_dict_attr_t const **found, char const *name)
{
	fr_dict_attr_t		find = {
					.name = name
				};
	dict_attr_search_t	search = {
					.find = &find
				};
	int			ret;

	if (found) *found = NULL;

	if (!name || !*name) return NULL;

	ret = fr_hash_table_walk(protocol_by_name, _dict_attr_find_in_dicts, &search);
	if (ret == 0) return NULL;

	if (found) *found = search.found_da;

	return search.found_dict;
}

/** Look up a vendor by one of its child attributes
 *
 * @param[in] da	The vendor attribute.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that number was regitered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_da(fr_dict_attr_t const *da)
{
	fr_dict_t 		*dict;
	fr_dict_vendor_t	dv;

	dv.pen = fr_dict_vendor_num_by_da(da);
	if (!dv.pen) return NULL;

	dict = fr_dict_by_da(da);

	return fr_hash_table_finddata(dict->vendors_by_num, &dv);
}

/** Look up a vendor by its name
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] name		to search for.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that name was regitered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name)
{
	fr_dict_vendor_t	*found;

	INTERNAL_IF_NULL(dict, NULL);

	if (!name) return 0;

	found = fr_hash_table_finddata(dict->vendors_by_name, &(fr_dict_vendor_t) { .name = name });
	if (!found) return 0;

	return found;
}

/** Look up a vendor by its PEN
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] vendor_pen	to search for.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that number was regitered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen)
{
	INTERNAL_IF_NULL(dict, NULL);

	return fr_hash_table_finddata(dict->vendors_by_num, &(fr_dict_vendor_t) { .pen = vendor_pen });
}

/** Return the vendor that parents this attribute
 *
 * @note Uses the dictionary hierachy to determine the parent
 *
 * @param[in] da		The dictionary attribute to find parent for.
 * @return
 *	- NULL if the attribute has no vendor.
 *	- A fr_dict_attr_t representing this attribute's associated vendor.
 */
fr_dict_attr_t const *fr_dict_vendor_attr_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *da_p = da;

	DA_VERIFY(da);

	while (da_p->parent) {
		if (da_p->type == FR_TYPE_VENDOR) break;
		da_p = da_p->parent;

		if (!da_p) return NULL;
	}
	if (da_p->type != FR_TYPE_VENDOR) return NULL;

	return da_p;
}

/** Return vendor attribute for the specified dictionary and pen
 *
 * @param[in] vendor_root	of the vendor root attribute.  Could be 26 (for example) in RADIUS.
 * @param[in] vendor_pen	to find.
 * @return
 *	- NULL if vendor does not exist.
 *	- A fr_dict_attr_t representing the vendor in the dictionary hierarchy.
 */
fr_dict_attr_t const *fr_dict_vendor_attr_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen)
{
	fr_dict_attr_t const *vendor;

	switch (vendor_root->type) {
	case FR_TYPE_VSA:	/* Vendor specific attribute */
	case FR_TYPE_EVS:	/* Extended vendor specific attribute */
		break;

	default:
		fr_strerror_printf("Wrong type for vendor root, expected '%s' or '%s' got '%s'",
				   fr_int2str(fr_value_box_type_table, FR_TYPE_VSA, "<INVALID>"),
				   fr_int2str(fr_value_box_type_table, FR_TYPE_EVS, "<INVALID>"),
				   fr_int2str(fr_value_box_type_table, vendor_root->type, "<INVALID>"));
		return NULL;
	}

	vendor = fr_dict_attr_child_by_num(vendor_root, vendor_pen);
	if (!vendor) {
		fr_strerror_printf("Vendor %i not defined", vendor_pen);
		return NULL;
	}

	if (vendor->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Wrong type for vendor, expected '%s' got '%s'",
				   fr_int2str(fr_value_box_type_table, vendor->type, "<INVALID>"),
				   fr_int2str(fr_value_box_type_table, FR_TYPE_VENDOR, "<INVALID>"));
		return NULL;
	}

	return vendor;
}

/** Look up a dictionary attribute by a name embedded in another string
 *
 * Find the first invalid attribute name char in the string pointed
 * to by name.
 *
 * Copy the characters between the start of the name string and the first
 * none #fr_dict_attr_allowed_chars char to a buffer and perform a dictionary lookup
 * using that value.
 *
 * If the attribute exists, advance the pointer pointed to by name
 * to the first none #fr_dict_attr_allowed_chars char, and return the DA.
 *
 * If the attribute does not exist, don't advance the pointer and return
 * NULL.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Where to store the resolve attribute.
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] name		string start.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
ssize_t fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
				    fr_dict_t const *dict, char const *name)
{
	fr_dict_attr_t const	*da;
	char const		*p;
	size_t			len;
	char			buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	*out = NULL;

	INTERNAL_IF_NULL(dict, 0);

	if (!*name) {
		fr_strerror_printf("Zero length attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return 0;
	}

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = name; fr_dict_attr_allowed_chars[(uint8_t)*p]; p++);

	len = p - name;
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return -(FR_DICT_ATTR_MAX_NAME_LEN);
	}

	memcpy(buffer, name, len);
	buffer[len] = '\0';

	da = fr_hash_table_finddata(dict->attributes_by_name, &(fr_dict_attr_t){ .name = buffer });
	if (!da) {
		if (err) *err = FR_DICT_ATTR_NOTFOUND;
		fr_strerror_printf("Unknown attribute '%.*s'", (int) len, name);
		return 0;
	}

	*out = da;
	if (err) *err = FR_DICT_ATTR_OK;

	return p - name;
}

/** Locate a #fr_dict_attr_t by its name
 *
 * @note Unlike attribute numbers, attribute names are unique to the dictionary.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] name		of the attribute to locate.
 * @return
 * 	- Attribute matching name.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_name(fr_dict_t const *dict, char const *name)
{
	INTERNAL_IF_NULL(dict, NULL);

	if (!name) return NULL;

	return fr_hash_table_finddata(dict->attributes_by_name, &(fr_dict_attr_t) { .name = name });
}

/** Locate a qualified #fr_dict_attr_t by its name and a dictionary qualifier
 *
 * @note If calling this function from the server any list or request qualifiers
 *  should be stripped first.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] name		Dictionary/Attribute name.
 * @param[in] fallback		If true, fallback to the internal dictionary.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
ssize_t fr_dict_attr_by_qualified_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
					      fr_dict_t const *dict_def, char const *name, bool fallback)
{
	fr_dict_t const		*dict = NULL;
	fr_dict_t const		*dict_iter = NULL;
	char const		*p = name;
	ssize_t			slen;
	fr_dict_attr_err_t	aerr = FR_DICT_ATTR_OK;
	bool			internal = false;
	fr_hash_iter_t  	iter;

	*out = NULL;

	INTERNAL_IF_NULL(dict_def, -1);

	/*
	 *	Figure out if we should use the default dictionary
	 *	or if the string was qualified.
	 */
	slen = fr_dict_by_protocol_substr(&dict, p, dict_def);
	if (slen < 0) {
		if (err) *err = FR_DICT_ATTR_PROTOCOL_NOTFOUND;
		return 0;

	/*
	 *	Nothing was parsed, use the default dictionary
	 */
	} else if (slen == 0) {
		dict = dict_def;

	/*
	 *	Has dictionary qualifier, can't fallback
	 */
	} else if (slen > 0) {
		p += slen;

		/*
		 *	Next thing SHOULD be a '.'
		 */
		if (*p++ != '.') {
			if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			return 0;
		}

		fallback = false;
	}

again:
	slen = fr_dict_attr_by_name_substr(&aerr, out, dict, p);

	switch (aerr) {
	case FR_DICT_ATTR_OK:
		break;

	case FR_DICT_ATTR_NOTFOUND:
		/*
		 *	Loop over all the dictionaries
		 */
		if (fallback) {
			/*
			 *	Haven't started yet, do so.
			 */
			if (!dict_iter) {
				/*
				 *	Check the internal dictionary
				 *	first, unless it's alreaday
				 *	been checked.
				 */
				if (!internal) {
					internal = true;
					if (dict_def != fr_dict_internal) {
						dict = fr_dict_internal;
						goto again;
					}
				}

				/*
				 *	Start the iteration over all dictionaries.
				 */
				dict_iter = fr_hash_table_iter_init(protocol_by_num, &iter);
			} else {
			redo:
				dict_iter = fr_hash_table_iter_next(protocol_by_num, &iter);
			}

			if (!dict_iter) goto fail;
			if (dict_iter == dict_def) goto redo;

			dict = dict_iter;
			goto again;
		}

	fail:
		if (err) *err = aerr;
		return -((p - name) + slen);

	/*
	 *	Other error codes are the same
	 */
	default:
		if (err) *err = aerr;
		return -((p - name) + slen);
	}

	p += slen;

	/*
	 *	If we're returning a success code indication,
	 *	ensure we populated out
	 */
	if (!fr_cond_assert(*out)) {
		if (err) *err = FR_DICT_ATTR_EINVAL;
		return 0;
	}

	if (err) *err = FR_DICT_ATTR_OK;

	return p - name;
}

/** Locate a qualified #fr_dict_attr_t by its name and a dictionary qualifier
 *
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] attr		Dictionary/Attribute name.
 * @param[in] fallback		If true, fallback to the internal dictionary.
 * @return an #fr_dict_attr_err_t value.
 */
fr_dict_attr_err_t fr_dict_attr_by_qualified_name(fr_dict_attr_t const **out, fr_dict_t const *dict_def,
						  char const *attr, bool fallback)
{
	ssize_t			slen;
	fr_dict_attr_err_t	err = FR_DICT_ATTR_PARSE_ERROR;

	slen = fr_dict_attr_by_qualified_name_substr(&err, out, dict_def, attr, fallback);
	if (slen <= 0) return err;

	if ((size_t)slen != strlen(attr)) {
		fr_strerror_printf("Trailing garbage after attr string \"%s\"", attr);
		return FR_DICT_ATTR_PARSE_ERROR;
	}

	return FR_DICT_ATTR_OK;
}

/** Lookup a attribute by its its vendor and attribute numbers and data type
 *
 * @note Only works with FR_TYPE_COMBO_IP
 *
 * @param[in] da		to look for type variant of.
 * @param[in] type		Variant of attribute to lookup.
 * @return
 * 	- Attribute matching parent/attr/type.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_type(fr_dict_attr_t const *da, fr_type_t type)
{
	return fr_hash_table_finddata(fr_dict_by_da(da)->attributes_combo,
				      &(fr_dict_attr_t){
				      		.parent = da->parent,
				      		.attr = da->attr,
				      		.type = type
				      });
}

/** Check if a child attribute exists in a parent using a pointer (da)
 *
 * @param[in] parent		to check for child in.
 * @param[in] child		to look for.
 * @return
 *	- The child attribute on success.
 *	- NULL if the child attribute does not exist.
 */
fr_dict_attr_t const *fr_dict_attr_child_by_da(fr_dict_attr_t const *parent, fr_dict_attr_t const *child)
{
	fr_dict_attr_t const *bin;

	DA_VERIFY(parent);

	if (!parent->children) return NULL;

	/*
	 *	Only some types can have children
	 */
	switch (parent->type) {
	default:
		return NULL;

	case FR_TYPE_STRUCTURAL:
		break;
	}

	/*
	 *	Child arrays may be trimmed back to save memory.
	 *	Check that so we don't SEGV.
	 */
	if ((child->attr & 0xff) > talloc_array_length(parent->children)) return NULL;

	bin = parent->children[child->attr & 0xff];
	for (;;) {
		if (!bin) return NULL;
		if (bin == child) return bin;
		bin = bin->next;
	}

	return NULL;
}

/** Check if a child attribute exists in a parent using an attribute number
 *
 * @param[in] parent		to check for child in.
 * @param[in] attr		number to look for.
 * @return
 *	- The child attribute on success.
 *	- NULL if the child attribute does not exist.
 */
inline fr_dict_attr_t const *fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *bin;

	DA_VERIFY(parent);

	if (!parent->children) return NULL;

	/*
	 *	Only some types can have children
	 */
	switch (parent->type) {
	default:
		return NULL;

	case FR_TYPE_STRUCTURAL:
		break;
	}

	/*
	 *	Child arrays may be trimmed back to save memory.
	 *	Check that so we don't SEGV.
	 */
	if ((attr & 0xff) > talloc_array_length(parent->children)) return NULL;

	bin = parent->children[attr & 0xff];
	for (;;) {
		if (!bin) return NULL;
		if (bin->attr == attr) return bin;
		bin = bin->next;
	}

	return NULL;
}

/** Lookup the structure representing an enum value in a #fr_dict_attr_t
 *
 * @param[in] da		to search in.
 * @param[in] value		to search for.
 * @return
 * 	- Matching #fr_dict_enum_t.
 * 	- NULL if no matching #fr_dict_enum_t could be found.
 */
fr_dict_enum_t *fr_dict_enum_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_enum_t	enumv, *dv;
	fr_dict_t	*dict;

	if (!da) return NULL;

	dict = fr_dict_by_da(da);
	if (!dict) {
		fr_strerror_printf("Attributes \"%s\" not present in any dictionaries", da->name);
		return NULL;
	}

	/*
	 *	Could be NULL or an unknown attribute, in which case
	 *	we want to avoid the lookup gracefully...
	 */
	if (value->type != da->type) return NULL;

	/*
	 *	First, look up aliases.
	 */
	enumv.da = da;
	enumv.alias = "";
	enumv.alias_len = 0;

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	dv = fr_hash_table_finddata(dict->values_by_alias, &enumv);
	if (dv) enumv.da = dv->da;

	enumv.value = value;

	return fr_hash_table_finddata(dict->values_by_da, &enumv);
}

/** Lookup the name of an enum value in a #fr_dict_attr_t
 *
 * @param[in] da		to search in.
 * @param[in] value		number to search for.
 * @return
 * 	- Name of value.
 * 	- NULL if no matching value could be found.
 */
char const *fr_dict_enum_alias_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_enum_t	*dv;
	fr_dict_t	*dict;

	if (!da) return NULL;

	dict = fr_dict_by_da(da);
	if (!dict) {
		fr_strerror_printf("Attributes \"%s\" not present in any dictionaries", da->name);
		return NULL;
	}

	dv = fr_dict_enum_by_value(da, value);
	if (!dv) return "";

	return dv->alias;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_enum_t *fr_dict_enum_by_alias(fr_dict_attr_t const *da, char const *alias, ssize_t len)
{
	fr_dict_enum_t	*found;
	fr_dict_enum_t	find = {
				.da = da,
				.alias = alias
			};
	fr_dict_t	*dict;

	if (!alias) return NULL;

	dict = fr_dict_by_da(da);
	if (!dict) {
		fr_strerror_printf("Attributes \"%s\" not present in any dictionaries", da->name);
		return NULL;
	}

	if (len < 0) len = strlen(alias);
	find.alias_len = (size_t)len;

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	found = fr_hash_table_finddata(dict->values_by_alias, &find);
	if (found) find.da = found->da;

	return fr_hash_table_finddata(dict->values_by_alias, &find);
}

/*
 *	String split routine.  Splits an input string IN PLACE
 *	into pieces, based on spaces.
 */
int fr_dict_str_to_argv(char *str, char **argv, int max_argc)
{
	int argc = 0;

	while (*str) {
		if (argc >= max_argc) break;

		/*
		 *	Chop out comments early.
		 */
		if (*str == '#') {
			*str = '\0';
			break;
		}

		while ((*str == ' ') ||
		       (*str == '\t') ||
		       (*str == '\r') ||
		       (*str == '\n'))
			*(str++) = '\0';

		if (!*str) break;

		argv[argc] = str;
		argc++;

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n'))
			str++;
	}

	return argc;
}

static int dict_read_sscanf_i(unsigned int *pvalue, char const *str)
{
	int rcode = 0;
	int base = 10;
	static char const *tab = "0123456789";

	if ((str[0] == '0') &&
	    ((str[1] == 'x') || (str[1] == 'X'))) {
		tab = "0123456789abcdef";
		base = 16;

		str += 2;
	}

	while (*str) {
		char const *c;

		if (*str == '.') break;

		c = memchr(tab, tolower((int)*str), base);
		if (!c) return 0;

		rcode *= base;
		rcode += (c - tab);
		str++;
	}

	*pvalue = rcode;
	return 1;
}

/** Parser context for dict_from_file
 *
 * Allows vendor and TLV context to persist across $INCLUDEs
 */
typedef struct {
	fr_dict_t		*dict;			//!< Protocol dictionary we're inserting attributes into.
	fr_dict_t		*old_dict;		//!< The dictionary before the current BEGIN-PROTOCOL block.

	fr_dict_vendor_t const	*block_vendor;		//!< Vendor block we're inserting attributes into.
							//!< Can be removed once we remove the vendor field from
							//!< #fr_dict_attr_t.

	fr_dict_attr_t const	*block_tlv[FR_DICT_TLV_NEST_MAX];	//!< Nested TLV block's we're
									//!< inserting attributes into.
	int			block_tlv_depth;	//!< Nested TLV block index we're inserting into.

	fr_dict_attr_t const	*parent;		//!< Current parent attribute (root/vendor/tlv).

	fr_dict_attr_t const	*value_attr;		//!< Cache of last attribute to speed up
							///< value processing.
	fr_dict_attr_t const	*previous_attr;		//!< for ".82" instead of "1.2.3.82".

	int			member_num;		//!< for attributes of type 'struct'

	TALLOC_CTX		*fixup_pool;		//!< Temporary pool for fixups, reduces holes
	dict_enum_fixup_t	*enum_fixup;
} dict_from_file_ctx_t;

/** Set a new root dictionary attribute
 *
 * @note Must only be called once per dictionary.
 *
 * @param[in] dict		to modify.
 * @param[in] name		of dictionary root.
 * @param[in] proto_number	The artificial (or IANA allocated) number for the protocol.
 *				This is only used for
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_root_set(fr_dict_t *dict, char const *name, unsigned int proto_number)
{
	fr_dict_attr_flags_t flags = {
		.is_root = 1,
		.type_size = 1,
		.length = 1
	};

	if (!fr_cond_assert(!dict->root)) {
		fr_strerror_printf("Dictionary root already set");
		return -1;
	}

	dict->root = dict_attr_alloc_name(dict, name);
	if (!dict->root) return -1;

	dict_attr_init(dict->root, NULL, proto_number, FR_TYPE_TLV, &flags);
	DA_VERIFY(dict->root);

	return 0;
}

static int _dict_free(fr_dict_t *dict)
{
	if (dict == fr_dict_internal) fr_dict_internal = NULL;

	if (!fr_cond_assert(!dict->in_protocol_by_name || fr_hash_table_delete(protocol_by_name, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol hash \"%s\"", dict->root->name);
		return -1;
	}
	if (!fr_cond_assert(!dict->in_protocol_by_num || fr_hash_table_delete(protocol_by_num, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol number_hash \"%s\"", dict->root->name);
		return -1;
	}

	return 0;
}

/** Allocate a new dictionary
 *
 * @param[in] ctx to allocate dictionary in.
 * @return
 *	- NULL on memory allocation error.
 */
static fr_dict_t *dict_alloc(TALLOC_CTX *ctx)
{
	fr_dict_t *dict;

	dict = talloc_zero(ctx, fr_dict_t);
	if (!dict) {
	error:
		fr_strerror_printf("Failed allocating memory for dictionary");
		talloc_free(dict);
		return NULL;
	}

	talloc_set_destructor(dict, _dict_free);

	/*
	 *	Pre-Allocate 6MB of pool memory for rapid startup
	 *	As that's the working memory required during
	 *	dictionary initialisation.
	 */
	dict->pool = talloc_pool(dict, DICT_POOL_SIZE);
	if (!dict->pool) goto error;

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 */
	dict->vendors_by_name = fr_hash_table_create(dict, dict_vendor_name_hash, dict_vendor_name_cmp, hash_pool_free);
	if (!dict->vendors_by_name) goto error;

	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	dict->vendors_by_num = fr_hash_table_create(dict, dict_vendor_pen_hash, dict_vendor_pen_cmp, NULL);
	if (!dict->vendors_by_num) goto error;

	/*
	 *	Create the table of attributes by name.   There MAY NOT
	 *	be multiple attributes of the same name.
	 */
	dict->attributes_by_name = fr_hash_table_create(dict, dict_attr_name_hash, dict_attr_name_cmp, NULL);
	if (!dict->attributes_by_name) goto error;

	/*
	 *	Horrible hacks for combo-IP.
	 */
	dict->attributes_combo = fr_hash_table_create(dict, dict_attr_combo_hash, dict_attr_combo_cmp, hash_pool_free);
	if (!dict->attributes_combo) goto error;

	dict->values_by_alias = fr_hash_table_create(dict, dict_enum_alias_hash, dict_enum_alias_cmp, hash_pool_free);
	if (!dict->values_by_alias) goto error;

	dict->values_by_da = fr_hash_table_create(dict, dict_enum_value_hash, dict_enum_value_cmp, hash_pool_free);
	if (!dict->values_by_da) goto error;

	return dict;
}

/** Lookup a dictionary reference
 *
 * Format is @verbatim[<proto>].[<attr>]@endverbatim
 *
 * If protocol is omitted lookup is in the current dictionary.
 *
 * FIXME: Probably needs the dictionary equivalent of pass2, to fixup circular dependencies
 *	DHCPv4->RADIUS and RADIUS->DHCPv4 are both valid.
 *
 * @param[in] dict	The current dictionary we're parsing.
 * @param[in,out] ref	The reference string.  Pointer advanced to the end of the string.
 * @return
 *	- NULL if the reference is invalid.
 *	- A local or foreign attribute representing the target of the reference.
 */
static fr_dict_attr_t const *dict_resolve_reference(fr_dict_t *dict, char const *ref)
{
	char const		*p = ref, *q, *end = p + strlen(ref);
	fr_dict_t		*proto_dict;
	fr_dict_attr_t const	*da;
	ssize_t			slen;

	/*
	 *	If the reference does not begin with .
	 *	then it's a reference into a foreign
	 *	protocol.
	 */
	if (*p != '.') {
		char buffer[FR_DICT_PROTO_MAX_NAME_LEN + 1];

		q = strchr(p, '.');
		if (!q) q = end;

		if ((size_t)(q - p) > sizeof(buffer)) {
			fr_strerror_printf("Protocol name too long");
			return NULL;
		}

		strlcpy(buffer, p, (q - p + 1));

		dict = fr_dict_by_protocol_name(buffer);
		if (!dict) {
			fr_strerror_printf("Referenced protocol \"%s\" not found", buffer);
			return NULL;
		}

		return NULL;
	/*
	 *	If the reference string begins with .
	 *	then the reference is in the current
	 *	dictionary.
	 */
	} else {
		proto_dict = dict;
	}

	/*
	 *	If there's a '.' after the dictionary, then
	 *	the reference is to a specific attribute.
	 */
	if (*p == '.') {
		p++;

		slen = fr_dict_attr_by_name_substr(NULL, &da, proto_dict, p);
		if (slen <= 0) {
			fr_strerror_printf("Referenced attribute \"%s\" not found", p);
			return NULL;
		}
	}

	da = fr_dict_root(proto_dict);
	if (!da) {
		fr_strerror_printf("Dictionary missing attribute root");
		return NULL;
	}

	return da;
}


static int dict_process_type_field(char const *name, fr_type_t *type_p, fr_dict_attr_flags_t *flags)
{
	char *p;
	int type;

	/*
	 *	Some types can have fixed length
	 */
	p = strchr(name, '[');
	if (p) *p = '\0';

	/*
	 *	find the type of the attribute.
	 */
	type = fr_str2int(fr_value_box_type_table, name, -1);
	if (type < 0) {
		fr_strerror_printf("Unknown data type '%s'", name);
		return -1;
	}

	if (p) {
		char *q;
		unsigned int length;

		if (type != FR_TYPE_OCTETS) {
			fr_strerror_printf("Only 'octets' types can have a 'length' parameter");
			return -1;
		}

		q = strchr(p + 1, ']');
		if (!q) {
			fr_strerror_printf("Invalid format for '%s[...]'", name);
			return -1;
		}

		*q = '\0';

		if (!dict_read_sscanf_i(&length, p + 1)) {
			fr_strerror_printf("Invalid length for '%s[...]'", name);
			return -1;
		}

		if ((length == 0) || (length > 253)) {
			fr_strerror_printf("Invalid length for '%s[...]'", name);
			return -1;
		}

		flags->length = length;
	}

	*type_p = type;
	return 0;
}


static int dict_process_flag_field(dict_from_file_ctx_t *ctx, char *name, fr_type_t type, fr_dict_attr_t const **ref_p, fr_dict_attr_flags_t *flags)
{
	char *p, *q, *v;
	fr_dict_attr_t const *ref = NULL;

	p = name;
	do {
		char key[64], value[256];

		q = strchr(p, ',');
		if (!q) q = p + strlen(p);

		/*
		 *	Nothing after the trailing comma
		 */
		if (p == q) break;

		if ((size_t)(q - p) > sizeof(key)) {
			fr_strerror_printf("ATTRIBUTE option key too long");
			return -1;
		}

		/*
		 *	Copy key and value
		 */
		if (!(v = memchr(p, '=', q - p)) || (v == q)) {
			value[0] = '\0';
			strlcpy(key, p, (q - p) + 1);
		} else {
			strlcpy(key, p, (v - p) + 1);
			strlcpy(value, v + 1, q - v);
		}

		/*
		 *	Boolean flag, means this is a tagged
		 *	attribute.
		 */
		if (strcmp(key, "has_tag") == 0) {
			flags->has_tag = 1;

			/*
			 *	Encryption method.
			 */
		} else if (strcmp(key, "encrypt") == 0) {
			char *qq;

			flags->encrypt = strtol(value, &qq, 0);
			if (*qq) {
				fr_strerror_printf("Invalid encrypt value \"%s\"", value);
				return -1;
			}

			/*
			 *	Marks the attribute up as internal.
			 *	This means it can use numbers outside of the allowed
			 *	protocol range, and also means it will not be included
			 *	in replies or proxy requests.
			 */
		} else if (strcmp(key, "internal") == 0) {
			flags->internal = 1;

		} else if (strcmp(key, "array") == 0) {
			flags->array = 1;

		} else if (strcmp(key, "concat") == 0) {
			flags->concat = 1;

		} else if (strcmp(key, "virtual") == 0) {
			flags->virtual = 1;

		} else if (strcmp(key, "long") == 0) {
			flags->extra = 1;

		} else if (ref_p && (strcmp(key, "reference") == 0)) {
			ref = dict_resolve_reference(ctx->dict, value);
			if (!ref) return -1;
			flags->is_reference = 1;

			*ref_p = ref;

		} else if (type == FR_TYPE_DATE) {
			int precision;

			precision = fr_str2int(date_precision_table, key, -1);
			if (precision < 0) {
				fr_strerror_printf("Unknown date precision '%s'", key);
				return -1;
			}
			flags->type_size = precision;

		} else {
			fr_strerror_printf("Unknown option '%s'", key);
			return -1;
		}
		p = q;
	} while (*p++);

	return 0;
}


/*
 *	Process the ATTRIBUTE command
 */
static int dict_read_process_attribute(dict_from_file_ctx_t *ctx, char **argv, int argc,
				       fr_dict_attr_flags_t *base_flags)
{
	bool			set_previous = true;

	unsigned int		attr;

	fr_type_t      		type;
	fr_dict_attr_flags_t	flags;
	fr_dict_attr_t const	*ref = NULL;
	fr_dict_attr_t const	*parent = ctx->parent;

	if ((argc < 3) || (argc > 4)) {
		fr_strerror_printf("Invalid ATTRIBUTE syntax");
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_printf("Invalid ATTRIBUTE name");
		return -1;
	}

	memcpy(&flags, base_flags, sizeof(flags));

	/*
	 *	Look for OIDs before doing anything else.
	 */
	if (!strchr(argv[1], '.')) {
		/*
		 *	Parse out the attribute number
		 */
		if (!dict_read_sscanf_i(&attr, argv[1])) {
			fr_strerror_printf("Invalid ATTRIBUTE number");
			return -1;
		}

		/*
		 *	Got a '.', which means "continue from the
		 *	previously defined attribute, which then must exist.
		 */
	} else if (argv[1][0] == '.') {
		if (!ctx->previous_attr) {
			fr_strerror_printf("Unknown parent for partial OID");
			return -1;
		}

		parent = ctx->previous_attr;
		set_previous = false;
		goto get_by_oid;

		/*
		 *	Got an OID string.  Every attribute should exist other
		 *	than the leaf, which is the attribute we're defining.
		 */
	} else {
		ssize_t slen;

get_by_oid:
		slen = fr_dict_attr_by_oid(ctx->dict, &parent, &attr, argv[1]);
		if (slen <= 0) return -1;

		if (!fr_cond_assert(parent)) return -1;	/* Should have provided us with a parent */
	}

	/*
	 *	Members of a 'struct' MUST use MEMBER, not ATTRIBUTE.
	 */
	if (parent->type == FR_TYPE_STRUCT) {
		fr_strerror_printf("Member %s of ATTRIBUTE %s type 'struct' MUST use \"MEMBER\" keyword",
				   argv[0], parent->name);
		return -1;
	}

	if (dict_process_type_field(argv[2], &type, &flags) < 0) return -1;

	/*
	 *	Parse options.
	 */
	if ((argc >= 4) && (dict_process_flag_field(ctx, argv[3], type, &ref, &flags) < 0)) return -1;

#ifdef WITH_DICTIONARY_WARNINGS
	/*
	 *	Hack to help us discover which vendors have illegal
	 *	attributes.
	 */
	if (!vendor && (attr < 256) &&
	    !strstr(fn, "rfc") && !strstr(fn, "illegal")) {
		fprintf(stderr, "WARNING: Illegal Attribute %s in %s\n",
			argv[0], fn);
	}
#endif

#ifdef __clang_analyzer__
	if (!ctx->dict) return -1;
#endif

	/*
	 *	Add in a normal attribute
	 */
	if (!ref) {
		if (fr_dict_attr_add(ctx->dict, parent, argv[0], attr, type, &flags) < 0) return -1;
	/*
	 *	Add in a special reference attribute
	 */
	} else {
		if (dict_attr_ref_add(ctx->dict, parent, argv[0], attr, type, &flags, ref) < 0) return -1;
	}

	/*
	 *	If we need to set the previous attribute, we have to
	 *	look it up by number.  This lets us set the
	 *	*canonical* previous attribute, and not any potential
	 *	duplicate which was just added.
	 */
	if (set_previous || (type == FR_TYPE_STRUCT)) ctx->previous_attr = fr_dict_attr_child_by_num(parent, attr);

	return 0;
}


/*
 *	Process the MEMBER command
 */
static int dict_read_process_member(dict_from_file_ctx_t *ctx, char **argv, int argc,
				       fr_dict_attr_flags_t *base_flags)
{
	fr_type_t      		type;
	fr_dict_attr_flags_t	flags;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_printf("Invalid MEMBER syntax");
		return -1;
	}

	if (!ctx->previous_attr) {
		fr_strerror_printf("MEMBER can only be used immediately after an ATTRIBUTE definition");
		return -1;
	}

	if (ctx->previous_attr->type != FR_TYPE_STRUCT) {
		fr_strerror_printf("MEMBER can only be used for ATTRIBUTEs of type 'struct', not %s", ctx->previous_attr->name);
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_printf("Invalid MEMBER name");
		return -1;
	}

	memcpy(&flags, base_flags, sizeof(flags));

	if (dict_process_type_field(argv[1], &type, &flags) < 0) return -1;

	/*
	 *	Parse options.
	 */
	if ((argc >= 3) && (dict_process_flag_field(ctx, argv[2], type, NULL, &flags) < 0)) return -1;

#ifdef __clang_analyzer__
	if (!ctx->dict) return -1;
#endif

	/*
	 *	Add in a normal attribute, and DON'T set ctx->previous_attr.
	 */
	if (fr_dict_attr_add(ctx->dict, ctx->previous_attr, argv[0], ++ctx->member_num, type, &flags) < 0) return -1;

	/*
	 *	A 'struct' can have a MEMBER of type 'tlv', but ONLY
	 *	as the last entry in the 'struct'.  If we see that,
	 *	set the previous attribute to the TLV we just added.
	 *	This allows the children of the TLV to be parsed as
	 *	partial OIDs, so we don't need to know the full path
	 *	to them.
	 */
	if (type == FR_TYPE_TLV) ctx->previous_attr = fr_dict_attr_child_by_num(ctx->previous_attr, ctx->member_num);

	return 0;
}


/** Process a value alias
 *
 */
static int dict_read_process_value(dict_from_file_ctx_t *ctx, char **argv, int argc)
{
	fr_dict_attr_t const		*da;
	fr_value_box_t			value;

	if (argc != 3) {
		fr_strerror_printf("Invalid VALUE syntax");
		return -1;
	}

	/*
	 *	Most VALUEs are bunched together by ATTRIBUTE.  We can
	 *	save a lot of lookups on dictionary initialization by
	 *	caching the last attribute for a VALUE.
	 */
	if (!ctx->value_attr || (strcasecmp(argv[0], ctx->value_attr->name) != 0)) {
		ctx->value_attr = fr_dict_attr_by_name(ctx->dict, argv[0]);
	}
	da = ctx->value_attr;

	/*
	 *	Remember which attribute is associated with this
	 *	value.  This allows us to define enum
	 *	values before the attribute exists, and fix them
	 *	up later.
	 */
	if (!da) {
		dict_enum_fixup_t *fixup;

		if (!fr_cond_assert_msg(ctx->fixup_pool, "fixup pool context invalid")) return -1;

		fixup = talloc_zero(ctx->fixup_pool, dict_enum_fixup_t);
		if (!fixup) {
		oom:
			talloc_free(fixup);
			fr_strerror_printf("Out of memory");
			return -1;
		}
		fixup->attribute = talloc_strdup(fixup, argv[0]);
		if (!fixup->attribute) goto oom;
		fixup->alias = talloc_strdup(fixup, argv[1]);
		if (!fixup->alias) goto oom;
		fixup->value = talloc_strdup(fixup, argv[2]);
		if (!fixup->value) goto oom;

		/*
		 *	Insert to the head of the list.
		 */
		fixup->next = ctx->enum_fixup;
		ctx->enum_fixup = fixup;

		return 0;
	}

	/*
	 *	Only a few data types can have VALUEs defined.
	 */
	switch (da->type) {
	case FR_TYPE_ABINARY:
	case FR_TYPE_GROUP:
	case FR_TYPE_STRUCTURAL:
	case FR_TYPE_INVALID:
	case FR_TYPE_MAX:
		fr_strerror_printf_push("Cannot define VALUE for ATTRIBUTE \"%s\" of data type \"%s\"", da->name,
					fr_int2str(fr_value_box_type_table, da->type, "<INVALID>"));
		return -1;

	default:
		break;
	}

	{
		fr_type_t type = da->type;	/* Might change - Stupid combo IP */

		if (fr_value_box_from_str(NULL, &value, &type, NULL, argv[2], -1, '\0', false) < 0) {
			fr_strerror_printf_push("Invalid VALUE for ATTRIBUTE \"%s\"", da->name);
			return -1;
		}
	}

	if (fr_dict_enum_add_alias(da, argv[1], &value, false, true) < 0) {
		fr_value_box_clear(&value);
		return -1;
	}
	fr_value_box_clear(&value);

	return 0;
}

/*
 *	Process the FLAGS command
 */
static int dict_read_process_flags(UNUSED fr_dict_t *dict, char **argv, int argc,
				   fr_dict_attr_flags_t *base_flags)
{
	bool sense = true;

	if (argc == 1) {
		char *p;

		p = argv[0];
		if (*p == '!') {
			sense = false;
			p++;
		}

		if (strcmp(p, "internal") == 0) {
			base_flags->internal = sense;
			return 0;
		}
	}

	fr_strerror_printf("Invalid FLAGS syntax");
	return -1;
}


static int dict_read_parse_format(char const *format, unsigned int *pvalue, int *ptype, int *plength,
				  bool *pcontinuation)
{
	char const *p;
	int type, length;
	bool continuation = false;

	if (strncasecmp(format, "format=", 7) != 0) {
		fr_strerror_printf("Invalid format for VENDOR.  Expected 'format=', got '%s'",
				   format);
		return -1;
	}

	p = format + 7;
	if ((strlen(p) < 3) ||
	    !isdigit((int)p[0]) ||
	    (p[1] != ',') ||
	    !isdigit((int)p[2]) ||
	    (p[3] && (p[3] != ','))) {
		fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
				   p);
		return -1;
	}

	type = (int)(p[0] - '0');
	length = (int)(p[2] - '0');

	if ((type != 1) && (type != 2) && (type != 4)) {
		fr_strerror_printf("Invalid type value %d for VENDOR", type);
		return -1;
	}

	if ((length != 0) && (length != 1) && (length != 2)) {
		fr_strerror_printf("Ivalid length value %d for VENDOR", length);
		return -1;
	}

	if (p[3] == ',') {
		if (!p[4]) {
			fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
					   p);
			return -1;
		}

		if ((p[4] != 'c') ||
		    (p[5] != '\0')) {
			fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
					   p);
			return -1;
		}
		continuation = true;

		if ((*pvalue != VENDORPEC_WIMAX) ||
		    (type != 1) || (length != 1)) {
			fr_strerror_printf("Only WiMAX VSAs can have continuations");
			return -1;
		}
	}

	*ptype = type;
	*plength = length;
	*pcontinuation = continuation;
	return 0;
}

/** Register the specified dictionary as a protocol dictionary
 *
 * Allows vendor and TLV context to persist across $INCLUDEs
 */
static int dict_read_process_protocol(char **argv, int argc)
{
	unsigned int	value;
	unsigned int	type_size = 1;
	fr_dict_t	*dict;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_printf("Missing arguments after PROTOCOL.  Expected PROTOCOL <num> <name>");
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!dict_read_sscanf_i(&value, argv[1])) {
		fr_strerror_printf("Invalid number '%s' following PROTOCOL", argv[1]);
		return -1;
	}

	if (value == 0) {
		fr_strerror_printf("Invalid value '%u' following PROTOCOL", value);
		return -1;
	}

	/*
	 *	Look for a format statement.  This may specify the
	 *	type length of the protocol's types.
	 */
	if (argc == 3) {
		char const *p;
		char *q;

		if (strncasecmp(argv[2], "format=", 7) != 0) {
			fr_strerror_printf("Invalid format for PROTOCOL.  Expected 'format=', got '%s'", argv[2]);
			return -1;
		}
		p = argv[2] + 7;

		type_size = strtoul(p, &q, 10);
		if (q != (p + strlen(p))) {
			fr_strerror_printf("Found trailing garbage '%s' after format specifier", p);
			return -1;
		}
	}

	/*
	 *	Cross check name / number.
	 */
	dict = fr_dict_by_protocol_name(argv[0]);
	if (dict) {
#ifdef __clang_analyzer__
		if (!dict->root) return -1;
#endif

		if (dict->root->attr != value) {
			fr_strerror_printf("Conflicting numbers %u vs %u for PROTOCOL \"%s\"",
					   dict->root->attr, value, dict->root->name);
			return -1;
		}

	} else if ((dict = fr_dict_by_protocol_num(value)) != NULL) {
#ifdef __clang_analyzer__
		if (!dict->root || !dict->root->name || !argv[0]) return -1;
#endif

		if (strcasecmp(dict->root->name, argv[0]) != 0) {
			fr_strerror_printf("Conflicting names \"%s\" vs \"%s\" for PROTOCOL %u",
					   dict->root->name, argv[0], dict->root->attr);
			return -1;
		}
	}

	/*
	 *	And check types no matter what.
	 */
	if (dict) {
		if (dict->root->flags.type_size != type_size) {
			fr_strerror_printf("Conflicting flags for PROTOCOL \"%s\"", dict->root->name);
			return -1;
		}
		return 0;
	}

	dict = dict_alloc(NULL);

	/*
	 *	Set the root attribute with the protocol name
	 */
	dict_root_set(dict, argv[0], value);

	if (dict_protocol_add(dict) < 0) return -1;

	return 0;
}

/*
 *	Process the VENDOR command
 */
static int dict_read_process_vendor(fr_dict_t *dict, char **argv, int argc)
{
	unsigned int			value;
	int				type, length;
	bool				continuation = false;
	fr_dict_vendor_t const		*dv;
	fr_dict_vendor_t		*mutable;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_printf("Invalid VENDOR syntax");
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!dict_read_sscanf_i(&value, argv[1])) {
		fr_strerror_printf("Invalid number in VENDOR");
		return -1;
	}

	/*
	 *	Look for a format statement.  Allow it to over-ride the hard-coded formats below.
	 */
	if (argc == 3) {
		if (dict_read_parse_format(argv[2], &value, &type, &length, &continuation) < 0) return -1;

	} else {
		type = length = 1;
	}

	/* Create a new VENDOR entry for the list */
	if (dict_vendor_add(dict, argv[0], value) < 0) return -1;

	dv = fr_dict_vendor_by_num(dict, value);
	if (!dv) {
		fr_strerror_printf("Failed adding format for VENDOR");
		return -1;
	}

	memcpy(&mutable, &dv, sizeof(mutable));

	mutable->type = type;
	mutable->length = length;
	mutable->flags = continuation;

	return 0;
}

static int fr_dict_finalise(dict_from_file_ctx_t *ctx)
{
	/*
	 *	Resolve any VALUE aliases (enums) that were defined
	 *	before the attributes they reference.
	 */
	if (ctx->enum_fixup) {
		fr_dict_attr_t const *da;
		dict_enum_fixup_t *this, *next;

		for (this = ctx->enum_fixup; this != NULL; this = next) {
			fr_value_box_t	value;
			fr_type_t	type;
			int		ret;

			next = this->next;
			da = fr_dict_attr_by_name(ctx->dict, this->attribute);
			if (!da) {
				fr_strerror_printf("No ATTRIBUTE '%s' defined for VALUE '%s'",
						   this->attribute, this->alias);
			error:
				return -1;
			}
			type = da->type;

			if (fr_value_box_from_str(this, &value, &type, NULL,
						  this->value, talloc_array_length(this->value) - 1, '\0', false) < 0) {
				fr_strerror_printf_push("Invalid VALUE for ATTRIBUTE \"%s\"", da->name);
				goto error;
			}

			ret = fr_dict_enum_add_alias(da, this->alias, &value, false, false);
			fr_value_box_clear(&value);

			if (ret < 0) goto error;

			/*
			 *	Just so we don't lose track of things.
			 */
			ctx->enum_fixup = next;
		}
	}
	TALLOC_FREE(ctx->fixup_pool);

	/*
	 *	Walk over all of the hash tables to ensure they're
	 *	initialized.  We do this because the threads may perform
	 *	lookups, and we don't want multi-threaded re-ordering
	 *	of the table entries.  That would be bad.
	 */
	fr_hash_table_walk(ctx->dict->vendors_by_name, hash_null_callback, NULL);
	fr_hash_table_walk(ctx->dict->vendors_by_num, hash_null_callback, NULL);

	fr_hash_table_walk(ctx->dict->values_by_da, hash_null_callback, NULL);
	fr_hash_table_walk(ctx->dict->values_by_alias, hash_null_callback, NULL);

	ctx->value_attr = NULL;
	ctx->previous_attr = NULL;

	return 0;
}

/** Parse a dictionary file
 *
 * @param[in] ctx	Contains the current state of the dictionary parser.
 *			Used to track what PROTOCOL, VENDOR or TLV block
 *			we're in. Block context changes in $INCLUDEs should
 *			not affect the context of the including file.
 * @param[in] dir_name	Directory containing the dictionary we're loading.
 * @param[in] filename	we're parsing.
 * @param[in] src_file	The including file.
 * @param[in] src_line	Line on which the $INCLUDE or $INCLUDE- statement was found.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _dict_from_file(dict_from_file_ctx_t *ctx,
			   char const *dir_name, char const *filename,
			   char const *src_file, int src_line)
{
	FILE			*fp;
	char 			dir[256], fn[256];
	char			buf[256];
	char			*p;
	int			line = 0;

	struct stat		statbuf;
	char			*argv[MAX_ARGV];
	int			argc;
	fr_dict_attr_t const	*da;

	/*
	 *	Base flags are only set for the current file
	 */
	fr_dict_attr_flags_t	base_flags;

	if (!fr_cond_assert(!ctx->dict->root || ctx->parent)) return -1;

	if ((strlen(dir_name) + 3 + strlen(filename)) > sizeof(dir)) {
		fr_strerror_printf_push("%s: Filename name too long", "Error reading dictionary");
		return -1;
	}

	/*
	 *	If it's an absolute dir, forget the parent dir,
	 *	and remember the new one.
	 *
	 *	If it's a relative dir, tack on the current filename
	 *	to the parent dir.  And use that.
	 */
	if (!FR_DIR_IS_RELATIVE(filename)) {
		strlcpy(dir, filename, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			p[1] = '\0';
		} else {
			strlcat(dir, "/", sizeof(dir));
		}

		strlcpy(fn, filename, sizeof(fn));
	} else {
		strlcpy(dir, dir_name, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			if (p[1]) strlcat(dir, "/", sizeof(dir));
		} else {
			strlcat(dir, "/", sizeof(dir));
		}
		strlcat(dir, filename, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			p[1] = '\0';
		} else {
			strlcat(dir, "/", sizeof(dir));
		}

		p = strrchr(filename, FR_DIR_SEP);
		if (p) {
			snprintf(fn, sizeof(fn), "%s%s", dir, p);
		} else {
			snprintf(fn, sizeof(fn), "%s%s", dir, filename);
		}
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			fr_strerror_printf_push("Couldn't open dictionary %s: %s", fr_syserror(errno), fn);
		} else {
			fr_strerror_printf_push("Error reading dictionary: %s[%d]: Couldn't open dictionary '%s': %s",
						src_file, src_line, fn,
						fr_syserror(errno));
		}
		return -2;
	}

	/*
	 *	If fopen works, this works.
	 */
	if (stat(fn, &statbuf) < 0) {
		fclose(fp);
		return -1;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fp);
		fr_strerror_printf_push("Dictionary is not a regular file: %s", fn);
		return -1;
	}

	/*
	 *	Globally writable dictionaries means that users can control
	 *	the server configuration with little difficulty.
	 */
#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		fclose(fp);
		fr_strerror_printf_push("Dictionary is globally writable: %s. "
					"Refusing to start due to insecure configuration", fn);
		return -1;
	}
#endif

	/*
	 *	Seed the random pool with data.
	 */
	fr_rand_seed(&statbuf, sizeof(statbuf));

	memset(&base_flags, 0, sizeof(base_flags));

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;

		switch (buf[0]) {
		case '#':
		case '\0':
		case '\n':
		case '\r':
			continue;
		}

		/*
		 *  Comment characters should NOT be appearing anywhere but
		 *  as start of a comment;
		 */
		p = strchr(buf, '#');
		if (p) *p = '\0';

		argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
		if (argc == 0) continue;

		if (argc == 1) {
			fr_strerror_printf("Invalid entry");

		error:
			fr_strerror_printf_push("Error reading %s[%d]", fn, line);
			fclose(fp);
			return -1;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
			if (dict_read_process_attribute(ctx,
							argv + 1, argc - 1,
							&base_flags) == -1) goto error;

			/*
			 *	When we see a new ATTRIBUTE, it means
			 *	that we're done the MEMBER definitions
			 *	of a 'struct'.
			 */
			ctx->member_num = 0;
			continue;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(argv[0], "VALUE") == 0) {
			if (dict_read_process_value(ctx, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Process FLAGS lines.
		 */
		if (strcasecmp(argv[0], "FLAGS") == 0) {
			if (dict_read_process_flags(ctx->dict, argv + 1, argc - 1, &base_flags) == -1) goto error;
			continue;
		}

		/*
		 *	Perhaps this is a MEMBER of a struct
		 *
		 *	@todo - create child ctx, so that we can have
		 *	nested structs.
		 */
		if (strcasecmp(argv[0], "MEMBER") == 0) {
			if (dict_read_process_member(ctx,
						     argv + 1, argc - 1,
						     &base_flags) == -1) goto error;
			continue;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strncasecmp(argv[0], "$INCLUDE", 8) == 0) {
			int rcode;
			dict_from_file_ctx_t nctx = *ctx;

			/*
			 *	Allow "$INCLUDE" or "$INCLUDE-", but
			 *	not anything else.
			 */
			if ((argv[0][8] != '\0') && ((argv[0][8] != '-') || (argv[0][9] != '\0'))) goto invalid_keyword;

			/*
			 *	Included files operate on a copy of the context.
			 *
			 *	This copy means that they inherit the
			 *	current context, including parents,
			 *	TLVs, etc.  But if the included file
			 *	leaves a "dangling" TLV or "last
			 *	attribute", then it won't affect the
			 *	parent.
			 */

			rcode = _dict_from_file(&nctx, dir, argv[1], fn, line);
			if ((rcode == -2) && (argv[0][8] == '-')) {
				fr_strerror_printf(NULL); /* delete all errors */
				rcode = 0;
			}

			if (rcode < 0) {
				fr_strerror_printf_push("from $INCLUDE at %s[%d]", fn, line);
				fclose(fp);
				return -1;
			}

			/*
			 *	Fixups are added to the head of the
			 *	list, so copy the new head over to the
			 *	parent.
			 */
			ctx->enum_fixup = nctx.enum_fixup;
			continue;
		} /* $INCLUDE */

		/*
		 *	Reset the previous attribute when we see
		 *	VENDOR or PROTOCOL or BEGIN/END-VENDOR, etc.
		 */
		ctx->value_attr = NULL;
		ctx->previous_attr = NULL;

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(argv[0], "VENDOR") == 0) {
			if (dict_read_process_vendor(ctx->dict, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Process PROTOCOL line.  Defines a new protocol.
		 */
		if (strcasecmp(argv[0], "PROTOCOL") == 0) {
			if (argc < 2) {
				fr_strerror_printf_push("Invalid PROTOCOL entry");
				goto error;
			}
			if (dict_read_process_protocol(argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Switches the current protocol context
		 */
		if (strcasecmp(argv[0], "BEGIN-PROTOCOL") == 0) {
			fr_dict_t *found;

			ctx->old_dict = ctx->dict;

			if (argc != 2) {
				fr_strerror_printf_push("Invalid BEGIN-PROTOCOL entry");
				goto error;
			}

			/*
			 *	If we're not parsing in the context of the internal
			 *	dictionary, then we don't allow BEGIN-PROTOCOL
			 *	statements.
			 */
			if (ctx->dict != fr_dict_internal) {
				fr_strerror_printf_push("Nested BEGIN-PROTOCOL statements are not allowed");
				goto error;
			}

			found = fr_dict_by_protocol_name(argv[1]);
			if (!found) {
				fr_strerror_printf("Unknown protocol '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Add a temporary fixup pool
			 *
			 *	@todo - make a nested ctx?
			 */
			if (!ctx->fixup_pool) ctx->fixup_pool = talloc_pool(NULL, DICT_FIXUP_POOL_SIZE);

			ctx->dict = found;
			ctx->parent = ctx->dict->root;

			// check if there's a linked library for the
			// protocol.  The values can be unknown (we
			// try to load one), or non-existent, or
			// known.  For the last two, we don't try to
			// load anything.

			//

			continue;
		}

		/*
		 *	Switches back to the previous protocol context
		 */
		if (strcasecmp(argv[0], "END-PROTOCOL") == 0) {
			fr_dict_t const *found;

			if (argc != 2) {
				fr_strerror_printf("Invalid END-PROTOCOL entry");
				goto error;
			}

			found = fr_dict_by_protocol_name(argv[1]);
			if (!found) {
				fr_strerror_printf("END-PROTOCOL %s does not refer to a valid protocol", argv[1]);
				goto error;
			}

			if (found != ctx->dict) {
				fr_strerror_printf("END-PROTOCOL %s does not match previous BEGIN-PROTOCOL %s",
						   argv[1], found->root->name);
				goto error;
			}

			/*
			 *	Applies fixups to any attributes added to
			 *	the protocol dictionary.
			 */
			if (fr_dict_finalise(ctx) < 0) goto error;

			/*
			 *	Switch back to old values.
			 *
			 *	@todo - just create a stack of contests, so we don't need "old_foo"
			 */
			ctx->dict = ctx->old_dict;
			ctx->parent = ctx->dict->root;
			continue;
		}

		/*
		 *	Switches TLV parent context
		 */
		if (strcasecmp(argv[0], "BEGIN-TLV") == 0) {
			fr_dict_attr_t const *common;

			if ((ctx->block_tlv_depth + 1) > FR_DICT_TLV_NEST_MAX) {
				fr_strerror_printf_push("TLVs are nested too deep");
				goto error;
			}

			if (argc != 2) {
				fr_strerror_printf_push("Invalid BEGIN-TLV entry");
				goto error;
			}

			da = fr_dict_attr_by_name(ctx->dict, argv[1]);
			if (!da) {
				fr_strerror_printf_push("Unknown attribute '%s'", argv[1]);
				goto error;
			}

			if (da->type != FR_TYPE_TLV) {
				fr_strerror_printf_push("Attribute '%s' should be a 'tlv', but is a '%s'",
							argv[1],
							fr_int2str(fr_value_box_type_table, da->type, "?Unknown?"));
				goto error;
			}

			common = fr_dict_parent_common(ctx->parent, da, true);
			if (!common ||
			    (common->type == FR_TYPE_VSA) ||
			    (common->type == FR_TYPE_EVS)) {
				fr_strerror_printf_push("Attribute '%s' should be a child of '%s'",
							argv[1], ctx->parent->name);
				goto error;
			}

			ctx->block_tlv[ctx->block_tlv_depth++] = ctx->parent;
			ctx->parent = da;

			continue;
		} /* BEGIN-TLV */

		/*
		 *	Switches back to previous TLV parent
		 */
		if (strcasecmp(argv[0], "END-TLV") == 0) {
			if (--ctx->block_tlv_depth < 0) {
				fr_strerror_printf_push("Too many END-TLV entries.  Mismatch at END-TLV %s", argv[1]);
				goto error;
			}

			if (argc != 2) {
				fr_strerror_printf_push("Invalid END-TLV entry");
				goto error;
			}

			da = fr_dict_attr_by_name(ctx->dict, argv[1]);
			if (!da) {
				fr_strerror_printf_push("Unknown attribute '%s'", argv[1]);
				goto error;
			}

			if (da != ctx->parent) {
				fr_strerror_printf_push("END-TLV %s does not match previous BEGIN-TLV %s", argv[1],
						   ctx->parent->name);
				goto error;
			}
			ctx->parent = ctx->block_tlv[ctx->block_tlv_depth];
			continue;
		} /* END-VENDOR */

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			fr_dict_vendor_t const	*vendor;
			fr_dict_attr_flags_t	flags;

			fr_dict_attr_t const	*vsa_da;
			fr_dict_attr_t const	*vendor_da;
			fr_dict_attr_t		*new;
			fr_dict_attr_t		*mutable;

			if (argc < 2) {
				fr_strerror_printf_push("Invalid BEGIN-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf_push("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Check for extended attr VSAs
			 *
			 *	BEGIN-VENDOR foo format=Foo-Encapsulation-Attr
			 */
			if (argc > 2) {
				if (strncmp(argv[2], "format=", 7) != 0) {
					fr_strerror_printf_push("Invalid format %s", argv[2]);
					goto error;
				}

				p = argv[2] + 7;
				da = fr_dict_attr_by_name(ctx->dict, p);
				if (!da) {
					fr_strerror_printf_push("Invalid format for BEGIN-VENDOR: Unknown "
								"attribute '%s'", p);
					goto error;
				}

				if (da->type != FR_TYPE_EVS) {
					fr_strerror_printf_push("Invalid format for BEGIN-VENDOR.  "
								"Attribute '%s' should be 'evs' but is '%s'", p,
								fr_int2str(fr_value_box_type_table, da->type, "?Unknown?"));
					goto error;
				}

				vsa_da = da;
			} else {
				/*
				 *	Automagically create Attribute 26
				 *
				 *	This should exist, but in case we're starting without
				 *	the RFC dictionaries we need to add it in the case
				 *	it doesn't.
				 */
				vsa_da = fr_dict_attr_child_by_num(ctx->parent, FR_VENDOR_SPECIFIC);
				if (!vsa_da) {
					memset(&flags, 0, sizeof(flags));

					if (fr_dict_attr_add(ctx->dict, ctx->parent, "Vendor-Specific",
							     FR_VENDOR_SPECIFIC, FR_TYPE_VSA, &flags) < 0) {
						fr_strerror_printf_push("Failed adding Vendor-Specific for Vendor %s",
									vendor->name);
						goto error;
					}

					vsa_da = fr_dict_attr_child_by_num(ctx->parent, FR_VENDOR_SPECIFIC);
					if (!vsa_da) {
						fr_strerror_printf_push("Failed finding Vendor-Specific for Vendor %s",
									vendor->name);
						goto error;
					}
				}
			}

			/*
			 *	Create a VENDOR attribute on the fly, either in the context
			 *	of the EVS attribute, or the VSA (26) attribute.
			 */
			vendor_da = fr_dict_attr_child_by_num(vsa_da, vendor->pen);
			if (!vendor_da) {
				memset(&flags, 0, sizeof(flags));

				if (vsa_da->type == FR_TYPE_VSA) {
					fr_dict_vendor_t const *dv;

					dv = fr_dict_vendor_by_num(ctx->dict, vendor->pen);
					if (dv) {
						flags.type_size = dv->type;
						flags.length = dv->length;

					} else { /* unknown vendor, shouldn't happen */
						flags.type_size = 1;
						flags.length = 1;
					}

				} else { /* EVS are always "format=1,1" */
					flags.type_size = 1;
					flags.length = 1;
				}

				memcpy(&mutable, &vsa_da, sizeof(mutable));
				new = dict_attr_alloc(mutable, ctx->parent, argv[1],
						      vendor->pen, FR_TYPE_VENDOR, &flags);
				if (dict_attr_child_add(mutable, new) < 0) {
					talloc_free(new);
					goto error;
				}

				vendor_da = new;
			}
			ctx->parent = vendor_da;
			ctx->block_vendor = vendor;
			continue;
		} /* BEGIN-VENDOR */

		if (strcasecmp(argv[0], "END-VENDOR") == 0) {
			fr_dict_vendor_t const *vendor;

			if (argc != 2) {
				fr_strerror_printf_push("Invalid END-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf_push("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			if (vendor != ctx->block_vendor) {
				fr_strerror_printf_push("END-VENDOR '%s' does not match any previous BEGIN-VENDOR",
						   argv[1]);
				goto error;
			}
			ctx->parent = ctx->dict->root;
			ctx->block_vendor = NULL;
			continue;
		} /* END-VENDOR */

		/*
		 *	Any other string: We don't recognize it.
		 */
	invalid_keyword:
		fr_strerror_printf_push("Invalid keyword '%s'", argv[0]);
		goto error;
	}
	fclose(fp);
	return 0;
}

static int dict_from_file(fr_dict_t *dict,
			  char const *dir_name, char const *filename,
			  char const *src_file, int src_line)
{
	int rcode;
	dict_from_file_ctx_t ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.dict = dict;
	ctx.parent = dict->root;

	rcode = _dict_from_file(&ctx,
				dir_name, filename, src_file, src_line);
	if (rcode < 0) {
		// free up the various fixups
		return rcode;
	}

	/*
	 *	Applies  to any attributes added to the *internal*
	 *	dictionary.
	 *
	 *	Fixups should have been applied already to any protocol
	 *	dictionaries.
	 */
	return fr_dict_finalise(&ctx);
}

/** (Re-)Initialize the special internal dictionary
 *
 * This dictionary has additional programatically generated attributes added to it,
 * and is checked in addition to the protocol specific dictionaries.
 *
 * @note The dictionary pointer returned in out must have its reference counter
 *	 decremented with #fr_dict_free when no longer used.
 *
 * @param[out] out		Where to write pointer to the internal dictionary.
 * @param[in] dict_subdir	name of the internal dictionary dir (may be NULL).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_internal_afrom_file(fr_dict_t **out, char const *dict_subdir)
{
	fr_dict_t		*dict;
	char			*dict_path = NULL;
	char			*tmp;
	FR_NAME_NUMBER const	*p;
	fr_dict_attr_flags_t	flags = { .internal = true };
	char			*type_name;

	if (unlikely(!protocol_by_name || !protocol_by_num)) {
		fr_strerror_printf("fr_dict_global_init() must be called before loading dictionary files");
		return -1;
	}

	/*
	 *	Increase the reference count of the internal dictionary.
	 */
	if (fr_dict_internal) {
		 talloc_increase_ref_count(fr_dict_internal);
		 *out = fr_dict_internal;
		 return 0;
	}

	memcpy(&tmp, &default_dict_dir, sizeof(tmp));
	dict_path = dict_subdir ? talloc_asprintf(NULL, "%s%c%s", default_dict_dir, FR_DIR_SEP, dict_subdir) : tmp;

	dict = dict_alloc(dict_ctx);
	if (!dict) {
	error:
		if (!fr_dict_internal) talloc_free(dict);
		talloc_free(dict_path);
		return -1;
	}

	/*
	 *	Set the root name of the dictionary
	 */
	dict_root_set(dict, "internal", 0);

	/*
	 *	Add cast attributes.  We do it this way,
	 *	so cast attributes get added automatically for new types.
	 *
	 *	We manually add the attributes to the dictionary, and bypass
	 *	fr_dict_attr_add(), because we know what we're doing, and
	 *	that function does too many checks.
	 */
	for (p = fr_value_box_type_table; p->name; p++) {
		fr_dict_attr_t *n;

		type_name = talloc_typed_asprintf(NULL, "Tmp-Cast-%s", p->name);

		n = dict_attr_alloc(dict->pool, dict->root, type_name,
				    FR_CAST_BASE + p->number, p->number, &flags);
		if (!n) {
			talloc_free(type_name);
			goto error;
		}

		if (!fr_hash_table_insert(dict->attributes_by_name, n)) {
			fr_strerror_printf("Failed inserting \"%s\" into internal dictionary", type_name);
			talloc_free(type_name);
			goto error;
		}

		talloc_free(type_name);

		/*
		 *	Set up parenting for the attribute.
		 */
		if (dict_attr_child_add(dict->root, n) < 0) goto error;
	}

	if (dict_path && dict_from_file(dict, dict_path, FR_DICTIONARY_FILE, NULL, 0) < 0) goto error;

	talloc_free(dict_path);

	*out = dict;
	if (!fr_dict_internal) fr_dict_internal = dict;

	return 0;
}

/** (Re)-initialize a protocol dictionary
 *
 * Initialize the directory, then fix the attr number of all attributes.
 *
 * @param[out] out		Where to write a pointer to the new dictionary.  Will free existing
 *				dictionary if files have changed and *out is not NULL.
 * @param[in] proto_name	that we're loading the dictionary for.
 * @param[in] proto_dir		Explicitly set where to hunt for the dictionary files.  May be NULL.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_protocol_afrom_file(fr_dict_t **out, char const *proto_name, char const *proto_dir)
{
	char		*dict_dir = NULL;
	fr_dict_t	*dict;

	if (unlikely(!protocol_by_name || !protocol_by_num)) {
		fr_strerror_printf("fr_dict_global_init() must be called before loading dictionary files");
		return -1;
	}

	if (unlikely(!fr_dict_internal)) {
		fr_strerror_printf("Internal dictionary must be initialised before loading protocol dictionaries");
		return -1;
	}

	/*
	 *	Increment the reference count if the dictionary
	 *	has already been loaded and return that.
	 */
	dict = fr_dict_by_protocol_name(proto_name);
	if (dict && dict->autoloaded) {
		talloc_increase_ref_count(dict);
		*out = dict;
		return 0;
	}

	if (!proto_dir) {
		dict_dir = talloc_asprintf(NULL, "%s%c%s", default_dict_dir, FR_DIR_SEP, proto_name);
	} else {
		dict_dir = talloc_asprintf(NULL, "%s%c%s", default_dict_dir, FR_DIR_SEP, proto_dir);
	}

	/*
	 *	Start in the context of the internal dictionary,
	 *	and switch to the context of a protocol dictionary
	 *	when we hit a BEGIN-PROTOCOL line.
	 *
	 *	This allows a single file to provide definitions
	 *	for multiple protocols, which'll probably be useful
	 *	at some point.
	 */
	if (dict_from_file(fr_dict_internal, dict_dir, FR_DICTIONARY_FILE, NULL, 0) < 0) {
	error:
		talloc_free(dict_dir);
		return -1;
	}

	/*
	 *	Check the dictionary actually defined the protocol
	 */
	dict = fr_dict_by_protocol_name(proto_name);
	if (!dict) {
		fr_strerror_printf("Dictionary \"%s\" missing \"BEGIN-PROTOCOL %s\" declaration", dict_dir, proto_name);
		goto error;
	}

	talloc_free(dict_dir);

	/*
	 *	If we're autoloading a previously defined dictionary,
	 *	then mark up the dictionary as now autoloaded.
	 */
	if (!dict->autoloaded) {
//		talloc_increase_ref_count(dict);
		dict->autoloaded = true;
	}

	*out = dict;

	return 0;
}

/** Read supplementary attribute definitions into an existing dictionary
 *
 * @param[in] dict	Existing dictionary.
 * @param[in] dir	dictionary is located in.
 * @param[in] filename	of the dictionary.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int fr_dict_read(fr_dict_t *dict, char const *dir, char const *filename)
{
	INTERNAL_IF_NULL(dict, -1);

	if (!dict->attributes_by_name) {
		fr_strerror_printf("%s: Must call fr_dict_internal_afrom_file() before fr_dict_read()", __FUNCTION__);
		return -1;
	}

	return dict_from_file(dict, dir, filename, NULL, 0);
}


/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] dict	to free.
 */
void fr_dict_free(fr_dict_t **dict)
{
	if (!*dict) return;

	talloc_decrease_ref_count(*dict);
	*dict = NULL;
}

/** Process a dict_attr_autoload element to load/verify a dictionary attribute
 *
 * @param[in] to_load	attribute definition
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_autoload(fr_dict_attr_autoload_t const *to_load)
{
	fr_dict_attr_t const		*da;
	fr_dict_attr_autoload_t const	*p = to_load;

	for (p = to_load; p->out; p++) {
		if (!p->dict) {
			fr_strerror_printf("Invalid autoload entry, missing dictionary pointer");
			return -1;
		}

		if (!*p->dict) {
			fr_strerror_printf("Can't resolve attribute \"%s\", dictionary not loaded", p->name);
			fr_strerror_printf_push("Check fr_dict_autoload_t struct has "
						"an entry to load the dictionary \"%s\" is located in, and that "
						"the symbol name is correct", p->name);
			return -1;
		}

		da = fr_dict_attr_by_name(*p->dict, p->name);
		if (!da) {
			fr_strerror_printf("Attribute \"%s\" not found in \"%s\" dictionary", p->name,
					   *p->dict ? (*p->dict)->root->name : "internal");
			return -1;
		}

		if (da->type != p->type) {
			fr_strerror_printf("Attribute \"%s\" should be type %s, but defined as type %s", da->name,
					   fr_int2str(fr_value_box_type_table, p->type, "?Unknown?"),
					   fr_int2str(fr_value_box_type_table, da->type, "?Unknown?"));
			return -1;
		}

		if (p->out) *(p->out) = da;
	}

	return 0;
}

/** Process a dict_autoload element to load a protocol
 *
 * @param[in] to_load	dictionary definition.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_autoload(fr_dict_autoload_t const *to_load)
{
	fr_dict_autoload_t const	*p;

	for (p = to_load; p->out; p++) {
		fr_dict_t *dict = NULL;

		if (unlikely(!p->proto)) {
			fr_strerror_printf("autoload missing parameter proto");
			return -1;
		}

		/*
		 *	Load the internal dictionary
		 */
		if (strcmp(p->proto, "freeradius") == 0) {
			if (fr_dict_internal_afrom_file(&dict, p->proto) < 0) return -1;
		} else {
			if (fr_dict_protocol_afrom_file(&dict, p->proto, p->base_dir) < 0) return -1;
		}

		*(p->out) = dict;
	}

	return 0;
}

/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] to_free	previously loaded dictionary to free.
 */
void fr_dict_autofree(fr_dict_autoload_t const *to_free)
{
	fr_dict_t			**dict;
	fr_dict_autoload_t const	*p;

	for (p = to_free; p->out; p++) {
		dict = p->out;
		if (!*dict) continue;

		fr_dict_free(dict);
	}
}

/** Callback to automatically load dictionaries required by modules
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	An array of fr_dict_autoload_t to load.
 * @param[in] user_ctx	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dl_dict_autoload(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	if (fr_dict_autoload((fr_dict_autoload_t const *)symbol) < 0) return -1;

	return 0;
}

/** Callback to automatically free a dictionary when the module is unloaded
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	An array of fr_dict_autoload_t to load.
 * @param[in] user_ctx	unused.
 */
void fr_dl_dict_autofree(UNUSED dl_t const *module, UNUSED void *symbol, UNUSED void *user_ctx)
{
//	fr_dict_autofree(((fr_dict_autoload_t *)symbol));
}

/** Callback to automatically resolve attributes and check the types are correct
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	An array of fr_dict_autoload_t to load.
 * @param[in] user_ctx	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dl_dict_attr_autoload(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	if (fr_dict_attr_autoload((fr_dict_attr_autoload_t *)symbol) < 0) return -1;

	return 0;
}

static void _fr_dict_dump(fr_dict_attr_t const *da, unsigned int lvl)
{
	unsigned int		i;
	size_t			len;
	fr_dict_attr_t const	*p;
	char			flags[256];

	fr_dict_snprint_flags(flags, sizeof(flags), da->type, &da->flags);

	printf("[%02i] 0x%016" PRIxPTR "%*s %s(%u) %s %s\n", lvl, (unsigned long)da, lvl * 2, " ",
	       da->name, da->attr, fr_int2str(fr_value_box_type_table, da->type, "<INVALID>"), flags);

	len = talloc_array_length(da->children);
	for (i = 0; i < len; i++) {
		for (p = da->children[i]; p; p = p->next) {
			_fr_dict_dump(p, lvl + 1);
		}
	}
}

void fr_dict_dump(fr_dict_t *dict)
{
	_fr_dict_dump(dict->root, 0);
}

/*
 *	External API for testing
 */
int fr_dict_parse_str(fr_dict_t *dict, char *buf, fr_dict_attr_t const *parent, unsigned int vendor_pen)
{
	int	argc;
	char	*argv[MAX_ARGV];
	int	ret;
	fr_dict_attr_flags_t base_flags;
	dict_from_file_ctx_t ctx;

	INTERNAL_IF_NULL(dict, -1);

	argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
	if (argc == 0) return 0;


	memset(&ctx, 0, sizeof(ctx));
	ctx.dict = dict;

	ctx.fixup_pool = talloc_pool(NULL, DICT_FIXUP_POOL_SIZE);
	if (!ctx.fixup_pool) return -1;

	if (strcasecmp(argv[0], "VALUE") == 0) {
		if (argc < 4) {
			fr_strerror_printf("VALUE needs at least 4 arguments, got %i", argc);
		error:
			TALLOC_FREE(ctx.fixup_pool);
			return -1;
		}

		if (!fr_dict_attr_by_name(dict, argv[1])) {
			fr_strerror_printf("Attribute \"%s\" does not exist in dictionary \"%s\"",
					   argv[1], dict->root->name);
			goto error;
		}
		ret = dict_read_process_value(&ctx, argv + 1, argc - 1);
		if (ret < 0) goto error;

	} else if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
		ctx.parent = parent;
		if (!ctx.parent) ctx.parent = fr_dict_root(dict);

		memset(&base_flags, 0, sizeof(base_flags));

		if (vendor_pen) ctx.block_vendor = fr_dict_vendor_by_num(dict, vendor_pen);

		ret = dict_read_process_attribute(&ctx,
						  argv + 1, argc - 1, &base_flags);
		if (ret < 0) goto error;
	} else if (strcasecmp(argv[0], "VENDOR") == 0) {
		ret = dict_read_process_vendor(dict, argv + 1, argc - 1);
		if (ret < 0) goto error;
	} else {
		fr_strerror_printf("Invalid input '%s'", argv[0]);
		goto error;
	}

	fr_dict_finalise(&ctx);

	return 0;
}

/** Initialise the global protocol hashes
 *
 * @note Must be called before any other dictionary functions.
 *
 * @param[in] ctx	to allocate protocol hashes in.
 * @param[in] dict_dir	the default location for the dictionaries.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_global_init(TALLOC_CTX *ctx, char const *dict_dir)
{
	if (!protocol_by_name) {
		protocol_by_name = fr_hash_table_create(ctx, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
		if (!protocol_by_name) {
			fr_strerror_printf("Failed initializing protocol_by_name hash");
			return -1;
		}
	}

	if (!protocol_by_num) {
		protocol_by_num = fr_hash_table_create(ctx, dict_protocol_num_hash, dict_protocol_num_cmp, NULL);
		if (!protocol_by_num) {
			fr_strerror_printf("Failed initializing protocol_by_num hash");
			return -1;
		}
	}

	talloc_free(default_dict_dir);		/* Free previous value */
	default_dict_dir = talloc_strdup(ctx, dict_dir);

	return 0;
}

/*
 *	[a-zA-Z0-9_-:.]+
 */
ssize_t fr_dict_valid_name(char const *name, ssize_t len)
{
	char const *p = name, *end;

	if (len < 0) len = strlen(name);

	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name is too long");
		return -1;
	}

	end = p + len;

	do {
		if (!fr_dict_attr_allowed_chars[(uint8_t)*p]) {
			fr_strerror_printf("Invalid character '%pV' in attribute name \"%pV\"",
					   fr_box_strvalue_len(p, 1), fr_box_strvalue_len(name, len));

			return -(p - name);
		}
		p++;
	} while (p < end);

	return len;
}

ssize_t fr_dict_valid_oid_str(char const *name, ssize_t len)
{
	char const *p = name, *end;

	if (len < 0) len = strlen(name);
	end = p + len;

	do {
		if (!fr_dict_attr_allowed_chars[(uint8_t)*p] && (*p != '.')) {
			fr_strerror_printf("Invalid character '%pV' in oid string \"%pV\"",
					   fr_box_strvalue_len(p, 1), fr_box_strvalue_len(name, len));

			return -(p - name);
		}
		p++;
	} while (p < end);

	return len;
}

void fr_dict_verify(char const *file, int line, fr_dict_attr_t const *da)
{
	int i;
	fr_dict_attr_t const *da_p;

	if (!da) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t pointer was NULL", file, line);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	(void) talloc_get_type_abort_const(da, fr_dict_attr_t);

	if ((!da->flags.is_root) && (da->depth == 0)) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
			     "Is not root, but depth is 0",
			     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	if (da->depth > FR_DICT_MAX_TLV_STACK) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
			     "Indicated depth (%u) greater than TLV stack depth (%u)",
			     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr,
			     da->depth, FR_DICT_MAX_TLV_STACK);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	for (da_p = da; da_p; da_p = da_p->next) {
		(void) talloc_get_type_abort_const(da_p, fr_dict_attr_t);
	}

	for (i = da->depth, da_p = da; (i >= 0) && da; i--, da_p = da_p->parent) {
		if (i != (int)da_p->depth) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
				     "Depth out of sequence, expected %i, got %u",
				     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr, i, da_p->depth);

			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

	}

	if ((i + 1) < 0) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t top of hierarchy was not at depth 0",
			     file, line);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}
}
