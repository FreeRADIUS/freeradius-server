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
 * @file src/lib/util/dict_util.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict_priv.h>
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

fr_dict_gctx_t *dict_gctx = NULL;	//!< Top level structure containing global dictionary state.

fr_table_num_ordered_t const date_precision_table[] = {
	{ L("microseconds"),	FR_TIME_RES_USEC },
	{ L("us"),		FR_TIME_RES_USEC },

	{ L("nanoseconds"),	FR_TIME_RES_NSEC },
	{ L("ns"),		FR_TIME_RES_NSEC },

	{ L("milliseconds"),	FR_TIME_RES_MSEC },
	{ L("ms"),		FR_TIME_RES_MSEC },

	{ L("seconds"),		FR_TIME_RES_SEC },
	{ L("s"),		FR_TIME_RES_SEC }

};
size_t date_precision_table_len = NUM_ELEMENTS(date_precision_table);


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
	[FR_TYPE_TIME_DELTA]   	= {4, 4},

	[FR_TYPE_TLV]		= {2, ~0},
	[FR_TYPE_STRUCT]	= {1, ~0},

	[FR_TYPE_VSA]		= {4, ~0},

	[FR_TYPE_MAX]		= {~0, 0}	//!< Ensure array covers all types.
};

/** Characters allowed in dictionary names
 *
 */
bool const fr_dict_attr_allowed_chars[UINT8_MAX + 1] = {
	['-'] = true, ['/'] = true, ['_'] = true,
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
	[FR_TYPE_VSA] = true,
	[FR_TYPE_VENDOR] = true
};

/*
 *	Create the hash of the name.
 *
 *	We copy the hash function here because it's substantially faster.
 */
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

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

/** Hash a enumeration name
 *
 */
static uint32_t dict_enum_name_hash(void const *data)
{
	fr_dict_enum_t const *enumv = data;

	return dict_hash_name((void const *)enumv->name, enumv->name_len);
}

/** Compare two dictionary attribute enum values
 *
 */
static int dict_enum_name_cmp(void const *one, void const *two)
{
	fr_dict_enum_t const *a = one;
	fr_dict_enum_t const *b = two;

	return strcasecmp(a->name, b->name);
}

/** Hash a dictionary enum value
 *
 */
static uint32_t dict_enum_value_hash(void const *data)
{
	fr_dict_enum_t const *enumv = data;

	return fr_value_box_hash_update(enumv->value, 0);
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

/** Set a dictionary attribute's name
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p	to set name for.
 * @param[in] name	to set.  If NULL a name will be automatically generated.
 */
static inline CC_HINT(always_inline) int dict_attr_name_set(fr_dict_attr_t **da_p, char const *name)
{
	char		buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];
	size_t		name_len;
	char		*name_start, *name_end;
	fr_dict_attr_t	*da = *da_p;

	/*
	 *	Generate a name if none is specified
	 */
	if (!name) {
		fr_sbuff_t unknown_name = FR_SBUFF_OUT(buffer, sizeof(buffer));


		fr_sbuff_in_sprintf(&unknown_name, "%u", da->attr);

		name = fr_sbuff_buff(&unknown_name);
		name_len = fr_sbuff_used(&unknown_name);
	} else {
		name_len = strlen(name);
	}

	/*
	 *	Grow the structure to hold the name
	 *
	 *	We add the name as an extension because it makes
	 *	the code less complex, and means the name value
	 *	is copied automatically when if the fr_dict_attr_t
	 *	is copied.
	 *
	 *	We do still need to fixup the da->name pointer
	 *	though.
	 */
	name_start = dict_attr_ext_alloc_size(da_p, FR_DICT_ATTR_EXT_NAME, name_len + 1);
	if (!name_start) return -1;

	name_end = name_start + name_len;

	memcpy(name_start, name, name_len);
	*name_end = '\0';

	(*da_p)->name = name_start;
	(*da_p)->name_len = name_len;

	return 0;
}

/** Add a child/nesting extension to an attribute
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to set a group reference for.
 */
static inline CC_HINT(always_inline) int dict_attr_children_init(fr_dict_attr_t **da_p)
{
	fr_dict_attr_ext_children_t	*ext;

	ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_CHILDREN);
	if (unlikely(!ext)) return -1;
	memset(ext, 0, sizeof(*ext));

	return 0;
}

/** Set a reference for a grouping attribute
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to set a group reference for.
 */
static inline CC_HINT(always_inline) int dict_attr_ref_init(fr_dict_attr_t **da_p)
{
	fr_dict_attr_ext_ref_t		*ext;

	ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) return -1;
	memset(ext, 0, sizeof(*ext));

	return 0;
}

/** Cache the vendor pointer for an attribute
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to set a group reference for.
 * @param[in] vendor		to set.
 */
static inline CC_HINT(always_inline) int dict_attr_vendor_set(fr_dict_attr_t **da_p, fr_dict_attr_t const *vendor)
{
	fr_dict_attr_ext_vendor_t	*ext;

	ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_VENDOR);
	if (unlikely(!ext)) return -1;

	ext->vendor = vendor;

	return 0;
}

/** Initialise an attribute's da stack from its parent
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to populate the da_stack for.
 */
static inline CC_HINT(always_inline) int dict_attr_da_stack_set(fr_dict_attr_t **da_p)
{
	fr_dict_attr_ext_da_stack_t	*ext, *p_ext;
	fr_dict_attr_t			*da = *da_p;
	fr_dict_attr_t const		*parent = da->parent;

	if (!parent) return 1;
	if (da->depth > FR_DICT_DA_STACK_CACHE_MAX) return 1;
	if (fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_DA_STACK)) return 1;

	p_ext = fr_dict_attr_ext(parent, FR_DICT_ATTR_EXT_DA_STACK);
	if (!p_ext) return 1;

	ext = dict_attr_ext_alloc_size(da_p, FR_DICT_ATTR_EXT_DA_STACK, sizeof(ext->da_stack[0]) * (da->depth + 1));
	if (unlikely(!ext)) return -1;

	memcpy(ext->da_stack, p_ext->da_stack, sizeof(ext->da_stack[0]) * parent->depth);

	/*
	 *	Always set the last stack entry to ourselves.
	 */
	ext->da_stack[da->depth] = da;

	return 0;
}

/** Initialise a per-attribute enumeration table
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to set a group reference for.
 */
static inline CC_HINT(always_inline) int dict_attr_enumv_init(fr_dict_attr_t **da_p)
{
	fr_dict_attr_ext_enumv_t	*ext;

	ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_ENUMV);
	if (unlikely(!ext)) return -1;
	memset(ext, 0, sizeof(*ext));

	return 0;
}

/** Initialise a per-attribute namespace
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to set a group reference for.
 */
static inline CC_HINT(always_inline) int dict_attr_namespace_init(fr_dict_attr_t **da_p)
{
	fr_dict_attr_ext_namespace_t	*ext;

	ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_NAMESPACE);
	if (unlikely(!ext)) return -1;

	/*
	 *	Create the table of attributes by name.
	 *      There MAY NOT be multiple attributes of the same name.
	 */
	ext->namespace = fr_hash_table_create(*da_p, dict_attr_name_hash, dict_attr_name_cmp, NULL);
	if (!ext->namespace) {
		fr_strerror_printf("Failed allocating \"namespace\" table");
		return -1;
	}

	return 0;
}

/** Initialise fields in a dictionary attribute structure
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] da_p		to initialise.
 * @param[in] parent		of the attribute, if none, should be
 *				the dictionary root.
 * @param[in] name		of attribute.  Pass NULL for auto-generated name.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] flags		to assign.
 */
int dict_attr_init(fr_dict_attr_t **da_p,
		   fr_dict_attr_t const *parent,
		   char const *name, int attr,
		   fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	**da_p = (fr_dict_attr_t) {
		.attr = attr,
		.type = type,
		.flags = *flags,
		.parent = parent,
	};

	/*
	 *	Record the parent
	 */
	if (parent) {
		(*da_p)->dict = parent->dict;
		(*da_p)->depth = parent->depth + 1;

		/*
		 *	Point to the vendor definition.  Since ~90% of
		 *	attributes are VSAs, caching this pointer will help.
		 */
		if (parent->type == FR_TYPE_VENDOR) {
			if (dict_attr_vendor_set(da_p, parent) < 0) return -1;
		} else {
			dict_attr_ext_copy(da_p, parent, FR_DICT_ATTR_EXT_VENDOR); /* Noop if no vendor extension */
		}
	} else {
		(*da_p)->depth = 0;
	}

	/*
	 *	Cache the da_stack so we don't need
	 *	to generate it at runtime.
	 */
	dict_attr_da_stack_set(da_p);

	/*
	 *	Structural types can have children
	 *	so add the extension for them.
	 */
	switch (type) {
	case FR_TYPE_STRUCTURAL:
	structural:
		if (type == FR_TYPE_GROUP) {
			if (dict_attr_ref_init(da_p) < 0) return -1;
			break;
		}

		if (type == FR_TYPE_TLV) {
			if (dict_attr_ref_init(da_p) < 0) return -1;	/* TLVs can reference common attribute sets */
		}

		if (dict_attr_children_init(da_p) < 0) return -1;
		if (dict_attr_namespace_init(da_p) < 0) return -1;	/* Needed for all TLV style attributes */
		break;

	/*
	 *	Keying types *sigh*
	 */
	case FR_TYPE_UINT8:	/* Hopefully temporary until unions are done properly */
	case FR_TYPE_UINT16:	/* Same here */
		if (dict_attr_enumv_init(da_p) < 0) return -1;
		goto structural;

	/*
	 *	Leaf types
	 */
	default:
		if (dict_attr_enumv_init(da_p) < 0) return -1;
		break;
	}

	/*
	 *	Name is a separate talloc chunk.  We allocate
	 *	it last because we cache the pointer value.
	 */
	if (dict_attr_name_set(da_p, name) < 0) return -1;

	DA_VERIFY(*da_p);

	return 0;
}

/** Allocate a partially completed attribute
 *
 * This is useful in some instances where we need to pre-allocate the attribute
 * for talloc hierarchy reasons, but want to finish initialising it
 * with #dict_attr_init later.
 *
 * @param[in] ctx		to allocate attribute in.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
fr_dict_attr_t *dict_attr_alloc_null(TALLOC_CTX *ctx)
{
	fr_dict_attr_t *da;

	da = talloc(ctx, fr_dict_attr_t);
	if (unlikely(!da)) return NULL;

	talloc_set_type(da, fr_dict_attr_t);

	return da;
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
fr_dict_attr_t *dict_attr_alloc(TALLOC_CTX *ctx,
				fr_dict_attr_t const *parent,
				char const *name, int attr,
				fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t	*n;

	n = dict_attr_alloc_null(ctx);
	if (unlikely(!n)) return NULL;

	if (dict_attr_init(&n, parent, name, attr, type, flags) < 0) {
		talloc_free(n);
		return NULL;
	}

	return n;
}

/** Copy a an existing attribute
 *
 * @param[in] ctx		to allocate new attribute in.
 * @param[in] in		attribute to copy.
 * @param[in] new_name		to assign to the attribute.
 *				If NULL the existing name will be used.
 * @return
 *	- A copy of the input fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t *dict_attr_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *in, char const *new_name)
{
	fr_dict_attr_t		*n;

	n = dict_attr_alloc(ctx, in->parent, new_name ? new_name : in->name, in->attr, in->type, &in->flags);
	if (unlikely(!n)) return NULL;

	if (dict_attr_ext_copy_all(&n, in) < 0) {
		talloc_free(n);
		return NULL;
	}
	DA_VERIFY(n);

	return n;
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
int dict_protocol_add(fr_dict_t *dict)
{
	if (!dict->root) return -1;	/* Should always have root */

	if (!fr_hash_table_insert(dict_gctx->protocol_by_name, dict)) {
		fr_dict_t *old_proto;

		old_proto = fr_hash_table_find_by_data(dict_gctx->protocol_by_name, dict);
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

	if (!fr_hash_table_insert(dict_gctx->protocol_by_num, dict)) {
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
int dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num)
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
	if (!vendor) {
	oom:
		fr_strerror_printf("Out of memory");
		return -1;
	}

	vendor->name = talloc_typed_strdup(vendor, name);
	if (!vendor->name) {
		talloc_free(vendor);
		goto oom;
	}
	vendor->pen = num;
	vendor->type = vendor->length = 1; /* defaults */

	if (!fr_hash_table_insert(dict->vendors_by_name, vendor)) {
		fr_dict_vendor_t const *old_vendor;

		old_vendor = fr_hash_table_find_by_data(dict->vendors_by_name, vendor);
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

/** See if a #fr_dict_attr_t can have children
 *
 *  The check for children is complicated by the need for "int" types
 *  to have children, when they are `key` fields in a `struct`.  This
 *  situation occurs when a struct has multiple sub-structures, which
 *  are selected based on a `key` field.
 *
 *  There is no other place for the sub-structures to go.  In the
 *  future, we may extend the functionality of the `key` field, by
 *  allowing non-integer data types.  That would require storing keys
 *  as #fr_dict_enum_t, and then placing the child (i.e. sub)
 *  structures there.  But that would involve adding children to
 *  enums, which is currently not supported.
 *
 * @param da the dictionary attribute to check.
 */
bool dict_attr_can_have_children(fr_dict_attr_t const *da)
{
	switch (da->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_STRUCT:
		return true;

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
		/*
		 *	Children are allowed here, but ONLY if this
		 *	attribute is a key field.
		 */
		if (da->parent && (da->parent->type == FR_TYPE_STRUCT) && da_is_key_field(da)) return true;
		break;

	default:
		break;
	}

	return false;
}

/** Add a child to a parent.
 *
 * @param[in] parent	we're adding a child to.
 * @param[in] child	to add to parent.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
int dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child)
{
	fr_dict_attr_t const * const *bin;
	fr_dict_attr_t **this;
	fr_dict_attr_t const **children;

	/*
	 *	Setup fields in the child
	 */
	fr_assert(child->parent == parent);

	DA_VERIFY(child);

	if (fr_dict_attr_ref(parent)) {
		fr_strerror_printf("Cannot add children to attribute '%s' which has 'ref=%s'",
				   parent->name, fr_dict_attr_ref(parent)->name);
		return false;
	}

	if (!dict_attr_can_have_children(parent)) {
		fr_strerror_printf("Cannot add children to attribute '%s' of type %s",
				   parent->name, fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
		return false;
	}

	/*
	 *	We only allocate the pointer array *if* the parent has children.
	 */
	children = dict_attr_children(parent);
	if (!children) {
		children = talloc_zero_array(parent, fr_dict_attr_t const *, UINT8_MAX + 1);
		if (!children) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
		if (dict_attr_children_set(parent, children) < 0) return -1;
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
	bin = &children[child->attr & 0xff];
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

/** Add an attribute to the name table for an attribute
 *
 * @param[in] dict		of protocol context we're operating in.
 * @param[in] parent		containing the namespace to add this attribute to.
 * @param[in] da		to add to the name lookup tables.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dict_attr_add_to_namespace(fr_dict_t *dict, fr_dict_attr_t const *parent, fr_dict_attr_t *da)
{
	fr_hash_table_t		*namespace;

	namespace = dict_attr_namespace(parent);
	if (unlikely(!namespace)) {
		fr_strerror_printf("Parent \"%s\" has no namespace", parent->name);
	error:
		return -1;
	}

	/*
	 *	Sanity check to stop children of vendors ending
	 *	up in the Vendor-Specific or root namespace.
	 */
	if ((fr_dict_vendor_num_by_da(da) != 0) && (da->type != FR_TYPE_VENDOR) &&
	    ((parent->type == FR_TYPE_VSA) || parent->flags.is_root)) {
		fr_strerror_printf("Cannot insert attribute '%s' of type %s into %s",
				   da->name,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"),
				   parent->name);
		goto error;
	}

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(namespace, da)) {
		fr_dict_attr_t *a;

		/*
		 *	Find the old name.  If it's the same name and
		 *	but the parent, or number, or type are
		 *	different, that's an error.
		 */
		a = fr_hash_table_find_by_data(namespace, da);
		if (a && (strcasecmp(a->name, da->name) == 0)) {
			if ((a->attr != da->attr) || (a->type != da->type) || (a->parent != da->parent)) {
				fr_strerror_printf("Duplicate attribute name \"%s\"", da->name);
				goto error;
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
		if (!fr_hash_table_replace(namespace, da)) {
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

		v4 = dict_attr_acopy(dict->pool, da, NULL);
		if (!v4) goto error;
		v4->type = FR_TYPE_IPV4_ADDR;

		v6 = dict_attr_acopy(dict->pool, da, NULL);
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

		v4 = dict_attr_acopy(dict->pool, da, NULL);
		if (!v4) goto error;
		v4->type = FR_TYPE_IPV4_PREFIX;

		v6 = dict_attr_acopy(dict->pool, da, NULL);
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

	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return -1;
	}

	/*
	 *	Check that the definition is valid.
	 */
	if (!dict_attr_fields_valid(dict, parent, name, &attr, type, &our_flags)) return -1;

	/*
	 *	Suppress duplicates.
	 */
#define FLAGS_EQUAL(_x) (old->flags._x == flags->_x)

	old = fr_dict_attr_by_name(NULL, fr_dict_root(dict), name);
	if (old) {
		if ((old->parent == parent)&& (old->type == type) &&
		    FLAGS_EQUAL(array) && FLAGS_EQUAL(subtype)  &&
		    ((old->attr == (unsigned int) attr) || ((attr < 0) && old->flags.internal))) {
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
						fr_table_str_by_value(fr_value_box_type_table, old->type, "?Unknown?"),
						fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"));
			return -1;
		}

		fr_strerror_printf_push("Cannot add duplicate name %s with different flags",
					name);
		return -1;
	}

	n = dict_attr_alloc(dict->pool, parent, name, attr, type, &our_flags);
	if (!n) return -1;

	if (dict_attr_add_to_namespace(dict, parent, n) < 0) {
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

	/*
	 *	If it's a group attribute, the default
	 *	reference goes to the root of the
	 *	dictionary as that's where the default
	 *	name/numberspace is.
	 *
	 *	This may be updated by the caller.
	 */
	if (type == FR_TYPE_GROUP) dict_attr_ref_set(n, fr_dict_root(dict));

	return 0;
}

int dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name,
			    fr_value_box_t const *value,
			    bool coerce, bool takes_precedence,
			    fr_dict_attr_t const *child_struct)
{
	size_t				len;
	fr_dict_t			*dict;
	fr_dict_enum_t			*enumv = NULL;
	fr_value_box_t			*enum_value = NULL;
	fr_dict_attr_ext_enumv_t	*ext;

	if (!da) {
		fr_strerror_printf("%s: Dictionary attribute not specified", __FUNCTION__);
		return -1;
	}

	if (!*name) {
		fr_strerror_printf("%s: Empty names are not permitted", __FUNCTION__);
		return -1;
	}

	len = strlen(name);
	if (len >= FR_DICT_ENUM_MAX_NAME_LEN) {
		fr_strerror_printf("%s: Value name too long", __FUNCTION__);
		return -1;
	}

	/*
	 *	Key fields CANNOT define VALUEs, and MUST define a child struct.
	 */
	if (da_is_key_field(da)) {
		if (!child_struct) {
			fr_strerror_printf("VALUEs cannot be defined for MEMBER attributes which are a 'key' field.");
			return -1;
		}
	} else if (child_struct) {
		fr_strerror_printf("Child structures cannot be defined for VALUEs which are not for 'key' attributes");
		return -1;
	}

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s attributes",
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Initialise enumv hash tables
	 */
	if (!ext->value_by_name || !ext->name_by_value) {
		ext->value_by_name = fr_hash_table_create(da, dict_enum_name_hash, dict_enum_name_cmp, hash_pool_free);
		if (!ext->value_by_name) {
			fr_strerror_printf("Failed allocating \"value_by_name\" table");
			return -1;
		}

		ext->name_by_value = fr_hash_table_create(da, dict_enum_value_hash, dict_enum_value_cmp, hash_pool_free);
		if (!ext->name_by_value) {
			fr_strerror_printf("Failed allocating \"name_by_value\" table");
			return -1;
		}
	}

	dict = dict_by_da(da);

	/*
	 *	Allocate a structure to map between
	 *	the name and value.
	 */
	enumv = talloc_zero_size(dict->pool, sizeof(fr_dict_enum_t) + sizeof(enumv->child_struct[0]) * (child_struct != NULL));
	if (!enumv) {
	oom:
		fr_strerror_printf("%s: Out of memory", __FUNCTION__);
		return -1;
	}
	talloc_set_type(enumv, fr_dict_enum_t);

	enumv->name = talloc_typed_strdup(enumv, name);
	enumv->name_len = strlen(name);

	if (child_struct) enumv->child_struct[0] = child_struct;
	enum_value = fr_value_box_alloc(enumv, da->type, NULL, false);
	if (!enum_value) goto oom;

	if (da->type != value->type) {
		if (!coerce) {
			fr_strerror_printf("%s: Type mismatch between attribute (%s) and enum (%s)",
					   __FUNCTION__,
					   fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, value->type, "<INVALID>"));
			return -1;
		}

		if (fr_value_box_cast(enumv, enum_value, da->type, NULL, value) < 0) {
			fr_strerror_printf_push("%s: Failed coercing enum type (%s) to attribute type (%s)",
						__FUNCTION__,
					   	fr_table_str_by_value(fr_value_box_type_table, value->type, "<INVALID>"),
					   	fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));

			return -1;
		}
	} else {
		if (fr_value_box_copy(enum_value, enum_value, value) < 0) {
			fr_strerror_printf_push("%s: Failed copying value into enum", __FUNCTION__);
			return -1;
		}
	}

	enumv->value = enum_value;

	/*
	 *	Add the value into the dictionary.
	 */
	{
		fr_dict_attr_t *tmp;
		memcpy(&tmp, &enumv, sizeof(tmp));

		if (!fr_hash_table_insert(ext->value_by_name, tmp)) {
			fr_dict_enum_t *old;

			/*
			 *	Suppress duplicates with the same
			 *	name and value.  There are lots in
			 *	dictionary.ascend.
			 */
			old = fr_dict_enum_by_name(da, name, -1);
			if (!fr_cond_assert(old)) return -1;

			if (fr_value_box_cmp(old->value, enumv->value) == 0) {
				talloc_free(enumv);
				return 0;
			}

			fr_strerror_printf("Duplicate VALUE name \"%s\" for Attribute '%s'. "
					   "Old value was \"%pV\", new value was \"%pV\"", name, da->name,
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
		if (!fr_hash_table_replace(ext->name_by_value, enumv)) {
			fr_strerror_printf("%s: Failed inserting value %s", __FUNCTION__, name);
			return -1;
		}
	} else {
		(void) fr_hash_table_insert(ext->name_by_value, enumv);
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

/** Add a value name
 *
 * Aliases are textual (string) names for a given value.
 *
 * Value names are not limited to integers, and may be added for any non-structural
 * attribute type.
 *
 * @param[in] da		to add enumeration value to.
 * @param[in] name		Name of value name.
 * @param[in] value		to associate with name.
 * @param[in] coerce		if the type of the value does not match the
 *				type of the da, attempt to cast it to match
 *				the type of the da.  If this is false and there's
 *				a type mismatch, we fail.
 *				We also fail if the value cannot be coerced to
 *				the attribute type.
 * @param[in] takes_precedence	This name should take precedence over previous
 *				names for the same value, when resolving value
 *				to name.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name,
			       fr_value_box_t const *value,
			       bool coerce, bool takes_precedence)
{
	return dict_attr_enum_add_name(da, name, value, coerce, takes_precedence, NULL);
}

/** Add an name to an integer attribute hashing the name for the integer value
 *
 */
int fr_dict_attr_enum_add_name_next(fr_dict_attr_t *da, char const *name)
{
	fr_value_box_t	v = {
				.type = da->type
			};
	fr_value_box_t	s = {
				.type = da->type
			};

	if (fr_dict_enum_by_name(da, name, -1)) return 0;

	switch (da->type) {
	case FR_TYPE_INT8:
		v.vb_int8 = s.vb_int8 = fr_hash_string(name) & INT8_MAX;
		break;

	case FR_TYPE_INT16:
		v.vb_int16 = s.vb_int16 = fr_hash_string(name) & INT16_MAX;
		break;

	case FR_TYPE_INT32:
		v.vb_int32 = s.vb_int32 = fr_hash_string(name) & INT32_MAX;
		break;

	case FR_TYPE_INT64:
		v.vb_int64 = s.vb_int64 = fr_hash_string(name) & INT64_MAX;
		break;

	case FR_TYPE_UINT8:
		v.vb_uint8 = s.vb_uint8 = fr_hash_string(name) & UINT8_MAX;
		break;

	case FR_TYPE_UINT16:
		v.vb_uint16 = s.vb_uint16 = fr_hash_string(name) & UINT16_MAX;
		break;

	case FR_TYPE_UINT32:
		v.vb_uint32 = s.vb_uint32 = fr_hash_string(name) & UINT32_MAX;
		break;

	case FR_TYPE_UINT64:
		v.vb_uint64 = s.vb_uint64 = fr_hash_string(name) & UINT64_MAX;
		break;

	default:
		fr_strerror_printf("Attribute is wrong type for auto-numbering, expected numeric type, got %s",
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return -1;
	}

	/*
	 *	If there's no existing value, add an enum
	 *	with the hash value of the name.
	 *
	 *	This helps with debugging as the values
	 *	are consistent.
	 */
	if (!fr_dict_enum_by_value(da, &v)) {
	add:
		return fr_dict_attr_enum_add_name(da, name, &v, false, false);
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

/** Find a common ancestor that two TLV type attributes share
 *
 * @param[in] a			first TLV attribute.
 * @param[in] b			second TLV attribute.
 * @param[in] is_ancestor	Enforce a->b relationship (a is parent or ancestor of b).
 * @return
 *	- Common ancestor if one exists.
 *	- NULL if no common ancestor exists.
 */
fr_dict_attr_t const *fr_dict_attr_common_parent(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor)
{
	unsigned int i;
	fr_dict_attr_t const *p_a, *p_b;

	if (!a || !b) return NULL;

	if (is_ancestor && (b->depth <= a->depth)) return NULL;	/* fast_path */

	/*
	 *	Find a common depth to work back from
	 */
	if (a->depth > b->depth) {
		p_b = b;
		for (p_a = a, i = a->depth - b->depth; p_a && (i > 0); p_a = p_a->parent, i--);
		if (is_ancestor && (p_a != p_b)) return NULL;
	} else if (a->depth < b->depth) {
		p_a = a;
		for (p_b = b, i = b->depth - a->depth; p_b && (i > 0); p_b = p_b->parent, i--);
		if (is_ancestor && (p_a != p_b)) return NULL;
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
int fr_dict_oid_component_legacy(unsigned int *out, char const **oid)
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
ssize_t fr_dict_attr_by_oid_legacy(fr_dict_t const *dict, fr_dict_attr_t const **parent, unsigned int *attr, char const *oid)
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

	if (fr_dict_oid_component_legacy(&num, &p) < 0) return oid - p;

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

		child = dict_attr_child_by_num(*parent, num);
		if (!child) {
			fr_strerror_printf("Unknown attribute '%i' in OID string \"%s\" for parent %s",
					   num, oid, (*parent)->name);
			return 0;	/* We parsed nothing */
		}

		/*
		 *	Record progress even if we error out.
		 *
		 *	Don't change this, you will break things.
		 */
		*parent = child;

		slen = fr_dict_attr_by_oid_legacy(dict, parent, attr, p);
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

/** Parse an OID component, resolving it to a defined attribute
 *
 * @note Will leave the sbuff pointing at the component the error occurred at
 *	 so that the caller can attempt to process the component in another way.
 *
 * @param[out] err		The parsing error that occurred.
 * @param[out] out		The deepest attribute we resolved.
 * @param[in] parent		Where to resolve relative attributes from.
 * @param[in] in		string to parse.
 * @return
 *	- >0 the number of bytes consumed.
 *	- <= 0 Parse error occurred here.
 */
ssize_t fr_dict_oid_component(fr_dict_attr_err_t *err,
			      fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
			      fr_sbuff_t *in)
{
	fr_sbuff_marker_t	start;
	uint32_t		num = 0;
	fr_sbuff_parse_error_t	sberr;
	fr_dict_attr_t const	*child;

	if (err) *err = FR_DICT_ATTR_OK;

	*out = NULL;

	fr_sbuff_marker(&start, in);

	switch (parent->type) {
	case FR_TYPE_STRUCTURAL:
		break;

	default:
		fr_strerror_printf("Attribute '%s' is not a structural type, "
				   "so cannot contain child attributes.  "
				   "Error at OID \"%.*s\"",
				   parent->name,
				   (int)fr_sbuff_remaining(in),
				   fr_sbuff_current(in));
		if (err) *err =FR_DICT_ATTR_NO_CHILDREN;
		return -fr_sbuff_marker_release_behind(&start);
	}

	fr_sbuff_out(&sberr, &num, in);
	switch (sberr) {
	/*
	 *	Lookup by number
	 */
	case FR_SBUFF_PARSE_OK:
		child = dict_attr_child_by_num(parent, num);
		if (!child) {
			fr_strerror_printf("Failed resolving child %u in context %s",
					   num, parent->name);
			if (err) *err = FR_DICT_ATTR_NOTFOUND;
			fr_sbuff_set(in, &start);		/* Reset to start of number */
			fr_sbuff_marker_release(&start);

			return 0;
		}
		break;

	/*
	 *	Lookup by name
	 */
	case FR_SBUFF_PARSE_ERROR_NOT_FOUND:
	{
		fr_dict_attr_err_t	our_err;
		ssize_t			slen;

		slen = fr_dict_attr_by_name_substr(&our_err, &child, parent, in);
		if (our_err != FR_DICT_ATTR_OK) {
			fr_strerror_printf("Failed resolving \"%.*s\" in context %s",
					   (int)fr_sbuff_remaining(in),
					   fr_sbuff_current(in),
					   parent->name);
			if (err) *err = our_err;
			return slen - fr_sbuff_marker_release_behind(&start);
		}
	}
		break;

	default:
		fr_strerror_printf("Invalid OID component \"%.*s\"",
				   (int)fr_sbuff_remaining(in), fr_sbuff_current(in));
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return -fr_sbuff_marker_release_behind(&start);
	}

	*out = child;

	return fr_sbuff_marker_release_behind(&start);
}

/** Resolve an attribute using an OID string
 *
 * @note Will leave the sbuff pointing at the component the error occurred at
 *	 so that the caller can attempt to process the component in another way.
 *
 * @param[out] err		The parsing error that occurred.
 * @param[out] out		The deepest attribute we resolved.
 * @param[in] parent		Where to resolve relative attributes from.
 * @param[in] in		string to parse.
 * @return
 *	- >0 the number of bytes consumed.
 *	- <= 0 Parse error occurred here.
 */
ssize_t fr_dict_attr_by_oid_substr(fr_dict_attr_err_t *err,
				   fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
				   fr_sbuff_t *in)
{
	fr_sbuff_marker_t	start;
	fr_dict_attr_t const	*our_parent = parent;

	fr_sbuff_marker(&start, in);

	/*
	 *	If the OID doesn't begin with '.' we
	 *	resolve it from the root.
	 */
	if (!fr_sbuff_next_if_char(in, '.')) parent = fr_dict_root(fr_dict_by_da(parent));

	*out = NULL;

	for (;;) {
		ssize_t			slen;
		fr_dict_attr_t const	*child;

		slen = fr_dict_oid_component(err, &child, our_parent, in);
		if ((slen <= 0) || !child) return slen - fr_sbuff_marker_release_behind(&start);

		our_parent = child;
		*out = child;

		if (!fr_sbuff_next_if_char(in, '.')) break;
	}

	return fr_sbuff_marker_release_behind(&start);
}

/** Resolve an attribute using an OID string
 *
 * @param[out] err		The parsing error that occurred.
 * @param[in] parent		Where to resolve relative attributes from.
 * @param[in] oid		string to parse.
 * @return
 *	- NULL if we couldn't resolve the attribute.
 *	- The resolved attribute.
 */
fr_dict_attr_t const *fr_dict_attr_by_oid(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *oid)
{
	fr_sbuff_t		sbuff = FR_SBUFF_IN(oid, strlen(oid));
	fr_dict_attr_t const	*da;

	if (fr_dict_attr_by_oid_substr(err, &da, parent, &sbuff) <= 0) return NULL;

	return da;
}

/** Return the root attribute of a dictionary
 *
 * @param dict			to return root for.
 * @return the root attribute of the dictionary.
 *
 * @hidecallergraph
 */
fr_dict_attr_t const *fr_dict_root(fr_dict_t const *dict)
{
	if (!dict) {
		if (!dict_gctx) return NULL;

		return dict_gctx->internal->root;	/* Remove me when dictionaries are done */
	}

	return dict->root;
}

bool fr_dict_is_read_only(fr_dict_t const *dict)
{
	return dict->read_only;
}

ssize_t dict_by_protocol_substr(fr_dict_attr_err_t *err,
				fr_dict_t **out, fr_sbuff_t *name, fr_dict_t const *dict_def)
{
	fr_dict_attr_t		root;

	fr_dict_t		*dict;
	size_t			len;
	char			buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1 + 1];	/* +1 \0 +1 for "too long" */
	fr_sbuff_t		our_name = FR_SBUFF_NO_ADVANCE(name);

	if (!dict_gctx || !name || !out) return 0;

	memset(&root, 0, sizeof(root));

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	len = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buffer, sizeof(buffer)),
					    &our_name, SIZE_MAX,
					    fr_dict_attr_allowed_chars);
	if (len == 0) {
		fr_strerror_printf("Zero length attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return 0;
	}
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return -(FR_DICT_ATTR_MAX_NAME_LEN);
	}

	/*
	 *	If what we stopped at wasn't a '.', then there
	 *	can't be a protocol name in this string.
	 */
	if (*(our_name.p) != '.') {
		memcpy(out, &dict_def, sizeof(*out));
		return 0;
	}

	root.name = buffer;
	dict = fr_hash_table_find_by_data(dict_gctx->protocol_by_name, &(fr_dict_t){ .root = &root });

	if (!dict) {
		fr_strerror_printf("Unknown protocol '%s'", root.name);
		*out = NULL;
		return 0;
	}
	*out = dict;

	return (size_t)fr_sbuff_set(name, &our_name);
}

/** Look up a protocol name embedded in another string
 *
 * @param[out] err		Parsing error.
 * @param[out] out		the resolve dictionary or NULL if the dictionary
 *				couldn't be resolved.
 * @param[in] name		string start.
 * @param[in] dict_def		The dictionary to return if no dictionary qualifier was found.
 * @return
 *	- 0 and *out != NULL.  Couldn't find a dictionary qualifier, so returned dict_def.
 *	- <= 0 on error and (*out == NULL) (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
ssize_t fr_dict_by_protocol_substr(fr_dict_attr_err_t *err, fr_dict_t const **out, fr_sbuff_t *name, fr_dict_t const *dict_def)
{
	ssize_t		slen;
	fr_dict_t	*dict = NULL;

	slen = dict_by_protocol_substr(err, &dict, name, dict_def);
	*out = dict;

	return slen;
}

/** Internal version of #fr_dict_by_protocol_name
 *
 * @note For internal use by the dictionary API only.
 *
 * @copybrief fr_dict_by_protocol_name
 */
fr_dict_t *dict_by_protocol_name(char const *name)
{
	if (!dict_gctx || !name) return NULL;

	return fr_hash_table_find_by_data(dict_gctx->protocol_by_name,
				      &(fr_dict_t){ .root = &(fr_dict_attr_t){ .name = name } });
}

/** Internal version of #fr_dict_by_protocol_num
 *
 * @note For internal use by the dictionary API only.
 *
 * @copybrief fr_dict_by_protocol_num
 */
fr_dict_t *dict_by_protocol_num(unsigned int num)
{
	if (!dict_gctx) return NULL;

	return fr_hash_table_find_by_data(dict_gctx->protocol_by_num,
				      &(fr_dict_t) { .root = &(fr_dict_attr_t){ .attr = num } });
}

/** Internal version of #fr_dict_by_da
 *
 * @note For internal use by the dictionary API only.
 *
 * @copybrief fr_dict_by_da
 */
fr_dict_t *dict_by_da(fr_dict_attr_t const *da)
{
#ifndef NDEBUG
	{
		fr_dict_attr_t const	*da_p = da;
		fr_dict_t const		*dict;

		dict = da->dict;
		while (da_p->parent) {
			da_p = da_p->parent;
			fr_cond_assert_msg(da_p->dict == dict, "Inconsistent dict membership.  "
					   "Expected %s, got %s",
					   !da_p->dict ? "(null)" : fr_dict_root(da_p->dict)->name,
					   !dict ? "(null)" : fr_dict_root(da_p->dict)->name);
			DA_VERIFY(da_p);
		}

		if (!da_p->flags.is_root) {
			fr_strerror_printf("%s: Attribute %s has not been inserted into a dictionary",
					   __FUNCTION__, da->name);
			return NULL;
		}
	}
#endif

	/*
	 *	Parent of the root attribute must
	 *	be the dictionary.
	 */
	return talloc_get_type_abort(da->dict, fr_dict_t);
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
 * @param[in] data	Dictionary to search in.
 * @param[in] uctx	Attribute to search for.
 * @return
 *	- 0 if attribute not found in dictionary.
 *	- 1 if attribute found in dictionary.
 */
static int _dict_attr_find_in_dicts(void *data, void *uctx)
{
	dict_attr_search_t	*search = uctx;
	fr_dict_t		*dict;
	fr_hash_table_t 	*namespace;

	if (!data) return 0;	/* We get called with NULL data */

	dict = talloc_get_type_abort(data, fr_dict_t);

	namespace = dict_attr_namespace(dict->root);
	if (!namespace) return 0;

	search->found_da = fr_hash_table_find_by_data(namespace, search->find);
	if (!search->found_da) return 0;

	search->found_dict = data;

	return 1;
}

/** Internal version of #fr_dict_by_attr_name
 *
 * @note For internal use by the dictionary API only.
 *
 * @copybrief fr_dict_by_attr_name
 */
fr_dict_t *dict_by_attr_name(fr_dict_attr_t const **found, char const *name)
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

	ret = fr_hash_table_walk(dict_gctx->protocol_by_name, _dict_attr_find_in_dicts, &search);
	if (ret == 0) return NULL;

	if (found) *found = search.found_da;

	return search.found_dict;
}

/** Lookup a protocol by its name
 *
 * @note For internal use by the dictionary API only.
 *
 * @param[in] name of the protocol to locate.
 * @return
 * 	- Attribute matching name.
 * 	- NULL if no matching protocol could be found.
 */
fr_dict_t const *fr_dict_by_protocol_name(char const *name)
{
	return dict_by_protocol_name(name);
}

/** Lookup a protocol by its number
 *
 * Returns the #fr_dict_t belonging to the protocol with the specified number
 * if any have been registered.
 *
 * @param[in] num to search for.
 * @return dictionary representing the protocol (if it exists).
 */
fr_dict_t const *fr_dict_by_protocol_num(unsigned int num)
{
	return dict_by_protocol_num(num);
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
fr_dict_t const *fr_dict_by_da(fr_dict_attr_t const *da)
{
	return dict_by_da(da);
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
fr_dict_t const *fr_dict_by_attr_name(fr_dict_attr_t const **found, char const *name)
{
	return dict_by_attr_name(found, name);
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

	dict = dict_by_da(da);

	return fr_hash_table_find_by_data(dict->vendors_by_num, &dv);
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

	found = fr_hash_table_find_by_data(dict->vendors_by_name, &(fr_dict_vendor_t) { .name = name });
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

	return fr_hash_table_find_by_data(dict->vendors_by_num, &(fr_dict_vendor_t) { .pen = vendor_pen });
}

/** Return vendor attribute for the specified dictionary and pen
 *
 * @param[in] vendor_root	of the vendor root attribute.  Could be 26 (for example) in RADIUS.
 * @param[in] vendor_pen	to find.
 * @return
 *	- NULL if vendor does not exist.
 *	- A fr_dict_attr_t representing the vendor in the dictionary hierarchy.
 */
fr_dict_attr_t const *fr_dict_vendor_da_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen)
{
	fr_dict_attr_t const *vendor;

	switch (vendor_root->type) {
	case FR_TYPE_VSA:	/* Vendor specific attribute */
		break;

	default:
		fr_strerror_printf("Wrong type for vendor root, expected '%s', got '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_VSA, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, vendor_root->type, "<INVALID>"));
		return NULL;
	}

	vendor = dict_attr_child_by_num(vendor_root, vendor_pen);
	if (!vendor) {
		fr_strerror_printf("Vendor %i not defined", vendor_pen);
		return NULL;
	}

	if (vendor->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Wrong type for vendor, expected '%s' got '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, vendor->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_VENDOR, "<INVALID>"));
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
 * @param[in] parent		containing the namespace to search in.
 * @param[in] name		string start.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
ssize_t fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
				    fr_dict_attr_t const *parent, fr_sbuff_t *name)
{
	fr_dict_attr_t const	*da;
	size_t			len;
	char			buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1 + 1];	/* +1 \0 +1 for "too long" */
	fr_sbuff_t		our_name = FR_SBUFF_NO_ADVANCE(name);
	fr_hash_table_t		*namespace;
	*out = NULL;

	len = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buffer, sizeof(buffer)),
					    &our_name, SIZE_MAX,
					    fr_dict_attr_allowed_chars);
	if (len == 0) {
		fr_strerror_printf("Zero length attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return 0;
	}
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return -(FR_DICT_ATTR_MAX_NAME_LEN);
	}

	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		return -1;
	}

	da = fr_hash_table_find_by_data(namespace, &(fr_dict_attr_t){ .name = buffer });
	if (!da) {
		if (err) *err = FR_DICT_ATTR_NOTFOUND;
		fr_strerror_printf("Attribute '%s' not found in namespace '%s'", buffer, parent->name);
		return 0;
	}

	*out = da;
	if (err) *err = FR_DICT_ATTR_OK;

	return fr_sbuff_set(name, &our_name);
}

/* Internal version of fr_dict_attr_by_name
 *
 */
fr_dict_attr_t *dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *name)
{
	fr_hash_table_t		*namespace;
	fr_dict_attr_t		*da;

	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		return NULL;
	}

	da = fr_hash_table_find_by_data(namespace, &(fr_dict_attr_t) { .name = name });
	if (!da) {
		if (err) *err = FR_DICT_ATTR_NOTFOUND;
		fr_strerror_printf("Attribute '%s' not found in namespace '%s'", name, parent->name);
		return NULL;
	}

	if (err) *err = FR_DICT_ATTR_OK;

	return da;
}

/** Locate a #fr_dict_attr_t by its name
 *
 * @param[out] err		Why the lookup failed. May be NULL.
 *				@see fr_dict_attr_err_t.
 * @param[in] parent		containing the namespace we're searching in.
 * @param[in] name		of the attribute to locate.
 * @return
 * 	- Attribute matching name.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *name)
{
	return dict_attr_by_name(err, parent, name);
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
					      fr_dict_t const *dict_def, fr_sbuff_t *name, bool fallback)
{
	fr_dict_t		*dict = NULL;
	fr_dict_t		*dict_iter = NULL;
	ssize_t			slen;
	fr_dict_attr_err_t	aerr = FR_DICT_ATTR_OK;
	bool			internal = false;
	fr_hash_iter_t  	iter;
	fr_sbuff_t		our_name = FR_SBUFF_NO_ADVANCE(name);
	*out = NULL;

	INTERNAL_IF_NULL(dict_def, -1);

	/*
	 *	Figure out if we should use the default dictionary
	 *	or if the string was qualified.
	 */
	slen = dict_by_protocol_substr(err, &dict, &our_name, dict_def);
	if (slen < 0) {
		return 0;

	/*
	 *	Nothing was parsed, use the default dictionary
	 */
	} else if (slen == 0) {
		memcpy(&dict, &dict_def, sizeof(dict));

	/*
	 *	Has dictionary qualifier, can't fallback
	 */
	} else if (slen > 0) {
		/*
		 *	Next thing SHOULD be a '.'
		 */
		if (!fr_sbuff_next_if_char(&our_name, '.')) {
			if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			return 0;
		}

		fallback = false;
	}

again:
	/*
	 *	We rely on the fact the sbuff is only
	 *	advanced on success.
	 */
	fr_dict_attr_by_name_substr(&aerr, out, fr_dict_root(dict), &our_name);
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
					if (dict_def != dict_gctx->internal) {
						dict = dict_gctx->internal;
						goto again;
					}
				}

				/*
				 *	Start the iteration over all dictionaries.
				 */
				dict_iter = fr_hash_table_iter_init(dict_gctx->protocol_by_num, &iter);
			} else {
			redo:
				dict_iter = fr_hash_table_iter_next(dict_gctx->protocol_by_num, &iter);
			}

			if (!dict_iter) goto fail;
			if (dict_iter == dict_def) goto redo;

			dict = dict_iter;
			goto again;
		}

	fail:
		if (err) *err = aerr;
		FR_SBUFF_ERROR_RETURN(&our_name);

	/*
	 *	Other error codes are the same
	 */
	default:
		if (err) *err = aerr;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	If we're returning a success code indication,
	 *	ensure we populated out
	 */
	if (!fr_cond_assert(*out)) {
		if (err) *err = FR_DICT_ATTR_EINVAL;
		return 0;
	}

	if (err) *err = FR_DICT_ATTR_OK;

	return (size_t)fr_sbuff_set(name, &our_name);
}

/** Locate a qualified #fr_dict_attr_t by its name and a dictionary qualifier
 *
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] name		Dictionary/Attribute name.
 * @param[in] fallback		If true, fallback to the internal dictionary.
 * @return an #fr_dict_attr_err_t value.
 */
fr_dict_attr_err_t fr_dict_attr_by_qualified_name(fr_dict_attr_t const **out, fr_dict_t const *dict_def,
						  char const *name, bool fallback)
{
	ssize_t			slen;
	fr_dict_attr_err_t	err = FR_DICT_ATTR_PARSE_ERROR;
	fr_sbuff_t		our_name;

	fr_sbuff_init(&our_name, name, strlen(name) + 1);

	slen = fr_dict_attr_by_qualified_name_substr(&err, out, dict_def, &our_name, fallback);
	if (slen <= 0) return err;

	if ((size_t)slen != fr_sbuff_len(&our_name)) {
		fr_strerror_printf("Trailing garbage after attr string \"%s\"", name);
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
	return fr_hash_table_find_by_data(dict_by_da(da)->attributes_combo,
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
	fr_dict_attr_t const **children;
	fr_dict_attr_t const *ref;

#ifndef NDEBUG
	/*
	 *	Asserts parent is not NULL in non-debug
	 *	builds, but parent is marked as nonnull
	 *	so we get complaints.
	 */
	DA_VERIFY(parent);
#endif

	ref = fr_dict_attr_ref(parent);
	if (ref) parent = ref;

	children = dict_attr_children(parent);
	if (!children) return NULL;

	/*
	 *	Child arrays may be trimmed back to save memory.
	 *	Check that so we don't SEGV.
	 */
	if ((child->attr & 0xff) > talloc_array_length(children)) return NULL;

	bin = children[child->attr & 0xff];
	for (;;) {
		if (!bin) return NULL;
		if (bin == child) return bin;
		bin = bin->next;
	}

	return NULL;
}

/** Internal version of fr_dict_attr_child_by_num
 *
 */
inline fr_dict_attr_t *dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *bin;
	fr_dict_attr_t const **children;
	fr_dict_attr_t const *ref;

	DA_VERIFY(parent);

	/*
	 *	Do any necessary dereferencing
	 */
	ref = fr_dict_attr_ref(parent);
	if (ref) parent = ref;

	children = dict_attr_children(parent);
	if (!children) return NULL;

	/*
	 *	Child arrays may be trimmed back to save memory.
	 *	Check that so we don't SEGV.
	 */
	if ((attr & 0xff) > talloc_array_length(children)) return NULL;

	bin = children[attr & 0xff];
	for (;;) {
		if (!bin) return NULL;
		if (bin->attr == attr) {
			fr_dict_attr_t *out;

			memcpy(&out, &bin, sizeof(bin));

			return out;
		}
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
fr_dict_attr_t const *fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
{
	return dict_attr_child_by_num(parent, attr);
}


/** Look up an attribute by name in the dictionary that contains the parent
 *
 */
ssize_t fr_dict_attr_child_by_name_substr(fr_dict_attr_err_t *err,
					  fr_dict_attr_t const **out, fr_dict_attr_t const *parent, fr_sbuff_t *name,
					  bool is_direct_decendent)
{
	ssize_t			slen;
	fr_dict_attr_t const	*ref;
	DA_VERIFY(parent);

	/*
	 *	Do any necessary dereferencing
	 */
	ref = fr_dict_attr_ref(parent);
	if (ref) parent = ref;

	if (!fr_dict_attr_has_ext(parent, FR_DICT_ATTR_EXT_CHILDREN)) {
		fr_strerror_printf("Parent (%s) is a %s, it cannot contain nested attributes",
				   parent->name,
				   fr_table_str_by_value(fr_value_box_type_table,
				   			 parent->type, "?Unknown?"));
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		return 0;

	} else if (!dict_attr_children(parent)) {
		fr_strerror_printf("Parent (%s) has no children", parent->name);
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		return 0;
	}

	slen = fr_dict_attr_by_name_substr(err, out, parent, name);
	if (slen <= 0) return slen;

	if (is_direct_decendent) {
		if ((*out)->parent != parent) {
		not_decendent:
			fr_strerror_printf("%s is not a descendent of parent (%s)", parent->name, (*out)->name);
			if (err) *err = FR_DICT_ATTR_NOT_DESCENDENT;
			*out = NULL;
			return 0;
		}
	} else if (!fr_dict_attr_common_parent(parent, *out, true)) goto not_decendent;

	return slen;
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
	fr_dict_attr_ext_enumv_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s attributes",
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		return NULL;
	}

	/*
	 *	No values associated with this attribute
	 */
	if (!ext->name_by_value) return NULL;

	/*
	 *	Could be NULL or an unknown attribute, in which case
	 *	we want to avoid the lookup gracefully...
	 */
	if (value->type != da->type) return NULL;

	return fr_hash_table_find_by_data(ext->name_by_value, &(fr_dict_enum_t){ .value = value });
}

/** Lookup the name of an enum value in a #fr_dict_attr_t
 *
 * @param[in] da		to search in.
 * @param[in] value		number to search for.
 * @return
 * 	- Name of value.
 * 	- NULL if no matching value could be found.
 */
char const *fr_dict_enum_name_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_enum_t	*dv;

	dv = fr_dict_enum_by_value(da, value);
	if (!dv) return NULL;

	return dv->name;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_enum_t *fr_dict_enum_by_name(fr_dict_attr_t const *da, char const *name, ssize_t len)
{
	fr_dict_attr_ext_enumv_t	*ext;

	if (!name) return NULL;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s attributes",
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		return NULL;
	}

	/*
	 *	No values associated with this attribute
	 */
	if (!ext->value_by_name) return NULL;

	if (len < 0) len = strlen(name);

	return fr_hash_table_find_by_data(ext->value_by_name, &(fr_dict_enum_t){ .name = name, .name_len = len});
}

int dict_dlopen(fr_dict_t *dict, char const *name)
{
	char *module_name;
	char *p, *q;

	if (!name) return 0;

	module_name = talloc_typed_asprintf(NULL, "libfreeradius-%s", name);
	for (p = module_name, q = p + talloc_array_length(p) - 1; p < q; p++) *p = tolower(*p);

	/*
	 *	Pass in dict as the uctx so that we can get at it in
	 *	any callbacks.
	 *
	 *	Not all dictionaries have validation functions.  It's
	 *	a soft error if they don't exist.
	 */
	dict->dl = dl_by_name(dict_gctx->dict_loader, module_name, dict, false);
	if (!dict->dl) {
		fr_strerror_printf_push("Failed loading dictionary validation library \"%s\"", module_name);
		talloc_free(module_name);
		return -1;
	}

	talloc_free(module_name);
	return 0;
}

static int _dict_free_autoref(void *data, UNUSED void *uctx)
{
	fr_dict_t *dict = talloc_get_type_abort(data, fr_dict_t);

	(void)fr_dict_free(&dict);

	return 0;
}

static int _dict_free(fr_dict_t *dict)
{
	if (!fr_cond_assert(!dict->in_protocol_by_name || fr_hash_table_delete(dict->gctx->protocol_by_name, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol hash \"%s\"", dict->root->name);
		return -1;
	}
	if (!fr_cond_assert(!dict->in_protocol_by_num || fr_hash_table_delete(dict->gctx->protocol_by_num, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol number_hash \"%s\"", dict->root->name);
		return -1;
	}

	if (dict->autoref &&
	    (fr_hash_table_walk(dict->autoref, _dict_free_autoref, NULL) < 0)) {
		return -1;
	}

	/*
	 *	Decrease the reference count on the validation
	 *	library we loaded.
	 */
	dl_free(dict->dl);

	/*
	 *	We don't necessarily control the order of freeing
	 *	children.
	 */
	if (dict == dict->gctx->internal) dict->gctx->internal = NULL;

	return 0;
}

/** Allocate a new dictionary
 *
 * @param[in] ctx to allocate dictionary in.
 * @return
 *	- NULL on memory allocation error.
 */
fr_dict_t *dict_alloc(TALLOC_CTX *ctx)
{
	fr_dict_t *dict;

	if (!dict_gctx) {
		fr_strerror_printf("Initialise global dictionary ctx with fr_dict_global_ctx_init()");
		return NULL;
	}

	dict = talloc_zero(ctx, fr_dict_t);
	if (!dict) {
		fr_strerror_printf("Failed allocating memory for dictionary");
	error:
		talloc_free(dict);
		return NULL;
	}
	dict->gctx = dict_gctx;	/* Record which global context this was allocated in */
	talloc_set_destructor(dict, _dict_free);

	/*
	 *	Pre-Allocate pool memory for rapid startup
	 *	As that's the working memory required during
	 *	dictionary initialisation.
	 */
	dict->pool = talloc_pool(dict, DICT_POOL_SIZE);
	if (!dict->pool) {
		fr_strerror_printf("Failed allocating talloc pool for dictionary");
		goto error;
	}

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 */
	dict->vendors_by_name = fr_hash_table_create(dict, dict_vendor_name_hash, dict_vendor_name_cmp, hash_pool_free);
	if (!dict->vendors_by_name) {
		fr_strerror_printf("Failed allocating \"vendors_by_name\" table");
		goto error;
	}
	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	dict->vendors_by_num = fr_hash_table_create(dict, dict_vendor_pen_hash, dict_vendor_pen_cmp, NULL);
	if (!dict->vendors_by_num) {
		fr_strerror_printf("Failed allocating \"vendors_by_num\" table");
		goto error;
	}

	/*
	 *	Inter-dictionary reference caching
	 */
	dict->autoref = fr_hash_table_create(dict, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
	if (!dict->autoref) {
		fr_strerror_printf("Failed allocating \"autoref\" table");
		goto error;
	}

	/*
	 *	Horrible hacks for combo-IP.
	 */
	dict->attributes_combo = fr_hash_table_create(dict, dict_attr_combo_hash, dict_attr_combo_cmp, hash_pool_free);
	if (!dict->attributes_combo) {
		fr_strerror_printf("Failed allocating \"attributes_combo\" table");
		goto error;
	}

	/*
	 *	Set default type size and length.
	 */
	dict->default_type_size = 1;
	dict->default_type_length = 1;

	return dict;
}

/** Manually increase the reference count for a dictionary
 *
 * This is useful if a previously loaded dictionary needs to
 * be bound to the lifetime of an additional object.
 *
 * @param[in] dict	to increase the reference count for.
 */
void fr_dict_reference(fr_dict_t *dict)
{
	talloc_increase_ref_count(dict);
}

/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] dict	to free.
 * @return how many references to the dictionary remain.
 */
int fr_dict_free(fr_dict_t **dict)
{
	int ret;

	if (!*dict) return 0;

	ret = talloc_decrease_ref_count(*dict);
	*dict = NULL;

	return ret;
}

/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] dict	to free.
 * @return how many references to the dictionary remain.
 */
int fr_dict_const_free(fr_dict_t const **dict)
{
	int ret;
	fr_dict_t *our_dict;

	if (!*dict) return 0;

	memcpy(&our_dict, dict, sizeof(our_dict));

	ret = talloc_decrease_ref_count(our_dict);
	*dict = NULL;

	return ret;
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
			fr_strerror_printf("Can't resolve Attribute '%s', dictionary not loaded", p->name);
			fr_strerror_printf_push("Check fr_dict_autoload_t struct has "
						"an entry to load the dictionary \"%s\" is located in, and that "
						"the fr_dict_autoload_t symbol name is correct", p->name);
			return -1;
		}

		da = fr_dict_attr_by_name(NULL, fr_dict_root(*p->dict), p->name);
		if (!da) {
			fr_strerror_printf("Attribute '%s' not found in \"%s\" dictionary", p->name,
					   *p->dict ? (*p->dict)->root->name : "internal");
			return -1;
		}

		if (da->type != p->type) {
			fr_strerror_printf("Attribute '%s' should be type %s, but defined as type %s", da->name,
					   fr_table_str_by_value(fr_value_box_type_table, p->type, "?Unknown?"),
					   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
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
		memcpy(&dict, &p->out, sizeof(dict)); /* const issues */
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
void fr_dl_dict_autofree(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	fr_dict_autofree(((fr_dict_autoload_t *)symbol));
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

/** Callback to automatically load validation routines for dictionaries.
 *
 * @param[in] dl	the library we just loaded
 * @param[in] symbol	pointer to a fr_dict_protocol_t table
 * @param[in] user_ctx	the global context which we don't need
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_onload_func(dl_t const *dl, void *symbol, UNUSED void *user_ctx)
{
	fr_dict_t *dict = talloc_get_type_abort(dl->uctx, fr_dict_t);
	fr_dict_protocol_t const *proto = symbol;


	/*
	 *	Set the protocol-specific callbacks.
	 */
	dict->proto = proto;

	/*
	 *	@todo - just use dict->proto->foo, once we get the
	 *	rest of the code cleaned up.
	 */
#undef COPY
#define COPY(_x) dict->_x = proto->_x
	COPY(default_type_size);
	COPY(default_type_length);
	COPY(subtype_table);
	COPY(subtype_table_len);
	COPY(attr_valid);

	return 0;
}

static int _dict_global_free(fr_dict_gctx_t *gctx)
{
	fr_hash_iter_t	iter;
	fr_dict_t	*dict;
	bool		still_loaded = false;

	if (gctx->internal) {
		fr_strerror_printf("Refusing to free dict gctx.  Internal dictionary is still loaded");
		still_loaded = true;
	}

	for (dict = fr_hash_table_iter_init(gctx->protocol_by_name, &iter);
	     dict;
	     dict = fr_hash_table_iter_next(gctx->protocol_by_name, &iter)) {
	     	(void)talloc_get_type_abort(dict, fr_dict_t);
		fr_strerror_printf_push("Refusing to free dict gctx.  %s protocol dictionary is still loaded",
					dict->root->name);
		still_loaded = true;
	}

	if (still_loaded) return -1;

	/*
	 *	Set this to NULL just in case the caller tries to use
	 *	dict_global_init() again.
	 */
	if (gctx == dict_gctx) dict_gctx = NULL;	/* In case the active context isn't this one */

	return 0;
}

/** Initialise the global protocol hashes
 *
 * @note Must be called before any other dictionary functions.
 *
 * @param[in] ctx	to allocate global resources in.
 * @param[in] dict_dir	the default location for the dictionaries.
 * @return
 *	- A pointer to the new global context on success.
 *	- NULL on failure.
 */
fr_dict_gctx_t const *fr_dict_global_ctx_init(TALLOC_CTX *ctx, char const *dict_dir)
{
	fr_dict_gctx_t *new_ctx;

	if (!dict_dir) {
		fr_strerror_printf("No dictionary location provided");
		return NULL;
	}

	new_ctx = talloc_zero(ctx, fr_dict_gctx_t);
	if (!new_ctx) {
	oom:
		fr_strerror_printf("Out of Memory");
		talloc_free(new_ctx);
		return NULL;
	}

	new_ctx->protocol_by_name = fr_hash_table_create(new_ctx, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
	if (!new_ctx->protocol_by_name) {
		fr_strerror_printf("Failed initializing protocol_by_name hash");
	error:
		talloc_free(new_ctx);
		return NULL;
	}

	new_ctx->protocol_by_num = fr_hash_table_create(new_ctx, dict_protocol_num_hash, dict_protocol_num_cmp, NULL);
	if (!new_ctx->protocol_by_num) {
		fr_strerror_printf("Failed initializing protocol_by_num hash");
		goto error;
	}

	new_ctx->dict_dir_default = talloc_strdup(new_ctx, dict_dir);
	if (!new_ctx->dict_dir_default) goto oom;

	new_ctx->dict_loader = dl_loader_init(new_ctx, NULL, false, false);
	if (!new_ctx->dict_loader) goto error;

	if (dl_symbol_init_cb_register(new_ctx->dict_loader, 0, "dict_protocol",
				       dict_onload_func, NULL) < 0) goto error;

	if (!dict_gctx) dict_gctx = new_ctx;	/* Set as the default */
	talloc_set_destructor(dict_gctx, _dict_global_free);

	return new_ctx;
}

/** Set a new, active, global dictionary context
 *
 * @param[in] gctx	To set.
 */
void fr_dict_global_ctx_set(fr_dict_gctx_t const *gctx)
{
	memcpy(&dict_gctx, &gctx, sizeof(dict_gctx));
}

/** Explicitly free all data associated with a global dictionary context
 *
 * @note You should *NOT* ignore the return code of this function.
 *       You should use perror() or PERROR() to print out the reason
 *       why freeing failed.
 *
 * @param[in] gctx	To set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_global_ctx_free(fr_dict_gctx_t const *gctx)
{
	return talloc_const_free(gctx);
}

/** Allow the default dict dir to be changed after initialisation
 *
 * @param[in] dict_dir	New default dict dir to use.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_global_ctx_dir_set(char const *dict_dir)
{
	if (!dict_gctx) return -1;

	talloc_free(dict_gctx->dict_dir_default);		/* Free previous value */
	dict_gctx->dict_dir_default = talloc_strdup(dict_gctx, dict_dir);
	if (!dict_gctx->dict_dir_default) return -1;

	return 0;
}

char const *fr_dict_global_dir(void)
{
	return dict_gctx->dict_dir_default;
}

/** Mark all dictionaries and the global dictionary ctx as read only
 *
 * Any attempts to add new attributes will now fail.
 */
void fr_dict_global_read_only(void)
{
	fr_hash_iter_t	iter;
	fr_dict_t	*dict;

	if (!dict_gctx) return;

	/*
	 *	Set everything to read only
	 */
	for (dict = fr_hash_table_iter_init(dict_gctx->protocol_by_num, &iter);
	     dict;
	     dict = fr_hash_table_iter_next(dict_gctx->protocol_by_num, &iter)) {
		talloc_set_memlimit(dict, talloc_get_size(dict));
		dict->read_only = true;
	}

	talloc_set_memlimit(dict_gctx, talloc_get_size(dict_gctx));
	dict_gctx->read_only = true;
}

/** Coerce to non-const
 *
 */
fr_dict_t *fr_dict_unconst(fr_dict_t const *dict)
{
	fr_dict_t *mutable;

	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}

	memcpy(&mutable, &dict, sizeof(dict));
	return mutable;
}

/** Coerce to non-const
 *
 */
fr_dict_attr_t *fr_dict_attr_unconst(fr_dict_attr_t const *da)
{
	fr_dict_attr_t *mutable;
	fr_dict_t *dict;

	dict = dict_by_da(da);
	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}

	memcpy(&mutable, &da, sizeof(da));
	return mutable;
}

fr_dict_t const *fr_dict_internal(void)
{
	if (!dict_gctx) return NULL;

	return dict_gctx->internal;
}

/*
 *	Check for the allowed characters.
 */
ssize_t fr_dict_valid_name(char const *name, ssize_t len)
{
	char const *p = name, *end;
	bool unknown = false;

	if (len < 0) len = strlen(name);

	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name is too long");
		return -1;
	}

	end = p + len;

	/*
	 *	Unknown attributes can have '.' in their name.
	 */
	if ((len > 5) && (memcmp(name, "Attr-", 5) == 0)) unknown = true;

	while (p < end) {
		if ((*p == '.') && unknown) p++;

		if (!fr_dict_attr_allowed_chars[(uint8_t)*p]) {
			fr_strerror_printf("Invalid character '%pV' in attribute name \"%pV\"",
					   fr_box_strvalue_len(p, 1), fr_box_strvalue_len(name, len));

			return -(p - name);
		}
		p++;
	}

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

	if (!da) fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t pointer was NULL", file, line);

	(void) talloc_get_type_abort_const(da, fr_dict_attr_t);

	if ((!da->flags.is_root) && (da->depth == 0)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
				     "Is not root, but depth is 0",
				     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr);
	}

	if (da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
				     "Indicated depth (%u) greater than TLV stack depth (%u)",
				     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr,
				     da->depth, FR_DICT_MAX_TLV_STACK);
	}

	for (da_p = da; da_p; da_p = da_p->next) {
		(void) talloc_get_type_abort_const(da_p, fr_dict_attr_t);
	}

	for (i = da->depth, da_p = da; (i >= 0) && da; i--, da_p = da_p->parent) {
		if (i != (int)da_p->depth) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
					     "Depth out of sequence, expected %i, got %u",
					     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr, i, da_p->depth);
		}

	}

	if ((i + 1) < 0) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t top of hierarchy was not at depth 0",
				     file, line);
	}

	if (da->parent && (da->parent->type == FR_TYPE_VENDOR) && !fr_dict_attr_has_ext(da, FR_DICT_ATTR_EXT_VENDOR)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: VSA missing 'vendor' extension", file, line);
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
		if (da->type != FR_TYPE_GROUP) {
			fr_assert_msg(fr_dict_attr_has_ext(da, FR_DICT_ATTR_EXT_CHILDREN),
				      "CONSISTENCY CHECK FAILED %s[%u]: %s missing 'children' extension",
				      file, line,
				      fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		}
		break;

	default:
		break;
	}
}

/** Iterate over children of a DA.
 *
 *  @param[in] parent	the parent da to iterate over
 *  @param[in,out] prev	pointer to NULL to start, otherwise pointer to the previously returned child
 *  @return
 *     - NULL for end of iteration
 *     - !NULL for a valid child.  This child MUST be passed to the next loop.
 */
fr_dict_attr_t const *fr_dict_attr_iterate_children(fr_dict_attr_t const *parent, fr_dict_attr_t const **prev)
{
	fr_dict_attr_t const * const *bin;
	fr_dict_attr_t const **children;
	fr_dict_attr_t const *ref;
	size_t len, i, start;

	if (!parent || !prev) return NULL;

	ref = fr_dict_attr_ref(parent);
	if (ref) parent = ref;

	children = dict_attr_children(parent);
	if (!children) return NULL;

	if (!*prev) {
		start = 0;

	} else if ((*prev)->next) {
		/*
		 *	There are more children in this bin, return
		 *	the next one.
		 */
		return (*prev)->next;

	} else {
		/*
		 *	Figure out which bin we were in.  If it was
		 *	the last one, we're done.
		 */
		start = (*prev)->attr & 0xff;
		if (start == 255) return NULL;

		/*
		 *	Start at the next bin.
		 */
		start++;
	}

	/*
	 *	Look for a non-empty bin, and return the first child
	 *	from there.
	 */
	len = talloc_array_length(children);
	for (i = start; i < len; i++) {
		bin = &children[i & 0xff];

		if (*bin) return *bin;
	}

	return NULL;
}

/** Call the specified callback for da and then for all its children
 *
 */
static int dict_walk(fr_dict_attr_t const *da, fr_dict_walk_t callback, void *uctx)
{
	size_t i, len;
	fr_dict_attr_t const **children;

	children = dict_attr_children(da);

	if (fr_dict_attr_ref(da) || !children) return callback(da, uctx);

	len = talloc_array_length(children);
	for (i = 0; i < len; i++) {
		int ret;
		fr_dict_attr_t const *bin;

		if (!children[i]) continue;

		for (bin = children[i]; bin; bin = bin->next) {
			ret = dict_walk(bin, callback, uctx);
			if (ret < 0) return ret;
		}
	}

	return 0;
}

int fr_dict_walk(fr_dict_attr_t const *da, fr_dict_walk_t callback, void *uctx)
{
	return dict_walk(da, callback, uctx);
}
