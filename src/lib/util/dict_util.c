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
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define _DICT_PRIVATE 1

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_ext_priv.h>
#include <freeradius-devel/util/dict_fixup_priv.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/syserror.h>

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

fr_dict_gctx_t *dict_gctx = NULL;	//!< Top level structure containing global dictionary state.

#define DICT_ATTR_ALLOWED_CHARS \
	['-'] = true, ['/'] = true, ['_'] = true, \
	['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true, \
	['5'] = true, ['6'] = true, ['7'] = true, ['8'] = true, ['9'] = true, \
	['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true, ['E'] = true, \
	['F'] = true, ['G'] = true, ['H'] = true, ['I'] = true, ['J'] = true, \
	['K'] = true, ['L'] = true, ['M'] = true, ['N'] = true, ['O'] = true, \
	['P'] = true, ['Q'] = true, ['R'] = true, ['S'] = true, ['T'] = true, \
	['U'] = true, ['V'] = true, ['W'] = true, ['X'] = true, ['Y'] = true, \
	['Z'] = true, \
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true, \
	['f'] = true, ['g'] = true, ['h'] = true, ['i'] = true, ['j'] = true, \
	['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true, ['o'] = true, \
	['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true, \
	['u'] = true, ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true, \
	['z'] = true

/** Characters allowed in a single dictionary attribute name
 *
 */
bool const fr_dict_attr_allowed_chars[UINT8_MAX + 1] = {
	DICT_ATTR_ALLOWED_CHARS
};

/** Characters allowed in a nested dictionary attribute name
 *
 */
bool const fr_dict_attr_nested_allowed_chars[UINT8_MAX + 1] = {
	DICT_ATTR_ALLOWED_CHARS,
	[ '.' ] = true
};

/** Characters allowed in enumeration value names
 *
 */
bool const fr_dict_enum_allowed_chars[UINT8_MAX + 1] = {
	['+'] = true, ['-'] = true, ['.'] = true, ['/'] = true, ['_'] = true,
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

/** Default protocol rules set for every dictionary
 *
 * This is usually overriden by the public symbol from the protocol library
 * associated with the dictionary
 * e.g. libfreeradius-dhcpv6.so -> libfreeradius_dhcpv6_dict_protocol.
 */
static fr_dict_protocol_t dict_proto_default = {
	.name = "default",
	.default_type_size = 2,
	.default_type_length = 2,
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

		/* coverity[overflow_const] */
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
static int8_t dict_protocol_name_cmp(void const *one, void const *two)
{
	fr_dict_t const *a = one;
	fr_dict_t const *b = two;
	int ret;

	ret = strcasecmp(a->root->name, b->root->name);
	return CMP(ret, 0);
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
static int8_t dict_protocol_num_cmp(void const *one, void const *two)
{
	fr_dict_t const *a = one;
	fr_dict_t const *b = two;

	return CMP(a->root->attr, b->root->attr);
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
static int8_t dict_attr_name_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one, *b = two;
	int ret;

	ret = strcasecmp(a->name, b->name);
	return CMP(ret, 0);
}

/** Compare two attributes by total order.
 *
 *  This function is safe / ordered even when the attributes are in
 *  different dictionaries.  This allows it to work for local
 *  variables, as those are in a different dictionary from the
 *  protocol ones.
 *
 *  This function orders parents first, then their children.
 */
int8_t fr_dict_attr_ordered_cmp(fr_dict_attr_t const *a, fr_dict_attr_t const *b)
{
	int8_t ret;

	/*
	 *	Order by parent first.  If the parents are different,
	 *	we order by parent numbers.
	 *
	 *	If the attributes share the same parent at some point,
	 *	then the deeper child is sorted later.
	 */
	if (a->depth < b->depth) {
		ret = fr_dict_attr_ordered_cmp(a, b->parent);
		if (ret != 0) return ret;

		return -1;	/* order a before b */
	}

	if (a->depth > b->depth) {
		ret = fr_dict_attr_ordered_cmp(a->parent, b);
		if (ret != 0) return ret;

		return +1;	/* order b before a */
	}

	/*
	 *	We're at the root (e.g. "RADIUS").  Compare by
	 *	protocol number.
	 *
	 *	Or, the parents are the same.  We can then order by
	 *	our (i.e. child) attribute number.
	 */
	if ((a->depth == 0) || (a->parent == b->parent)) {
		/*
		 *	Order known attributes before unknown / raw ones.
		 */
		ret = (b->flags.is_unknown | b->flags.is_raw) - (a->flags.is_unknown | a->flags.is_raw);
		if (ret != 0) return 0;

		return CMP(a->attr, b->attr);
	}

	/*
	 *	The parents are different, we don't need to order by
	 *	our attribute number.  Instead, we order by the
	 *	parent.
	 *
	 *	Note that at this point, the call below will never
	 *	return 0, because the parents are different.
	 */
	return fr_dict_attr_ordered_cmp(a->parent, b->parent);
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
static int8_t dict_vendor_name_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;
	int ret;

	ret = strcasecmp(a->name, b->name);
	return CMP(ret, 0);
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
static int8_t dict_vendor_pen_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return CMP(a->pen, b->pen);
}

/** Hash a enumeration name
 *
 */
static uint32_t dict_enum_name_hash(void const *data)
{
	fr_dict_enum_value_t const *enumv = data;

	return dict_hash_name((void const *)enumv->name, enumv->name_len);
}

/** Compare two dictionary attribute enum values
 *
 */
static int8_t dict_enum_name_cmp(void const *one, void const *two)
{
	fr_dict_enum_value_t const *a = one;
	fr_dict_enum_value_t const *b = two;
	size_t len;
	int ret;

	if (a->name_len >= b->name_len) {
		len = a->name_len;
	} else {
		len = b->name_len;
	}

	ret = strncasecmp(a->name, b->name, len);
	return CMP(ret, 0);
}

/** Hash a dictionary enum value
 *
 */
static uint32_t dict_enum_value_hash(void const *data)
{
	fr_dict_enum_value_t const *enumv = data;

	return fr_value_box_hash(enumv->value);
}

/** Compare two dictionary enum values
 *
 */
static int8_t dict_enum_value_cmp(void const *one, void const *two)
{
	fr_dict_enum_value_t const *a = one;
	fr_dict_enum_value_t const *b = two;
	int ret;

	ret = fr_value_box_cmp(a->value, b->value); /* not yet int8_t! */
	return CMP(ret, 0);
}

/** Resolve an alias attribute to the concrete attribute it points to
 *
 * @param[out] err	where to write the error (if any).
 * @param[in] da	to resolve.
 * @return
 *	- NULL on error.
 *	- The concrete attribute on success.
 */
static inline fr_dict_attr_t const *dict_attr_alias(fr_dict_attr_err_t *err, fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *ref;

	if (!da->flags.is_alias) return da;

	ref = fr_dict_attr_ref(da);
	if (unlikely(!ref)) {
		fr_strerror_printf("ALIAS attribute '%s' missing reference", da->name);
		if (err) *err = FR_DICT_ATTR_INTERNAL_ERROR;
		return NULL;
	} else {
		if (err) *err = FR_DICT_ATTR_OK;
	}

	return ref;
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


		(void) fr_sbuff_in_sprintf(&unknown_name, "%u", da->attr);

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
	 *
	 *	If the attribute already has extensions
	 *	then we don't want to leak the old
	 *	namespace hash table.
	 */
	if (!ext->namespace) {
		ext->namespace = fr_hash_table_talloc_alloc(*da_p, fr_dict_attr_t,
							    dict_attr_name_hash, dict_attr_name_cmp, NULL);
		if (!ext->namespace) {
			fr_strerror_printf("Failed allocating \"namespace\" table");
			return -1;
		}
	}

	return 0;
}

/** Initialise type specific fields within the dictionary attribute
 *
 * Call when the type of the attribute is known.
 *
 * @param[in,out] da_p	to set the type for.
 * @param[in] type	to set.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
int dict_attr_type_init(fr_dict_attr_t **da_p, fr_type_t type)
{
	if (unlikely(((*da_p)->type != FR_TYPE_NULL) &&
		     ((*da_p)->type != type))) {
		fr_strerror_printf("Cannot set data type to '%s' - it is already set to '%s'",
				   fr_type_to_str(type), fr_type_to_str((*da_p)->type));
		return -1;
	}

	if (unlikely((*da_p)->state.finalised == true)) {
		fr_strerror_const("Can't perform type initialisation on finalised attribute");
		return -1;
	}

	/*
	 *	Structural types can have children
	 *	so add the extension for them.
	 */
	switch (type) {
	case FR_TYPE_STRUCTURAL:
		/*
		 *	Groups don't have children or namespaces.  But
		 *	they always have refs.  Either to the root of
		 *	the current dictionary, or to another dictionary,
		 *	via its top-level TLV.
		 *
		 *	Note that when multiple TLVs have the same
		 *	children, the dictionary has to use "clone="
		 *	instead of "ref=".  That's because the
		 *	children of the TLVs all require the correct
		 *	parentage.  Perhaps that can be changed when
		 *	the encoders / decoders are updated.  It would be good to just reference the DAs instead of cloning an entire subtree.
		 */
		if ((type == FR_TYPE_GROUP) && !fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_REF)) {
			if (dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_REF) == NULL) return -1;
			break;
		}

		if (dict_attr_children_init(da_p) < 0) return -1;
		if (dict_attr_namespace_init(da_p) < 0) return -1;	/* Needed for all TLV style attributes */

		(*da_p)->last_child_attr = (1 << 24);	/* High enough not to conflict with protocol numbers */
		break;

	/*
	 *	Leaf types
	 */
	default:
		if (dict_attr_enumv_init(da_p) < 0) return -1;
		break;
	}

	(*da_p)->flags.is_known_width |= fr_type_fixed_size[type];

	/*
	 *	Set default type-based flags
	 */
	switch (type) {
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		(*da_p)->flags.length = 4;
		(*da_p)->flags.flag_time_res = FR_TIME_RES_SEC;
		break;


	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		(*da_p)->flags.is_known_width = ((*da_p)->flags.length != 0);
		break;

	default:
		break;
	}

	(*da_p)->type = type;

	return 0;
}

/** Initialise fields which depend on a parent attribute
 *
 * @param[in,out] da_p	to initialise.
 * @param[in] parent	of the attribute.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
int dict_attr_parent_init(fr_dict_attr_t **da_p, fr_dict_attr_t const *parent)
{
	fr_dict_attr_t		  *da = *da_p;
	fr_dict_t const		  *dict = parent->dict;
	fr_dict_attr_ext_vendor_t *ext;

	if (unlikely((*da_p)->type == FR_TYPE_NULL)) {
		fr_strerror_const("Attribute type must be set before initialising parent.  Use dict_attr_type_init() first");
		return -1;
	}

	if (unlikely(da->parent != NULL)) {
		fr_strerror_printf("Attempting to set parent for '%s' to '%s', but parent already set to '%s'",
				   da->name, parent->name, da->parent->name);
		return -1;
	}

	if (unlikely((*da_p)->state.finalised == true)) {
		fr_strerror_printf("Attempting to set parent for '%s' to '%s', but attribute already finalised",
				   da->name, parent->name);
		return -1;
	}

	da->parent = parent;
	da->dict = parent->dict;
	da->depth = parent->depth + 1;
	da->flags.internal |= parent->flags.internal;

	/*
	 *	Point to the vendor definition.  Since ~90% of
	 *	attributes are VSAs, caching this pointer will help.
	 */
	if (da->type == FR_TYPE_VENDOR) {
		da->flags.type_size = dict->root->flags.type_size;
		da->flags.length = dict->root->flags.type_size;

		if ((dict->root->attr == FR_DICT_PROTO_RADIUS) && (da->depth == 2)) {
			fr_dict_vendor_t const *dv;

			dv = fr_dict_vendor_by_num(dict, da->attr);
			if (dv) {
				da->flags.type_size = dv->type;
				da->flags.length = dv->length;
			}
		}

	} else if (da->type == FR_TYPE_TLV) {
		da->flags.type_size = dict->root->flags.type_size;
		da->flags.length = dict->root->flags.type_size;
	}

	if (parent->type == FR_TYPE_VENDOR) {
		ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_VENDOR);
		if (unlikely(!ext)) return -1;

		ext->vendor = parent;

	} else {
		ext = dict_attr_ext_copy(da_p, parent, FR_DICT_ATTR_EXT_VENDOR); /* Noop if no vendor extension */
	}

	da = *da_p;

	if (!ext || ((da->type != FR_TYPE_TLV) && (da->type != FR_TYPE_VENDOR))) return 0;

	da->flags.type_size = ext->vendor->flags.type_size;
	da->flags.length = ext->vendor->flags.type_size;

	return 0;
}

/** Set the attribute number (if any)
 *
 * @param[in] da		to set the attribute number for.
 * @param[in] num		to set.
 */
int dict_attr_num_init(fr_dict_attr_t *da, unsigned int num)
{
	if (da->state.attr_set) {
		fr_strerror_const("Attribute number already set");
		return -1;
	}
	da->attr = num;
	da->state.attr_set = true;

	return 0;
}

/** Set the attribute number (if any)
 *
 * @note Must have a parent set.
 *
 * @param[in] da		to set the attribute number for.
 */
int dict_attr_num_init_name_only(fr_dict_attr_t *da)
{
	if (!da->parent) {
		fr_strerror_const("Attribute must have parent set before automatically setting attribute number");
		return -1;
	}
	return dict_attr_num_init(da, ++fr_dict_attr_unconst(da->parent)->last_child_attr);
}

/** Set where the dictionary attribute was defined
 *
 */
void dict_attr_location_init(fr_dict_attr_t *da, char const *filename, int line)
{
	da->filename = filename;
	da->line = line;
}

/** Set remaining fields in a dictionary attribute before insertion
 *
 * @param[in] da_p		to finalise.
 * @param[in] name		of the attribute.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
int dict_attr_finalise(fr_dict_attr_t **da_p, char const *name)
{
	fr_dict_attr_t		*da;

	/*
	*	Finalising the attribute allocates its
	*	automatic number if its a name only attribute.
	*/
	da = *da_p;

	/*
	 *	Initialize the length field automatically if it's not been set already
	 */
	if (!da->flags.length && fr_type_is_leaf(da->type) && !fr_type_is_variable_size(da->type)) {
		fr_value_box_t box;

		fr_value_box_init(&box, da->type, NULL, false);
		da->flags.length = fr_value_box_network_length(&box);
	}

	switch(da->type) {
	case FR_TYPE_STRUCT:
		da->flags.is_known_width |= da->flags.array;
		break;

	case FR_TYPE_GROUP:
	{
		fr_dict_attr_ext_ref_t	*ext;
		/*
		*	If it's a group attribute, the default
		*	reference goes to the root of the
		*	dictionary as that's where the default
		*	name/numberspace is.
		*
		*	This may be updated by the caller.
		*/
		ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
		if (unlikely(ext == NULL)) {
			fr_strerror_const("Missing ref extension");
			return -1;
		}

		/*
		 *	For groups, if a ref wasn't provided then
		 *	set it to the dictionary root.
		 */
		if ((ext->type == FR_DICT_ATTR_REF_NONE) &&
		    (unlikely(dict_attr_ref_set(da, fr_dict_root(da->dict), FR_DICT_ATTR_REF_ALIAS) < 0))) {
			return -1;
		}
	}
		break;

	default:
		break;
	}

	/*
	 *	Name is a separate talloc chunk.  We allocate
	 *	it last because we cache the pointer value.
	 */
	if (dict_attr_name_set(da_p, name) < 0) return -1;

	DA_VERIFY(*da_p);

	(*da_p)->state.finalised = true;

	return 0;
}

static inline CC_HINT(always_inline)
int dict_attr_init_common(char const *filename, int line,
			  fr_dict_attr_t **da_p,
			  fr_dict_attr_t const *parent,
			  fr_type_t type, dict_attr_args_t const *args)
{
	dict_attr_location_init((*da_p), filename, line);

	if (unlikely(dict_attr_type_init(da_p, type) < 0)) return -1;

	if (args->flags) (*da_p)->flags = *args->flags;

	if (parent && (dict_attr_parent_init(da_p, parent) < 0)) return -1;

	if (args->ref && (dict_attr_ref_aset(da_p, args->ref, FR_DICT_ATTR_REF_ALIAS) < 0)) return -1;

	/*
	 *	Everything should be created correctly.
	 */
	if (!(*da_p)->flags.internal && !(*da_p)->flags.is_alias &&
	    parent && ((parent->type == FR_TYPE_TLV) || (parent->type ==FR_TYPE_VENDOR))) {
		if (!parent->flags.type_size) {
			fr_strerror_printf("Parent %s has zero type_size", parent->name);
			return -1;
		}

		if ((uint64_t) (*da_p)->attr >= ((uint64_t) 1 << (8 * parent->flags.type_size))) {
			fr_strerror_printf("Child of parent %s has invalid attribute number %u for type_size %u",
					   parent->name, (*da_p)->attr, parent->flags.type_size);
			return -1;
		}
	}

	return 0;
}

/** Initialise fields in a dictionary attribute structure
 *
 * This function is a wrapper around the other initialisation functions.
 *
 * The reason for the separation, is that sometimes we're initialising a dictionary attribute
 * by parsing an actual dictionary file, and other times we're copying attribute, or initialising
 * them programatically.
 *
 * This function should only be used for the second case, where we have a complet attribute
 * definition already.
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] filename		file.
 * @param[in] line		number.
 * @param[in] da_p		to initialise.
 * @param[in] parent		of the attribute, if none, this attribute will
 *				be initialised as a dictionary root.
 * @param[in] name		of attribute.  Pass NULL for auto-generated name.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] args		optional initialisation arguments.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int _dict_attr_init(char const *filename, int line,
		    fr_dict_attr_t **da_p,
		    fr_dict_attr_t const *parent,
		    char const *name, unsigned int attr,
		    fr_type_t type, dict_attr_args_t const *args)
{
	/*
	 *	We initialize the number first, as doing that doesn't have any other side effects.
	 */
	if (unlikely(dict_attr_num_init(*da_p, attr) < 0)) return -1;

	/*
	 *	This function then checks the number, for things like VSAs.
	 */
	if (unlikely(dict_attr_init_common(filename, line, da_p, parent, type, args) < 0)) return -1;

	if (unlikely(dict_attr_finalise(da_p, name) < 0)) return -1;

	return 0;
}

/** Initialise fields in a dictionary attribute structure
 *
 * This function is a wrapper around the other initialisation functions.
 *
 * The reason for the separation, is that sometimes we're initialising a dictionary attribute
 * by parsing an actual dictionary file, and other times we're copying attribute, or initialising
 * them programatically.
 *
 * This function should only be used for the second case, where we have a complet attribute
 * definition already.
 *
 * @note This function can only be used _before_ the attribute is inserted into the dictionary.
 *
 * @param[in] filename		file.
 * @param[in] line		number.
 * @param[in] da_p		to initialise.
 * @param[in] parent		of the attribute, if none, this attribute will
 *				be initialised as a dictionary root.
 * @param[in] name		of attribute.  Pass NULL for auto-generated name.
 *				automatically generated.
 * @param[in] type		of the attribute.
 * @param[in] args		optional initialisation arguments.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int _dict_attr_init_name_only(char const *filename, int line,
			 fr_dict_attr_t **da_p,
			 fr_dict_attr_t const *parent,
			 char const *name,
			 fr_type_t type, dict_attr_args_t const *args)
{
	if (unlikely(dict_attr_init_common(filename, line, da_p, parent, type, args) < 0)) return -1;

	/*
	 *	Automatically generate the attribute number when the attribut is added.
	 */
	(*da_p)->flags.name_only = true;

	if (unlikely(dict_attr_finalise(da_p, name) < 0)) return -1;

	return 0;
}

static int _dict_attr_free(fr_dict_attr_t *da)
{
	fr_dict_attr_ext_enumv_t	*ext;

#if 0
#ifdef WITH_VERIFY_PTR
	/*
	 *	Check that any attribute we reference is still valid
	 *	when we're being freed.
	 */
	fr_dict_attr_t const *ref = fr_dict_attr_ref(da);

	if (ref) (void)talloc_get_type_abort_const(ref, fr_dict_attr_t);
#endif
#endif

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (ext) talloc_free(ext->value_by_name);		/* Ensure this is freed before the enumvs */

	return 0;
}

/** Allocate a partially completed attribute
 *
 * This is useful in some instances where we need to pre-allocate the attribute
 * for talloc hierarchy reasons, but want to finish initialising it
 * with #dict_attr_init later.
 *
 * @param[in] ctx		to allocate attribute in.
 * @param[in] proto		protocol specific extensions.
 * @return
 *	- A new, partially completed, fr_dict_attr_t on success.
 *	- NULL on failure (memory allocation error).
 */
fr_dict_attr_t *dict_attr_alloc_null(TALLOC_CTX *ctx, fr_dict_protocol_t const *proto)
{
	fr_dict_attr_t *da;

	/*
	 *	Do not use talloc zero, the caller
	 *	always initialises memory allocated
	 *	here.
	 */
	da = talloc_zero(ctx, fr_dict_attr_t);
	if (unlikely(!da)) return NULL;

	/*
	 *	Allocate room for the protocol specific flags
	 */
	if (proto->attr.flags.len > 0) {
		if (unlikely(dict_attr_ext_alloc_size(&da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC,
						      proto->attr.flags.len) == NULL)) {
			talloc_free(da);
			return NULL;
		}
	}
	talloc_set_destructor(da, _dict_attr_free);

	return da;
}

/** Allocate a dictionary root attribute on the heap
 *
 * @param[in] filename		file.
 * @param[in] line		number.
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] dict		the attribute will be used in.
 * @param[in] name		of the attribute.  If NULL an OID string
 *				will be created and set as the name.
 * @param[in] proto_number		number.  This should be
 * @param[in] args		optional initialisation arguments.
 * @return
 *	- A new fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t *_dict_attr_alloc_root(char const *filename, int line,
				      TALLOC_CTX *ctx,
				      fr_dict_t const *dict,
				      char const *name, int proto_number,
				      dict_attr_args_t const *args)
{
	fr_dict_attr_t	*n;

	n = dict_attr_alloc_null(ctx, dict->proto);
	if (unlikely(!n)) return NULL;

	if (_dict_attr_init(filename, line, &n, NULL, name, proto_number, FR_TYPE_TLV, args) < 0) {
		talloc_free(n);
		return NULL;
	}

	return n;
}

/** Allocate a dictionary attribute on the heap
 *
 * @param[in] filename		file.
 * @param[in] line		number.
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] parent		of the attribute.
 * @param[in] name		of the attribute.  If NULL an OID string
 *				will be created and set as the name.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] args		optional initialisation arguments.
 * @return
 *	- A new fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t *_dict_attr_alloc(char const *filename, int line,
				 TALLOC_CTX *ctx,
				 fr_dict_attr_t const *parent,
				 char const *name, int attr,
				 fr_type_t type, dict_attr_args_t const *args)
{
	fr_dict_attr_t	*n;

	n = dict_attr_alloc_null(ctx, parent->dict->proto);
	if (unlikely(!n)) return NULL;

	if (_dict_attr_init(filename, line, &n, parent, name, attr, type, args) < 0) {
		talloc_free(n);
		return NULL;
	}

	return n;
}

/** Copy a an existing attribute, possibly to a new location
 *
 * @param[in] ctx		to allocate new attribute in.
 * @param[in] parent		where to parent the copy from. If NULL, in->parent is used.
 * @param[in] in		attribute to copy.
 * @param[in] name		to assign to the attribute. If NULL, in->name is used.
 * @return
 *	- A copy of the input fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t *dict_attr_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, fr_dict_attr_t const *in,
				char const *name)
{
	fr_dict_attr_t		*n;

	if (in->flags.has_fixup) {
		fr_strerror_printf("Cannot copy from %s - source attribute is waiting for additional definitions",
				   in->name);
		return NULL;
	}

	fr_assert(parent || name);

	n = dict_attr_alloc(ctx, parent ? parent : in->parent, name ? name : in->name,
			    in->attr, in->type, &(dict_attr_args_t){ .flags = &in->flags });
	if (unlikely(!n)) return NULL;

	/*
	 *	This newly allocated attribute is not the target of a ref.
	 */
	n->flags.is_ref_target = false;

	if (dict_attr_ext_copy_all(&n, in) < 0) {
	error:
		talloc_free(n);
		return NULL;
	}
	DA_VERIFY(n);

	if (fr_type_is_structural(in->type) && in->flags.has_alias) {
		if (dict_attr_acopy_aliases(n, in) < 0) goto error;
	}

	return n;
}

int fr_dict_attr_acopy_local(fr_dict_attr_t const *dst, fr_dict_attr_t const *src)
{
	if (!dst->flags.local) {
		fr_strerror_const("Cannot copy attributes to a non-local dictionary");
		return -1;
	}

	if (src->flags.has_fixup) {
		fr_strerror_printf("Cannot copy from %s to %s - source attribute is waiting for additional definitions",
				   src->name, dst->name);
		return -1;
	}

	/*
	 *	Why not?  @todo - check and fix
	 */
	if (src->flags.local) {
		fr_strerror_const("Cannot copy a local attribute");
		return -1;
	}

	return dict_attr_acopy_children(dst->dict, UNCONST(fr_dict_attr_t *, dst), src);
}

static int dict_attr_acopy_child(fr_dict_t *dict, fr_dict_attr_t *dst, fr_dict_attr_t const *src,
				 fr_dict_attr_t const *child)
{
	fr_dict_attr_t			*copy;

	copy = dict_attr_acopy(dict->pool, dst, child, child->name);
	if (!copy) return -1;

	fr_assert(copy->parent == dst);
	copy->depth = copy->parent->depth + 1;

	if (dict_attr_child_add(dst, copy) < 0) return -1;

	if (dict_attr_add_to_namespace(dst, copy) < 0) return -1;

	if (!dict_attr_children(child)) return 0;

	if (dict_attr_acopy_children(dict, copy, child) < 0) return -1;

	/*
	 *	Children of a UNION get an ALIAS added to the parent of the UNION.  This allows the UNION
	 *	attribute to be omitted from parsing and printing.
	 */
	if (src->type != FR_TYPE_UNION) return 0;

	return dict_attr_alias_add(dst->parent, copy->name, copy);
}


/** Copy the children of an existing attribute
 *
 * @param[in] dict		to allocate the children in
 * @param[in] dst		where to copy the children to
 * @param[in] src		where to copy the children from
 * @return
 *	- 0 on success
 *	- <0 on error
 */
int dict_attr_acopy_children(fr_dict_t *dict, fr_dict_attr_t *dst, fr_dict_attr_t const *src)
{
	uint				child_num;
	fr_dict_attr_t const		*child = NULL, *src_key = NULL;
	fr_dict_attr_t			*dst_key;

	fr_assert(fr_dict_attr_has_ext(dst, FR_DICT_ATTR_EXT_CHILDREN));
	fr_assert(dst->type == src->type);
	fr_assert(fr_dict_attr_is_key_field(src) == fr_dict_attr_is_key_field(dst));

	/*
	 *	For non-struct parents, we can copy their children in any order.
	 */
	if (likely(src->type != FR_TYPE_STRUCT)) {
		for (child = fr_dict_attr_iterate_children(src, &child);
		     child != NULL;
		     child = fr_dict_attr_iterate_children(src, &child)) {
			if (dict_attr_acopy_child(dict, dst, src, child) < 0) return -1;
		}

		return 0;
	}

	/*
	 *	For structs, we copy the children in order.  This allows "key" fields to be copied before
	 *	fields which depend on them.
	 *
	 *	Note that due to the checks in the DEFINE and ATTRIBUTE parsers (but not the validate
	 *	routines), STRUCTs can only have children which are MEMBERs.  And MEMBERs are allocated in
	 *	order.
	 */
	for (child_num = 1, child = fr_dict_attr_child_by_num(src, child_num);
	     child != NULL;
	     child_num++, child = fr_dict_attr_child_by_num(src, child_num)) {
		/*
		 *	If the key field has enums, then delay copying the enums until after we've copied all
		 *	of the other children.
		 *
		 *	For a UNION which is inside of a STRUCT, the UNION has a reference to the key field.
		 *	So the key field needs to be defined before we create the UNION.
		 *
		 *	But the key field also has a set of ENUMs, each of which has a key ref to the UNION
		 *	member which is associated with that key value.  This means that we have circular
		 *	dependencies.
		 *
		 *	The loop is resolved by creating the key first, and allocating room for an ENUM
		 *	extension.  This allows the UNION to reference the key.  Once the UNION is created, we
		 *	go back and copy all of the ENUMs over.  The ENUM copy routine will take care of
		 *	fixing up the refs.
		 */
		if (unlikely(fr_dict_attr_is_key_field(child) && child->flags.has_value)) {
			src_key = child;

			if (src_key->flags.has_fixup) {
				fr_strerror_printf("Cannot copy from %s - source attribute is waiting for additional definitions",
						   src_key->name);
				return -1;
			}

			dst_key = dict_attr_alloc(dict, dst, src_key->name,
						  src_key->attr, src_key->type, &(dict_attr_args_t){ .flags = &src_key->flags });
			if (unlikely(!dst_key)) return -1;

			if (!dict_attr_ext_alloc(&dst_key, FR_DICT_ATTR_EXT_ENUMV)) return -1;

			fr_assert(dst_key->parent == dst);
			dst_key->depth = dst->depth + 1;

			if (dict_attr_child_add(dst, dst_key) < 0) return -1;

			if (dict_attr_add_to_namespace(dst, dst_key) < 0) return -1;

			continue;
		}

		if (dict_attr_acopy_child(dict, dst, src, child) < 0) return -1;

		DA_VERIFY(child);
	}

	DA_VERIFY(dst);

	if (!src_key) return 0;

	if (!dict_attr_ext_copy(&dst_key, src_key, FR_DICT_ATTR_EXT_ENUMV)) return -1;

	return 0;
}

/** Copy the VALUEs of an existing attribute, by casting them
 *
 * @param[in] dst		where to cast the VALUEs to
 * @param[in] src		where to cast the VALUEs from
 * @return
 *	- 0 on success
 *	- <0 on error
 */
int dict_attr_acopy_enumv(fr_dict_attr_t *dst, fr_dict_attr_t const *src)
{
	fr_dict_attr_ext_enumv_t	*ext;

	fr_assert(!fr_type_is_non_leaf(dst->type));
	fr_assert(!fr_type_is_non_leaf(src->type));

	fr_assert(fr_dict_attr_has_ext(dst, FR_DICT_ATTR_EXT_ENUMV));
	fr_assert(fr_dict_attr_has_ext(src, FR_DICT_ATTR_EXT_ENUMV));

	ext = fr_dict_attr_ext(src, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_assert(0);
		return -1;
	}

	if (!ext->name_by_value) {
		fr_strerror_printf("Reference enum %s does not have any VALUEs to copy", src->name);
		return -1;
	}

	if (dict_attr_ext_copy(&dst, src, FR_DICT_ATTR_EXT_ENUMV)) return fr_hash_table_num_elements(ext->name_by_value);

	return -1;
}


/** Copy aliases of an existing attribute to a new one.
 *
 * @param[in] dst		where to copy the children to
 * @param[in] src		where to copy the children from
 * @return
 *	- 0 on success
 *	- <0 on error
 */
int dict_attr_acopy_aliases(UNUSED fr_dict_attr_t *dst, fr_dict_attr_t const *src)
{
	fr_hash_table_t *namespace;
	fr_hash_iter_t	iter;
	fr_dict_attr_t const *da;

	if (!src->flags.has_alias) return 0;

	switch (src->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
		break;

		/*
		 *	Automatically added aliases are copied in dict_attr_acopy_child().
		 */
	case FR_TYPE_STRUCT:
		return 0;

	default:
		fr_strerror_printf("Cannot add ALIAS to parent attribute %s of data type '%s'", src->name, fr_type_to_str(src->type));
		return -1;

	}

	namespace = dict_attr_namespace(src);
	fr_assert(namespace != NULL);

	for (da = fr_hash_table_iter_init(namespace, &iter);
	     da != NULL;
	     da = fr_hash_table_iter_next(namespace, &iter)) {
		if (!da->flags.is_alias) continue;

#if 1
		fr_strerror_printf("Cannot clone ALIAS %s.%s to %s.%s", src->name, da->name, dst->name, da->name);
		return -1;
		
#else
		fr_dict_attr_t const *parent, *ref;
		fr_dict_attr_t const *new_ref;

		ref = fr_dict_attr_ref(da);
		fr_assert(ref != NULL);

		/*
		 *	ALIASes are normally down the tree, to shorten sibling relationships.
		 *	e.g. Cisco-AVPAir -> Vendor-Specific.Cisco.AV-Pair.
		 *
		 *	The question is to we want to allow aliases to create cross-tree links?  I suspect
		 *	not.
		 */
		parent = fr_dict_attr_common_parent(src, ref, true);
		if (!parent) {
			fr_strerror_printf("Cannot clone ALIAS %s.%s to %s.%s, the alias reference %s is outside of the shared tree",
					   src->name, da->name, dst->name, da->name, ref->name);
			return -1;
		}

		fr_assert(parent == src);

		new_ref = fr_dict_attr_by_name(NULL, dst, da->name);
		fr_assert(new_ref == NULL);

		/*
		 *	This function needs to walk back up from "ref" to "src", finding the intermediate DAs.
		 *	Once that's done, it needs to walk down from "dst" to create a new "ref".
		 */
		new_ref = dict_alias_reref(dst, src, ref);
		fr_assert(new_ref != NULL);

		if (dict_attr_alias_add(dst, da->name, new_ref) < 0) return -1;
#endif
	}

	return 0;
}

/** Add an alias to an existing attribute
 *
 */
int dict_attr_alias_add(fr_dict_attr_t const *parent, char const *alias, fr_dict_attr_t const *ref)
{
	fr_dict_attr_t const *da, *common;
	fr_dict_attr_t *self;
	fr_hash_table_t *namespace;

	switch (parent->type) {
	case FR_TYPE_STRUCT:
		/*
		 *	If we are a STRUCT, the reference an only be to children of a UNION.
		 */
		fr_assert(ref->parent->type == FR_TYPE_UNION);

		/*
		 *	And the UNION must be a MEMBER of the STRUCT.
		 */
		fr_assert(ref->parent->parent == parent);
		break;

	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_GROUP:
		break;

	default:
		fr_strerror_printf("Cannot add ALIAS to parent attribute %s of data type '%s'",
				   parent->name, fr_type_to_str(parent->type));
		return -1;
	}

	if ((ref->type == FR_TYPE_UNION) || fr_dict_attr_is_key_field(ref)) {
		fr_strerror_printf("Cannot add ALIAS to target attribute %s of data type '%s'",
				   ref->name, fr_type_to_str(ref->type));
		return -1;
	}

	da = dict_attr_by_name(NULL, parent, alias);
	if (da) {
		fr_strerror_printf("ALIAS '%s' conflicts with another attribute in namespace %s",
				   alias, parent->name);
		return -1;
	}

	/*
	 *	ALIASes can point across the tree and down, for the same parent.  ALIASes cannot go back up
	 *	the tree.
	 */
	common = fr_dict_attr_common_parent(parent, ref, true);
	if (!common) {
		fr_strerror_printf("Invalid ALIAS to target attribute %s of data type '%s' - the attributes do not share a parent",
				   ref->name, fr_type_to_str(ref->type));
		return -1;
	}

	/*
	 *	Note that we do NOT call fr_dict_attr_add() here.
	 *
	 *	When that function adds two equivalent attributes, the
	 *	second one is prioritized for printing.  For ALIASes,
	 *	we want the pre-existing one to be prioritized.
	 *
	 *	i.e. you can lookup the ALIAS by "name", but you
	 *	actually get returned "ref".
	 */
	{
		fr_dict_attr_flags_t flags = ref->flags;

		flags.is_alias = 1;	/* These get followed automatically by public functions */

		self = dict_attr_alloc(parent->dict->pool, parent, alias, ref->attr, FR_TYPE_VOID, (&(dict_attr_args_t){ .flags = &flags, .ref = ref }));
		if (unlikely(!self)) return -1;
	}

	self->dict = parent->dict;
	UNCONST(fr_dict_attr_t *, parent)->flags.has_alias = true;

	fr_assert(fr_dict_attr_ref(self) == ref);

	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
	error:
		talloc_free(self);
		return -1;
	}

	if (!fr_hash_table_insert(namespace, self)) {
		fr_strerror_const("Internal error storing attribute");
		goto error;
	}

	return 0;
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

		old_proto = fr_hash_table_find(dict_gctx->protocol_by_name, dict);
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
		fr_strerror_printf("%s: Duplicate protocol number %u", __FUNCTION__, dict->root->attr);
		return -1;
	}
	dict->in_protocol_by_num = true;

	dict_dependent_add(dict, "global");

	/*
	 *	Create and add sub-attributes which allow other
	 *	protocols to be encapsulated in the internal
	 *	namespace.
	 */
	if (dict_gctx->internal && (dict != dict_gctx->internal)) {
		fr_dict_attr_t const *da;
		fr_dict_attr_flags_t flags = { 0 };

		if (!dict_gctx->attr_protocol_encapsulation) dict_gctx->attr_protocol_encapsulation = fr_dict_attr_by_name(NULL, dict_gctx->internal->root, "Proto");
		fr_assert(dict_gctx->attr_protocol_encapsulation != NULL);

		da = fr_dict_attr_child_by_num(dict_gctx->attr_protocol_encapsulation, dict->root->attr);
		if (!da) {
			if (fr_dict_attr_add(dict_gctx->internal, dict_gctx->attr_protocol_encapsulation,
					     dict->root->name, dict->root->attr, FR_TYPE_GROUP, &flags) < 0) {
				return -1;
			}

			da = fr_dict_attr_child_by_num(dict_gctx->attr_protocol_encapsulation, dict->root->attr);
			fr_assert(da != NULL);
		}

		dict_attr_ref_set(da, dict->root, FR_DICT_ATTR_REF_ALIAS);
	}

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
		fr_strerror_const("Out of memory");
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

		old_vendor = fr_hash_table_find(dict->vendors_by_name, vendor);
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
	if (fr_hash_table_replace(NULL, dict->vendors_by_num, vendor) < 0) {
		fr_strerror_printf("%s: Failed inserting vendor %s", __FUNCTION__, name);
		return -1;
	}

	return 0;
}

/** See if a #fr_dict_attr_t can have children
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
	case FR_TYPE_UNION:
		return true;

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
		return -1;
	}

	if (!dict_attr_can_have_children(parent)) {
		fr_strerror_printf("Cannot add children to attribute '%s' of type %s",
				   parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if ((parent->type == FR_TYPE_VSA) && (child->type != FR_TYPE_VENDOR)) {
		fr_strerror_printf("Cannot add non-vendor children to attribute '%s' of type %s",
				   parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	The parent has children by name only, not by number.  Don't even bother trying to track
	 *	numbers, except for VENDOR in root, and MEMBER of a struct.
	 */
	if (!parent->flags.is_root && parent->flags.name_only &&
	    (parent->type != FR_TYPE_STRUCT) && (parent->type != FR_TYPE_TLV)) {
		return 0;
	}

	/*
	 *	We only allocate the pointer array *if* the parent has children.
	 */
	children = dict_attr_children(parent);
	if (!children) {
		children = talloc_zero_array(parent, fr_dict_attr_t const *, UINT8_MAX + 1);
		if (!children) {
			fr_strerror_const("Out of memory");
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
	for (bin = &children[child->attr & 0xff]; *bin; bin = &(*bin)->next) {
		/*
		 *	Workaround for vendors that overload the RFC space.
		 *	Structural attributes always take priority.
		 */
		bool child_is_struct = fr_type_is_structural(child->type);
		bool bin_is_struct = fr_type_is_structural((*bin)->type);

		if (child_is_struct && !bin_is_struct) break;
		if (fr_dict_vendor_num_by_da(child) <= fr_dict_vendor_num_by_da(*bin)) break;	/* Prioritise RFC attributes */
		if (child->attr <= (*bin)->attr) break;
	}

	memcpy(&this, &bin, sizeof(this));
	child->next = *this;
	*this = child;

	return 0;
}

/** Add an attribute to the name table for an attribute
 *
 * @param[in] parent		containing the namespace to add this attribute to.
 * @param[in] da		to add to the name lookup tables.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dict_attr_add_to_namespace(fr_dict_attr_t const *parent, fr_dict_attr_t *da)
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
				   fr_type_to_str(da->type),
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
		a = fr_hash_table_find(namespace, da);
		if (a && (strcasecmp(a->name, da->name) == 0)) {
			if ((a->attr != da->attr) || (a->type != da->type) || (a->parent != da->parent)) {
				fr_strerror_printf("Duplicate attribute name '%s' in namespace '%s'.  "
				   		   "Originally defined %s[%d]",
						   da->name, parent->name,
						   a->filename, a->line);
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
		if (fr_hash_table_replace(NULL, namespace, da) < 0) {
			fr_strerror_const("Internal error storing attribute");
			goto error;
		}
	}

	return 0;
}

/** A variant of fr_dict_attr_t that allows a pre-allocated, populated fr_dict_attr_t to be added
 *
 */
int fr_dict_attr_add_initialised(fr_dict_attr_t *da)
{
	fr_dict_attr_t const	*exists;

	if (unlikely(da->dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(da->dict)->name);
		return -1;
	}

	if (unlikely(da->state.finalised == false)) {
		fr_strerror_const("Attribute has not been finalised");
		return -1;
	}

	/*
	 *	Check that the definition is valid.
	 */
	if (!dict_attr_valid(da)) return -1;

	/*
	 *	Don't allow duplicate names
	 *
	 *	Previously we allowed duplicate names, but only if the
	 *	attributes were compatible (we'd just ignore the operation).
	 *
	 *	But as attribute parsing may have generated fixups, which
	 *	we'd now need to unpick, it's easier just to error out
	 *	and have the user fix the duplicate.
	 */
	exists = fr_dict_attr_by_name(NULL, da->parent, da->name);
	if (exists) {
		fr_strerror_printf("Duplicate attribute name '%s' in namespace '%s'.  "
				   "Originally defined %s[%d]", da->name, da->parent->name,
				   exists->filename, exists->line);
		return -1;
	}

	/*
	 *	In some cases name_only attributes may have explicitly
	 *	assigned numbers. Ensure that there are no conflicts
	 *	between auto-assigned and explkicitly assigned.
	 */
	if (da->flags.name_only) {
		if (da->state.attr_set) {
			fr_dict_attr_t *parent = fr_dict_attr_unconst(da->parent);

			if (da->attr > da->parent->last_child_attr) {
				parent->last_child_attr = da->attr;

				/*
				*	If the attribute is outside of the bounds of
				*	the type size, then it MUST be an internal
				*	attribute.  Set the flag in this attribute, so
				*	that the encoder doesn't have to do complex
				*	checks.
				*/
				if ((da->attr >= (((uint64_t)1) << (8 * parent->flags.type_size)))) da->flags.internal = true;
			}
		} else if (unlikely(dict_attr_num_init_name_only(da)) < 0) {
			return -1;
		}
	}

	/*
	 *	Attributes can also be indexed by number.  Ensure that
	 *	all attributes of the same number have the same
	 *	properties.
	 */
	exists = fr_dict_attr_child_by_num(da->parent, da->attr);
	if (exists) {
		fr_strerror_printf("Duplicate attribute number %u in namespace '%s'.  "
				   "Originally defined by '%s' at %s[%d]",
				   da->attr, da->parent->name, exists->name, exists->filename, exists->line);
		return -1;
	}

	/*
	 *	Add in by number
	 */
	if (dict_attr_child_add(UNCONST(fr_dict_attr_t *, da->parent), da) < 0) return -1;

	/*
	 *	Add in by name
	 */
	if (dict_attr_add_to_namespace(da->parent, da) < 0) return -1;

#ifndef NDEBUG
	{
		fr_dict_attr_t const *found;

		/*
		 *	Check if we added the attribute
		 */
		found = dict_attr_child_by_num(da->parent, da->attr);
		if (!found) {
			fr_strerror_printf("FATAL - Failed to find attribute number %u we just added to namespace '%s'", da->attr, da->parent->name);
			return -1;
		}

		if (!dict_attr_by_name(NULL, da->parent, da->name)) {
			fr_strerror_printf("FATAL - Failed to find attribute '%s' we just added to namespace '%s'", da->name, da->parent->name);
			return -1;
		}
	}
#endif

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
		     char const *name, unsigned int attr, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t *da;

	if (fr_dict_attr_ref(parent)) {
		fr_strerror_printf("Cannot add children to attribute '%s' which has 'ref=%s'",
				   parent->name, fr_dict_attr_ref(parent)->name);
		return -1;
	}

	if (!dict_attr_can_have_children(parent)) {
		fr_strerror_printf("Cannot add children to attribute '%s' of type %s",
				   parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	da = dict_attr_alloc_null(dict->pool, dict->proto);
	if (unlikely(!da)) return -1;

	if (dict_attr_init(&da, parent, name,
			   attr, type, &(dict_attr_args_t){ .flags = flags}) < 0) return -1;

	return fr_dict_attr_add_initialised(da);
}

/** Add an attribute to the dictionary
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] parent		to add attribute under.
 * @param[in] name		of the attribute.
 * @param[in] type		of attribute.
 * @param[in] flags		to set in the attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_add_name_only(fr_dict_t *dict, fr_dict_attr_t const *parent,
			       char const *name, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t *da;

	da = dict_attr_alloc_null(dict->pool, dict->proto);
	if (unlikely(!da)) return -1;

	if (dict_attr_init_name_only(&da, parent, name,type, &(dict_attr_args_t){ .flags = flags}) < 0) return -1;

	return fr_dict_attr_add_initialised(da);
}


int dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name,
			    fr_value_box_t const *value,
			    bool coerce, bool takes_precedence,
			    fr_dict_attr_t const *key_child_ref)
{
	size_t				len;
	fr_dict_enum_value_t		*enumv = NULL;
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
		fr_strerror_printf("VALUE name is too long");
		return -1;
	}

	/*
	 *	If the parent isn't a key field, then we CANNOT add a child struct.
	 */
	if (!fr_dict_attr_is_key_field(da) && key_child_ref) {
		fr_strerror_const("Child attributes cannot be defined for VALUEs which are not 'key' attributes");
		return -1;
	}

	if (fr_type_is_structural(da->type) || (da->type == FR_TYPE_STRING)) {
		fr_strerror_printf("Enumeration names cannot be added for data type '%s'", fr_type_to_str(da->type));
		return -1;
	}

	if (da->flags.is_alias) {
		fr_strerror_printf("Enumeration names cannot be added for ALIAS '%s'", da->name);
		return -1;
	}

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s", da->name);
		return -1;
	}

	/*
	 *	Initialise enumv hash tables
	 */
	if (!ext->value_by_name || !ext->name_by_value) {
		ext->value_by_name = fr_hash_table_talloc_alloc(da, fr_dict_enum_value_t, dict_enum_name_hash,
								dict_enum_name_cmp, hash_pool_free);
		if (!ext->value_by_name) {
			fr_strerror_printf("Failed allocating \"value_by_name\" table");
			return -1;
		}

		ext->name_by_value = fr_hash_table_talloc_alloc(da, fr_dict_enum_value_t, dict_enum_value_hash,
								dict_enum_value_cmp, NULL);
		if (!ext->name_by_value) {
			fr_strerror_printf("Failed allocating \"name_by_value\" table");
			return -1;
		}
	}

	/*
	 *	Allocate a structure to map between
	 *	the name and value.
	 */
	enumv = talloc_zero_size(da, sizeof(fr_dict_enum_value_t));
	if (!enumv) {
	oom:
		fr_strerror_printf("%s: Out of memory", __FUNCTION__);
		return -1;
	}
	talloc_set_type(enumv, fr_dict_enum_value_t);

	enumv->name = talloc_typed_strdup(enumv, name);
	enumv->name_len = len;

	if (key_child_ref) {
		fr_dict_enum_ext_attr_ref_t *ref;

		ref = dict_enum_ext_alloc(&enumv, FR_DICT_ENUM_EXT_ATTR_REF);
		if (!ref) goto oom;

		ref->da = key_child_ref;
	}

	enum_value = fr_value_box_alloc(enumv, da->type, NULL);
	if (!enum_value) goto oom;

	if (da->type != value->type) {
		if (!coerce) {
			fr_strerror_printf("Type mismatch between attribute (%s) and enum (%s)",
					   fr_type_to_str(da->type),
					   fr_type_to_str(value->type));
			return -1;
		}

		if (fr_value_box_cast(enumv, enum_value, da->type, NULL, value) < 0) {
			fr_strerror_printf_push("Failed coercing enum type (%s) to attribute type (%s)",
					   	fr_type_to_str(value->type),
					   	fr_type_to_str(da->type));

			return -1;
		}
	} else {
		if (unlikely(fr_value_box_copy(enum_value, enum_value, value) < 0)) {
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
			fr_dict_enum_value_t const *old;

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

		if (enumv->name_len > ext->max_name_len) ext->max_name_len = enumv->name_len;
	}

	/*
	 *	There are multiple VALUE's, keyed by attribute, so we
	 *	take care of that here.
	 */
	if (takes_precedence) {
		if (fr_hash_table_replace(NULL, ext->name_by_value, enumv) < 0) {
			fr_strerror_printf("%s: Failed inserting value %s", __FUNCTION__, name);
			return -1;
		}
	} else {
		(void) fr_hash_table_insert(ext->name_by_value, enumv);
	}

	/*
	 *	Mark the attribute up as having an enumv
	 */
	UNCONST(fr_dict_attr_t *, da)->flags.has_value = 1;

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
int fr_dict_enum_add_name(fr_dict_attr_t *da, char const *name,
			       fr_value_box_t const *value,
			       bool coerce, bool takes_precedence)
{
	return dict_attr_enum_add_name(da, name, value, coerce, takes_precedence, NULL);
}

/** Add an name to an integer attribute hashing the name for the integer value
 *
 * If the integer value conflicts with an existing name, it's incremented
 * until we find a free value.
 */
int fr_dict_enum_add_name_next(fr_dict_attr_t *da, char const *name)
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
				   fr_type_to_str(da->type));
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
		return fr_dict_enum_add_name(da, name, &v, false, false);
	}

	for (;;) {
		fr_value_box_increment(&v);

		if (fr_value_box_cmp_op(T_OP_CMP_EQ, &v, &s) == 0) {
			fr_strerror_const("No free integer values for enumeration");
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
		fr_strerror_const("Unexpected text after OID component");
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

	/*
	 *	Only a limited number of structural types can have children.  Specifically, groups cannot.
	 */
	if (!dict_attr_can_have_children(*parent)) {
		fr_strerror_printf("Attribute %s (%u) cannot contain a child attribute.  "
				   "Error at sub OID \"%s\"", (*parent)->name, (*parent)->attr, oid);
		return 0;	/* We parsed nothing */
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
			fr_strerror_printf("Unknown attribute '%u' in OID string \"%s\" for parent %s",
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
 * @param[in] tt		Terminal strings.
 * @return
 *	- >0 the number of bytes consumed.
 *	- <0 Parse error occurred here.
 */
fr_slen_t fr_dict_oid_component(fr_dict_attr_err_t *err,
			        fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
			        fr_sbuff_t *in, fr_sbuff_term_t const *tt)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	uint32_t		num = 0;
	fr_sbuff_parse_error_t	sberr;
	fr_dict_attr_t const	*child;

	if (err) *err = FR_DICT_ATTR_OK;

	*out = NULL;

	if (!dict_attr_can_have_children(parent)) {
		fr_strerror_printf("Attribute '%s' is type %s and cannot contain child attributes.  "
				   "Error at OID \"%.*s\"",
				   parent->name,
				   fr_type_to_str(parent->type),
				   (int)fr_sbuff_remaining(&our_in),
				   fr_sbuff_current(&our_in));
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (fr_dict_attr_by_name_substr(err, &child, parent, &our_in, tt) > 0) goto done;

	fr_sbuff_out(&sberr, &num, &our_in);
	switch (sberr) {
	/*
	 *	Lookup by number
	 */
	case FR_SBUFF_PARSE_OK:
		if (!fr_sbuff_is_char(&our_in, '.') && !fr_sbuff_is_terminal(&our_in, tt)) {
			if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			fr_strerror_printf("Invalid OID component (%s) \"%.*s\"",
					   fr_table_str_by_value(sbuff_parse_error_table, sberr, "<INVALID>"),
					   (int)fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));
			goto fail;
		}

		child = dict_attr_child_by_num(parent, num);
		if (!child) {
			fr_sbuff_set_to_start(&our_in);
			fr_strerror_printf("Failed resolving child %u in namespace '%s'",
					   num, parent->name);
			if (err) *err = FR_DICT_ATTR_NOTFOUND;
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (err) *err = FR_DICT_ATTR_OK;
		break;

	case FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW:
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;

		fr_sbuff_set_to_start(&our_in);

		{
			fr_sbuff_marker_t c_start;

			fr_sbuff_marker(&c_start, &our_in);
			fr_sbuff_adv_past_allowed(&our_in, FR_DICT_ATTR_MAX_NAME_LEN, fr_dict_attr_allowed_chars, NULL);
			fr_strerror_printf("Invalid value \"%.*s\" - attribute numbers must be less than 2^32",
					   (int)fr_sbuff_behind(&c_start), fr_sbuff_current(&c_start));
		}
		FR_SBUFF_ERROR_RETURN(&our_in);

	default:
	fail:
		/*
		 *	Leave *err from the call to fr_dict_attr_by_name_substr().
		 */
		fr_sbuff_set_to_start(&our_in);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

done:
	child = dict_attr_alias(err, child);
	if (unlikely(!child)) FR_SBUFF_ERROR_RETURN(&our_in);

	*out = child;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Resolve an attribute using an OID string
 *
 * @note Will leave the sbuff pointing at the component the error occurred at
 *	 so that the caller can attempt to process the component in another way.
 *	 An err pointer should be provided in order to determine if an error
 *	 occurred.
 *
 * @param[out] err		The parsing error that occurred.
 * @param[out] out		The deepest attribute we resolved.
 * @param[in] parent		Where to resolve relative attributes from.
 * @param[in] in		string to parse.
 * @param[in] tt		Terminal strings.
 * @return The number of bytes of name consumed.
 */
fr_slen_t fr_dict_attr_by_oid_substr(fr_dict_attr_err_t *err,
				     fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
				     fr_sbuff_t *in, fr_sbuff_term_t const *tt)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	m_c;
	fr_dict_attr_t const	*our_parent = parent;

	fr_sbuff_marker(&m_c, &our_in);

	/*
	 *	If the OID doesn't begin with '.' we
	 *	resolve it from the root.
	 */
#if 0
	if (!fr_sbuff_next_if_char(&our_in, '.')) our_parent = fr_dict_root(fr_dict_by_da(parent));
#else
	(void) fr_sbuff_next_if_char(&our_in, '.');
#endif
	*out = NULL;

	for (;;) {
		fr_dict_attr_t const	*child;

		if ((fr_dict_oid_component(err, &child, our_parent, &our_in, tt) < 0) || !child) {
			*out = our_parent;
			fr_sbuff_set(&our_in, &m_c);	/* Reset to the start of the last component */
			break;	/* Resolved as much as we can */
		}

		our_parent = child;
		*out = child;

		fr_sbuff_set(&m_c, &our_in);
		if (!fr_sbuff_next_if_char(&our_in, '.')) break;
	}

	FR_SBUFF_SET_RETURN(in, &our_in);
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

	if (fr_dict_attr_by_oid_substr(err, &da, parent, &sbuff, NULL) <= 0) return NULL;
	if (err && *err != FR_DICT_ATTR_OK) return NULL;

	/*
	 *	If we didn't parse the entire string, then the parsing stopped at an unknown child.
	 *	e.g. Vendor-Specific.Cisco.Foo.  In that case, the full attribute wasn't found.
	 */
	if (fr_sbuff_remaining(&sbuff) > 0) {
		if (err) *err = FR_DICT_ATTR_NOTFOUND;
		return NULL;
	}

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
	return dict->root;
}

bool fr_dict_is_read_only(fr_dict_t const *dict)
{
	return dict->read_only;
}

dl_t *fr_dict_dl(fr_dict_t const *dict)
{
	return dict->dl;
}

fr_slen_t dict_by_protocol_substr(fr_dict_attr_err_t *err,
				  fr_dict_t **out, fr_sbuff_t *name, fr_dict_t const *dict_def)
{
	fr_dict_attr_t		root;

	fr_sbuff_t		our_name;
	fr_dict_t		*dict;
	fr_slen_t		slen;
	char			buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1 + 1];	/* +1 \0 +1 for "too long" */

	if (!dict_gctx || !name || !out) {
		if (err) *err = FR_DICT_ATTR_EINVAL;
		if (name) FR_SBUFF_ERROR_RETURN(name);
		return 0;
	}

	our_name = FR_SBUFF(name);
	memset(&root, 0, sizeof(root));

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buffer, sizeof(buffer)),
					     &our_name, SIZE_MAX,
					     fr_dict_attr_allowed_chars);
	if (slen == 0) {
		fr_strerror_const("Zero length attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}
	if (slen > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_const("Attribute name too long");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	The remaining operations don't generate errors
	 */
	if (err) *err = FR_DICT_ATTR_OK;

	/*
	 *	If what we stopped at wasn't a '.', then there
	 *	can't be a protocol name in this string.
	 */
	if (*(our_name.p) && (*(our_name.p) != '.')) {
		memcpy(out, &dict_def, sizeof(*out));
		return 0;
	}

	root.name = buffer;
	dict = fr_hash_table_find(dict_gctx->protocol_by_name, &(fr_dict_t){ .root = &root });

	if (!dict) {
		if (strcasecmp(root.name, "internal") != 0) {
			fr_strerror_printf("Unknown protocol '%s'", root.name);
			memcpy(out, &dict_def, sizeof(*out));
			fr_sbuff_set_to_start(&our_name);
			FR_SBUFF_ERROR_RETURN(&our_name);
		}

		dict = dict_gctx->internal;
	}

	*out = dict;

	FR_SBUFF_SET_RETURN(name, &our_name);
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
 *	- < 0 on error and (*out == NULL) (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
fr_slen_t fr_dict_by_protocol_substr(fr_dict_attr_err_t *err, fr_dict_t const **out, fr_sbuff_t *name, fr_dict_t const *dict_def)
{
	return dict_by_protocol_substr(err, UNCONST(fr_dict_t **, out), name, dict_def);
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

	return fr_hash_table_find(dict_gctx->protocol_by_name,
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

	return fr_hash_table_find(dict_gctx->protocol_by_num,
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
					   !dict ? "(null)" : fr_dict_root(dict)->name);
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

/** See if two dictionaries have the same end parent
 *
 * @param[in] dict1 one dictionary
 * @param[in] dict2 two dictionary
 * @return
 *	- true the dictionaries have the same end parent
 *	- false the dictionaries do not have the same end parent.
 */
bool fr_dict_compatible(fr_dict_t const *dict1, fr_dict_t const *dict2)
{
	while (dict1->next) dict1 = dict1->next;

	while (dict2->next) dict2 = dict2->next;

	return (dict1 == dict2);
}

/** Look up a vendor by one of its child attributes
 *
 * @param[in] da	The vendor attribute.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that number was registered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_da(fr_dict_attr_t const *da)
{
	fr_dict_t 		*dict;
	fr_dict_vendor_t	dv;

	dv.pen = fr_dict_vendor_num_by_da(da);
	if (!dv.pen) return NULL;

	dict = dict_by_da(da);

	return fr_hash_table_find(dict->vendors_by_num, &dv);
}

/** Look up a vendor by its name
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] name		to search for.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that name was registered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name)
{
	fr_dict_vendor_t	*found;

	INTERNAL_IF_NULL(dict, NULL);

	if (!name) return 0;

	found = fr_hash_table_find(dict->vendors_by_name, &(fr_dict_vendor_t) { .name = name });
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
 *	- NULL if no vendor with that number was registered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen)
{
	INTERNAL_IF_NULL(dict, NULL);

	return fr_hash_table_find(dict->vendors_by_num, &(fr_dict_vendor_t) { .pen = vendor_pen });
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
				   fr_type_to_str(FR_TYPE_VSA),
				   fr_type_to_str(vendor_root->type));
		return NULL;
	}

	vendor = dict_attr_child_by_num(vendor_root, vendor_pen);
	if (!vendor) {
		fr_strerror_printf("Vendor %u not defined", vendor_pen);
		return NULL;
	}

	if (vendor->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Wrong type for vendor, expected '%s' got '%s'",
				   fr_type_to_str(vendor->type),
				   fr_type_to_str(FR_TYPE_VENDOR));
		return NULL;
	}

	return vendor;
}

/** Callback function for resolving dictionary attributes
 *
 * @param[out] err	Where to write error codes.  Any error
 *			other than FR_DICT_ATTR_NOTFOUND will
 *			prevent resolution from continuing.
 * @param[out] out	Where to write resolved DA.
 * @param[in] parent	The dictionary root or other attribute to search from.
 * @param[in] in	Contains the string to resolve.
 * @param[in] tt	Terminal sequences to use to determine the portion
 *			of in to search.
 * @return
 *	- < 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
typedef fr_slen_t (*dict_attr_resolve_func_t)(fr_dict_attr_err_t *err,
				   	      fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
				   	      fr_sbuff_t *in, fr_sbuff_term_t const *tt);

/** Internal function for searching for attributes in multiple dictionaries
 *
 * @param[out] err		Any errors that occurred searching.
 * @param[out] out		The attribute we found.
 * @param[in] dict_def		The default dictionary to search in.
 * @param[in] in		string to resolve to an attribute.
 * @param[in] tt		terminals that indicate the end of the string.
 * @param[in] internal		Resolve the attribute in the internal dictionary.
 * @param[in] foreign		Resolve attribute in a foreign dictionary,
 *				i.e. one other than dict_def.
 * @param[in] func		to use for resolution.
 * @return
 *	- <=0 on error (the offset of the error).
 *	- >0 on success.
 */
static inline CC_HINT(always_inline)
fr_slen_t dict_attr_search(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
			   fr_dict_t const *dict_def,
			   fr_sbuff_t *in, fr_sbuff_term_t const *tt,
			   bool internal, bool foreign,
			   dict_attr_resolve_func_t func)
{
	fr_dict_attr_err_t	our_err = FR_DICT_ATTR_OK;
	fr_hash_iter_t  	iter;
	fr_dict_t		*dict = NULL;
	fr_sbuff_t		our_in = FR_SBUFF(in);

	if (internal && !dict_gctx->internal) internal = false;

	/*
	 *	Always going to fail...
	 */
	if (unlikely(!internal && !foreign && !dict_def)) {
		if (err) *err = FR_DICT_ATTR_EINVAL;
		*out = NULL;
		return 0;
	}

	/*
	 *	dict_def search in the specified dictionary
	 */
	if (dict_def) {
		(void)func(&our_err, out, fr_dict_root(dict_def), &our_in, tt);
		switch (our_err) {
		case FR_DICT_ATTR_OK:
			FR_SBUFF_SET_RETURN(in, &our_in);

		case FR_DICT_ATTR_NOTFOUND:
			if (!internal && !foreign) goto error;
			break;

		default:
			goto error;
		}
	}

	/*
	 *	Next in the internal dictionary
	 */
	if (internal) {
		(void)func(&our_err, out, fr_dict_root(dict_gctx->internal), &our_in, tt);
		switch (our_err) {
		case FR_DICT_ATTR_OK:
			FR_SBUFF_SET_RETURN(in, &our_in);

		case FR_DICT_ATTR_NOTFOUND:
			if (!foreign) goto error;
			break;

		default:
			goto error;
		}
	}

	/*
	 *	Now loop over the protocol dictionaries
	 */
	for (dict = fr_hash_table_iter_init(dict_gctx->protocol_by_num, &iter);
	     dict;
	     dict = fr_hash_table_iter_next(dict_gctx->protocol_by_num, &iter)) {
		if (dict == dict_def) continue;
		if (dict == dict_gctx->internal) continue;

		(void)func(&our_err, out, fr_dict_root(dict), &our_in, tt);
		switch (our_err) {
		case FR_DICT_ATTR_OK:
			FR_SBUFF_SET_RETURN(in, &our_in);

		case FR_DICT_ATTR_NOTFOUND:
			continue;

		default:
			break;
		}
	}

error:
	/*
	 *	Add a more helpful error message about
	 *	which dictionaries we tried to locate
	 *	the attribute in.
	 */
	if (our_err == FR_DICT_ATTR_NOTFOUND) {
		fr_sbuff_marker_t	start;
		char			*list = NULL;

#define DICT_NAME_APPEND(_in, _dict) \
do { \
	char *_n; \
	_n = talloc_strdup_append_buffer(_in, fr_dict_root(_dict)->name); \
	if (unlikely(!_n)) { \
		talloc_free(_in); \
		goto done; \
	} \
	_in = _n; \
	_n = talloc_strdup_append_buffer(_in, ", "); \
	if (unlikely(!_n)) { \
		talloc_free(_in); \
		goto done; \
	} \
	_in = _n; \
} while (0)

		our_in = FR_SBUFF(in);
		fr_sbuff_marker(&start, &our_in);

		list = talloc_strdup(NULL, "");
		if (unlikely(!list)) goto done;

		if (dict_def) DICT_NAME_APPEND(list, dict_def);
		if (internal) DICT_NAME_APPEND(list, dict_gctx->internal);

		if (foreign) {
			for (dict = fr_hash_table_iter_init(dict_gctx->protocol_by_num, &iter);
			     dict;
			     dict = fr_hash_table_iter_next(dict_gctx->protocol_by_num, &iter)) {
				if (dict == dict_def) continue;
				if (dict == dict_gctx->internal) continue;

				if (internal) DICT_NAME_APPEND(list, dict);
			}
		}

		fr_strerror_printf("Attribute '%pV' not found.  Searched in: %pV",
				   fr_box_strvalue_len(fr_sbuff_current(&start),
				   		       fr_sbuff_adv_until(&our_in, SIZE_MAX, tt, '\0')),
				   fr_box_strvalue_len(list, talloc_array_length(list) - 3));

		talloc_free(list);
	}

done:
	if (err) *err = our_err;
	*out = NULL;

	FR_SBUFF_ERROR_RETURN(&our_in);
}

/** Internal function for searching for attributes in multiple dictionaries
 *
 * Unlike #dict_attr_search this function searches for a protocol name preceding
 * the attribute identifier.
 */
static inline CC_HINT(always_inline)
fr_slen_t dict_attr_search_qualified(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
				     fr_dict_t const *dict_def,
				     fr_sbuff_t *in, fr_sbuff_term_t const *tt,
				     bool internal, bool foreign,
				     dict_attr_resolve_func_t func)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_dict_attr_err_t	our_err;
	fr_dict_t 		*initial;
	fr_slen_t		slen;

	/*
	 *	Check for dictionary prefix
	 */
	slen = dict_by_protocol_substr(&our_err, &initial, &our_in, dict_def);
	if (our_err != FR_DICT_ATTR_OK) {
	error:
		if (err) *err = our_err;
		*out = NULL;
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
 	 *	Has dictionary qualifier, can't fallback
	 */
	if (slen > 0) {
		/*
		 *	Next thing SHOULD be a '.'
		 */
		if (!fr_sbuff_next_if_char(&our_in, '.')) {
			if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			*out = NULL;
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		internal = foreign = false;
	}

	if (dict_attr_search(&our_err, out, initial, &our_in, tt, internal, foreign, func) < 0) goto error;
	if (err) *err = FR_DICT_ATTR_OK;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Locate a qualified #fr_dict_attr_t by its name and a dictionary qualifier
 *
 * This function will search through all loaded dictionaries, or a subset of
 * loaded dictionaries, for a matching attribute in the top level namespace.
 *
 * This attribute may be qualified with `<protocol>.` to selection an attribute
 * in a specific case.
 *
 * @note If calling this function from the server any list or request qualifiers
 *  should be stripped first.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] name		Dictionary/Attribute name.
 * @param[in] tt		Terminal strings.
 * @param[in] internal		If true, fallback to the internal dictionary.
 * @param[in] foreign		If true, fallback to foreign dictionaries.
 * @return
 *	- < 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
fr_slen_t fr_dict_attr_search_by_qualified_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						       fr_dict_t const *dict_def,
						       fr_sbuff_t *name, fr_sbuff_term_t const *tt,
						       bool internal, bool foreign)
{
	return dict_attr_search_qualified(err, out, dict_def, name, tt,
					  internal, foreign, fr_dict_attr_by_name_substr);
}

/** Locate a #fr_dict_attr_t by its name in the top level namespace of a dictionary
 *
 * This function will search through all loaded dictionaries, or a subset of
 * loaded dictionaries, for a matching attribute in the top level namespace.
 *
 * @note If calling this function from the server any list or request qualifiers
 *  should be stripped first.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] name		Dictionary/Attribute name.
 * @param[in] tt		Terminal strings.
 * @param[in] internal		If true, fallback to the internal dictionary.
 * @param[in] foreign		If true, fallback to foreign dictionaries.
 * @return
 *	- < 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
fr_slen_t fr_dict_attr_search_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
					     fr_dict_t const *dict_def,
					     fr_sbuff_t *name, fr_sbuff_term_t const *tt,
					     bool internal, bool foreign)
{
	return dict_attr_search_qualified(err, out, dict_def, name, tt,
					  internal, foreign, fr_dict_attr_by_name_substr);
}

/** Locate a qualified #fr_dict_attr_t by a dictionary qualified OID string
 *
 * This function will search through all loaded dictionaries, or a subset of
 * loaded dictionaries, for a matching attribute.
 *
 * @note If calling this function from the server any list or request qualifiers
 *  should be stripped first.
 *
 * @note err should be checked to determine if a parse error occurred.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] in		Dictionary/Attribute name.
 * @param[in] tt		Terminal strings.
 * @param[in] internal		If true, fallback to the internal dictionary.
 * @param[in] foreign		If true, fallback to foreign dictionaries.
 * @return The number of bytes of name consumed.
 */
fr_slen_t fr_dict_attr_search_by_qualified_oid_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						      fr_dict_t const *dict_def,
						      fr_sbuff_t *in, fr_sbuff_term_t const *tt,
						      bool internal, bool foreign)
{
	return dict_attr_search_qualified(err, out, dict_def, in, tt,
					  internal, foreign, fr_dict_attr_by_oid_substr);
}

/** Locate a qualified #fr_dict_attr_t by a dictionary using a non-qualified OID string
 *
 * This function will search through all loaded dictionaries, or a subset of
 * loaded dictionaries, for a matching attribute.
 *
 * @note If calling this function from the server any list or request qualifiers
 *  should be stripped first.
 *
 * @note err should be checked to determine if a parse error occurred.
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t
 * @param[out] out		Dictionary found attribute.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] in		Dictionary/Attribute name.
 * @param[in] tt		Terminal strings.
 * @param[in] internal		If true, fallback to the internal dictionary.
 * @param[in] foreign		If true, fallback to foreign dictionaries.
 * @return The number of bytes of name consumed.
 */
fr_slen_t fr_dict_attr_search_by_oid_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
					    fr_dict_t const *dict_def,
					    fr_sbuff_t *in, fr_sbuff_term_t const *tt,
					    bool internal, bool foreign)
{
	return dict_attr_search_qualified(err, out, dict_def, in, tt,
					  internal, foreign, fr_dict_attr_by_oid_substr);
}

/** Locate a qualified #fr_dict_attr_t by its name and a dictionary qualifier
 *
 * @param[out] err		Why parsing failed. May be NULL.
 *				@see fr_dict_attr_err_t.
 * @param[in] dict_def		Default dictionary for non-qualified dictionaries.
 * @param[in] name		Dictionary/Attribute name.
 * @param[in] internal		If true, fallback to the internal dictionary.
 * @param[in] foreign		If true, fallback to foreign dictionaries.
 * @return an #fr_dict_attr_err_t value.
 */
fr_dict_attr_t const *fr_dict_attr_search_by_qualified_oid(fr_dict_attr_err_t *err, fr_dict_t const *dict_def,
							   char const *name,
							   bool internal, bool foreign)
{
	ssize_t			slen;
	fr_sbuff_t		our_name;
	fr_dict_attr_t const	*da;
	fr_dict_attr_err_t	our_err;

	fr_sbuff_init_in(&our_name, name, strlen(name));

	slen = fr_dict_attr_search_by_qualified_oid_substr(&our_err, &da, dict_def, &our_name, NULL, internal, foreign);
	if (our_err != FR_DICT_ATTR_OK) {
		if (err) *err = our_err;
		return NULL;
	}
	if ((size_t)slen != fr_sbuff_len(&our_name)) {
		fr_strerror_printf("Trailing garbage after attr string \"%s\"", name);
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		return NULL;
	}

	return da;
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
 * @param[in] tt		Terminal sequences to use to determine the portion
 *				of in to search.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
fr_slen_t fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
				      fr_dict_attr_t const *parent, fr_sbuff_t *name, UNUSED fr_sbuff_term_t const *tt)
{
	fr_dict_attr_t const	*da;
	size_t			len;
	fr_dict_attr_t const	*ref;
	char const		*p;
	char			buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1 + 1];	/* +1 \0 +1 for "too long" */
	fr_sbuff_t		our_name = FR_SBUFF(name);
	fr_hash_table_t		*namespace;

	*out = NULL;

#ifdef STATIC_ANALYZER
	memset(buffer, 0, sizeof(buffer));
#endif

	len = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buffer, sizeof(buffer)),
					    &our_name, SIZE_MAX,
					    fr_dict_attr_allowed_chars);
	if (len == 0) {
		fr_strerror_const("Zero length attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_const("Attribute name too long");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	Do a second pass, ensuring that the name has at least one alphanumeric character.
	 */
	for (p = buffer; p < (buffer + len); p++) {
		if (sbuff_char_alpha_num[(uint8_t) *p]) break;
	}

	if ((size_t) (p - buffer) == len) {
		fr_strerror_const("Invalid attribute name");
		if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	ref = fr_dict_attr_ref(parent);
	if (ref) parent = ref;

redo:
	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		fr_sbuff_set_to_start(&our_name);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	da = fr_hash_table_find(namespace, &(fr_dict_attr_t){ .name = buffer });
	if (!da) {
		if (parent->flags.is_root) {
			fr_dict_t const *dict = fr_dict_by_da(parent);

			if (dict->next) {
				parent = dict->next->root;
				goto redo;
			}
		}

		if (err) *err = FR_DICT_ATTR_NOTFOUND;
		fr_strerror_printf("Attribute '%s' not found in namespace '%s'", buffer, parent->name);
		fr_sbuff_set_to_start(&our_name);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	da = dict_attr_alias(err, da);
	if (unlikely(!da)) FR_SBUFF_ERROR_RETURN(&our_name);

	*out = da;
	if (err) *err = FR_DICT_ATTR_OK;

	FR_SBUFF_SET_RETURN(name, &our_name);
}

/* Internal version of fr_dict_attr_by_name
 *
 */
fr_dict_attr_t *dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *name)
{
	fr_hash_table_t		*namespace;
	fr_dict_attr_t		*da;

	DA_VERIFY(parent);

redo:
	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
		if (err) *err = FR_DICT_ATTR_NO_CHILDREN;
		return NULL;
	}

	da = fr_hash_table_find(namespace, &(fr_dict_attr_t) { .name = name });
	if (!da) {
		if (parent->flags.is_root) {
			fr_dict_t const *dict = fr_dict_by_da(parent);

			if (dict->next) {
				parent = dict->next->root;
				goto redo;
			}
		}

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
	fr_dict_attr_t const *da;

	DA_VERIFY(parent);

	da = dict_attr_by_name(err, parent, name);
	if (!da) return NULL;

	da = dict_attr_alias(err, da);
	if (unlikely(!da)) return NULL;

	return da;
}

/** Internal version of fr_dict_attr_child_by_num
 *
 */
fr_dict_attr_t *dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
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
	fr_dict_attr_t const *da;

	da = dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	da = dict_attr_alias(NULL, da);
	if (unlikely(!da)) return NULL;

	return da;
}

/** Iterate over all enumeration values for an attribute
 *
 * @param[in] da		to iterate over.
 * @param[in] iter		to use for iteration.
 * @return
 * 	- First #fr_dict_enum_value_t in the attribute.
 * 	- NULL if no enumeration values exist.
 */
fr_dict_enum_value_t const *fr_dict_enum_iter_init(fr_dict_attr_t const *da, fr_dict_enum_iter_t *iter)
{
	fr_dict_attr_ext_enumv_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("%s has no enumeration values to iterate over", da->name);
		return NULL;
	}

	return fr_hash_table_iter_init(ext->value_by_name, iter);
}

/* Iterate over next enumeration value for an attribute
 *
 * @param[in] da		to iterate over.
 * @param[in] iter		to use for iteration.
 * @return
 * 	- Next #fr_dict_enum_value_t in the attribute.
 * 	- NULL if no more enumeration values exist.
 */
fr_dict_enum_value_t const *fr_dict_enum_iter_next(fr_dict_attr_t const *da, fr_dict_enum_iter_t *iter)
{
	fr_dict_attr_ext_enumv_t	*ext;
	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("%s has no enumeration values to iterate over", da->name);
		return NULL;
	}

	return fr_hash_table_iter_next(ext->value_by_name, iter);;
}

/** Lookup the structure representing an enum value in a #fr_dict_attr_t
 *
 * @param[in] da		to search in.
 * @param[in] value		to search for.
 * @return
 * 	- Matching #fr_dict_enum_value_t.
 * 	- NULL if no matching #fr_dict_enum_value_t could be found.
 */
fr_dict_enum_value_t const *fr_dict_enum_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_attr_ext_enumv_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s attributes",
				   fr_type_to_str(da->type));
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

	return fr_hash_table_find(ext->name_by_value, &(fr_dict_enum_value_t){ .value = value });
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
	fr_dict_enum_value_t const *dv;

	dv = fr_dict_enum_by_value(da, value);
	if (!dv) return NULL;

	return dv->name;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_enum_value_t const *fr_dict_enum_by_name(fr_dict_attr_t const *da, char const *name, ssize_t len)
{
	fr_dict_attr_ext_enumv_t	*ext;

	if (!name) return NULL;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext) {
		fr_strerror_printf("VALUE cannot be defined for %s attributes",
				   fr_type_to_str(da->type));
		return NULL;
	}

	/*
	 *	No values associated with this attribute
	 */
	if (!ext->value_by_name) return NULL;

	if (len < 0) len = strlen(name);

	return fr_hash_table_find(ext->value_by_name, &(fr_dict_enum_value_t){ .name = name, .name_len = len});
}

/*
 *	Get a value by its name, keyed off of an attribute, from an sbuff
 */
fr_slen_t fr_dict_enum_by_name_substr(fr_dict_enum_value_t **out, fr_dict_attr_t const *da, fr_sbuff_t *in)
{
	fr_dict_attr_ext_enumv_t	*ext;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_dict_enum_value_t *found = NULL;
	size_t		found_len = 0;
	uint8_t		*p;
	uint8_t		name[FR_DICT_ENUM_MAX_NAME_LEN + 1];

	/*
	 *	No values associated with this attribute, do nothing.
	 */
	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
	if (!ext || !ext->value_by_name) return 0;

	/*
	 *	Loop until we exhaust all of the possibilities.
	 */
	for (p = name; (size_t) (p - name) < ext->max_name_len; p++) {
		int len = (p - name) + 1;
		fr_dict_enum_value_t *enumv;

		*p = fr_sbuff_char(&our_in, '\0');
		if (!fr_dict_enum_allowed_chars[*p]) {
			break;
		}
		fr_sbuff_next(&our_in);

		enumv = fr_hash_table_find(ext->value_by_name, &(fr_dict_enum_value_t){ .name = (char const *) name,
											.name_len = len});

		/*
		 *	Return the LONGEST match, as there may be
		 *	overlaps.  e.g. "Framed", and "Framed-User".
		 */
		if (enumv) {
			found = enumv;
			found_len = len;
		}
	}

	if (found) {
		*out = found;
		FR_SBUFF_SET_RETURN(in, found_len);
	}

	return 0;
}

/** Extract an enumeration name from a string
 *
 * This function defines the canonical format for an enumeration name.
 *
 * An enumeration name is made up of one or more fr_dict_attr_allowed_chars
 * with at least one character in the sequence not being a special character
 * i.e. [-+/_] or a number.
 *
 * This disambiguates enumeration identifiers from mathematical expressions.
 *
 * If we allowed enumeration names consisting of sequences of numbers separated
 * by special characters it would not be possible to determine if the special
 * character were an operator in a subexpression.
 *
 * For example take:
 *
 *    &My-Enum-Attr == 01234-5678
 *
 * Without having access to the enumeration values of My-Enum-Attr (which we
 * might not have during tokenisation), we cannot tell if this is:
 *
 * (&My-Enum-Attr == 01234-5678)
 *
 * OR
 *
 * ((&My-Enum-Attr == 01234) - 5678)
 *
 * If an alpha character occurs anywhere in the string i.e:
 *
 *    (&My-Enum-Attr == 01234-A5678)
 *
 * we know 01234-A5678 can't be a mathematical sub-expression because the
 * second potential operand can no longer be parsed as an integer constant.
 *
 * @param[out] out	The name string we managed to extract.
 *			May be NULL in which case only the length of the name
 *			will be returned.
 * @param[out] err	Type of parsing error which occurred.  May be NULL.
 * @param[in] in	The string containing the enum identifier.
 * @param[in] tt	If non-null verify that a terminal sequence occurs
 *			after the enumeration name.
 * @return
 *	- <0 the offset at which the parse error occurred.
 *	- >1 the number of bytes parsed.
 */
fr_slen_t fr_dict_enum_name_from_substr(fr_sbuff_t *out, fr_sbuff_parse_error_t *err,
					fr_sbuff_t *in, fr_sbuff_term_t const *tt)
{
	fr_sbuff_t our_in = FR_SBUFF(in);
	bool seen_alpha = false;

	while (fr_sbuff_is_in_charset(&our_in, fr_dict_enum_allowed_chars)) {
		if (fr_sbuff_is_alpha(&our_in)) seen_alpha = true;
		fr_sbuff_next(&our_in);
	}

	if (!seen_alpha) {
		if (fr_sbuff_used(&our_in) == 0) {
			fr_strerror_const("VALUE name is empty");
			if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND;
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_strerror_const("VALUE name must contain at least one alpha character");
		if (err) *err = FR_SBUFF_PARSE_ERROR_FORMAT;
		fr_sbuff_set_to_start(&our_in);	/* Marker should be at the start of the enum */
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Check that the sequence is correctly terminated
	 */
	if (tt && !fr_sbuff_is_terminal(&our_in, tt)) {
		fr_strerror_const("VALUE name has trailing text");
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING;
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (out) return fr_sbuff_out_bstrncpy_exact(out, in, fr_sbuff_used(&our_in));

	if (err) *err = FR_SBUFF_PARSE_OK;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

int dict_dlopen(fr_dict_t *dict, char const *name)
{
	char			*lib_name;
	char			*sym_name;
	fr_dict_protocol_t	*proto;

	if (!name) return 0;

	lib_name = talloc_typed_asprintf(NULL, "libfreeradius-%s", name);
	if (unlikely(lib_name == NULL)) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}
	talloc_bstr_tolower(lib_name);

	dict->dl = dl_by_name(dict_gctx->dict_loader, lib_name, NULL, false);
	if (!dict->dl) {
		fr_strerror_printf_push("Failed loading dictionary validation library \"%s\"", lib_name);
		talloc_free(lib_name);
		return -1;
	}
	talloc_free(lib_name);

	/*
	 *	The public symbol that contains per-protocol rules
	 *	and extensions.
	 *
	 *	It ends up being easier to do this using dlsym to
	 *	resolve the symbol and not use the autoloader
	 *	callbacks as theoretically multiple dictionaries
	 *	could use the same protocol library, and then the
	 *	autoloader callback would only run for the first
	 * 	dictionary which loaded the protocol.
	 */
	sym_name = talloc_typed_asprintf(NULL, "libfreeradius_%s_dict_protocol", name);
	if (unlikely(sym_name == NULL)) {
		talloc_free(lib_name);
		goto oom;
	}
	talloc_bstr_tolower(sym_name);

	/*
	 *	De-hyphenate the symbol name
	 */
	{
		char *p, *q;

		for (p = sym_name, q = p + (talloc_array_length(sym_name) - 1); p < q; p++) *p = *p == '-' ? '_' : *p;
	}

	proto = dlsym(dict->dl->handle, sym_name);
	talloc_free(sym_name);

	/*
	 *	Soft failure, not all protocol libraires provide
	 *	custom validation functions or flats.
	 */
	if (!proto) return 0;

	/*
	 *	Replace the default protocol with the custom one
	 *	if we have it...
	 */
	dict->proto = proto;

	return 0;
}

/** Find a dependent in the tree of dependents
 *
 */
static int8_t _dict_dependent_cmp(void const *a, void const *b)
{
	fr_dict_dependent_t const *dep_a = a;
	fr_dict_dependent_t const *dep_b = b;
	int ret;

	ret = strcmp(dep_a->dependent, dep_b->dependent);
	return CMP(ret, 0);
}

/** Record a new dependency on a dictionary
 *
 * These are used to determine what is currently depending on a dictionary.
 *
 * @param[in] dict	to record dependency on.
 * @param[in] dependent	Either C src file, or another dictionary.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int dict_dependent_add(fr_dict_t *dict, char const *dependent)
{
	fr_dict_dependent_t *found;

	found = fr_rb_find(dict->dependents, &(fr_dict_dependent_t){ .dependent = dependent } );
	if (!found) {
		fr_dict_dependent_t *new;

		new = talloc_zero(dict->dependents, fr_dict_dependent_t);
		if (unlikely(!new)) return -1;

		/*
		 *	If the dependent is in a module that gets
		 *	unloaded, any strings in the text area also
		 *	get unloaded (including dependent locations).
		 *
		 *	Strdup the string here so we don't get
		 *	random segfaults if a module forgets to unload
		 *	a dictionary.
		 */
		new->dependent = talloc_typed_strdup(new, dependent);
		fr_rb_insert(dict->dependents, new);

		new->count = 1;

		return 0;
	}

	found->count++;	/* Increase ref count */

	return 0;
}

/** Manually increase the reference count for a dictionary
 *
 * This is useful if a previously loaded dictionary needs to
 * be bound to the lifetime of an additional object.
 *
 * @param[in] dict	to increase the reference count for.
 * @param[in] dependent	requesting the loading of the dictionary.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_dict_dependent_add(fr_dict_t const *dict, char const *dependent)
{
	fr_dict_t *m_dict = fr_dict_unconst(dict);

	if (unlikely(!m_dict)) return -1;

	return dict_dependent_add(m_dict, dependent);
}

/** Decrement ref count for a dependent in a dictionary
 *
 * @param[in] dict	to remove dependency from.
 * @param[in] dependent	Either C src, or another dictionary dependent.
 *			What depends on this dictionary.
 */
int dict_dependent_remove(fr_dict_t *dict, char const *dependent)
{
	fr_dict_dependent_t *found;

	found = fr_rb_find(dict->dependents, &(fr_dict_dependent_t){ .dependent = dependent } );
	if (!found) {
		fr_strerror_printf("Dependent \"%s\" not found in dictionary \"%s\"", dependent, dict->root->name);
		return -1;
	}

	if (found->count == 0) {
		fr_strerror_printf("Zero ref count invalid for dependent \"%s\", dictionary \"%s\"",
				   dependent, dict->root->name);
		return -1;
	}

	if (--found->count == 0) {
		fr_rb_delete(dict->dependents, found);
		talloc_free(found);
		return 0;
	}

	return 1;
}

/** Check if a dictionary still has dependents
 *
 * @param[in] dict	to check
 * @return
 *	- true if there's still at least one dependent.
 *	- false if there are no dependents.
 */
bool dict_has_dependents(fr_dict_t *dict)
{
	return (fr_rb_num_elements(dict->dependents) > 0);
}

#ifndef NDEBUG
static void dependent_debug(fr_dict_t *dict)
{
	fr_rb_iter_inorder_t	iter;
	fr_dict_dependent_t	*dep;

	if (!dict_has_dependents(dict)) return;

	fprintf(stderr, "DEPENDENTS FOR %s\n", dict->root->name);

	for (dep = fr_rb_iter_init_inorder(dict->dependents, &iter);
	     dep;
	     dep = fr_rb_iter_next_inorder(dict->dependents, &iter)) {
		fprintf(stderr, "\t<- %s (%d)\n", dep->dependent, dep->count);
	}
}
#endif


static int dict_autoref_free(fr_dict_t *dict)
{
	fr_dict_t **refd_list;
	unsigned int i;

	if (!dict->autoref) return 0;

	if (fr_hash_table_flatten(dict->autoref, (void ***)&refd_list, dict->autoref) < 0) {
		fr_strerror_const("failed flattening autoref hash table");
		return -1;
	}

	/*
	 *	Free the dictionary.  It will call proto->free() if there's nothing more to do.
	 */
	for (i = 0; i < talloc_array_length(refd_list); i++) {
		if (fr_dict_free(&refd_list[i], dict->root->name) < 0) {
			fr_strerror_printf("failed freeing autoloaded protocol %s", refd_list[i]->root->name);
			return -1;
		}
	}

	TALLOC_FREE(dict->autoref);

	return 0;
}

static int _dict_free(fr_dict_t *dict)
{
	/*
	 *	We don't necessarily control the order of freeing
	 *	children.
	 */
	if (dict != dict->gctx->internal) {
		fr_dict_attr_t const *da;

		if (dict->gctx->attr_protocol_encapsulation && dict->root) {
			da = fr_dict_attr_child_by_num(dict->gctx->attr_protocol_encapsulation, dict->root->attr);
			if (da && fr_dict_attr_ref(da)) dict_attr_ref_null(da);
		}
	}

#ifdef STATIC_ANALYZER
	if (!dict->root) {
		fr_strerror_const("dict root is missing");
		return -1;
	}
#endif

	/*
	 *	If we called init(), then call free()
	 */
	if (dict->proto && dict->proto->free) {
		dict->proto->free();
	}

	if (!fr_cond_assert(!dict->in_protocol_by_name || fr_hash_table_delete(dict->gctx->protocol_by_name, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol hash \"%s\"", dict->root->name);
		return -1;
	}
	dict->in_protocol_by_name = false;

	if (!fr_cond_assert(!dict->in_protocol_by_num || fr_hash_table_delete(dict->gctx->protocol_by_num, dict))) {
		fr_strerror_printf("Failed removing dictionary from protocol number_hash \"%s\"", dict->root->name);
		return -1;
	}
	dict->in_protocol_by_num = false;

	if (dict_has_dependents(dict)) {
		fr_rb_iter_inorder_t	iter;
		fr_dict_dependent_t	*dep;

		fr_strerror_printf("Refusing to free dictionary \"%s\", still has dependents", dict->root->name);

		for (dep = fr_rb_iter_init_inorder(dict->dependents, &iter);
		     dep;
		     dep = fr_rb_iter_next_inorder(dict->dependents, &iter)) {
			fr_strerror_printf_push("%s (%d)", dep->dependent, dep->count);
		}

		return -1;
	}

	/*
	 *	Free the hash tables with free functions first
	 *	so that the things the hash tables reference
	 *	are still there.
	 */
	talloc_free(dict->vendors_by_name);

	/*
	 *	Decrease the reference count on the validation
	 *	library we loaded.
	 */
	dl_free(dict->dl);

	if (dict == dict->gctx->internal) {
		dict->gctx->internal = NULL;
		dict->gctx->attr_protocol_encapsulation = NULL;
	}

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
		fr_strerror_const("Initialise global dictionary ctx with fr_dict_global_ctx_init()");
		return NULL;
	}

	dict = talloc_zero(ctx, fr_dict_t);
	if (!dict) {
		fr_strerror_const("Failed allocating memory for dictionary");
	error:
		talloc_free(dict);
		return NULL;
	}
	dict->gctx = dict_gctx;	/* Record which global context this was allocated in */
	talloc_set_destructor(dict, _dict_free);

	/*
	 *	A list of all the files that constitute this dictionary
	 */
	fr_dlist_talloc_init(&dict->filenames, fr_dict_filename_t, entry);

	/*
	 *	Pre-Allocate pool memory for rapid startup
	 *	As that's the working memory required during
	 *	dictionary initialisation.
	 */
	dict->pool = talloc_pool(dict, DICT_POOL_SIZE);
	if (!dict->pool) {
		fr_strerror_const("Failed allocating talloc pool for dictionary");
		goto error;
	}

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 */
	dict->vendors_by_name = fr_hash_table_alloc(dict, dict_vendor_name_hash, dict_vendor_name_cmp, hash_pool_free);
	if (!dict->vendors_by_name) {
		fr_strerror_printf("Failed allocating \"vendors_by_name\" table");
		goto error;
	}
	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	dict->vendors_by_num = fr_hash_table_alloc(dict, dict_vendor_pen_hash, dict_vendor_pen_cmp, NULL);
	if (!dict->vendors_by_num) {
		fr_strerror_printf("Failed allocating \"vendors_by_num\" table");
		goto error;
	}

	/*
	 *	Inter-dictionary reference caching
	 */
	dict->autoref = fr_hash_table_alloc(dict, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
	if (!dict->autoref) {
		fr_strerror_printf("Failed allocating \"autoref\" table");
		goto error;
	}

	/*
	 *	Who/what depends on this dictionary
	 */
	dict->dependents = fr_rb_inline_alloc(dict, fr_dict_dependent_t, node, _dict_dependent_cmp, NULL);

	/*
	 *	Set the default dictionary protocol, this can
	 *	be overriden by the protocol library.
	 */
	dict->proto = &dict_proto_default;

	return dict;
}

/** Allocate a new local dictionary
 *
 * @param[in] parent parent dictionary and talloc ctx
 * @return
 *	- NULL on memory allocation error.
 *
 *  This dictionary cannot define vendors, or inter-dictionary
 *  dependencies.  However, we initialize the relevant fields just in
 *  case.  We should arguably just skip initializing those fields, and
 *  just allow the server to crash if programmers do something stupid with it.
 */
fr_dict_t *fr_dict_protocol_alloc(fr_dict_t const *parent)
{
	fr_dict_t *dict;
	fr_dict_attr_t *da;

	fr_dict_attr_flags_t flags = {
		.is_root = true,
		.local = true,
		.internal = true,
		.type_size = parent->root->flags.type_size,
		.length = parent->root->flags.length,
	};

	dict = dict_alloc(UNCONST(fr_dict_t *, parent));
	if (!dict) return NULL;

	/*
	 *	Allocate the root attribute.  This dictionary is
	 *	always protocol "local", and number "0".
	 */
	da = dict_attr_alloc_root(dict->pool, parent, "local", 0,
				  &(dict_attr_args_t){ .flags = &flags });
	if (unlikely(!da)) {
		talloc_free(dict);
		return NULL;
	}

	da->last_child_attr = fr_dict_root(parent)->last_child_attr;

	dict->root = da;
	dict->root->dict = dict;
	dict->next = parent;

	DA_VERIFY(dict->root);

	return dict;
}

/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] dict	to free.
 * @param[in] dependent	that originally allocated this dictionary.
 * @return
 *	- 0 on success (dictionary freed).
 *	- 1 if other things still depend on the dictionary.
 *	- -1 on error (dependent doesn't exist)
 */
int fr_dict_const_free(fr_dict_t const **dict, char const *dependent)
{
	fr_dict_t **our_dict = UNCONST(fr_dict_t **, dict);

	return fr_dict_free(our_dict, dependent);
}

/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] dict	to free.
 * @param[in] dependent	that originally allocated this dictionary.
 * @return
 *	- 0 on success (dictionary freed).
 *	- 1 if other things still depend on the dictionary.
 *	- -1 on error (dependent doesn't exist)
 */
int fr_dict_free(fr_dict_t **dict, char const *dependent)
{
	if (!*dict) return 0;

	switch (dict_dependent_remove(*dict, dependent)) {
	case 0:		/* dependent has no more refs */
		if (!dict_has_dependents(*dict)) {
			talloc_free(*dict);
			return 0;
		}
		FALL_THROUGH;

	case 1:		/* dependent has more refs */
		return 1;

	default:	/* error */
		return -1;
	}
}

/** Process a dict_attr_autoload element to load/verify a dictionary attribute
 *
 * @param[in] to_load	attribute definition
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_enum_autoload(fr_dict_enum_autoload_t const *to_load)
{
	fr_dict_enum_autoload_t const	*p = to_load;
	fr_dict_enum_value_t const		*enumv;

	for (p = to_load; p->out; p++) {
		if (unlikely(!p->attr)) {
			fr_strerror_printf("Invalid attribute autoload entry for \"%s\", missing attribute pointer", p->name);
			return -1;
		}

		if (unlikely(!*p->attr)) {
			fr_strerror_printf("Can't resolve value \"%s\", attribute not loaded", p->name);
			fr_strerror_printf_push("Check fr_dict_attr_autoload_t struct has "
						"an entry to load the attribute \"%s\" is located in, and that "
						"the fr_dict_autoload_attr_t symbol name is correct", p->name);
			return -1;
		}

		enumv = fr_dict_enum_by_name(*(p->attr), p->name, -1);
		if (!enumv) {
			fr_strerror_printf("Value '%s' not found in \"%s\" attribute",
					   p->name, (*(p->attr))->name);
			return -1;
		}

		if (p->out) *(p->out) = enumv->value;
	}

	return 0;
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
	fr_dict_attr_t const		*root = NULL;

	for (p = to_load; p->out; p++) {
		if (!p->dict) {
			fr_strerror_printf("Invalid attribute autoload entry for \"%s\", missing dictionary pointer", p->name);
			return -1;
		}

		if (!*p->dict) {
			fr_strerror_printf("Autoloader autoloader can't resolve attribute \"%s\", dictionary not loaded", p->name);
			fr_strerror_printf_push("Check fr_dict_autoload_t struct has "
						"an entry to load the dictionary \"%s\" is located in, and that "
						"the fr_dict_autoload_t symbol name is correct", p->name);
			return -1;
		}

		if (!root || (root->dict != *p->dict) || (p->name[0] != '.')) {
			root = (*p->dict)->root;
		}

		if (p->name[0] == '.') {
			da = fr_dict_attr_by_oid(NULL, root, p->name + 1);
			if (!da) {
				fr_strerror_printf("Autoloader attribute \"%s\" not found in \"%s\" dictionary under attribute %s", p->name,
						   *p->dict ? (*p->dict)->root->name : "internal", root->name);
				return -1;
			}
		} else {
			da = fr_dict_attr_by_oid(NULL, fr_dict_root(*p->dict), p->name);
			if (!da) {
				fr_strerror_printf("Autoloader attribute \"%s\" not found in \"%s\" dictionary", p->name,
						   *p->dict ? (*p->dict)->root->name : "internal");
				return -1;
			}

			if (fr_type_is_structural(da->type)) root = da;
		}

		if (da->type != p->type) {
			fr_strerror_printf("Autoloader attribute \"%s\" should be type %s, but defined as type %s", da->name,
					   fr_type_to_str(p->type),
					   fr_type_to_str(da->type));
			return -1;
		}

		DA_VERIFY(da);

		if (p->out) *(p->out) = da;
	}

	return 0;
}

/** Process a dict_autoload element to load a protocol
 *
 * @param[in] to_load	dictionary definition.
 * @param[in] dependent	that is loading this dictionary.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_dict_autoload(fr_dict_autoload_t const *to_load, char const *dependent)
{
	fr_dict_autoload_t const	*p;

	for (p = to_load; p->out; p++) {
		fr_dict_t *dict = NULL;

		if (unlikely(!p->proto)) {
			fr_strerror_const("autoload missing parameter proto");
			return -1;
		}

		/*
		 *	Load the internal dictionary
		 */
		if (strcmp(p->proto, "freeradius") == 0) {
			if (fr_dict_internal_afrom_file(&dict, p->proto, dependent) < 0) return -1;
		} else {
			if (fr_dict_protocol_afrom_file(&dict, p->proto, p->base_dir, dependent) < 0) return -1;
		}

		*(p->out) = dict;
	}

	return 0;
}


/** Decrement the reference count on a previously loaded dictionary
 *
 * @param[in] to_free	previously loaded dictionary to free.
 * @param[in] dependent	that originally allocated this dictionary
 */
int _fr_dict_autofree(fr_dict_autoload_t const *to_free, char const *dependent)
{
	fr_dict_autoload_t const *p;

	for (p = to_free; p->out; p++) {
		int ret;

		if (!*p->out) continue;
		ret = fr_dict_const_free(p->out, dependent);

		if (ret == 0) *p->out = NULL;
		if (ret < 0) return -1;
	}

	return 0;
}

/** Structure used to managed the lifetime of a dictionary
 *
 * This should only be used when dictionaries are being dynamically loaded during
 * compilation.  It should not be used to load dictionaries at runtime, or if
 * modules need to load dictionaries (use static fr_dict_autoload_t defs).

 */
struct fr_dict_autoload_talloc_s {
	fr_dict_autoload_t load[2];		//!< Autoloader def.
	char const *dependent;			//!< Dependent that loaded the dictionary.
};

/** Talloc destructor to automatically free dictionaries
 *
 * @param[in] to_free	dictionary autoloader definition describing the dictionary to free.
 */
static int _fr_dict_autoload_talloc_free(fr_dict_autoload_talloc_t const *to_free)
{
	return _fr_dict_autofree(to_free->load, to_free->dependent);
}

/** Autoload a dictionary and bind the lifetime to a talloc chunk
 *
 * Mainly useful for resolving "forward" references from unlang immediately.
 *
 * @note If the talloc chunk is freed it does not mean the dictionary will
 *	 be immediately freed.  It will be freed when all other references
 *	 to the dictionary are gone.
 *
 * @param[in] ctx	to bind the dictionary lifetime to.
 * @param[out] out	pointer to the loaded dictionary.
 * @param[in] proto	to load.
 * @param[in] dependent to register this reference to.  Will be dupd.
 */
fr_dict_autoload_talloc_t *_fr_dict_autoload_talloc(TALLOC_CTX *ctx, fr_dict_t const **out, char const *proto, char const *dependent)
{
	fr_dict_autoload_talloc_t *dict_ref;
	int ret;

	dict_ref = talloc(ctx, fr_dict_autoload_talloc_t);
	if (unlikely(dict_ref == NULL)) {
	oom:
		fr_strerror_const("Out of memory");
		return NULL;
	}

	dict_ref->load[0] = (fr_dict_autoload_t){ .proto = proto, .out = out};
	dict_ref->load[1] = (fr_dict_autoload_t) DICT_AUTOLOAD_TERMINATOR;
	dict_ref->dependent = talloc_strdup(dict_ref, dependent);
	if (unlikely(dict_ref->dependent == NULL)) {
		talloc_free(dict_ref);
		goto oom;
	}

	ret = _fr_dict_autoload(dict_ref->load, dependent);
	if (ret < 0) {
		talloc_free(dict_ref);
		return NULL;
	}

	return dict_ref;
}

/** Callback to automatically resolve enum values
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	An array of fr_dict_enum_autoload_t to load.
 * @param[in] user_ctx	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dl_dict_enum_autoload(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	if (fr_dict_enum_autoload((fr_dict_enum_autoload_t *)symbol) < 0) return -1;

	return 0;
}

/** Callback to automatically resolve attributes and check the types are correct
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	An array of fr_dict_attr_autoload_t to load.
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

static int _dict_global_free_at_exit(void *uctx)
{
	return talloc_free(uctx);
}

static int _dict_global_free(fr_dict_gctx_t *gctx)
{
	fr_hash_iter_t	iter;
	fr_dict_t	*dict;
	bool		still_loaded = false;

	/*
	 *	Make sure this doesn't fire later and mess
	 *	things up...
	 */
	if (gctx->free_at_exit) fr_atexit_global_disarm(true, _dict_global_free_at_exit, gctx);

	/*
	 *	Free up autorefs first, which will free up inter-dictionary dependencies.
	 */
	for (dict = fr_hash_table_iter_init(gctx->protocol_by_name, &iter);
	     dict;
	     dict = fr_hash_table_iter_next(gctx->protocol_by_name, &iter)) {
		(void)talloc_get_type_abort(dict, fr_dict_t);

		if (dict_autoref_free(dict) < 0) return -1;
	}

	for (dict = fr_hash_table_iter_init(gctx->protocol_by_name, &iter);
	     dict;
	     dict = fr_hash_table_iter_next(gctx->protocol_by_name, &iter)) {
	     	(void)talloc_get_type_abort(dict, fr_dict_t);
	     	dict_dependent_remove(dict, "global");			/* remove our dependency */

		if (talloc_free(dict) < 0) {
#ifndef NDEBUG
			FR_FAULT_LOG("gctx failed to free dictionary %s - %s", dict->root->name, fr_strerror());
#endif
			still_loaded = true;
		}
	}

	/*
	 *	Free the internal dictionary as the last step, after all of the protocol dictionaries and
	 *	libraries have freed their references to it.
	 */
	if (gctx->internal) {
		dict_dependent_remove(gctx->internal, "global");	/* remove our dependency */

		if (talloc_free(gctx->internal) < 0) still_loaded = true;
	}

	if (still_loaded) {
#ifndef NDEBUG
		fr_dict_gctx_debug(stderr, gctx);
#endif
		return -1;
	}

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
 * @param[in] ctx		to allocate global resources in.
 * @param[in] free_at_exit	Install an at_exit handler to free the global ctx.
 *				This is useful when dictionaries are held by other
 *				libraries which free them using atexit handlers.
 * @param[in] dict_dir		the default location for the dictionaries.
 * @return
 *	- A pointer to the new global context on success.
 *	- NULL on failure.
 */
fr_dict_gctx_t *fr_dict_global_ctx_init(TALLOC_CTX *ctx, bool free_at_exit, char const *dict_dir)
{
	fr_dict_gctx_t *new_ctx;

	if (!dict_dir) {
		fr_strerror_const("No dictionary location provided");
		return NULL;
	}

	new_ctx = talloc_zero(ctx, fr_dict_gctx_t);
	if (!new_ctx) {
		fr_strerror_const("Out of Memory");
		return NULL;
	}
	new_ctx->perm_check = true;	/* Check file permissions by default */

	new_ctx->protocol_by_name = fr_hash_table_alloc(new_ctx, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
	if (!new_ctx->protocol_by_name) {
		fr_strerror_const("Failed initializing protocol_by_name hash");
	error:
		talloc_free(new_ctx);
		return NULL;
	}

	new_ctx->protocol_by_num = fr_hash_table_alloc(new_ctx, dict_protocol_num_hash, dict_protocol_num_cmp, NULL);
	if (!new_ctx->protocol_by_num) {
		fr_strerror_const("Failed initializing protocol_by_num hash");
		goto error;
	}

	new_ctx->dict_dir_default = talloc_strdup(new_ctx, dict_dir);
	if (!new_ctx->dict_dir_default) goto error;

	new_ctx->dict_loader = dl_loader_init(new_ctx, NULL, false, false);
	if (!new_ctx->dict_loader) goto error;

	new_ctx->free_at_exit = free_at_exit;

	talloc_set_destructor(new_ctx, _dict_global_free);

	if (!dict_gctx) dict_gctx = new_ctx;	/* Set as the default */

	if (free_at_exit) fr_atexit_global(_dict_global_free_at_exit, new_ctx);

	return new_ctx;
}

/** Set whether we check dictionary file permissions
 *
 * @param[in] gctx	to alter.
 * @param[in] enable	Whether we should check file permissions as they're loaded.
 */
void fr_dict_global_ctx_perm_check(fr_dict_gctx_t *gctx, bool enable)
{
	gctx->perm_check = enable;
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
	if (dict_gctx == gctx) dict_gctx = NULL;

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

char const *fr_dict_global_ctx_dir(void)
{
	return dict_gctx->dict_dir_default;
}

/** Mark all dictionaries and the global dictionary ctx as read only
 *
 * Any attempts to add new attributes will now fail.
 */
void fr_dict_global_ctx_read_only(void)
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
	     	dict_hash_tables_finalise(dict);
		dict->read_only = true;
	}

	dict = dict_gctx->internal;
	dict_hash_tables_finalise(dict);
	dict->read_only = true;
	dict_gctx->read_only = true;
}

/** Dump information about currently loaded dictionaries
 *
 * Intended to be called from a debugger
 */
void fr_dict_gctx_debug(FILE *fp, fr_dict_gctx_t const *gctx)
{
	fr_hash_iter_t			dict_iter;
	fr_dict_t			*dict;
	fr_rb_iter_inorder_t		dep_iter;
	fr_dict_dependent_t		*dep;

	if (gctx == NULL) gctx = dict_gctx;

	if (!gctx) {
		fprintf(fp, "gctx not initialised\n");
		return;
	}

	fprintf(fp, "gctx %p report\n", dict_gctx);
	for (dict = fr_hash_table_iter_init(gctx->protocol_by_num, &dict_iter);
	     dict;
	     dict = fr_hash_table_iter_next(gctx->protocol_by_num, &dict_iter)) {
		for (dep = fr_rb_iter_init_inorder(dict->dependents, &dep_iter);
		     dep;
		     dep = fr_rb_iter_next_inorder(dict->dependents, &dep_iter)) {
			fprintf(fp, "\t%s is referenced from %s count (%d)\n",
				dict->root->name, dep->dependent, dep->count);
		}
	}

	if (gctx->internal) {
		for (dep = fr_rb_iter_init_inorder(gctx->internal->dependents, &dep_iter);
		     dep;
		     dep = fr_rb_iter_next_inorder(gctx->internal->dependents, &dep_iter)) {
			fprintf(fp, "\t%s is referenced from %s count (%d)\n",
				gctx->internal->root->name, dep->dependent, dep->count);
		}
	}
}

/** Iterate protocols by name
 *
 */
fr_dict_t *fr_dict_global_ctx_iter_init(fr_dict_global_ctx_iter_t *iter)
{
	if (!dict_gctx) return NULL;

	return fr_hash_table_iter_init(dict_gctx->protocol_by_name, iter);
}

fr_dict_t *fr_dict_global_ctx_iter_next(fr_dict_global_ctx_iter_t *iter)
{
	if (!dict_gctx) return NULL;

	return fr_hash_table_iter_next(dict_gctx->protocol_by_name, iter);
}


/** Coerce to non-const
 *
 */
fr_dict_t *fr_dict_unconst(fr_dict_t const *dict)
{
	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}
	return UNCONST(fr_dict_t *, dict);
}

/** Coerce to non-const
 *
 */
fr_dict_attr_t *fr_dict_attr_unconst(fr_dict_attr_t const *da)
{
	fr_dict_t *dict;

	dict = dict_by_da(da);
	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}

	return UNCONST(fr_dict_attr_t *, da);
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
	bool alnum = false;

	if (len < 0) len = strlen(name);

	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_const("Attribute name is too long");
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

		alnum |= sbuff_char_alpha_num[(uint8_t)*p];

		p++;
	}

	if (!alnum) {
		fr_strerror_const("Invalid attribute name");
		return -1;
	}

	return len;
}

ssize_t fr_dict_valid_oid_str(char const *name, ssize_t len)
{
	char const *p = name, *end;
	bool alnum = false;

	if (len < 0) len = strlen(name);
	end = p + len;

	do {
		if (!fr_dict_attr_allowed_chars[(uint8_t)*p] && (*p != '.')) {
			fr_strerror_printf("Invalid character '%pV' in oid string \"%pV\"",
					   fr_box_strvalue_len(p, 1), fr_box_strvalue_len(name, len));

			return -(p - name);
		}

		alnum |= sbuff_char_alpha_num[(uint8_t)*p];
		p++;
	} while (p < end);

	if (!alnum) return 0;

	return len;
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


void fr_dict_attr_verify(char const *file, int line, fr_dict_attr_t const *da)
{
	int i;
	fr_dict_attr_t const *da_p;

	if (!da) fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t pointer was NULL", file, line);

	(void) talloc_get_type_abort_const(da, fr_dict_attr_t);

	if ((!da->flags.is_root) && (da->depth == 0)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t %s vendor: %u, attr %u: "
				     "Is not root, but depth is 0",
				     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr);
	}

	if (da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t %s vendor: %u, attr %u: "
				     "Indicated depth (%u) greater than TLV stack depth (%d)",
				     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr,
				     da->depth, FR_DICT_MAX_TLV_STACK);
	}

	for (da_p = da; da_p; da_p = da_p->next) {
		(void) talloc_get_type_abort_const(da_p, fr_dict_attr_t);
	}

	for (i = da->depth, da_p = da; (i >= 0) && da; i--, da_p = da_p->parent) {
		if (!da_p) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t %s vendor: %u, attr %u: "
					     "Depth indicated there should be a parent, but parent is NULL",
					     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr);
		}
		if (i != (int)da_p->depth) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t %s vendor: %u, attr %u: "
					     "Depth out of sequence, expected %i, got %u",
					     file, line, da->name, fr_dict_vendor_num_by_da(da), da->attr, i, da_p->depth);
		}

	}

	if ((i + 1) < 0) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: fr_dict_attr_t top of hierarchy was not at depth 0",
				     file, line);
	}

	if (da->parent && (da->parent->type == FR_TYPE_VENDOR) && !fr_dict_attr_has_ext(da, FR_DICT_ATTR_EXT_VENDOR)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%d]: VSA missing 'vendor' extension", file, line);
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
	{
		fr_hash_table_t *ht;

		if (da->type == FR_TYPE_GROUP) break;

		fr_assert_msg(fr_dict_attr_has_ext(da, FR_DICT_ATTR_EXT_CHILDREN),
			      "CONSISTENCY CHECK FAILED %s[%d]: %s missing 'children' extension",
			      file, line,
			      fr_type_to_str(da->type));

		fr_assert_msg(fr_dict_attr_has_ext(da, FR_DICT_ATTR_EXT_NAMESPACE),
			      "CONSISTENCY CHECK FAILED %s[%d]: %s missing 'namespace' extension",
			      file, line,
			      fr_type_to_str(da->type));

		/*
		 *	Check the namespace hash table is ok
		 */
		ht = dict_attr_namespace(da);
		if (unlikely(!ht)) break;
		fr_hash_table_verify(ht);
	}
		break;

	default:
		break;
	}
}

/** See if a structural da is allowed to contain another da
 *
 *  We have some complex rules with different structural types,
 *  different protocol dictionaries, references to other protocols,
 *  etc.
 *
 *  @param[in] parent	The parent da, must be structural
 *  @param[in] child	The alleged child
 *  @return
 *	- false - the child is not allowed to be contained by the parent
 *	- true - the child is allowed to be contained by the parent
 */
bool fr_dict_attr_can_contain(fr_dict_attr_t const *parent, fr_dict_attr_t const *child)
{
	/*
	 *	This is the common case: child is from the parent.
	 */
	if (child->parent == parent) return true;

	if (child->flags.is_raw) return true; /* let people do stupid things */

	/*
	 *	Only structural types can have children.
	 */
	if (!fr_type_structural[parent->type]) return false;

	/*
	 *	An internal attribute can go into any other container.
	 *
	 *	Any other attribute can go into an internal structural
	 *	attribute, because why not?
	 */
	if (dict_gctx) {
		if (child->dict == dict_gctx->internal) return true;

		if (parent->dict == dict_gctx->internal) return true;
	}

	/*
	 *	Anything can go into internal groups.
	 */
	if ((parent->type == FR_TYPE_GROUP) && parent->flags.internal) return true;

	/*
	 *	Protocol attributes have to be in the same dictionary.
	 *
	 *	Unless they're a cross-protocol grouping attribute.
	 *	In which case we check if the ref is the same.
	 */
	if (child->dict != parent->dict) {
		fr_dict_attr_t const *ref;

		ref = fr_dict_attr_ref(parent);

		return (ref && (ref->dict == child->dict));
	}

	/*
	 *	Key fields can have children, but everyone else thinks
	 *	that the struct is the parent.  <sigh>
	 */
	if ((parent->type == FR_TYPE_STRUCT) && child->parent->parent == parent) return true;

	/*
	 *	We're in the same protocol dictionary, but the child
	 *	isn't directly from the parent.  Therefore the only
	 *	type of same-protocol structure it can go into is a
	 *	group.
	 */
	return (parent->type == FR_TYPE_GROUP);
}

/** Return the protocol descriptor for the dictionary.
 *
 */
fr_dict_protocol_t const *fr_dict_protocol(fr_dict_t const *dict)
{
	return dict->proto;
}

/*
 *	Get the real protocol namespace behind a local one.
 */
fr_dict_attr_t const *fr_dict_unlocal(fr_dict_attr_t const *da)
{
	if (!da->flags.local) return da;

	fr_assert(da->dict->root == da);

	while (da->dict->next) {
		da = da->dict->next->root;
	}

	return da;
}

/*
 *	Get the real protocol dictionary behind a local one.
 */
fr_dict_t const	*fr_dict_proto_dict(fr_dict_t const *dict)
{
	while (dict->next) dict = dict->next;

	return dict;
}

int fr_dict_attr_set_group(fr_dict_attr_t **da_p, fr_dict_attr_t const *ref)
{
	if ((*da_p)->type == FR_TYPE_GROUP) {
		fr_assert(fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_REF) != NULL);
		return 0;
	}

	(*da_p)->type = FR_TYPE_GROUP;
	(*da_p)->flags.type_size = 0;
	(*da_p)->flags.length = 0;

	fr_assert(fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_REF) == NULL);

	return dict_attr_ref_aset(da_p, ref, FR_DICT_ATTR_REF_ALIAS);
}
