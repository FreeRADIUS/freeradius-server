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

bool			dict_initialised = false;
char			*dict_dir_default;		//!< The default location for loading dictionaries if one
							///< wasn't provided.
TALLOC_CTX		*dict_ctx;

static dl_loader_t	*dict_loader;			//!< for protocol validation

static fr_hash_table_t	*protocol_by_name = NULL;	//!< Hash containing names of all the registered protocols.
static fr_hash_table_t	*protocol_by_num = NULL;	//!< Hash containing numbers of all the registered protocols.

fr_table_num_ordered_t const date_precision_table[] = {
	{ "microseconds",	FR_TIME_RES_USEC },
	{ "us",			FR_TIME_RES_USEC },

	{ "nanoseconds",	FR_TIME_RES_NSEC },
	{ "ns",			FR_TIME_RES_NSEC },

	{ "milliseconds",	FR_TIME_RES_MSEC },
	{ "ms",			FR_TIME_RES_MSEC },

	{ "seconds",		FR_TIME_RES_SEC },
	{ "s",			FR_TIME_RES_SEC }

};
size_t date_precision_table_len = NUM_ELEMENTS(date_precision_table);

static fr_table_num_ordered_t const dhcpv6_subtype_table[] = {
	{ "dns_label",			FLAG_ENCODE_DNS_LABEL },
	{ "encode=dns_label",		FLAG_ENCODE_DNS_LABEL },
};
static size_t dhcpv6_subtype_table_len = NUM_ELEMENTS(dhcpv6_subtype_table);

static fr_table_num_ordered_t const eap_aka_sim_subtype_table[] = {
	{ "encrypt=aes-cbc",		1 }, /* any non-zero value will do */
};
static size_t eap_aka_sim_subtype_table_len = NUM_ELEMENTS(eap_aka_sim_subtype_table);

/** Magic internal dictionary
 *
 * Internal dictionary is checked in addition to the protocol dictionary
 * when resolving attribute names.
 *
 * This is because internal attributes are valid for every
 * protocol.
 */
fr_dict_t	*fr_dict_internal = NULL;	//!< Internal server dictionary.

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
	[FR_TYPE_ABINARY]	= {32, ~0},

	[FR_TYPE_TLV]		= {2, ~0},
	[FR_TYPE_STRUCT]	= {1, ~0},

	[FR_TYPE_EXTENDED]	= {1, ~0},

	[FR_TYPE_VSA]		= {4, ~0},

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

/** Hash a dictionary name
 *
 */
static uint32_t dict_enum_name_hash(void const *data)
{
	uint32_t hash;
	fr_dict_enum_t const *enumv = data;

	hash = dict_hash_name((void const *)enumv->name, enumv->name_len);

	return fr_hash_update(&enumv->da, sizeof(enumv->da), hash);		//-V568
}

/** Compare two dictionary attribute enum values
 *
 */
static int dict_enum_name_cmp(void const *one, void const *two)
{
	int rcode;
	fr_dict_enum_t const *a = one;
	fr_dict_enum_t const *b = two;

	rcode = a->da - b->da;
	if (rcode != 0) return rcode;

	return strcasecmp(a->name, b->name);
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

/** Allocate a dictionary attribute and assign a name
 *
 * @param[in] ctx		to allocate attribute in.
 * @param[in] name		to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
fr_dict_attr_t *dict_attr_alloc_name(TALLOC_CTX *ctx, char const *name)
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

	if (!fr_cond_assert(parent)) return NULL;

	/*
	 *	Allocate a new attribute
	 */
	if (!name) {
		char		buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];
		char		*p = buffer;
		size_t		len;
		size_t		need;
		fr_dict_attr_t	tmp;

		memset(&tmp, 0, sizeof(tmp));
		dict_attr_init(&tmp, parent, attr, type, flags);

		len = snprintf(p, sizeof(buffer), "Attr-");
		p += len;

		fr_dict_print_attr_oid(&need, p, sizeof(buffer) - (p - buffer), NULL, &tmp);
		if (need > 0) {
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

	/*
	 *	Set the subtype flags and other necessary things.
	 */
	switch (dict->root->attr) {
	case FR_PROTOCOL_DHCPV6:
		dict->subtype_table = dhcpv6_subtype_table;
		dict->subtype_table_len = dhcpv6_subtype_table_len;
		dict->default_type_size = 2;
		dict->default_type_length = 2;
		break;

	case FR_PROTOCOL_EAP_AKA_SIM:
		dict->subtype_table = eap_aka_sim_subtype_table;
		dict->subtype_table_len = eap_aka_sim_subtype_table_len;
		break;

	default:
		break;
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
int dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child)
{
	fr_dict_attr_t const * const *bin;
	fr_dict_attr_t **this;

	/*
	 *	Setup fields in the child
	 */
	child->parent = parent;
	child->depth = parent->depth + 1;

	DA_VERIFY(child);

	switch (parent->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_STRUCT:
	case FR_TYPE_EXTENDED:
		break;

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
		/*
		 *	Children are allowed here, but ONLY if this
		 *	attribute is a key field.
		 */
		if (parent->parent && (parent->parent->type == FR_TYPE_STRUCT) && da_is_key_field(parent)) break;
		/* FALL-THROUGH */

	default:
		fr_strerror_printf("Cannot add children to attribute '%s' of type %s",
				   parent->name, fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
		return false;
	}

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
int dict_attr_add_by_name(fr_dict_t *dict, fr_dict_attr_t *da)
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
		    FLAGS_EQUAL(has_tag) && FLAGS_EQUAL(array) && FLAGS_EQUAL(concat) && FLAGS_EQUAL(subtype)) {
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
int fr_dict_enum_add_name(fr_dict_attr_t const *da, char const *name,
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

	if (!*name) {
		fr_strerror_printf("%s: Empty names are not permitted", __FUNCTION__);
		return -1;
	}

	len = strlen(name);
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
	enumv->name = talloc_typed_strdup(enumv, name);
	enumv->name_len = strlen(name);
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
	enumv->da = da;

	/*
	 *	Add the value into the dictionary.
	 */
	{
		fr_dict_attr_t *tmp;
		memcpy(&tmp, &enumv, sizeof(tmp));

		if (!fr_hash_table_insert(dict->values_by_name, tmp)) {
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

			fr_strerror_printf("Duplicate VALUE name \"%s\" for attribute \"%s\". "
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
		if (!fr_hash_table_replace(dict->values_by_da, enumv)) {
			fr_strerror_printf("%s: Failed inserting value %s", __FUNCTION__, name);
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

/** Add an name to an integer attribute hashing the name for the integer value
 *
 */
int fr_dict_enum_add_name_next(fr_dict_attr_t const *da, char const *name)
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
		return fr_dict_enum_add_name(da, name, &v, false, false);
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
		break;

	default:
		fr_strerror_printf("Wrong type for vendor root, expected '%s', got '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_VSA, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, vendor_root->type, "<INVALID>"));
		return NULL;
	}

	vendor = fr_dict_attr_child_by_num(vendor_root, vendor_pen);
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
	 *	We return the child of the referenced attribute, and
	 *	not of the "group" attribute.
	 */
	if (parent->type == FR_TYPE_GROUP) {
		parent = parent->ref;
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
	 *	First, look up names.
	 */
	enumv.da = da;
	enumv.name = "";
	enumv.name_len = 0;

	/*
	 *	Look up the attribute name target, and use
	 *	the correct attribute number if found.
	 */
	dv = fr_hash_table_finddata(dict->values_by_name, &enumv);
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
char const *fr_dict_enum_name_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value)
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

	return dv->name;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_enum_t *fr_dict_enum_by_name(fr_dict_attr_t const *da, char const *name, ssize_t len)
{
	fr_dict_enum_t	*found;
	fr_dict_enum_t	find = {
				.da = da,
				.name = name
			};
	fr_dict_t	*dict;

	if (!name) return NULL;

	dict = fr_dict_by_da(da);
	if (!dict) {
		fr_strerror_printf("Attributes \"%s\" not present in any dictionaries", da->name);
		return NULL;
	}

	if (len < 0) len = strlen(name);
	find.name_len = (size_t)len;

	/*
	 *	Look up the attribute name target, and use
	 *	the correct attribute number if found.
	 */
	found = fr_hash_table_finddata(dict->values_by_name, &find);
	if (found) find.da = found->da;

	return fr_hash_table_finddata(dict->values_by_name, &find);
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
	dict->dl = dl_by_name(dict_loader, module_name, dict, false);

	talloc_free(module_name);
	return 0;
}

static int _dict_free_autoref(UNUSED void *ctx, void *data)
{
	fr_dict_t *dict = data;

	talloc_decrease_ref_count(dict);
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

	if (dict->autoref &&
	    (fr_hash_table_walk(dict->autoref, _dict_free_autoref, NULL) < 0)) {
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
fr_dict_t *dict_alloc(TALLOC_CTX *ctx)
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
	 *	Pre-Allocate pool memory for rapid startup
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
	 *	Inter-dictionary reference caching
	 */
	dict->autoref = fr_hash_table_create(dict, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);

	/*
	 *	Horrible hacks for combo-IP.
	 */
	dict->attributes_combo = fr_hash_table_create(dict, dict_attr_combo_hash, dict_attr_combo_cmp, hash_pool_free);
	if (!dict->attributes_combo) goto error;

	dict->values_by_name = fr_hash_table_create(dict, dict_enum_name_hash, dict_enum_name_cmp, hash_pool_free);
	if (!dict->values_by_name) goto error;

	dict->values_by_da = fr_hash_table_create(dict, dict_enum_value_hash, dict_enum_value_cmp, hash_pool_free);
	if (!dict->values_by_da) goto error;

	/*
	 *	Set default type size and length.
	 */
	dict->default_type_size = 1;
	dict->default_type_length = 1;

	return dict;
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

static void _fr_dict_dump(fr_dict_t const *dict, fr_dict_attr_t const *da, unsigned int lvl)
{
	unsigned int		i;
	size_t			len;
	fr_dict_attr_t const	*p;
	char			flags[256];

	fr_dict_snprint_flags(flags, sizeof(flags), dict, da->type, &da->flags);

	printf("[%02i] 0x%016" PRIxPTR "%*s %s(%u) %s %s\n", lvl, (unsigned long)da, lvl * 2, " ",
	       da->name, da->attr, fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"), flags);

	len = talloc_array_length(da->children);
	for (i = 0; i < len; i++) {
		for (p = da->children[i]; p; p = p->next) {
			_fr_dict_dump(dict, p, lvl + 1);
		}
	}
}

void fr_dict_dump(fr_dict_t const *dict)
{
	_fr_dict_dump(dict, dict->root, 0);
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

	return 0;
}

/** Initialise the global protocol hashes
 *
 * @note Must be called before any other dictionary functions.
 *
 * @param[in] ctx	to allocate global resources in.
 * @param[in] dict_dir	the default location for the dictionaries.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_global_init(TALLOC_CTX *ctx, char const *dict_dir)
{
	TALLOC_FREE(dict_ctx);
	dict_ctx = ctx;

	if (!protocol_by_name) {
		protocol_by_name = fr_hash_table_create(dict_ctx, dict_protocol_name_hash, dict_protocol_name_cmp, NULL);
		if (!protocol_by_name) {
			fr_strerror_printf("Failed initializing protocol_by_name hash");
			return -1;
		}
	}

	if (!protocol_by_num) {
		protocol_by_num = fr_hash_table_create(dict_ctx, dict_protocol_num_hash, dict_protocol_num_cmp, NULL);
		if (!protocol_by_num) {
			fr_strerror_printf("Failed initializing protocol_by_num hash");
			return -1;
		}
	}

	talloc_free(dict_dir_default);		/* Free previous value */
	dict_dir_default = talloc_strdup(dict_ctx, dict_dir);

	dict_loader = dl_loader_init(ctx, NULL, NULL, false, false);
	if (!dict_loader) return -1;

	if (dl_symbol_init_cb_register(dict_loader, 0, "dict_protocol", dict_onload_func, NULL) < 0) {
		return -1;
	}

	dict_initialised = true;

	return 0;
}

/** Allow the default dict dir to be changed after initialisation
 *
 * @param[in] dict_dir	New default dict dir to use.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_dir_set(char const *dict_dir)
{
	talloc_free(dict_dir_default);		/* Free previous value */
	dict_dir_default = talloc_strdup(dict_ctx, dict_dir);
	if (!dict_dir_default) return -1;

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
	int i, start;

	if (!parent || !parent->children || !prev) return NULL;

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
	for (i = start; i < 256; i++) {
		bin = &parent->children[i & 0xff];

		if (*bin) return *bin;
	}

	return NULL;
}

/** Coerce to non-const
 *
 */
fr_dict_t *fr_dict_coerce(fr_dict_t const *dict)
{
	fr_dict_t *mutable;

	memcpy(&mutable, &dict, sizeof(dict));
	return mutable;
}
