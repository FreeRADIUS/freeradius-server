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

/**
 * @file lib/util/dict.c
 * @brief Functions to parse FreeRADIUS dictionary file(s).
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#ifdef WITH_DHCP
#  include <freeradius-devel/dhcpv4/dhcpv4.h>
#endif

#include <ctype.h>

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#define MAX_ARGV (16)

/** Magic internal dictionary
 *
 * Internal dictionary is checked in addition to the protocol dictionary
 * when resolving attribute names.
 *
 * This is because internal attributes are valid for every
 * protocol.
 */
fr_dict_t	*fr_dict_internal = NULL;	//!< Internal server dictionary.

/*
 *	For faster HUP's, we cache the stat information for
 *	files we've $INCLUDEd
 */
typedef struct dict_stat_t {
	struct dict_stat_t *next;
	struct stat stat_buf;
} dict_stat_t;

/** A temporary enum value, which we'll resolve later
 *
 */
typedef struct dict_enum_fixup_t {
	char *attribute;		//!< we couldn't find (and will need to resolve later).
	char *alias;			//!< Raw enum name.
	char *value;			//!< Raw enum value.  We can't do anything with this until
					//!< we know the attribute type, which we only find out later.

	struct dict_enum_fixup_t *next;	//!< Next in the linked list of fixups.
} dict_enum_fixup_t;

/** Vendors and attribute names
 *
 * It's very likely that the same vendors will operate in multiple
 * protocol spaces, but number their attributes differently, so we need
 * per protocol dictionaries.
 *
 * There would also be conflicts for DHCP(v6)/RADIUS attributes etc...
 */
struct fr_dict {
	dict_enum_fixup_t	*enum_fixup;

	dict_stat_t		*stat_head;
	dict_stat_t		*stat_tail;

	fr_hash_table_t		*vendors_by_name;	//!< Lookup vendor by name.
	fr_hash_table_t		*vendors_by_num;	//!< Lookup vendor by PEN.

	fr_hash_table_t		*attributes_by_name;	//!< Allow attribute lookup by unique name.

	fr_hash_table_t		*attributes_combo;	//!< Lookup variants of polymorphic attributes.

	fr_hash_table_t		*values_by_da;		//!< Lookup an attribute enum by its value.
	fr_hash_table_t		*values_by_alias;	//!< Lookup an attribute enum by its alias name.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.
	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce allocs.
};

/** Map data types to names representing those types
 */
FR_NAME_NUMBER const dict_attr_types[] = {
	{ "string",		FR_TYPE_STRING },
	{ "octets",		FR_TYPE_OCTETS },

	{ "ipaddr",		FR_TYPE_IPV4_ADDR },
	{ "ipv4prefix",		FR_TYPE_IPV4_PREFIX },
	{ "ipv6addr",		FR_TYPE_IPV6_ADDR },
	{ "ipv6prefix",		FR_TYPE_IPV6_PREFIX },
	{ "ifid",		FR_TYPE_IFID },
	{ "combo-ip",		FR_TYPE_COMBO_IP_ADDR },
	{ "combo-prefix",	FR_TYPE_COMBO_IP_PREFIX },
	{ "ether",		FR_TYPE_ETHERNET },

	{ "bool",		FR_TYPE_BOOL },

	{ "uint8",        	FR_TYPE_UINT8 },
	{ "uint16",        	FR_TYPE_UINT16 },
	{ "uint32",		FR_TYPE_UINT32 },
	{ "uint64",		FR_TYPE_UINT64 },

	{ "int8",		FR_TYPE_INT8 },
	{ "int16",		FR_TYPE_INT16 },
	{ "int32",         	FR_TYPE_INT32 },
	{ "int64",		FR_TYPE_INT64 },

	{ "float32",		FR_TYPE_FLOAT32 },
	{ "float64",		FR_TYPE_FLOAT64 },

	{ "timeval",		FR_TYPE_TIMEVAL },
	{ "date",		FR_TYPE_DATE },
	{ "date_milliseconds",	FR_TYPE_DATE_MILLISECONDS },
	{ "date_microseconds",	FR_TYPE_DATE_MICROSECONDS },
	{ "date_nanoseconds",	FR_TYPE_DATE_NANOSECONDS },

	{ "abinary",		FR_TYPE_ABINARY },

	{ "size",		FR_TYPE_SIZE },

	{ "tlv",		FR_TYPE_TLV },
	{ "struct",        	FR_TYPE_STRUCT },

	{ "extended",      	FR_TYPE_EXTENDED },
	{ "long-extended", 	FR_TYPE_LONG_EXTENDED },

	{ "vsa",          	FR_TYPE_VSA },
	{ "evs",           	FR_TYPE_EVS },
	{ "vendor",        	FR_TYPE_VENDOR },

	/*
	 *	Alternative names
	 */
	{ "cidr",         	FR_TYPE_IPV4_PREFIX },
	{ "byte",		FR_TYPE_UINT8 },
	{ "short",		FR_TYPE_UINT16 },
	{ "integer",		FR_TYPE_UINT32 },
	{ "integer64",		FR_TYPE_UINT64 },
	{ "decimal",		FR_TYPE_FLOAT64 },
	{ "signed",        	FR_TYPE_INT32 },

	{ NULL,			0 }
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

	[FR_TYPE_BOOL]	= {1, 1},
	[FR_TYPE_UINT8]		= {1, 1},
	[FR_TYPE_UINT16]		= {2, 2},
	[FR_TYPE_UINT32]	= {4, 4},
	[FR_TYPE_UINT64]	= {8, 8},
	[FR_TYPE_SIZE]		= {sizeof(size_t), sizeof(size_t)},
	[FR_TYPE_INT32]	= {4, 4},

	[FR_TYPE_DATE]		= {4, 4},
	[FR_TYPE_ABINARY]	= {32, ~0},

	[FR_TYPE_TLV]		= {2, ~0},
	[FR_TYPE_STRUCT]	= {1, ~0},

	[FR_TYPE_EXTENDED]	= {2, ~0},
	[FR_TYPE_LONG_EXTENDED]	= {3, ~0},

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
	[FR_TYPE_LONG_EXTENDED] = true,
	[FR_TYPE_VSA] = true,
	[FR_TYPE_EVS] = true,
	[FR_TYPE_VENDOR] = true
};

/*
 *	Create the hash of the name.
 *
 *	We copy the hash function here because it's substantially faster.
 */
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

#ifdef __clang_analyzer__
#  define INTERNAL_IF_NULL(_dict) do {\
	if (!_dict) _dict = fr_dict_internal; \
	if (!_dict) return NULL; \
} while (0)
#else
#  define INTERNAL_IF_NULL(_dict) if (!_dict) _dict = fr_dict_internal
#endif

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
 * @param[in] name of the attribute, vendor or protocol.
 * @return the hashed derived from the name.
 */
static uint32_t dict_hash_name(char const *name)
{
	uint32_t hash = FNV_MAGIC_INIT;
	char const *p;

	for (p = name; *p != '\0'; p++) {
		int c = *(unsigned char const *)p;
		if (isalpha(c)) c = tolower(c);

		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t)(c & 0xff);
	}

	return hash;
}

/** Wrap name hash function for fr_dict_attr_t
 *
 * @param data fr_dict_attr_t to hash.
 * @return the hash derived from the name of the attribute.
 */
static uint32_t dict_attr_name_hash(void const *data)
{
	return dict_hash_name(((fr_dict_attr_t const *)data)->name);
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
	return dict_hash_name(((fr_dict_vendor_t const *)data)->name);
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
static uint32_t dict_vendor_vendorpec_hash(void const *data)
{
	return fr_hash(&(((fr_dict_vendor_t const *)data)->vendorpec),
		       sizeof(((fr_dict_vendor_t const *)data)->vendorpec));
}

/** Compare two vendor numbers
 *
 */
static int dict_vendor_vendorpec_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return a->vendorpec - b->vendorpec;
}

/** Hash a dictionary name
 *
 */
static uint32_t dict_enum_alias_hash(void const *data)
{
	uint32_t hash;
	fr_dict_enum_t const *enumv = data;

	hash = dict_hash_name(enumv->alias);
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

/** Add an entry to the list of stat buffers.
 */
static void dict_stat_add(fr_dict_t *dict, struct stat const *stat_buf)
{
	dict_stat_t *this;

	this = talloc_zero(dict, dict_stat_t);
	if (!this) return;

	memcpy(&(this->stat_buf), stat_buf, sizeof(this->stat_buf));

	if (!dict->stat_head) {
		dict->stat_head = dict->stat_tail = this;
	} else {
		dict->stat_tail->next = this;
		dict->stat_tail = this;
	}
}

/** See if any dictionaries have changed.  If not, don't do anything
 */
static int dict_stat_check(fr_dict_t *dict, char const *dir, char const *file)
{
	struct stat stat_buf;
	dict_stat_t *this;
	char buffer[2048];

	/*
	 *	Nothing cached, all files are new.
	 */
	if (!dict || !dict->stat_head) return 0;

	/*
	 *	Stat the file.
	 */
	snprintf(buffer, sizeof(buffer), "%s/%s", dir, file);
	if (stat(buffer, &stat_buf) < 0) return 0;

	/*
	 *	Find the cache entry.
	 *	FIXME: use a hash table.
	 *	FIXME: check dependencies, via children.
	 *	       if A loads B and B changes, we probably want
	 *	       to reload B at the minimum.
	 */
	for (this = dict->stat_head; this != NULL; this = this->next) {
		if (this->stat_buf.st_dev != stat_buf.st_dev) continue;
		if (this->stat_buf.st_ino != stat_buf.st_ino) continue;

		/*
		 *	The file has changed.  Re-read it.
		 */
		if (this->stat_buf.st_mtime < stat_buf.st_mtime) return 0;

		/*
		 *	The file is the same.  Ignore it.
		 */
		return 1;
	}

	/*
	 *	Not in the cache.
	 */
	return 0;
}

static void _fr_dict_dump(fr_dict_attr_t const *da, unsigned int lvl)
{
	unsigned int		i;
	size_t			len;
	fr_dict_attr_t const	*p;

	printf("%p - %s (%u) %s\n", da, da->name, da->attr, fr_int2str(dict_attr_types, da->type, "<INVALID>"));

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

/** Add a vendor to the dictionary
 *
 * Inserts a vendor entry into the vendor hash table.  This must be done before adding
 * attributes under a VSA.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] name of the vendor.
 * @param[in] num Vendor's Private Enterprise Number.
 * @return
 * 	- 0 on success.
 * 	- -1 on failure.
 */
int fr_dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num)
{
	INTERNAL_IF_NULL(dict);
	size_t			len;
	fr_dict_vendor_t	*vendor;

	len = strlen(name);
	if (len >= FR_DICT_VENDOR_MAX_NAME_LEN) {
		fr_strerror_printf("%s: Vendor name too long", __FUNCTION__);
		return -1;
	}

	vendor = (fr_dict_vendor_t *)talloc_zero_array(dict->pool, uint8_t, sizeof(*vendor) + len);
	if (vendor == NULL) {
		fr_strerror_printf("%s: Out of memory", __FUNCTION__);
		return -1;
	}
	talloc_set_type(vendor, fr_dict_vendor_t);

	strlcpy(vendor->name, name, len + 1);
	vendor->vendorpec = num;
	vendor->type = vendor->length = 1; /* defaults */

	if (!fr_hash_table_insert(dict->vendors_by_name, vendor)) {
		fr_dict_vendor_t *old_vendor;

		old_vendor = fr_hash_table_finddata(dict->vendors_by_name, vendor);
		if (!old_vendor) {
			fr_strerror_printf("%s: Failed inserting vendor name %s", __FUNCTION__, name);
			return -1;
		}
		if ((strcmp(old_vendor->name, vendor->name) == 0) && (old_vendor->vendorpec != vendor->vendorpec)) {
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
 * @param parent we're adding a child to.
 * @param child to add to parent.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
static inline int fr_dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child)
{
	fr_dict_attr_t const * const *bin;
	fr_dict_attr_t **this;

	/*
	 *	Setup fields in the child
	 */
	child->parent = parent;
	child->depth = parent->depth + 1;

	/*
	 *	We only allocate the pointer array *if* the parent has children.
	 */
	if (!parent->children) parent->children = talloc_zero_array(parent, fr_dict_attr_t const *, UINT8_MAX + 1);
	if (!parent->children) return -1;

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
		else if (child->vendor <= (*bin)->vendor) break;	/* Prioritise RFC attributes */
		else if (child->attr <= (*bin)->attr) break;

		bin = &(*bin)->next;
	}

	memcpy(&this, &bin, sizeof(this));
	child->next = *this;
	*this = child;

	return 0;
}

/** Build the tlv_stack for the specified DA and encode the path in OID form
 *
 * @param[out] out Where to write the OID.
 * @param[in] outlen Length of the output buffer.
 * @param[in] ancestor If not NULL, only print OID portion between ancestor and da.
 * @param[in] da to print OID string for.
 * @return the number of bytes written to the buffer.
 */
size_t dict_print_attr_oid(char *out, size_t outlen,
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

/** Grow or shrink a heap allocated fr_dict_attr_t and copy a new name string into its name buffer
 *
 * @param[in] da	to set a new name for.
 * @param[in] name	to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure (memory allocation error).
 */
static int fr_dict_attr_set_name(fr_dict_attr_t **da, char const *name)
{
	size_t		len;
	fr_dict_attr_t	*new;

	len = strlen(name);

	talloc_set_type(*da, uint8_t);
	new = (fr_dict_attr_t *)talloc_realloc(talloc_parent(*da), *da, uint8_t, sizeof(fr_dict_attr_t) + len + 1);
	if (!new) return -1;

	talloc_set_type(new, fr_dict_attr_t);

	strlcpy(new->name, name, len + 1);

	*da = new;

	return 0;
}

/** Allocate a dictionary attribute on the heap
 *
 * @param[in] ctx	to allocate the attribute in.
 * @param[in] parent	of the attribute, if none, should be the dictionary root.
 * @param[in] name	of the attribute.  If NULL an OID string will be created and set as the name.
 * @param[in] vendor	of the attribute.  Deprecated.
 * @param[in] attr	number.
 * @param[in] type	of the attribute.
 * @param[in] flags	to assign.
 * @return
 *	- A new fr_dict_attr_t on success.
 *	- NULL on failure.
 */
static fr_dict_attr_t *fr_dict_attr_alloc(TALLOC_CTX *ctx,
					  fr_dict_attr_t const *parent,
				   	  char const *name, unsigned int vendor, int attr,
				   	  fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t *da;

	if (!fr_cond_assert(parent)) return NULL;

	da = (fr_dict_attr_t *)talloc_zero_array(ctx, uint8_t, sizeof(*da));
	if (!da) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	talloc_set_type(da, fr_dict_attr_t);

	da->attr = attr;
	da->vendor = vendor;
	da->type = type;
	memcpy(&da->flags, flags, sizeof(*flags));
	da->parent = parent;
	da->depth = parent->depth + 1;

	if (!name) {
		char	buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];
		char	*p = buffer;
		size_t	len;

		len = snprintf(p, sizeof(buffer), "Attr-");
		p += len;

		len = dict_print_attr_oid(p, sizeof(buffer) - (p - buffer), NULL, da);
		if (is_truncated(len, sizeof(buffer) - (p - buffer))) {
			fr_strerror_printf("OID string too long for unknown attribute");
			return NULL;
		}

		if (fr_dict_attr_set_name(&da, buffer) < 0) {
		error:
			talloc_free(da);
			return NULL;
		}
		return da;
	}

	if (fr_dict_attr_set_name(&da, name) < 0) goto error;

	return da;
}

/** Add an attribute to the name table for the dictionary.
 *
 * @todo we need to check length of none vendor attributes.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] parent to add attribute under.
 * @param[in] name of the attribute.
 * @param[in] attr number.
 * @param[in] type of attribute.
 * @param[in] flags to set in the attribute.
 * @return
 *	- fr_dict_attr_t on success
 *	- NULL on failure
 */
static fr_dict_attr_t *fr_dict_attr_add_by_name(fr_dict_t *dict, fr_dict_attr_t const *parent,
						char const *name, int attr, fr_type_t type, fr_dict_attr_flags_t flags)
{
	unsigned int		vendor;
	size_t			namelen;
	fr_dict_attr_t		*n;
	fr_dict_attr_t const	*v;

	INTERNAL_IF_NULL(dict);

	if (!fr_cond_assert(parent)) return NULL;

	namelen = strlen(name);
	if (namelen >= FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
	error:
		fr_strerror_printf("fr_dict_attr_add: Failed adding '%s': %s", name, fr_strerror());
		return NULL;
	}

	if (fr_dict_valid_name(name, -1) < 0) return NULL;

	/*
	 *	type_size is used to limit the maximum attribute number, so it's checked first.
	 */
	if (flags.type_size) {
		if ((type != FR_TYPE_TLV) && (type != FR_TYPE_VENDOR)) {
			fr_strerror_printf("The 'format=' flag can only be used with attributes of type 'tlv'");
			goto error;
		}

		if ((flags.type_size != 1) &&
		    (flags.type_size != 2) &&
		    (flags.type_size != 4)) {
			fr_strerror_printf("The 'format=' flag can only be used with attributes of type size 1,2 or 4");
			goto error;
		}
	}

	/******************** sanity check attribute number ********************/

	if (parent->flags.is_root) {
		static unsigned int max_attr = UINT8_MAX + 1;

		if (attr == -1) {
			if (fr_dict_attr_by_name(dict, name)) return 0; /* exists, don't add it again */
			attr = ++max_attr;
			flags.internal = 1;

		} else if (attr <= 0) {
			fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", attr);
			goto error;

		} else if ((unsigned int) attr > max_attr) {
			max_attr = attr;
		}

		/*
		 *	Auto-set internal flags for raddb/dictionary.
		 *	So that the end user doesn't have to know
		 *	about internal implementation of the server.
		 */
		if ((parent->flags.type_size == 1) &&
		    (attr >= 3000) && (attr < 4000)) {
			flags.internal = true;
		}
	}

	/*
	 *	Any other negative attribute number is wrong.
	 */
	if (attr < 0) {
		fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than zero", attr);
		goto error;
	}

	/*
	 *	If attributes have number greater than 255, do sanity checks.
	 *
	 *	We assume that the root attribute is of type TLV, with
	 *	the appropriate flags set for attributes in this
	 *	space.
	 */
	if ((attr > UINT8_MAX) && !flags.internal &&
	    !((strncmp("VMPS", name, 4) == 0) || (strncmp("VQP", name, 3) == 0))) {	/* Fixme */
		for (v = parent; v != NULL; v = v->parent) {
			if ((v->type == FR_TYPE_TLV) || (v->type == FR_TYPE_VENDOR)) {
				if ((v->flags.type_size < 4) &&
				    (attr >= (1 << (8 * v->flags.type_size)))) {
					fr_strerror_printf("Attributes must have value between 1..%u",
							   (1 << (8 * v->flags.type_size)) - 1);
					goto error;
				}
				break;
			}
		}
	}

	/******************** sanity check flags ********************/

	/*
	 *	virtual attributes are special.
	 */
	if (flags.virtual) {
		if (!parent->flags.is_root) {
			fr_strerror_printf("The 'virtual' flag can only be used for normal attributes");
			goto error;
		}

		if (attr <= (1 << (8 * parent->flags.type_size))) {
			fr_strerror_printf("The 'virtual' flag can only be used for non-protocol attributes");
			goto error;
		}
	}

	/*
	 *	Tags can only be used in a few limited situations.
	 */
	if (flags.has_tag) {
		if ((type != FR_TYPE_UINT32) && (type != FR_TYPE_STRING)) {
			fr_strerror_printf("The 'has_tag' flag can only be used for attributes of type 'integer' "
					   "or 'string'");
			goto error;
		}

		if (!(parent->flags.is_root ||
		      ((parent->type == FR_TYPE_VENDOR) &&
		       (parent->parent && parent->parent->type == FR_TYPE_VSA)))) {
			fr_strerror_printf("The 'has_tag' flag can only be used with RFC and VSA attributes");
			goto error;
		}

		if (flags.array || flags.has_value || flags.concat || flags.virtual ||
		    flags.length) {
			fr_strerror_printf("The 'has_tag' flag cannot be used any other flag");
			goto error;
		}

		if (flags.encrypt && (flags.encrypt != FLAG_ENCRYPT_TUNNEL_PASSWORD)) {
			fr_strerror_printf("The 'has_tag' flag can only be used with 'encrypt=2'");
			goto error;
		}
	}

	/*
	 *	'concat' can only be used in a few limited situations.
	 */
	if (flags.concat) {
		if (type != FR_TYPE_OCTETS) {
			fr_strerror_printf("The 'concat' flag can only be used for attributes of type 'octets'");
			goto error;
		}

		if (!parent->flags.is_root) {
			fr_strerror_printf("The 'concat' flag can only be used with RFC attributes");
			goto error;
		}

		if (flags.array || flags.internal || flags.has_value || flags.virtual ||
		    flags.encrypt || flags.length) {
			fr_strerror_printf("The 'concat' flag cannot be used any other flag");
			goto error;
		}
	}

	/*
	 *	'octets[n]' can only be used in a few limited situations.
	 */
	if (flags.length) {
		if (flags.array || flags.has_value || flags.virtual) {
			fr_strerror_printf("The 'octets[...]' syntax cannot be used any other flag");
			goto error;
		}

		if (flags.length > 253) {
			fr_strerror_printf("Invalid length %d", flags.length);
			return NULL;
		}

		if ((type == FR_TYPE_TLV) || (type == FR_TYPE_VENDOR)) {
			if ((flags.length != 1) &&
			    (flags.length != 2) &&
			    (flags.length != 4)) {
				fr_strerror_printf("The 'length' flag can only be used with attributes of TLV lengths of 1,2 or 4");
				goto error;
			}

		} else if ((type != FR_TYPE_OCTETS) &&
			   (type != FR_TYPE_STRUCT)) {
			fr_strerror_printf("The 'length' flag can only be set for attributes of type 'octets' or 'struct'");
			goto error;
		}

		if (type == FR_TYPE_STRUCT) {
			if (flags.type_size != 0) {
				fr_strerror_printf("Invalid initializer for type_size");
				goto error;
			}

			/*
			 *	Set maximum length for the struct, and
			 *	initialize the current length to be zero.
			 */
			flags.type_size = flags.length;
			flags.length = 0;
		}
	}

	/*
	 *	DHCP options allow for packing multiple values into one option.
	 *
	 *	We allow it for DHCP and FreeDHCP dictionaries.  Not anywhere else.
	 */
	if (flags.array) {
		for (v = parent; v != NULL; v = v->parent) {
			if (v->type != FR_TYPE_VENDOR) continue;

			if ((v->attr != 34673) && /* freedhcp */
			    (v->attr != DHCP_MAGIC_VENDOR)) {
				fr_strerror_printf("The 'array' flag can only be used with DHCP options");
				goto error;
			}
			break;
		}

		switch (type) {
		default:
			fr_strerror_printf("The 'array' flag cannot be used with attributes of type '%s'",
					   fr_int2str(dict_attr_types, type, "<UNKNOWN>"));
			goto error;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_DATE:
		case FR_TYPE_STRING:
			break;
		}

		if (flags.internal || flags.has_value || flags.encrypt || flags.virtual) {
			fr_strerror_printf("The 'array' flag cannot be used any other flag");
			goto error;
		}
	}

	/*
	 *	'has_value' should only be set internally.  If the
	 *	caller sets it, we still sanity check it.
	 */
	if (flags.has_value) {
		if (type != FR_TYPE_UINT32) {
			fr_strerror_printf("The 'has_value' flag can only be used with attributes "
					   "of type 'integer'");
			goto error;
		}

		if (flags.encrypt || flags.virtual) {
			fr_strerror_printf("The 'has_value' flag cannot be used with any other flag");
			goto error;
		}
	}

	if (flags.encrypt) {
		/*
		 *	Stupid hacks for MS-CHAP-MPPE-Keys.  The User-Password
		 *	encryption method has no provisions for encoding the
		 *	length of the data.  For User-Password, the data is
		 *	(presumably) all printable non-zero data.  For
		 *	MS-CHAP-MPPE-Keys, the data is binary crap.  So... we
		 *	MUST specify a length in the dictionary.
		 */
		if ((flags.encrypt == FLAG_ENCRYPT_USER_PASSWORD) && (type != FR_TYPE_STRING)) {
			if (type != FR_TYPE_OCTETS) {
				fr_strerror_printf("The 'encrypt=1' flag can only be used with "
						   "attributes of type 'string'");
				goto error;
			}

			if (flags.length == 0) {
				fr_strerror_printf("The 'encrypt=1' flag MUST be used with an explicit length for "
						   "'octets' data types");
				goto error;
			}
		}

		if (flags.encrypt > FLAG_ENCRYPT_OTHER) {
			fr_strerror_printf("The 'encrypt' flag can only be 0..4");
			goto error;
		}

		/*
		 *	The Tunnel-Password encryption method can be used anywhere.
		 *
		 *	We forbid User-Password and Ascend-Send-Secret
		 *	methods in the extended space.
		 */
		if ((flags.encrypt != FLAG_ENCRYPT_TUNNEL_PASSWORD) && !flags.internal && !parent->flags.internal) {
			for (v = parent; v != NULL; v = v->parent) {
				switch (v->type) {
				case FR_TYPE_EXTENDED:
				case FR_TYPE_LONG_EXTENDED:
				case FR_TYPE_EVS:
					fr_strerror_printf("The 'encrypt=%d' flag cannot be used with attributes "
							   "of type '%s'", flags.encrypt,
							   fr_int2str(dict_attr_types, type, "<UNKNOWN>"));
					goto error;

				default:
					break;
				}

			}
		}

		switch (type) {
		case FR_TYPE_TLV:
			if (flags.internal || parent->flags.internal) break;
			/* FALL-THROUGH */

		default:
		encrypt_fail:
			fr_strerror_printf("The 'encrypt' flag cannot be used with attributes of type '%s'",
					   fr_int2str(dict_attr_types, type, "<UNKNOWN>"));
			goto error;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_UINT32:
		case FR_TYPE_OCTETS:
			if (flags.encrypt == FLAG_ENCRYPT_ASCEND_SECRET) goto encrypt_fail;

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
	case FR_TYPE_LONG_EXTENDED:
	case FR_TYPE_VSA:
		if (!parent->flags.is_root) {
			fr_strerror_printf("Attributes of type '%s' can only be used in the RFC space",
					   fr_int2str(dict_attr_types, type, "?Unknown?"));
			goto error;
		}
		break;

	/*
	 *	EVS may only occur under extended and long extended.
	 */
	case FR_TYPE_EVS:
		if ((parent->type != FR_TYPE_EXTENDED) && (parent->type != FR_TYPE_LONG_EXTENDED)) {
			fr_strerror_printf("Attributes of type 'evs' MUST have a parent of type 'extended', "
					   "instead of '%s'", fr_int2str(dict_attr_types, parent->type, "?Unknown?"));
			goto error;
		}
		break;

	case FR_TYPE_VENDOR:
		if ((parent->type != FR_TYPE_VSA) && (parent->type != FR_TYPE_EVS)) {
			fr_strerror_printf("Attributes of type 'vendor' MUST have a parent of type 'vsa' or "
					   "'evs', instead of '%s'",
					   fr_int2str(dict_attr_types, parent->type, "?Unknown?"));
			goto error;
		}

		if (parent->type == FR_TYPE_VSA) {
			fr_dict_vendor_t const *dv;

			dv = fr_dict_vendor_by_num(dict, attr);
			if (dv) {
				flags.type_size = dv->type;
				flags.length = dv->length;
			} else {
				flags.type_size = 1;
				flags.length = 1;
			}
		} else {
			flags.type_size = 1;
			flags.length = 1;
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
					   fr_int2str(dict_attr_types, type, "?Unknown?"));
			goto error;
		}

		/*
		 *	Over-ride whatever was there before, so we
		 *	don't have multiple formats of VSAs.
		 */
		flags.type_size = v->flags.type_size;
		flags.length = v->flags.length;
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
					   fr_int2str(dict_attr_types, type, "?Unknown?"));
			goto error;
		}
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_TIMEVAL:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_COMBO_IP_PREFIX:
		fr_strerror_printf("Attributes of type '%s' cannot be used in dictionaries",
				   fr_int2str(dict_attr_types, type, "?Unknown?"));
		goto error;

	default:
		break;
	}

	/*
	 *	Force "length" for data types of fixed length;
	 */
	switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_BOOL:
		flags.length = 1;
		break;

	case FR_TYPE_UINT16:
		flags.length = 2;
		break;

	case FR_TYPE_DATE:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_INT32:
		flags.length = 4;
		break;

	case FR_TYPE_UINT64:
		flags.length = 8;
		break;

	case FR_TYPE_SIZE:
		flags.length = sizeof(size_t);
		break;

	case FR_TYPE_ETHERNET:
		flags.length = 6;
		break;

	case FR_TYPE_IFID:
		flags.length = 8;
		break;

	case FR_TYPE_IPV6_ADDR:
		flags.length = 16;
		break;

	case FR_TYPE_EXTENDED:
		if (!parent->flags.is_root || (attr < 241)) {
			fr_strerror_printf("Attributes of type 'extended' MUST be "
					   "RFC attributes with value >= 241.");
			goto error;
		}
		flags.length = 0;
		break;

	case FR_TYPE_LONG_EXTENDED:
		if (!parent->flags.is_root || (attr < 241)) {
			fr_strerror_printf("Attributes of type 'long-extended' MUST "
					   "be RFC attributes with value >= 241.");
			goto error;
		}

		flags.length = 0;
		break;

	case FR_TYPE_EVS:
		if (attr != FR_VENDOR_SPECIFIC) {
			fr_strerror_printf("Attributes of type 'evs' MUST have attribute code 26, got %i", attr);
			goto error;
		}

		flags.length = 0;
		break;

		/*
		 *	The length is calculated from th children, not
		 *	input as the flags.
		 */
	case FR_TYPE_STRUCT:
		flags.length = 0;
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
	case FR_TYPE_TLV:
		flags.is_pointer = true;
		break;

	default:
		break;
	}

	/*
	 *	Validate attribute based on parent.
	 */
	if (parent->type == FR_TYPE_STRUCT) {
		fr_dict_attr_t *mutable;

		/*
		 *	STRUCTs will have their length filled in later.
		 */
		if ((type != FR_TYPE_STRUCT) && (flags.length == 0)) {
			fr_strerror_printf("Children of 'struct' type attributes MUST have fixed length.");
			goto error;
		}

		if ((attr > 1) && !parent->flags.length) {
			fr_strerror_printf("Children of 'struct' type attributes MUST start with sub-attribute 1.");
			goto error;
		}

		/*
		 *	Sneak in the length of the children.
		 */
		memcpy(&mutable, &parent, sizeof(mutable));
		mutable->flags.length += flags.length;

		/*
		 *	The struct has a maximum size.  Complain if we exceed it.
		 */
		if (mutable->flags.type_size && (mutable->flags.length > mutable->flags.type_size)) {
			fr_strerror_printf("Child attribute causes struct to overflow maximum size of %d octets",
					   mutable->flags.type_size);
			goto error;
		}
	}

	/*
	 *	Propogate vendor down the attribute tree.
	 */
	if (parent->type == FR_TYPE_VENDOR) {
		vendor = parent->attr;
	} else {
		vendor = parent->vendor;
	}

	n = fr_dict_attr_alloc(dict->pool, parent, name, vendor, attr, type, &flags);
	if (!n) {
	oom:
		fr_strerror_printf("Out of memory");
		goto error;
	}

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(dict->attributes_by_name, n)) {
		fr_dict_attr_t *a;

		/*
		 *	If the attribute has identical number, then
		 *	error out.  We don't allow duplicate attribute
		 *	definitions.
		 */
		a = fr_hash_table_finddata(dict->attributes_by_name, n);
		if (a && (strcasecmp(a->name, n->name) == 0)) {
			if ((a->attr != n->attr) || (a->parent != n->parent)) {
				fr_strerror_printf("Duplicate attribute name");
				talloc_free(n);
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
		if (!fr_hash_table_replace(dict->attributes_by_name, n)) {
			fr_strerror_printf("Internal error storing attribute");
			talloc_free(n);
			goto error;
		}
	}

	/*
	 *	Hacks for combo-IP
	 */
	if (n->type == FR_TYPE_COMBO_IP_ADDR) {
		fr_dict_attr_t *v4, *v6;

		v4 = (fr_dict_attr_t *)talloc_zero_array(dict->pool, uint8_t, sizeof(*v4) + namelen);
		if (!v4) goto oom;
		talloc_set_type(v4, fr_dict_attr_t);

		v6 = (fr_dict_attr_t *)talloc_zero_array(dict->pool, uint8_t, sizeof(*v6) + namelen);
		if (!v6) goto oom;
		talloc_set_type(v6, fr_dict_attr_t);

		memcpy(v4, n, sizeof(*v4) + namelen);
		v4->type = FR_TYPE_IPV4_ADDR;

		memcpy(v6, n, sizeof(*v6) + namelen);
		v6->type = FR_TYPE_IPV6_ADDR;
		if (!fr_hash_table_replace(dict->attributes_combo, v4)) {
			fr_strerror_printf("Failed inserting IPv4 version of combo attribute");
			goto error;
		}

		if (!fr_hash_table_replace(dict->attributes_combo, v6)) {
			fr_strerror_printf("Failed inserting IPv6 version of combo attribute");
			goto error;
		}
	}

	return n;
}

/** Add an attribute to the dictionary
 *
 * @todo we need to check length of none vendor attributes.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] parent to add attribute under.
 * @param[in] name of the attribute.
 * @param[in] attr number.
 * @param[in] type of attribute.
 * @param[in] flags to set in the attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_add(fr_dict_t *dict, fr_dict_attr_t const *parent,
		     char const *name, int attr, fr_type_t type, fr_dict_attr_flags_t flags)
{
	fr_dict_attr_t *n;
	fr_dict_attr_t *mutable;

	n = fr_dict_attr_add_by_name(dict, parent, name, attr, type, flags);
	if (!n) return -1;

	/*
	 *	Setup parenting for the attribute
	 */
	memcpy(&mutable, &parent, sizeof(mutable));

	if (fr_dict_attr_child_add(mutable, n) < 0) return -1;

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
 * @param[in] coerce		if the type of the value does not match the type of the da,
 *				attempt to cast it to match the type of the da.  If this is
 *				false and there's a type mismatch, we fail.
 *				We also fail if the value cannot be coerced to the attribute type.
 * @param[in] takes_precedence	This alias should take precedence over previous aliases for the
 *				same value, when resolving value to alias.
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
		fr_strerror_printf("%s: Out of memory", __FUNCTION__);
		return -1;
	}
	enumv->alias = talloc_typed_strdup(enumv, alias);
	enum_value = fr_value_box_alloc(enumv, da->type, NULL, false);

	if (da->type != value->type) {
		if (!coerce) {
			fr_strerror_printf("%s: Type mismatch between attribute (%s) and enum (%s)",
					   __FUNCTION__,
					   fr_int2str(dict_attr_types, da->type, "<INVALID>"),
					   fr_int2str(dict_attr_types, value->type, "<INVALID>"));
			return -1;
		}

		if (fr_value_box_cast(enumv, enum_value, da->type, NULL, value) < 0) {
			fr_strerror_printf_push("%s: Failed coercing enum type (%s) to attribute type (%s)",
						__FUNCTION__,
					   	fr_int2str(dict_attr_types, value->type, "<INVALID>"),
					   	fr_int2str(dict_attr_types, da->type, "<INVALID>"));

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
			old = fr_dict_enum_by_alias(dict, da, alias);
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

/*
 *	Process the ATTRIBUTE command
 */
static int dict_read_process_attribute(fr_dict_t *dict, fr_dict_attr_t const *parent,
			     	       unsigned int block_vendor, char **argv, int argc,
				       fr_dict_attr_flags_t *base_flags)
{
	bool			oid = false;

	unsigned int		vendor = 0;
	unsigned int		attr;

	int			type;
	unsigned int		length;
	fr_dict_attr_flags_t	flags;
	char			*p;

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
		 *	Got an OID string.  Every attribute should exist other
		 *	than the leaf, which is the attribute we're defining.
		 */
	} else {
		ssize_t slen;

		oid = true;
		vendor = block_vendor;

		slen = fr_dict_attr_by_oid(dict, &parent, &vendor, &attr, argv[1]);
		if (slen <= 0) {
			return -1;
		}

		if (!fr_cond_assert(parent)) return -1;	/* Should have provided us with a parent */

		block_vendor = vendor; /* Weird case where we're processing 26.<vid>.<tlv> */
	}

	/*
	 *	Some types can have fixed length
	 */
	p = strchr(argv[2], '[');
	if (p) *p = '\0';

	/*
	 *	find the type of the attribute.
	 */
	type = fr_str2int(dict_attr_types, argv[2], -1);
	if (type < 0) {
		fr_strerror_printf("Unknown data type '%s'", argv[2]);
		return -1;
	}

	if (p) {
		char *q;

		q = strchr(p + 1, ']');
		if (!q) {
			fr_strerror_printf("Invalid format for '%s[...]'", argv[2]);
			return -1;
		}

		*q = 0;

		if (!dict_read_sscanf_i(&length, p + 1)) {
			fr_strerror_printf("Invalid length for '%s[...]'", argv[2]);
			return -1;
		}

		if ((length == 0) || (length > 253)) {
			fr_strerror_printf("Invalid length for '%s[...]'", argv[2]);
			return -1;
		}

		flags.length = length;
	}

	/*
	 *	Parse options.
	 */
	if (argc >= 4) {
		char *key, *next, *last;

		key = argv[3];
		do {
			next = strchr(key, ',');
			if (next) *(next++) = '\0';

			/*
			 *	Boolean flag, means this is a tagged
			 *	attribute.
			 */
			if ((strcmp(key, "has_tag") == 0) || (strcmp(key, "has_tag=1") == 0)) {
				flags.has_tag = 1;

			/*
			 *	Encryption method.
			 */
			} else if (strncmp(key, "encrypt=", 8) == 0) {
				flags.encrypt = strtol(key + 8, &last, 0);
				if (*last) {
					fr_strerror_printf("Invalid option %s", key);
					return -1;
				}

				/*
				 *	Marks the attribute up as internal.
				 *	This means it can use numbers outside of the allowed
				 *	protocol range, and also means it will not be included
				 *	in replies or proxy requests.
				 */
			} else if (strncmp(key, "internal", 9) == 0) {
				flags.internal = 1;

			} else if (strncmp(key, "array", 6) == 0) {
				flags.array = 1;

			} else if (strncmp(key, "concat", 7) == 0) {
				flags.concat = 1;

			} else if (strncmp(key, "virtual", 8) == 0) {
				flags.virtual = 1;

			/*
			 *	The only thing is the vendor name,
			 *	and it's a known name: allow it.
			 */
			} else if ((key == argv[3]) && !next) {
				if (oid) {
					fr_strerror_printf("ATTRIBUTE cannot use a 'vendor' flag");
					return -1;
				}

				if (block_vendor) {
					fr_strerror_printf("Vendor flag inside of 'BEGIN-VENDOR' is not allowed");
					return -1;
				}

				vendor = fr_dict_vendor_by_name(dict, key);
				if (!vendor) goto unknown;
				break;

			} else {
			unknown:
				fr_strerror_printf("Unknown option '%s'", key);
				return -1;
			}

			key = next;
			if (key && !*key) break;
		} while (key);
	}

	if (block_vendor) vendor = block_vendor;

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

	/*
	 *	Add it in.
	 */
	if (fr_dict_attr_add(dict, parent, argv[0], attr, type, flags) < 0) {
		return -1;
	}

	return 0;
}


/*
 *	Process the ATTRIBUTE command, where it only has a name.
 */
static int dict_read_process_named_attribute(fr_dict_t *dict, fr_dict_attr_t const *parent,
					     char **argv, int argc,
					     fr_dict_attr_flags_t *base_flags)
{
	int type;
	unsigned int attr;
	uint32_t hash;
	char *p, normalized[512];

	if (argc != 2) {
		fr_strerror_printf("Invalid ATTRIBUTE syntax");
		return -1;
	}

	/*
	 *	find the type of the attribute.
	 */
	type = fr_str2int(dict_attr_types, argv[1], -1);
	if (type < 0) {
		fr_strerror_printf("Unknown data type '%s'", argv[1]);
		return -1;
	}

	strlcpy(normalized, argv[0], sizeof(normalized));
	for (p = normalized; *p != '\0'; p++) {
		if (isupper((int) *p)) {
			*p = tolower((int) *p);
		}
	}

	hash = fr_hash_string(normalized);
	attr = hash;

	/*
	 *	Add it in.
	 */
	if (fr_dict_attr_add(dict, parent, argv[0], attr, type, *base_flags) < 0) {
		return -1;
	}

	return 0;
}

/** Process a value alias
 *
 */
static int dict_read_process_value(fr_dict_t *dict, char **argv, int argc)
{
	static fr_dict_attr_t const	*last_attr = NULL;
	fr_dict_attr_t const		*da;
	fr_value_box_t			value;

	if (argc != 3) {
		fr_strerror_printf("Invalid VALUE syntax");
		return -1;
	}

	/*
	 *	Most VALUEs are bunched together by ATTRIBUTE.  We can
	 *	save a lot of lookups on dictionary initialization by
	 *	caching the last attribute.
	 */
	if (last_attr && (strcasecmp(argv[0], last_attr->name) == 0)) {
		da = last_attr;
	} else {
		da = fr_dict_attr_by_name(dict, argv[0]);
		last_attr = da;
	}

	/*
	 *	Remember which attribute is associated with this
	 *	value.  This allows us to define enum
	 *	values before the attribute exists, and fix them
	 *	up later.
	 */
	if (!da) {
		dict_enum_fixup_t *fixup;

		fixup = talloc_zero(dict->pool, dict_enum_fixup_t);
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
		fixup->next = dict->enum_fixup;
		dict->enum_fixup = fixup;

		return 0;
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

	/* Create a new VENDOR entry for the list */
	if (fr_dict_vendor_add(dict, argv[0], value) < 0) {
		return -1;
	}

	/*
	 *	Look for a format statement.  Allow it to over-ride the hard-coded formats below.
	 */
	if (argc == 3) {
		if (dict_read_parse_format(argv[2], &value, &type, &length, &continuation) < 0) {
			return -1;
		}

	} else if (value == VENDORPEC_USR) { /* catch dictionary screw-ups */
		type = 4;
		length = 0;

	} else if (value == VENDORPEC_LUCENT) {
		type = 2;
		length = 1;

	} else if (value == VENDORPEC_STARENT) {
		type = 2;
		length = 2;

	} else {
		type = length = 1;
	}

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

/** Parser context for dict_from_file
 *
 * Allows vendor and TLV context to persist across $INCLUDEs
 */
typedef struct dict_from_file_ctx {
	fr_dict_t		*dict;
	unsigned int		block_vendor;
	int			block_tlv_depth;
	fr_dict_attr_t const	*parent;
	fr_dict_attr_t const	*block_tlv[FR_DICT_TLV_NEST_MAX];
} dict_from_file_ctx_t;

/*
 *	Initialize the dictionary.
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
	fr_dict_attr_flags_t	base_flags;

	if (!fr_cond_assert(ctx->parent)) return -1;

	if ((strlen(dir_name) + 3 + strlen(filename)) > sizeof(dir)) {
		fr_strerror_printf("%s: Filename name too long", __FUNCTION__);
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

	/*
	 *	Check if we've loaded this file before.  If so, ignore it.
	 */
	p = strrchr(fn, FR_DIR_SEP);
	if (p) {
		*p = '\0';
		if (dict_stat_check(ctx->dict, fn, p + 1)) {
			*p = FR_DIR_SEP;
			return 0;
		}
		*p = FR_DIR_SEP;
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			fr_strerror_printf("%s: Couldn't open dictionary '%s': %s",
					   __FUNCTION__, fn, fr_syserror(errno));
		} else {
			fr_strerror_printf("%s: %s[%d]: Couldn't open dictionary '%s': %s",
					   __FUNCTION__, src_file, src_line, fn, fr_syserror(errno));
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
		fr_strerror_printf("%s: Dictionary '%s' is not a regular file", __FUNCTION__, fn);
		return -1;
	}

	/*
	 *	Globally writable dictionaries means that users can control
	 *	the server configuration with little difficulty.
	 */
#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		fclose(fp);
		fr_strerror_printf("%s: Dictionary '%s' is globally writable.  Refusing to start "
				   "due to insecure configuration", __FUNCTION__, fn);
		return -1;
	}
#endif

	dict_stat_add(ctx->dict, &statbuf);

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
			fr_strerror_printf_push("%s: %s[%d]", __FUNCTION__, fn, line);
			fclose(fp);
			return -1;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(argv[0], "VALUE") == 0) {
			if (dict_read_process_value(ctx->dict, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
			if (!base_flags.named) {
				if (dict_read_process_attribute(ctx->dict, ctx->parent, ctx->block_vendor,
								argv + 1, argc - 1, &base_flags) == -1) goto error;
			} else {
				if (dict_read_process_named_attribute(ctx->dict, ctx->parent,
								      argv + 1, argc - 1, &base_flags) == -1) goto error;
			}
			continue;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(argv[0], "FLAGS") == 0) {
			if (dict_read_process_flags(ctx->dict, argv + 1, argc - 1, &base_flags) == -1) goto error;
			continue;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strcasecmp(argv[0], "$INCLUDE") == 0) {
			if (_dict_from_file(ctx, dir, argv[1], fn, line) < 0) goto error;
			continue;
		} /* $INCLUDE */

		/*
		 *	Optionally include a dictionary
		 */
		if (strcasecmp(argv[0], "$INCLUDE-") == 0) {
			int rcode = _dict_from_file(ctx, dir, argv[1], fn, line);

			if (rcode == -2) {
				fr_strerror_printf(NULL); /* reset error to nothing */
				continue;
			}

			if (rcode < 0) goto error;
			continue;
		} /* $INCLUDE- */

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(argv[0], "VENDOR") == 0) {
			if (dict_read_process_vendor(ctx->dict, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		if (strcasecmp(argv[0], "BEGIN-TLV") == 0) {
			fr_dict_attr_t const *common;

			if ((ctx->block_tlv_depth + 1) > FR_DICT_TLV_NEST_MAX) {
				fr_strerror_printf("TLVs are nested too deep");
				goto error;
			}

			if (argc != 2) {
				fr_strerror_printf("Invalid BEGIN-TLV entry");
				goto error;
			}

			da = fr_dict_attr_by_name(ctx->dict, argv[1]);
			if (!da) {
				fr_strerror_printf("Unknown attribute '%s'", argv[1]);
				goto error;
			}

			if (da->type != FR_TYPE_TLV) {
				fr_strerror_printf("Attribute '%s' should be a 'tlv', but is a '%s'",
						   argv[1],
						   fr_int2str(dict_attr_types, da->type, "?Unknown?"));
				goto error;
			}

			common = fr_dict_parent_common(ctx->parent, da, true);
			if (!common ||
			    (common->type == FR_TYPE_VSA) ||
			    (common->type == FR_TYPE_EVS)) {
				fr_strerror_printf("Attribute '%s' is not a child of '%s'", argv[1], ctx->parent->name);
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
				fr_strerror_printf("Too many END-TLV entries.  Mismatch at END-TLV %s", argv[1]);
				goto error;
			}

			if (argc != 2) {
				fr_strerror_printf("Invalid END-TLV entry");
				goto error;
			}

			da = fr_dict_attr_by_name(ctx->dict, argv[1]);
			if (!da) {
				fr_strerror_printf("Unknown attribute '%s'", argv[1]);
				goto error;
			}

			if (da != ctx->parent) {
				fr_strerror_printf("END-TLV %s does not match previous BEGIN-TLV %s", argv[1],
						   ctx->parent->name);
				goto error;
			}
			ctx->parent = ctx->block_tlv[ctx->block_tlv_depth];
			continue;
		} /* END-VENDOR */

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			unsigned int		vendor;
			fr_dict_attr_flags_t	flags;

			fr_dict_attr_t const	*vsa_da;
			fr_dict_attr_t const	*vendor_da;
			fr_dict_attr_t		*new;
			fr_dict_attr_t		*mutable;

			if (argc < 2) {
				fr_strerror_printf("Invalid BEGIN-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Check for extended attr VSAs
			 *
			 *	BEGIN-VENDOR foo format=Foo-Encapsulation-Attr
			 */
			if (argc > 2) {
				if (strncmp(argv[2], "format=", 7) != 0) {
					fr_strerror_printf("Invalid format %s", argv[2]);
					goto error;
				}

				p = argv[2] + 7;
				da = fr_dict_attr_by_name(ctx->dict, p);
				if (!da) {
					fr_strerror_printf("Invalid format for BEGIN-VENDOR: Unknown attribute '%s'",
							   p);
					goto error;
				}

				if (da->type != FR_TYPE_EVS) {
					fr_strerror_printf("Invalid format for BEGIN-VENDOR.  Attribute '%s' should "
							   "be 'evs' but is '%s'", p,
							   fr_int2str(dict_attr_types, da->type, "?Unknown?"));
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

					memcpy(&mutable, &ctx->parent, sizeof(mutable));
					new = fr_dict_attr_alloc(mutable, fr_dict_root(ctx->dict), "Vendor-Specific", 0,
								 FR_VENDOR_SPECIFIC, FR_TYPE_VSA, &flags);
					fr_dict_attr_child_add(mutable, new);
					vsa_da = new;
				}
			}

			/*
			 *	Create a VENDOR attribute on the fly, either in the context
			 *	of the EVS attribute, or the VSA (26) attribute.
			 */
			vendor_da = fr_dict_attr_child_by_num(vsa_da, vendor);
			if (!vendor_da) {
				memset(&flags, 0, sizeof(flags));

				if (vsa_da->type == FR_TYPE_VSA) {
					fr_dict_vendor_t const *dv;

					dv = fr_dict_vendor_by_num(ctx->dict, vendor);
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
				new = fr_dict_attr_alloc(mutable, ctx->parent,
							 argv[1], 0, vendor, FR_TYPE_VENDOR, &flags);
				fr_dict_attr_child_add(mutable, new);

				vendor_da = new;
			}
			ctx->parent = vendor_da;
			ctx->block_vendor = vendor;
			continue;
		} /* BEGIN-VENDOR */

		if (strcasecmp(argv[0], "END-VENDOR") == 0) {
			unsigned int vendor;

			if (argc != 2) {
				fr_strerror_printf("Invalid END-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			if (vendor != ctx->block_vendor) {
				fr_strerror_printf("END-VENDOR '%s' does not match any previous BEGIN-VENDOR",
						   argv[1]);
				goto error;
			}
			ctx->parent = ctx->dict->root;
			ctx->block_vendor = 0;
			continue;
		} /* END-VENDOR */

		/*
		 *	Any other string: We don't recognize it.
		 */
		fr_strerror_printf("Invalid keyword '%s'", argv[0]);
		goto error;
	}
	fclose(fp);
	return 0;
}

static int dict_from_file(fr_dict_t *dict,
			  char const *dir_name, char const *filename,
			  char const *src_file, int src_line)
{
	dict_from_file_ctx_t ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.dict = dict;
	ctx.parent = dict->root;

	return _dict_from_file(&ctx, dir_name, filename, src_file, src_line);
}


static bool defined_cast_types = false;

/** (re)initialize a protocol dictionary
 *
 * Initialize the directory, then fix the attr member of all attributes.
 *
 * First dictionary initialised will be set as the default internal dictionary.
 *
 * @param[in] ctx to allocate the dictionary from.
 * @param[out] out Where to write a pointer to the new dictionary.  Will free existing
 *	dictionary if files have changed and *out is not NULL.
 * @param[in] dir to read dictionary files from.
 * @param[in] fn file name to read.
 * @param[in] name to use for the root attributes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_from_file(TALLOC_CTX *ctx, fr_dict_t **out, char const *dir, char const *fn, char const *name)
{
	fr_dict_t *dict;

	if (!*out) {
		/* Pre-Allocate 5MB of pool memory for rapid startup */
		dict = talloc_zero(ctx, fr_dict_t);
		dict->pool = talloc_pool(dict, (1024 * 1024 * 5));
	} else {
		dict = *out;
		if (dict_stat_check(dict, dir, fn)) return 0;
	}

	/*
	 *	Free the old dictionaries
	 */
	if (*out == fr_dict_internal) fr_dict_internal = dict;
	TALLOC_FREE(*out);

	/*
	 *	Remove this at some point...
	 */
	if (!fr_dict_internal) fr_dict_internal = dict;

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 */
	dict->vendors_by_name = fr_hash_table_create(dict, dict_vendor_name_hash, dict_vendor_name_cmp, hash_pool_free);
	if (!dict->vendors_by_name) {
	error:
		talloc_free(dict);
		return -1;
	}

	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	dict->vendors_by_num = fr_hash_table_create(dict, dict_vendor_vendorpec_hash, dict_vendor_vendorpec_cmp, NULL);
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

	/*
	 *	Magic dictionary root attribute
	 */
	dict->root = (fr_dict_attr_t *)talloc_zero_array(dict, uint8_t, sizeof(fr_dict_attr_t) + strlen(name));
	strcpy(dict->root->name, name);
	talloc_set_type(dict->root, fr_dict_attr_t);
	dict->root->flags.is_root = 1;
	dict->root->type = FR_TYPE_TLV;
	dict->root->flags.type_size = 1;
	dict->root->flags.length = 1;

	dict->enum_fixup = NULL;        /* just to be safe. */

	/*
	 *	Add cast attributes.  We do it this way,
	 *	so cast attributes get added automatically for new types.
	 *
	 *	We manually add the attributes to the dictionary, and bypass
	 *	fr_dict_attr_add(), because we know what we're doing, and
	 *	that function does too many checks.
	 */
	if (!defined_cast_types) {
		FR_NAME_NUMBER const	*p;
		fr_dict_attr_flags_t	flags;
		char			*type_name;

		memset(&flags, 0, sizeof(flags));

		flags.internal = 1;

		for (p = dict_attr_types; p->name; p++) {
			fr_dict_attr_t *n;

			type_name = talloc_asprintf(dict->pool, "Tmp-Cast-%s", p->name);

			n = fr_dict_attr_alloc(dict->pool, dict->root, type_name,
					       0, FR_CAST_BASE + p->number, p->number, &flags);
			if (!n) goto error;

			if (!fr_hash_table_insert(dict->attributes_by_name, n)) goto error;

			/*
			 *	Set up parenting for the attribute.
			 */
			if (fr_dict_attr_child_add(dict->root, n) < 0) goto error;

			talloc_free(type_name);
		}
		defined_cast_types = true;
	}

	if (dict_from_file(dict, dir, fn, NULL, 0) < 0) goto error;

	/*
	 *	Resolve any VALUE aliases (enums) that were defined
	 *	before the attributes they reference.
	 */
	if (dict->enum_fixup) {
		fr_dict_attr_t const *da;
		dict_enum_fixup_t *this, *next;

		for (this = dict->enum_fixup; this != NULL; this = next) {
			fr_value_box_t	value;
			fr_type_t	type;

			next = this->next;
			da = fr_dict_attr_by_name(dict, this->attribute);
			if (!da) {
				fr_strerror_printf("No ATTRIBUTE '%s' defined for VALUE '%s'",
						   this->attribute, this->alias);
				goto error;
			}
			type = da->type;

			if (fr_value_box_from_str(this, &value, &type, NULL,
						  this->value, talloc_array_length(this->value) - 1, '\0', false) < 0) {
				fr_strerror_printf_push("Invalid VALUE for ATTRIBUTE \"%s\"", da->name);
				goto error;
			}

			if (fr_dict_enum_add_alias(da, this->alias, &value, false, false) < 0) goto error;

			/*
			 *	Just so we don't lose track of things.
			 */
			dict->enum_fixup = next;
		}
	}

	/*
	 *	Walk over all of the hash tables to ensure they're
	 *	initialized.  We do this because the threads may perform
	 *	lookups, and we don't want multi-threaded re-ordering
	 *	of the table entries.  That would be bad.
	 */
	fr_hash_table_walk(dict->vendors_by_name, hash_null_callback, NULL);
	fr_hash_table_walk(dict->vendors_by_num, hash_null_callback, NULL);

	fr_hash_table_walk(dict->values_by_da, hash_null_callback, NULL);
	fr_hash_table_walk(dict->values_by_alias, hash_null_callback, NULL);

	*out = dict;

	return 0;
}

int fr_dict_read(fr_dict_t *dict, char const *dir, char const *filename)
{
	INTERNAL_IF_NULL(dict);

	if (!dict->attributes_by_name) {
		fr_strerror_printf("%s: Must call fr_dict_from_file() before fr_dict_read()", __FUNCTION__);
		return -1;
	}

	return dict_from_file(dict, dir, filename, NULL, 0);
}

/*
 *	External API for testing
 */
int fr_dict_parse_str(fr_dict_t *dict, char *buf, fr_dict_attr_t const *parent, unsigned int vendor)
{
	int	argc;
	char	*argv[MAX_ARGV];
	fr_dict_attr_flags_t base_flags;

	INTERNAL_IF_NULL(dict);

	argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
	if (argc == 0) return 0;

	if (strcasecmp(argv[0], "VALUE") == 0) {
		return dict_read_process_value(dict, argv + 1, argc - 1);
	}

	if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
		if (!parent) parent = fr_dict_root(dict);

		memset(&base_flags, 0, sizeof(base_flags));

		return dict_read_process_attribute(dict, parent, vendor, argv + 1, argc - 1, &base_flags);
	}

	if (strcasecmp(argv[0], "VENDOR") == 0) {
		return dict_read_process_vendor(dict, argv + 1, argc - 1);
	}

	fr_strerror_printf("Invalid input '%s'", argv[0]);
	return -1;
}

/** Return the root attribute of a dictionary
 *
 * @param dict to return root for.
 * @return the root attribute of the dictionary.
 */
fr_dict_attr_t const *fr_dict_root(fr_dict_t const *dict)
{
	return dict->root;
}

/** Copy a known or unknown attribute to produce an unknown attribute
 *
 * Will copy the complete hierarchy down to the first known attribute.
 */
fr_dict_attr_t *fr_dict_unknown_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_dict_attr_t *new, *new_parent = NULL;
	fr_dict_attr_t const *parent;

	if (da->parent->flags.is_unknown) {
		new_parent = fr_dict_unknown_acopy(ctx, da->parent);
		parent = new_parent;
	} else {
		parent = da->parent;
	}

	new = fr_dict_attr_alloc(ctx, parent, da->name, da->vendor, da->attr, da->type, &da->flags);
	new->parent = parent;
	new->depth = da->depth;

	/*
	 *	Inverted tallloc hierarchy.
	 */
	if (new_parent) talloc_steal(new, parent);

	return new;
}

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old #fr_dict_attr_t, that is left up to the caller.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] old unknown attribute to add.
 * @return
 *	- Existing #fr_dict_attr_t if old was found in a dictionary.
 *	- A new entry representing old.
 */
fr_dict_attr_t const *fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent;
	fr_dict_attr_flags_t flags;

	if (!old) return NULL;

	da = fr_dict_attr_by_name(dict, old->name);
	if (da) return da;

	/*
	 *	Define the complete unknown hierarchy
	 */
	if (old->parent->flags.is_unknown) {
		parent = fr_dict_unknown_add(dict, old->parent);
	} else {
		parent = old->parent;
	}

	memcpy(&flags, &old->flags, sizeof(flags));
	flags.is_unknown = false;
	flags.is_raw = true;

	/*
	 *	Ensure the vendor is present in the
	 *	vendor hash.
	 */
	if (old->type == FR_TYPE_VENDOR) if (fr_dict_vendor_add(dict, old->name, old->attr) < 0) return NULL;

	/*
	 *	Look up the attribute by number.  If it doesn't exist,
	 *	add it both by name and by number.  If it does exist,
	 *	add it only by name.
	 */
	da = fr_dict_attr_child_by_num(parent, old->attr);
	if (da) {
		/*
		 *	Add the unknown by NAME.  e.g. if the admin does "Attr-26", we want
		 *	to return "Attr-26", and NOT "Vendor-Specific".  The rest of the server
		 *	is responsible for converting "Attr-26 = 0x..." to an actual attribute,
		 *	if it so desires.
		 */
		return fr_dict_attr_add_by_name(dict, parent, old->name, old->attr, old->type, flags);
	}

	/*
	 *	Add the attribute by both name and number.
	 */
	if (fr_dict_attr_add(dict, parent, old->name, old->attr, old->type, flags) < 0) return NULL;

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
 * @param da to free.
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

/** Initialises an unknown attribute
 *
 * Initialises a dict attr for an unknown attribute/vendor/type without adding
 * it to dictionary pools/hashes.
 *
 * Unknown attributes are used to transparently pass undecodeable attributes
 * when we proxy requests.
 *
 * @param[in,out] da struct to initialise, must be at least FR_DICT_ATTR_SIZE bytes.
 * @param[in] parent of the unknown attribute (may also be unknown).
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return 0 on success.
 */
static int fr_dict_unknown_from_fields(fr_dict_attr_t *da, fr_dict_attr_t const *parent,
				       unsigned int vendor, unsigned int attr)
{
	char *p;
	size_t len = 0;
	size_t bufsize = FR_DICT_ATTR_MAX_NAME_LEN;

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	memset(da, 0, FR_DICT_ATTR_SIZE);

	da->attr = attr;
	da->vendor = vendor;
	da->type = FR_TYPE_OCTETS;
	da->flags.is_unknown = true;
	da->flags.is_raw = true;
	da->flags.is_pointer = true;
	da->parent = parent;
	da->depth = parent->depth + 1;

	p = da->name;

	len = snprintf(p, bufsize, "Attr-");
	p += len;
	bufsize -= len;

	dict_print_attr_oid(p, bufsize, NULL, da);
	return 0;
}

/** Allocates an unknown attribute
 *
 * @copybrief fr_dict_unknown_from_fields
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct EVS or VSA attribute. This is accessible via da->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx to allocate DA in.
 * @param[in] parent of the unknown attribute (may also be unknown).
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return 0 on success.
 */
fr_dict_attr_t const *fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						   unsigned int vendor, unsigned int attr)
{
	uint8_t			*p;
	fr_dict_attr_t const	*da;
	fr_dict_attr_t		*n;
	fr_dict_attr_t		*new_parent = NULL;

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

	p = talloc_zero_array(ctx, uint8_t, FR_DICT_ATTR_SIZE);
	if (!p) {
		fr_strerror_printf("Out of memory");
		parent = new_parent;	/* Stupid const rules */
		fr_dict_unknown_free(&parent);
		return NULL;
	}
	n = (fr_dict_attr_t *)p;
	talloc_set_type(n, fr_dict_attr_t);

	if (!fr_cond_assert(parent)) { /* coverity */
		talloc_free(p);
		return NULL;
	}

	if (fr_dict_unknown_from_fields(n, parent, vendor, attr) < 0) {
		talloc_free(p);
		parent = new_parent;	/* Stupid const rules */
		fr_dict_unknown_free(&parent);
		return NULL;
	}

	/*
	 *	The config files may reference the unknown by name.
	 *	If so, use the pre-defined name instead of an unknown
	 *	one.
	 *
	 *	@fixme: pass the root into this function!
	 */
	da = fr_dict_attr_by_name(NULL, n->name);
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

/** Build an unknown vendor, parented by a VSA or EVS attribute
 *
 * This allows us to complete the path back to the dictionary root in the case
 * of unknown attributes with unknown vendors.
 *
 * @note Will return known vendors attributes where possible.  Do not free directly,
 *	use #fr_dict_unknown_free.
 *
 * @param[in] ctx to allocate the vendor attribute in.
 * @param[out] out Where to write point to new unknown dict attr representing the unknown vendor.
 * @param[in] parent of the vendor attribute, either an EVS or VSA attribute.
 * @param[in] vendor id.
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

		*out = fr_dict_attr_alloc(ctx, parent, NULL, 0, vendor, FR_TYPE_VENDOR, &flags);

		return 0;

	case FR_TYPE_VENDOR:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return -1;
		fr_strerror_printf("Unknown vendor cannot be parented by another vendor");
		return -1;

	default:
		fr_strerror_printf("Unknown vendors can only be parented by 'vsa' or 'evs' "
				   "attributes, not '%s'", fr_int2str(dict_attr_types, parent->type, "?Unknown?"));
		return -1;
	}
}

/** Initialise a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @copybrief fr_dict_unknown_from_fields
 *
 * @param[in] ctx	to allocate the attribute in.
 * @param[out] out	Where to write the new attribute to.
 * @param[in] parent	of the unknown attribute (may also be unknown).
 * @param[in] num	of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_dict_unknown_attr_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				     	  fr_dict_attr_t const *parent, unsigned long num)
{
	fr_dict_attr_t		*da;
	unsigned long		vendor = 0;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
					.is_raw = true,
					.is_pointer = true
				};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	if (parent->type == FR_TYPE_VENDOR) vendor = parent->attr;

	da = fr_dict_attr_alloc(ctx, parent, NULL, vendor, num, FR_TYPE_OCTETS, &flags);
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
 * @copybrief fr_dict_unknown_from_fields
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct EVS or VSA attribute. This is accessible via vp->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx	to alloc new attribute in.
 * @param[out] out	Where to write the head of the chain unknown dictionary attributes.
 * @param[in] parent	Attribute to use as the root for resolving OIDs in.  Usually
 *			the root of a protocol dictionary.
 * @param[in] oid_str	of attribute.
 * @return
 *	- The number of bytes parsed on success.
 *	- <= 0 on failure.  Negative offset indicates parse error position.
 */
ssize_t fr_dict_unknown_afrom_oid_str(TALLOC_CTX *ctx, fr_dict_attr_t **out,
			      	      fr_dict_attr_t const *parent, char const *oid_str)
{
	char const		*p = oid_str, *end = oid_str + strlen(oid_str);
	fr_dict_attr_t const	*our_parent = parent;
	TALLOC_CTX		*top_ctx = NULL, *our_ctx = ctx;

	fr_dict_attr_t		*n = NULL;

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	if (fr_dict_valid_name(oid_str, -1) < 0) return -1;

	/*
	 *	All unknown attributes are of the form "Attr-#-#-#-#"
	 */
	if (strncasecmp(p, "Attr-", 5) != 0) {
		fr_strerror_printf("Unknown attribute '%s'", oid_str);
		return 0;
	}
	p += 5;

	do {
		unsigned int		num;
		fr_dict_attr_t const	*da = NULL;

		if (fr_dict_oid_component(&num, &p) < 0) {
		error:
			talloc_free(top_ctx);
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
						if (fr_dict_unknown_vendor_afrom_num(our_ctx, &n,
										     our_parent, num) < 0) {
							goto error;
						}
						da = n;
					}
					break;

				case FR_TYPE_TLV:
				case FR_TYPE_EXTENDED:
				case FR_TYPE_LONG_EXTENDED:
				is_root:
					if (fr_dict_unknown_attr_afrom_num(our_ctx, &n, our_parent, num) < 0) {
						goto error;
					}

					da = n;
					break;

				/*
				 *	Can't have a FR_TYPE_STRING inside a
				 *	FR_TYPE_STRING (for example)
				 */
				default:
					fr_strerror_printf("Parent OID component (%s) in \"%.*s\" specified a "
							   "non-structural type (%s)", our_parent->name,
							   (int)(p - oid_str), oid_str,
							   fr_int2str(dict_attr_types, our_parent->type, "<INVALID>"));
					goto error;
				}
			}
			our_parent = da;

			if (n && n->flags.is_unknown) {
				if (top_ctx == NULL) top_ctx = n;	/* Track first unknown */
				our_ctx = n;
			}


			break;

		/*
		 *	Leaf attribute
		 */
		case '\0':
			if (fr_dict_unknown_attr_afrom_num(our_ctx, &n, our_parent, num) < 0) goto error;
			break;
		}
		p++;
	} while (p < end);

	if (!n) return 0;

	/*
	 *	Invert the talloc hierarchy, so that if the unknown
	 *	attribute is freed, any unknown parents are also freed.
	 */
	for (our_parent = n->parent, our_ctx = n;
	     our_parent && our_parent->flags.is_unknown;
	     our_parent = our_parent->parent) {
		fr_dict_attr_t *tmp;

		memcpy(&tmp, &our_parent, sizeof(tmp));			/* const issues *sigh* */

		our_ctx = talloc_steal(our_ctx, tmp);
	}

	VERIFY_DA(n);

	*out = n;

	return end - oid_str;
}

/** Create a dictionary attribute by name embedded in another string
 *
 * Find the first invalid attribute name char in the string pointed to by name.
 *
 * Copy the characters between the start of the name string and the first none
 * #fr_dict_attr_allowed_chars char to a buffer and initialise da as an unknown attribute.
 *
 * @param[in] ctx	To allocate unknown #fr_dict_attr_t in.
 * @param[out] out	Where to write the head of the chain unknown dictionary attributes.
 * @param[in] parent	Attribute to use as the root for resolving OIDs in.  Usually
 *			the root of a protocol dictionary.
 * @param[in] name	string start.
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
	for (p = name; fr_dict_attr_allowed_chars[(int)*p] || (*p == '.') || (*p == '-'); p++);

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
 * @param dict to search in.
 * @param da Nested tlv structure to convert.
 * @return
 *	- NULL if we can't.
 *	- Known attribute if we can.
 */
fr_dict_attr_t const *fr_dict_attr_known(fr_dict_t *dict, fr_dict_attr_t const *da)
{
	INTERNAL_IF_NULL(dict);

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

static void fr_dict_snprint_flags(char *out, size_t outlen, fr_dict_attr_flags_t flags)
{
	char *p = out, *end = p + outlen;
	size_t len;

	out[0] = '\0';

#define FLAG_SET(_flag) \
do { \
	if (flags._flag) {\
		p += strlcpy(p, STRINGIFY(_flag)",", end - p);\
		if (p >= end) return;\
	}\
} while (0)

	FLAG_SET(is_root);
	FLAG_SET(is_unknown);
	FLAG_SET(is_raw);
	FLAG_SET(internal);
	FLAG_SET(has_tag);
	FLAG_SET(array);
	FLAG_SET(has_value);
	FLAG_SET(concat);
	FLAG_SET(is_pointer);
	FLAG_SET(virtual);
	FLAG_SET(compare);

	if (flags.encrypt) {
		p += snprintf(p, end - p, "encrypt=%i,", flags.encrypt);
		if (p >= end) return;
	}

	if (flags.length) {
		p += snprintf(p, end - p, "length=%i,", flags.length);
		if (p >= end) return;
	}

	if (!out[0]) return;

	/*
	 *	Trim the comma
	 */
	len = strlen(out);
	if (out[len - 1] == ',') out[len - 1] = '\0';
}

void fr_dict_print(fr_dict_attr_t const *da, int depth)
{
	char buff[256];
	unsigned int i;
	char const *name;

	fr_dict_snprint_flags(buff, sizeof(buff), da->flags);

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

	case FR_TYPE_LONG_EXTENDED:
		name = "LONG EXTENDED";
		break;

	case FR_TYPE_STRUCT:
		name = "STRUCT";
		break;

	default:
		name = "ATTRIBUTE";
		break;
	}

	printf("%u%.*s%s \"%s\" vendor: %x (%u), num: %x (%u), type: %s, flags: %s\n", da->depth, depth,
	       "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", name, da->name,
	       da->vendor, da->vendor, da->attr, da->attr,
	       fr_int2str(dict_attr_types, da->type, "?Unknown?"), buff);

	if (da->children) for (i = 0; i < talloc_array_length(da->children); i++) {
		if (da->children[i]) {
			fr_dict_attr_t const *bin;

			for (bin = da->children[i]; bin; bin = bin->next) fr_dict_print(bin, depth + 1);
		}
	}
}

/** Find a common ancestor that two TLV type attributes share
 *
 * @param a first TLV attribute.
 * @param b second TLV attribute.
 * @param is_ancestor Enforce a->b relationship (a is parent or ancestor of b).
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
 * @param[out] out Value of component.
 * @param[in] oid string to parse.
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
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[out] attr Number we parsed.
 * @param[in,out] vendor number of attribute.
 * @param[in,out] parent attribute (or root of dictionary).  Will be updated to the parent
 *	directly beneath the leaf.
 * @param[in] oid string to parse.
 * @return
 *	- > 0 on success (number of bytes parsed).
 *	- <= 0 on parse error (negative offset of parse error).
 */
ssize_t fr_dict_attr_by_oid(fr_dict_t *dict, fr_dict_attr_t const **parent,
			    unsigned int *vendor, unsigned int *attr, char const *oid)
{
	char const		*p = oid;
	unsigned int		num = 0;
	ssize_t			slen;

	if (!fr_cond_assert(parent)) return 0;
	INTERNAL_IF_NULL(dict);

	*attr = 0;

	if (fr_dict_oid_component(&num, &p) < 0) return oid - p;

	/*
	 *	Record progress even if we error out.
	 *
	 *	Don't change this, you will break things.
	 */
	*attr = num;

	/*
	 *	Look for 26.VID.x.y
	 *
	 *	This allows us to specify a VSA if our parent is the root
	 *	of the dictionary, and we're operating outside of a vendor
	 *	block.
	 *
	 *	The additional code is because we need at least three components
	 *	the VSA attribute (26), the vendor ID, and actual attribute.
	 */
	if (((*parent)->flags.is_root) && !*vendor && (num == FR_VENDOR_SPECIFIC)) {
		fr_dict_vendor_t const *dv;

		if (p[0] == '\0') {
			fr_strerror_printf("Vendor attribute must specify a VID");
			return oid - p;
		}
		p++;

		if (fr_dict_oid_component(&num, &p) < 0) return oid - p;
		if (p[0] == '\0') {
			fr_strerror_printf("Vendor attribute must specify a child");
			return oid - p;
		}
		p++;

		dv = fr_dict_vendor_by_num(dict, num);
		if (!dv) {
			fr_strerror_printf("Unknown vendor '%u' ", num);
			return oid - p;
		}
		*vendor = dv->vendorpec;	/* Record vendor number */

		/*
		 *	Recurse to get the attribute.
		 */
		slen = fr_dict_attr_by_oid(dict, parent, vendor, attr, p);
		if (slen <= 0) return slen - (p - oid);

		slen += p - oid;
		return slen;
	}

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
	if (((*parent)->type != FR_TYPE_VENDOR) && !(*parent)->flags.is_root &&
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

		slen = fr_dict_attr_by_oid(dict, parent, vendor, attr, p);
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

/** Attempt to locate the protocol dictionary containing an attribute
 *
 * @note Unlike fr_dict_by_attr_name, doesn't search through all the dictionaries,
 *	just uses the fr_dict_attr_t hierarchy and the talloc hierarchy to locate
 *	the dictionary (much much faster and more scalable).
 *
 * @param[in] da To get the containing dictionary for.
 * @return
 *	- The dictionary containing da.
 *	- NULL.
 */
fr_dict_t *fr_dict_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *da_p = da;

	while (da_p->parent) {
		da_p = da_p->parent;
		VERIFY_DA(da_p);
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

/** Look up a vendor by its name
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] name to search for.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that name was regitered for this protocol.
 */
int fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name)
{
	fr_dict_vendor_t *dv;
	size_t buffer[(sizeof(*dv) + FR_DICT_VENDOR_MAX_NAME_LEN + sizeof(size_t) - 1) / sizeof(size_t)];

	if (!name) return 0;
	INTERNAL_IF_NULL(dict);

	dv = (fr_dict_vendor_t *)buffer;
	strlcpy(dv->name, name, FR_DICT_VENDOR_MAX_NAME_LEN + 1);

	dv = fr_hash_table_finddata(dict->vendors_by_name, dv);
	if (!dv) return 0;

	return dv->vendorpec;
}

/** Look up a vendor by its PEN
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] vendorpec to search for.
 * @return
 *	- The vendor.
 *	- NULL if no vendor with that number was regitered for this protocol.
 */
fr_dict_vendor_t const *fr_dict_vendor_by_num(fr_dict_t const *dict, int vendorpec)
{
	fr_dict_vendor_t dv;

	INTERNAL_IF_NULL(dict);

	dv.vendorpec = vendorpec;

	return fr_hash_table_finddata(dict->vendors_by_num, &dv);
}

/** Return the vendor that parents this attribute
 *
 * @note Uses the dictionary hierachy to determine the parent
 *
 * @param[in] da The dictionary attribute to find parent for.
 * @return
 *	- NULL if the attribute has no vendor.
 *	- A fr_dict_attr_t representing this attribute's associated vendor.
 */
fr_dict_attr_t const *fr_dict_vendor_attr_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *da_p = da;

	while (da_p->parent) {
		if (da_p->type == FR_TYPE_VENDOR) break;
		da_p = da_p->parent;
	}
	if (da_p->type != FR_TYPE_VENDOR) return NULL;

	return da_p;
}

/** Return vendor attribute for the specified dictionary and vendorpec
 *
 * @param[in] dict		to search for the vendor in.
 * @param[in] vendor_root	of the vendor root attribute.  Could be 26 (for example) in RADIUS.
 * @param[in] vendor		to find.
 * @return
 *	- NULL if vendor does not exist.
 *	- A fr_dict_attr_t representing the vendor in the dictionary hierarchy.
 */
fr_dict_attr_t const *fr_dict_vendor_attr_by_num(fr_dict_t const *dict, unsigned int vendor_root, unsigned int vendor)
{
	fr_dict_attr_t const *da;

	if (!dict) return NULL;

	da = fr_dict_attr_child_by_num(fr_dict_root(dict), vendor_root);
	if (!da) {
		fr_strerror_printf("Vendor root attribute %i not defined in dict %s", vendor_root, dict->root->name);
		return NULL;
	}

	switch (da->type) {
	case FR_TYPE_VSA:	/* Vendor specific attribute */
	case FR_TYPE_EVS:	/* Extended vendor specific attribute */
		break;

	default:
		fr_strerror_printf("Wrong type for vendor root, expected '%s' or '%s' got '%s'",
				   fr_int2str(dict_attr_types, FR_TYPE_VSA, "<INVALID>"),
				   fr_int2str(dict_attr_types, FR_TYPE_EVS, "<INVALID>"),
				   fr_int2str(dict_attr_types, da->type, "<INVALID>"));
		return NULL;
	}

	da = fr_dict_attr_child_by_num(da, vendor);
	if (!da) {
		fr_strerror_printf("Vendor %i not defined", vendor);
		return NULL;
	}

	if (da->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Wrong type for vendor, expected '%s' got '%s'",
				   fr_int2str(dict_attr_types, da->type, "<INVALID>"),
				   fr_int2str(dict_attr_types, FR_TYPE_VENDOR, "<INVALID>"));
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
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in,out] name string start.
 * @return
 * 	- Attribute matching name.
 *  	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_name_substr(fr_dict_t const *dict, char const **name)
{
	fr_dict_attr_t *find;
	fr_dict_attr_t const *da;
	char const *p;
	size_t len;
	uint32_t buffer[(sizeof(*find) + FR_DICT_ATTR_MAX_NAME_LEN + 3) / 4];

	if (!name || !*name) return NULL;
	INTERNAL_IF_NULL(dict);

	find = (fr_dict_attr_t *)buffer;

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = *name; fr_dict_attr_allowed_chars[(int)*p]; p++);

	len = p - *name;
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
		return NULL;
	}
	strlcpy(find->name, *name, len + 1);

	da = fr_hash_table_finddata(dict->attributes_by_name, find);
	if (!da) {
		fr_strerror_printf("Unknown attribute '%s'", find->name);
		return NULL;
	}
	*name = p;

	return da;
}

/** Locate a #fr_dict_attr_t by its name
 *
 * @note Unlike attribute numbers, attribute names are unique to the dictionary.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] name of the attribute to locate.
 * @return
 * 	- Attribute matching name.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_name(fr_dict_t const *dict, char const *name)
{
	fr_dict_attr_t *da;
	uint32_t buffer[(sizeof(*da) + FR_DICT_ATTR_MAX_NAME_LEN + 3) / 4];

	if (!name) return NULL;
	INTERNAL_IF_NULL(dict);

	da = (fr_dict_attr_t *)buffer;
	strlcpy(da->name, name, FR_DICT_ATTR_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(dict->attributes_by_name, da);
}

/** Lookup a #fr_dict_attr_t by its vendor and attribute numbers
 *
 * @note This is a deprecated function, new code should use #fr_dict_attr_child_by_num.
 *
 * @param[in] dict of protocol context we're operating in.  If NULL the internal
 *	dictionary will be used.
 * @param[in] vendor number of the attribute.
 * @param[in] attr number of the attribute.
 * @return
 * 	- Attribute matching vendor/attr.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_num(fr_dict_t *dict, unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t const *parent;

	INTERNAL_IF_NULL(dict);

	if (vendor == 0) return fr_dict_attr_child_by_num(dict->root, attr);

	parent = fr_dict_attr_child_by_num(dict->root, FR_VENDOR_SPECIFIC);
	if (!parent) return NULL;

	parent = fr_dict_attr_child_by_num(parent, vendor);
	if (!parent) return NULL;

	return fr_dict_attr_child_by_num(parent, attr);
}

/** Lookup a attribute by its its vendor and attribute numbers and data type
 *
 * @note Only works with FR_TYPE_COMBO_IP
 *
 * @param[in] da	to look for type variant of.
 * @param[in] type	Variant of attribute to lookup.
 * @return
 * 	- Attribute matching parent/attr/type.
 * 	- NULL if no matching attribute could be found.
 */
fr_dict_attr_t const *fr_dict_attr_by_type(fr_dict_attr_t const *da, fr_type_t type)
{
	fr_dict_t	*dict = fr_dict_by_da(da);
	fr_dict_attr_t	find = {
				.parent = da->parent,
				.attr = da->attr,
				.type = type
			};

	return fr_hash_table_finddata(dict->attributes_combo, &find);
}

/** Check if a child attribute exists in a parent using a pointer (da)
 *
 * @param parent to check for child in.
 * @param child to look for.
 * @return
 *	- The child attribute on success.
 *	- NULL if the child attribute does not exist.
 */
inline fr_dict_attr_t const *fr_dict_attr_child_by_da(fr_dict_attr_t const *parent, fr_dict_attr_t const *child)
{
	fr_dict_attr_t const *bin;

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
 * @param parent to check for child in.
 * @param attr number to look for.
 * @return
 *	- The child attribute on success.
 *	- NULL if the child attribute does not exist.
 */
inline fr_dict_attr_t const *fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *bin;

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
 * @param[in] dict	of protocol context we're operating in.
 *			If NULL the internal dictionary will be used.
 * @param[in] da	to search in.
 * @param[in] value to search for.
 * @return
 * 	- Matching #fr_dict_enum_t.
 * 	- NULL if no matching #fr_dict_enum_t could be found.
 */
fr_dict_enum_t *fr_dict_enum_by_value(fr_dict_t *dict, fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_enum_t enumv, *dv;

	if (!da) return NULL;

	INTERNAL_IF_NULL(dict);

	if (!fr_cond_assert(value->type == da->type)) return NULL;

	/*
	 *	First, look up aliases.
	 */
	enumv.da = da;
	enumv.alias = "";

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
 * @param[in] dict	of protocol context we're operating in.  If NULL the internal
 *			dictionary will be used.
 * @param[in] da	to search in.
 * @param[in] value	number to search for.
 * @return
 * 	- Name of value.
 * 	- NULL if no matching value could be found.
 */
char const *fr_dict_enum_alias_by_value(fr_dict_t *dict, fr_dict_attr_t const *da, fr_value_box_t const *value)
{
	fr_dict_enum_t *dv;

	if (!da) return NULL;

	INTERNAL_IF_NULL(dict);

	dv = fr_dict_enum_by_value(dict, da, value);
	if (!dv) return "";

	return dv->alias;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_enum_t *fr_dict_enum_by_alias(fr_dict_t *dict, fr_dict_attr_t const *da, char const *alias)
{
	fr_dict_enum_t find, *found;

	memset(&find, 0, sizeof(find));

	if (!alias) return NULL;

	INTERNAL_IF_NULL(dict);

	find.da = da;
	find.alias = alias;

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	found = fr_hash_table_finddata(dict->values_by_alias, &find);
	if (found) find.da = found->da;

	return fr_hash_table_finddata(dict->values_by_alias, &find);
}

/*
 *	[a-zA-Z0-9_-:.]+
 */
ssize_t fr_dict_valid_name(char const *name, ssize_t len)
{
	uint8_t const *p = (uint8_t const *)name, *end;

	if (len < 0) len = strlen(name);
	end = p + len;

	do {
		if (!fr_dict_attr_allowed_chars[*p]) {
			char buff[5];

			fr_snprint(buff, sizeof(buff), (char const *)p, 1, '\'');
			fr_strerror_printf("Invalid character '%s' in attribute name", buff);

			return -(p - (uint8_t const *)name);
		}
		p++;
	} while (p < end);

	return 0;
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
			     file, line, da->name, da->vendor, da->attr);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	if (da->depth > FR_DICT_MAX_TLV_STACK) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
			     "Indicated depth (%u) greater than TLV stack depth (%u)",
			     file, line, da->name, da->vendor, da->attr, da->depth, FR_DICT_MAX_TLV_STACK);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	for (da_p = da; da_p; da_p = da_p->next) {
		(void) talloc_get_type_abort_const(da_p, fr_dict_attr_t);
	}

	for (i = da->depth, da_p = da; (i >= 0) && da; i--, da_p = da_p->parent) {
		if (i != (int)da_p->depth) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t %s vendor: %i, attr %i: "
				     "Depth out of sequence, expected %i, got %u",
				     file, line, da->name, da->vendor, da->attr, i, da_p->depth);

			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

	}

	if ((i + 1) < 0) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: fr_dict_attr_t top of hierarchy was not at depth 0",
			     file, line);

		if (!fr_cond_assert(0)) fr_exit_now(1);
	}
}
