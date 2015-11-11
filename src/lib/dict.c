/*
 * dict.c	Routines to read the dictionary file.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */
RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#ifdef WITH_DHCP
#include	<freeradius-devel/dhcp.h>
#endif

#include	<ctype.h>

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include	<sys/stat.h>
#endif

/** Vendors and attribute names
 *
 * It's very likely that the same vendors will operate in multiple
 * protocol spaces, but number their attributes differently, so we need
 * per protocol dictionaries.
 *
 * There would also be conflicts for DHCP(v6)/RADIUS attributes etc...
 */
struct fr_dict {
	fr_hash_table_t		*vendors_by_name;
	fr_hash_table_t		*vendors_by_num;

	fr_hash_table_t		*attributes_by_name;	//!< Lookup an attribute by its name.
	fr_hash_table_t		*attributes_by_num;	//!< Lookup an attribute by its number.

	fr_hash_table_t		*attributes_combo;	//!< Attributes that can be multiple types.

	fr_hash_table_t		*values_by_num;		//!< Lookup an attribute enum by integer value.
	fr_hash_table_t		*values_by_name;	//!< Lookup an attribute enum by name.

	fr_dict_attr_t		*base_attrs[256];	//!< Quick lookup for protocols with an 8bit attribute space.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.
	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce mallocs.
};

fr_dict_t *fr_main_dict;

/*
 *	For faster HUP's, we cache the stat information for
 *	files we've $INCLUDEd
 */
typedef struct dict_stat_t {
	struct dict_stat_t *next;
	struct stat stat_buf;
} dict_stat_t;

static dict_stat_t *stat_head = NULL;
static dict_stat_t *stat_tail = NULL;

typedef struct value_fixup_t {
	char		attrstr[FR_DICT_ATTR_MAX_NAME_LEN];
	fr_dict_value_t	*dval;
	struct value_fixup_t *next;
} value_fixup_t;

/*
 *	So VALUEs in the dictionary can have forward references.
 */
static value_fixup_t *value_fixup = NULL;

const FR_NAME_NUMBER dict_attr_types[] = {
	{ "integer",       PW_TYPE_INTEGER },
	{ "string",        PW_TYPE_STRING },
	{ "ipaddr",        PW_TYPE_IPV4_ADDR },
	{ "date",          PW_TYPE_DATE },
	{ "abinary",       PW_TYPE_ABINARY },
	{ "octets",        PW_TYPE_OCTETS },
	{ "ifid",          PW_TYPE_IFID },
	{ "ipv6addr",      PW_TYPE_IPV6_ADDR },
	{ "ipv6prefix",    PW_TYPE_IPV6_PREFIX },
	{ "byte",          PW_TYPE_BYTE },
	{ "short",         PW_TYPE_SHORT },
	{ "ether",         PW_TYPE_ETHERNET },
	{ "combo-ip",      PW_TYPE_COMBO_IP_ADDR },
	{ "tlv",           PW_TYPE_TLV },
	{ "signed",        PW_TYPE_SIGNED },
	{ "extended",      PW_TYPE_EXTENDED },
	{ "long-extended", PW_TYPE_LONG_EXTENDED },
	{ "evs",           PW_TYPE_EVS },
	{ "uint8",         PW_TYPE_BYTE },
	{ "uint16",        PW_TYPE_SHORT },
	{ "uint32",        PW_TYPE_INTEGER },
	{ "int32",         PW_TYPE_SIGNED },
	{ "integer64",     PW_TYPE_INTEGER64 },
	{ "uint64",        PW_TYPE_INTEGER64 },
	{ "ipv4prefix",    PW_TYPE_IPV4_PREFIX },
	{ "cidr",          PW_TYPE_IPV4_PREFIX },
	{ "vsa",           PW_TYPE_VSA },
	{ "vendor",        PW_TYPE_VENDOR },
	{ NULL,            0 }
};

/*
 *	Map data types to min / max data sizes.
 */
const size_t dict_attr_sizes[PW_TYPE_MAX][2] = {
	[PW_TYPE_INVALID]	= {~0, 0},
	[PW_TYPE_STRING]	= {0, ~0},
	[PW_TYPE_INTEGER]	= {4, 4 },
	[PW_TYPE_IPV4_ADDR]	= {4, 4},
	[PW_TYPE_DATE]		= {4, 4},
	[PW_TYPE_ABINARY]	= {32, ~0},
	[PW_TYPE_OCTETS]	= {0, ~0},
	[PW_TYPE_IFID]		= {8, 8},
	[PW_TYPE_IPV6_ADDR]	= {16, 16},
	[PW_TYPE_IPV6_PREFIX]	= {2, 18},
	[PW_TYPE_BYTE]		= {1, 1},
	[PW_TYPE_SHORT]		= {2, 2},
	[PW_TYPE_ETHERNET]	= {6, 6},
	[PW_TYPE_SIGNED]	= {4, 4},
	[PW_TYPE_COMBO_IP_ADDR]	= {4, 16},
	[PW_TYPE_TLV]		= {2, ~0},
	[PW_TYPE_EXTENDED]	= {2, ~0},
	[PW_TYPE_LONG_EXTENDED]	= {3, ~0},
	[PW_TYPE_EVS]		= {6, ~0},
	[PW_TYPE_INTEGER64]	= {8, 8},
	[PW_TYPE_IPV4_PREFIX]	= {6, 6},
	[PW_TYPE_VSA]		= {4, ~0}
};

/*
 *	For packing multiple TLV numbers into one 32-bit integer.  The
 *	first 3 bytes are just the 8-bit number.  The next two are
 *	more limited.  We only allow 31 attributes nested 3 layers
 *	deep, and only 7 nested 4 layers deep.  This should be
 *	sufficient for most purposes.
 *
 *	For TLVs and extended attributes, we packet the base attribute
 *	number into the upper 8 bits of the "vendor" field.
 *
 *	e.g.	OID		attribute	vendor
 *		241.1		1		(241 << 24)
 *		241.26.9.1	1		(241 << 24) | (9)
 *		241.1.2		1 | (2 << 8)	(241 << 24)
 */
#define MAX_TLV_NEST (4)
/*
 *	Bit packing:
 *	8 bits of base attribute
 *	8 bits for nested TLV 1
 *	8 bits for nested TLV 2
 *	5 bits for nested TLV 3
 *	3 bits for nested TLV 4
 */
int const fr_attr_max_tlv = MAX_TLV_NEST;
int const fr_attr_shift[MAX_TLV_NEST + 1] = { 0, 8, 16, 24, 29 };

int const fr_attr_mask[MAX_TLV_NEST + 1] = { 0xff, 0xff, 0xff, 0x1f, 0x07 };

/*
 *	attr & fr_attr_parent_mask[i] == Nth parent of attr
 */
static unsigned int const fr_attr_parent_mask[MAX_TLV_NEST + 1] = { 0, 0x000000ff, 0x0000ffff, 0x00ffffff, 0x1fffffff };

/*
 *	Create the hash of the name.
 *
 *	We copy the hash function here because it's substantially faster.
 */
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

static uint32_t dict_hashname(char const *name)
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

/*
 *	Hash callback functions.
 */
static uint32_t dict_attr_name_hash(void const *data)
{
	return dict_hashname(((fr_dict_attr_t const *)data)->name);
}

static int dict_attr_name_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one;
	fr_dict_attr_t const *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_attr_value_hash(void const *data)
{
	uint32_t hash;
	fr_dict_attr_t const *attr = data;

	hash = fr_hash(&attr->vendor, sizeof(attr->vendor));
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

static int dict_attr_value_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one;
	fr_dict_attr_t const *b = two;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	return a->attr - b->attr;
}

static uint32_t dict_attr_combo_hash(void const *data)
{
	uint32_t hash;
	fr_dict_attr_t const *attr = data;

	hash = fr_hash(&attr->vendor, sizeof(attr->vendor));
	hash = fr_hash_update(&attr->type, sizeof(attr->type), hash);
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

static int dict_attr_combo_cmp(void const *one, void const *two)
{
	fr_dict_attr_t const *a = one;
	fr_dict_attr_t const *b = two;

	if (a->type < b->type) return -1;
	if (a->type > b->type) return +1;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	return a->attr - b->attr;
}

static uint32_t dict_vendor_name_hash(void const *data)
{
	return dict_hashname(((fr_dict_vendor_t const *)data)->name);
}

static int dict_vendor_name_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_vendor_value_hash(void const *data)
{
	return fr_hash(&(((fr_dict_vendor_t const *)data)->vendorpec),
		       sizeof(((fr_dict_vendor_t const *)data)->vendorpec));
}

static int dict_vendor_value_cmp(void const *one, void const *two)
{
	fr_dict_vendor_t const *a = one;
	fr_dict_vendor_t const *b = two;

	return a->vendorpec - b->vendorpec;
}

static uint32_t dict_value_name_hash(void const *data)
{
	uint32_t hash;
	fr_dict_value_t const *dval = data;

	hash = dict_hashname(dval->name);
	hash = fr_hash_update(&dval->vendor, sizeof(dval->vendor), hash);
	return fr_hash_update(&dval->attr, sizeof(dval->attr), hash);
}

static int dict_value_name_cmp(void const *one, void const *two)
{
	int rcode;
	fr_dict_value_t const *a = one;
	fr_dict_value_t const *b = two;

	rcode = a->attr - b->attr;
	if (rcode != 0) return rcode;

	rcode = a->vendor - b->vendor;
	if (rcode != 0) return rcode;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_value_value_hash(void const *data)
{
	uint32_t hash;
	fr_dict_value_t const *dval = data;

	hash = fr_hash(&dval->attr, sizeof(dval->attr));
	hash = fr_hash_update(&dval->vendor, sizeof(dval->vendor), hash);
	return fr_hash_update(&dval->value, sizeof(dval->value), hash);
}

static int dict_value_value_cmp(void const *one, void const *two)
{
	int rcode;
	fr_dict_value_t const *a = one;
	fr_dict_value_t const *b = two;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	rcode = a->attr - b->attr;
	if (rcode != 0) return rcode;

	return a->value - b->value;
}

/*
 *	Free the list of stat buffers
 */
static void dict_stat_free(void)
{
	dict_stat_t *this, *next;

	if (!stat_head) {
		stat_tail = NULL;
		return;
	}

	for (this = stat_head; this != NULL; this = next) {
		next = this->next;
		free(this);
	}

	stat_head = stat_tail = NULL;
}

/*
 *	Add an entry to the list of stat buffers.
 */
static void dict_stat_add(struct stat const *stat_buf)
{
	dict_stat_t *this;

	this = malloc(sizeof(*this));
	if (!this) return;
	memset(this, 0, sizeof(*this));

	memcpy(&(this->stat_buf), stat_buf, sizeof(this->stat_buf));

	if (!stat_head) {
		stat_head = stat_tail = this;
	} else {
		stat_tail->next = this;
		stat_tail = this;
	}
}

/*
 *	See if any dictionaries have changed.  If not, don't
 *	do anything.
 */
static int dict_stat_check(char const *dir, char const *file)
{
	struct stat stat_buf;
	dict_stat_t *this;
	char buffer[2048];

	/*
	 *	Nothing cached, all files are new.
	 */
	if (!stat_head) return 0;

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
	for (this = stat_head; this != NULL; this = this->next) {
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

/*
 *	Free the dictionary_attributes and dictionary_values lists.
 */
static int _fr_dict_free(UNUSED fr_dict_t *dict)
{
	dict_stat_free();	/* Fixme - should be in the same struct as dict */

	return 0;
}

/*
 *	Add vendor to the list.
 */
int fr_dict_vendor_add(char const *name, unsigned int num)
{
	size_t length;
	fr_dict_vendor_t *dv;

	if (num >= FR_MAX_VENDOR) {
		fr_strerror_printf("fr_dict_vendor_add: Cannot handle vendor ID larger than 2^24");
		return -1;
	}

	if ((length = strlen(name)) >= FR_DICT_VENDOR_MAX_NAME_LEN) {
		fr_strerror_printf("fr_dict_vendor_add: vendor name too long");
		return -1;
	}

	dv = (fr_dict_vendor_t *)talloc_zero_array(fr_main_dict->pool, uint8_t, sizeof(*dv) + length);
	if (dv == NULL) {
		fr_strerror_printf("fr_dict_vendor_add: out of memory");
		return -1;
	}
	talloc_set_type(dv, fr_dict_vendor_t);

	strcpy(dv->name, name);
	dv->vendorpec = num;
	dv->type = dv->length = 1; /* defaults */

	if (!fr_hash_table_insert(fr_main_dict->vendors_by_name, dv)) {
		fr_dict_vendor_t *old_dv;

		old_dv = fr_hash_table_finddata(fr_main_dict->vendors_by_name, dv);
		if (!old_dv) {
			fr_strerror_printf("fr_dict_vendor_add: Failed inserting vendor name %s", name);
			return -1;
		}
		if (old_dv->vendorpec != dv->vendorpec) {
			fr_strerror_printf("fr_dict_vendor_add: Duplicate vendor name %s", name);
			return -1;
		}

		/*
		 *	Already inserted.  Discard the duplicate entry.
		 */
		talloc_free(dv);
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
	if (!fr_hash_table_replace(fr_main_dict->vendors_by_num, dv)) {
		fr_strerror_printf("fr_dict_vendor_add: Failed inserting vendor %s",
				   name);
		return -1;
	}

	return 0;
}

const int fr_dict_attr_allowed_chars[256] = {
/* 0x   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f */
/* 0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 1 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 2 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
/* 3 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
/* 4 */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/* 5 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
/* 6 */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/* 7 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
/* 8 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 9 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* a */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* b */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* c */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* d */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* e */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* f */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 *	[a-zA-Z0-9_-:.]+
 */
int fr_dict_valid_name(char const *name)
{
	uint8_t const *p;

	for (p = (uint8_t const *)name; *p != '\0'; p++) {
		if (!fr_dict_attr_allowed_chars[*p]) {
			char buff[5];

			fr_snprint(buff, sizeof(buff), (char const *)p, 1, '\'');
			fr_strerror_printf("Invalid character '%s' in attribute", buff);

			return -(p - (uint8_t const *)name);
		}
	}

	return 0;
}

static void fr_dict_snprint_flags(char *out, size_t outlen, ATTR_FLAGS flags)
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
	FLAG_SET(is_tlv);
	FLAG_SET(internal);
	FLAG_SET(has_tag);
	FLAG_SET(array);
	FLAG_SET(has_value);
	FLAG_SET(has_value_alias);
	FLAG_SET(has_tlv);
	FLAG_SET(extended);
	FLAG_SET(long_extended);
	FLAG_SET(evs);
	FLAG_SET(wimax);
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
	case PW_TYPE_VSA:
		name = "VSA";
		break;

	case PW_TYPE_EXTENDED:
		name = "EXTENDED";
		break;

	case PW_TYPE_TLV:
		name = "TLV";
		break;

	case PW_TYPE_EVS:
		name = "EVS";
		break;

	case PW_TYPE_VENDOR:
		name = "VENDOR";
		break;

	case PW_TYPE_LONG_EXTENDED:
		name = "LONG EXTENDED";
		break;

	default:
		name = "ATTR";
		break;
	}

	printf("%.*s%s \"%s\" vendor: %x (%i), num: %x (%i), type: %s, flags: %s\n", depth,
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
 * @return
 *	- Common ancestor if one exists.
 *	- NULL if no common ancestor exists.
 */
fr_dict_attr_t const *fr_dict_parent_common(fr_dict_attr_t const *a, fr_dict_attr_t const *b)
{
	unsigned int i;
	fr_dict_attr_t const *p_a, *p_b;

	if (!a || !b) return NULL;

	if (!a->flags.is_tlv || !b->flags.is_tlv) return NULL;	/* If not TLVs then they can't have a parent */
	if (!a->parent || !b->parent) return NULL;		/* Either are at the root */
	if (!a->parent->flags.has_tlv || !b->parent->flags.has_tlv) return NULL;

	/*
	 *	Find a common depth to work back from
	 */
	if (a->depth > b->depth) {
		p_b = b;
		for (p_a = a, i = a->depth - b->depth; p_a && i; p_a = p_a->parent, i++);
	} else if (a->depth < b->depth) {
		p_a = a;
		for (p_b = b, i = b->depth - a->depth; p_b && i; p_b = p_b->parent, i++);
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
		case PW_TYPE_STRUCTURAL:
			child_is_struct = true;
			break;

		default:
			break;
		}

		switch ((*bin)->type) {
		case PW_TYPE_STRUCTURAL:
			bin_is_struct = true;
			break;

		default:
			break;
		}

		if (child_is_struct && !bin_is_struct) break;
		else if (child->vendor < (*bin)->vendor) break;	/* Prioritise RFC attributes */
		else if (child->attr < (*bin)->attr) break;

		bin = &(*bin)->next;
	}

	memcpy(&this, &bin, sizeof(this));
	child->next = *this;
	*this = child;

	return 0;
}

/** Check if a child attribute exists in a parent
 *
 * @param parent to check for child in.
 * @param attr number to look for.
 * @return
 *	- The child attribute on success.
 *	- NULL if the child attribute does not exist.
 */
static inline fr_dict_attr_t const *fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *bin;

	if (!parent->children) return NULL;

	/*
	 *	Only some types can have children
	 */
	switch (parent->type) {
	default:
		return NULL;

	case PW_TYPE_VENDOR:
	case PW_TYPE_VSA:
	case PW_TYPE_TLV:
	case PW_TYPE_EVS:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
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

static fr_dict_attr_t *fr_dict_attr_alloc(TALLOC_CTX *ctx,
				   	  char const *name, unsigned int vendor, int attr,
				   	  PW_TYPE type, ATTR_FLAGS flags)
{
	fr_dict_attr_t *da;
	size_t namelen = strlen(name);

	da = (fr_dict_attr_t *)talloc_zero_array(ctx, uint8_t, sizeof(*da) + namelen);
	if (!da) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	talloc_set_type(da, fr_dict_attr_t);

	memcpy(da->name, name, namelen);
	da->name[namelen] = '\0';
	da->attr = attr;
	da->vendor = vendor;
	da->type = type;
	da->flags = flags;

	return da;
}

/** Add an attribute to the dictionary
 *
 * @todo we need to check length of none vendor attributes.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_add(fr_dict_attr_t const *parent, char const *name, unsigned int vendor, int attr,
		     PW_TYPE type, ATTR_FLAGS flags)
{
	size_t namelen;
	fr_dict_attr_t *n;
	static int max_attr = 0;

	if (!fr_assert(parent)) return -1;

	namelen = strlen(name);
	if (namelen >= FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");
	error:
		fr_strerror_printf("fr_dict_attr_add: Failed adding \"%s\": %s", name, fr_strerror());
		return -1;
	}

	if (fr_dict_valid_name(name) < 0) return -1;

	if (flags.has_tag &&
	    !((type == PW_TYPE_INTEGER) || (type == PW_TYPE_STRING))) {
		fr_strerror_printf("Only 'integer' and 'string' attributes can have tags");
		goto error;
	}

	/*
	 *	Disallow attributes of type zero.
	 */
	if (!attr && !vendor) {
		fr_strerror_printf("Attribute 0 is invalid and cannot be used");
		goto error;
	}

	/*
	 *	If the attr is '-1', that means use a pre-existing
	 *	one (if it already exists).  If one does NOT already exist,
	 *	then create a new attribute, with a non-conflicting value,
	 *	and use that.
	 */
	if (attr == -1) {
		if (fr_dict_attr_by_name(name)) return 0; /* exists, don't add it again */

		attr = ++max_attr;
	} else if (vendor == 0) {
		/*
		 *  Update 'max_attr'
		 */
		if (attr > max_attr) max_attr = attr;
	}

	/*
	 *	We're still in the same space and the parent isn't a TLV.  That's an error.
	 *
	 *	Otherwise, fr_dict_parent_by_num() has taken us from an Extended sub-attribute to
	 *	a *the* Extended attribute, whish isn't what we want here.
	 */
	if (!flags.internal && (vendor == parent->vendor) && (parent->type != PW_TYPE_TLV)) {
		fr_strerror_printf("Has parent attribute %s which is not of type 'tlv'", parent->name);
		goto error;
	}

	/*
	 *	Special case for VSAs - We need to pre-create the hierachy
	 */
	if ((vendor & (FR_MAX_VENDOR - 1)) && parent->flags.is_root) {
		ATTR_FLAGS new_flags;

		fr_dict_attr_t const *vsa_attr, *vendor_attr;
		fr_dict_attr_t *new;
		fr_dict_attr_t *mutable;

		memset(&new_flags, 0, sizeof(new_flags));

		vsa_attr = fr_dict_attr_child_by_num(parent, PW_VENDOR_SPECIFIC);
		if (!vsa_attr) {
			memcpy(&mutable, &parent, sizeof(mutable));
			new = fr_dict_attr_alloc(mutable, "Vendor-Specific", 0,
						 PW_VENDOR_SPECIFIC, PW_TYPE_VSA, new_flags);
			fr_dict_attr_child_add(mutable, new);
			vsa_attr = new;
		}

		vendor_attr = fr_dict_attr_child_by_num(vsa_attr, (vendor & (FR_MAX_VENDOR - 1)));
		if (!vendor_attr) {
			memcpy(&mutable, &vsa_attr, sizeof(mutable));
			new = fr_dict_attr_alloc(mutable, "vendor", 0,
						 (vendor & (FR_MAX_VENDOR - 1)), PW_TYPE_VENDOR, new_flags);
			fr_dict_attr_child_add(mutable, new);
			vendor_attr = new;
		}
		parent = vendor_attr;
	}

	/*
	 *	Manually extended flags for extended attributes.  We
	 *	can't expect the caller to know all of the details of the flags.
	 */
	if (vendor >= FR_MAX_VENDOR) {
		fr_dict_attr_t const *da;

		/*
		 *	Trying to manually create an extended
		 *	attribute, but the parent extended attribute
		 *	doesn't exist?  That's an error.
		 */
		da = fr_dict_attr_by_num(0, vendor / FR_MAX_VENDOR);
		if (!da) {
			fr_strerror_printf("Extended attributes must be defined from the extended space");
			goto error;
		}

		/*
		 *	There's still a real vendor.  Since it's an
		 *	extended attribute, set the EVS flag.
		 */
		if ((vendor & (FR_MAX_VENDOR - 1)) != 0) flags.evs = 1;
	}

	/*
	 *	Additional checks for extended attributes.
	 */
	if (flags.extended || flags.long_extended || flags.evs) {
		if (vendor && (vendor < FR_MAX_VENDOR)) {
			fr_strerror_printf("VSAs cannot use the \"extended\" or \"evs\" attribute formats");
			goto error;
		}
		if (flags.has_tag
#ifdef WITH_DHCP
		    || flags.array
#endif
		    || (flags.encrypt != FLAG_ENCRYPT_NONE)) {
			fr_strerror_printf("The \"extended\" attributes MUST NOT have any flags set");
			goto error;
		}
	}

	if (flags.evs) {
		if (!(flags.extended || flags.long_extended)) {
			fr_strerror_printf("Attributes of type \"evs\" MUST have a parent of type \"extended\"");
			goto error;
		}
	}

	/*
	 *	Do various sanity checks.
	 */
	if (attr < 0) {
		fr_strerror_printf("ATTRIBUTE number %i is invalid, must be greater than or equal to zero", attr);
		goto error;
	}

	if (flags.has_tlv && flags.length) {
		fr_strerror_printf("TLVs cannot have a fixed length");
		goto error;
	}

	if (vendor && flags.concat) {
		fr_strerror_printf("VSAs cannot have the \"concat\" flag set");
		goto error;
	}

	if (flags.concat && (type != PW_TYPE_OCTETS)) {
		fr_strerror_printf("The \"concat\" flag can only be set for attributes of type \"octets\"");
		goto error;
	}

	if (flags.concat && (flags.has_tag || flags.array || flags.is_tlv || flags.has_tlv ||
			     flags.length || flags.evs || flags.extended || flags.long_extended ||
			     (flags.encrypt != FLAG_ENCRYPT_NONE))) {
		fr_strerror_printf("The \"concat\" flag cannot be used with any other flag");
		goto error;
	}

	if (flags.length && (type != PW_TYPE_OCTETS)) {
		fr_strerror_printf("The \"length\" flag can only be set for attributes of type \"octets\"");
		goto error;
	}

	if (flags.length && (flags.has_tag || flags.array || flags.is_tlv || flags.has_tlv ||
			     flags.concat || flags.evs || flags.extended || flags.long_extended ||
			     (flags.encrypt > FLAG_ENCRYPT_USER_PASSWORD))) {
		fr_strerror_printf("The \"length\" flag cannot be used with any other flag");
		goto error;
	}

	/*
	 *	Force "length" for data types of fixed length;
	 */
	switch (type) {
	case PW_TYPE_BYTE:
		flags.length = 1;
		break;

	case PW_TYPE_SHORT:
		flags.length = 2;
		break;

	case PW_TYPE_DATE:
	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_INTEGER:
	case PW_TYPE_SIGNED:
		flags.length = 4;
		break;

	case PW_TYPE_INTEGER64:
		flags.length = 8;
		break;

	case PW_TYPE_ETHERNET:
		flags.length = 6;
		break;

	case PW_TYPE_IFID:
		flags.length = 8;
		break;

	case PW_TYPE_IPV6_ADDR:
		flags.length = 16;
		break;

	case PW_TYPE_EXTENDED:
		if ((vendor != 0) || (attr < 241)) {
			fr_strerror_printf("Attributes of type \"extended\" MUST be "
					   "RFC attributes with value >= 241.");
			goto error;
		}

		flags.length = 0;
		flags.extended = 1;
		break;

	case PW_TYPE_LONG_EXTENDED:
		if ((vendor != 0) || (attr < 241)) {
			fr_strerror_printf("Attributes of type \"long-extended\" MUST "
					   "be RFC attributes with value >= 241.");
			goto error;
		}

		flags.length = 0;
		flags.extended = 1;
		flags.long_extended = 1;
		break;

	case PW_TYPE_EVS:
		if (attr != PW_VENDOR_SPECIFIC) {
			fr_strerror_printf("Attributes of type \"evs\" MUST have attribute code 26.");
			goto error;
		}

		flags.length = 0;
		flags.extended = 1;
		flags.evs = 1;
		break;

	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
		flags.is_pointer = true;
		break;

	default:
		break;
	}

	/*
	 *	Stupid hacks for MS-CHAP-MPPE-Keys.  The User-Password
	 *	encryption method has no provisions for encoding the
	 *	length of the data.  For User-Password, the data is
	 *	(presumably) all printable non-zero data.  For
	 *	MS-CHAP-MPPE-Keys, the data is binary crap.  So... we
	 *	MUST specify a length in the dictionary.
	 */
	if ((flags.encrypt == FLAG_ENCRYPT_USER_PASSWORD) && (type != PW_TYPE_STRING)) {
		if (type != PW_TYPE_OCTETS) {
			fr_strerror_printf("The \"encrypt=1\" flag cannot be used with non-string data types");
			goto error;
		}

		if (flags.length == 0) {
			fr_strerror_printf("The \"encrypt=1\" flag MUST be used with an explicit length for "
					   "'octets' data types");
			goto error;
		}
	}

	if ((vendor & (FR_MAX_VENDOR - 1)) != 0) {
		fr_dict_vendor_t *dv;
		static fr_dict_vendor_t *last_vendor = NULL;
		unsigned int vendor_max;

		if (flags.has_tlv && (flags.encrypt != FLAG_ENCRYPT_NONE)) {
			fr_strerror_printf("TLV's cannot be encrypted");
			goto error;
		}

		if (flags.is_tlv && flags.has_tag) {
			fr_strerror_printf("Sub-TLV's cannot have a tag");
			goto error;
		}

		if (flags.has_tlv && flags.has_tag) {
			fr_strerror_printf("TLV's cannot have a tag");
			goto error;
		}

		/*
		 *	Most ATTRIBUTEs are bunched together by
		 *	VENDOR.  We can save a lot of lookups on
		 *	dictionary initialization by caching the last
		 *	vendor.
		 */
		if (last_vendor &&
		    ((vendor & (FR_MAX_VENDOR - 1)) == last_vendor->vendorpec)) {
			dv = last_vendor;
		} else {
			/*
			 *	Ignore the high byte (sigh)
			 */
			dv = fr_dict_vendor_by_num(vendor & (FR_MAX_VENDOR - 1));
			last_vendor = dv;
		}

		/*
		 *	If the vendor isn't defined, die.
		 */
		if (!dv) {
			fr_strerror_printf("Unknown vendor %u", vendor & (FR_MAX_VENDOR - 1));
			goto error;
		}

		if (!attr && dv->type != 1) {
			fr_strerror_printf("Cannot have value zero");
			goto error;
		}

		/*
		 *	Maximum allow attribute based on
		 *	the length of the vendor's type
		 *	field.
		 */
		vendor_max = ((uint64_t)1 << (dv->type << 3)) - 1;
		if (((unsigned int)attr > vendor_max) && !flags.is_tlv && !flags.internal) {
			fr_strerror_printf("ATTRIBUTE has invalid number %i (larger than vendor max %u)",
					   attr, vendor_max);
			goto error;
		} /* else 256..65535 are allowed */

		/*
		 *	<sigh> Alvarion, being *again* a horribly
		 *	broken vendor, has re-used the WiMAX format in
		 *	their proprietary vendor space.  This re-use
		 *	means that there are *multiple* conflicting
		 *	Alvarion dictionaries.
		 */
		flags.wimax = dv->flags;
	} /* it's a VSA of some kind */

	n = fr_dict_attr_alloc(fr_main_dict->pool, name, vendor, attr, type, flags);
	if (!n) {
	oom:
		fr_strerror_printf("Out of memory");
		goto error;
	}

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(fr_main_dict->attributes_by_name, n)) {
		fr_dict_attr_t *a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = fr_hash_table_finddata(fr_main_dict->attributes_by_name, n);
		if (a && (strcasecmp(a->name, n->name) == 0)) {
			if (a->attr != n->attr) {
				fr_strerror_printf("Duplicate attribute name");
				talloc_free(n);
				goto error;
			}

			/*
			 *	Same name, same vendor, same attr,
			 *	maybe the flags and/or type is
			 *	different.  Let the new value
			 *	over-ride the old one.
			 */
		}

		fr_hash_table_delete(fr_main_dict->attributes_by_num, a);

		if (!fr_hash_table_replace(fr_main_dict->attributes_by_name, n)) {
			fr_strerror_printf("Internal error storing attribute");
			talloc_free(n);
			goto error;
		}
	}

	/*
	 *	Insert the SAME pointer (not free'd when this entry is
	 *	deleted), into another table.
	 *
	 *	We want this behaviour because we want OLD names for
	 *	the attributes to be read from the configuration
	 *	files, but when we're printing them, (and looking up
	 *	by value) we want to use the NEW name.
	 */
	if (!fr_hash_table_replace(fr_main_dict->attributes_by_num, n)) {
		fr_strerror_printf("Failed inserting attribute");
		goto error;
	}

	/*
	 *	Hacks for combo-IP
	 */
	if (n->type == PW_TYPE_COMBO_IP_ADDR) {
		fr_dict_attr_t *v4, *v6;

		v4 = (fr_dict_attr_t *)talloc_zero_array(fr_main_dict->pool, uint8_t, sizeof(*v4) + namelen);
		if (!v4) goto oom;
		talloc_set_type(v4, fr_dict_attr_t);

		v6 = (fr_dict_attr_t *)talloc_zero_array(fr_main_dict->pool, uint8_t, sizeof(*v6) + namelen);
		if (!v6) goto oom;
		talloc_set_type(v6, fr_dict_attr_t);

		memcpy(v4, n, sizeof(*v4) + namelen);
		v4->type = PW_TYPE_IPV4_ADDR;

		memcpy(v6, n, sizeof(*v6) + namelen);
		v6->type = PW_TYPE_IPV6_ADDR;
		if (!fr_hash_table_replace(fr_main_dict->attributes_combo, v4)) {
			fr_strerror_printf("Failed inserting IPv4 version of combo attribute");
			goto error;
		}

		if (!fr_hash_table_replace(fr_main_dict->attributes_combo, v6)) {
			fr_strerror_printf("Failed inserting IPv6 version of combo attribute");
			goto error;
		}
	}

	if (!vendor && (attr > 0) && (attr < 256)) fr_main_dict->base_attrs[attr] = n;

	/*
	 *	Setup parenting for the attribute
	 */
	if (parent) {
		fr_dict_attr_t *mutable;

		memcpy(&mutable, &parent, sizeof(mutable));

		if (fr_dict_attr_child_add(mutable, n) < 0) return -1;
	}

	return 0;
}

/*
 *	Add a value for an attribute to the dictionary.
 */
int fr_dict_value_add(char const *attr, char const *alias, int value)
{
	size_t		length;
	fr_dict_attr_t const	*da;
	fr_dict_value_t	*dval;

	static fr_dict_attr_t const *last_attr = NULL;

	if (!*alias) {
		fr_strerror_printf("fr_dict_value_add: empty names are not permitted");
		return -1;
	}

	if ((length = strlen(alias)) >= FR_DICT_VALUE_MAX_NAME_LEN) {
		fr_strerror_printf("fr_dict_value_add: value name too long");
		return -1;
	}

	dval = (fr_dict_value_t *)talloc_zero_array(fr_main_dict->pool, uint8_t, sizeof(*dval) + length);
	if (dval == NULL) {
		fr_strerror_printf("fr_dict_value_add: out of memory");
		return -1;
	}
	talloc_set_type(dval, fr_dict_value_t);

	strcpy(dval->name, alias);
	dval->value = value;

	/*
	 *	Most VALUEs are bunched together by ATTRIBUTE.  We can
	 *	save a lot of lookups on dictionary initialization by
	 *	caching the last attribute.
	 */
	if (last_attr && (strcasecmp(attr, last_attr->name) == 0)) {
		da = last_attr;
	} else {
		da = fr_dict_attr_by_name(attr);
		last_attr = da;
	}

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	if (da) {
		if (da->flags.has_value_alias) {
			fr_strerror_printf(
				"fr_dict_value_add: Cannot add VALUE for ATTRIBUTE \"%s\": It already has a VALUE-ALIAS",
				attr);
			return -1;
		}

		dval->attr = da->attr;
		dval->vendor = da->vendor;

		/*
		 *	Enforce valid values
		 *
		 *	Don't worry about fixups...
		 */
		switch (da->type) {
		case PW_TYPE_BYTE:
			if (value > 255) {
				talloc_free(dval);
				fr_strerror_printf(
					"fr_dict_value_add: ATTRIBUTEs of type 'byte' cannot have VALUEs larger than 255");
				return -1;
			}
			break;
		case PW_TYPE_SHORT:
			if (value > 65535) {
				talloc_free(dval);
				fr_strerror_printf(
					"fr_dict_value_add: ATTRIBUTEs of type 'short' cannot have VALUEs larger than 65535");
				return -1;
			}
			break;

			/*
			 *	Allow octets for now, because
			 *	of dictionary.cablelabs
			 */
		case PW_TYPE_OCTETS:

		case PW_TYPE_INTEGER:
			break;

		case PW_TYPE_INTEGER64:
		default:
			talloc_free(dval);
			fr_strerror_printf("fr_dict_value_add: VALUEs cannot be defined for attributes of type '%s'",
					   fr_int2str(dict_attr_types, da->type, "?Unknown?"));
			return -1;
		}
	} else {
		value_fixup_t *fixup;

		fixup = (value_fixup_t *)malloc(sizeof(*fixup));
		if (!fixup) {
			talloc_free(dval);
			fr_strerror_printf("fr_dict_value_add: out of memory");
			return -1;
		}
		memset(fixup, 0, sizeof(*fixup));

		strlcpy(fixup->attrstr, attr, sizeof(fixup->attrstr));
		fixup->dval = dval;

		/*
		 *	Insert to the head of the list.
		 */
		fixup->next = value_fixup;
		value_fixup = fixup;

		return 0;
	}

	/*
	 *	Add the value into the dictionary.
	 */
	{
		fr_dict_attr_t *tmp;
		memcpy(&tmp, &dval, sizeof(tmp));

		if (!fr_hash_table_insert(fr_main_dict->values_by_name, tmp)) {
			if (da) {
				fr_dict_value_t *old;

				/*
				 *	Suppress duplicates with the same
				 *	name and value.  There are lots in
				 *	dictionary.ascend.
				 */
				old = fr_dict_value_by_name(da->vendor, da->attr, alias);
				if (old && (old->value == dval->value)) {
					talloc_free(dval);
					return 0;
				}
			}

			talloc_free(dval);
			fr_strerror_printf("fr_dict_value_add: Duplicate value name %s for attribute %s", alias,
					   attr);
			return -1;
		}
	}

	/*
	 *	There are multiple VALUE's, keyed by attribute, so we
	 *	take care of that here.
	 */
	if (!fr_hash_table_replace(fr_main_dict->values_by_num, dval)) {
		fr_strerror_printf("fr_dict_value_add: Failed inserting value %s",
				   alias);
		return -1;
	}

	return 0;
}

static int sscanf_i(char const *str, unsigned int *pvalue)
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
 *	Get the OID based on various pieces of information.
 *
 *	Remember, the packing format is weird.
 *
 *	00VID	000000AA	normal VSA for vendor VID
 *	00VID	AABBCCDD	normal VSAs with TLVs
 *	EE000   000000AA	extended attr (241.1)
 *	EE000	AABBCCDD	extended attr with TLVs
 *	EEVID	000000AA	EVS with vendor VID, attr AAA
 *	EEVID	AABBCCDD	EVS with TLVs
 *
 *	<whew>!  Are we crazy, or what?
 */
int fr_dict_str_to_oid(unsigned int *p_vendor, unsigned int *p_attr, char const *oid, int tlv_depth)
{
	char const *p;
	unsigned int attr;
	fr_dict_attr_t const *da = NULL;

	if (tlv_depth > fr_attr_max_tlv) {
		fr_strerror_printf("Too many sub-attributes");
		return -1;
	}

	/*
	 *	If *p_attr is set, check if the attribute exists.
	 *	Otherwise, check that the vendor exists.
	 */
	if (*p_attr) {
		da = fr_dict_attr_by_num(*p_vendor, *p_attr);
		if (!da) {
			fr_strerror_printf("Parent attribute is undefined");
			return -1;
		}

		if (!da->flags.has_tlv && !da->flags.extended) {
			fr_strerror_printf("Parent attribute %s cannot have sub-attributes",
					   da->name);
			return -1;
		}

	} else if ((*p_vendor & (FR_MAX_VENDOR - 1)) != 0) {
		if (!fr_dict_vendor_by_num(*p_vendor & (FR_MAX_VENDOR - 1))) {
			fr_strerror_printf("Unknown vendor %u",
					   *p_vendor & (FR_MAX_VENDOR - 1));
			return -1;
		}
	}

	p = strchr(oid, '.');

	/*
	 *	Look for 26.VID.x.y
	 *
	 *	If we find it, re-write the parameters, and recurse.
	 */
	if (!*p_vendor && (tlv_depth == 0) && (*p_attr == PW_VENDOR_SPECIFIC)) {
		fr_dict_vendor_t const *dv;

		if (!p) {
			fr_strerror_printf("VSA needs to have sub-attribute");
			return -1;
		}

		if (!sscanf_i(oid, p_vendor)) {
			fr_strerror_printf("Invalid number in attribute");
			return -1;
		}

		if (*p_vendor >= FR_MAX_VENDOR) {
			fr_strerror_printf("Cannot handle vendor ID larger than 2^24");

			return -1;
		}

		dv = fr_dict_vendor_by_num(*p_vendor & (FR_MAX_VENDOR - 1));
		if (!dv) {
			fr_strerror_printf("Unknown vendor \"%u\" ",
					   *p_vendor & (FR_MAX_VENDOR - 1));
			return -1;
		}

		/*
		 *	Start off with (attr=0, vendor=VID), and
		 *	recurse.  This causes the various checks above
		 *	to be done.
		 */
		*p_attr = 0;
		return fr_dict_str_to_oid(p_vendor, p_attr, p + 1, 0);
	}

	if (!sscanf_i(oid, &attr)) {
		fr_strerror_printf("Invalid number in attribute");
		return -1;
	}

	if (!*p_vendor && (tlv_depth == 1) && da &&
	    (da->flags.has_tlv || da->flags.extended)) {

		*p_vendor = *p_attr * FR_MAX_VENDOR;
		*p_attr = attr;

		if (!p) return 0;
		return fr_dict_str_to_oid(p_vendor, p_attr, p + 1, 1);
	}

	/*
	 *	And pack the data according to the scheme described in
	 *	the comments at the start of this function.
	 */
	if (*p_attr) {
		*p_attr |= (attr & fr_attr_mask[tlv_depth]) << fr_attr_shift[tlv_depth];
	} else {
		*p_attr = attr;
	}

	if (p) {
		return fr_dict_str_to_oid(p_vendor, p_attr, p + 1, tlv_depth + 1);
	}

	return tlv_depth;
}

/*
 *	Process the ATTRIBUTE command
 */
static int process_attribute(fr_dict_t *dict, char const *fn, int const line,
			     unsigned int block_vendor,
			     fr_dict_attr_t const *block_tlv, int tlv_depth,
			     char **argv, int argc)
{
	int			oid = 0;

	unsigned int		vendor = 0;
	unsigned int		attr;

	int			type;
	unsigned int		length;
	ATTR_FLAGS		flags;
	char			*p;
	fr_dict_attr_t const	*parent;

	if ((argc < 3) || (argc > 4)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid ATTRIBUTE line", fn, line);
		return -1;
	}

	/*
	 *	Parent is either the root of the dictionary or the TLV
	 *	described by the TLV block.
	 */
	parent = block_tlv ? block_tlv : dict->root;

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[1], "Attr-", 5) == 0) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Invalid attribute name", fn, line);
		return -1;
	}

	memset(&flags, 0, sizeof(flags));

	/*
	 *	Look for OIDs before doing anything else.
	 */
	p = strchr(argv[1], '.');
	if (p) oid = 1;

	/*
	 *	Validate all entries
	 */
	if (!sscanf_i(argv[1], &attr)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid attr", fn, line);
		return -1;
	}

	if (oid) {
		fr_dict_attr_t const *da;

		vendor = block_vendor;

		/*
		 *	Parse the rest of the OID.
		 */
		if (fr_dict_str_to_oid(&vendor, &attr, p + 1, tlv_depth + 1) < 0) {
			char buffer[256];

			strlcpy(buffer, fr_strerror(), sizeof(buffer));

			fr_strerror_printf("fr_dict_init: %s[%d]: Invalid attribute identifier: %s", fn, line, buffer);
			return -1;
		}
		block_vendor = vendor;

		/*
		 *	Set the flags based on the parents flags.
		 */
		da = fr_dict_parent_by_num(vendor, attr);
		if (!da) {
			fr_strerror_printf("fr_dict_init: %s[%d]: Parent attribute is undefined.", fn, line);
			return -1;
		}

		flags.extended = da->flags.extended;
		flags.long_extended = da->flags.long_extended;
		flags.evs = da->flags.evs;
		if (da->flags.has_tlv) flags.is_tlv = 1;
	}

	if (strncmp(argv[2], "octets[", 7) != 0) {
		/*
		 *	find the type of the attribute.
		 */
		type = fr_str2int(dict_attr_types, argv[2], -1);
		if (type < 0) {
			fr_strerror_printf("fr_dict_init: %s[%d]: invalid type \"%s\"",
					   fn, line, argv[2]);
			return -1;
		}

	} else {
		type = PW_TYPE_OCTETS;

		p = strchr(argv[2] + 7, ']');
		if (!p) {
			fr_strerror_printf("fr_dict_init: %s[%d]: Invalid format for octets", fn, line);
			return -1;
		}

		*p = 0;

		if (!sscanf_i(argv[1], &length)) {
			fr_strerror_printf("fr_dict_init: %s[%d]: invalid length", fn, line);
			return -1;
		}

		if ((length == 0) || (length > 253)) {
			fr_strerror_printf("fr_dict_init: %s[%d]: invalid length", fn, line);
			return -1;
		}

		flags.length = length;
	}

	/*
	 *	Parse options.
	 */
	if (argc >= 4) {
		char *key, *next, *last;

		/*
		 *	Keep it real.
		 */
		if (flags.extended) {
			fr_strerror_printf("fr_dict_init: %s[%d]: Extended attributes cannot use flags", fn, line);
			return -1;
		}

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
			 *	Encryption method, defaults to 0 (none).
			 *	Currently valid is just type 2,
			 *	Tunnel-Password style, which can only
			 *	be applied to strings.
			 */
			} else if (strncmp(key, "encrypt=", 8) == 0) {
				flags.encrypt = strtol(key + 8, &last, 0);
				if (*last) {
					fr_strerror_printf("fr_dict_init: %s[%d] invalid option %s",
							   fn, line, key);
					return -1;
				}

				if ((flags.encrypt == FLAG_ENCRYPT_ASCEND_SECRET) &&
				    (type != PW_TYPE_STRING)) {
					fr_strerror_printf("fr_dict_init: %s[%d] Only \"string\" types can have the "
								   "\"encrypt=3\" flag set", fn, line);
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

				switch (type) {
				case PW_TYPE_IPV4_ADDR:
				case PW_TYPE_IPV6_ADDR:
				case PW_TYPE_BYTE:
				case PW_TYPE_SHORT:
				case PW_TYPE_INTEGER:
				case PW_TYPE_DATE:
				case PW_TYPE_STRING:
					break;

				default:
					fr_strerror_printf("fr_dict_init: %s[%d] \"%s\" type cannot have the "
								   "\"array\" flag set",
							   fn, line,
							   fr_int2str(dict_attr_types, type, "<UNKNOWN>"));
					return -1;
				}

			} else if (strncmp(key, "concat", 7) == 0) {
				flags.concat = 1;

				if (type != PW_TYPE_OCTETS) {
					fr_strerror_printf("fr_dict_init: %s[%d] Only \"octets\" type can have the "
								   "\"concat\" flag set", fn, line);
					return -1;
				}

			} else if (strncmp(key, "virtual", 8) == 0) {
				flags.virtual = 1;

				if (vendor != 0) {
					fr_strerror_printf("fr_dict_init: %s[%d] VSAs cannot have the \"virtual\" "
								   "flag set", fn, line);
					return -1;
				}

				if (attr < 256) {
					fr_strerror_printf("fr_dict_init: %s[%d] Standard attributes cannot "
								   "have the \"virtual\" flag set", fn, line);
					return -1;
				}

			/*
			 *	The only thing is the vendor name,
			 *	and it's a known name: allow it.
			 */
			} else if ((key == argv[3]) && !next) {
				if (oid) {
					fr_strerror_printf("fr_dict_init: %s[%d] New-style attributes cannot use "
								   "a vendor flag", fn, line);
					return -1;
				}

				if (block_vendor) {
					fr_strerror_printf("fr_dict_init: %s[%d] Vendor flag inside of \"BEGIN-VENDOR\" "
								   "is not allowed", fn, line);
					return -1;
				}

				vendor = fr_dict_vendor_by_name(key);
				if (!vendor) goto unknown;
				break;

			} else {
			unknown:
				fr_strerror_printf("fr_dict_init: %s[%d]: unknown option \"%s\"", fn, line, key);
				return -1;
			}

			key = next;
			if (key && !*key) break;
		} while (key);
	}

	if (block_vendor) vendor = block_vendor;

	/*
	 *	Special checks for tags, they make our life much more
	 *	difficult.
	 */
	if (flags.has_tag) {
		/*
		 *	Only string, octets, and integer can be tagged.
		 */
		switch (type) {
		case PW_TYPE_STRING:
		case PW_TYPE_INTEGER:
			break;

		default:
			fr_strerror_printf("fr_dict_init: %s[%d]: Attributes of type %s cannot be tagged.",
					   fn, line,
					   fr_int2str(dict_attr_types, type, "?Unknown?"));
			return -1;
		}
	}

	if (type == PW_TYPE_TLV) {
		if (vendor && (vendor < FR_MAX_VENDOR)
#ifdef WITH_DHCP
		    && (vendor != DHCP_MAGIC_VENDOR)
#endif
			) {
			fr_dict_vendor_t *dv;

			dv = fr_dict_vendor_by_num(vendor);
			if (!dv || (dv->type != 1) || (dv->length != 1)) {
				fr_strerror_printf("fr_dict_init: %s[%d]: Type \"tlv\" can only be for \"format=1,1\".",
						   fn, line);
				return -1;
			}

		}
		flags.has_tlv = 1;
	}

	if (block_tlv) {
		/*
		 *	TLV's can be only one octet.
		 */
		if ((attr == 0) || ((attr & ~fr_attr_mask[tlv_depth]) != 0)) {
			fr_strerror_printf("fr_dict_init: %s[%d]: sub-tlv has invalid attribute number",
					   fn, line);
			return -1;
		}

		/*
		 *	Shift the attr left.
		 */
		attr <<= fr_attr_shift[tlv_depth];
		attr |= block_tlv->attr;
		flags.is_tlv = 1;
	}

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
	if (fr_dict_attr_add(parent, argv[0], vendor, attr, type, flags) < 0) {
		fr_strerror_printf("fr_dict_init: %s[%d]: %s", fn, line, fr_strerror());
		return -1;
	}

	return 0;
}

/*
 *	Process the VALUE command
 */
static int process_value(char const *fn, int const line, char **argv, int argc)
{
	unsigned int value;

	if (argc != 3) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid VALUE line",
				   fn, line);
		return -1;
	}
	/*
	 *	For Compatibility, skip "Server-Config"
	 */
	if (strcasecmp(argv[0], "Server-Config") == 0)
		return 0;

	/*
	 *	Validate all entries
	 */
	if (!sscanf_i(argv[2], &value)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid value",
				   fn, line);
		return -1;
	}

	if (fr_dict_value_add(argv[0], argv[1], value) < 0) {
		char buffer[256];

		strlcpy(buffer, fr_strerror(), sizeof(buffer));

		fr_strerror_printf("fr_dict_init: %s[%d]: %s",
				   fn, line, buffer);
		return -1;
	}

	return 0;
}

/*
 *	Process the VALUE-ALIAS command
 *
 *	This allows VALUE mappings to be shared among multiple
 *	attributes.
 */
static int process_value_alias(char const *fn, int const line, char **argv, int argc)
{
	fr_dict_attr_t const *my_da, *da;
	fr_dict_value_t *dval;

	if (argc != 2) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid VALUE-ALIAS line",
				   fn, line);
		return -1;
	}

	my_da = fr_dict_attr_by_name(argv[0]);
	if (!my_da) {
		fr_strerror_printf("fr_dict_init: %s[%d]: ATTRIBUTE \"%s\" does not exist",
				   fn, line, argv[1]);
		return -1;
	}

	if (my_da->flags.has_value_alias) {
		fr_strerror_printf(
			"fr_dict_init: %s[%d]: Cannot add VALUE-ALIAS to ATTRIBUTE \"%s\" with pre-existing VALUE-ALIAS",
			fn, line, argv[0]);
		return -1;
	}

	da = fr_dict_attr_by_name(argv[1]);
	if (!da) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Cannot find ATTRIBUTE \"%s\" for alias",
				   fn, line, argv[1]);
		return -1;
	}

	if (da->flags.has_value_alias) {
		fr_strerror_printf(
			"fr_dict_init: %s[%d]: Cannot add VALUE-ALIAS to ATTRIBUTE \"%s\" which itself has a VALUE-ALIAS",
			fn, line, argv[1]);
		return -1;
	}

	if (my_da->type != da->type) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Cannot add VALUE-ALIAS between attributes of differing type",
				   fn, line);
		return -1;
	}

	dval = talloc_zero(fr_main_dict->pool, fr_dict_value_t);
	if (dval == NULL) {
		fr_strerror_printf("fr_dict_value_add: out of memory");
		return -1;
	}

	dval->name[0] = '\0';        /* empty name */
	dval->attr = my_da->attr;
	dval->vendor = my_da->vendor;
	dval->value = da->attr;

	if (!fr_hash_table_insert(fr_main_dict->values_by_name, dval)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Error create alias", fn, line);
		talloc_free(dval);
		return -1;
	}

	return 0;
}

static int parse_format(char const *fn, int line, char const *format, int *pvalue, int *ptype, int *plength,
			bool *pcontinuation)
{
	char const *p;
	int type, length;
	bool continuation = false;

	if (strncasecmp(format, "format=", 7) != 0) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Invalid format for VENDOR.  Expected \"format=\", got \"%s\"",
				   fn, line, format);
		return -1;
	}

	p = format + 7;
	if ((strlen(p) < 3) ||
	    !isdigit((int)p[0]) ||
	    (p[1] != ',') ||
	    !isdigit((int)p[2]) ||
	    (p[3] && (p[3] != ','))) {
		fr_strerror_printf(
			"fr_dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
			fn, line, p);
		return -1;
	}

	type = (int)(p[0] - '0');
	length = (int)(p[2] - '0');

	if ((type != 1) && (type != 2) && (type != 4)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid type value %d for VENDOR",
				   fn, line, type);
		return -1;
	}

	if ((length != 0) && (length != 1) && (length != 2)) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid length value %d for VENDOR",
				   fn, line, length);
		return -1;
	}

	if (p[3] == ',') {
		if (!p[4]) {
			fr_strerror_printf(
				"fr_dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
				fn, line, p);
			return -1;
		}

		if ((p[4] != 'c') ||
		    (p[5] != '\0')) {
			fr_strerror_printf(
				"fr_dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
				fn, line, p);
			return -1;
		}
		continuation = true;

		if ((*pvalue != VENDORPEC_WIMAX) ||
		    (type != 1) || (length != 1)) {
			fr_strerror_printf("fr_dict_init: %s[%d]: Only WiMAX VSAs can have continuations",
					   fn, line);
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
static int process_vendor(char const *fn, int const line, char **argv, int argc)
{
	int value;
	int type, length;
	bool continuation = false;
	fr_dict_vendor_t *dv;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_printf("fr_dict_init: %s[%d] invalid VENDOR entry",
				   fn, line);
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!isdigit((int)argv[1][0])) {
		fr_strerror_printf("fr_dict_init: %s[%d]: invalid value",
				   fn, line);
		return -1;
	}
	value = atoi(argv[1]);

	/* Create a new VENDOR entry for the list */
	if (fr_dict_vendor_add(argv[0], value) < 0) {
		fr_strerror_printf("fr_dict_init: %s[%d]: %s",
				   fn, line, fr_strerror());
		return -1;
	}

	/*
	 *	Look for a format statement.  Allow it to over-ride the hard-coded formats below.
	 */
	if (argc == 3) {
		if (parse_format(fn, line, argv[2], &value, &type, &length, &continuation) < 0) {
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

	dv = fr_dict_vendor_by_num(value);
	if (!dv) {
		fr_strerror_printf("fr_dict_init: %s[%d]: Failed adding format for VENDOR",
				   fn, line);
		return -1;
	}

	dv->type = type;
	dv->length = length;
	dv->flags = continuation;

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

static int my_dict_init(fr_dict_t *dict, char const *parent, char const *filename,
			char const *src_file, int src_line);

int fr_dict_read(fr_dict_t *dict, char const *dir, char const *filename)
{
	if (!fr_main_dict->attributes_by_name) {
		fr_strerror_printf("Must call fr_dict_init() before fr_dict_read()");
		return -1;
	}

	return my_dict_init(dict, dir, filename, NULL, 0);
}

#define MAX_ARGV (16)

/*
 *	Initialize the dictionary.
 */
static int my_dict_init(fr_dict_t *dict, char const *parent, char const *filename,
			char const *src_file, int src_line)
{
	FILE	*fp;
	char 	dir[256], fn[256];
	char	buf[256];
	char	*p;
	int	line = 0;
	unsigned int	vendor;
	unsigned int	block_vendor;
	struct stat statbuf;
	char	*argv[MAX_ARGV];
	int	argc;
	fr_dict_attr_t const *da, *block_tlv[MAX_TLV_NEST + 1];
	int	which_block_tlv = 0;

	block_tlv[0] = NULL;
	block_tlv[1] = NULL;
	block_tlv[2] = NULL;
	block_tlv[3] = NULL;

	if ((strlen(parent) + 3 + strlen(filename)) > sizeof(dir)) {
		fr_strerror_printf("fr_dict_init: filename name too long");
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
		strlcpy(dir, parent, sizeof(dir));
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
		if (dict_stat_check(fn, p + 1)) {
			*p = FR_DIR_SEP;
			return 0;
		}
		*p = FR_DIR_SEP;
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			fr_strerror_printf("fr_dict_init: Couldn't open dictionary \"%s\": %s",
					   fn, fr_syserror(errno));
		} else {
			fr_strerror_printf("fr_dict_init: %s[%d]: Couldn't open dictionary \"%s\": %s",
					   src_file, src_line, fn, fr_syserror(errno));
		}
		return -2;
	}

	stat(fn, &statbuf); /* fopen() guarantees this will succeed */
	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fp);
		fr_strerror_printf("fr_dict_init: Dictionary \"%s\" is not a regular file",
				   fn);
		return -1;
	}

	/*
	 *	Globally writable dictionaries means that users can control
	 *	the server configuration with little difficulty.
	 */
#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		fclose(fp);
		fr_strerror_printf(
			"fr_dict_init: Dictionary \"%s\" is globally writable.  Refusing to start due to insecure configuration.",
			fn);
		return -1;
	}
#endif

	dict_stat_add(&statbuf);

	/*
	 *	Seed the random pool with data.
	 */
	fr_rand_seed(&statbuf, sizeof(statbuf));

	block_vendor = 0;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;
		if (buf[0] == '#' || buf[0] == 0 ||
		    buf[0] == '\n' || buf[0] == '\r')
			continue;

		/*
		 *  Comment characters should NOT be appearing anywhere but
		 *  as start of a comment;
		 */
		p = strchr(buf, '#');
		if (p) *p = '\0';

		argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
		if (argc == 0) continue;

		if (argc == 1) {
			fr_strerror_printf("fr_dict_init: %s[%d] invalid entry",
					   fn, line);
			fclose(fp);
			return -1;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(argv[0], "VALUE") == 0) {
			if (process_value(fn, line,
					  argv + 1, argc - 1) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
			if (process_attribute(dict, fn, line, block_vendor,
					      block_tlv[which_block_tlv],
					      which_block_tlv,
					      argv + 1, argc - 1) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strcasecmp(argv[0], "$INCLUDE") == 0) {
			if (my_dict_init(dict, dir, argv[1], fn, line) < 0) {
				fclose(fp);
				return -1;
			}
			continue;
		} /* $INCLUDE */

		/*
		 *	Optionally include a dictionary
		 */
		if (strcasecmp(argv[0], "$INCLUDE-") == 0) {
			int rcode = my_dict_init(dict, dir, argv[1], fn, line);

			if (rcode == -2) {
				fr_strerror_printf(NULL); /* reset error to nothing */
				continue;
			}

			if (rcode < 0) {
				fclose(fp);
				return -1;
			}
			continue;
		} /* $INCLUDE- */

		if (strcasecmp(argv[0], "VALUE-ALIAS") == 0) {
			if (process_value_alias(fn, line,
						argv + 1, argc - 1) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(argv[0], "VENDOR") == 0) {
			if (process_vendor(fn, line,
					   argv + 1, argc - 1) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		if (strcasecmp(argv[0], "BEGIN-TLV") == 0) {
			if (argc != 2) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d] invalid BEGIN-TLV entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			da = fr_dict_attr_by_name(argv[1]);
			if (!da) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: unknown attribute %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (da->type != PW_TYPE_TLV) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: attribute %s is not of type tlv",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (which_block_tlv >= MAX_TLV_NEST) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: TLVs are nested too deep",
					fn, line);
				fclose(fp);
				return -1;
			}

			block_tlv[++which_block_tlv] = da;
			continue;
		} /* BEGIN-TLV */

		if (strcasecmp(argv[0], "END-TLV") == 0) {
			if (argc != 2) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d] invalid END-TLV entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			da = fr_dict_attr_by_name(argv[1]);
			if (!da) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: unknown attribute %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (da != block_tlv[which_block_tlv]) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: END-TLV %s does not match any previous BEGIN-TLV",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}
			block_tlv[which_block_tlv--] = NULL;
			continue;
		} /* END-VENDOR */

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			if (argc < 2) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = fr_dict_vendor_by_name(argv[1]);
			if (!vendor) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: unknown vendor %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			block_vendor = vendor;

			/*
			 *	Check for extended attr VSAs
			 *
			 *	BEGIN-VENDOR foo format=Foo-Encapsulation-Attr
			 */
			if (argc > 2) {
				if (strncmp(argv[2], "format=", 7) != 0) {
					fr_strerror_printf(
						"fr_dict_init: %s[%d]: Invalid format %s",
						fn, line, argv[2]);
					fclose(fp);
					return -1;
				}

				p = argv[2] + 7;
				da = fr_dict_attr_by_name(p);
				if (!da) {
					fr_strerror_printf(
						"fr_dict_init: %s[%d]: Invalid format for BEGIN-VENDOR: unknown attribute \"%s\"",
						fn, line, p);
					fclose(fp);
					return -1;
				}

				if (!da->flags.evs) {
					fr_strerror_printf(
						"fr_dict_init: %s[%d]: Invalid format for BEGIN-VENDOR.  Attribute \"%s\" is not of \"evs\" data type",
						fn, line, p);
					fclose(fp);
					return -1;
				}

				/*
				 *	Pack the encapsulating
				 *	attribute into the upper 8
				 *	bits of the vendor ID
				 */
				block_vendor |= da->vendor;
			}

			continue;
		} /* BEGIN-VENDOR */

		if (strcasecmp(argv[0], "END-VENDOR") == 0) {
			if (argc != 2) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d] invalid END-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = fr_dict_vendor_by_name(argv[1]);
			if (!vendor) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: unknown vendor %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (vendor != (block_vendor & (FR_MAX_VENDOR - 1))) {
				fr_strerror_printf(
					"fr_dict_init: %s[%d]: END-VENDOR %s does not match any previous BEGIN-VENDOR",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}
			block_vendor = 0;
			continue;
		} /* END-VENDOR */

		/*
		 *	Any other string: We don't recognize it.
		 */
		fr_strerror_printf("fr_dict_init: %s[%d] invalid keyword \"%s\"",
				   fn, line, argv[0]);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/*
 *	Empty callback for hash table initialization.
 */
static int null_callback(UNUSED void *ctx, UNUSED void *data)
{
	return 0;
}

static void fr_pool_free(void *to_free)
{
	talloc_free(to_free);
}

/** Return the root attribute of a dictionary
 *
 */
fr_dict_attr_t const *fr_dict_root(fr_dict_t const *dict)
{
	return dict->root;
}

/** Initialize a protocol dictionary
 *
 * Initialize the directory, then fix the attr member of all attributes.
 *
 * @param ctx to allocate the dictionary from.
 * @param out If not NULL, wehre to write a pointer to the new dictionary.
 * @param dir to read dictionary files from.
 * @param fn file name to read.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_init(TALLOC_CTX *ctx, fr_dict_t **out, char const *dir, char const *fn, char const *name)
{
	fr_dict_t *dict;

	*out = NULL;

	/*
	 *	Check if we need to change anything.  If not, don't do
	 *	anything.
	 */
	if (dict_stat_check(dir, fn)) return 0;

	dict = talloc_zero(ctx, fr_dict_t);
	talloc_set_destructor(dict, _fr_dict_free);
	dict->pool = talloc_pool(dict, (1024 * 1024 * 5));	/* Pre-Allocate 5MB of pool memory for rapid startup */

	/*
	 *	Free the old dictionaries, and the stat cache.
	 *
	 *	Should be removed at some point.
	 */
	talloc_free(fr_main_dict);
	fr_main_dict = dict;

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 *
	 *	Each vendor is malloc'd, so the free function is free.
	 */
	dict->vendors_by_name = fr_hash_table_create(dict, dict_vendor_name_hash, dict_vendor_name_cmp, fr_pool_free);
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
	dict->vendors_by_num = fr_hash_table_create(dict, dict_vendor_value_hash, dict_vendor_value_cmp, NULL);
	if (!dict->vendors_by_num) goto error;

	/*
	 *	Create the table of attributes by name.   There MAY NOT
	 *	be multiple attributes of the same name.
	 *
	 *	Each attribute is malloc'd, so the free function is free.
	 */
	dict->attributes_by_name = fr_hash_table_create(dict, dict_attr_name_hash, dict_attr_name_cmp, fr_pool_free);
	if (!dict->attributes_by_name) goto error;

	/*
	 *	Create the table of attributes by value.  There MAY
	 *	be attributes of the same value.  If there are, we
	 *	pick the latest one.
	 */
	dict->attributes_by_num = fr_hash_table_create(dict, dict_attr_value_hash, dict_attr_value_cmp, NULL);
	if (!dict->attributes_by_num) goto error;

	/*
	 *	Horrible hacks for combo-IP.
	 */
	dict->attributes_combo = fr_hash_table_create(dict, dict_attr_combo_hash, dict_attr_combo_cmp, fr_pool_free);
	if (!dict->attributes_combo) goto error;

	dict->values_by_name = fr_hash_table_create(dict, dict_value_name_hash, dict_value_name_cmp, fr_pool_free);
	if (!dict->values_by_name) goto error;

	dict->values_by_num = fr_hash_table_create(dict, dict_value_value_hash, dict_value_value_cmp, fr_pool_free);
	if (!dict->values_by_num) goto error;

	/*
	 *	Magic dictionary root attribute
	 */
	dict->root = (fr_dict_attr_t *)talloc_zero_array(dict, uint8_t, sizeof(fr_dict_attr_t) + strlen(name));
	strcpy(dict->root->name, name);
	talloc_set_type(dict->root, fr_dict_attr_t);
	dict->root->flags.is_root = 1;
	dict->root->type = PW_TYPE_TLV;

	value_fixup = NULL;        /* just to be safe. */

	if (my_dict_init(dict, dir, fn, NULL, 0) < 0) goto error;

	if (value_fixup) {
		fr_dict_attr_t const *a;
		value_fixup_t *this, *next;

		for (this = value_fixup; this != NULL; this = next) {
			next = this->next;

			a = fr_dict_attr_by_name(this->attrstr);
			if (!a) {
				fr_strerror_printf("fr_dict_init: No ATTRIBUTE \"%s\" defined for VALUE \"%s\"",
						   this->attrstr, this->dval->name);
				goto error; /* leak, but they should die... */
			}

			this->dval->attr = a->attr;

			/*
			 *	Add the value into the dictionary.
			 */
			if (!fr_hash_table_replace(dict->values_by_name, this->dval)) {
				fr_strerror_printf("fr_dict_value_add: Duplicate value name %s for attribute %s",
						   this->dval->name, a->name);
				goto error;
			}

			/*
			 *	Allow them to use the old name, but
			 *	prefer the new name when printing
			 *	values.
			 */
			if (!fr_hash_table_finddata(dict->values_by_num, this->dval)) {
				fr_hash_table_replace(dict->values_by_num, this->dval);
			}
			free(this);

			/*
			 *	Just so we don't lose track of things.
			 */
			value_fixup = next;
		}
	}

	/*
	 *	Walk over all of the hash tables to ensure they're
	 *	initialized.  We do this because the threads may perform
	 *	lookups, and we don't want multi-threaded re-ordering
	 *	of the table entries.  That would be bad.
	 */
	fr_hash_table_walk(dict->vendors_by_name, null_callback, NULL);
	fr_hash_table_walk(dict->vendors_by_num, null_callback, NULL);

	fr_hash_table_walk(dict->attributes_by_name, null_callback, NULL);
	fr_hash_table_walk(dict->attributes_by_num, null_callback, NULL);

	fr_hash_table_walk(dict->values_by_num, null_callback, NULL);
	fr_hash_table_walk(dict->values_by_name, null_callback, NULL);

	if (out) *out = dict;

	return 0;
}

static size_t dict_print_attr_oid(char *buffer, size_t size, unsigned int attr, int dv_type)
{
	int nest;
	size_t outlen;
	size_t len;

	switch (dv_type) {
	default:
	case 1:
		len = snprintf(buffer, size, "%u", attr & 0xff);
		break;

	case 4:
		return snprintf(buffer, size, "%u", attr);

	case 2:
		return snprintf(buffer, size, "%u", attr & 0xffff);

	}

	if ((attr >> 8) == 0) return len;

	outlen = len;
	buffer += len;
	size -= len;

	for (nest = 1; nest <= fr_attr_max_tlv; nest++) {
		if (((attr >> fr_attr_shift[nest]) & fr_attr_mask[nest]) == 0) break;

		len = snprintf(buffer, size, ".%u",
			       (attr >> fr_attr_shift[nest]) & fr_attr_mask[nest]);

		outlen = len;
		buffer += len;
		size -= len;
	}

	return outlen;
}

/** Free dynamically allocated (unknown attributes)
 *
 * If the da was dynamically allocated it will be freed, else the function
 * will return without doing anything.
 *
 * @param da to free.
 */
void fr_dict_attr_free(fr_dict_attr_t const **da)
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

/** Initialises a dictionary attr for unknown attributes
 *
 * Initialises a dict attr for an unknown attribute/vendor/type without adding
 * it to dictionary pools/hashes.
 *
 * @param[in,out] da struct to initialise, must be at least FR_DICT_ATTR_SIZE bytes.
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return 0 on success.
 */
int fr_dict_unknown_from_fields(fr_dict_attr_t *da, unsigned int vendor, unsigned int attr)
{
	char *p;
	int dv_type = 1;
	size_t len = 0;
	size_t bufsize = FR_DICT_ATTR_MAX_NAME_LEN;

	memset(da, 0, FR_DICT_ATTR_SIZE);

	da->attr = attr;
	da->vendor = vendor;
	da->type = PW_TYPE_OCTETS;
	da->flags.is_unknown = true;
	da->flags.is_pointer = true;

	/*
	 *	Unknown attributes of the "WiMAX" vendor get marked up
	 *	as being for WiMAX.
	 */
	if (vendor == VENDORPEC_WIMAX) {
		da->flags.wimax = 1;
	}

	p = da->name;

	len = snprintf(p, bufsize, "Attr-");
	p += len;
	bufsize -= len;

	if (vendor > FR_MAX_VENDOR) {
		len = snprintf(p, bufsize, "%u.", vendor / FR_MAX_VENDOR);
		p += len;
		bufsize -= len;
		vendor &= (FR_MAX_VENDOR) - 1;
	}

	if (vendor) {
		fr_dict_vendor_t *dv;

		/*
		 *	dv_type is the length of the vendor's type field
		 *	RFC 2865 never defined a mandatory length, so
		 *	different vendors have different length type fields.
		 */
		dv = fr_dict_vendor_by_num(vendor);
		if (dv) {
			dv_type = dv->type;
		}
		len = snprintf(p, bufsize, "26.%u.", vendor);

		p += len;
		bufsize -= len;
	}

	dict_print_attr_oid(p, bufsize, attr, dv_type);

	return 0;
}

/** Allocs a dictionary attr for unknown attributes
 *
 * Allocs a dict attr for an unknown attribute/vendor/type without adding
 * it to dictionary pools/hashes.
 *
 * @param[in] ctx to allocate DA in.
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return 0 on success.
 */
fr_dict_attr_t const *fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, unsigned int vendor, unsigned int attr)
{
	uint8_t *p;
	fr_dict_attr_t *da;

	p = talloc_zero_array(ctx, uint8_t, FR_DICT_ATTR_SIZE);
	if (!p) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	da = (fr_dict_attr_t *)p;
	talloc_set_type(da, fr_dict_attr_t);

	if (fr_dict_unknown_from_fields(da, vendor, attr) < 0) {
		talloc_free(p);
		return NULL;
	}

	return da;
}

/** Create a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @note We can't validate attribute numbers here as a dictionary
 *	 lookup is required to determine if the attribute
 *	 has been marked as internal.
 *	 Even validating numbers based on dv_type which is the
 *	 length of the vendor field is wrong. Attribute number
 *	 checks must be done by the caller.
 *
 * @param[in] da to initialise.
 * @param[in] name of attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_from_str(fr_dict_attr_t *da, char const *name)
{
	unsigned int   	attr, vendor = 0;
	unsigned int    dv_type = 1;	/* The type of vendor field */

	char const	*p = name;
	char		*q;

	fr_dict_vendor_t	*dv;
	fr_dict_attr_t const	*found;

	if (fr_dict_valid_name(name) < 0) return -1;

	/*
	 *	Pull off vendor prefix first.
	 */
	if (strncasecmp(p, "Attr-", 5) != 0) {
		if (strncasecmp(p, "Vendor-", 7) == 0) {
			vendor = (int)strtol(p + 7, &q, 10);
			if ((vendor == 0) || (vendor > FR_MAX_VENDOR)) {
				fr_strerror_printf("Invalid vendor value in attribute name \"%s\"", name);

				return -1;
			}

			p = q;

		/* must be vendor name */
		} else {
			char buffer[256];

			q = strchr(p, '-');

			if (!q) {
				fr_strerror_printf("Invalid vendor name in attribute name \"%s\"", name);
				return -1;
			}

			if ((size_t)(q - p) >= sizeof(buffer)) {
				fr_strerror_printf("Vendor name too long in attribute name \"%s\"", name);

				return -1;
			}

			memcpy(buffer, p, (q - p));
			buffer[q - p] = '\0';

			vendor = fr_dict_vendor_by_name(buffer);
			if (!vendor) {
				fr_strerror_printf("Unknown name \"%s\"", name);

				return -1;
			}

			p = q;
		}

		if (*p != '-') {
			fr_strerror_printf("Invalid text following vendor definition in attribute name \"%s\"", name);

			return -1;
		}
		p++;
	}

	/*
	 *	Attr-%d
	 */
	if (strncasecmp(p, "Attr-", 5) != 0) {
		fr_strerror_printf("Unknown attribute \"%s\"", name);

		return -1;
	}

	attr = strtol(p + 5, &q, 10);

	/*
	 *	Invalid name.
	 */
	if (attr == 0) {
		fr_strerror_printf("Invalid value in attribute name \"%s\"", name);

		return -1;
	}

	p = q;

	/*
	 *	Vendor-%d-Attr-%d
	 *	VendorName-Attr-%d
	 *	Attr-%d
	 *	Attr-%d.
	 *
	 *	Anything else is invalid.
	 */
	if (((vendor != 0) && (*p != '\0')) ||
	    ((vendor == 0) && *p && (*p != '.'))) {
	invalid:
		fr_strerror_printf("Invalid OID");
		return -1;
	}

	/*
	 *	Look for OIDs.  Require the "Attr-26.Vendor-Id.type"
	 *	format, and disallow "Vendor-%d-Attr-%d" and
	 *	"VendorName-Attr-%d"
	 *
	 *	This section parses the Vendor-Id portion of
	 *	Attr-%d.%d.  where the first number is 26, *or* an
	 *	extended name of the "evs" foundta type.
	 */
	if (*p == '.') {
		found = fr_dict_attr_by_num(0, attr);
		if (!found) {
			fr_strerror_printf("Cannot parse names without dictionaries");

			return -1;
		}

		if ((attr != PW_VENDOR_SPECIFIC) &&
		    !(found->flags.extended || found->flags.long_extended)) {
			fr_strerror_printf("Standard attributes cannot use OIDs");

			return -1;
		}

		if ((attr == PW_VENDOR_SPECIFIC) || found->flags.evs) {
			vendor = strtol(p + 1, &q, 10);
			if ((vendor == 0) || (vendor > FR_MAX_VENDOR)) {
				fr_strerror_printf("Invalid vendor");

				return -1;
			}

			if (*q != '.') goto invalid;

			p = q;

			if (found->flags.evs) vendor |= attr * FR_MAX_VENDOR;
			attr = 0;
		} /* else the second number is a TLV number */
	}

	/*
	 *	Get the expected maximum size of the name.
	 */
	if (vendor) {
		dv = fr_dict_vendor_by_num(vendor & (FR_MAX_VENDOR - 1));
		if (dv) {
			dv_type = dv->type;
			if (dv_type > 3) dv_type = 3; /* hack */
		}
	}

	/*
	 *	Parse the next number.  It could be a Vendor-Type
	 *	of 1..2^24, or it could be a TLV.
	 */
	if (*p == '.') {
		attr = strtol(p + 1, &q, 10);
		if (attr == 0) {
			fr_strerror_printf("Invalid name number");
			return -1;
		}

		if (*q) {
			if (*q != '.') {
				goto invalid;
			}

			if (dv_type != 1) {
				goto invalid;
			}
		}

		p = q;
	}

	if (*p == '.') {
		if (fr_dict_str_to_oid(&vendor, &attr, p + 1, 1) < 0) {
			return -1;
		}
	}

	/*
	 *	If the caller doesn't provide a fr_dict_attr_t
	 *	we can't call fr_dict_unknown_from_fields.
	 */
	if (!da) {
		fr_strerror_printf("Unknown attributes disallowed");
		return -1;
	}

	return fr_dict_unknown_from_fields(da, vendor, attr);
}

/** Create a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @param[in] ctx to alloc new attribute in.
 * @param[in] name of attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
fr_dict_attr_t const *fr_dict_unknown_afrom_str(TALLOC_CTX *ctx, char const *name)
{
	uint8_t *p;
	fr_dict_attr_t *da;

	p = talloc_zero_array(ctx, uint8_t, FR_DICT_ATTR_SIZE);
	if (!p) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	da = (fr_dict_attr_t *)p;
	talloc_set_type(da, fr_dict_attr_t);

	if (fr_dict_unknown_from_str(da, name) < 0) {
		talloc_free(p);
		return NULL;
	}

	return da;
}

/** Create a dictionary attribute by name embedded in another string
 *
 * Find the first invalid attribute name char in the string pointed
 * to by name.
 *
 * Copy the characters between the start of the name string and the first
 * none dict_attr_allowed_char to a buffer and initialise da as an
 * unknown attribute.
 *
 * @param[out] da to initialise.
 * @param[in,out] name string start.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_from_substr(fr_dict_attr_t *da, char const **name)
{
	char const *p;
	size_t len;
	char buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	if (!name || !*name) return -1;

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = *name; fr_dict_attr_allowed_chars[(int)*p] || (*p == '.') || (*p == '-'); p++);

	len = p - *name;
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");

		return -1;
	}
	if (len == 0) {
		fr_strerror_printf("Invalid attribute name");
		return -1;
	}
	strlcpy(buffer, *name, len + 1);

	if (fr_dict_unknown_from_str(da, buffer) < 0) return -1;

	*name = p;

	return 0;
}

/*
 *	Bamboo skewers under the fingernails in 5, 4, 3, 2, ...
 */
const fr_dict_attr_t *fr_dict_parent_by_num(unsigned int vendor, unsigned int attr)
{
	int i;
	unsigned int base_vendor;

	/*
	 *	RFC attributes can't be of type "tlv".
	 */
	if (!vendor) return NULL;

	base_vendor = vendor & (FR_MAX_VENDOR - 1);

	/*
	 *	It's a real vendor.
	 */
	if (base_vendor != 0) {
		fr_dict_vendor_t const *dv;

		dv = fr_dict_vendor_by_num(base_vendor);
		if (!dv) return NULL;

		/*
		 *	Only standard format attributes can be of type "tlv",
		 *	Except for DHCP.  <sigh>
		 */
		if ((vendor != 54) && ((dv->type != 1) || (dv->length != 1))) return NULL;

		for (i = MAX_TLV_NEST; i > 0; i--) {
			unsigned int parent;

			parent = attr & fr_attr_parent_mask[i];

			if (parent != attr) return fr_dict_attr_by_num(vendor, parent); /* not base_vendor */
		}

		/*
		 *	It was a top-level VSA.  There's no parent.
		 *	We COULD return the appropriate enclosing VSA
		 *	(26, or 241.26, etc.) but that's not what we
		 *	want.
		 */
		return NULL;
	}

	/*
	 *	It's an extended attribute.  Return the base Extended-Attr-X
	 */
	if (attr < 256) return fr_dict_attr_by_num(0, (vendor / FR_MAX_VENDOR) & 0xff);

	/*
	 *	Figure out which attribute it is.
	 */
	for (i = MAX_TLV_NEST; i > 0; i--) {
		unsigned int parent;

		parent = attr & fr_attr_parent_mask[i];
		if (parent != attr) return fr_dict_attr_by_num(vendor, parent); /* not base_vendor */
	}

	return NULL;
}

/*
 *	Get an attribute by its numerical value.
 */
fr_dict_attr_t const *fr_dict_attr_by_num(unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t da;

	if ((attr > 0) && (attr < 256) && !vendor) return fr_main_dict->base_attrs[attr];

	da.attr = attr;
	da.vendor = vendor;

	return fr_hash_table_finddata(fr_main_dict->attributes_by_num, &da);
}

/** Get an attribute by its numerical value and data type
 *
 * Used only for COMBO_IP
 *
 * @return The attribute, or NULL if not found.
 */
fr_dict_attr_t const *fr_dict_attr_by_type(unsigned int vendor, unsigned int attr, PW_TYPE type)
{
	fr_dict_attr_t da;

	da.attr = attr;
	da.vendor = vendor;
	da.type = type;

	return fr_hash_table_finddata(fr_main_dict->attributes_combo, &da);
}

/** Using a parent and attr/vendor, find a child attr/vendor
 *
 */
int fr_dict_attr_child(fr_dict_attr_t const *parent, unsigned int *p_vendor, unsigned int *p_attr)
{
	unsigned int attr, vendor;
	fr_dict_attr_t da;

	if (!parent || !p_attr || !p_vendor) return false;

	attr = *p_attr;
	vendor = *p_vendor;

	/*
	 *	Only some types can have children
	 */
	switch (parent->type) {
	default:
		return false;

	case PW_TYPE_VSA:
	case PW_TYPE_TLV:
	case PW_TYPE_EVS:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
		break;
	}

	if ((vendor == 0) && (parent->vendor != 0)) return false;

	/*
	 *	Bootstrap by starting off with the parents values.
	 */
	da.attr = parent->attr;
	da.vendor = parent->vendor;

	/*
	 *	Do various butchery to insert the "attr" value.
	 *
	 *	00VID	000000AA	normal VSA for vendor VID
	 *	00VID	DDCCBBAA	normal VSAs with TLVs
	 *	EE000   000000AA	extended attr (241.1)
	 *	EE000	DDCCBBAA	extended attr with TLVs
	 *	EEVID	000000AA	EVS with vendor VID, attr AAA
	 *	EEVID	DDCCBBAA	EVS with TLVs
	 */
	if (!da.vendor) {
		da.vendor = parent->attr * FR_MAX_VENDOR;
		da.vendor |= vendor;
		da.attr = attr;

	} else {
		int i;

		/*
		 *	Trying to nest too deep.  It's an error
		 */
		if (parent->attr & (fr_attr_mask[MAX_TLV_NEST] << fr_attr_shift[MAX_TLV_NEST])) {
			return false;
		}

		for (i = MAX_TLV_NEST - 1; i >= 0; i--) {
			if ((parent->attr & (fr_attr_mask[i] << fr_attr_shift[i]))) {
				da.attr |= (attr & fr_attr_mask[i + 1]) << fr_attr_shift[i + 1];
				goto find;
			}
		}

		return false;
	}

find:
#if 0
		fprintf(stderr, "LOOKING FOR %08x %08x + %08x %08x --> %08x %08x\n",
			parent->vendor, parent->attr, attr, vendor,
			da.vendor, da.attr);
#endif

	*p_attr   = da.attr;
	*p_vendor = da.vendor;
	return true;
}

/*
 *	Get an attribute by it's numerical value, and the parent
 */
fr_dict_attr_t const *fr_dict_attr_by_parent(fr_dict_attr_t const *parent, unsigned int vendor, unsigned int attr)
{
	unsigned int my_attr, my_vendor;
	fr_dict_attr_t da;

	my_attr = attr;
	my_vendor = vendor;

	if (!fr_dict_attr_child(parent, &my_vendor, &my_attr)) return NULL;

	da.attr = my_attr;
	da.vendor = my_vendor;

	return fr_hash_table_finddata(fr_main_dict->attributes_by_num, &da);
}

/*
 *	Get an attribute by its name.
 */
fr_dict_attr_t const *fr_dict_attr_by_name(char const *name)
{
	fr_dict_attr_t *da;
	uint32_t buffer[(sizeof(*da) + FR_DICT_ATTR_MAX_NAME_LEN + 3) / 4];

	if (!name) return NULL;

	da = (fr_dict_attr_t *)buffer;
	strlcpy(da->name, name, FR_DICT_ATTR_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(fr_main_dict->attributes_by_name, da);
}

/** Look up a dictionary attribute by name embedded in another string
 *
 * Find the first invalid attribute name char in the string pointed
 * to by name.
 *
 * Copy the characters between the start of the name string and the first
 * none dict_attr_allowed_char to a buffer and perform a dictionary lookup
 * using that value.
 *
 * If the attribute exists, advance the pointer pointed to by name
 * to the first none dict_attr_allowed_char char, and return the DA.
 *
 * If the attribute does not exist, don't advance the pointer and return
 * NULL.
 *
 * @param[in,out] name string start.
 * @return
 *	- NULL if no attributes matching the name could be found.
 *	- #fr_dict_attr_t found in the global dictionary.
 */
fr_dict_attr_t const *fr_dict_attr_by_name_substr(char const **name)
{
	fr_dict_attr_t *find;
	fr_dict_attr_t const *da;
	char const *p;
	size_t len;
	uint32_t buffer[(sizeof(*find) + FR_DICT_ATTR_MAX_NAME_LEN + 3) / 4];

	if (!name || !*name) return NULL;

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

	da = fr_hash_table_finddata(fr_main_dict->attributes_by_name, find);
	if (!da) {
		fr_strerror_printf("Unknown attribute \"%s\"", find->name);
		return NULL;
	}
	*name = p;

	return da;
}

/*
 *	Associate a value with an attribute and return it.
 */
fr_dict_value_t *fr_dict_value_by_attr(unsigned int vendor, unsigned int attr, int value)
{
	fr_dict_value_t dval, *dv;

	/*
	 *	First, look up aliases.
	 */
	dval.attr = attr;
	dval.vendor = vendor;
	dval.name[0] = '\0';

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	dv = fr_hash_table_finddata(fr_main_dict->values_by_name, &dval);
	if (dv) dval.attr = dv->value;

	dval.value = value;

	return fr_hash_table_finddata(fr_main_dict->values_by_num, &dval);
}

/*
 *	Associate a value with an attribute and return it.
 */
char const *fr_dict_value_name_by_attr(unsigned int vendor, unsigned int attr, int value)
{
	fr_dict_value_t *dv;

	dv = fr_dict_value_by_attr(vendor, attr, value);
	if (!dv) return "";

	return dv->name;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
fr_dict_value_t *fr_dict_value_by_name(unsigned int vendor, unsigned int attr, char const *name)
{
	fr_dict_value_t *my_dv, *dv;
	uint32_t buffer[(sizeof(*my_dv) + FR_DICT_VALUE_MAX_NAME_LEN + 3) / 4];

	if (!name) return NULL;

	my_dv = (fr_dict_value_t *)buffer;
	my_dv->attr = attr;
	my_dv->vendor = vendor;
	my_dv->name[0] = '\0';

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	dv = fr_hash_table_finddata(fr_main_dict->values_by_name, my_dv);
	if (dv) my_dv->attr = dv->value;

	strlcpy(my_dv->name, name, FR_DICT_VALUE_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(fr_main_dict->values_by_name, my_dv);
}

/*
 *	Get the vendor PEC based on the vendor name
 *
 *	This is efficient only for small numbers of vendors.
 */
int fr_dict_vendor_by_name(char const *name)
{
	fr_dict_vendor_t *dv;
	size_t buffer[(sizeof(*dv) + FR_DICT_VENDOR_MAX_NAME_LEN + sizeof(size_t) - 1) / sizeof(size_t)];

	if (!name) return 0;

	dv = (fr_dict_vendor_t *)buffer;
	strlcpy(dv->name, name, FR_DICT_VENDOR_MAX_NAME_LEN + 1);

	dv = fr_hash_table_finddata(fr_main_dict->vendors_by_name, dv);
	if (!dv) return 0;

	return dv->vendorpec;
}

/*
 *	Return the vendor struct based on the PEC.
 */
fr_dict_vendor_t *fr_dict_vendor_by_num(int vendorpec)
{
	fr_dict_vendor_t dv;

	dv.vendorpec = vendorpec;

	return fr_hash_table_finddata(fr_main_dict->vendors_by_num, &dv);
}

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old #fr_dict_attr_t, that is left up to the caller.
 *
 * @param old unknown attribute to add.
 * @return
 *	- Existing #fr_dict_attr_t if old was found in a dictionary.
 *	- A new entry representing old.
 */
fr_dict_attr_t const *fr_dict_unknown_add(fr_dict_attr_t const *old)
{
	fr_dict_attr_t const *da;
	ATTR_FLAGS flags;

	if (!old) return NULL;

	if (!old->flags.is_unknown) return old;

	da = fr_dict_attr_by_num(old->vendor, old->attr);
	if (da) return da;

	memcpy(&flags, &old->flags, sizeof(flags));
	flags.is_unknown = false;

	if (fr_dict_attr_add(old->parent, old->name, old->vendor, old->attr, old->type, flags) < 0) {
		return NULL;
	}

	da = fr_dict_attr_by_num(old->vendor, old->attr);
	return da;
}
