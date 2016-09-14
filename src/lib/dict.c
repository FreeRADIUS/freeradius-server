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

static fr_hash_table_t *vendors_byname = NULL;
static fr_hash_table_t *vendors_byvalue = NULL;

static fr_hash_table_t *attributes_byname = NULL;
static fr_hash_table_t *attributes_byvalue = NULL;

static fr_hash_table_t *attributes_combo = NULL;

static fr_hash_table_t *values_byvalue = NULL;
static fr_hash_table_t *values_byname = NULL;

static DICT_ATTR *dict_base_attrs[256];

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
	char		attrstr[DICT_ATTR_MAX_NAME_LEN];
	DICT_VALUE	*dval;
	struct value_fixup_t *next;
} value_fixup_t;


/*
 *	So VALUEs in the dictionary can have forward references.
 */
static value_fixup_t *value_fixup = NULL;

const FR_NAME_NUMBER dict_attr_types[] = {
	{ "integer",	PW_TYPE_INTEGER },
	{ "string",	PW_TYPE_STRING },
	{ "ipaddr",	PW_TYPE_IPV4_ADDR },
	{ "date",	PW_TYPE_DATE },
	{ "abinary",	PW_TYPE_ABINARY },
	{ "octets",	PW_TYPE_OCTETS },
	{ "ifid",	PW_TYPE_IFID },
	{ "ipv6addr",	PW_TYPE_IPV6_ADDR },
	{ "ipv6prefix", PW_TYPE_IPV6_PREFIX },
	{ "byte",	PW_TYPE_BYTE },
	{ "short",	PW_TYPE_SHORT },
	{ "ether",	PW_TYPE_ETHERNET },
	{ "combo-ip",	PW_TYPE_COMBO_IP_ADDR },
	{ "tlv",	PW_TYPE_TLV },
	{ "signed",	PW_TYPE_SIGNED },
	{ "extended",	PW_TYPE_EXTENDED },
	{ "long-extended",	PW_TYPE_LONG_EXTENDED },
	{ "evs",	PW_TYPE_EVS },
	{ "uint8",	PW_TYPE_BYTE },
	{ "uint16",	PW_TYPE_SHORT },
	{ "uint32",	PW_TYPE_INTEGER },
	{ "int32",	PW_TYPE_SIGNED },
	{ "integer64",	PW_TYPE_INTEGER64 },
	{ "uint64",	PW_TYPE_INTEGER64 },
	{ "ipv4prefix", PW_TYPE_IPV4_PREFIX },
	{ "cidr", 	PW_TYPE_IPV4_PREFIX },
	{ "vsa",	PW_TYPE_VSA },
	{ NULL, 0 }
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

unsigned const fr_attr_mask[MAX_TLV_NEST + 1] = { 0xff, 0xff, 0xff, 0x1f, 0x07 };

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
		int c = *(unsigned char const *) p;
		if (isalpha(c)) c = tolower(c);

		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t ) (c & 0xff);
	}

	return hash;
}


/*
 *	Hash callback functions.
 */
static uint32_t dict_attr_name_hash(void const *data)
{
	return dict_hashname(((DICT_ATTR const *)data)->name);
}

static int dict_attr_name_cmp(void const *one, void const *two)
{
	DICT_ATTR const *a = one;
	DICT_ATTR const *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_attr_value_hash(void const *data)
{
	uint32_t hash;
	DICT_ATTR const *attr = data;

	hash = fr_hash(&attr->vendor, sizeof(attr->vendor));
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

static int dict_attr_value_cmp(void const *one, void const *two)
{
	DICT_ATTR const *a = one;
	DICT_ATTR const *b = two;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	return a->attr - b->attr;
}

static uint32_t dict_attr_combo_hash(void const *data)
{
	uint32_t hash;
	DICT_ATTR const *attr = data;

	hash = fr_hash(&attr->vendor, sizeof(attr->vendor));
	hash = fr_hash_update(&attr->type, sizeof(attr->type), hash);
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

static int dict_attr_combo_cmp(void const *one, void const *two)
{
	DICT_ATTR const *a = one;
	DICT_ATTR const *b = two;

	if (a->type < b->type) return -1;
	if (a->type > b->type) return +1;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	return a->attr - b->attr;
}

static uint32_t dict_vendor_name_hash(void const *data)
{
	return dict_hashname(((DICT_VENDOR const *)data)->name);
}

static int dict_vendor_name_cmp(void const *one, void const *two)
{
	DICT_VENDOR const *a = one;
	DICT_VENDOR const *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_vendor_value_hash(void const *data)
{
	return fr_hash(&(((DICT_VENDOR const *)data)->vendorpec),
			 sizeof(((DICT_VENDOR const *)data)->vendorpec));
}

static int dict_vendor_value_cmp(void const *one, void const *two)
{
	DICT_VENDOR const *a = one;
	DICT_VENDOR const *b = two;

	return a->vendorpec - b->vendorpec;
}

static uint32_t dict_value_name_hash(void const *data)
{
	uint32_t hash;
	DICT_VALUE const *dval = data;

	hash = dict_hashname(dval->name);
	hash = fr_hash_update(&dval->vendor, sizeof(dval->vendor), hash);
	return fr_hash_update(&dval->attr, sizeof(dval->attr), hash);
}

static int dict_value_name_cmp(void const *one, void const *two)
{
	int rcode;
	DICT_VALUE const *a = one;
	DICT_VALUE const *b = two;

	rcode = a->attr - b->attr;
	if (rcode != 0) return rcode;

	rcode = a->vendor - b->vendor;
	if (rcode != 0) return rcode;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_value_value_hash(void const *data)
{
	uint32_t hash;
	DICT_VALUE const *dval = data;

	hash = fr_hash(&dval->attr, sizeof(dval->attr));
	hash = fr_hash_update(&dval->vendor, sizeof(dval->vendor), hash);
	return fr_hash_update(&dval->value, sizeof(dval->value), hash);
}

static int dict_value_value_cmp(void const *one, void const *two)
{
	int rcode;
	DICT_VALUE const *a = one;
	DICT_VALUE const *b = two;

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

typedef struct fr_pool_t {
	void	*page_end;
	void	*free_ptr;
	struct fr_pool_t *page_free;
	struct fr_pool_t *page_next;
} fr_pool_t;

#define FR_POOL_SIZE (32768)
#define FR_ALLOC_ALIGN (8)

static fr_pool_t *dict_pool = NULL;

static fr_pool_t *fr_pool_create(void)
{
	fr_pool_t *fp = malloc(FR_POOL_SIZE);

	if (!fp) return NULL;

	memset(fp, 0, FR_POOL_SIZE);

	fp->page_end = ((uint8_t *) fp) + FR_POOL_SIZE;
	fp->free_ptr = ((uint8_t *) fp) + sizeof(*fp);
	fp->page_free = fp;
	fp->page_next = NULL;
	return fp;
}

static void fr_pool_delete(fr_pool_t **pfp)
{
	fr_pool_t *fp, *next;

	if (!pfp || !*pfp) return;

	for (fp = *pfp; fp != NULL; fp = next) {
		next = fp->page_next;
		fp->page_next = NULL;
		free(fp);
	}
	*pfp = NULL;
}


static void *fr_pool_alloc(size_t size)
{
	void *ptr;

	if (size == 0) return NULL;

	if (size > 256) return NULL; /* shouldn't happen */

	if (!dict_pool) {
		dict_pool = fr_pool_create();
		if (!dict_pool) return NULL;
	}

	if ((size & (FR_ALLOC_ALIGN - 1)) != 0) {
		size += FR_ALLOC_ALIGN - (size & (FR_ALLOC_ALIGN - 1));
	}

	if ((((uint8_t *) dict_pool->page_free->free_ptr) + size) > (uint8_t *) dict_pool->page_free->page_end) {
		dict_pool->page_free->page_next = fr_pool_create();
		if (!dict_pool->page_free->page_next) return NULL;
		dict_pool->page_free = dict_pool->page_free->page_next;
	}

	ptr = dict_pool->page_free->free_ptr;
	dict_pool->page_free->free_ptr = ((uint8_t *) dict_pool->page_free->free_ptr) + size;

	return ptr;
}


static void fr_pool_free(UNUSED void *ptr)
{
	/*
	 *	Place-holder for later code.
	 */
}

/*
 *	Free the dictionary_attributes and dictionary_values lists.
 */
void dict_free(void)
{
	/*
	 *	Free the tables
	 */
	fr_hash_table_free(vendors_byname);
	fr_hash_table_free(vendors_byvalue);
	vendors_byname = NULL;
	vendors_byvalue = NULL;

	fr_hash_table_free(attributes_byname);
	fr_hash_table_free(attributes_byvalue);
	fr_hash_table_free(attributes_combo);
	attributes_byname = NULL;
	attributes_byvalue = NULL;
	attributes_combo = NULL;

	fr_hash_table_free(values_byname);
	fr_hash_table_free(values_byvalue);
	values_byname = NULL;
	values_byvalue = NULL;

	memset(dict_base_attrs, 0, sizeof(dict_base_attrs));

	fr_pool_delete(&dict_pool);

	dict_stat_free();
}

/*
 *	Add vendor to the list.
 */
int dict_addvendor(char const *name, unsigned int value)
{
	size_t length;
	DICT_VENDOR *dv;

	if (value >= FR_MAX_VENDOR) {
		fr_strerror_printf("dict_addvendor: Cannot handle vendor ID larger than 2^24");
		return -1;
	}

	if ((length = strlen(name)) >= DICT_VENDOR_MAX_NAME_LEN) {
		fr_strerror_printf("dict_addvendor: vendor name too long");
		return -1;
	}

	if ((dv = fr_pool_alloc(sizeof(*dv) + length)) == NULL) {
		fr_strerror_printf("dict_addvendor: out of memory");
		return -1;
	}

	strcpy(dv->name, name);
	dv->vendorpec  = value;
	dv->type = dv->length = 1; /* defaults */

	if (!fr_hash_table_insert(vendors_byname, dv)) {
		DICT_VENDOR *old_dv;

		old_dv = fr_hash_table_finddata(vendors_byname, dv);
		if (!old_dv) {
			fr_strerror_printf("dict_addvendor: Failed inserting vendor name %s", name);
			return -1;
		}
		if (old_dv->vendorpec != dv->vendorpec) {
			fr_strerror_printf("dict_addvendor: Duplicate vendor name %s", name);
			return -1;
		}

		/*
		 *	Already inserted.  Discard the duplicate entry.
		 */
		fr_pool_free(dv);
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
	if (!fr_hash_table_replace(vendors_byvalue, dv)) {
		fr_strerror_printf("dict_addvendor: Failed inserting vendor %s",
			   name);
		return -1;
	}

	return 0;
}

const int dict_attr_allowed_chars[256] = {
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
int dict_valid_name(char const *name)
{
	uint8_t const *p;

	for (p = (uint8_t const *) name; *p != '\0'; p++) {
		if (!dict_attr_allowed_chars[*p]) {
			char buff[5];

			fr_prints(buff, sizeof(buff), (char const *)p, 1, '\'');
			fr_strerror_printf("Invalid character '%s' in attribute", buff);

			return -(p - (uint8_t const *)name);
		}
	}

	return 0;
}


/*
 *	Find the parent of the attr/vendor.
 */
DICT_ATTR const *dict_parent(unsigned int attr, unsigned int vendor)
{
	int i;
	unsigned int base_vendor;

	/*
	 *	RFC attributes can't be of type "tlv", except for dictionary.rfc6930
	 */
	if (!vendor) {
#ifdef PW_IPV6_6RD_CONFIGURATION
		if (attr == PW_IPV6_6RD_CONFIGURATION) return NULL;

		if (((attr & 0xff) == PW_IPV6_6RD_CONFIGURATION) &&
		    (attr >> 8) < 4) {
			return dict_attrbyvalue(PW_IPV6_6RD_CONFIGURATION, 0);
		}
#endif
		return NULL;
	}

	base_vendor = vendor & (FR_MAX_VENDOR - 1);

	/*
	 *	It's a real vendor.
	 */
	if (base_vendor != 0) {
		DICT_VENDOR const *dv;

		dv = dict_vendorbyvalue(base_vendor);
		if (!dv) return NULL;

		/*
		 *	Only standard format attributes can be of type "tlv",
		 *	Except for DHCP.  <sigh>
		 */
		if ((vendor != 54) && ((dv->type != 1) || (dv->length != 1))) return NULL;

		for (i = MAX_TLV_NEST; i > 0; i--) {
			unsigned int parent;

			parent = attr & fr_attr_parent_mask[i];

			if (parent != attr) return dict_attrbyvalue(parent, vendor); /* not base_vendor */
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
	if (attr < 256) return dict_attrbyvalue((vendor / FR_MAX_VENDOR) & 0xff, 0);

	/*
	 *	Figure out which attribute it is.
	 */
	for (i = MAX_TLV_NEST; i > 0; i--) {
		unsigned int parent;

		parent = attr & fr_attr_parent_mask[i];
		if (parent != attr) return dict_attrbyvalue(parent, vendor); /* not base_vendor */
	}

	return NULL;
}


/** Add an attribute to the dictionary
 *
 * @return 0 on success -1 on failure.
 */
int dict_addattr(char const *name, int attr, unsigned int vendor, PW_TYPE type,
		 ATTR_FLAGS flags)
{
	size_t namelen;
	DICT_ATTR const	*parent;
	DICT_ATTR *n;
	static int      max_attr = 0;

	namelen = strlen(name);
	if (namelen >= DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("dict_addattr: attribute name too long");
		return -1;
	}

	if (dict_valid_name(name) < 0) return -1;

	if (flags.has_tag &&
	    !((type == PW_TYPE_INTEGER) || (type == PW_TYPE_STRING))) {
		fr_strerror_printf("dict_addattr: Only 'integer' and 'string' attributes can have tags");
		return -1;
	}

	/*
	 *	Disallow attributes of type zero.
	 */
	if (!attr && !vendor) {
		fr_strerror_printf("dict_addattr: Attribute 0 is invalid and cannot be used");
		return -1;
	}

	/*
	 *	If the attr is '-1', that means use a pre-existing
	 *	one (if it already exists).  If one does NOT already exist,
	 *	then create a new attribute, with a non-conflicting value,
	 *	and use that.
	 */
	if (attr == -1) {
		if (dict_attrbyname(name)) {
			return 0; /* exists, don't add it again */
		}

		attr = ++max_attr;

	} else if (vendor == 0) {
		/*
		 *  Update 'max_attr'
		 */
		if (attr > max_attr) {
			max_attr = attr;
		}
	}

	/*
	 *	Check the parent attribute, and set the various flags
	 *	based on the parents values.  It's OK for the caller
	 *	to not set them, as we'll set them.  But if the caller
	 *	sets them when he's not supposed to set them, that's
	 *	an error.
	 */
	parent = dict_parent(attr, vendor);
	if (parent) {
		/*
		 *	We're still in the same space and the parent isn't a TLV.  That's an error.
		 *
		 *	Otherwise, dict_parent() has taken us from an Extended sub-attribute to
		 *	a *the* Extended attribute, whish isn't what we want here.
		 */
		if ((vendor == parent->vendor) && (parent->type != PW_TYPE_TLV)) {
			fr_strerror_printf("dict_addattr: Attribute %s has parent attribute %s which is not of type 'tlv'",
					   name, parent->name);
			return -1;
		}

		flags.extended |= parent->flags.extended;
		flags.long_extended |= parent->flags.long_extended;
		flags.evs |= parent->flags.evs;
	}

	/*
	 *	Manually extended flags for extended attributes.  We
	 *	can't expect the caller to know all of the details of the flags.
	 */
	if (vendor >= FR_MAX_VENDOR) {
		DICT_ATTR const *da;

		/*
		 *	Trying to manually create an extended
		 *	attribute, but the parent extended attribute
		 *	doesn't exist?  That's an error.
		 */
		da = dict_attrbyvalue(vendor / FR_MAX_VENDOR, 0);
		if (!da) {
			fr_strerror_printf("Extended attributes must be defined from the extended space");
			return -1;
		}

		flags.extended |= da->flags.extended;
		flags.long_extended |= da->flags.long_extended;
		flags.evs |= da->flags.evs;

		/*
		 *	There's still a real vendor.  Since it's an
		 *	extended attribute, set the EVS flag.
		 */
		if ((vendor & (FR_MAX_VENDOR -1)) != 0) flags.evs = 1;
	}

	/*
	 *	Additional checks for extended attributes.
	 */
	if (flags.extended || flags.long_extended || flags.evs) {
		if (vendor && (vendor < FR_MAX_VENDOR)) {
			fr_strerror_printf("dict_addattr: VSAs cannot use the \"extended\" or \"evs\" attribute formats");
			return -1;
		}
		if (flags.has_tag
#ifdef WITH_DHCP
		    || flags.array
#endif
		    || ((flags.encrypt != FLAG_ENCRYPT_NONE) && (flags.encrypt != FLAG_ENCRYPT_TUNNEL_PASSWORD))) {
			fr_strerror_printf("dict_addattr: The \"extended\" attributes MUST NOT have any flags set");
			return -1;
		}
	}

	if (flags.evs) {
		if (!(flags.extended || flags.long_extended)) {
			fr_strerror_printf("dict_addattr: Attributes of type \"evs\" MUST have a parent of type \"extended\"");
			return -1;
		}
	}

	/*
	 *	Do various sanity checks.
	 */
	if (attr < 0) {
		fr_strerror_printf("dict_addattr: ATTRIBUTE has invalid number (less than zero)");
		return -1;
	}

	if (flags.has_tlv && flags.length) {
		fr_strerror_printf("TLVs cannot have a fixed length");
		return -1;
	}

	if (vendor && flags.concat) {
		fr_strerror_printf("VSAs cannot have the \"concat\" flag set");
		return -1;
	}

	if (flags.concat && (type != PW_TYPE_OCTETS)) {
		fr_strerror_printf("The \"concat\" flag can only be set for attributes of type \"octets\"");
		return -1;
	}

	if (flags.concat && (flags.has_tag || flags.array || flags.is_tlv || flags.has_tlv ||
			     flags.length || flags.evs || flags.extended || flags.long_extended ||
			     (flags.encrypt != FLAG_ENCRYPT_NONE))) {
		fr_strerror_printf("The \"concat\" flag cannot be used with any other flag");
		return -1;
	}

	if (flags.length && (type != PW_TYPE_OCTETS)) {
		fr_strerror_printf("The \"length\" flag can only be set for attributes of type \"octets\"");
		return -1;
	}

	if (flags.length && (flags.has_tag || flags.array || flags.is_tlv || flags.has_tlv ||
			     flags.concat || flags.evs || flags.extended || flags.long_extended ||
			     (flags.encrypt > FLAG_ENCRYPT_USER_PASSWORD))) {
		fr_strerror_printf("The \"length\" flag cannot be used with any other flag");
		return -1;
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
			return -1;
		}

		flags.length = 0;
		flags.extended = 1;
		break;

	case PW_TYPE_LONG_EXTENDED:
		if ((vendor != 0) || (attr < 241)) {
			fr_strerror_printf("Attributes of type \"long-extended\" MUST "
					   "be RFC attributes with value >= 241.");
			return -1;
		}

		flags.length = 0;
		flags.extended = 1;
		flags.long_extended = 1;
		break;

	case PW_TYPE_EVS:
		if (attr != PW_VENDOR_SPECIFIC) {
			fr_strerror_printf("Attributes of type \"evs\" MUST have "
					   "attribute code 26.");
			return -1;
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
			return -1;
		}

		if (flags.length == 0) {
			fr_strerror_printf("The \"encrypt=1\" flag MUST be used with an explicit length for 'octets' data types");
			return -1;
		}
	}

	if ((vendor & (FR_MAX_VENDOR -1)) != 0) {
		DICT_VENDOR *dv;
		static DICT_VENDOR *last_vendor = NULL;

		if (flags.has_tlv && (flags.encrypt != FLAG_ENCRYPT_NONE)) {
			fr_strerror_printf("TLV's cannot be encrypted");
			return -1;
		}

		if (flags.is_tlv && flags.has_tag) {
			fr_strerror_printf("Sub-TLV's cannot have a tag");
			return -1;
		}

		if (flags.has_tlv && flags.has_tag) {
			fr_strerror_printf("TLV's cannot have a tag");
			return -1;
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
			dv = dict_vendorbyvalue(vendor & (FR_MAX_VENDOR - 1));
			last_vendor = dv;
		}

		/*
		 *	If the vendor isn't defined, die.
		 */
		if (!dv) {
			fr_strerror_printf("dict_addattr: Unknown vendor %u",
					   vendor & (FR_MAX_VENDOR - 1));
			return -1;
		}

		if (!attr && dv->type != 1) {
			fr_strerror_printf("dict_addattr: Attribute %s cannot have value zero",
					   name);
			return -1;
		}

		/*
		 *	FIXME: Switch over dv->type, and limit things
		 *	properly.
		 */
		if ((dv->type == 1) && (attr >= 256) && !flags.is_tlv) {
			fr_strerror_printf("dict_addattr: ATTRIBUTE has invalid number (larger than 255)");
			return -1;
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

	/*
	 *	Create a new attribute for the list
	 */
	if ((n = fr_pool_alloc(sizeof(*n) + namelen)) == NULL) {
	oom:
		fr_strerror_printf("dict_addattr: out of memory");
		return -1;
	}

	memcpy(n->name, name, namelen);
	n->name[namelen] = '\0';
	n->attr = attr;
	n->vendor = vendor;
	n->type = type;
	n->flags = flags;

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(attributes_byname, n)) {
		DICT_ATTR	*a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = fr_hash_table_finddata(attributes_byname, n);
		if (a && (strcasecmp(a->name, n->name) == 0)) {
			if (a->attr != n->attr) {
				fr_strerror_printf("dict_addattr: Duplicate attribute name %s", name);
				fr_pool_free(n);
				return -1;
			}

			/*
			 *	Same name, same vendor, same attr,
			 *	maybe the flags and/or type is
			 *	different.  Let the new value
			 *	over-ride the old one.
			 */
		}


		fr_hash_table_delete(attributes_byvalue, a);

		if (!fr_hash_table_replace(attributes_byname, n)) {
			fr_strerror_printf("dict_addattr: Internal error storing attribute %s", name);
			fr_pool_free(n);
			return -1;
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
	if (!fr_hash_table_replace(attributes_byvalue, n)) {
		fr_strerror_printf("dict_addattr: Failed inserting attribute name %s", name);
		return -1;
	}

	/*
	 *	Hacks for combo-IP
	 */
	if (n->type == PW_TYPE_COMBO_IP_ADDR) {
		DICT_ATTR *v4, *v6;

		v4 = fr_pool_alloc(sizeof(*v4) + namelen);
		if (!v4) goto oom;

		v6 = fr_pool_alloc(sizeof(*v6) + namelen);
		if (!v6) goto oom;

		memcpy(v4, n, sizeof(*v4) + namelen);
		v4->type = PW_TYPE_IPV4_ADDR;

		memcpy(v6, n, sizeof(*v6) + namelen);
		v6->type = PW_TYPE_IPV6_ADDR;
		if (!fr_hash_table_replace(attributes_combo, v4)) {
			fr_strerror_printf("dict_addattr: Failed inserting attribute name %s - IPv4", name);
			return -1;
		}

		if (!fr_hash_table_replace(attributes_combo, v6)) {
			fr_strerror_printf("dict_addattr: Failed inserting attribute name %s - IPv6", name);
			return -1;
		}
	}

	if (!vendor && (attr > 0) && (attr < 256)) {
		 dict_base_attrs[attr] = n;
	}

	return 0;
}


/*
 *	Add a value for an attribute to the dictionary.
 */
int dict_addvalue(char const *namestr, char const *attrstr, int value)
{
	size_t		length;
	DICT_ATTR const	*da;
	DICT_VALUE	*dval;

	static DICT_ATTR const *last_attr = NULL;

	if (!*namestr) {
		fr_strerror_printf("dict_addvalue: empty names are not permitted");
		return -1;
	}

	if ((length = strlen(namestr)) >= DICT_VALUE_MAX_NAME_LEN) {
		fr_strerror_printf("dict_addvalue: value name too long");
		return -1;
	}

	if ((dval = fr_pool_alloc(sizeof(*dval) + length)) == NULL) {
		fr_strerror_printf("dict_addvalue: out of memory");
		return -1;
	}
	memset(dval, 0, sizeof(*dval));

	strcpy(dval->name, namestr);
	dval->value = value;

	/*
	 *	Most VALUEs are bunched together by ATTRIBUTE.  We can
	 *	save a lot of lookups on dictionary initialization by
	 *	caching the last attribute.
	 */
	if (last_attr && (strcasecmp(attrstr, last_attr->name) == 0)) {
		da = last_attr;
	} else {
		da = dict_attrbyname(attrstr);
		last_attr = da;
	}

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	if (da) {
		if (da->flags.has_value_alias) {
			fr_strerror_printf("dict_addvalue: Cannot add VALUE for ATTRIBUTE \"%s\": It already has a VALUE-ALIAS", attrstr);
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
				fr_pool_free(dval);
				fr_strerror_printf("dict_addvalue: ATTRIBUTEs of type 'byte' cannot have VALUEs larger than 255");
				return -1;
			}
			break;
		case PW_TYPE_SHORT:
			if (value > 65535) {
				fr_pool_free(dval);
				fr_strerror_printf("dict_addvalue: ATTRIBUTEs of type 'short' cannot have VALUEs larger than 65535");
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
			fr_pool_free(dval);
			fr_strerror_printf("dict_addvalue: VALUEs cannot be defined for attributes of type '%s'",
				   fr_int2str(dict_attr_types, da->type, "?Unknown?"));
			return -1;
		}
	} else {
		value_fixup_t *fixup;

		fixup = (value_fixup_t *) malloc(sizeof(*fixup));
		if (!fixup) {
			fr_pool_free(dval);
			fr_strerror_printf("dict_addvalue: out of memory");
			return -1;
		}
		memset(fixup, 0, sizeof(*fixup));

		strlcpy(fixup->attrstr, attrstr, sizeof(fixup->attrstr));
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
		DICT_ATTR *tmp;
		memcpy(&tmp, &dval, sizeof(tmp));

		if (!fr_hash_table_insert(values_byname, tmp)) {
			if (da) {
				DICT_VALUE *old;

				/*
				 *	Suppress duplicates with the same
				 *	name and value.  There are lots in
				 *	dictionary.ascend.
				 */
				old = dict_valbyname(da->attr, da->vendor, namestr);
				if (old && (old->value == dval->value)) {
					fr_pool_free(dval);
					return 0;
				}
			}

			fr_pool_free(dval);
			fr_strerror_printf("dict_addvalue: Duplicate value name %s for attribute %s", namestr, attrstr);
			return -1;
		}
	}

	/*
	 *	There are multiple VALUE's, keyed by attribute, so we
	 *	take care of that here.
	 */
	if (!fr_hash_table_replace(values_byvalue, dval)) {
		fr_strerror_printf("dict_addvalue: Failed inserting value %s",
			   namestr);
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

		c = memchr(tab, tolower((int) *str), base);
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
 *	Vendor  Attribute
 *	------  ---------
 *	00VID	000000AA	normal VSA for vendor VID
 *	00VID	AABBCCDD	normal VSAs with TLVs
 *	EE000   000000AA	extended attr (241.1)
 *	EE000	AABBCCDD	extended attr with TLVs
 *	EEVID	000000AA	EVS with vendor VID, attr AAA
 *	EEVID	AABBCCDD	EVS with TLVs
 *
 *	<whew>!  Are we crazy, or what?
 */
int dict_str2oid(char const *ptr, unsigned int *pvalue, unsigned int *pvendor,
		 int tlv_depth)
{
	char const *p;
	unsigned int attr;
	
#ifdef WITH_DICT_OID_DEBUG
	fprintf(stderr, "PARSING %s tlv_depth %d pvalue %08x pvendor %08x\n", ptr,
		tlv_depth, *pvalue, *pvendor);
#endif

	if (tlv_depth > fr_attr_max_tlv) {
		fr_strerror_printf("Too many sub-attributes");
		return -1;
	}

	/*
	 *	No vendor, try to do basic parsing.
	 */
	if (!*pvendor && !*pvalue) {
		/*
		 *	Can't call us with a pre-parsed value and no vendor.
		 */
		if (tlv_depth != 0) {
			fr_strerror_printf("Invalid call with wrong TLV depth %d", tlv_depth);
			return -1;
		}

		p = strchr(ptr, '.');
		if (!sscanf_i(ptr, &attr)) {
			fr_strerror_printf("Invalid data '%s' in attribute identifier", ptr);
			return -1;
		}

		/*
		 *	Normal attribute with no OID.  Return it.
		 */
		if (!p) {
			*pvalue = attr;
			goto done;
		}

		/*
		 *	We have an OID, look up the attribute to see what it is.
		 */
		if (attr != PW_VENDOR_SPECIFIC) {
			DICT_ATTR const *da;

			da = dict_attrbyvalue(attr, 0);
			if (!da) {
				*pvalue = attr;
				goto done;
			}

			/*
			 *	Standard attributes (including internal
			 *	ones) can have TLVs, but only for some
			 *	of them.
			 */
			if (!da->flags.extended) {
#ifdef PW_IPV6_6RD_CONFIGURATION
				if (attr == PW_IPV6_6RD_CONFIGURATION) {
					*pvalue = attr;
					ptr = p + 1;
					tlv_depth = 1;
					goto keep_parsing;
				}
#endif
				fr_strerror_printf("Standard attributes cannot use OIDs");
				return -1;
			}

			*pvendor = attr * FR_MAX_VENDOR;
			ptr = p + 1;
		} /* and fall through to re-parsing the VSA */

		/*
		 *	Look for the attribute number.
		 */
		if (!sscanf_i(ptr, &attr)) {
			fr_strerror_printf("Invalid data '%s' in attribute identifier", ptr);
			return -1;
		}

		p = strchr(ptr, '.');

		/*
		 *	Handle VSAs.  Either in the normal space, or in the extended space.
		 */
		if (attr == PW_VENDOR_SPECIFIC) {
			if (!p) {
				*pvalue = attr;
				goto done;
			}
			ptr = p + 1;

			if (!sscanf_i(ptr, &attr)) {
				fr_strerror_printf("Invalid data '%s' in vendor identifier", ptr);
				return -1;
			}

			p = strchr(ptr, '.');
			if (!p) {
				fr_strerror_printf("Cannot define VENDOR in an ATTRIBUTE");
				return -1;
			}
			ptr = p + 1;

			*pvendor |= attr;
		} else {
			*pvalue = attr;
		}
	} /* fall through to processing an OID with pre-defined *pvendor and *pvalue */

keep_parsing:
#ifdef WITH_DICT_OID_DEBUG
	fprintf(stderr, "KEEP PARSING %s tlv_depth %d pvalue %08x pvendor %08x\n", ptr,
		tlv_depth, *pvalue, *pvendor);
#endif

	/*
	 *	Check the vendor.  Only RFC format attributes can have TLVs.
	 */
	if (*pvendor) {
		DICT_VENDOR const *dv = NULL;

		dv = dict_vendorbyvalue(*pvendor);
		if (dv && (dv->type != 1)) {
			if (*pvalue || (tlv_depth != 0)) {
				fr_strerror_printf("Attribute cannot have TLVs");
				return -1;
			}

			if (!sscanf_i(ptr, &attr)) {
				fr_strerror_printf("Invalid data '%s' in attribute identifier", ptr);
				return -1;
			}

			if ((dv->type < 3) && (attr > (unsigned int) (1 << (8 * dv->type)))) {
				fr_strerror_printf("Number '%s' out of allowed range in attribute identifier", ptr);
				return -1;
			}
			
			*pvalue = attr;

#ifdef WITH_DHCP
			/*
			 *	DHCP attributes can have TLVs. <sigh>
			 */
			if (*pvendor == 54) goto dhcp_skip;
#endif
			goto done;
		}
	}

	/*
	 *	Parse the rest of the TLVs.
	 */
	while (tlv_depth <= fr_attr_max_tlv) {
#ifdef WITH_DICT_OID_DEBUG
		fprintf(stderr, "TLV  PARSING %s tlv_depth %d pvalue %08x pvendor %08x\n", ptr,
			tlv_depth, *pvalue, *pvendor);
#endif

		if (!sscanf_i(ptr, &attr)) {
			fr_strerror_printf("Invalid data '%s' in attribute identifier", ptr);
			return -1;
		}

		if (attr > fr_attr_mask[tlv_depth]) {
			fr_strerror_printf("Number '%s' out of allowed range in attribute identifier", ptr);
			return -1;
		}

		attr <<= fr_attr_shift[tlv_depth];

#ifdef WITH_DICT_OID_DEBUG
		if (*pvendor) {
			DICT_ATTR const *da;

			da = dict_parent(*pvalue | attr, *pvendor);
			if (!da) {
				fprintf(stderr, "STR2OID FAILED PARENT %08x | %08x, %08x\n",
					*pvalue, attr, *pvendor);
			} else if ((da->attr != *pvalue) || (da->vendor != *pvendor)) {
				fprintf(stderr, "STR2OID DISAGREEMENT WITH PARENT %08x, %08x\t%08x, %08x\n",
					*pvalue, *pvendor, da->attr, da->vendor);
			}
		}
#endif

		*pvalue |= attr;

#ifdef WITH_DHCP
	dhcp_skip:
#endif
		p = strchr(ptr, '.');
		if (!p) break;

		ptr = p + 1;
		tlv_depth++;
	}

done:
#ifdef WITH_DICT_OID_DEBUG
	fprintf(stderr, "RETURNING %08x %08x\n", *pvalue, *pvendor);
#endif
	return 0;
}


/*
 *	Process the ATTRIBUTE command
 */
static int process_attribute(char const* fn, int const line,
			     unsigned int block_vendor,
			     DICT_ATTR const *block_tlv, int tlv_depth,
			     char **argv, int argc)
{
	int		oid = 0;
	unsigned int    vendor = 0;
	unsigned int	value;
	int		type;
	unsigned int	length;
	ATTR_FLAGS	flags;
	char		*p;

	if ((argc < 3) || (argc > 4)) {
		fr_strerror_printf("dict_init: %s[%d]: invalid ATTRIBUTE line",
			fn, line);
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_printf("dict_init: %s[%d]: Invalid attribute name",
				   fn, line);
		return -1;
	}

	memset(&flags, 0, sizeof(flags));

	/*
	 *	Look for OIDs before doing anything else.
	 */
	if (strchr(argv[1], '.') != NULL) oid = 1;

	{
		DICT_ATTR const *da;

		vendor = block_vendor;

		if (!block_tlv) {
			value = 0;
		} else {
			value = block_tlv->attr;
		}

		/*
		 *	Parse OID.
		 */
		if (dict_str2oid(argv[1], &value, &vendor, tlv_depth) < 0) {
			char buffer[256];

			strlcpy(buffer, fr_strerror(), sizeof(buffer));

			fr_strerror_printf("dict_init: %s[%d]: Invalid attribute identifier: %s", fn, line, buffer);
			return -1;
		}
		block_vendor = vendor;

		if (oid) {
			/*
			 *	Set the flags based on the parents flags.
			 */
			da = dict_parent(value, vendor);
			if (!da) {
				fr_strerror_printf("dict_init: %s[%d]: Parent attribute for %08x,%08x is undefined.", fn, line, value, vendor);
				return -1;
			}

			flags.extended = da->flags.extended;
			flags.long_extended = da->flags.long_extended;
			flags.evs = da->flags.evs;
			if (da->flags.has_tlv) flags.is_tlv = 1;
		}
	}

	if (strncmp(argv[2], "octets[", 7) != 0) {
		/*
		 *	find the type of the attribute.
		 */
		type = fr_str2int(dict_attr_types, argv[2], -1);
		if (type < 0) {
			fr_strerror_printf("dict_init: %s[%d]: invalid type \"%s\"",
					   fn, line, argv[2]);
			return -1;
		}

	} else {
		type = PW_TYPE_OCTETS;

		p = strchr(argv[2] + 7, ']');
		if (!p) {
			fr_strerror_printf("dict_init: %s[%d]: Invalid format for octets", fn, line);
			return -1;
		}

		*p = 0;

		if (!sscanf_i(argv[2] + 7, &length)) {
			fr_strerror_printf("dict_init: %s[%d]: invalid length", fn, line);
			return -1;
		}

		if ((length == 0) || (length > 253)) {
			fr_strerror_printf("dict_init: %s[%d]: invalid length", fn, line);
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
			fr_strerror_printf("dict_init: %s[%d]: Extended attributes cannot use flags", fn, line);
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
					fr_strerror_printf("dict_init: %s[%d] invalid option %s",
							   fn, line, key);
					return -1;
				}

				if ((flags.encrypt == FLAG_ENCRYPT_ASCEND_SECRET) &&
				    (type != PW_TYPE_STRING)) {
					fr_strerror_printf("dict_init: %s[%d] Only \"string\" types can have the "
							   "\"encrypt=3\" flag set", fn, line);
					return -1;
				}

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
					fr_strerror_printf("dict_init: %s[%d] \"%s\" type cannot have the "
							   "\"array\" flag set",
							   fn, line,
							   fr_int2str(dict_attr_types, type, "<UNKNOWN>"));
					return -1;
				}

			} else if (strncmp(key, "concat", 7) == 0) {
				flags.concat = 1;

				if (type != PW_TYPE_OCTETS) {
					fr_strerror_printf("dict_init: %s[%d] Only \"octets\" type can have the "
							   "\"concat\" flag set", fn, line);
					return -1;
				}

			} else if (strncmp(key, "virtual", 8) == 0) {
				flags.virtual = 1;

				if (vendor != 0) {
					fr_strerror_printf("dict_init: %s[%d] VSAs cannot have the \"virtual\" "
							   "flag set", fn, line);
					return -1;
				}

				if (value < 256) {
					fr_strerror_printf("dict_init: %s[%d] Standard attributes cannot "
							   "have the \"virtual\" flag set", fn, line);
					return -1;
				}

			/*
			 *	The only thing is the vendor name,
			 *	and it's a known name: allow it.
			 */
			} else if ((key == argv[3]) && !next) {
				if (oid) {
					fr_strerror_printf("dict_init: %s[%d] New-style attributes cannot use "
							   "a vendor flag", fn, line);
					return -1;
				}

				if (block_vendor) {
					fr_strerror_printf("dict_init: %s[%d] Vendor flag inside of \"BEGIN-VENDOR\" "
							   "is not allowed", fn, line);
					return -1;
				}

				vendor = dict_vendorbyname(key);
				if (!vendor) goto unknown;
				break;

			} else {
			unknown:
				fr_strerror_printf("dict_init: %s[%d]: unknown option \"%s\"", fn, line, key);
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
			fr_strerror_printf("dict_init: %s[%d]: Attributes of type %s cannot be tagged.",
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
			DICT_VENDOR *dv;

			dv = dict_vendorbyvalue(vendor);
			if (!dv || (dv->type != 1) || (dv->length != 1)) {
				fr_strerror_printf("dict_init: %s[%d]: Type \"tlv\" can only be for \"format=1,1\".",
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
		if ((value == 0) || ((value & ~fr_attr_mask[tlv_depth]) != 0)) {
			fr_strerror_printf( "dict_init: %s[%d]: sub-tlv has invalid attribute number",
					    fn, line);
			return -1;
		}

		/*
		 *	Shift the value left.
		 */
		value <<= fr_attr_shift[tlv_depth];
		value |= block_tlv->attr;
		flags.is_tlv = 1;
	}

#ifdef WITH_DICTIONARY_WARNINGS
	/*
	 *	Hack to help us discover which vendors have illegal
	 *	attributes.
	 */
	if (!vendor && (value < 256) &&
	    !strstr(fn, "rfc") && !strstr(fn, "illegal")) {
		fprintf(stderr, "WARNING: Illegal Attribute %s in %s\n",
			argv[0], fn);
	}
#endif

	/*
	 *	Add it in.
	 */
	if (dict_addattr(argv[0], value, vendor, type, flags) < 0) {
		char buffer[256];

		strlcpy(buffer, fr_strerror(), sizeof(buffer));

		fr_strerror_printf("dict_init: %s[%d]: %s",
				   fn, line, buffer);
		return -1;
	}

	return 0;
}


/*
 *	Process the VALUE command
 */
static int process_value(char const* fn, int const line, char **argv,
			 int argc)
{
	unsigned int	value;

	if (argc != 3) {
		fr_strerror_printf("dict_init: %s[%d]: invalid VALUE line",
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
		fr_strerror_printf("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}

	if (dict_addvalue(argv[1], argv[0], value) < 0) {
		char buffer[256];

		strlcpy(buffer, fr_strerror(), sizeof(buffer));

		fr_strerror_printf("dict_init: %s[%d]: %s",
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
static int process_value_alias(char const* fn, int const line, char **argv,
			       int argc)
{
	DICT_ATTR const *my_da, *da;
	DICT_VALUE *dval;

	if (argc != 2) {
		fr_strerror_printf("dict_init: %s[%d]: invalid VALUE-ALIAS line",
			fn, line);
		return -1;
	}

	my_da = dict_attrbyname(argv[0]);
	if (!my_da) {
		fr_strerror_printf("dict_init: %s[%d]: ATTRIBUTE \"%s\" does not exist",
			   fn, line, argv[1]);
		return -1;
	}

	if (my_da->flags.has_value_alias) {
		fr_strerror_printf("dict_init: %s[%d]: Cannot add VALUE-ALIAS to ATTRIBUTE \"%s\" with pre-existing VALUE-ALIAS",
			   fn, line, argv[0]);
		return -1;
	}

	da = dict_attrbyname(argv[1]);
	if (!da) {
		fr_strerror_printf("dict_init: %s[%d]: Cannot find ATTRIBUTE \"%s\" for alias",
			   fn, line, argv[1]);
		return -1;
	}

	if (da->flags.has_value_alias) {
		fr_strerror_printf("dict_init: %s[%d]: Cannot add VALUE-ALIAS to ATTRIBUTE \"%s\" which itself has a VALUE-ALIAS",
			   fn, line, argv[1]);
		return -1;
	}

	if (my_da->type != da->type) {
		fr_strerror_printf("dict_init: %s[%d]: Cannot add VALUE-ALIAS between attributes of differing type",
			   fn, line);
		return -1;
	}

	if ((dval = fr_pool_alloc(sizeof(*dval))) == NULL) {
		fr_strerror_printf("dict_addvalue: out of memory");
		return -1;
	}

	dval->name[0] = '\0';	/* empty name */
	dval->attr = my_da->attr;
	dval->vendor = my_da->vendor;
	dval->value = da->attr;

	if (!fr_hash_table_insert(values_byname, dval)) {
		fr_strerror_printf("dict_init: %s[%d]: Error create alias",
			   fn, line);
		fr_pool_free(dval);
		return -1;
	}

	return 0;
}


static int parse_format(char const *fn, int line, char const *format, int *pvalue, int *ptype, int *plength, bool *pcontinuation)
{
	char const *p;
	int type, length;
	bool continuation = false;

	if (strncasecmp(format, "format=", 7) != 0) {
		fr_strerror_printf("dict_init: %s[%d]: Invalid format for VENDOR.  Expected \"format=\", got \"%s\"",
				   fn, line, format);
		return -1;
	}

	p = format + 7;
	if ((strlen(p) < 3) ||
	    !isdigit((int) p[0]) ||
	    (p[1] != ',') ||
	    !isdigit((int) p[2]) ||
	    (p[3] && (p[3] != ','))) {
		fr_strerror_printf("dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
				   fn, line, p);
		return -1;
	}

	type = (int) (p[0] - '0');
	length = (int) (p[2] - '0');

	if ((type != 1) && (type != 2) && (type != 4)) {
		fr_strerror_printf("dict_init: %s[%d]: invalid type value %d for VENDOR",
				   fn, line, type);
		return -1;
	}

	if ((length != 0) && (length != 1) && (length != 2)) {
		fr_strerror_printf("dict_init: %s[%d]: invalid length value %d for VENDOR",
				   fn, line, length);
		return -1;
	}

	if (p[3] == ',') {
		if (!p[4]) {
			fr_strerror_printf("dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
					   fn, line, p);
			return -1;
		}

		if ((p[4] != 'c') ||
		    (p[5] != '\0')) {
			fr_strerror_printf("dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
					   fn, line, p);
			return -1;
		}
		continuation = true;

		if ((*pvalue != VENDORPEC_WIMAX) ||
		    (type != 1) || (length != 1)) {
			fr_strerror_printf("dict_init: %s[%d]: Only WiMAX VSAs can have continuations",
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
static int process_vendor(char const* fn, int const line, char **argv,
			  int argc)
{
	int		value;
	int		type, length;
	bool		continuation = false;
	DICT_VENDOR	*dv;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_printf( "dict_init: %s[%d] invalid VENDOR entry",
			    fn, line);
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!isdigit((int) argv[1][0])) {
		fr_strerror_printf("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}
	value = atoi(argv[1]);

	/* Create a new VENDOR entry for the list */
	if (dict_addvendor(argv[0], value) < 0) {
		char buffer[256];

		strlcpy(buffer, fr_strerror(), sizeof(buffer));

		fr_strerror_printf("dict_init: %s[%d]: %s",
			   fn, line, buffer);
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

	dv = dict_vendorbyvalue(value);
	if (!dv) {
		fr_strerror_printf("dict_init: %s[%d]: Failed adding format for VENDOR",
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
int str2argv(char *str, char **argv, int max_argc)
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
		       (*str == '\n')) *(str++) = '\0';

		if (!*str) break;

		argv[argc] = str;
		argc++;

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n')) str++;
	}

	return argc;
}

static int my_dict_init(char const *parent, char const *filename,
			char const *src_file, int src_line);

int dict_read(char const *dir, char const *filename)
{
	if (!attributes_byname) {
		fr_strerror_printf("Must call dict_init() before dict_read()");
		return -1;
	}

	return my_dict_init(dir, filename, NULL, 0);
}


#define MAX_ARGV (16)

/*
 *	Initialize the dictionary.
 */
static int my_dict_init(char const *parent, char const *filename,
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
	DICT_ATTR const *da, *block_tlv[MAX_TLV_NEST + 1];
	int	which_block_tlv = 0;

	block_tlv[0] = NULL;
	block_tlv[1] = NULL;
	block_tlv[2] = NULL;
	block_tlv[3] = NULL;

	if ((strlen(parent) + 3 + strlen(filename)) > sizeof(dir)) {
		fr_strerror_printf("dict_init: filename name too long");
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
			fr_strerror_printf("dict_init: Couldn't open dictionary \"%s\": %s",
				   fn, fr_syserror(errno));
		} else {
			fr_strerror_printf("dict_init: %s[%d]: Couldn't open dictionary \"%s\": %s",
				   src_file, src_line, fn, fr_syserror(errno));
		}
		return -2;
	}

	stat(fn, &statbuf); /* fopen() guarantees this will succeed */
	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fp);
		fr_strerror_printf("dict_init: Dictionary \"%s\" is not a regular file",
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
		fr_strerror_printf("dict_init: Dictionary \"%s\" is globally writable.  Refusing to start due to insecure configuration.",
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

		argc = str2argv(buf, argv, MAX_ARGV);
		if (argc == 0) continue;

		if (argc == 1) {
			fr_strerror_printf( "dict_init: %s[%d] invalid entry",
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
			if (process_attribute(fn, line, block_vendor,
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
			if (my_dict_init(dir, argv[1], fn, line) < 0) {
				fclose(fp);
				return -1;
			}
			continue;
		} /* $INCLUDE */

		/*
		 *	Optionally include a dictionary
		 */
		if (strcasecmp(argv[0], "$INCLUDE-") == 0) {
			int rcode = my_dict_init(dir, argv[1], fn, line);

			if (rcode == -2) continue;

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
				"dict_init: %s[%d] invalid BEGIN-TLV entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			da = dict_attrbyname(argv[1]);
			if (!da) {
				fr_strerror_printf(
					"dict_init: %s[%d]: unknown attribute %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (da->type != PW_TYPE_TLV) {
				fr_strerror_printf(
					"dict_init: %s[%d]: attribute %s is not of type tlv",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (which_block_tlv >= MAX_TLV_NEST) {
				fr_strerror_printf(
					"dict_init: %s[%d]: TLVs are nested too deep",
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
				"dict_init: %s[%d] invalid END-TLV entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			da = dict_attrbyname(argv[1]);
			if (!da) {
				fr_strerror_printf(
					"dict_init: %s[%d]: unknown attribute %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (da != block_tlv[which_block_tlv]) {
				fr_strerror_printf(
					"dict_init: %s[%d]: END-TLV %s does not match any previous BEGIN-TLV",
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
				"dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(argv[1]);
			if (!vendor) {
				fr_strerror_printf(
					"dict_init: %s[%d]: unknown vendor %s",
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
						"dict_init: %s[%d]: Invalid format %s",
						fn, line, argv[2]);
					fclose(fp);
					return -1;
				}

				p = argv[2] + 7;
				da = dict_attrbyname(p);
				if (!da) {
					fr_strerror_printf("dict_init: %s[%d]: Invalid format for BEGIN-VENDOR: unknown attribute \"%s\"",
							   fn, line, p);
					fclose(fp);
					return -1;
				}

				if (!da->flags.evs) {
					fr_strerror_printf("dict_init: %s[%d]: Invalid format for BEGIN-VENDOR.  Attribute \"%s\" is not of \"evs\" data type",
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
				"dict_init: %s[%d] invalid END-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(argv[1]);
			if (!vendor) {
				fr_strerror_printf(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (vendor != (block_vendor & (FR_MAX_VENDOR - 1))) {
				fr_strerror_printf(
					"dict_init: %s[%d]: END-VENDOR %s does not match any previous BEGIN-VENDOR",
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
		fr_strerror_printf("dict_init: %s[%d] invalid keyword \"%s\"",
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


/*
 *	Initialize the directory, then fix the attr member of
 *	all attributes.
 */
int dict_init(char const *dir, char const *fn)
{
	/*
	 *	Check if we need to change anything.  If not, don't do
	 *	anything.
	 */
	if (dict_stat_check(dir, fn)) {
		return 0;
	}

	/*
	 *	Free the dictionaries, and the stat cache.
	 */
	dict_free();

	/*
	 *	Create the table of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 *
	 *	Each vendor is malloc'd, so the free function is free.
	 */
	vendors_byname = fr_hash_table_create(dict_vendor_name_hash,
						dict_vendor_name_cmp,
						fr_pool_free);
	if (!vendors_byname) {
		return -1;
	}

	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	vendors_byvalue = fr_hash_table_create(dict_vendor_value_hash,
						 dict_vendor_value_cmp,
						 fr_pool_free);
	if (!vendors_byvalue) {
		return -1;
	}

	/*
	 *	Create the table of attributes by name.   There MAY NOT
	 *	be multiple attributes of the same name.
	 *
	 *	Each attribute is malloc'd, so the free function is free.
	 */
	attributes_byname = fr_hash_table_create(dict_attr_name_hash,
						   dict_attr_name_cmp,
						   fr_pool_free);
	if (!attributes_byname) {
		return -1;
	}

	/*
	 *	Create the table of attributes by value.  There MAY
	 *	be attributes of the same value.  If there are, we
	 *	pick the latest one.
	 */
	attributes_byvalue = fr_hash_table_create(dict_attr_value_hash,
						    dict_attr_value_cmp,
						    fr_pool_free);
	if (!attributes_byvalue) {
		return -1;
	}

	/*
	 *	Horrible hacks for combo-IP.
	 */
	attributes_combo = fr_hash_table_create(dict_attr_combo_hash,
						dict_attr_combo_cmp,
						fr_pool_free);
	if (!attributes_combo) {
		return -1;
	}

	values_byname = fr_hash_table_create(dict_value_name_hash,
					       dict_value_name_cmp,
					       fr_pool_free);
	if (!values_byname) {
		return -1;
	}

	values_byvalue = fr_hash_table_create(dict_value_value_hash,
						dict_value_value_cmp,
						fr_pool_free);
	if (!values_byvalue) {
		return -1;
	}

	value_fixup = NULL;	/* just to be safe. */

	if (my_dict_init(dir, fn, NULL, 0) < 0)
		return -1;

	if (value_fixup) {
		DICT_ATTR const *a;
		value_fixup_t *this, *next;

		for (this = value_fixup; this != NULL; this = next) {
			next = this->next;

			a = dict_attrbyname(this->attrstr);
			if (!a) {
				fr_strerror_printf(
					"dict_init: No ATTRIBUTE \"%s\" defined for VALUE \"%s\"",
					this->attrstr, this->dval->name);
				return -1; /* leak, but they should die... */
			}

			this->dval->attr = a->attr;

			/*
			 *	Add the value into the dictionary.
			 */
			if (!fr_hash_table_replace(values_byname,
						     this->dval)) {
				fr_strerror_printf("dict_addvalue: Duplicate value name %s for attribute %s", this->dval->name, a->name);
				return -1;
			}

			/*
			 *	Allow them to use the old name, but
			 *	prefer the new name when printing
			 *	values.
			 */
			if (!fr_hash_table_finddata(values_byvalue, this->dval)) {
				fr_hash_table_replace(values_byvalue,
							this->dval);
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
	fr_hash_table_walk(vendors_byname, null_callback, NULL);
	fr_hash_table_walk(vendors_byvalue, null_callback, NULL);

	fr_hash_table_walk(attributes_byname, null_callback, NULL);
	fr_hash_table_walk(attributes_byvalue, null_callback, NULL);

	fr_hash_table_walk(values_byvalue, null_callback, NULL);
	fr_hash_table_walk(values_byname, null_callback, NULL);

	return 0;
}

static size_t print_attr_oid(char *buffer, size_t size, unsigned int attr,
			     int dv_type)
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
void dict_attr_free(DICT_ATTR const **da)
{
	DICT_ATTR **tmp;

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
 * @param[in,out] da struct to initialise, must be at least DICT_ATTR_SIZE bytes.
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return 0 on success.
 */
int dict_unknown_from_fields(DICT_ATTR *da, unsigned int attr, unsigned int vendor)
{
	char *p;
	int dv_type = 1;
	size_t len = 0;
	size_t bufsize = DICT_ATTR_MAX_NAME_LEN;

	memset(da, 0, DICT_ATTR_SIZE);

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
		DICT_VENDOR *dv;

		/*
		 *	dv_type is the length of the vendor's type field
		 *	RFC 2865 never defined a mandatory length, so
		 *	different vendors have different length type fields.
		 */
		dv = dict_vendorbyvalue(vendor);
		if (dv) {
			dv_type = dv->type;
		}
		len = snprintf(p, bufsize, "26.%u.", vendor);

		p += len;
		bufsize -= len;
	}

	print_attr_oid(p, bufsize , attr, dv_type);

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
DICT_ATTR const *dict_unknown_afrom_fields(TALLOC_CTX *ctx, unsigned int attr, unsigned int vendor)
{
	uint8_t *p;
	DICT_ATTR *da;

	p = talloc_zero_array(ctx, uint8_t, DICT_ATTR_SIZE);
	if (!p) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	da = (DICT_ATTR *) p;
	talloc_set_type(da, DICT_ATTR);

	if (dict_unknown_from_fields(da, attr, vendor) < 0) {
		talloc_free(p);
		return NULL;
	}

	return da;
}

/** Create a DICT_ATTR from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @param[in] da to initialise.
 * @param[in] name of attribute.
 * @return 0 on success -1 on failure.
 */
int dict_unknown_from_str(DICT_ATTR *da, char const *name)
{
	unsigned int   	attr = 0, vendor = 0;

	char const	*p = name;
	char		*q;

	if (dict_valid_name(name) < 0) return -1;

	/*
	 *	Pull off vendor prefix first.
	 */
	if (strncasecmp(p, "Attr-", 5) != 0) {
		if (strncasecmp(p, "Vendor-", 7) == 0) {
			vendor = (int) strtol(p + 7, &q, 10);
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

			if ((size_t) (q - p) >= sizeof(buffer)) {
				fr_strerror_printf("Vendor name too long in attribute name \"%s\"", name);

				return -1;
			}

			memcpy(buffer, p, (q - p));
			buffer[q - p] = '\0';

			vendor = dict_vendorbyname(buffer);
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

	/*
	 *	Parse the OID, with a (possibly) pre-defined vendor.
	 */
	if (dict_str2oid(p + 5, &attr, &vendor, 0) < 0) {
		return -1;
	}

	return dict_unknown_from_fields(da, attr, vendor);
}

/** Create a DICT_ATTR from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @param[in] ctx to alloc new attribute in.
 * @param[in] name of attribute.
 * @return 0 on success -1 on failure.
 */
DICT_ATTR const *dict_unknown_afrom_str(TALLOC_CTX *ctx, char const *name)
{
	uint8_t *p;
	DICT_ATTR *da;

	p = talloc_zero_array(ctx, uint8_t, DICT_ATTR_SIZE);
	if (!p) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	da = (DICT_ATTR *) p;
	talloc_set_type(da, DICT_ATTR);

	if (dict_unknown_from_str(da, name) < 0) {
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
 * @return 0 on success or -1 on error;
 */
int dict_unknown_from_substr(DICT_ATTR *da, char const **name)
{
	char const *p;
	size_t len;
	char buffer[DICT_ATTR_MAX_NAME_LEN + 1];

	if (!name || !*name) return -1;

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = *name; dict_attr_allowed_chars[(int) *p] || (*p == '.' ) || (*p == '-'); p++);

	len = p - *name;
	if (len > DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");

		return -1;
	}
	if (len == 0) {
		fr_strerror_printf("Invalid attribute name");
		return -1;
	}
	strlcpy(buffer, *name, len + 1);

	if (dict_unknown_from_str(da, buffer) < 0) return -1;

	*name = p;

	return 0;
}

/*
 *	Get an attribute by its numerical value.
 */
DICT_ATTR const *dict_attrbyvalue(unsigned int attr, unsigned int vendor)
{
	DICT_ATTR da;

	if ((attr > 0) && (attr < 256) && !vendor) return dict_base_attrs[attr];

	da.attr = attr;
	da.vendor = vendor;

	return fr_hash_table_finddata(attributes_byvalue, &da);
}


/** Get an attribute by its numerical value and data type
 *
 * Used only for COMBO_IP
 *
 * @return The attribute, or NULL if not found
 */
DICT_ATTR const *dict_attrbytype(unsigned int attr, unsigned int vendor,
				 PW_TYPE type)
{
	DICT_ATTR da;

	da.attr = attr;
	da.vendor = vendor;
	da.type = type;

	return fr_hash_table_finddata(attributes_combo, &da);
}

/** Using a parent and attr/vendor, find a child attr/vendor
 *
 */
int dict_attr_child(DICT_ATTR const *parent,
		    unsigned int *pattr, unsigned int *pvendor)
{
	unsigned int attr, vendor;
	DICT_ATTR da;

	if (!parent || !pattr || !pvendor) return false;

	attr = *pattr;
	vendor = *pvendor;

	/*
	 *	Only some types can have children
	 */
	switch (parent->type) {
	default: return false;

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

	*pattr = da.attr;
	*pvendor = da.vendor;
	return true;
}

/*
 *	Get an attribute by it's numerical value, and the parent
 */
DICT_ATTR const *dict_attrbyparent(DICT_ATTR const *parent, unsigned int attr, unsigned int vendor)
{
	unsigned int my_attr, my_vendor;
	DICT_ATTR da;

	my_attr = attr;
	my_vendor = vendor;

	if (!dict_attr_child(parent, &my_attr, &my_vendor)) return NULL;

	da.attr = my_attr;
	da.vendor = my_vendor;

	return fr_hash_table_finddata(attributes_byvalue, &da);
}


/*
 *	Get an attribute by its name.
 */
DICT_ATTR const *dict_attrbyname(char const *name)
{
	DICT_ATTR *da;
	uint32_t buffer[(sizeof(*da) + DICT_ATTR_MAX_NAME_LEN + 3)/4];

	if (!name) return NULL;

	da = (DICT_ATTR *) buffer;
	strlcpy(da->name, name, DICT_ATTR_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(attributes_byname, da);
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
 * @return NULL if no attributes matching the name could be found, else
 */
DICT_ATTR const *dict_attrbyname_substr(char const **name)
{
	DICT_ATTR *find;
	DICT_ATTR const *da;
	char const *p;
	size_t len;
	uint32_t buffer[(sizeof(*find) + DICT_ATTR_MAX_NAME_LEN + 3)/4];

	if (!name || !*name) return NULL;

	find = (DICT_ATTR *) buffer;

	/*
	 *	Advance p until we get something that's not part of
	 *	the dictionary attribute name.
	 */
	for (p = *name; dict_attr_allowed_chars[(int) *p]; p++);

	len = p - *name;
	if (len > DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name too long");

		return NULL;
	}
	strlcpy(find->name, *name, len + 1);

	da = fr_hash_table_finddata(attributes_byname, find);
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
DICT_VALUE *dict_valbyattr(unsigned int attr, unsigned int vendor, int value)
{
	DICT_VALUE dval, *dv;

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
	dv = fr_hash_table_finddata(values_byname, &dval);
	if (dv)	dval.attr = dv->value;

	dval.value = value;

	return fr_hash_table_finddata(values_byvalue, &dval);
}

/*
 *	Associate a value with an attribute and return it.
 */
char const *dict_valnamebyattr(unsigned int attr, unsigned int vendor, int value)
{
	DICT_VALUE *dv;

	dv = dict_valbyattr(attr, vendor, value);
	if (!dv) return "";

	return dv->name;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
DICT_VALUE *dict_valbyname(unsigned int attr, unsigned int vendor, char const *name)
{
	DICT_VALUE *my_dv, *dv;
	uint32_t buffer[(sizeof(*my_dv) + DICT_VALUE_MAX_NAME_LEN + 3)/4];

	if (!name) return NULL;

	my_dv = (DICT_VALUE *) buffer;
	my_dv->attr = attr;
	my_dv->vendor = vendor;
	my_dv->name[0] = '\0';

	/*
	 *	Look up the attribute alias target, and use
	 *	the correct attribute number if found.
	 */
	dv = fr_hash_table_finddata(values_byname, my_dv);
	if (dv) my_dv->attr = dv->value;

	strlcpy(my_dv->name, name, DICT_VALUE_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(values_byname, my_dv);
}

/*
 *	Get the vendor PEC based on the vendor name
 *
 *	This is efficient only for small numbers of vendors.
 */
int dict_vendorbyname(char const *name)
{
	DICT_VENDOR *dv;
	size_t buffer[(sizeof(*dv) + DICT_VENDOR_MAX_NAME_LEN + sizeof(size_t) - 1) / sizeof(size_t)];

	if (!name) return 0;

	dv = (DICT_VENDOR *) buffer;
	strlcpy(dv->name, name, DICT_VENDOR_MAX_NAME_LEN + 1);

	dv = fr_hash_table_finddata(vendors_byname, dv);
	if (!dv) return 0;

	return dv->vendorpec;
}

/*
 *	Return the vendor struct based on the PEC.
 */
DICT_VENDOR *dict_vendorbyvalue(int vendorpec)
{
	DICT_VENDOR dv;

	dv.vendorpec = vendorpec;

	return fr_hash_table_finddata(vendors_byvalue, &dv);
}

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old DICT_ATTR, that is left up to the caller.
 *
 * @param old unknown attribute to add.
 * @return existing DICT_ATTR if old was found in a dictionary, else the new entry in the dictionary
 * 	   representing old.
 */
DICT_ATTR const *dict_unknown_add(DICT_ATTR const *old)
{
	DICT_ATTR const *da, *parent;
	ATTR_FLAGS flags;

	if (!old) return NULL;

	if (!old->flags.is_unknown) return old;

	da = dict_attrbyvalue(old->attr, old->vendor);
	if (da) return da;

	memcpy(&flags, &old->flags, sizeof(flags));
	flags.is_unknown = false;

	parent = dict_parent(old->attr, old->vendor);
	if (parent) {
		if (parent->flags.has_tlv) flags.is_tlv = true;
		flags.evs = parent->flags.evs;
		flags.extended = parent->flags.extended;
		flags.long_extended = parent->flags.long_extended;
	}

	if (dict_addattr(old->name, old->attr, old->vendor, old->type, flags) < 0) {
		return NULL;
	}

	da = dict_attrbyvalue(old->attr, old->vendor);
	return da;
}
