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

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#include	<ctype.h>

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include	<sys/stat.h>
#endif

#define DICT_VALUE_MAX_NAME_LEN (128)
#define DICT_VENDOR_MAX_NAME_LEN (128)
#define DICT_ATTR_MAX_NAME_LEN (128)

static fr_hash_table_t *vendors_byname = NULL;
static fr_hash_table_t *vendors_byvalue = NULL;

static fr_hash_table_t *attributes_byname = NULL;
static fr_hash_table_t *attributes_byvalue = NULL;

static fr_hash_table_t *values_byvalue = NULL;
static fr_hash_table_t *values_byname = NULL;

static DICT_ATTR *dict_base_attrs[256];

/*
 *	For faster HUP's, we cache the stat information for
 *	files we've $INCLUDEd
 */
typedef struct dict_stat_t {
	struct dict_stat_t *next;
	char	   	   *name;
	time_t		   mtime;
} dict_stat_t;

static char *stat_root_dir = NULL;
static char *stat_root_file = NULL;

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

static const FR_NAME_NUMBER type_table[] = {
	{ "integer",	PW_TYPE_INTEGER },
	{ "string",	PW_TYPE_STRING },
	{ "ipaddr",	PW_TYPE_IPADDR },
	{ "date",	PW_TYPE_DATE },
	{ "abinary",	PW_TYPE_ABINARY },
	{ "octets",	PW_TYPE_OCTETS },
	{ "ifid",	PW_TYPE_IFID },
	{ "ipv6addr",	PW_TYPE_IPV6ADDR },
	{ "ipv6prefix", PW_TYPE_IPV6PREFIX },
	{ "byte",	PW_TYPE_BYTE },
	{ "short",	PW_TYPE_SHORT },
	{ "ether",	PW_TYPE_ETHERNET },
	{ "combo-ip",	PW_TYPE_COMBO_IP },
	{ "tlv",	PW_TYPE_TLV },
	{ "signed",	PW_TYPE_SIGNED },
	{ NULL, 0 }
};


/*
 *	Create the hash of the name.
 *
 *	We copy the hash function here because it's substantially faster.
 */
#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

static uint32_t dict_hashname(const char *name)
{
	uint32_t hash = FNV_MAGIC_INIT;
	const char *p;

	for (p = name; *p != '\0'; p++) {
		int c = *(const unsigned char *) p;
		if (isalpha(c)) c = tolower(c);

		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t ) (c & 0xff);
	}

	return hash;
}


/*
 *	Hash callback functions.
 */
static uint32_t dict_attr_name_hash(const void *data)
{
	return dict_hashname(((const DICT_ATTR *)data)->name);
}

static int dict_attr_name_cmp(const void *one, const void *two)
{
	const DICT_ATTR *a = one;
	const DICT_ATTR *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_attr_value_hash(const void *data)
{
	uint32_t hash;
	const DICT_ATTR *attr = data;

	hash = fr_hash(&attr->vendor, sizeof(attr->vendor));
	return fr_hash_update(&attr->attr, sizeof(attr->attr), hash);
}

static int dict_attr_value_cmp(const void *one, const void *two)
{
	const DICT_ATTR *a = one;
	const DICT_ATTR *b = two;

	if (a->vendor < b->vendor) return -1;
	if (a->vendor > b->vendor) return +1;

	return a->attr - b->attr;
}

static uint32_t dict_vendor_name_hash(const void *data)
{
	return dict_hashname(((const DICT_VENDOR *)data)->name);
}

static int dict_vendor_name_cmp(const void *one, const void *two)
{
	const DICT_VENDOR *a = one;
	const DICT_VENDOR *b = two;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_vendor_value_hash(const void *data)
{
	return fr_hash(&(((const DICT_VENDOR *)data)->vendorpec),
			 sizeof(((const DICT_VENDOR *)data)->vendorpec));
}

static int dict_vendor_value_cmp(const void *one, const void *two)
{
	const DICT_VENDOR *a = one;
	const DICT_VENDOR *b = two;

	return a->vendorpec - b->vendorpec;
}

static uint32_t dict_value_name_hash(const void *data)
{
	uint32_t hash;
	const DICT_VALUE *dval = data;

	hash = dict_hashname(dval->name);
	return fr_hash_update(&dval->attr, sizeof(dval->attr), hash);
}

static int dict_value_name_cmp(const void *one, const void *two)
{
	int rcode;
	const DICT_VALUE *a = one;
	const DICT_VALUE *b = two;

	rcode = a->attr - b->attr;
	if (rcode != 0) return rcode;

	return strcasecmp(a->name, b->name);
}

static uint32_t dict_value_value_hash(const void *data)
{
	uint32_t hash;
	const DICT_VALUE *dval = data;

	hash = fr_hash(&dval->attr, sizeof(dval->attr));
	return fr_hash_update(&dval->value, sizeof(dval->value), hash);
}

static int dict_value_value_cmp(const void *one, const void *two)
{
	int rcode;
	const DICT_VALUE *a = one;
	const DICT_VALUE *b = two;

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

	free(stat_root_dir);
	stat_root_dir = NULL;
	free(stat_root_file);
	stat_root_file = NULL;

	if (!stat_head) {
		stat_tail = NULL;
		return;
	}

	for (this = stat_head; this != NULL; this = next) {
		next = this->next;
		free(this->name);
		free(this);
	}

	stat_head = stat_tail = NULL;
}


/*
 *	Add an entry to the list of stat buffers.
 */
static void dict_stat_add(const char *name, const struct stat *stat_buf)
{
	dict_stat_t *this;

	this = malloc(sizeof(*this));
	if (!this) return;
	memset(this, 0, sizeof(*this));

	this->name = strdup(name);
	this->mtime = stat_buf->st_mtime;

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
static int dict_stat_check(const char *root_dir, const char *root_file)
{
	struct stat buf;
	dict_stat_t *this;

	if (!stat_root_dir) return 0;
	if (!stat_root_file) return 0;

	if (strcmp(root_dir, stat_root_dir) != 0) return 0;
	if (strcmp(root_file, stat_root_file) != 0) return 0;

	if (!stat_head) return 0; /* changed, reload */

	for (this = stat_head; this != NULL; this = this->next) {
		if (stat(this->name, &buf) < 0) return 0;

		if (buf.st_mtime != this->mtime) return 0;
	}

	return 1;
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
	attributes_byname = NULL;
	attributes_byvalue = NULL;

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
int dict_addvendor(const char *name, int value)
{
	size_t length;
	DICT_VENDOR *dv;

	if (value > 65535) {
	       	fr_strerror_printf("dict_addvendor: Cannot handle vendor ID larger than 65535");
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

/*
 *	Add an attribute to the dictionary.
 */
int dict_addattr(const char *name, int vendor, int type, int value,
		 ATTR_FLAGS flags)
{
	size_t namelen;
	static int      max_attr = 0;
	const char	*p;
	DICT_ATTR	*attr;

	namelen = strlen(name);
	if (namelen >= DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("dict_addattr: attribute name too long");
		return -1;
	}

	for (p = name; *p != '\0'; p++) {
		if (*p < ' ') {
			fr_strerror_printf("dict_addattr: attribute name cannot contain control characters");
			return -1;
		}

		if ((*p == '"') || (*p == '\\')) {
			fr_strerror_printf("dict_addattr: attribute name cannot contain quotation or backslash");
			return -1;
		}

		if ((*p == '<') || (*p == '>') || (*p == '&')) {
			fr_strerror_printf("dict_addattr: attribute name cannot contain XML control characters");
			return -1;
		}
	}

	/*
	 *	If the value is '-1', that means use a pre-existing
	 *	one (if it already exists).  If one does NOT already exist,
	 *	then create a new attribute, with a non-conflicting value,
	 *	and use that.
	 */
	if (value == -1) {
		if (dict_attrbyname(name)) {
			return 0; /* exists, don't add it again */
		}

		value = ++max_attr;

	} else if (vendor == 0) {
		/*
		 *  Update 'max_attr'
		 */
		if (value > max_attr) {
			max_attr = value;
		}
	}

	if (value < 0) {
		fr_strerror_printf("dict_addattr: ATTRIBUTE has invalid number (less than zero)");
		return -1;
	}

	if (value >= 65536) {
		fr_strerror_printf("dict_addattr: ATTRIBUTE has invalid number (larger than 65535).");
		return -1;
	}

	if (vendor) {
		DICT_VENDOR *dv;
		static DICT_VENDOR *last_vendor = NULL;

		if (flags.is_tlv && (flags.encrypt != FLAG_ENCRYPT_NONE)) {
			fr_strerror_printf("Sub-TLV's cannot be encrypted");
			return -1;
		}

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
		if (last_vendor && (vendor == last_vendor->vendorpec)) {
			dv = last_vendor;
		} else {
			dv = dict_vendorbyvalue(vendor);
			last_vendor = dv;
		}

		/*
		 *	If the vendor isn't defined, die.
		 */
		if (!dv) {
			fr_strerror_printf("dict_addattr: Unknown vendor");
			return -1;
		}

		/*
		 *	FIXME: Switch over dv->type, and limit things
		 *	properly.
		 */
		if ((dv->type == 1) && (value >= 256) && !flags.is_tlv) {
			fr_strerror_printf("dict_addattr: ATTRIBUTE has invalid number (larger than 255).");
			return -1;
		} /* else 256..65535 are allowed */
	}

	/*
	 *	Create a new attribute for the list
	 */
	if ((attr = fr_pool_alloc(sizeof(*attr) + namelen)) == NULL) {
		fr_strerror_printf("dict_addattr: out of memory");
		return -1;
	}

	memcpy(attr->name, name, namelen);
	attr->name[namelen] = '\0';
	attr->attr = value;
	attr->attr |= (vendor << 16); /* FIXME: hack */
	attr->vendor = vendor;
	attr->type = type;
	attr->flags = flags;
	attr->vendor = vendor;

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!fr_hash_table_insert(attributes_byname, attr)) {
		DICT_ATTR	*a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = fr_hash_table_finddata(attributes_byname, attr);
		if (a && (strcasecmp(a->name, attr->name) == 0)) {
			if (a->attr != attr->attr) {
				fr_strerror_printf("dict_addattr: Duplicate attribute name %s", name);
				fr_pool_free(attr);
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

		if (!fr_hash_table_replace(attributes_byname, attr)) {
			fr_strerror_printf("dict_addattr: Internal error storing attribute %s", name);
			fr_pool_free(attr);
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
	if (!fr_hash_table_replace(attributes_byvalue, attr)) {
		fr_strerror_printf("dict_addattr: Failed inserting attribute name %s", name);
		return -1;
	}

	if (!vendor && (value > 0) && (value < 256)) {
	 	 dict_base_attrs[value] = attr;
	}

	return 0;
}


/*
 *	Add a value for an attribute to the dictionary.
 */
int dict_addvalue(const char *namestr, const char *attrstr, int value)
{
	size_t		length;
	DICT_ATTR	*dattr;
	DICT_VALUE	*dval;

	static DICT_ATTR *last_attr = NULL;

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
		dattr = last_attr;
	} else {
		dattr = dict_attrbyname(attrstr);
		last_attr = dattr;
	}

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	if (dattr) {
		if (dattr->flags.has_value_alias) {
			fr_strerror_printf("dict_addvalue: Cannot add VALUE for ATTRIBUTE \"%s\": It already has a VALUE-ALIAS", attrstr);
			return -1;
		}

		dval->attr = dattr->attr;

		/*
		 *	Enforce valid values
		 *
		 *	Don't worry about fixups...
		 */
		switch (dattr->type) {
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

			default:
				fr_pool_free(dval);
				fr_strerror_printf("dict_addvalue: VALUEs cannot be defined for attributes of type '%s'",
					   fr_int2str(type_table, dattr->type, "?Unknown?"));
				return -1;
		}

		dattr->flags.has_value = 1;
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
	if (!fr_hash_table_insert(values_byname, dval)) {
		if (dattr) {
			DICT_VALUE *old;

			/*
			 *	Suppress duplicates with the same
			 *	name and value.  There are lots in
			 *	dictionary.ascend.
			 */
			old = dict_valbyname(dattr->attr, namestr);
			if (old && (old->value == dval->value)) {
				fr_pool_free(dval);
				return 0;
			}
		}

		fr_pool_free(dval);
		fr_strerror_printf("dict_addvalue: Duplicate value name %s for attribute %s", namestr, attrstr);
		return -1;
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

static int sscanf_i(const char *str, int *pvalue)
{
	int rcode = 0;
	int base = 10;
	const char *tab = "0123456789";

	if ((str[0] == '0') &&
	    ((str[1] == 'x') || (str[1] == 'X'))) {
		tab = "0123456789abcdef";
		base = 16;

		str += 2;
	}

	while (*str) {
		const char *c;

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
 *	Process the ATTRIBUTE command
 */
static int process_attribute(const char* fn, const int line,
			     const int block_vendor, DICT_ATTR *block_tlv,
			     char **argv, int argc)
{
	int		vendor = 0;
	int		value;
	int		type;
	ATTR_FLAGS	flags;

	if ((argc < 3) || (argc > 4)) {
		fr_strerror_printf("dict_init: %s[%d]: invalid ATTRIBUTE line",
			fn, line);
		return -1;
	}

	/*
	 *	Validate all entries
	 */
	if (!sscanf_i(argv[1], &value)) {
		fr_strerror_printf("dict_init: %s[%d]: invalid value", fn, line);
		return -1;
	}

	/*
	 *	find the type of the attribute.
	 */
	type = fr_str2int(type_table, argv[2], -1);
	if (type < 0) {
		fr_strerror_printf("dict_init: %s[%d]: invalid type \"%s\"",
			fn, line, argv[2]);
		return -1;
	}

	/*
	 *	Only look up the vendor if the string
	 *	is non-empty.
	 */
	memset(&flags, 0, sizeof(flags));
	if (argc == 4) {
		char *key, *next, *last;

		key = argv[3];
		do {
			next = strchr(key, ',');
			if (next) *(next++) = '\0';

			if (strcmp(key, "has_tag") == 0 ||
			    strcmp(key, "has_tag=1") == 0) {
				/* Boolean flag, means this is a
				   tagged attribute */
				flags.has_tag = 1;
				
			} else if (strncmp(key, "encrypt=", 8) == 0) {
				/* Encryption method, defaults to 0 (none).
				   Currently valid is just type 2,
				   Tunnel-Password style, which can only
				   be applied to strings. */
				flags.encrypt = strtol(key + 8, &last, 0);
				if (*last) {
					fr_strerror_printf( "dict_init: %s[%d] invalid option %s",
						    fn, line, key);
					return -1;
				}

				if ((flags.encrypt == FLAG_ENCRYPT_ASCEND_SECRET) &&
				    (type != PW_TYPE_STRING)) {
					fr_strerror_printf( "dict_init: %s[%d] Only \"string\" types can have the \"encrypt=2\" flag set.",
							    fn, line);
					return -1;
				}
				
			} else if (strncmp(key, "array", 8) == 0) {
				flags.array = 1;
				
				switch (type) {
					case PW_TYPE_IPADDR:
					case PW_TYPE_BYTE:
					case PW_TYPE_SHORT:
					case PW_TYPE_INTEGER:
					case PW_TYPE_DATE:
						break;

					default:
						fr_strerror_printf( "dict_init: %s[%d] Only IP addresses can have the \"array\" flag set.",
							    fn, line);
						return -1;
				}

				/*
				 *	The only thing is the vendor name,
				 *	and it's a known name: allow it.
				 */
			} else if ((key == argv[3]) && !next && !block_vendor &&
				   ((vendor = dict_vendorbyname(key)) !=0)) {
				break;

			} else {
				fr_strerror_printf( "dict_init: %s[%d]: unknown option \"%s\"",
					    fn, line, key);
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
				   fr_int2str(type_table, type, "?Unknown?"));
			return -1;

		}
	}

	if (type == PW_TYPE_TLV) {
		flags.has_tlv = 1;
	}

	if (block_tlv) {
		/*
		 *	TLV's can be only one octet.
		 */
		if ((value <= 0) || (value > 255)) {
			fr_strerror_printf( "dict_init: %s[%d]: sub-tlv's cannot have value > 255",
				    fn, line);
			return -1;
		}

		if (flags.encrypt != FLAG_ENCRYPT_NONE) {
			fr_strerror_printf( "dict_init: %s[%d]: sub-tlv's cannot be encrypted",
				    fn, line);
			return -1;
		}

		/*
		 *	
		 */
		value <<= 8;
		value |= (block_tlv->attr & 0xffff);
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
	if (dict_addattr(argv[0], vendor, type, value, flags) < 0) {
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
static int process_value(const char* fn, const int line, char **argv,
			 int argc)
{
	int	value;

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
static int process_value_alias(const char* fn, const int line, char **argv,
			       int argc)
{
	DICT_ATTR *my_da, *da;
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

	if (my_da->flags.has_value) {
		fr_strerror_printf("dict_init: %s[%d]: Cannot add VALUE-ALIAS to ATTRIBUTE \"%s\" with pre-existing VALUE",
			   fn, line, argv[0]);
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

	if (!da->flags.has_value) {
		fr_strerror_printf("dict_init: %s[%d]: VALUE-ALIAS cannot refer to ATTRIBUTE %s: It has no values",
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
	dval->value = da->attr;

	if (!fr_hash_table_insert(values_byname, dval)) {
		fr_strerror_printf("dict_init: %s[%d]: Error create alias",
			   fn, line);
		fr_pool_free(dval);
		return -1;
	}

	return 0;
}


/*
 *	Process the VENDOR command
 */
static int process_vendor(const char* fn, const int line, char **argv,
			  int argc)
{
	int	value;
	int	continuation = 0;
	const	char *format = NULL;

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
	 *	Look for a format statement
	 */
	if (argc == 3) {
		format = argv[2];

	} else if (value == VENDORPEC_USR) { /* catch dictionary screw-ups */
		format = "format=4,0";

	} else if (value == VENDORPEC_LUCENT) {
		format = "format=2,1";

	} else if (value == VENDORPEC_STARENT) {
		format = "format=2,2";

	} /* else no fixups to do */

	if (format) {
		int type, length;
		const char *p;
		DICT_VENDOR *dv;

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

		if (p[3] == ',') {
			if ((p[4] != 'c') ||
			    (p[5] != '\0')) {
				fr_strerror_printf("dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
					   fn, line, p);
				return -1;
			}
			continuation = 1;
		}

		dv = dict_vendorbyvalue(value);
		if (!dv) {
			fr_strerror_printf("dict_init: %s[%d]: Failed adding format for VENDOR",
				   fn, line);
			return -1;
		}

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

		dv->type = type;
		dv->length = length;
		dv->flags = continuation;
	}

	return 0;
}

/*
 *	String split routine.  Splits an input string IN PLACE
 *	into pieces, based on spaces.
 */
static int str2argv(char *str, char **argv, int max_argc)
{
	int argc = 0;

	while (*str) {
		if (argc >= max_argc) return argc;

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

		if (!*str) return argc;

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

#define MAX_ARGV (16)

/*
 *	Initialize the dictionary.
 */
static int my_dict_init(const char *dir, const char *fn,
			const char *src_file, int src_line)
{
	FILE	*fp;
	char 	dirtmp[256];
	char	buf[256];
	char	*p;
	int	line = 0;
	int	vendor;
	int	block_vendor;
	struct stat statbuf;
	char	*argv[MAX_ARGV];
	int	argc;
	DICT_ATTR *da, *block_tlv = NULL;

	if (strlen(fn) >= sizeof(dirtmp) / 2 ||
	    strlen(dir) >= sizeof(dirtmp) / 2) {
		fr_strerror_printf("dict_init: filename name too long");
		return -1;
	}

	/*
	 *	First see if fn is relative to dir. If so, create
	 *	new filename. If not, remember the absolute dir.
	 */
	if ((p = strrchr(fn, FR_DIR_SEP)) != NULL) {
		strcpy(dirtmp, fn);
		dirtmp[p - fn] = 0;
		dir = dirtmp;
	} else if (dir && dir[0] && strcmp(dir, ".") != 0) {
		snprintf(dirtmp, sizeof(dirtmp), "%s/%s", dir, fn);
		fn = dirtmp;
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			fr_strerror_printf("dict_init: Couldn't open dictionary \"%s\": %s",
				   fn, strerror(errno));
		} else {
			fr_strerror_printf("dict_init: %s[%d]: Couldn't open dictionary \"%s\": %s",
				   src_file, src_line, fn, strerror(errno));
		}
		return -1;
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

	dict_stat_add(fn, &statbuf);

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
					      block_tlv,
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

			if (block_tlv) {
				fr_strerror_printf(
					"dict_init: %s[%d]: Cannot nest TLVs",
					fn, line);
				fclose(fp);
				return -1;
			}

			block_tlv = da;
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

			if (da != block_tlv) {
				fr_strerror_printf(
					"dict_init: %s[%d]: END-TLV %s does not match any previous BEGIN-TLV",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}
			block_tlv = NULL;
			continue;
		} /* END-VENDOR */

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			if (argc != 2) {
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

			if (vendor != block_vendor) {
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
static int null_callback(void *ctx, void *data)
{
	ctx = ctx;		/* -Wunused */
	data = data;		/* -Wunused */

	return 0;
}


/*
 *	Initialize the directory, then fix the attr member of
 *	all attributes.
 */
int dict_init(const char *dir, const char *fn)
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
	stat_root_dir = strdup(dir);
	stat_root_file = strdup(fn);

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
		DICT_ATTR *a;
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

/*
 *	Get an attribute by its numerical value.
 */
DICT_ATTR *dict_attrbyvalue(unsigned int attr)
{
	DICT_ATTR dattr;

	if ((attr > 0) && (attr < 256)) return dict_base_attrs[attr];

	dattr.attr = attr;
	dattr.vendor = VENDOR(attr);

	return fr_hash_table_finddata(attributes_byvalue, &dattr);
}

/*
 *	Get an attribute by its name.
 */
DICT_ATTR *dict_attrbyname(const char *name)
{
	DICT_ATTR *da;
	uint32_t buffer[(sizeof(*da) + DICT_ATTR_MAX_NAME_LEN + 3)/4];

	if (!name) return NULL;

	da = (DICT_ATTR *) buffer;
	strlcpy(da->name, name, DICT_ATTR_MAX_NAME_LEN + 1);

	return fr_hash_table_finddata(attributes_byname, da);
}

/*
 *	Associate a value with an attribute and return it.
 */
DICT_VALUE *dict_valbyattr(unsigned int attr, int value)
{
	DICT_VALUE dval, *dv;

	/*
	 *	First, look up aliases.
	 */
	dval.attr = attr;
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
 *	Get a value by its name, keyed off of an attribute.
 */
DICT_VALUE *dict_valbyname(unsigned int attr, const char *name)
{
	DICT_VALUE *my_dv, *dv;
	uint32_t buffer[(sizeof(*my_dv) + DICT_VALUE_MAX_NAME_LEN + 3)/4];

	if (!name) return NULL;

	my_dv = (DICT_VALUE *) buffer;
	my_dv->attr = attr;
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
int dict_vendorbyname(const char *name)
{
	DICT_VENDOR *dv;
	uint32_t buffer[(sizeof(*dv) + DICT_VENDOR_MAX_NAME_LEN + 3)/4];

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
