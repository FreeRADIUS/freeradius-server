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
 * Copyright 2000  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include	<freeradius-devel/autoconf.h>

#include	<stdlib.h>
#include	<ctype.h>
#include	<string.h>

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include	<sys/stat.h>
#endif

#include	<unistd.h>

#include	<freeradius-devel/missing.h>
#include	<freeradius-devel/libradius.h>

#define DICT_VALUE_MAX_NAME_LEN (128)
#define DICT_VENDOR_MAX_NAME_LEN (128)

static lrad_hash_table_t *vendors_byname = NULL;
static lrad_hash_table_t *vendors_byvalue = NULL;

static lrad_hash_table_t *attributes_byname = NULL;
static lrad_hash_table_t *attributes_byvalue = NULL;

static lrad_hash_table_t *values_byvalue = NULL;
static lrad_hash_table_t *values_byname = NULL;

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
	char		attrstr[40];
	DICT_VALUE	*dval;
	struct value_fixup_t *next;
} value_fixup_t;


/*
 *	So VALUEs in the dictionary can have forward references.
 */
static value_fixup_t *value_fixup = NULL;

static const LRAD_NAME_NUMBER type_table[] = {
	{ "string",	PW_TYPE_STRING },
	{ "integer",	PW_TYPE_INTEGER },
	{ "ipaddr",	PW_TYPE_IPADDR },
	{ "date",	PW_TYPE_DATE },
	{ "abinary",	PW_TYPE_ABINARY },
	{ "octets",	PW_TYPE_OCTETS },
	{ "ifid",	PW_TYPE_IFID },
	{ "ipv6addr",	PW_TYPE_IPV6ADDR },
	{ "ipv6prefix", PW_TYPE_IPV6PREFIX },
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

	hash = lrad_hash(&attr->vendor, sizeof(attr->vendor));
	return lrad_hash_update(&attr->attr, sizeof(attr->attr), hash);
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
	return lrad_hash(&(((const DICT_VENDOR *)data)->vendorpec),
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
	return lrad_hash_update(&dval->attr, sizeof(dval->attr), hash);
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

	hash = lrad_hash(&dval->attr, sizeof(dval->attr));
	return lrad_hash_update(&dval->value, sizeof(dval->value), hash);
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


/*
 *	Free the dictionary_attributes and dictionary_values lists.
 */
void dict_free(void)
{
	/*
	 *	Free the tables
	 */
	lrad_hash_table_free(vendors_byname);
	lrad_hash_table_free(vendors_byvalue);
	vendors_byname = NULL;
	vendors_byvalue = NULL;

	lrad_hash_table_free(attributes_byname);
	lrad_hash_table_free(attributes_byvalue);
	attributes_byname = NULL;
	attributes_byvalue = NULL;

	lrad_hash_table_free(values_byname);
	lrad_hash_table_free(values_byvalue);
	values_byname = NULL;
	values_byvalue = NULL;

	dict_stat_free();
}


/*
 *	Add vendor to the list.
 */
int dict_addvendor(const char *name, int value)
{
	size_t length;
	DICT_VENDOR *dv;

	if (value >= 32767) {
	       	librad_log("dict_addvendor: Cannot handle vendor ID larger than 65535");
		return -1;
	}

	if ((length = strlen(name)) >= DICT_VENDOR_MAX_NAME_LEN) {
		librad_log("dict_addvendor: vendor name too long");
		return -1;
	}
	
	if ((dv = malloc(sizeof(*dv) + length)) == NULL) {
		librad_log("dict_addvendor: out of memory");
		return -1;
	}

	strcpy(dv->name, name);
	dv->vendorpec  = value;
	dv->type = dv->length = 1; /* defaults */

	if (!lrad_hash_table_insert(vendors_byname, dv)) {
		DICT_VENDOR *old_dv;

		old_dv = lrad_hash_table_finddata(vendors_byname, dv);
		if (!old_dv) {
			librad_log("dict_addvendor: Failed inserting vendor name %s", name);
			return -1;
		}
		if (old_dv->vendorpec != dv->vendorpec) {
			librad_log("dict_addvendor: Duplicate vendor name %s", name);
			return -1;
		}

		/*
		 *	Already inserted.  Discard the duplicate entry.
		 */
		free(dv);
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
	if (!lrad_hash_table_replace(vendors_byvalue, dv)) {
		librad_log("dict_addvendor: Failed inserting vendor %s",
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
	static int      max_attr = 0;
	DICT_ATTR	*attr;

	if (strlen(name) > (sizeof(attr->name) -1)) {
		librad_log("dict_addattr: attribute name too long");
		return -1;
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
		librad_log("dict_addattr: ATTRIBUTE has invalid number (less than zero)");
		return -1;
	}

	if (value >= 65536) {
		librad_log("dict_addattr: ATTRIBUTE has invalid number (larger than 65535).");
		return -1;
	}

	if (vendor) {
		DICT_VENDOR *dv = dict_vendorbyvalue(vendor);

		/*
		 *	If the vendor isn't defined, die/
		 */
		if (!dv) {
			librad_log("dict_addattr: Unknown vendor");
			return -1;
		}

		/*
		 *	FIXME: Switch over dv->type, and limit things
		 *	properly.
		 */
		if ((dv->type == 1) && (value >= 256)) {
			librad_log("dict_addattr: ATTRIBUTE has invalid number (larger than 255).");
			return -1;
		} /* else 256..65535 are allowed */
	}

	/*
	 *	Create a new attribute for the list
	 */
	if ((attr = malloc(sizeof(*attr))) == NULL) {
		librad_log("dict_addattr: out of memory");
		return -1;
	}

	strcpy(attr->name, name);
	attr->attr = value;
	attr->attr |= (vendor << 16); /* FIXME: hack */
	attr->vendor = vendor;
	attr->type = type;
	attr->flags = flags;
	attr->vendor = vendor;

	/*
	 *	Yet another hack for Diameter-encoded attributes:
	 */
	if (attr->flags.diameter) attr->attr |= (1 << 31);

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (!lrad_hash_table_insert(attributes_byname, attr)) {
		DICT_ATTR	*a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = lrad_hash_table_finddata(attributes_byname, attr);
		if (a && (strcasecmp(a->name, attr->name) == 0)) {
			if (a->attr != attr->attr) {
				librad_log("dict_addattr: Duplicate attribute name %s", name);
				return -1;
			}

			/*
			 *	Same name, same vendor, same attr,
			 *	maybe the flags and/or type is
			 *	different.  Let the new value
			 *	over-ride the old one.
			 */
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
	if (!lrad_hash_table_replace(attributes_byvalue, attr)) {
		librad_log("dict_addattr: Failed inserting attribute name %s", name);
		return -1;
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

	if ((length = strlen(namestr)) >= DICT_VALUE_MAX_NAME_LEN) {
		librad_log("dict_addvalue: value name too long");
		return -1;
	}

	if ((dval = malloc(sizeof(*dval) + length)) == NULL) {
		librad_log("dict_addvalue: out of memory");
		return -1;
	}
	memset(dval, 0, sizeof(*dval));

	strcpy(dval->name, namestr);
	dval->value = value;

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	dattr = dict_attrbyname(attrstr);
	if (dattr) {
		dval->attr = dattr->attr;
	} else {
		value_fixup_t *fixup;
		
		fixup = (value_fixup_t *) malloc(sizeof(*fixup));
		if (!fixup) {
			librad_log("dict_addvalue: out of memory");
			return -1;
		}
		memset(fixup, 0, sizeof(*fixup));

		strNcpy(fixup->attrstr, attrstr, sizeof(fixup->attrstr));
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
	if (!lrad_hash_table_insert(values_byname, dval)) {
		if (dattr) {
			DICT_VALUE *old;
			
			/*
			 *	Suppress duplicates with the same
			 *	name and value.  There are lots in
			 *	dictionary.ascend.
			 */
			old = dict_valbyname(dattr->attr, namestr);
			if (old && (old->value == dval->value)) {
				free(dval);
				return 0;
			}
		}

		librad_log("dict_addvalue: Duplicate value name %s for attribute %s", namestr, attrstr);
		return -1;
	}

	/*
	 *	There are multiple VALUE's, keyed by attribute, so we
	 *	take care of that here.
	 */
	if (!lrad_hash_table_replace(values_byvalue, dval)) {
		librad_log("dict_addvalue: Failed inserting value %s",
			   namestr);
		return -1;
	}

	return 0;
}

/*
 *	Process the ATTRIBUTE command
 */
static int process_attribute(const char* fn, const int line,
			     const int block_vendor, char **argv,
			     int argc)
{
	int		vendor = 0;
	int		value;
	int		type;
	char		*s, *c;
	ATTR_FLAGS	flags;

	if ((argc < 3) || (argc > 4)) {
		librad_log("dict_init: %s[%d]: invalid ATTRIBUTE line",
			fn, line);
		return -1;
	}

	/*
	 *	Validate all entries
	 */
	if (!isdigit((int) argv[1][0])) {
		librad_log("dict_init: %s[%d]: invalid value", fn, line);
		return -1;
	}
	sscanf(argv[1], "%i", &value);

	/*
	 *	find the type of the attribute.
	 */
	type = lrad_str2int(type_table, argv[2], -1);
	if (type < 0) {
		librad_log("dict_init: %s[%d]: invalid type \"%s\"",
			fn, line, argv[2]);
		return -1;
	}

	/*
	 *	Only look up the vendor if the string
	 *	is non-empty.
	 */
	memset(&flags, 0, sizeof(flags));
	if (argc == 4) {
		s = strtok(argv[3], ",");
		while (s) {
			if (strcmp(s, "has_tag") == 0 ||
			    strcmp(s, "has_tag=1") == 0) {
				/* Boolean flag, means this is a
				   tagged attribute */
				flags.has_tag = 1;
				
			} else if (strncmp(s, "encrypt=", 8) == 0) {
				/* Encryption method, defaults to 0 (none).
				   Currently valid is just type 2,
				   Tunnel-Password style, which can only
				   be applied to strings. */
				flags.encrypt = strtol(s + 8, &c, 0);
				if (*c) {
					librad_log( "dict_init: %s[%d] invalid option %s",
						    fn, line, s);
					return -1;
				}
			} else if (strncmp(s, "diameter", 8) == 0) {
				flags.diameter = 1;

			} else {
				/* Must be a vendor 'flag'... */
				if (strncmp(s, "vendor=", 7) == 0) {
					/* New format */
					s += 7;
				}
				
				vendor = dict_vendorbyname(s);
				if (!vendor) {
					librad_log( "dict_init: %s[%d]: unknown vendor %s",
						    fn, line, s);
					return -1;
				}
				if (block_vendor && argv[3][0] &&
				    (block_vendor != vendor)) {
					librad_log("dict_init: %s[%d]: mismatched vendor %s within BEGIN-VENDOR/END-VENDOR block",
						   fn, line, argv[3]);
					return -1;
				}
			}
			s = strtok(NULL, ",");
		}
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
			librad_log("dict_init: %s[%d]: Attributes of type %s cannot be tagged.",
				   fn, line,
				   lrad_int2str(type_table, type, "?Unknown?"));
			return -1;
			
		}
	}

	/*
	 *	Add it in.
	 */
	if (dict_addattr(argv[0], vendor, type, value, flags) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
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
		librad_log("dict_init: %s[%d]: invalid VALUE line",
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
	if (!isdigit((int) argv[2][0])) {
		librad_log("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}
	sscanf(argv[2], "%i", &value);

	if (dict_addvalue(argv[1], argv[0], value) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
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
	const	char *format = NULL;

	if ((argc < 2) || (argc > 3)) {
		librad_log( "dict_init: %s[%d] invalid VENDOR entry",
			    fn, line);
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!isdigit((int) argv[1][0])) {
		librad_log("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}
	value = atoi(argv[1]);

	/* Create a new VENDOR entry for the list */
	if (dict_addvendor(argv[0], value) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
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
			librad_log("dict_init: %s[%d]: Invalid format for VENDOR.  Expected \"format=\", got \"%s\"",
				   fn, line, format);
			return -1;
		}

		p = format + 7;
		if ((strlen(p) != 3) || 
		    !isdigit((int) p[0]) ||
		    (p[1] != ',') ||
		    !isdigit((int) p[2])) {
			librad_log("dict_init: %s[%d]: Invalid format for VENDOR.  Expected text like \"1,1\", got \"%s\"",
				   fn, line, p);
			return -1;
		}

		type = (int) (p[0] - '0');
		length = (int) (p[2] - '0');

		dv = dict_vendorbyvalue(value);
		if (!dv) {
			librad_log("dict_init: %s[%d]: Failed adding format for VENDOR",
				   fn, line);
			return -1;
		}

		if ((type != 1) && (type != 2) && (type != 4)) {
			librad_log("dict_init: %s[%d]: invalid type value %d for VENDOR",
				   fn, line, type);
			return -1;
		}

		if ((length != 0) && (length != 1) && (length != 2)) {
			librad_log("dict_init: %s[%d]: invalid length value %d for VENDOR",
				   fn, line, length);
			return -1;
		}

		dv->type = type;
		dv->length = length;
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

	if (strlen(fn) >= sizeof(dirtmp) / 2 ||
	    strlen(dir) >= sizeof(dirtmp) / 2) {
		librad_log("dict_init: filename name too long");
		return -1;
	}

	/*
	 *	First see if fn is relative to dir. If so, create
	 *	new filename. If not, remember the absolute dir.
	 */
	if ((p = strrchr(fn, '/')) != NULL) {
		strcpy(dirtmp, fn);
		dirtmp[p - fn] = 0;
		dir = dirtmp;
	} else if (dir && dir[0] && strcmp(dir, ".") != 0) {
		snprintf(dirtmp, sizeof(dirtmp), "%s/%s", dir, fn);
		fn = dirtmp;
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			librad_log("dict_init: Couldn't open dictionary \"%s\": %s",
				   fn, strerror(errno));
		} else {
			librad_log("dict_init: %s[%d]: Couldn't open dictionary \"%s\": %s",
				   src_file, src_line, fn, strerror(errno));
		}
		return -1;
	}

	stat(fn, &statbuf); /* fopen() guarantees this will succeed */
	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fp);
		librad_log("dict_init: Dictionary \"%s\" is not a regular file",
			   fn);
		return -1;	  
	}
	dict_stat_add(fn, &statbuf);

	/*
	 *	Seed the random pool with data.
	 */
	lrad_rand_seed(&statbuf, sizeof(statbuf));

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
			librad_log( "dict_init: %s[%d] invalid entry",
				    fn, line);
			fclose(fp);
			return -1;
		}

		if (0) {
			int i;

			fprintf(stderr, "ARGC = %d\n",argc);
			for (i = 0; i < argc; i++) {
				fprintf(stderr, "\t%s\n", argv[i]);
			}
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
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
			if (process_attribute(fn, line, block_vendor,
					      argv + 1, argc - 1) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
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

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			if (argc != 2) {
				librad_log(
				"dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(argv[1]);
			if (!vendor) {
				librad_log(
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
				librad_log(
				"dict_init: %s[%d] invalid END-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(argv[1]);
			if (!vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, argv[1]);
				fclose(fp);
				return -1;
			}

			if (vendor != block_vendor) {
				librad_log(
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
		librad_log(
			"dict_init: %s[%d] invalid keyword \"%s\"",
			fn, line, argv[0]);
		fclose(fp);
		return -1;
	}
	fclose(fp);
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
	vendors_byname = lrad_hash_table_create(dict_vendor_name_hash,
						dict_vendor_name_cmp,
						free);
	if (!vendors_byname) {
		return -1;
	}

	/*
	 *	Create the table of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	vendors_byvalue = lrad_hash_table_create(dict_vendor_value_hash,
						 dict_vendor_value_cmp,
						 NULL);
	if (!vendors_byvalue) {
		return -1;
	}

	/*
	 *	Create the table of attributes by name.   There MAY NOT
	 *	be multiple attributes of the same name.
	 *
	 *	Each attribute is malloc'd, so the free function is free.
	 */
	attributes_byname = lrad_hash_table_create(dict_attr_name_hash,
						   dict_attr_name_cmp,
						   free);
	if (!attributes_byname) {
		return -1;
	}

	/*
	 *	Create the table of attributes by value.  There MAY
	 *	be attributes of the same value.  If there are, we
	 *	pick the latest one.
	 */
	attributes_byvalue = lrad_hash_table_create(dict_attr_value_hash,
						    dict_attr_value_cmp,
						    NULL);
	if (!attributes_byvalue) {
		return -1;
	}

	values_byname = lrad_hash_table_create(dict_value_name_hash,
					       dict_value_name_cmp,
					       free);
	if (!values_byname) {
		return -1;
	}

	values_byvalue = lrad_hash_table_create(dict_value_value_hash,
						dict_value_value_cmp,
						NULL);
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
				librad_log(
					"dict_init: No ATTRIBUTE \"%s\" defined for VALUE \"%s\"",
					this->attrstr, this->dval->name);
				return -1; /* leak, but they should die... */
			}

			this->dval->attr = a->attr;

			/*
			 *	Add the value into the dictionary.
			 */
			if (!lrad_hash_table_replace(values_byname,
						     this->dval)) {
				librad_log("dict_addvalue: Duplicate value name %s for attribute %s", this->dval->name, a->name);
				return -1;
			}
			
			/*
			 *	Allow them to use the old name, but
			 *	prefer the new name when printing
			 *	values.
			 */
			if (!lrad_hash_table_finddata(values_byvalue, this->dval)) {
				lrad_hash_table_replace(values_byvalue,
							this->dval);
			}
			free(this);

			/*
			 *	Just so we don't lose track of things.
			 */
			value_fixup = next;
		}
	}

	return 0;
}

/*
 *	Get an attribute by its numerical value.
 */
DICT_ATTR *dict_attrbyvalue(int attr)
{
	DICT_ATTR dattr;

	dattr.attr = attr;
	dattr.vendor = VENDOR(attr) & 0x7fff;

	return lrad_hash_table_finddata(attributes_byvalue, &dattr);
}

/*
 *	Get an attribute by its name.
 */
DICT_ATTR *dict_attrbyname(const char *name)
{
	DICT_ATTR dattr;

	if (!name) return NULL;

	strNcpy(dattr.name, name, sizeof(dattr.name));

	return lrad_hash_table_finddata(attributes_byname, &dattr);
}

/*
 *	Associate a value with an attribute and return it.
 */
DICT_VALUE *dict_valbyattr(int attr, int value)
{
	DICT_VALUE dval;

	dval.attr = attr;
	dval.value = value;
	
	return lrad_hash_table_finddata(values_byvalue, &dval);
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
DICT_VALUE *dict_valbyname(int attr, const char *name)
{
	DICT_VALUE *dv;
	uint32_t buffer[(sizeof(*dv) + DICT_VALUE_MAX_NAME_LEN + 3)/4];

	if (!name) return NULL;

	dv = (DICT_VALUE *) buffer;
	dv->attr = attr;
	strNcpy(dv->name, name, DICT_VALUE_MAX_NAME_LEN);

	return lrad_hash_table_finddata(values_byname, dv);
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
	strNcpy(dv->name, name, DICT_VENDOR_MAX_NAME_LEN);
	
	dv = lrad_hash_table_finddata(vendors_byname, dv);
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

	return lrad_hash_table_finddata(vendors_byvalue, &dv);
}
