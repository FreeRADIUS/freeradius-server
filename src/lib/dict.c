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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Copyright 2000  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

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

#include	"missing.h"
#include	"libradius.h"

#define DICT_VALUE_MAX_NAME_LEN (128)
#define DICT_VENDOR_MAX_NAME_LEN (128)

static rbtree_t *vendors_byname = NULL;
static rbtree_t *vendors_byvalue = NULL;

static rbtree_t *attributes_byname = NULL;
static rbtree_t *attributes_byvalue = NULL;

static rbtree_t *values_byvalue = NULL;
static rbtree_t *values_byname = NULL;

/*
 *	For faster HUP's, we cache the stat information for
 *	files we've $INCLUDEd
 */
typedef struct dict_stat_t {
	struct dict_stat_t *next;
	const char	   *name;
	time_t		   mtime;
} dict_stat_t;

static const char *stat_root_dir = NULL;
static const char *stat_root_file = NULL;

static dict_stat_t *stat_head = NULL;
static dict_stat_t *stat_tail = NULL;

/*
 *	Internal data structures to make it faster to manage
 *	the dictionaries.  Hmm... we COULD use a hash table, and
 *	get rid of the rbtree stuff, which could be faster.
 */
typedef struct INT_DICT_VENDOR {
	uint32_t	hash;
	DICT_VENDOR	dv;
} INT_DICT_VENDOR;

typedef struct INT_DICT_ATTR {
	uint32_t	hash;
	DICT_ATTR	attr;
} INT_DICT_ATTR;

typedef struct INT_DICT_VALUE {
	uint32_t	hash;
	DICT_VALUE	dval;
} INT_DICT_VALUE;


typedef struct value_fixup_t {
	char		attrstr[40];
	INT_DICT_VALUE	*dval;
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
 *	Quick pointers to the base 0..255 attributes.
 *
 *	These attributes are referenced a LOT, especially during
 *	decoding of the on-the-wire packets.  It's useful to keep a
 *	cache of their dictionary entries, so looking them up is
 *	O(1), instead of O(log(N)).  (N==number of dictionary entries...)
 */
static DICT_ATTR *base_attributes[256];

/*
 *	Create the hash of the name.
 */
static uint32_t dict_hashname(const char *name)
{
	const char *p;
	char *q;
	char buffer[1024];
	
	p = name;
	q = buffer;
	while (*p) {
		if (isalpha(*p)) {
			*(q++) = tolower((int) *(p++));
		} else {
			*(q++) = *(p++);
		}
	}
	*q = '\0';
	return lrad_hash(buffer, strlen(buffer));
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
	memset(base_attributes, 0, sizeof(base_attributes));

	/*
	 *	Free the trees
	 */
	rbtree_free(vendors_byname);
	rbtree_free(vendors_byvalue);
	vendors_byname = NULL;
	vendors_byvalue = NULL;

	rbtree_free(attributes_byname);
	rbtree_free(attributes_byvalue);
	attributes_byname = NULL;
	attributes_byvalue = NULL;

	rbtree_free(values_byname);
	rbtree_free(values_byvalue);
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
	INT_DICT_VENDOR *dv;

	if (value >= (1 << 16)) {
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

	dv->hash = dict_hashname(name);
	strcpy(dv->dv.name, name);
	dv->dv.vendorpec  = value;

	if (rbtree_insert(vendors_byname, dv) == 0) {
		INT_DICT_VENDOR *old_dv;

		old_dv = rbtree_finddata(vendors_byname, dv);
		if (!old_dv) {
			librad_log("dict_addvendor: Failed inserting vendor name %s", name);
			return -1;
		}
		if (old_dv->dv.vendorpec != dv->dv.vendorpec) {
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
	 *	Insert the SAME pointer (not free'd when this tree is
	 *	deleted), into another tree.
	 *
	 *	If the newly inserted entry is a duplicate of an existing
	 *	entry, then the old entry is tossed, and the new one
	 *	replaces it.  This behaviour is configured in the
	 *	rbtree_create() function.
	 *
	 *	We want this behaviour because we want OLD names for
	 *	the attributes to be read from the configuration
	 *	files, but when we're printing them, (and looking up
	 *	by value) we want to use the NEW name.
	 */
	rbtree_insert(vendors_byvalue, dv);

	return 0;
}

/*
 *	Add an attribute to the dictionary.
 */
int dict_addattr(const char *name, int vendor, int type, int value,
		 ATTR_FLAGS flags)
{
	static int      max_attr = 0;
	INT_DICT_ATTR	*attr;

	if (strlen(name) > (sizeof(attr->attr.name) -1)) {
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
		/*
		 *	If the vendor isn't defined, die/
		 */
		if (!dict_vendorbyvalue(vendor)) {
			librad_log("dict_addattr: Unknown vendor");
			return -1;
		}

		/*
		 *	With a few exceptions, attributes can only be
		 *	1..255.  The check above catches the less than
		 *	zero case.
		 */
		if ((vendor != VENDORPEC_USR) &&
		    (vendor != VENDORPEC_LUCENT) &&
		    (value > 256)) {
			librad_log("dict_addattr: ATTRIBUTE has invalid number (larger than 255).");
			return -1;
		}
	}

	/*
	 *	Create a new attribute for the list
	 */
	if ((attr = malloc(sizeof(*attr))) == NULL) {
		librad_log("dict_addattr: out of memory");
		return -1;
	}

	attr->hash = dict_hashname(name);
	strcpy(attr->attr.name, name);
	attr->attr.attr = value;
	attr->attr.attr |= (vendor << 16); /* FIXME: hack */
	attr->attr.type = type;
	attr->attr.flags = flags;
	attr->attr.vendor = vendor;


	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (rbtree_insert(attributes_byname, attr) == 0) {
		INT_DICT_ATTR	*a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = rbtree_finddata(attributes_byname, attr);
		if (a && (strcasecmp(a->attr.name, attr->attr.name) == 0)) {
			if (a->attr.attr != attr->attr.attr) {
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

	if ((attr->attr.attr >= 0) && (attr->attr.attr < 256)) {
		/*
		 *	If it's an on-the-wire base attribute,
		 *	then keep a quick reference to it, for speed.
		 */
		base_attributes[attr->attr.attr] = &(attr->attr);
	}

	/*
	 *	Insert the SAME pointer (not free'd when this tree is
	 *	deleted), into another tree.
	 *
	 *	If the newly inserted entry is a duplicate of an existing
	 *	entry, then the old entry is tossed, and the new one
	 *	replaces it.  This behaviour is configured in the
	 *	rbtree_create() function.
	 *
	 *	We want this behaviour because we want OLD names for
	 *	the attributes to be read from the configuration
	 *	files, but when we're printing them, (and looking up
	 *	by value) we want to use the NEW name.
	 */
	rbtree_insert(attributes_byvalue, attr);

	return 0;
}


/*
 *	Add a value for an attribute to the dictionary.
 */
int dict_addvalue(const char *namestr, const char *attrstr, int value)
{
	size_t		length;
	DICT_ATTR	*dattr;
	INT_DICT_VALUE	*dval;

	if ((length = strlen(namestr)) >= DICT_VALUE_MAX_NAME_LEN) {
		librad_log("dict_addvalue: value name too long");
		return -1;
	}

	if ((dval = malloc(sizeof(*dval) + length)) == NULL) {
		librad_log("dict_addvalue: out of memory");
		return -1;
	}
	memset(dval, 0, sizeof(*dval));

	dval->hash = dict_hashname(namestr);
	strcpy(dval->dval.name, namestr);
	dval->dval.value = value;

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	dattr = dict_attrbyname(attrstr);
	if (dattr) {
		dval->dval.attr = dattr->attr;
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
	if (rbtree_insert(values_byname, dval) == 0) {
		if (dattr) {
			DICT_VALUE *old;
			
			/*
			 *	Suppress duplicates with the same
			 *	name and value.  There are lots in
			 *	dictionary.ascend.
			 */
			old = dict_valbyname(dattr->attr, namestr);
			if (old && (old->value == dval->dval.value)) {
				free(dval);
				return 0;
			}
		}

		librad_log("dict_addvalue: Duplicate value name %s for attribute %s", namestr, attrstr);
		return -1;
	}
	rbtree_insert(values_byvalue, dval);

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

	/*
	 *	valuepair.c will get excited when creating attributes,
	 *	if it sees values which look like integers, so we can't
	 *	use them here.
	 */
	if (isdigit(argv[1][0])) {
		librad_log("dict_init: %s[%d]: Names for VALUEs cannot start with a digit.",
			   fn, line);
	}
	
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

	if (argc != 2) {
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
 *	Callbacks for red-black trees.
 */
static int vendorname_cmp(const void *a, const void *b)
{
	const INT_DICT_VENDOR *one = a;
	const INT_DICT_VENDOR *two = b;

	if (one->hash < two->hash) return -1;
	if (one->hash > two->hash) return +1;

	/*
	 *	With a reasonable 32-bit hash, this cmp isn't strictly
	 *	necessary.  Removing it makes very little difference
	 *	in time, but could (one day) cause a problem.  So it's
	 *	left in.
	 */
	return strcasecmp(one->dv.name, two->dv.name);
}

/*
 *	Return: < 0  if a < b,
 *	        == 0 if a == b
 */
static int vendorvalue_cmp(const void *a, const void *b)
{
	/*
	 *	Don't look at the hashes, as we don't care about names
	 */

	return (((const INT_DICT_VENDOR *)a)->dv.vendorpec -
		((const INT_DICT_VENDOR *)b)->dv.vendorpec);
}

/*
 *	Callbacks for red-black trees.
 */
static int attrname_cmp(const void *a, const void *b)
{
	const INT_DICT_ATTR *one = a;
	const INT_DICT_ATTR *two = b;

	if (one->hash < two->hash) return -1;
	if (one->hash > two->hash) return +1;

	/*
	 *	With a reasonable 32-bit hash, this cmp isn't strictly
	 *	necessary.  Removing it makes very little difference
	 *	in time, but could (one day) cause a problem.  So it's
	 *	left in.
	 */
	return strcasecmp(one->attr.name, two->attr.name);
}

/*
 *	Return: < 0  if a < b,
 *	        == 0 if a == b
 */
static int attrvalue_cmp(const void *a, const void *b)
{
	/*
	 *	Don't look at the hashes, as we don't care about names
	 */

	return (((const INT_DICT_ATTR *)a)->attr.attr -
		((const INT_DICT_ATTR *)b)->attr.attr);
}

/*
 *	Compare values by name, keying off of the attribute number,
 *	and then the value name.
 */
static int valuename_cmp(const void *a, const void *b)
{
	int rcode;
	const INT_DICT_VALUE *one = a;
	const INT_DICT_VALUE *two = b;

	rcode = (one->dval.attr - two->dval.attr);
	if (rcode != 0) return rcode;

	if (one->hash < two->hash) return -1;
	if (one->hash > two->hash) return +1;

	/*
	 *	With a reasonable 32-bit hash, this cmp isn't strictly
	 *	necessary.  Removing it makes very little difference
	 *	in time, but could (one day) cause a problem.  So it's
	 *	left in.
	 */
	return strcasecmp(one->dval.name, two->dval.name);
}

/*
 *	Compare values by value, keying off of the attribute number,
 *	and then the value number.
 */
static int valuevalue_cmp(const void *a, const void *b)
{
	int rcode;
	const INT_DICT_VALUE *one = a;
	const INT_DICT_VALUE *two = b;

	rcode = (one->dval.attr - two->dval.attr);
	if (rcode != 0) return rcode;

	/*
	 *	Don't look at the hashes, as we don't care about names
	 */

	return (one->dval.value - two->dval.value);
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
	 *	Create the tree of vendor by name.   There MAY NOT
	 *	be multiple vendors of the same name.
	 *
	 *	Each vendor is malloc'd, so the free function is free.
	 */
	vendors_byname = rbtree_create(vendorname_cmp, free, 0);
	if (!vendors_byname) {
		return -1;
	}

	/*
	 *	Create the tree of vendors by value.  There MAY
	 *	be vendors of the same value.  If there are, we
	 *	pick the latest one.
	 */
	vendors_byvalue = rbtree_create(vendorvalue_cmp, NULL, 1);
	if (!vendors_byvalue) {
		return -1;
	}

	/*
	 *	Create the tree of attributes by name.   There MAY NOT
	 *	be multiple attributes of the same name.
	 *
	 *	Each attribute is malloc'd, so the free function is free.
	 */
	attributes_byname = rbtree_create(attrname_cmp, free, 0);
	if (!attributes_byname) {
		return -1;
	}

	/*
	 *	Create the tree of attributes by value.  There MAY
	 *	be attributes of the same value.  If there are, we
	 *	pick the latest one.
	 */
	attributes_byvalue = rbtree_create(attrvalue_cmp, NULL, 1);
	if (!attributes_byvalue) {
		return -1;
	}

	values_byname = rbtree_create(valuename_cmp, free, 0);
	if (!values_byname) {
		return -1;
	}

	values_byvalue = rbtree_create(valuevalue_cmp, NULL, 1);
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
					this->attrstr, this->dval->dval.name);
				return -1; /* leak, but they should die... */
			}

			this->dval->dval.attr = a->attr;

			/*
			 *	Add the value into the dictionary.
			 */
			if (rbtree_insert(values_byname, this->dval) == 0) {
				librad_log("dict_addvalue: Duplicate value name %s for attribute %s", this->dval->dval.name, a->name);
				return -1;
			}
			
			/*
			 *	Allow them to use the old name, but
			 *	prefer the new name when printing
			 *	values.
			 */
			if (!rbtree_find(values_byvalue, this->dval)) {
				rbtree_insert(values_byvalue, this->dval);
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
DICT_ATTR *dict_attrbyvalue(int val)
{
	/*
	 *	If it's an on-the-wire base attribute, return
	 *	the cached value for it.
	 */
	if ((val >= 0) && (val < 256)) {
		return base_attributes[val];

	} else {
		INT_DICT_ATTR myattr, *da;

		myattr.attr.attr = val;
		da = rbtree_finddata(attributes_byvalue, &myattr);
		if (da) return &(da->attr);
	}

	return NULL;		/* never reached, but useful */
}

/*
 *	Get an attribute by its name.
 *
 *	We can refer to an attribute by it's name, or by
 *	canonical reference:
 *
 *	Attribute-Name
 *	Attr-%d
 *	VendorName-Attr-%d
 *	Vendor-%d-Attr-%d
 *	VendorName-Attribute-Name
 */
DICT_ATTR *dict_attrbyname(const char *name)
{
	INT_DICT_ATTR myattr, *da;

	myattr.hash = dict_hashname(name);
	strNcpy(myattr.attr.name, name, sizeof(myattr.attr.name));
	da = rbtree_finddata(attributes_byname, &myattr);
	if (da) return &(da->attr);

	{
		int value, attr;
		const char *p = name;
		char *q;
		
		/*
		 *	Look for:
		 *
		 *	Vendor-%d-Attr-%d
		 *	VendorName-Attr-%d
		 *	Attr-%d		%d = 1-65535
		 */

		attr = 0;

		if (strncasecmp(p, "Vendor-", 7) == 0) {
			p += 7;
			value = (int) strtol(p, &q, 10);

			/*
			 *	Validate the parsed data.
			 */
			if ((value <= 0) || (value > 65535)) {
				return NULL;
			}
			p = q + 1; /* skip the '-' */
			attr = value << 16; /* FIXME: horrid hack */

		} else if ((q = strchr(name, '-')) != NULL) {
			/*
			 *	myattr.name is a temporary buffer
			 */
			if ((q - name) >= sizeof(myattr.attr.name)) return NULL;
			
			memcpy(myattr.attr.name, name, q - name);
			myattr.attr.name[q - name] = '\0';

			/*
			 *	No leading vendor name, stop looking.
			 */
			value = dict_vendorbyname(myattr.attr.name);
			if (!value) return NULL;

			p = q + 1; /* skip the '-' */
			attr = value << 16;
		}

		/*
		 *	Accept only certain names.
		 */
		if (strncasecmp(p, "Attr-", 5) == 0) {
			value = (int) strtol(p + 5, &q, 10);
			if (*q) return NULL; /* characters after the digits */
			if ((value <= 0) || (value > 65535)) return NULL; /* bad value */
			attr |= value;

			/*
			 *	FIXME: If it doesn't exit, maybe we
			 *	want to create it, and make it type
			 *	"octets"?
			 */
			return dict_attrbyvalue(attr);
		}

		/*
		 *	If there's no leading Vendor-%d, or Vendorname,
		 *	and the attribute is not Attr-%d, then don't
		 *	bother looking it up again.
		 */
		if (attr == 0) return NULL;
		
		/*
		 *	Else maybe it's Vendor-%d-Attribute-Name
		 */
		strNcpy(myattr.attr.name, p, sizeof(myattr.attr.name));
	}
	
	/*
	 *	FIXME: If it doesn't exist, maybe we want to create
	 *	it, and make it type "octets"?
	 */
	myattr.hash = dict_hashname(myattr.attr.name);
	da = rbtree_finddata(attributes_byname, &myattr);
	if (da) return &(da->attr);
	return NULL;
}

/*
 *	Associate a value with an attribute and return it.
 */
DICT_VALUE *dict_valbyattr(int attr, int val)
{
	INT_DICT_VALUE	myval, *dval;

	myval.dval.attr = attr;
	myval.dval.value = val;

	dval = rbtree_finddata(values_byvalue, &myval);
	if (dval) return &(dval->dval);
	return NULL;
}

/*
 *	Get a value by its name, keyed off of an attribute.
 */
DICT_VALUE *dict_valbyname(int attr, const char *name)
{
	INT_DICT_VALUE	*dv;

	/*
	 *	This is a bit of a hack.
	 */
	uint8_t		buffer[sizeof(*dv) + DICT_VALUE_MAX_NAME_LEN];

	/*
	 *	The name is too long, we can't find it.
	 */
	if (strlen(name) >= DICT_VALUE_MAX_NAME_LEN) return NULL;

	dv = (INT_DICT_VALUE *) buffer;
	dv->dval.attr = attr;
	dv->hash = dict_hashname(name);
	strcpy(dv->dval.name, name);

	dv = rbtree_finddata(values_byname, dv);
	if (dv) return &(dv->dval);
	return NULL;
}

/*
 *	Get the vendor PEC based on the vendor name
 *
 *	This is efficient only for small numbers of vendors.
 */
int dict_vendorbyname(const char *name)
{
	INT_DICT_VENDOR	*dv, *found;

	/*
	 *	This is a bit of a hack.
	 */
	uint8_t		buffer[sizeof(*dv) + DICT_VENDOR_MAX_NAME_LEN];

	/*
	 *	The name is too long, we can't find it.
	 */
	if (strlen(name) >= DICT_VENDOR_MAX_NAME_LEN) return 0;

	dv = (INT_DICT_VENDOR *) buffer;
	dv->hash = dict_hashname(name);
	strcpy(dv->dv.name, name);
	
	found = rbtree_finddata(vendors_byname, dv);
	if (!found) return 0;

	return found->dv.vendorpec;
}

/*
 *	Return the vendor struct based on the PEC.
 */
DICT_VENDOR *dict_vendorbyvalue(int vendor)
{
	INT_DICT_VENDOR	myvendor, *dv;

	myvendor.dv.vendorpec = vendor;

	dv = rbtree_finddata(vendors_byvalue, &myvendor);
	if (dv) return &(dv->dv);

	return NULL;
}
