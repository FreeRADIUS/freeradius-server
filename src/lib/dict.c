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

#include	"libradius.h"
#include	"missing.h"

/*
 *	There are very few vendors, and they're looked up only when we
 *	read the dictionaries.  So it's OK to have a singly linked
 *	list here.
 */
static DICT_VENDOR	*dictionary_vendors = NULL;

static rbtree_t *attributes_byname = NULL;
static rbtree_t *attributes_byvalue = NULL;

static rbtree_t *values_byvalue = NULL;
static rbtree_t *values_byname = NULL;

/*
 *	So VALUEs in the dictionary can have forward references.
 */
static rbtree_t *values_fixup = NULL;

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
 *	Free the dictionary_attributes and dictionary_values lists.
 */
static void dict_free(void)
{
	DICT_VENDOR	*dvend, *enext;

	memset(base_attributes, 0, sizeof(base_attributes));

	for (dvend = dictionary_vendors; dvend; dvend = enext) {
		enext = dvend->next;
		free(dvend);
	}

	dictionary_vendors = NULL;

	/*
	 *	Free the tree of attributes by name and value.
	 */
	rbtree_free(attributes_byname);
	rbtree_free(attributes_byvalue);
	attributes_byname = NULL;
	attributes_byvalue = NULL;

	rbtree_free(values_byname);
	rbtree_free(values_byvalue);
	values_byname = NULL;
	values_byvalue = NULL;
}

/*
 *	Add vendor to the list.
 */
int dict_addvendor(const char *name, int value)
{
	DICT_VENDOR *vval;

	if (value >= (1 << 16)) {
	       	librad_log("dict_addvendor: Cannot handle vendor ID larger than 65535");
		return -1;
	}

	if (strlen(name) > (sizeof(vval->name) -1)) {
		librad_log("dict_addvendor: vendor name too long");
		return -1;
	}

	if ((vval =(DICT_VENDOR *)malloc(sizeof(DICT_VENDOR))) == NULL) {
		librad_log("dict_addvendor: out of memory");
		return -1;
	}
	strcpy(vval->name, name);
	vval->vendorpec  = value;

	/* Insert at front. */
	vval->next = dictionary_vendors;
	dictionary_vendors = vval;

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
		attr = dict_attrbyname(name);
		if (attr != NULL) {
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


	/*
	 *	Create a new attribute for the list
	 */
	if ((attr = (DICT_ATTR *)malloc(sizeof(DICT_ATTR))) == NULL) {
		librad_log("dict_addattr: out of memory");
		return -1;
	}
	strcpy(attr->name, name);
	attr->attr = value;
	attr->type = type;
	attr->flags = flags;

	if (vendor) {
		attr->attr |= (vendor << 16);
	} else if ((attr->attr >= 0) && (attr->attr < 256)) {
		/*
		 *	If it's an on-the-wire base attribute,
		 *	then keep a quick reference to it, for speed.
		 */
		base_attributes[attr->attr] = attr;
	}

	/*
	 *	Insert the attribute, only if it's not a duplicate.
	 */
	if (rbtree_insert(attributes_byname, attr) == 0) {
		DICT_ATTR	*a;

		/*
		 *	If the attribute has identical number, then
		 *	ignore the duplicate.
		 */
		a = rbtree_finddata(attributes_byname, attr);
		if (a->attr == attr->attr) {
			free(attr);
			return 0;
		}

		librad_log("dict_addattr: Duplicate attribute %s", name);
		return -1;
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
int dict_addvalue(const char *namestr, char *attrstr, int value)
{
	DICT_ATTR	*dattr;
	DICT_VALUE	*dval;

	if (strlen(namestr) > (sizeof(dval->name) -1)) {
		librad_log("dict_addvalue: value name too long");
		return -1;
	}

	if ((dval = (DICT_VALUE *)malloc(sizeof(DICT_VALUE))) == NULL) {
		librad_log("dict_addvalue: out of memory");
		return -1;
	}

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
		dval->attr = (int) strdup(attrstr);
		rbtree_insert(values_fixup, dval);
		return 0;
	}

	/*
	 *	Add the value into the dictionary.
	 */
	if (rbtree_insert(values_byname, dval) == 0) {
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
			     const int block_vendor, const char* data)
{
	int		vendor;
	char		namestr[256];
	char		valstr[256];
	char		typestr[256];
	char		optstr[256];
	int		value;
	int		type;
	char		*s, *c;
	ATTR_FLAGS	flags;

	vendor = 0;
	optstr[0] = 0;
	if(sscanf(data, "%s%s%s%s", namestr, valstr, typestr, optstr) < 3) {
		librad_log("dict_init: %s[%d]: invalid ATTRIBUTE line",
			fn, line);
		return -1;
	}

	/*
	 *	Validate all entries
	 */
	if (!isdigit((int) *valstr)) {
		librad_log("dict_init: %s[%d]: invalid value", fn, line);
		return -1;
	}
	if (valstr[0] != '0')
		value = atoi(valstr);
	else
		sscanf(valstr, "%i", &value);

	/*
	 *	find the type of the attribute.
	 */
	type = lrad_str2int(type_table, typestr, -1);
	if (type < 0) {
		librad_log("dict_init: %s[%d]: invalid type \"%s\"",
			fn, line, typestr);
		return -1;
	}

	/*
	 *	Ignore comments
	 */
	if (optstr[0] == '#') optstr[0] = '\0';

	/*
	 *	Only look up the vendor if the string
	 *	is non-empty.
	 */

	memset(&flags, 0, sizeof(flags));
	s = strtok(optstr, ",");
	while(s) {
		if (strcmp(s, "has_tag") == 0 ||
		    strcmp(s, "has_tag=1") == 0) {
			 /* Boolean flag, means this is a
			    tagged attribute */
			 flags.has_tag = 1;
		}
		else if (strncmp(s, "len+=", 5) == 0 ||
			 strncmp(s, "len-=", 5) == 0) {
			  /* Length difference, to accomodate
			     braindead NASes & their vendors */
			  flags.len_disp = strtol(s + 5, &c, 0);
			  if (*c) {
				librad_log("dict_init: %s[%d] invalid option %s",
					   fn, line, s);
				return -1;
			  }
			  if (s[3] == '-') {
				flags.len_disp = -flags.len_disp;
			  }
		}
		else if (strncmp(s, "encrypt=", 8) == 0) {
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
		}
		else {
			  /* Must be a vendor 'flag'... */
			  if (strncmp(s, "vendor=", 5) == 0) {
				/* New format */
				s += 5;
			  }

			  vendor = dict_vendorbyname(s);
			  if (!vendor) {
				librad_log( "dict_init: %s[%d]: unknown vendor %s",
					   fn, line, optstr);
				return -1;
			  }
			  if (block_vendor && optstr[0] &&
			      (block_vendor != vendor)) {
				librad_log("dict_init: %s[%d]: mismatched vendor %s within BEGIN-VENDOR/END-VENDOR block",
					   fn, line, optstr);
				return -1;
			  }
		}
		s = strtok(NULL, ",");
	}

	if (block_vendor) vendor = block_vendor;

	if (dict_addattr(namestr, vendor, type, value, flags) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
		return -1;
	}

	return 0;
}


/*
 *	Process the VALUE command
 */
static int process_value(const char* fn, const int line, const char* data)
{
	char	namestr[256];
	char	valstr[256];
	char	attrstr[256];
	int	value;

	if (sscanf(data, "%s%s%s", attrstr, namestr, valstr) != 3) {
		librad_log("dict_init: %s[%d]: invalid VALUE line",
			fn, line);
		return -1;
	}
	/*
	 *	For Compatibility, skip "Server-Config"
	 */
	if (strcasecmp(attrstr, "Server-Config") == 0)
		return 0;

	/*
	 *	Validate all entries
	 */
	if (!isdigit((int) *valstr)) {
		librad_log("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}
	if (valstr[0] != '0')
		value = atoi(valstr);
	else
		sscanf(valstr, "%i", &value);

	if (dict_addvalue(namestr, attrstr, value) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
		return -1;
	}

	return 0;
}


/*
 *	Process the VENDOR command
 */
static int process_vendor(const char* fn, const int line, const char* data)
{
	char	valstr[256];
	char	attrstr[256];
	int	value;

	if (sscanf(data, "%s%s", attrstr, valstr) != 2) {
		librad_log(
		"dict_init: %s[%d] invalid VENDOR entry",
			fn, line);
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!isdigit((int) *valstr)) {
		librad_log("dict_init: %s[%d]: invalid value",
			fn, line);
		return -1;
	}
	value = atoi(valstr);

	/* Create a new VENDOR entry for the list */
	if (dict_addvendor(attrstr, value) < 0) {
		librad_log("dict_init: %s[%d]: %s",
			   fn, line, librad_errstr);
		return -1;
	}

	return 0;
}


/*
 *	Initialize the dictionary.
 */
static int my_dict_init(const char *dir, const char *fn,
			const char *src_file, int src_line)
{
	FILE	*fp;
	char 	dirtmp[256];
	char	buf[256];
	char	optstr[256];
	char	*p;
	char	*keyword;
	char	*data;
	int	line = 0;
	int	vendor;
	int	block_vendor;

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

		keyword = strtok(buf, " \t\r\n");
		if (keyword == NULL) {
			continue;
		}

		data    = strtok(NULL, "\r\n");
		if (data == NULL || data[0] == 0) {
			librad_log("dict_init: %s[%d]: invalid entry for keyword %s",
				fn, line, keyword);
			fclose(fp);
			return -1;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strcasecmp(keyword, "$INCLUDE") == 0) {
			p = strtok(data, " \t");
			if (my_dict_init(dir, data, fn, line) < 0) {
				fclose(fp);
				return -1;
			}
			continue;
		} /* $INCLUDE */

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(keyword, "ATTRIBUTE") == 0) {
			if (process_attribute(fn, line, block_vendor, data) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(keyword, "VALUE") == 0) {
			if (process_value(fn, line, data) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(keyword, "VENDOR") == 0) {
			if (process_vendor(fn, line, data) == -1) {
				fclose(fp);
				return -1;
			}
			continue;
		}

		if (strcasecmp(keyword, "BEGIN-VENDOR") == 0) {
			optstr[0] = 0;
			if (sscanf(data, "%s", optstr) != 1) {
				librad_log(
				"dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(optstr);
			if (!vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, optstr);
				fclose(fp);
				return -1;
			}
			block_vendor = vendor;
			continue;
		} /* BEGIN-VENDOR */

		if (strcasecmp(keyword, "END-VENDOR") == 0) {
			optstr[0] = 0;
			if (sscanf(data, "%s", optstr) != 1) {
				librad_log(
				"dict_init: %s[%d] invalid END-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorbyname(optstr);
			if (!vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, optstr);
				fclose(fp);
				return -1;
			}

			if (vendor != block_vendor) {
				librad_log(
					"dict_init: %s[%d]: END-VENDOR %s does not match any previous BEGIN-VENDOR",
					fn, line, optstr);
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
			fn, line, keyword);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/*
 *	Callbacks for red-black trees.
 */
static int attrname_cmp(const void *a, const void *b)
{
	return strcasecmp(((const DICT_ATTR *)a)->name,
			  ((const DICT_ATTR *)b)->name);
}

/*
 *	Return: < 0  if a < b,
 *	        == 0 if a == b
 */
static int attrvalue_cmp(const void *a, const void *b)
{
	return (((const DICT_ATTR *)a)->attr -
		((const DICT_ATTR *)b)->attr);
}

/*
 *	Compare values by name, keying off of the attribute number,
 *	and then the value name.
 */
static int valuename_cmp(const void *a, const void *b)
{
	int rcode;
	rcode = (((const DICT_VALUE *)a)->attr -
		 ((const DICT_VALUE *)b)->attr);
	if (rcode != 0) return rcode;

	return strcasecmp(((const DICT_VALUE *)a)->name,
			  ((const DICT_VALUE *)b)->name);
}

/*
 *	Compare values by value, keying off of the attribute number,
 *	and then the value number.
 */
static int valuevalue_cmp(const void *a, const void *b)
{
	int rcode;
	rcode = (((const DICT_VALUE *)a)->attr -
		 ((const DICT_VALUE *)b)->attr);
	if (rcode != 0) return rcode;

	return (((const DICT_VALUE *)a)->value -
		 ((const DICT_VALUE *)b)->value);
}

/*
 *	Compare values by name, keying off of the value number,
 *	and then the value number.
 */
static int valuefixup_cmp(const void *a, const void *b)
{
	int rcode;
	rcode = strcasecmp((const char *) ((const DICT_VALUE *)a)->attr,
			   (const char *) ((const DICT_VALUE *)b)->attr);
	if (rcode != 0) return rcode;

	return (((const DICT_VALUE *)a)->value -
		((const DICT_VALUE *)b)->value);
}

static int values_fixup_func(void *data)
{
	DICT_ATTR  *a;
	DICT_VALUE *v;
	DICT_VALUE *dval = data;

	a = dict_attrbyname((const char *) dval->attr);
	if (!a) {
		librad_log("dict_addvalue: No attribute named %s for value %s", (const char *) dval->attr, dval->name);
		return -1;
	}

	free ((const char *) dval->attr);
	dval->attr = a->attr;

	/*
	 *	Add the value into the dictionary.
	 */

	if (rbtree_insert(values_byname, dval) == 0) {
		librad_log("dict_addvalue: Duplicate value name %s for attribute %s", dval->name, a->name);
		return -1;
	}

	/*
	 *	Allow them to use the old name, but prefer the new name
	 *	when printing values.
	 */
	v = rbtree_find(values_byvalue, dval);
	if (!v) {
		rbtree_insert(values_byvalue, dval);
	}

	return 0;
}

/*
 *	Initialize the directory, then fix the attr member of
 *	all attributes.
 */
int dict_init(const char *dir, const char *fn)
{
	dict_free();

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

	values_byname = rbtree_create(valuename_cmp, NULL, 1);
	if (!values_byname) {
		return -1;
	}

	values_byvalue = rbtree_create(valuevalue_cmp, NULL, 1);
	if (!values_byvalue) {
		return -1;
	}

	/*
	 *	ONLY used in this function!
	 */
	values_fixup = rbtree_create(valuefixup_cmp, NULL, 1);
	if (!values_fixup) {
		return -1;
	}

	if (my_dict_init(dir, fn, NULL, 0) < 0)
		return -1;

	/*
	 *	Fix up the dictionary, based on values with an attribute
	 *	of zero.
	 */
	if (rbtree_walk(values_fixup, values_fixup_func, InOrder) != 0) {
		return -1;
	}

	rbtree_free(values_fixup);
	values_fixup = NULL;

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
		DICT_ATTR myattr;

		myattr.attr = val;
		return rbtree_finddata(attributes_byvalue, &myattr);
	}

	return NULL;		/* never reached, but useful */
}

/*
 *	Get an attribute by its name.
 */
DICT_ATTR *dict_attrbyname(const char *name)
{
	DICT_ATTR myattr;

	strNcpy(myattr.name, name, sizeof(myattr.name));

	return rbtree_finddata(attributes_byname, &myattr);
}

/*
 *	Associate a value with an attribute and return it.
 */
DICT_VALUE *dict_valbyattr(int attr, int val)
{
	DICT_VALUE	myval;

	myval.attr = attr;
	myval.value = val;

	return rbtree_finddata(values_byvalue, &myval);
}

/*
 *	Get a value by its name.
 *      If you pass an actual attr, it will try to match it.
 *      If you just want it to return on the first match,
 *      send it 0 as the attr. I hope this works the way it
 *      seems to. :) --kph
 */
DICT_VALUE *dict_valbyname(int attr, const char *name)
{
	DICT_VALUE	myval;

	myval.attr = attr;
	strNcpy(myval.name, name, sizeof(myval.name));

	return rbtree_finddata(values_byname, &myval);
}

/*
 *	Get the vendor PEC based on the vendor name
 */
int dict_vendorbyname(const char *name)
{
	DICT_VENDOR *v;

	/*
	 *	Find the vendor, if any.
	 */
	for (v = dictionary_vendors; v; v = v->next) {
		if (strcasecmp(name, v->name) == 0) {
			return v->vendorpec;
		}
	}

	return 0;
}

/*
 *	Return the vendor struct based on the PEC.
 */
DICT_VENDOR *dict_vendorbyvalue(int vendor)
{
	DICT_VENDOR *v;

	/*
	 *	Find the vendor, if any.
	 */
	for (v = dictionary_vendors; v; v = v->next) {
		if (vendor == v->vendorpec) {
			return v;
		}
	}

	return NULL;

}
