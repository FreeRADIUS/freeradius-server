/*
 * dict.c	Routines to read the dictionary file.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdlib.h>
#include	<ctype.h>
#include	<string.h>

#if HAVE_MALLOC_H
#include	<malloc.h>
#endif

#include	"libradius.h"
#include	"missing.h"

static DICT_ATTR	*dictionary_attributes = NULL;
static DICT_VALUE	*dictionary_values = NULL;
static DICT_VENDOR	*dictionary_vendors = NULL;

static int		vendorno = 1;
static const char *dtypes[] = {
	"string",
	"integer",
	"ipaddr",
	"date",
	"abinary",
	"octets",
	NULL,
};

#ifdef WITH_DICT_NOCASE
#define DICT_STRCMP strcasecmp
#else
#define DICT_STRCMP strcmp
#endif

/*
 *	Quick pointers to the base 0..255 attributes.
 *
 *	These attributes are referenced a LOT, especially during
 *	decoding of the on-the-wire packets.  It's useful to keep a
 *	cache of their dictionary entries, so looking them up is
 *	O(1), instead of O(N).  (N==number of dictionary entries...)
 */
static DICT_ATTR *base_attributes[256];

/*
 *	Free the dictionary_attributes and dictionary_values lists.
 */
static void dict_free(void)
{
	DICT_ATTR	*dattr, *anext;
	DICT_VALUE	*dval, *vnext;
	DICT_VENDOR	*dvend, *enext;

	for (dattr = dictionary_attributes; dattr; dattr = anext) {
		anext = dattr->next;
		free(dattr);
	}
	for (dval = dictionary_values; dval; dval = vnext) {
		vnext = dval->next;
		free(dval);
	}
	for (dvend = dictionary_vendors; dvend; dvend = enext) {
		enext = dvend->next;
		free(dvend);
	}

	dictionary_attributes = NULL;
	dictionary_values = NULL;
	dictionary_vendors = NULL;
	vendorno = 1;

	memset(base_attributes, 0, sizeof(base_attributes));
}

/*
 *	Add vendor to the list.
 */
int dict_addvendor(const char *name, int value)
{
	DICT_VENDOR *vval;

	if (strlen(name) > (sizeof(vval->vendorname) -1)) {
		librad_log("dict_addvendor: vendor name too long");
		return -1;
	}

	if ((vval =(DICT_VENDOR *)malloc(sizeof(DICT_VENDOR))) == NULL) {
		librad_log("dict_addvendor: out of memory");
		return -1;
	}
	strcpy(vval->vendorname, name);
	vval->vendorpec  = value;
	vval->vendorcode = vendorno++;

	/* Insert at front. */
	vval->next = dictionary_vendors;
	dictionary_vendors = vval;

	return 0;
}

int dict_addattr(const char *name, int vendor, int type, int value)
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
	 *	Add to the front of the list, so that
	 *	values at the end of the file override
	 *	those in the begin.
	 */
	attr->next = dictionary_attributes;
	dictionary_attributes = attr;
	
	return 0;
}

int dict_addvalue(const char *namestr, char *attrstr, int value)
{
	DICT_VALUE	*dval;

	if (strlen(namestr) > (sizeof(dval->name) -1)) {
		librad_log("dict_addvalue: value name too long");
		return -1;
	}

	if (strlen(attrstr) > (sizeof(dval->attrname) -1)) {
		librad_log("dict_addvalue: attribute name too long");
		return -1;
	}

	if ((dval = (DICT_VALUE *)malloc(sizeof(DICT_VALUE))) == NULL) {
		librad_log("dict_addvalue: out of memory");
		return -1;
	}
	
	strcpy(dval->name, namestr);
	strcpy(dval->attrname, attrstr);
	dval->attr = 0;		/* ??? */
	dval->value = value;
	
	/* Insert at front. */
	dval->next = dictionary_values;
	dictionary_values = dval;
			
	return 0;
}

/*
 *	Initialize the dictionary.
 */
static int my_dict_init(const char *dir, const char *fn, const char *src_file, int src_line)
{
	FILE	*fp;
	char 	dirtmp[256];
	char	buf[256];
	char	namestr[256];
	char	valstr[256];
	char	attrstr[256];
	char	typestr[256];
	char	vendorstr[256];
	char	*p;
	char	*keyword;
	char	*data;
	int	line = 0;
	int	value;
	int	type;
	int	vendor;
	int	block_vendor;
	int	is_attrib;
	int	vendor_usr_seen = 0;
	int	is_nmc;

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
		sprintf(dirtmp, "%s/%s", dir, fn);
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

		keyword = strtok(buf, " \t\r\n");
		if (keyword == NULL)
			continue;

		data    = strtok(NULL, "\r\n");
		if (data == NULL || data[0] == 0) {
			librad_log("dict_init: %s[%d]: invalid entry",
				fn, line);
			return -1;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strcasecmp(keyword, "$INCLUDE") == 0) {
			if (my_dict_init(dir, data, fn, line) < 0)
				return -1;
			continue;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		is_attrib = 0;
		if (DICT_STRCMP(keyword, "ATTRIBUTE") == 0)
			is_attrib = 1;

		is_nmc = 0;
		if (DICT_STRCMP(keyword, "ATTRIB_NMC") == 0)
			is_attrib = is_nmc = 1;

		if (is_attrib) {

			vendor = 0;
			vendorstr[0] = 0;
			if(sscanf(data, "%s%s%s%s", namestr,
					valstr, typestr, vendorstr) < 3) {
				librad_log(
					"dict_init: %s[%d]: invalid ATTRIBUTE line",
					fn, line);
				return -1;
			}

			/*
			 *	Convert ATTRIB_NMC into our format.
			 *	We might need to add USR to the list of
			 *	vendors first.
			 */
			if (is_nmc && vendorstr[0] == 0) {
				if (!vendor_usr_seen) {
					if (dict_addvendor("USR", VENDORPEC_USR) < 0) {
						librad_log("dict_init: %s[%d]: %s", fn, line, librad_errstr);
						return -1;
					}
					vendor_usr_seen = 1;
				}
				strcpy(vendorstr, "USR");
			}

			/*
			 *	Validate all entries
			 */
			if (!isdigit(*valstr)) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				return -1;
			}
			if (valstr[0] != '0')
				value = atoi(valstr);
			else
				sscanf(valstr, "%i", &value);

			/*
			 *	find the type.
			 */
			for (type = 0; dtypes[type]; type++) {
				if (DICT_STRCMP(typestr, dtypes[type]) == 0)
					break;
			}
			if (dtypes[type] == NULL) {
				librad_log("dict_init: %s[%d]: invalid type",
					fn, line);
				return -1;
			}

			/*
			 *	Ignore comments
			 */
			if (vendorstr[0] == '#') {
				vendorstr[0] = '\0';
			}

			/*
			 *	Only look up the vendor if the string
			 *	is non-empty.
			 */
			if (vendorstr[0]) {
				vendor = dict_vendorname(vendorstr);
				if (!vendor) {
					librad_log(
						"dict_init: %s[%d]: unknown vendor %s",
						fn, line, vendorstr);
					return -1;
				}
			}

			if (block_vendor && vendorstr[0] &&
			    (block_vendor != vendor)) {
				librad_log(
					"dict_init: %s[%d]: mismatched vendor %s within BEGIN-VENDOR/END-VENDOR block",
					fn, line, vendorstr);
				return -1;
			}

			if (block_vendor) vendor = block_vendor;

			if (dict_addattr(namestr, vendor, type, value) < 0) {
				librad_log("dict_init: %s[%d]: %s",
					   fn, line, librad_errstr);
				return -1;
			}
			continue;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (DICT_STRCMP(keyword, "VALUE") == 0) {
			if (sscanf(data, "%s%s%s", attrstr,
						namestr, valstr) != 3) {
				librad_log("dict_init: %s[%d]: invalid VALUE line",
					fn, line);
				return -1;
			}
			/*
			 *	For Compatibility, skip "Server-Config"
			 */
			if (DICT_STRCMP(attrstr, "Server-Config") == 0)
				continue;

			/*
			 *	Validate all entries
			 */
			if (!isdigit(*valstr)) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				return -1;
			}
			if (valstr[0] != '0')
				value = atoi(valstr);
			else
				sscanf(valstr, "%i", &value);

#if 0
			/*
			 *	This WOULD be nice, but the dictionary
			 *	files require heavy editing to enable it,
			 *	as many entries are out of order. :(
			 */
			if (dict_attrbyname(attrstr) == NULL) {
				librad_log("dict_init: %s[%d]: No previously defined ATTRIBUTE %s for VALUE", 
					   fn, line, attrstr);
				return -1;
			}
#endif

			if (dict_addvalue(namestr, attrstr, value) < 0) {
				librad_log("dict_init: %s[%d]: %s", 
					   fn, line, librad_errstr);
				return -1;
			}
			continue;
		}

		/*
		 *	Process VENDOR lines.
		 */
		if (DICT_STRCMP(keyword, "VENDOR") == 0) {

			if (sscanf(data, "%s%s", attrstr, valstr) != 2) {
				librad_log(
				"dict_init: %s[%d] invalid VENDOR entry",
					fn, line);
				return -1;
			}

			/*
			 *	 Validate all entries
			 */
			if (!isdigit(*valstr)) {
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

			if (value == VENDORPEC_USR)
				vendor_usr_seen = 1;

			continue;
		}

		if (DICT_STRCMP(keyword, "BEGIN-VENDOR") == 0) {
			vendorstr[0] = 0;
			if (sscanf(data, "%s", vendorstr) != 1) {
				librad_log(
				"dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				return -1;
			}

			vendor = dict_vendorname(vendorstr);
			if (!vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, vendorstr);
				return -1;
			}
			block_vendor = vendor;
			continue;
		}

		if (DICT_STRCMP(keyword, "END-VENDOR") == 0) {
			vendorstr[0] = 0;
			if (sscanf(data, "%s", vendorstr) != 1) {
				librad_log(
				"dict_init: %s[%d] invalid END-VENDOR entry",
					fn, line);
				return -1;
			}

			vendor = dict_vendorname(vendorstr);
			if (!vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, vendorstr);
				return -1;
			}

			if (vendor != block_vendor) {
				librad_log(
					"dict_init: %s[%d]: END-VENDOR %s does not match any previous BEGIN-VENDOR",
					fn, line, vendorstr);
				return -1;
			}
			block_vendor = 0;
			continue;
		}

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
	DICT_ATTR	*attr;
	DICT_VALUE	*dval;

	dict_free();

	if (my_dict_init(dir, fn, NULL, 0) < 0)
		return -1;

	for (dval = dictionary_values; dval; dval = dval->next) {
		if (dval->attr != 0)
			continue;
		if ((attr = dict_attrbyname(dval->attrname)) == NULL) {
		librad_log("dict_init: VALUE %s for unknown ATTRIBUTE %s",
			dval->name, dval->attrname);
			return -1;
		}
		dval->attr = attr->attr;
	}

	return 0;
}

/*
 *	Get an attribute by its numerical value.
 */
DICT_ATTR * dict_attrbyvalue(int val)
{
	DICT_ATTR	*a;

	/*
	 *	If it's an on-the-wire base attribute, return
	 *	the cached value for it.
	 */
	if ((val >= 0) && (val < 256)) {
		return base_attributes[val];
	}

	for (a = dictionary_attributes; a; a = a->next) {
		if (a->attr == val)
			return a;
	}

	return NULL;
}

/*
 *	Get an attribute by its name.
 */
DICT_ATTR * dict_attrbyname(const char *name)
{
	DICT_ATTR	*a;

	for (a = dictionary_attributes; a; a = a->next) {
		if (DICT_STRCMP(a->name, name) == 0)
			return a;
	}

	return NULL;
}

/*
 *	Associate a value with an attribute and return it.
 */
DICT_VALUE * dict_valbyattr(int attr, int val)
{
	DICT_VALUE	*v;

	for (v = dictionary_values; v; v = v->next) {
		if (v->attr == attr && v->value == val)
			return v;
	}

	return NULL;
}

/*
 *	Get a value by its name.
 *      If you pass an actual attr, it will try to match it.
 *      If you just want it to return on the first match,
 *      send it 0 as the attr. I hope this works the way it
 *      seems to. :) --kph
 */
DICT_VALUE * dict_valbyname(int attr, const char *name)
{
	DICT_VALUE	*v;

	for (v = dictionary_values; v; v = v->next) {
		if ((attr == 0 || v->attr == attr) &&
		    DICT_STRCMP(v->name, name) == 0)
		 return v;
               
	}

	return NULL;
}

/*
 *	Get the PEC (Private Enterprise Code) of the vendor
 *	based on its internal number.
 */
int dict_vendorpec(int code)
{
	DICT_VENDOR	*v;

	for (v = dictionary_vendors; v; v = v->next)
		if (v->vendorcode == code)
			break;

	return v ? v->vendorpec : 0;
}

/*
 *	Get the internal code of the vendor based on its PEC.
 */
int dict_vendorcode(int pec)
{
	DICT_VENDOR	*v;

	for (v = dictionary_vendors; v; v = v->next)
		if (v->vendorpec == pec)
			break;
	return v ? v->vendorcode : 0;
}

/*
 *	Get the vendor code based on the vendor name
 */
int dict_vendorname(const char *name)
{
	DICT_VENDOR *v;

	/*
	 *	Find the vendor, if any.
	 */
	for (v = dictionary_vendors; v; v = v->next) {
		if (DICT_STRCMP(name, v->vendorname) == 0) {
			return v->vendorcode;
		}
	}

	return 0;
}
