/*
 * dict.c	Routines to read the dictionary file.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<ctype.h>
#include	<string.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"libradius.h"
#include	"missing.h"

static DICT_ATTR	*dictionary_attributes;
static DICT_VALUE	*dictionary_values;
static DICT_VENDOR	*dictionary_vendors;

static int		vendorno = 1;
static char *dtypes[] = {
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
}

/*
 *	Add vendor to the list.
 */
int dict_addvendor(char *name, int value)
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

int dict_addattr(char *name, int vendor, int type, int value)
{
	DICT_ATTR	*attr;

	if (strlen(name) > (sizeof(attr->name) -1)) {
		librad_log("dict_addattr: attribute name too long");
		return -1;
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

int dict_addvalue(char *namestr, char *attrstr, int value)
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
static int my_dict_init(char *dir, char *fn)
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
	int	is_attrib;
#ifdef ATTRIB_NMC
	int	vendor_usr_seen = 0;
	int	is_nmc;
#endif

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
		librad_log("dict_init: Couldn't open dictionary: %s", fn);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {

		line++;
		if (buf[0] == '#' || buf[0] == 0 || buf[0] == '\n')
			continue;

		keyword = strtok(buf, " \t\n");
		data    = strtok(NULL, "\n");
		if (data == NULL || data[0] == 0) {
			librad_log("dict_init: %s[%d]: invalid entry",
				fn, line);
			return -1;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strcasecmp(keyword, "$INCLUDE") == 0) {
			if (my_dict_init(dir, data) < 0)
				return -1;
			continue;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		is_attrib = 0;
		if (strcmp(keyword, "ATTRIBUTE") == 0)
			is_attrib = 1;
#ifdef ATTRIB_NMC
		is_nmc = 0;
		if (strcmp(keyword, "ATTRIB_NMC") == 0)
			is_attrib = is_nmc = 1;
#endif
		if (is_attrib) {

			vendor = 0;
			vendorstr[0] = 0;
			if(sscanf(data, "%s%s%s%s", namestr,
					valstr, typestr, vendorstr) < 3) {
				librad_log(
					"dict_init: %s[%d]: invalid attribute",
					fn, line);
				return -1;
			}

#ifdef ATTRIB_NMC
			/*
			 *	Convert ATTRIB_NMC into our format.
			 *	We might need to add USR to the list of
			 *	vendors first.
			 */
			if (is_nmc && vendorstr[0] == 0) {
				if (!vendor_usr_seen) {
					if (dict_addvendor("USR", VENDORPEC_USR) < 0)
						librad_log("dict_init: %s[%d]: %s", fn, line, librad_errstr);
						return -1;
					vendor_usr_seen = 1;
				}
				strcpy(vendorstr, "USR");
			}
#endif
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
				if (strcmp(typestr, dtypes[type]) == 0)
					break;
			}
			if (dtypes[type] == NULL) {
				librad_log("dict_init: %s[%d]: invalid type",
					fn, line);
				return -1;
			}

			vendor = dict_vendorname(vendorstr);
			if (vendorstr[0] && !vendor) {
				librad_log(
					"dict_init: %s[%d]: unknown vendor %s",
					fn, line, vendorstr);
				return -1;
			}

			if (dict_addattr(namestr, vendor, type, value) < 0) {
				librad_log("dict_init: %s[%d]: %s",
					   fn, line, librad_errstr);
				return -1;
			}

		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcmp(keyword, "VALUE") == 0) {

			if (sscanf(data, "%s%s%s", attrstr,
						namestr, valstr) != 3) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				return -1;
			}
			/*
			 *	For Compatibility, skip "Server-Config"
			 */
			if (strcmp(attrstr, "Server-Config") == 0)
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

			if (dict_addvalue(namestr, attrstr, value) < 0) {
				librad_log("dict_init: %s[%d]: %s", 
					   fn, line, librad_errstr);
				return -1;
			}
		}

		/*
		 *	Process VENDOR lines.
		 */
		if (strcmp(keyword, "VENDOR") == 0) {

			if (sscanf(data, "%s%s", attrstr, valstr) != 2) {
				librad_log(
				"dict_init: %s[%d] invalid vendor entry",
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
#ifdef ATTRIB_NMC
			if (value == VENDORPEC_USR)
				vendor_usr_seen = 1;
#endif
		}
	}
	fclose(fp);
	return 0;
}

/*
 *	Initialize the directory, then fix the attr member of
 *	all attributes.
 */
int dict_init(char *dir, char *fn)
{
	DICT_ATTR	*attr;
	DICT_VALUE	*dval;

	dict_free();

	if (my_dict_init(dir, fn) < 0)
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

	for (a = dictionary_attributes; a; a = a->next) {
		if (a->attr == val)
			return a;
	}

	return NULL;
}

/*
 *	Get an attribute by its name.
 */
DICT_ATTR * dict_attrbyname(char *name)
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
 */
DICT_VALUE * dict_valbyname(char *name)
{
	DICT_VALUE	*v;

	for (v = dictionary_values; v; v = v->next) {
		if (DICT_STRCMP(v->name, name) == 0)
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
int dict_vendorname(char *name)
{
	DICT_VENDOR *v;

	/*
	 *	Find the vendor, if any.
	 */
	for (v = dictionary_vendors; v; v = v->next) {
		if (strcmp(name, v->vendorname) == 0) {
			return v->vendorcode;
		}
	}

	return 0;
}
