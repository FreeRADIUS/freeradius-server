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

static const LRAD_NAME_NUMBER type_table[] = {
	{ "string",	PW_TYPE_STRING },
	{ "integer",	PW_TYPE_INTEGER },
	{ "ipaddr",	PW_TYPE_IPADDR },
	{ "date",	PW_TYPE_DATE },
	{ "abinary",	PW_TYPE_ABINARY },
	{ "octets",	PW_TYPE_OCTETS },
	{ NULL, 0 }
};

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

	memset(base_attributes, 0, sizeof(base_attributes));
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

	/* Insert at front. */
	vval->next = dictionary_vendors;
	dictionary_vendors = vval;

	return 0;
}

int dict_addattr(const char *name, int vendor, int type, int value, ATTR_FLAGS flags)
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
	DICT_ATTR	*dattr;
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

	/*
	 *	Remember which attribute is associated with this
	 *	value, if possible.
	 */
	dattr = dict_attrbyname(attrstr);
	if (dattr) {
		dval->attr = dattr->attr;
	} else {
		dval->attr = 0;
	}
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
	char	optstr[256];
	char	*p, *s, *c;
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
	ATTR_FLAGS  flags;

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
		 *  Comments should NOT be appearing anywhere but
		 *  as comments;
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
		is_attrib = 0;
		if (strcasecmp(keyword, "ATTRIBUTE") == 0)
			is_attrib = 1;

		is_nmc = 0;
		if (strcasecmp(keyword, "ATTRIB_NMC") == 0)
			is_attrib = is_nmc = 1;

		if (is_attrib) {

			vendor = 0;
			optstr[0] = 0;
			if(sscanf(data, "%s%s%s%s", namestr,
					valstr, typestr, optstr) < 3) {
				librad_log(
					"dict_init: %s[%d]: invalid ATTRIBUTE line",
					fn, line);
				fclose(fp);
				return -1;
			}

			/*
			 *	Convert ATTRIB_NMC into our format.
			 *	We might need to add USR to the list of
			 *	vendors first.
			 */
			if (is_nmc && optstr[0] == 0) {
				if (!vendor_usr_seen) {
					if (dict_addvendor("USR", VENDORPEC_USR) < 0) {
						librad_log("dict_init: %s[%d]: %s", fn, line, librad_errstr);
						fclose(fp);
						return -1;
					}
					vendor_usr_seen = 1;
				}
				strcpy(optstr, "USR");
			}

			/*
			 *	Validate all entries
			 */
			if (!isdigit((int) *valstr)) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				fclose(fp);
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
				fclose(fp);
				return -1;
			}

			/*
			 *	Ignore comments
			 */
			if (optstr[0] == '#') {
				optstr[0] = '\0';
			}

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
					        librad_log(
							   "dict_init: %s[%d] invalid option %s",
							   fn, line, s);
						fclose(fp);
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
					        librad_log(
							   "dict_init: %s[%d] invalid option %s",
							   fn, line, s);
						fclose(fp);
						return -1;
					  }
				}
				else {
				          /* Must be a vendor 'flag'... */
				          if (strncmp(s, "vendor=", 5) == 0) {
					        /* New format */
					        s += 5;   
					  }
                         
					  vendor = dict_vendorname(s);
					  if (!vendor) {
					        librad_log(
							   "dict_init: %s[%d]: unknown vendor %s",
							   fn, line, optstr);
						fclose(fp);
						return -1;
					  }
					  if (block_vendor && optstr[0] &&
					      (block_vendor != vendor)) {
					        librad_log(
							   "dict_init: %s[%d]: mismatched vendor %s within BEGIN-VENDOR/END-VENDOR block",
							   fn, line, optstr);
						fclose(fp);
						return -1;
					  }
				}
				s = strtok(NULL, ",");
			}
 
			if (block_vendor) vendor = block_vendor;

			if (dict_addattr(namestr, vendor, type, value, flags) < 0) {
				librad_log("dict_init: %s[%d]: %s",
					   fn, line, librad_errstr);
				fclose(fp);
				return -1;
			}
			continue;
		} /* ATTRIBUTE, or ATTRIB_NMC */

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(keyword, "VALUE") == 0) {
			if (sscanf(data, "%s%s%s", attrstr,
						namestr, valstr) != 3) {
				librad_log("dict_init: %s[%d]: invalid VALUE line",
					fn, line);
				fclose(fp);
				return -1;
			}
			/*
			 *	For Compatibility, skip "Server-Config"
			 */
			if (strcasecmp(attrstr, "Server-Config") == 0)
				continue;

			/*
			 *	Validate all entries
			 */
			if (!isdigit((int) *valstr)) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				fclose(fp);
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
				fclose(fp);
				return -1;
			}
#endif

			if (dict_addvalue(namestr, attrstr, value) < 0) {
				librad_log("dict_init: %s[%d]: %s", 
					   fn, line, librad_errstr);
				fclose(fp);
				return -1;
			}
			continue;
		} /* VALUE */

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(keyword, "VENDOR") == 0) {

			if (sscanf(data, "%s%s", attrstr, valstr) != 2) {
				librad_log(
				"dict_init: %s[%d] invalid VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			/*
			 *	 Validate all entries
			 */
			if (!isdigit((int) *valstr)) {
				librad_log("dict_init: %s[%d]: invalid value",
					fn, line);
				fclose(fp);
				return -1;
			}
			value = atoi(valstr);

			/* Create a new VENDOR entry for the list */
			if (dict_addvendor(attrstr, value) < 0) {
				librad_log("dict_init: %s[%d]: %s",
					   fn, line, librad_errstr);
				fclose(fp);
				return -1;
			}

			if (value == VENDORPEC_USR)
				vendor_usr_seen = 1;

			continue;
		} /* VENDOR */

		if (strcasecmp(keyword, "BEGIN-VENDOR") == 0) {
			optstr[0] = 0;
			if (sscanf(data, "%s", optstr) != 1) {
				librad_log(
				"dict_init: %s[%d] invalid BEGIN-VENDOR entry",
					fn, line);
				fclose(fp);
				return -1;
			}

			vendor = dict_vendorname(optstr);
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

			vendor = dict_vendorname(optstr);
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
		if (strcasecmp(a->name, name) == 0)
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
		    strcasecmp(v->name, name) == 0)
		 return v;
               
	}

	return NULL;
}

/*
 *	Get the vendor PEC based on the vendor name
 */
int dict_vendorname(const char *name)
{
	DICT_VENDOR *v;

	/*
	 *	Find the vendor, if any.
	 */
	for (v = dictionary_vendors; v; v = v->next) {
		if (strcasecmp(name, v->vendorname) == 0) {
			return v->vendorpec;
		}
	}

	return 0;
}
