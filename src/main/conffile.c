/*
 * conffile.c	Read the radiusd.conf file.
 *
 *		Yep I should learn to use lex & yacc, or at least
 *		write a decent parser. I know how to do that, really :)
 *		miquels@cistron.nl
 *
 * Version:	$Id$
 *
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdlib.h>
#include <string.h>

#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"
#include "token.h"
#include "modules.h"

static const char rcsid[] =
"$Id$";

#define xstrdup strdup

typedef enum conf_type {
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION
} CONF_ITEM_TYPE;

struct conf_item {
	struct conf_item *next;
	struct conf_part *parent;
	int lineno;
	CONF_ITEM_TYPE type;
};
struct conf_pair {
	CONF_ITEM item;
	char *attr;
	char *value;
	LRAD_TOKEN operator;
};
struct conf_part {
	CONF_ITEM item;
	char *name1;
	char *name2;
	struct conf_item *children;
};

/*
 *	Isolate the scary casts in these tiny provably-safe functions
 */
CONF_PAIR *cf_itemtopair(CONF_ITEM *ci)
{
	if (ci == NULL)
		return NULL;
	rad_assert(ci->type == CONF_ITEM_PAIR);
	return (CONF_PAIR *)ci;
}
CONF_SECTION *cf_itemtosection(CONF_ITEM *ci)
{
	if (ci == NULL)
		return NULL;
	rad_assert(ci->type == CONF_ITEM_SECTION);
	return (CONF_SECTION *)ci;
}
CONF_ITEM *cf_pairtoitem(CONF_PAIR *cp)
{
	if (cp == NULL)
		return NULL;
	return (CONF_ITEM *)cp;
}
CONF_ITEM *cf_sectiontoitem(CONF_SECTION *cs)
{
	if (cs == NULL)
		return NULL;
	return (CONF_ITEM *)cs;
}

/*
 *	Create a new CONF_PAIR
 */
static CONF_PAIR *cf_pair_alloc(const char *attr, const char *value,
		LRAD_TOKEN operator, CONF_SECTION *parent)
{
	CONF_PAIR *cp;

	cp = (CONF_PAIR *)rad_malloc(sizeof(CONF_PAIR));
	memset(cp, 0, sizeof(CONF_PAIR));
	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;
	cp->attr = xstrdup(attr);
	cp->value = xstrdup(value);
	cp->operator = operator;

	return cp;
}

/*
 *	Free a CONF_PAIR
 */
void cf_pair_free(CONF_PAIR **cp)
{
	if (!cp || !*cp) return;

	if ((*cp)->attr)
		free((*cp)->attr);
	if ((*cp)->value)
		free((*cp)->value);

#ifndef NDEBUG
	memset(*cp, 0, sizeof(*cp));
#endif
	free(*cp);

	*cp = NULL;
}

/*
 *	Allocate a CONF_SECTION
 */
static CONF_SECTION *cf_section_alloc(const char *name1, const char *name2,
		CONF_SECTION *parent)
{
	CONF_SECTION	*cs;

	if (name1 == NULL || !name1[0]) 
		name1 = "main";

	cs = (CONF_SECTION *)rad_malloc(sizeof(CONF_SECTION));
	memset(cs, 0, sizeof(CONF_SECTION));
	cs->item.type = CONF_ITEM_SECTION;
	cs->item.parent = parent;
	cs->name1 = strdup(name1);
	cs->name2 = (name2 && *name2) ? xstrdup(name2) : NULL;

	return cs;
}

/*
 *	Free a CONF_SECTION
 */
void cf_section_free(CONF_SECTION **cs)
{
	CONF_ITEM	*ci, *next;

	if (!cs || !*cs) return;

	for (ci = (*cs)->children; ci; ci = next) {
		next = ci->next;
		if (ci->type==CONF_ITEM_PAIR) {
			CONF_PAIR *pair = cf_itemtopair(ci);
			cf_pair_free(&pair);
		} else {
			CONF_SECTION *section = cf_itemtosection(ci);
			cf_section_free(&section);
		}
	}

	if ((*cs)->name1) 
		free((*cs)->name1);
	if ((*cs)->name2) 
		free((*cs)->name2);

	/*
	 * And free the section
	 */
#ifndef NDEBUG
	memset(*cs, 0, sizeof(*cs));
#endif
	free(*cs);

	*cs = NULL;
}

/*
 *	Add an item to a configuration section.
 */
static void cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci_new)
{
	CONF_ITEM *ci;
	
	for (ci = cs->children; ci && ci->next; ci = ci->next)
		;

	if (ci == NULL)
		cs->children = ci_new;
	else
		ci->next = ci_new;
}

/*
 *	Expand the variables in an input string.
 */
static const char *cf_expand_variables(const char *cf, int *lineno,
				       CONF_SECTION *cs,
				       char *output, const char *input)
{
	char *p;
	const char *end, *ptr;
	char name[8192];
	CONF_PAIR *cpn;
	CONF_SECTION *outercs;

	p = output;
	ptr = input;
	while (*ptr) {
		/*
		 *	Ignore anything other than "${"
		 */
		if ((*ptr == '$') && (ptr[1] == '{')) {
			/*
			 *	Look for trailing '}', and log a
			 *	warning for anything that doesn't match,
			 *	and exit with a fatal error.
			 */
			end = strchr(ptr, '}');
			if (end == NULL) {
				*p = '\0';
				radlog(L_INFO, "%s[%d]: Variable expansion missing }",
				       cf, *lineno);
				return NULL;
			}
			
			ptr += 2;
			
			memcpy(name, ptr, end - ptr);
			name[end - ptr] = '\0';
			
			cpn = cf_pair_find(cs, name);
			
			/*
			 *	Also look recursively up the section tree,
			 *	so things like ${confdir} can be defined
			 *	there and used inside the module config
			 *	sections.
			 */
			for (outercs=cs->item.parent; 
			     (cpn == NULL) && (outercs != NULL);
			     outercs=outercs->item.parent) {
				cpn = cf_pair_find(outercs, name);
			}
			if (!cpn) {
				radlog(L_ERR, "%s[%d]: Unknown variable \"%s\"",
				       cf, *lineno, name);
				return NULL;
			}
			
			/*
			 *  Substitute the value of the variable.
			 */
			strcpy(p, cpn->value);
			p += strlen(p);
			ptr = end + 1;

		} else if (memcmp(ptr, "$ENV{", 5) == 0) {
			char *env;

			ptr += 5;

			/*
			 *	Look for trailing '}', and log a
			 *	warning for anything that doesn't match,
			 *	and exit with a fatal error.
			 */
			end = strchr(ptr, '}');
			if (end == NULL) {
				*p = '\0';
				radlog(L_INFO, "%s[%d]: Environment variable expansion missing }",
				       cf, *lineno);
				return NULL;
			}
			
			memcpy(name, ptr, end - ptr);
			name[end - ptr] = '\0';
			
			/*
			 *	Get the environment variable.
			 *	If none exists, then make it an empty string.
			 */
			env = getenv(name);
			if (env == NULL) {
				*name = '\0';
				env = name;
			}

			strcpy(p, env);
			p += strlen(p);
			ptr = end + 1;

		} else {
			/*
			 *	Copy it over verbatim.
			 */
			*(p++) = *(ptr++);
		}
	} /* loop over all of the input string. */
		
	*p = '\0';

	return output;
}

/*
 *	Parse a configuration section into user-supplied variables.
 */
int cf_section_parse(CONF_SECTION *cs, void *base,
		     const CONF_PARSER *variables)
{
	int i;
	int rcode;
	char **q;
	CONF_PAIR *cp;
	CONF_SECTION *subsection;
	uint32_t ipaddr;
	char buffer[8192];
	const char *value;
	void *data;

	/*
	 *	Handle the user-supplied variables.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		value = variables[i].dflt;
		if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			data = variables[i].data;
		}

		cp = cf_pair_find(cs, variables[i].name);
		if (cp) {
			value = cp->value;
		}
		
		switch (variables[i].type)
		{
		case PW_TYPE_SUBSECTION:
			subsection = cf_section_sub_find(cs,variables[i].name);

			/*
			 *	If the configuration section is NOT there,
			 *	then ignore it.
			 *
			 *	FIXME! This is probably wrong... we should
			 *	probably set the items to their default values.
			 */
			if (subsection == NULL) {
				break;
			}

			rcode = cf_section_parse(subsection, base,
					(CONF_PARSER *) data);
			if (rcode < 0) {
				return -1;
			}
			break;

		case PW_TYPE_BOOLEAN:
			/*
			 *	Allow yes/no and on/off
			 */
			if ((strcasecmp(value, "yes") == 0) ||
					(strcasecmp(value, "on") == 0)) {
				*(int *)data = 1;
			} else if ((strcasecmp(value, "no") == 0) ||
						(strcasecmp(value, "off") == 0)) {
				*(int *)data = 0;
			} else {
				*(int *)data = 0;
				radlog(L_ERR, "Bad value \"%s\" for boolean variable %s", value, variables[i].name);
				return -1;
			}
			DEBUG2(" %s: %s = %s",
					cs->name1,
					variables[i].name,
					value);
			break;

		case PW_TYPE_INTEGER:
			*(int *)data = strtol(value, 0, 0);
			DEBUG2(" %s: %s = %d",
					cs->name1,
					variables[i].name,
					*(int *)data);
			break;
			
		case PW_TYPE_STRING_PTR:
			q = (char **) data;
			if (*q != NULL) {
				free(*q);
			}

			/*
			 *	Expand variables while parsing,
			 *	but ONLY expand ones which haven't already
			 *	been expanded.
			 */
			if (value && (value == variables[i].dflt)) {
				value = cf_expand_variables("?",
							    &cs->item.lineno,
							    cs, buffer, value);
				if (!value) {
					return -1;
				}
			}

			DEBUG2(" %s: %s = \"%s\"",
					cs->name1,
					variables[i].name,
					value ? value : "(null)");
			*q = value ? strdup(value) : NULL;
			break;

		case PW_TYPE_IPADDR:
			/*
			 *	Allow '*' as any address
			 */
			if (strcmp(value, "*") == 0) {
				*(uint32_t *) data = 0;
				break;
			}
			ipaddr = ip_getaddr(value);
			if (ipaddr == 0) {
				radlog(L_ERR, "Can't find IP address for host %s", value);
				return -1;
			}
			DEBUG2(" %s: %s = %s IP address [%s]",
					cs->name1,
					variables[i].name,
					value, ip_ntoa(buffer, ipaddr));
			*(uint32_t *) data = ipaddr;
			break;
			
		default:
			radlog(L_ERR, "type %d not supported yet", variables[i].type);
			return -1;
			break;
		} /* switch over variable type */
	} /* for all variables in the configuration section */
	
	return 0;
}

/*
 *	Read a part of the config file.
 */
static CONF_SECTION *cf_section_read(const char *cf, int *lineno, FILE *fp,
		const char *name1, const char *name2,
		CONF_SECTION *parent)
{
	CONF_SECTION *cs, *css;
	CONF_PAIR *cpn;
	char *ptr;
	const char *value;
	char buf[8192];
	char buf1[8192];
	char buf2[8192];
	char buf3[8192];
	int t1, t2, t3;
	char *cbuf = buf;
	int len;
	
	/*
	 *	Ensure that the user can't add CONF_SECTIONs
	 *	with 'internal' names;
	 */
	if ((name1 != NULL) && (name1[0] == '_')) {
		radlog(L_ERR, "%s[%d]: Illegal configuration section name",
			cf, *lineno);
		return NULL;
	}

	/*
	 *	Allocate new section.
	 */
	cs = cf_section_alloc(name1, name2, parent);
	cs->item.lineno = *lineno;

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		int eof;

		/*
		 *	Get data, and remember if we are at EOF.
		 */
		eof = (fgets(cbuf, sizeof(buf) - (cbuf - buf), fp) == NULL);
		(*lineno)++;

		len = strlen(cbuf);

		/*
		 *	We've filled the buffer, and there isn't
		 *	a CR in it.  Die!
		 */
		if ((len == sizeof(buf)) &&
		    (cbuf[len - 1] != '\n')) {
			radlog(L_ERR, "%s[%d]: Line too long",
			       cf, *lineno);
			cf_section_free(&cs);
			return NULL;
		}

		/*
		 *  Check for continuations.
		 */
		if (cbuf[len - 1] == '\n') len--;

		/*
		 *	Last character is '\\'.  Over-write it,
		 *	and read another line.
		 */
		if ((len > 0) && (cbuf[len - 1] == '\\')) {
			cbuf[len - 1] = '\0';
			cbuf += len - 1;
			continue;
		}

		/*
		 *  We're at EOF, and haven't read anything.  Stop.
		 */
		if (eof && (cbuf == buf)) {
			break;
		}

		ptr = cbuf = buf;
		t1 = gettoken(&ptr, buf1, sizeof(buf1));

		/*
		 *	Skip comments and blank lines immediately.
		 */
		if ((*buf1 == '#') || (*buf1 == '\0')) {
			continue;
		}

		/*
		 *	Allow for $INCLUDE files
		 *
		 *      This *SHOULD* work for any level include.  
		 *      I really really really hate this file.  -cparker
		 */
		if (strcasecmp(buf1, "$INCLUDE") == 0) {

			CONF_SECTION      *is;

			t2 = getword(&ptr, buf2, sizeof(buf2));

			value = cf_expand_variables(cf, lineno, cs, buf, buf2);
			if (value == NULL) {
				cf_section_free(&cs);
				return NULL;
			}

			DEBUG2( "Config:   including file: %s", value );

			if ((is = conf_read(cf, *lineno, value, parent)) == NULL) {
				cf_section_free(&cs);
				return NULL;
			}

			/*
			 *	Add the included conf to our CONF_SECTION
			 */
			if (is != NULL) {
				if (is->children != NULL) {
					CONF_ITEM *ci;
			
					/*
					 *	Re-write the parent of the
					 *	moved children to be the
					 *	upper-layer section.
					 */
					for (ci = is->children; ci; ci = ci->next) {
						ci->parent = cs;
					}

					/*
					 *	If there are children, then
					 *	move them up a layer.
					 */
					if (is->children) {
						cf_item_add(cs, is->children);
					}
					is->children = NULL;
				}
				/*
				 *	Always free the section for the
				 *	$INCLUDEd file.
				 */
				cf_section_free(&is);
			}

			continue;
		}

		/*
		 *	No '=': must be a section or sub-section.
		 */
		if (strchr(ptr, '=') == NULL) {
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = gettoken(&ptr, buf3, sizeof(buf3));
		} else {
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = getword(&ptr, buf3, sizeof(buf3));
		}

		/*
		 *	See if it's the end of a section.
		 */
		if (t1 == T_RCBRACE) {
			if (name1 == NULL || buf2[0]) {
				radlog(L_ERR, "%s[%d]: Unexpected end of section",
						cf, *lineno);
				cf_section_free(&cs);
				return NULL;
			}
			return cs;
		}

		/*
		 * Perhaps a subsection.
		 */
		if (t2 == T_LCBRACE || t3 == T_LCBRACE) {
			css = cf_section_read(cf, lineno, fp, buf1,
					t2==T_LCBRACE ? NULL : buf2, cs);
			if (css == NULL) {
				cf_section_free(&cs);
				return NULL;
			}
			cf_item_add(cs, cf_sectiontoitem(css));

			continue;
		}

		/*
		 *	Ignore semi-colons.
		 */
		if (*buf2 == ';') 
			*buf2 = '\0';

		/*
		 *	Must be a normal attr = value line.
		 */
		if (buf1[0] != 0 && buf2[0] == 0 && buf3[0] == 0) {
			t2 = T_OP_EQ;
		} else if (buf1[0] == 0 || buf2[0] == 0 || 
			   (t2 < T_EQSTART || t2 > T_EQEND)) {
			radlog(L_ERR, "%s[%d]: Line is not in 'attribute = value' format",
					cf, *lineno);
			cf_section_free(&cs);
			return NULL;
		}

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			radlog(L_ERR, "%s[%d]: Illegal configuration pair name \"%s\"",
					cf, *lineno, buf1);
			cf_section_free(&cs);
			return NULL;
		}

		/*
		 *	Handle variable substitution via ${foo}
		 */
		value = cf_expand_variables(cf, lineno, cs, buf, buf3);
		if (!value) {
			cf_section_free(&cs);
			return NULL;
		}


		/*
		 *	Add this CONF_PAIR to our CONF_SECTION
		 */
		cpn = cf_pair_alloc(buf1, value, t2, parent);
		cpn->item.lineno = *lineno;
		cf_item_add(cs, cf_pairtoitem(cpn));
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (name1 != NULL) {
		radlog(L_ERR, "%s[%d]: Unexpected end of file", cf, *lineno);
		cf_section_free(&cs);
		return NULL;
	}

	return cs;
}

/*
 *	Read the config file.
 */
CONF_SECTION *conf_read(const char *fromfile, int fromline, 
			const char *conffile, CONF_SECTION *parent)
{
	FILE		*fp;
	int		lineno = 0;
	CONF_SECTION	*cs;
	
	if ((fp = fopen(conffile, "r")) == NULL) {
		if (fromfile) {
			radlog(L_ERR|L_CONS, "%s[%d]: Unable to open file \"%s\": %s",
					fromfile, fromline, conffile, strerror(errno));
		} else {
			radlog(L_ERR|L_CONS, "Unable to open file \"%s\": %s",
					conffile, strerror(errno));
		}
		return NULL;
	}

	if(parent) {
	    cs = cf_section_read(conffile, &lineno, fp, NULL, NULL, parent);
	} else {
	    cs = cf_section_read(conffile, &lineno, fp, NULL, NULL, NULL);
	}

	fclose(fp);

	return cs;
}


/* 
 * Return a CONF_PAIR within a CONF_SECTION.
 */
CONF_PAIR *cf_pair_find(CONF_SECTION *section, const char *name)
{
	CONF_ITEM	*ci;

	if (section == NULL) {
		section = mainconfig.config;
	}

	for (ci = section->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR)
			continue;
		if (name == NULL || strcmp(cf_itemtopair(ci)->attr, name) == 0)
			break;
	}

	return cf_itemtopair(ci);
}

/*
 * Return the attr of a CONF_PAIR
 */

char *cf_pair_attr(CONF_PAIR *pair)
{
	return (pair ? pair->attr : NULL);
}

/*
 * Return the value of a CONF_PAIR
 */

char *cf_pair_value(CONF_PAIR *pair)
{
	return (pair ? pair->value : NULL);
}

/*
 * Return the first label of a CONF_SECTION
 */

char *cf_section_name1(CONF_SECTION *section)
{
	return (section ? section->name1 : NULL);
}

/*
 * Return the second label of a CONF_SECTION
 */

char *cf_section_name2(CONF_SECTION *section)
{
	return (section ? section->name2 : NULL);
}

/* 
 * Find a value in a CONF_SECTION
 */
char *cf_section_value_find(CONF_SECTION *section, const char *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(section, attr);

	return (cp ? cp->value : NULL);
}

/*
 * Return the next pair after a CONF_PAIR
 * with a certain name (char *attr) If the requested
 * attr is NULL, any attr matches.
 */

CONF_PAIR *cf_pair_find_next(CONF_SECTION *section, CONF_PAIR *pair, const char *attr)
{
	CONF_ITEM	*ci;

	/*
	 * If pair is NULL this must be a first time run
	 * Find the pair with correct name
	 */

	if (pair == NULL){
		return cf_pair_find(section, attr);
	}

	ci = cf_pairtoitem(pair)->next;

	for (; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR)
			continue;
		if (attr == NULL || strcmp(cf_itemtopair(ci)->attr, attr) == 0)
			break;
	}

	return cf_itemtopair(ci);
}

/*
 * Find a CONF_SECTION, or return the root if name is NULL
 */

CONF_SECTION *cf_section_find(const char *name)
{
	if (name)
		return cf_section_sub_find(mainconfig.config, name);
	else
		return mainconfig.config;
}

/*
 * Find a sub-section in a section
 */

CONF_SECTION *cf_section_sub_find(CONF_SECTION *section, const char *name)
{
	CONF_ITEM *ci;

	for (ci = section->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;
		if (strcmp(cf_itemtosection(ci)->name1, name) == 0)
			break;
	}

	return cf_itemtosection(ci);

}

/*
 * Return the next subsection after a CONF_SECTION
 * with a certain name1 (char *name1). If the requested
 * name1 is NULL, any name1 matches.
 */

CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
		CONF_SECTION *subsection,
		const char *name1)
{
	CONF_ITEM	*ci;

	/*
	 * If subsection is NULL this must be a first time run
	 * Find the subsection with correct name
	 */

	if (subsection == NULL){
		ci = section->children;
	} else {
		ci = cf_sectiontoitem(subsection)->next;
	}

	for (; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;
		if ((name1 == NULL) || 
				(strcmp(cf_itemtosection(ci)->name1, name1) == 0))
			break;
	}

	return cf_itemtosection(ci);
}

/*
 * Return the next item after a CONF_ITEM.
 */

CONF_ITEM *cf_item_find_next(CONF_SECTION *section, CONF_ITEM *item)
{
	/*
	 * If item is NULL this must be a first time run
	 * Return the first item
	 */

	if (item == NULL) {
		return section->children;
	} else {
		return item->next;
	}
}

int cf_section_lineno(CONF_SECTION *section)
{
	return cf_sectiontoitem(section)->lineno;
}

int cf_pair_lineno(CONF_PAIR *pair)
{
	return cf_pairtoitem(pair)->lineno;
}

int cf_item_is_section(CONF_ITEM *item)
{
	return item->type == CONF_ITEM_SECTION;
}


#if 0
/* 
 * JMG dump_config tries to dump the config structure in a readable format
 * 
*/

static int dump_config_section(CONF_SECTION *cs, int indent)
{
	CONF_SECTION	*scs;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;

	/* The DEBUG macro doesn't let me
	 *   for(i=0;i<indent;++i) debugputchar('\t');
	 * so I had to get creative. --Pac. */

	for (ci = cs->children; ci; ci = ci->next) {
		if (ci->type == CONF_ITEM_PAIR) {
			cp=cf_itemtopair(ci);
			DEBUG("%.*s%s = %s",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				cp->attr, cp->value);
		} else {
			scs=cf_itemtosection(ci);
			DEBUG("%.*s%s %s%s{",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				scs->name1,
				scs->name2 ? scs->name2 : "",
				scs->name2 ?  " " : "");
			dump_config_section(scs, indent+1);
			DEBUG("%.*s}",
				indent, "\t\t\t\t\t\t\t\t\t\t\t");
		}
	}

	return 0;
}

int dump_config(void)
{
	return dump_config_section(mainconfig.config, 0);
}
#endif
