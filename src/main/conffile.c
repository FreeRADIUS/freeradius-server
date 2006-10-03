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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/autoconf.h>

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#endif

#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>

static const char rcsid[] =
"$Id$";

typedef enum conf_type {
	CONF_ITEM_INVALID = 0,
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION,
	CONF_ITEM_DATA
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
	const char *name1;
	const char *name2;
	struct conf_item *children;
	struct conf_item *tail;	/* for speed */
	rbtree_t	*pair_tree; /* and a partridge.. */
	rbtree_t	*section_tree; /* no jokes here */
	rbtree_t	*name2_tree; /* for sections of the same name2 */
	rbtree_t	*data_tree;
};


/*
 *	Internal data that is associated with a configuration section,
 *	so that we don't have to track it separately.
 */
struct conf_data {
	CONF_ITEM  item;
	const char *name;
	int	   flag;
	void	   *data;	/* user data */
	void       (*free)(void *); /* free user data function */
};


static int cf_data_add_internal(CONF_SECTION *cs, const char *name,
				void *data, void (*data_free)(void *),
				int flag);
static void *cf_data_find_internal(CONF_SECTION *cs, const char *name,
				   int flag);

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

static CONF_DATA *cf_itemtodata(CONF_ITEM *ci)
{
	if (ci == NULL)
		return NULL;
	rad_assert(ci->type == CONF_ITEM_DATA);
	return (CONF_DATA *)ci;
}
static CONF_ITEM *cf_datatoitem(CONF_DATA *cd)
{
	if (cd == NULL)
		return NULL;
	return (CONF_ITEM *)cd;
}

/*
 *	Create a new CONF_PAIR
 */
static CONF_PAIR *cf_pair_alloc(const char *attr, const char *value,
				LRAD_TOKEN operator, CONF_SECTION *parent)
{
	CONF_PAIR *cp;

	cp = rad_malloc(sizeof(*cp));
	memset(cp, 0, sizeof(*cp));
	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;
	cp->attr = strdup(attr);
	cp->value = strdup(value);
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


static void cf_data_free(CONF_DATA **cd)
{
	if (!cd || !*cd) return;

	free((*cd)->name);
	if (!(*cd)->free) {
		free((*cd)->data);
	} else {
		((*cd)->free)((*cd)->data);
	}
#ifndef NDEBUG
	memset(*cd, 0, sizeof(*cd));
#endif
	free(*cd);
	*cd = NULL;
}

/*
 *	rbtree callback function
 */
static int pair_cmp(const void *a, const void *b)
{
	const CONF_PAIR *one = a;
	const CONF_PAIR *two = b;

	return strcmp(one->attr, two->attr);
}


/*
 *	rbtree callback function
 */
static int section_cmp(const void *a, const void *b)
{
	const CONF_SECTION *one = a;
	const CONF_SECTION *two = b;

	return strcmp(one->name1, two->name1);
}


/*
 *	rbtree callback function
 */
static int name2_cmp(const void *a, const void *b)
{
	const CONF_SECTION *one = a;
	const CONF_SECTION *two = b;

	rad_assert(strcmp(one->name1, two->name1) == 0);

	if (!one->name2 && !two->name2) return 0;
	if (!one->name2) return -1;
	if (!two->name2) return +1;

	return strcmp(one->name2, two->name2);
}


/*
 *	rbtree callback function
 */
static int data_cmp(const void *a, const void *b)
{
	int rcode;

	const CONF_DATA *one = a;
	const CONF_DATA *two = b;

	rcode = one->flag - two->flag;
	if (rcode != 0) return rcode;

	return strcmp(one->name, two->name);
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

		switch (ci->type) {
		case CONF_ITEM_PAIR: {
				CONF_PAIR *pair = cf_itemtopair(ci);
				cf_pair_free(&pair);
			}
			break;

		case CONF_ITEM_SECTION: {
				
				CONF_SECTION *section = cf_itemtosection(ci);
				cf_section_free(&section);
			}
			break;

		case CONF_ITEM_DATA: {
				CONF_DATA *data = cf_itemtodata(ci);
				cf_data_free(&data);
			}
			break;

		default:	/* should really be an error. */
			break;
		}
	}

	if ((*cs)->name1)
		free((*cs)->name1);
	if ((*cs)->name2)
		free((*cs)->name2);
	if ((*cs)->pair_tree)
		rbtree_free((*cs)->pair_tree);
	if ((*cs)->section_tree)
		rbtree_free((*cs)->section_tree);
	if ((*cs)->name2_tree)
		rbtree_free((*cs)->name2_tree);
	if ((*cs)->data_tree)
		rbtree_free((*cs)->data_tree);

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
 *	Allocate a CONF_SECTION
 */
static CONF_SECTION *cf_section_alloc(const char *name1, const char *name2,
				      CONF_SECTION *parent)
{
	CONF_SECTION	*cs;

	if (!name1) return NULL;

	cs = rad_malloc(sizeof(*cs));
	memset(cs, 0, sizeof(*cs));
	cs->item.type = CONF_ITEM_SECTION;
	cs->item.parent = parent;
	cs->name1 = strdup(name1);
	if (!cs->name1) {
		cf_section_free(&cs);
		return NULL;
	}
	
	if (name2 && *name2) {
		cs->name2 = strdup(name2);
		if (!cs->name2) {
			cf_section_free(&cs);
			return NULL;
		}
	}
	cs->pair_tree = rbtree_create(pair_cmp, NULL, 0);
	if (!cs->pair_tree) {
		cf_section_free(&cs);
		return NULL;
	}

	/*
	 *	Don't create a data tree, it may not be needed.
	 */

	/*
	 *	Don't create the section tree here, it may not
	 *	be needed.
	 */
	return cs;
}


/*
 *	Add an item to a configuration section.
 */
static void cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci)
{
	if (!cs->children) {
		rad_assert(cs->tail == NULL);
		cs->children = ci;
	} else {
		rad_assert(cs->tail != NULL);
		cs->tail->next = ci;
	}

	/*
	 *	Update the trees (and tail) for each item added.
	 */
	for (/* nothing */; ci != NULL; ci = ci->next) {
		cs->tail = ci;

		/*
		 *	For fast lookups, pair's and sections get
		 *	added to rbtree's.
		 */
		switch (ci->type) {
			case CONF_ITEM_PAIR:
				rbtree_insert(cs->pair_tree, ci);
				break;
				
			case CONF_ITEM_SECTION: {
				const CONF_SECTION *cs_new = cf_itemtosection(ci);
				
				if (!cs->section_tree) {
					cs->section_tree = rbtree_create(section_cmp, NULL, 0);
					/* ignore any errors */
				}
				
				if (cs->section_tree) {
					rbtree_insert(cs->section_tree, cs_new);				}
				
				/*
				 *	Two names: find the named instance.
				 */
				if (cs_new->name2) {
					CONF_SECTION *old_cs;
					
					/*
					 *	Find the FIRST
					 *	CONF_SECTION having
					 *	the given name1, and
					 *	create a new tree
					 *	under it.
					 */
					old_cs = rbtree_finddata(cs->section_tree, cs_new);
					if (!old_cs) return; /* this is a bad error! */
					
					if (!old_cs->name2_tree) {
						old_cs->name2_tree = rbtree_create(name2_cmp,
										   NULL, 0);
					}
					if (old_cs->name2_tree) {
						rbtree_insert(old_cs->name2_tree, cs_new);
					}
				} /* had a name2 */
				break;
			} /* was a section */

			case CONF_ITEM_DATA:
				if (!cs->data_tree) {
					cs->data_tree = rbtree_create(data_cmp, NULL, 0);
				}
				if (cs->data_tree) {
					rbtree_insert(cs->data_tree, ci);
				}
				break;

			default: /* FIXME: assert & error! */
				break;

		} /* switch over conf types */
	} /* loop over ci */
}

/*
 *	Expand the variables in an input string.
 */
static const char *cf_expand_variables(const char *cf, int *lineno,
				       const CONF_SECTION *outercs,
				       char *output, const char *input)
{
	char *p;
	const char *end, *ptr;
	char name[8192];
	const CONF_SECTION *parentcs;

	/*
	 *	Find the master parent conf section.
	 *	We can't use mainconfig.config, because we're in the
	 *	process of re-building it, and it isn't set up yet...
	 */
	for (parentcs = outercs;
	     parentcs->item.parent != NULL;
	     parentcs = parentcs->item.parent) {
		/* do nothing */
	}

	p = output;
	ptr = input;
	while (*ptr) {
		/*
		 *	Ignore anything other than "${"
		 */
		if ((*ptr == '$') && (ptr[1] == '{')) {
			int up;
			CONF_PAIR *cp;
			const CONF_SECTION *cs;

			/*
			 *	FIXME: Add support for ${foo:-bar},
			 *	like in xlat.c
			 */

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

			cp = NULL;
			up = 0;

			/*
			 *	${.foo} means "foo from the current section"
			 */
			if (*ptr == '.') {
				up = 1;
				cs = outercs;
				ptr++;

				/*
				 *	${..foo} means "foo from the section
				 *	enclosing this section" (etc.)
				 */
				while (*ptr == '.') {
					if (cs->item.parent)
						cs = cs->item.parent;
					ptr++;
				}

			} else {
				const char *q;
				/*
				 *	${foo} is local, with
				 *	main as lower priority
				 */
				cs = outercs;

				/*
				 *	${foo.bar.baz} is always rooted
				 *	from the top.
				 */
				for (q = ptr; *q && q != end; q++) {
					if (*q == '.') {
						cs = parentcs;
						up = 1;
						break;
					}
				}
			}

			while (cp == NULL) {
				char *q;
				/*
				 *	Find the next section.
				 */
				for (q = name;
				     (*ptr != 0) && (*ptr != '.') &&
					     (ptr != end);
				     q++, ptr++) {
					*q = *ptr;
				}
				*q = '\0';

				/*
				 *	The character is a '.', find a
				 *	section (as the user has given
				 *	us a subsection to find)
				 */
				if (*ptr == '.') {
					CONF_SECTION *next;

					ptr++;	/* skip the period */

					/*
					 *	Find the sub-section.
					 */
					next = cf_section_sub_find(cs, name);
					if (next == NULL) {
						radlog(L_ERR, "config: No such section %s in variable %s", name, input);
						return NULL;
					}
					cs = next;

				} else { /* no period, must be a conf-part */
					/*
					 *	Find in the current referenced
					 *	section.
					 */
					cp = cf_pair_find(cs, name);
					if (cp == NULL) {
						/*
						 *	It it was NOT ${..foo}
						 *	then look in the
						 *	top-level config items.
						 */
						if (!up) cp = cf_pair_find(parentcs, name);
					}
					if (cp == NULL) {
						radlog(L_ERR, "config: No such configuration item %s in section %s when expanding string \"%s\"", name,
						       cf_section_name1(cs),
						       input);
						return NULL;
					}
				}
			} /* until cp is non-NULL */

			/*
			 *  Substitute the value of the variable.
			 */
			strcpy(p, cp->value);
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
 *	Parses an item (not a CONF_ITEM) into the specified format,
 *	with a default value.
 *
 *	Returns -1 on error, 0 for correctly parsed, and 1 if the
 *	default value was used.  Note that the default value will be
 *	used ONLY if the CONF_PAIR is NULL.
 */
int cf_item_parse(CONF_SECTION *cs, const char *name,
		  int type, void *data, const char *dflt)
{
	int rcode = 0;
	char **q;
	const char *value;
	lrad_ipaddr_t ipaddr;
	const CONF_PAIR *cp;
	char ipbuf[128];

	cp = cf_pair_find(cs, name);
	if (cp) {
		value = cp->value;

	} else if (!dflt) {
		return 1;	/* nothing to parse, return default value */

	} else {
		rcode = 1;
		value = dflt;
	}

	switch (type) {
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
			radlog(L_ERR, "Bad value \"%s\" for boolean variable %s", value, name);
			return -1;
		}
		DEBUG2(" %s: %s = %s", cs->name1, name, value);
		break;
		
	case PW_TYPE_INTEGER:
		*(int *)data = strtol(value, 0, 0);
		DEBUG2(" %s: %s = %d",
		       cs->name1, name,
		       *(int *)data);
		break;
		
	case PW_TYPE_STRING_PTR:
		q = (char **) data;
		if (*q != NULL) {
			free(*q);
		}
		
		/*
		 *	Expand variables which haven't already been
		 *	expanded automagically when the configuration
		 *	file was read.
		 */
		if (value == dflt) {
			char buffer[8192];

			int lineno = cs->item.lineno;

			/*
			 *	FIXME: sizeof(buffer)?
			 */
			value = cf_expand_variables("?",
						    &lineno,
						    cs, buffer, value);
			if (!value) return -1;
		}
		
		DEBUG2(" %s: %s = \"%s\"",
		       cs->name1, name,
		       value ? value : "(null)");
		*q = value ? strdup(value) : NULL;
		break;
		
		/*
		 *	This is the same as PW_TYPE_STRING_PTR,
		 *	except that we also "stat" the file, and
		 *	cache the result.
		 */
	case PW_TYPE_FILENAME:
		q = (char **) data;
		if (*q != NULL) {
			free(*q);
		}
		
		/*
		 *	Expand variables which haven't already been
		 *	expanded automagically when the configuration
		 *	file was read.
		 */
		if (value == dflt) {
			char buffer[8192];

			int lineno = cs->item.lineno;

			/*
			 *	FIXME: sizeof(buffer)?
			 */
			value = cf_expand_variables("?",
						    &lineno,
						    cs, buffer, value);
			if (!value) return -1;
		}
		
		DEBUG2(" %s: %s = \"%s\"",
		       cs->name1, name,
		       value ? value : "(null)");
		*q = value ? strdup(value) : NULL;

		/*
		 *	And now we "stat" the file.
		 */
		if (*q) {
			struct stat buf;

			if (stat(*q, &buf) == 0) {
				time_t *mtime;

				mtime = rad_malloc(sizeof(*mtime));
				*mtime = buf.st_mtime;
				/* FIXME: error? */
				cf_data_add_internal(cs, *q, mtime, free,
						     PW_TYPE_FILENAME);
			}
		}
		break;

	case PW_TYPE_IPADDR:
		/*
		 *	Allow '*' as any address
		 */
		if (strcmp(value, "*") == 0) {
			*(uint32_t *) data = htonl(INADDR_ANY);
			DEBUG2(" %s: %s = *", cs->name1, name);
			break;
		}
		if (ip_hton(value, AF_INET, &ipaddr) < 0) {
			radlog(L_ERR, "Can't find IP address for host %s", value);
			return -1;
		}
		DEBUG2(" %s: %s = %s IP address [%s]",
		       cs->name1, name, value,
		       ip_ntoh(&ipaddr, ipbuf, sizeof(ipbuf)));
		*(uint32_t *) data = ipaddr.ipaddr.ip4addr.s_addr;
		break;
		
	case PW_TYPE_IPV6ADDR:
		if (ip_hton(value, AF_INET6, &ipaddr) < 0) {
			radlog(L_ERR, "Can't find IPv6 address for host %s", value);
			return -1;
		}
		DEBUG2(" %s: %s = %s IPv6 address [%s]",
		       cs->name1, name, value,
		       ip_ntoh(&ipaddr, ipbuf, sizeof(ipbuf)));
		memcpy(data, &ipaddr.ipaddr.ip6addr,
		       sizeof(ipaddr.ipaddr.ip6addr));
		break;
		
	default:
		radlog(L_ERR, "type %d not supported yet", type);
		return -1;
		break;
	} /* switch over variable type */
	
	return rcode;
}

/*
 *	Parse a configuration section into user-supplied variables.
 */
int cf_section_parse(const CONF_SECTION *cs, void *base,
		     const CONF_PARSER *variables)
{
	int i;
	void *data;

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	Handle subsections specially
		 */
		if (variables[i].type == PW_TYPE_SUBSECTION) {
			const CONF_SECTION *subcs;
			subcs = cf_section_sub_find(cs, variables[i].name);
			
			/*
			 *	If the configuration section is NOT there,
			 *	then ignore it.
			 *
			 *	FIXME! This is probably wrong... we should
			 *	probably set the items to their default values.
			 */
			if (!subcs) continue;

			if (!variables[i].dflt) {
				DEBUG2("Internal sanity check 1 failed in cf_section_parse");
				return -1;
			}
			
			if (cf_section_parse(subcs, base,
					     (const CONF_PARSER *) variables[i].dflt) < 0) {
				return -1;
			}
			continue;
		} /* else it's a CONF_PAIR */
		
		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			DEBUG2("Internal sanity check 2 failed in cf_section_parse");
			return -1;
		}

		/*
		 *	Parse the pair we found, or a default value.
		 */
		if (cf_item_parse(cs, variables[i].name, variables[i].type,
				  data, variables[i].dflt) < 0) {
			return -1;
		}
	} /* for all variables in the configuration section */

	return 0;
}


/*
 *	Free strings we've parsed into data structures.
 */
void cf_section_parse_free_strings(void *base, const CONF_PARSER *variables)
{
	int i;

	if (!variables) return;
	
	/*
	 *	Free up dynamically allocated string pointers.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		char **p;

		if ((variables[i].type != PW_TYPE_STRING_PTR) &&
		    (variables[i].type != PW_TYPE_FILENAME)) {
			continue;
		}
		
		/*
		 *	Prefer the data, if it's there.
		 *	Else use the base + offset.
		 */
		if (variables[i].data) {
			p = (char **) &(variables[i].data);
		} else {
			p = (char **) (((char *)base) + variables[i].offset);
		}
		free(*p);
		*p = NULL;
	}
}


/*
 *	Read a part of the config file.
 */
static int cf_section_read(const char *file, int *lineno, FILE *fp,
			   CONF_SECTION *current)

{
	CONF_SECTION *this, *css;
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

	this = current;		/* add items here */

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
		if ((len == (sizeof(buf) - 1)) &&
		    (cbuf[len - 1] != '\n')) {
			radlog(L_ERR, "%s[%d]: Line too long",
			       file, *lineno);
			return -1;
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

               if ((*buf1 == '#') || (*buf1 == '\0')) {
                       continue;
	       }

		/*
		 *	The caller eats "name1 name2 {", and calls us
		 *	for the data inside of the section.  So if we
		 *	receive a closing brace, then it must mean the
		 *	end of the section.
		 */
	       if (t1 == T_RCBRACE) {
		       if (this == current) {
			       radlog(L_ERR, "%s[%d]: Too many closing braces",
				      file, *lineno);
			       return -1;
			       
		       }
		       this = this->item.parent;
		       continue;
		}

		/*
		 *	Allow for $INCLUDE files
		 *
		 *      This *SHOULD* work for any level include.
		 *      I really really really hate this file.  -cparker
		 */
		if (strcasecmp(buf1, "$INCLUDE") == 0) {
			t2 = getword(&ptr, buf2, sizeof(buf2));

			value = cf_expand_variables(file, lineno, this, buf, buf2);
			if (!value) return -1;

#ifdef HAVE_DIRENT_H
			/*
			 *	$INCLUDE foo/
			 *
			 *	Include ALL non-"dot" files in the directory.
			 *	careful!
			 */
			if (value[strlen(value) - 1] == '/') {
				DIR		*dir;
				struct dirent	*dp;
				struct stat stat_buf;

				DEBUG2( "Config:   including files in directory: %s", value );
				dir = opendir(value);
				if (!dir) {
					radlog(L_ERR, "%s[%d]: Error reading directory %s: %s",
					       file, *lineno, value,
					       strerror(errno));
					return -1;
				}

				/*
				 *	Read the directory, ignoring "." files.
				 */
				while ((dp = readdir(dir)) != NULL) {
					const char *p;

					if (dp->d_name[0] == '.') continue;

					/*
					 *	Check for valid characters
					 */
					for (p = dp->d_name; *p != '\0'; p++) {
						if (isalpha((int)*p) ||
						    isdigit((int)*p) ||
						    (*p == '_') ||
						    (*p == '.')) continue;
						break;
					}
					if (*p != '\0') continue;

					snprintf(buf2, sizeof(buf2), "%s%s",
						 value, dp->d_name);
					if ((stat(buf2, &stat_buf) != 0) ||
					    S_ISDIR(stat_buf.st_mode)) continue;
					/*
					 *	Read the file into the current
					 *	configuration sectoin.
					 */
					if (cf_file_include(buf2, this) < 0) {
						closedir(dir);
						return -1;
					}
				}
				closedir(dir);
			}  else
#endif
			{ /* it was a normal file */
				if (cf_file_include(value, this) < 0) {
					return -1;
				}
			}
			continue;
		} /* we were in an include */

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
		 * Perhaps a subsection.
		 */
		if (t2 == T_LCBRACE || t3 == T_LCBRACE) {
			css = cf_section_alloc(buf1,
					       t2 == T_LCBRACE ? NULL : buf2,
					       this);
			if (!css) {
				radlog(L_ERR, "%s[%d]: Failed allocating memory for section",
						file, *lineno);
			}
			cf_item_add(this, cf_sectiontoitem(css));
			css->item.lineno = *lineno;

			/*
			 *	The current section is now the child section.
			 */
			this = css;
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
					file, *lineno);
			return -1;
		}

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			radlog(L_ERR, "%s[%d]: Illegal configuration pair name \"%s\"",
					file, *lineno, buf1);
			return -1;
		}

		/*
		 *	Handle variable substitution via ${foo}
		 */
		value = cf_expand_variables(file, lineno, this, buf, buf3);
		if (!value) return -1;


		/*
		 *	Add this CONF_PAIR to our CONF_SECTION
		 */
		cpn = cf_pair_alloc(buf1, value, t2, this);
		cpn->item.lineno = *lineno;
		cf_item_add(this, cf_pairtoitem(cpn));
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (feof(fp) && (this != current)) {
		radlog(L_ERR, "%s[%d]: EOF reached without closing brace for section %s starting at line %d",
		       file, *lineno,
		       cf_section_name1(this), cf_section_lineno(this));
		return -1;
	}

	return 0;
}

/*
 *	Include one config file in another.
 */
int cf_file_include(const char *file, CONF_SECTION *cs)
{
	FILE		*fp;
	int		lineno = 0;
	struct stat	buf;

	DEBUG2( "Config:   including file: %s", file);

	fp = fopen(file, "r");
	if (!fp) {
		radlog(L_ERR|L_CONS, "Unable to open file \"%s\": %s",
		       file, strerror(errno));
		return -1;
	}

	/*
	 *	Read the section.  It's OK to have EOF without a
	 *	matching close brace.
	 */
	if (cf_section_read(file, &lineno, fp, cs) < 0) {
		fclose(fp);
		return -1;
	}

	/*
	 *	Add the filename to the section
	 */
	if (stat(file, &buf) == 0) {
		time_t *mtime;
		
		mtime = rad_malloc(sizeof(*mtime));
		*mtime = buf.st_mtime;
		/* FIXME: error? */
		cf_data_add_internal(cs, file, mtime, free,
				     PW_TYPE_FILENAME);
	}

	fclose(fp);
	return 0;
}

/*
 *	Bootstrap a config file.
 */
CONF_SECTION *cf_file_read(const char *file)
{
	CONF_SECTION *cs;

	cs = cf_section_alloc("main", NULL, NULL);
	if (!cs) return NULL;

	if (cf_file_include(file, cs) < 0) {
		cf_section_free(&cs);
		return NULL;
	}

	return cs;
}

/*
 * Return a CONF_PAIR within a CONF_SECTION.
 */
CONF_PAIR *cf_pair_find(const CONF_SECTION *cs, const char *name)
{
	CONF_ITEM	*ci;

	if (!cs) cs = mainconfig.config;

	/*
	 *	Find the name in the tree, for speed.
	 */
	if (name) {
		CONF_PAIR mycp;

		mycp.attr = name;
		return rbtree_finddata(cs->pair_tree, &mycp);
	}

	/*
	 *	Else find the first one
	 */
	for (ci = cs->children; ci; ci = ci->next) {
		if (ci->type == CONF_ITEM_PAIR)
			return cf_itemtopair(ci);
	}
	
	return NULL;
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

const char *cf_section_name1(const CONF_SECTION *cs)
{
	return (cs ? cs->name1 : NULL);
}

/*
 * Return the second label of a CONF_SECTION
 */

const char *cf_section_name2(const CONF_SECTION *cs)
{
	return (cs ? cs->name2 : NULL);
}

/*
 * Find a value in a CONF_SECTION
 */
char *cf_section_value_find(const CONF_SECTION *cs, const char *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(cs, attr);

	return (cp ? cp->value : NULL);
}

/*
 * Return the next pair after a CONF_PAIR
 * with a certain name (char *attr) If the requested
 * attr is NULL, any attr matches.
 */

CONF_PAIR *cf_pair_find_next(const CONF_SECTION *cs,
			     const CONF_PAIR *pair, const char *attr)
{
	CONF_ITEM	*ci;

	/*
	 * If pair is NULL this must be a first time run
	 * Find the pair with correct name
	 */

	if (pair == NULL){
		return cf_pair_find(cs, attr);
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

CONF_SECTION *cf_section_sub_find(const CONF_SECTION *cs, const char *name)
{
	CONF_ITEM *ci;

	/*
	 *	Do the fast lookup if possible.
	 */
	if (name && cs->section_tree) {
		CONF_SECTION mycs;

		mycs.name1 = name;
		mycs.name2 = NULL;
		return rbtree_finddata(cs->section_tree, &mycs);
	}

	for (ci = cs->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;
		if (strcmp(cf_itemtosection(ci)->name1, name) == 0)
			break;
	}

	return cf_itemtosection(ci);

}


/*
 *	Find a CONF_SECTION with both names.
 */
CONF_SECTION *cf_section_sub_find_name2(const CONF_SECTION *cs,
					const char *name1, const char *name2)
{
	CONF_ITEM    *ci;

	if (!name2) return cf_section_sub_find(cs, name1);

	if (!cs) cs = mainconfig.config;

	if (name1 && (cs->section_tree)) {
		CONF_SECTION mycs, *master_cs;
		
		mycs.name1 = name1;
		mycs.name2 = name2;
		
		master_cs = rbtree_finddata(cs->section_tree, &mycs);
		if (master_cs) {
			return rbtree_finddata(master_cs->name2_tree, &mycs);
		}
	}

	/*
	 *	Else do it the old-fashioned way.
	 */
	for (ci = cs->children; ci; ci = ci->next) {
		CONF_SECTION *subcs;

		if (ci->type != CONF_ITEM_SECTION)
			continue;

		subcs = cf_itemtosection(ci);
		if (!name1) {
			if (!subcs->name2) {
				if (strcmp(subcs->name1, name2) == 0) break;
			} else {
				if (strcmp(subcs->name2, name2) == 0) break;
			}
			continue; /* don't do the string comparisons below */
		}

		if ((strcmp(subcs->name1, name1) == 0) &&
		    (subcs->name2 != NULL) &&
		    (strcmp(subcs->name2, name2) == 0))
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
int cf_item_is_pair(CONF_ITEM *item)
{
	return item->type == CONF_ITEM_PAIR;
}


static CONF_DATA *cf_data_alloc(CONF_SECTION *parent, const char *name,
				void *data, void (*data_free)(void *))
{
	CONF_DATA *cd;

	cd = rad_malloc(sizeof(*cd));
	memset(cd, 0, sizeof(*cd));

	cd->item.type = CONF_ITEM_DATA;
	cd->item.parent = parent;
	cd->name = strdup(name);
	cd->data = data;
	cd->free = data_free;

	return cd;
}


static void *cf_data_find_internal(CONF_SECTION *cs, const char *name,
				   int flag)
{
	if (!cs || !name) return NULL;
	
	/*
	 *	Find the name in the tree, for speed.
	 */
	if (cs->data_tree) {
		CONF_DATA mycd, *cd;

		mycd.name = name;
		mycd.flag = flag;
		cd = rbtree_finddata(cs->data_tree, &mycd);
		if (cd) return cd->data;
	}

	return NULL;
}

/*
 *	Find data from a particular section.
 */
void *cf_data_find(CONF_SECTION *cs, const char *name)
{
	return cf_data_find_internal(cs, name, 0);
}


/*
 *	Add named data to a configuration section.
 */
static int cf_data_add_internal(CONF_SECTION *cs, const char *name,
				void *data, void (*data_free)(void *),
				int flag)
{
	CONF_DATA *cd;

	if (!cs || !name) return -1;

	/*
	 *	Already exists.  Can't add it.
	 */
	if (cf_data_find_internal(cs, name, flag) != NULL) return -1;

	cd = cf_data_alloc(cs, name, data, data_free);
	if (!cd) return -1;
	cd->flag = flag;

	cf_item_add(cs, cf_datatoitem(cd));

	return 0;
}

/*
 *	Add named data to a configuration section.
 */
int cf_data_add(CONF_SECTION *cs, const char *name,
		void *data, void (*data_free)(void *))
{
	return cf_data_add_internal(cs, name, data, data_free, 0);
}


/*
 *	Copy CONF_DATA from src to dst
 */
static void cf_section_copy_data(CONF_SECTION *s, CONF_SECTION *d)
{
	
	CONF_ITEM *cd, *next, **last;

	/*
	 *	Don't check if s->data_tree is NULL.  It's child
	 *	sections may have data, even if this section doesn't.
	 */

	rad_assert(d->data_tree == NULL);
	d->data_tree = s->data_tree;
	s->data_tree = NULL;
	
	/*
	 *	Walk through src, moving CONF_ITEM_DATA
	 *	to dst, by hand.
	 */
	last = &(s->children);
	for (cd = s->children; cd != NULL; cd = next) {
		next = cd->next;
		
		/*
		 *	Recursively copy data from child sections.
		 */
		if (cd->type == CONF_ITEM_SECTION) {
			CONF_SECTION *s1, *d1;
			
			s1 = cf_itemtosection(cd);
			d1 = cf_section_sub_find_name2(d, s1->name1, s1->name2);
			if (d1) {
				cf_section_copy_data(s1, d1);
			}
			last = &(cd->next);
			continue;
		}

		/*
		 *	Not conf data, remember last ptr.
		 */
		if (cd->type != CONF_ITEM_DATA) {
			last = &(cd->next);
			continue;
		}
		
		/*
		 *	Remove it from the src list
		 */
		*last = cd->next;
		cd->next = NULL;
		
		/*
		 *	Add it to the dst list
		 */
		if (!d->children) {
			rad_assert(d->tail == NULL);
			d->children = cd;
		} else {
			rad_assert(d->tail != NULL);
			d->tail->next = cd;
		}
		d->tail = cd;
	}
}

/*
 *	For a CONF_DATA element, stat the filename, if necessary.
 */
static int filename_stat(void *context, void *data)
{
	struct stat buf;
	CONF_DATA *cd = data;

	context = context;	/* -Wunused */

	if (cd->flag != PW_TYPE_FILENAME) return 0;

	if (stat(cd->name, &buf) < 0) return -1;

	if (buf.st_mtime != *(time_t *) cd->data) return -1;

	return 0;
}


/*
 *	Compare two CONF_SECTIONS.  The items MUST be in the same
 *	order.
 */
static int cf_section_cmp(CONF_SECTION *a, CONF_SECTION *b)
{
	CONF_ITEM *ca = a->children;
	CONF_ITEM *cb = b->children;

	while (1) {
		CONF_PAIR *pa, *pb;

		/*
		 *	Done.  Stop.
		 */
		if (!ca && !cb) break;

		/*
		 *	Skip CONF_DATA.
		 */
		if (ca && ca->type == CONF_ITEM_DATA) {
			ca = ca->next;
			continue;
		}
		if (cb && cb->type == CONF_ITEM_DATA) {
			cb = cb->next;
			continue;
		}

		/*
		 *	One is smaller than the other.  Exit.
		 */
		if (!ca || !cb) return 0;

		if (ca->type != cb->type) return 0;

		/*
		 *	Deal with subsections.
		 */
		if (ca->type == CONF_ITEM_SECTION) {
			CONF_SECTION *sa = cf_itemtosection(ca);
			CONF_SECTION *sb = cf_itemtosection(cb);

			if (!cf_section_cmp(sa, sb)) return 0;
			goto next;
		}

		rad_assert(ca->type == CONF_ITEM_PAIR);

		pa = cf_itemtopair(ca);
		pb = cf_itemtopair(cb);

		/*
		 *	Different attr and/or value, Exit.
		 */
		if ((strcmp(pa->attr, pb->attr) != 0) ||
		    (strcmp(pa->value, pb->value) != 0)) return 0;
		

		/*
		 *	And go to the next element.
		 */
	next:
		ca = ca->next;
		cb = cb->next;
	}

	/*
	 *	Walk over the CONF_DATA, stat'ing PW_TYPE_FILENAME.
	 */
	if (a->data_tree &&
	    (rbtree_walk(a->data_tree, InOrder, filename_stat, NULL) != 0)) {
		return 0;
	}

	/*
	 *	They must be the same, say so.
	 */
	return 1;
}




/*
 *	Migrate CONF_DATA from one section to another.
 */
int cf_section_migrate(CONF_SECTION *dst, CONF_SECTION *src)
{
	CONF_ITEM *ci;
	CONF_SECTION *s, *d;

	for (ci = src->children; ci != NULL; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;

		s = cf_itemtosection(ci);
		d = cf_section_sub_find_name2(dst, s->name1, s->name2);

		if (!d) continue; /* not in new one, don't migrate it */

		/*
		 *	A section of the same name is in BOTH src & dst,
		 *	compare the CONF_PAIR's.  If they're all the same,
		 *	then copy the CONF_DATA from one to the other.
		 */
		if (cf_section_cmp(s, d)) {
			cf_section_copy_data(s, d);
		}
	}

	return 1;		/* rcode means anything? */
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
		switch (ci->type) {
		case CONF_ITEM_PAIR:
			cp=cf_itemtopair(ci);
			DEBUG("%.*s%s = %s",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				cp->attr, cp->value);
			break;

		case CONF_ITEM_SECTION:
			scs=cf_itemtosection(ci);
			DEBUG("%.*s%s %s%s{",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				scs->name1,
				scs->name2 ? scs->name2 : "",
				scs->name2 ?  " " : "");
			dump_config_section(scs, indent+1);
			DEBUG("%.*s}",
				indent, "\t\t\t\t\t\t\t\t\t\t\t");
			break;

		default:	/* FIXME: Do more! */
			break;
		}
	}

	return 0;
}

int dump_config(void)
{
	return dump_config_section(mainconfig.config, 0);
}
#endif
