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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <ctype.h>

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
	const char *filename;
	CONF_ITEM_TYPE type;
};
struct conf_pair {
	CONF_ITEM item;
	const char *attr;
	const char *value;
	FR_TOKEN operator;
	FR_TOKEN value_type;
};
struct conf_part {
	CONF_ITEM item;
	const char *name1;
	const char *name2;
	struct conf_item *children;
	struct conf_item *tail;	/* for speed */
	CONF_SECTION	*template;
	rbtree_t	*pair_tree; /* and a partridge.. */
	rbtree_t	*section_tree; /* no jokes here */
	rbtree_t	*name2_tree; /* for sections of the same name2 */
	rbtree_t	*data_tree;
	void		*base;
	int depth;
	const CONF_PARSER *variables;
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

int cf_log_config = 1;
int cf_log_modules = 1;

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
				FR_TOKEN operator, FR_TOKEN value_type,
				CONF_SECTION *parent)
{
	char *p;
	size_t attr_len, value_len = 0;
	CONF_PAIR *cp;

	if (!attr) return NULL;
	attr_len = strlen(attr) + 1;
	if (value) value_len = strlen(value) + 1;

	p = rad_malloc(sizeof(*cp) + attr_len + value_len);

	cp = (CONF_PAIR *) p;
	memset(cp, 0, sizeof(*cp));
	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;

	p += sizeof(*cp);
	memcpy(p, attr, attr_len);
	cp->attr = p;

	if (value) {
		p += attr_len;
		memcpy(p, value, value_len);
		cp->value = p;
	}
	cp->value_type = value_type;
	cp->operator = operator;

	return cp;
}

/*
 *	Free a CONF_PAIR
 */
void cf_pair_free(CONF_PAIR **cp)
{
	if (!cp || !*cp) return;

	/*
	 *	attr && value are allocated contiguous with cp.
	 */

#ifndef NDEBUG
	memset(*cp, 0, sizeof(*cp));
#endif
	free(*cp);

	*cp = NULL;
}


static void cf_data_free(CONF_DATA **cd)
{
	if (!cd || !*cd) return;

	/* name is allocated contiguous with cd */
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
 *	Free strings we've parsed into data structures.
 */
void cf_section_parse_free(CONF_SECTION *cs, void *base)
{
	int i;
	const CONF_PARSER *variables = cs->variables;

	/*
	 *	Don't automatically free the strings if we're being
	 *	called from a module.  This is also for clients.c,
	 *	where client_free() expects to be able to free the
	 *	client structure.  If we moved everything to key off
	 *	of the config files, we might solve some problems...
	 */
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
		 *	No base struct offset, data must be the pointer.
		 *	If data doesn't exist, ignore the entry, there
		 *	must be something wrong.
		 */
		if (!base) {
			if (!variables[i].data) {
				continue;
			}

			p = (char **) variables[i].data;;

		} else if (variables[i].data) {
			p = (char **) variables[i].data;;

		} else {
			p = (char **) (((char *)base) + variables[i].offset);
		}

		free(*p);
		*p = NULL;
	}
}


/*
 *	Free a CONF_SECTION
 */
void cf_section_free(CONF_SECTION **cs)
{
	CONF_ITEM	*ci, *next;

	if (!cs || !*cs) return;

	cf_section_parse_free(*cs, (*cs)->base);

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

	/*
	 *	Name1 and name2 are allocated contiguous with
	 *	cs.
	 */
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
	size_t name1_len, name2_len = 0;
	char *p;
	CONF_SECTION	*cs;

	if (!name1) return NULL;

	name1_len = strlen(name1) + 1;
	if (name2) name2_len = strlen(name2) + 1;

	p = rad_malloc(sizeof(*cs) + name1_len + name2_len);

	cs = (CONF_SECTION *) p;
	memset(cs, 0, sizeof(*cs));
	cs->item.type = CONF_ITEM_SECTION;
	cs->item.parent = parent;

	p += sizeof(*cs);
	memcpy(p, name1, name1_len);
	cs->name1 = p;

	if (name2 && *name2) {
		p += name1_len;
		memcpy(p, name2, name2_len);
		cs->name2 = p;
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

	if (parent) cs->depth = parent->depth + 1;

	return cs;
}

/*
 *	Replace pair in a given section with a new pair,
 *	of the given value.
 */
int cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, const char *value)
{
	CONF_PAIR *newp;
	CONF_ITEM *ci, *cn, **last;

	newp = cf_pair_alloc(cp->attr, value, cp->operator, cp->value_type,
			     cs);
	if (!newp) return -1;

	ci = cf_pairtoitem(cp);
	cn = cf_pairtoitem(newp);

	/*
	 *	Find the old one from the linked list, and replace it
	 *	with the new one.
	 */
	for (last = &cs->children; (*last) != NULL; last = &(*last)->next) {
		if (*last == ci) {
			cn->next = (*last)->next;
			*last = cn;
			ci->next = NULL;
			break;
		}
	}

	rbtree_deletebydata(cs->pair_tree, ci);

	rbtree_insert(cs->pair_tree, cn);

	return 0;
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
				CONF_SECTION *cs_new = cf_itemtosection(ci);

				if (!cs->section_tree) {
					cs->section_tree = rbtree_create(section_cmp, NULL, 0);
					if (!cs->section_tree) {
						radlog(L_ERR, "Out of memory");
						_exit(1);
					}
				}

				rbtree_insert(cs->section_tree, cs_new);

				/*
				 *	Two names: find the named instance.
				 */
				{
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


CONF_ITEM *cf_reference_item(const CONF_SECTION *parentcs,
			     CONF_SECTION *outercs,
			     const char *ptr)
{
	CONF_PAIR *cp;
	CONF_SECTION *next;
	const CONF_SECTION *cs = outercs;
	char name[8192];
	char *p;

	strlcpy(name, ptr, sizeof(name));
	p = name;

	/*
	 *	".foo" means "foo from the current section"
	 */
	if (*p == '.') {
		p++;
		
		/*
		 *	..foo means "foo from the section
		 *	enclosing this section" (etc.)
		 */
		while (*p == '.') {
			if (cs->item.parent)
				cs = cs->item.parent;
			p++;
		}

		/*
		 *	"foo.bar.baz" means "from the root"
		 */
	} else if (strchr(p, '.') != NULL) {
		if (!parentcs) goto no_such_item;

		cs = parentcs;
	}

	while (*p) {
		char *q, *r;

		r = strchr(p, '[');
		q = strchr(p, '.');
		if (!r && !q) break;

		if (r && q > r) q = NULL;
		if (q && q < r) r = NULL;

		/*
		 *	Split off name2.
		 */
		if (r) {
			q = strchr(r + 1, ']');
			if (!q) return NULL; /* parse error */

			/*
			 *	Points to foo[bar]xx: parse error,
			 *	it should be foo[bar] or foo[bar].baz
			 */
			if (q[1] && q[1] != '.') goto no_such_item;

			*r = '\0';
			*q = '\0';
			next = cf_section_sub_find_name2(cs, p, r + 1);
			*r = '[';
			*q = ']';

			/*
			 *	Points to a named instance of a section.
			 */
			if (!q[1]) {
				if (!next) goto no_such_item;
				return cf_sectiontoitem(next);
			}

			q++;	/* ensure we skip the ']' and '.' */

		} else {
			*q = '\0';
			next = cf_section_sub_find(cs, p);
			*q = '.';
		}

		if (!next) break; /* it MAY be a pair in this section! */

		cs = next;
		p = q + 1;
	}

	if (!*p) goto no_such_item;

 retry:
	/*
	 *	Find it in the current referenced
	 *	section.
	 */
	cp = cf_pair_find(cs, p);
	if (cp) return cf_pairtoitem(cp);

	next = cf_section_sub_find(cs, p);
	if (next) return cf_sectiontoitem(next);
	
	/*
	 *	"foo" is "in the current section, OR in main".
	 */
	if ((p == name) && (parentcs != NULL) && (cs != parentcs)) {
		cs = parentcs;
		goto retry;
	}

no_such_item:
	DEBUG2("WARNING: No such configuration item %s", ptr);
	return NULL;
}


CONF_SECTION *cf_top_section(CONF_SECTION *cs)
{
	while (cs->item.parent != NULL) {
		cs = cs->item.parent;
	}

	return cs;
}


/*
 *	Expand the variables in an input string.
 */
static const char *cf_expand_variables(const char *cf, int *lineno,
				       CONF_SECTION *outercs,
				       char *output, size_t outsize,
				       const char *input)
{
	char *p;
	const char *end, *ptr;
	const CONF_SECTION *parentcs;
	char name[8192];

	/*
	 *	Find the master parent conf section.
	 *	We can't use mainconfig.config, because we're in the
	 *	process of re-building it, and it isn't set up yet...
	 */
	parentcs = cf_top_section(outercs);

	p = output;
	ptr = input;
	while (*ptr) {
		/*
		 *	Ignore anything other than "${"
		 */
		if ((*ptr == '$') && (ptr[1] == '{')) {
			CONF_ITEM *ci;
			CONF_PAIR *cp;

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

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (end - ptr) >= sizeof(name)) {
				radlog(L_ERR, "%s[%d]: Reference string is too large",
				       cf, *lineno);
				return NULL;
			}

			memcpy(name, ptr, end - ptr);
			name[end - ptr] = '\0';

			ci = cf_reference_item(parentcs, outercs, name);
			if (!ci || (ci->type != CONF_ITEM_PAIR)) {
				radlog(L_ERR, "%s[%d]: Reference \"%s\" not found",
				       cf, *lineno, input);
				return NULL;
			}

			/*
			 *  Substitute the value of the variable.
			 */
			cp = cf_itemtopair(ci);
			if (!cp->value) {
				radlog(L_ERR, "%s[%d]: Reference \"%s\" has no value",
				       cf, *lineno, input);
				return NULL;
			}
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

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (end - ptr) >= sizeof(name)) {
				radlog(L_ERR, "%s[%d]: Environment variable name is too large",
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
	fr_ipaddr_t ipaddr;
	const CONF_PAIR *cp = NULL;
	char ipbuf[128];

	if (cs) cp = cf_pair_find(cs, name);
	if (cp) {
		value = cp->value;

	} else if (!dflt) {
		return 1;	/* nothing to parse, return default value */

	} else {
		rcode = 1;
		value = dflt;
	}

	if (!value) {
		return 0;
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
		cf_log_info(cs, "\t%s = %s", name, value);
		break;

	case PW_TYPE_INTEGER:
		*(int *)data = strtol(value, 0, 0);
		cf_log_info(cs, "\t%s = %d", name, *(int *)data);
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

			int lineno = 0;

			if (cs) lineno = cs->item.lineno;

			/*
			 *	FIXME: sizeof(buffer)?
			 */
			value = cf_expand_variables("<internal>",
						    &lineno,
						    cs, buffer, sizeof(buffer),
						    value);
			if (!value) {
				cf_log_err(cf_sectiontoitem(cs),"Failed expanding variable %s", name);
				return -1;
			}
		}

		cf_log_info(cs, "\t%s = \"%s\"", name, value ? value : "(null)");
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

			int lineno = 0;

			if (cs) lineno = cs->item.lineno;

			/*
			 *	FIXME: sizeof(buffer)?
			 */
			value = cf_expand_variables("?",
						    &lineno,
						    cs, buffer, sizeof(buffer),
						    value);
			if (!value) return -1;
		}

		cf_log_info(cs, "\t%s = \"%s\"", name, value ? value : "(null)");
		*q = value ? strdup(value) : NULL;

		/*
		 *	And now we "stat" the file.
		 *
		 *	FIXME: This appears to leak memory on exit,
		 *	and we don't use this information.  So it's
		 *	commented out for now.
		 */
		if (0 && *q) {
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
			cf_log_info(cs, "\t%s = *", name);
			break;
		}
		if (ip_hton(value, AF_INET, &ipaddr) < 0) {
			radlog(L_ERR, "Can't find IP address for host %s", value);
			return -1;
		}
		
		if (strspn(value, "0123456789.") == strlen(value)) {
			cf_log_info(cs, "\t%s = %s", name, value);
		} else {
			cf_log_info(cs, "\t%s = %s IP address [%s]", name, value,
			       ip_ntoh(&ipaddr, ipbuf, sizeof(ipbuf)));
		}
		*(uint32_t *) data = ipaddr.ipaddr.ip4addr.s_addr;
		break;

	case PW_TYPE_IPV6ADDR:
		if (ip_hton(value, AF_INET6, &ipaddr) < 0) {
			radlog(L_ERR, "Can't find IPv6 address for host %s", value);
			return -1;
		}
		cf_log_info(cs, "\t%s = %s IPv6 address [%s]", name, value,
			       ip_ntoh(&ipaddr, ipbuf, sizeof(ipbuf)));
		memcpy(data, &ipaddr.ipaddr.ip6addr,
		       sizeof(ipaddr.ipaddr.ip6addr));
		break;

	default:
		radlog(L_ERR, "type %d not supported yet", type);
		return -1;
	} /* switch over variable type */

	if (!cp) {
		CONF_PAIR *cpn;

		cpn = cf_pair_alloc(name, value, T_OP_SET, T_BARE_WORD, cs);
		cpn->item.filename = "<internal>";
		cpn->item.lineno = 0;
		cf_item_add(cs, cf_pairtoitem(cpn));
	}

	return rcode;
}

static const char *parse_spaces = "                                                                                                                                                                                                                                                                ";

/*
 *	A copy of cf_section_parse that initializes pointers before
 *	parsing them.
 */
static void cf_section_parse_init(CONF_SECTION *cs, void *base,
				  const CONF_PARSER *variables)
{
	int i;
	void *data;

	for (i = 0; variables[i].name != NULL; i++) {
		if (variables[i].type == PW_TYPE_SUBSECTION) {
			CONF_SECTION *subcs;
			subcs = cf_section_sub_find(cs, variables[i].name);
			if (!subcs) continue;

			if (!variables[i].dflt) continue;

			cf_section_parse_init(subcs, base,
					      (const CONF_PARSER *) variables[i].dflt);
			continue;
		}

		if ((variables[i].type != PW_TYPE_STRING_PTR) &&
		    (variables[i].type != PW_TYPE_FILENAME)) {
			continue;
		}

		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			continue;
		}

		*(char **) data = NULL;
	} /* for all variables in the configuration section */
}

/*
 *	Parse a configuration section into user-supplied variables.
 */
int cf_section_parse(CONF_SECTION *cs, void *base,
		     const CONF_PARSER *variables)
{
	int i;
	void *data;

	cs->variables = variables; /* this doesn't hurt anything */

	if (!cs->name2) {
		cf_log_info(cs, "%.*s%s {", cs->depth, parse_spaces,
		       cs->name1);
	} else {
		cf_log_info(cs, "%.*s%s %s {", cs->depth, parse_spaces,
		       cs->name1, cs->name2);
	}

	cf_section_parse_init(cs, base, variables);

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	Handle subsections specially
		 */
		if (variables[i].type == PW_TYPE_SUBSECTION) {
			CONF_SECTION *subcs;
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
				goto error;
			}

			if (cf_section_parse(subcs, base,
					     (const CONF_PARSER *) variables[i].dflt) < 0) {
				goto error;
			}
			continue;
		} /* else it's a CONF_PAIR */

		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			DEBUG2("Internal sanity check 2 failed in cf_section_parse");
			goto error;
		}

		/*
		 *	Parse the pair we found, or a default value.
		 */
		if (cf_item_parse(cs, variables[i].name, variables[i].type,
				  data, variables[i].dflt) < 0) {
			goto error;
		}
	} /* for all variables in the configuration section */

	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);

	cs->base = base;

	return 0;

 error:
	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);
	cf_section_parse_free(cs, base);
	return -1;
}


/*
 *	Sanity check the "if" or "elsif", presuming that the first '('
 *	has already been eaten.
 *
 *	We're not really parsing it here, just checking if it's mostly
 *	well-formed.
 */
static int condition_looks_ok(const char **ptr)
{
	int num_braces = 1;
	int quote = 0;
	const char *p = *ptr;

	while (*p) {
		if (quote) {
			if (*p == quote) {
				p++;
				quote = 0;
				continue;
			}

			if (*p == '\\') {
				if (!p[1]) {
					return 0; /* no trailing slash */
				}
				p += 2;
				continue;
			}
			p++;
			continue;
		}

		switch (*p) {
		case '\\':
			if (!p[1]) {
				return 0; /* no trailing slash */
			}
			p += 2;
			continue;

		case '(':
			num_braces++;
			p++;
			continue;

		case ')':
			if (num_braces == 1) {
				const char *q = p + 1;

				/*
				 *	Validate that there isn't much
				 *	else after the closing brace.
				 */
				while ((*q == ' ') || (*q == '\t')) q++;

				/*
				 *	Parse error.
				 */
				if (*q != '{') {
					DEBUG2("Expected open brace '{' after condition at %s", p);
					return 0;
				}

				*ptr = p + 1; /* include the trailing ')' */
				return 1;
			}
			num_braces--;
			p++;
			continue;

		case '"':
		case '\'':
		case '/':
		case '`':
			quote = *p;
			/* FALL-THROUGH */

		default:
			p++;
			break;
		}
	}

	DEBUG3("Unexpected error");
	return 0;
}


static const char *cf_local_file(CONF_SECTION *cs, const char *local,
				 char *buffer, size_t bufsize)
{
	size_t dirsize;
	const char *p;
	CONF_SECTION *parentcs = cf_top_section(cs);

	p = strrchr(parentcs->item.filename, FR_DIR_SEP);
	if (!p) return local;

	dirsize = (p - parentcs->item.filename) + 1;

	if ((dirsize + strlen(local)) >= bufsize) {
		return NULL;
	}

	memcpy(buffer, parentcs->item.filename, dirsize);
	strlcpy(buffer + dirsize, local, bufsize - dirsize);

	return buffer;
}

static int seen_too_much(const char *filename, int lineno, const char *ptr)
{
	while (*ptr) {
		if (isspace(*ptr)) {
			ptr++;
			continue;
		}

		if (*ptr == '#') return FALSE;

		break;
	}

	if (*ptr) {
		radlog(L_ERR, "%s[%d] Unexpected text %s.  See \"man unlang\"",
		       filename, lineno, ptr);
		return TRUE;
	}

	return FALSE;
}


/*
 *	Read a part of the config file.
 */
static int cf_section_read(const char *filename, int *lineno, FILE *fp,
			   CONF_SECTION *current)

{
	CONF_SECTION *this, *css;
	CONF_PAIR *cpn;
	const char *ptr;
	const char *value;
	char buf[8192];
	char buf1[8192];
	char buf2[8192];
	char buf3[8192];
	int t1, t2, t3;
	char *cbuf = buf;
	size_t len;

	this = current;		/* add items here */

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		int at_eof;

		/*
		 *	Get data, and remember if we are at EOF.
		 */
		at_eof = (fgets(cbuf, sizeof(buf) - (cbuf - buf), fp) == NULL);
		(*lineno)++;

		/*
		 *	We read the entire 8k worth of data: complain.
		 *	Note that we don't care if the last character
		 *	is \n: it's still forbidden.  This means that
		 *	the maximum allowed length of text is 8k-1, which
		 *	should be plenty.
		 */
		len = strlen(cbuf);
		if ((cbuf + len + 1) >= (buf + sizeof(buf))) {
			radlog(L_ERR, "%s[%d]: Line too long",
			       filename, *lineno);
			return -1;
		}

		/*
		 *	Not doing continuations: check for edge
		 *	conditions.
		 */
		if (cbuf == buf) {
			if (at_eof) break;
			
			ptr = buf;
			while (*ptr && isspace((int) *ptr)) ptr++;

			if (!*ptr || (*ptr == '#')) continue;

		} else if (at_eof || (len == 0)) {
			radlog(L_ERR, "%s[%d]: Continuation at EOF is illegal",
			       filename, *lineno);
			return -1;
		}

		/*
		 *	See if there's a continuation.
		 */
		while ((len > 0) &&
		       ((cbuf[len - 1] == '\n') || (cbuf[len - 1] == '\r'))) {
			len--;
			cbuf[len] = '\0';
		}

		if ((len > 0) && (cbuf[len - 1] == '\\')) {
			cbuf[len - 1] = '\0';
			cbuf += len - 1;
			continue;
		}

		ptr = cbuf = buf;

		/*
		 *	The parser is getting to be evil.
		 */
		while ((*ptr == ' ') || (*ptr == '\t')) ptr++;

		if (((ptr[0] == '%') && (ptr[1] == '{')) ||
		    (ptr[0] == '`')) {
			int hack;

			if (ptr[0] == '%') {
				hack = rad_copy_variable(buf1, ptr);
			} else {
				hack = rad_copy_string(buf1, ptr);
			}
			if (hack < 0) {
				radlog(L_ERR, "%s[%d]: Invalid expansion: %s",
				       filename, *lineno, ptr);
				return -1;
			}

			t1 = T_BARE_WORD;
			ptr += hack;

			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			switch (t2) {
			case T_EOL:
			case T_HASH:
				goto do_bare_word;
				
			default:
				radlog(L_ERR, "%s[%d]: Invalid expansion: %s",
				       filename, *lineno, ptr);
				return -1;
			}
		} else {
			t1 = gettoken(&ptr, buf1, sizeof(buf1));
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
				      filename, *lineno);
			       return -1;

		       }
		       this = this->item.parent;
		       if (seen_too_much(filename, *lineno, ptr)) return -1;
		       continue;
		}

		/*
		 *	Allow for $INCLUDE files
		 *
		 *      This *SHOULD* work for any level include.
		 *      I really really really hate this file.  -cparker
		 */
	       if ((strcasecmp(buf1, "$INCLUDE") == 0) ||
		   (strcasecmp(buf1, "$-INCLUDE") == 0)) {
		       int relative = 1;

		        t2 = getword(&ptr, buf2, sizeof(buf2));

			if (buf2[0] == '$') relative = 0;

			value = cf_expand_variables(filename, lineno, this, buf, sizeof(buf), buf2);
			if (!value) return -1;

			if (!FR_DIR_IS_RELATIVE(value)) relative = 0;

			if (relative) {
				value = cf_local_file(current, value, buf3,
						      sizeof(buf3));
				if (!value) {
					radlog(L_ERR, "%s[%d]: Directories too deep.",
					       filename, *lineno);
					return -1;
				}
			}


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

				DEBUG2("including files in directory %s", value );
				dir = opendir(value);
				if (!dir) {
					radlog(L_ERR, "%s[%d]: Error reading directory %s: %s",
					       filename, *lineno, value,
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
						    (*p == '-') ||
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
				if (buf1[1] == '-') {
					struct stat statbuf;

					if (stat(value, &statbuf) < 0) {
						DEBUG("WARNING: Not including file %s: %s", value, strerror(errno));
						continue;
					}
				}

				if (cf_file_include(value, this) < 0) {
					return -1;
				}
			}
			continue;
		} /* we were in an include */

	       if (strcasecmp(buf1, "$template") == 0) {
		       CONF_ITEM *ci;
		       CONF_SECTION *parentcs, *templatecs;
		       t2 = getword(&ptr, buf2, sizeof(buf2));

		       parentcs = cf_top_section(current);

		       templatecs = cf_section_sub_find(parentcs, "templates");
		       if (!templatecs) {
				radlog(L_ERR, "%s[%d]: No \"templates\" section for reference \"%s\"",
				       filename, *lineno, buf2);
				return -1;
		       }

		       ci = cf_reference_item(parentcs, templatecs, buf2);
		       if (!ci || (ci->type != CONF_ITEM_SECTION)) {
				radlog(L_ERR, "%s[%d]: Reference \"%s\" not found",
				       filename, *lineno, buf2);
				return -1;
		       }
		       
		       if (this->template) {
				radlog(L_ERR, "%s[%d]: Section already has a template",
				       filename, *lineno);
				return -1;
		       }

		       this->template = cf_itemtosection(ci);
		       continue;
	       }

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			radlog(L_ERR, "%s[%d]: Illegal configuration pair name \"%s\"",
					filename, *lineno, buf1);
			return -1;
		}

		/*
		 *	Grab the next token.
		 */
		t2 = gettoken(&ptr, buf2, sizeof(buf2));
		switch (t2) {
		case T_EOL:
		case T_HASH:
		do_bare_word:
			t3 = t2;
			t2 = T_OP_EQ;
			value = NULL;
			goto do_set;

		case T_OP_ADD:
		case T_OP_CMP_EQ:
		case T_OP_SUB:
		case T_OP_LE:
		case T_OP_GE:
		case T_OP_CMP_FALSE:
			if (!this || (strcmp(this->name1, "update") != 0)) {
				radlog(L_ERR, "%s[%d]: Invalid operator in assignment",
				       filename, *lineno);
				return -1;
			}
			/* FALL-THROUGH */

		case T_OP_EQ:
		case T_OP_SET:
			t3 = getstring(&ptr, buf3, sizeof(buf3));
			if (t3 == T_OP_INVALID) {
				radlog(L_ERR, "%s[%d]: Parse error: %s",
				       filename, *lineno,
				       fr_strerror());
				return -1;
			}

			/*
			 *	These are not allowed.  Print a
			 *	helpful error message.
			 */
			if ((t3 == T_BACK_QUOTED_STRING) &&
			    (!this || (strcmp(this->name1, "update") != 0))) {
				radlog(L_ERR, "%s[%d]: Syntax error: Invalid string `...` in assignment",
				       filename, *lineno);
				return -1;
			}

			/*
			 *	Handle variable substitution via ${foo}
			 */
			if ((t3 == T_BARE_WORD) ||
			    (t3 == T_DOUBLE_QUOTED_STRING)) {
				value = cf_expand_variables(filename, lineno, this,
							    buf, sizeof(buf), buf3);
				if (!value) return -1;
			} else if ((t3 == T_EOL) ||
				   (t3 == T_HASH)) {
				value = NULL;
			} else {
				value = buf3;
			}
			
			/*
			 *	Add this CONF_PAIR to our CONF_SECTION
			 */
		do_set:
			cpn = cf_pair_alloc(buf1, value, t2, t3, this);
			cpn->item.filename = filename;
			cpn->item.lineno = *lineno;
			cf_item_add(this, cf_pairtoitem(cpn));
			continue;

			/*
			 *	This horrible code is here to support
			 *	if/then/else failover in the
			 *	authorize, etc. sections.  It makes no
			 *	sense anywhere else.
			 */
		case T_LBRACE:
			if ((strcmp(buf1, "if") == 0) ||
			    (strcmp(buf1, "elsif") == 0)) {
				const char *end = ptr;
				CONF_SECTION *server;

				if (!condition_looks_ok(&end)) {
					radlog(L_ERR, "%s[%d]: Parse error in condition at: %s",
					       filename, *lineno, ptr);
					return -1;
				}

				if ((size_t) (end - ptr) >= (sizeof(buf2) - 1)) {
					radlog(L_ERR, "%s[%d]: Statement too complicated after \"%s\"",
					       filename, *lineno, buf1);
					return -1;
				}

				/*
				 *	More sanity checking.  This is
				 *	getting to be a horrible hack.
				 */
				server = this;
				while (server) {
					if (strcmp(server->name1, "server") == 0) break;
					server = server->item.parent;
				}
				
				if (0 && !server) {
					radlog(L_ERR, "%s[%d]: Processing directives such as \"%s\" cannot be used here.",
					       filename, *lineno, buf1);
					return -1;
				}

				buf2[0] = '(';
				memcpy(buf2 + 1, ptr, end - ptr);
				buf2[end - ptr + 1] = '\0';
				ptr = end;
				t2 = T_BARE_WORD;

				if (gettoken(&ptr, buf3, sizeof(buf3)) != T_LCBRACE) {
					radlog(L_ERR, "%s[%d]: Expected '{'",
					       filename, *lineno);
					return -1;
				}
				goto section_alloc;

			} else {
				radlog(L_ERR, "%s[%d]: Parse error after \"%s\"",
				       filename, *lineno, buf1);
				return -1;
			}

			/* FALL-THROUGH */

			/*
			 *	No '=', must be a section or sub-section.
			 */
		case T_BARE_WORD:
		case T_DOUBLE_QUOTED_STRING:
		case T_SINGLE_QUOTED_STRING:
			t3 = gettoken(&ptr, buf3, sizeof(buf3));
			if (t3 != T_LCBRACE) {
				radlog(L_ERR, "%s[%d]: Expecting section start brace '{' after \"%s %s\"",
				       filename, *lineno, buf1, buf2);
				return -1;
			}
			/* FALL-THROUGH */

		case T_LCBRACE:
		section_alloc:
			if (seen_too_much(filename, *lineno, ptr)) return -1;

			css = cf_section_alloc(buf1,
					       t2 == T_LCBRACE ? NULL : buf2,
					       this);
			if (!css) {
				radlog(L_ERR, "%s[%d]: Failed allocating memory for section",
						filename, *lineno);
				return -1;
			}
			cf_item_add(this, cf_sectiontoitem(css));
			css->item.filename = filename;
			css->item.lineno = *lineno;

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			continue;

		default:
			radlog(L_ERR, "%s[%d]: Parse error after \"%s\"",
			       filename, *lineno, buf1);
			return -1;
		}
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (feof(fp) && (this != current)) {
		radlog(L_ERR, "%s[%d]: EOF reached without closing brace for section %s starting at line %d",
		       filename, *lineno,
		       cf_section_name1(this), cf_section_lineno(this));
		return -1;
	}

	return 0;
}

/*
 *	Include one config file in another.
 */
int cf_file_include(const char *filename, CONF_SECTION *cs)
{
	FILE		*fp;
	int		lineno = 0;
	struct stat	statbuf;
	time_t		*mtime;
	CONF_DATA	*cd;

	DEBUG2( "including configuration file %s", filename);

	if (stat(filename, &statbuf) == 0) {
#ifdef S_IWOTH
		if ((statbuf.st_mode & S_IWOTH) != 0) {
			radlog(L_ERR|L_CONS, "Configuration file %s is globally writable.  Refusing to start due to insecure configuration.",
			       filename);
			return -1;
		}
#endif

#ifdef S_IROTH
		if (0 && (statbuf.st_mode & S_IROTH) != 0) {
			radlog(L_ERR|L_CONS, "Configuration file %s is globally readable.  Refusing to start due to insecure configuration.",
			       filename);
			return -1;
		}
#endif
	}

	fp = fopen(filename, "r");
	if (!fp) {
		radlog(L_ERR|L_CONS, "Unable to open file \"%s\": %s",
		       filename, strerror(errno));
		return -1;
	}

	if (cf_data_find_internal(cs, filename, PW_TYPE_FILENAME)) {
		fclose(fp);
		radlog(L_ERR, "Cannot include the same file twice: \"%s\"",
		       filename);
		return -1;
	}

	/*
	 *	Add the filename to the section
	 */
	mtime = rad_malloc(sizeof(*mtime));
	*mtime = statbuf.st_mtime;

	if (cf_data_add_internal(cs, filename, mtime, free,
				 PW_TYPE_FILENAME) < 0) {
		fclose(fp);
		radlog(L_ERR|L_CONS, "Internal error opening file \"%s\"",
		       filename);
		return -1;
	}

	cd = cf_data_find_internal(cs, filename, PW_TYPE_FILENAME);
	if (!cd) {
		fclose(fp);
		radlog(L_ERR|L_CONS, "Internal error opening file \"%s\"",
		       filename);
		return -1;
	}

	if (!cs->item.filename) cs->item.filename = filename;

	/*
	 *	Read the section.  It's OK to have EOF without a
	 *	matching close brace.
	 */
	if (cf_section_read(cd->name, &lineno, fp, cs) < 0) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

/*
 *	Bootstrap a config file.
 */
CONF_SECTION *cf_file_read(const char *filename)
{
	char *p;
	CONF_PAIR *cp;
	CONF_SECTION *cs;

	cs = cf_section_alloc("main", NULL, NULL);
	if (!cs) return NULL;

	cp = cf_pair_alloc("confdir", filename, T_OP_SET, T_BARE_WORD, cs);
	if (!cp) return NULL;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cp->item.filename = "internal";
	cp->item.lineno = 0;
	cf_item_add(cs, cf_pairtoitem(cp));

	if (cf_file_include(filename, cs) < 0) {
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
	CONF_PAIR	*cp = NULL;

	if (!cs) return NULL;

	/*
	 *	Find the name in the tree, for speed.
	 */
	if (name) {
		CONF_PAIR mycp;

		mycp.attr = name;
		cp = rbtree_finddata(cs->pair_tree, &mycp);
	} else {
		/*
		 *	Else find the first one that matches
		 */
		for (ci = cs->children; ci; ci = ci->next) {
			if (ci->type == CONF_ITEM_PAIR) {
				return cf_itemtopair(ci);
			}
		}
	}

	if (cp || !cs->template) return cp;

	return cf_pair_find(cs->template, name);
}

/*
 * Return the attr of a CONF_PAIR
 */

const char *cf_pair_attr(CONF_PAIR *pair)
{
	return (pair ? pair->attr : NULL);
}

/*
 * Return the value of a CONF_PAIR
 */

const char *cf_pair_value(CONF_PAIR *pair)
{
	return (pair ? pair->value : NULL);
}

/*
 *	Copied here for error reporting.
 */
extern void fr_strerror_printf(const char *, ...);

/*
 * Turn a CONF_PAIR into a VALUE_PAIR
 * For now, ignore the "value_type" field...
 */
VALUE_PAIR *cf_pairtovp(CONF_PAIR *pair)
{
	VALUE_PAIR *vp;

	if (!pair) {
		fr_strerror_printf("Internal error");
		return NULL;
	}

	if (!pair->value) {
		fr_strerror_printf("No value given for attribute %s", pair->attr);
		return NULL;
	}

	/*
	 *	pairmake handles tags.  pairalloc() doesn't.
	 */
	vp = pairmake(pair->attr, NULL, pair->operator);
	if (!vp) {
		return NULL;
	}

	/*
	 *	Ignore the value if it's a false comparison.
	 */
	if (pair->operator == T_OP_CMP_FALSE) return vp;

	if (pair->value_type == T_BARE_WORD) {
		if ((vp->type == PW_TYPE_STRING) && 
		    (pair->value[0] == '0') && (pair->value[1] == 'x')) {
			vp->type = PW_TYPE_OCTETS;
		}
		if (!pairparsevalue(vp, pair->value)) {
			pairfree(&vp);
			return NULL;
		}
		vp->flags.do_xlat = 0;
	  
	} else if (pair->value_type == T_SINGLE_QUOTED_STRING) {
		if (!pairparsevalue(vp, pair->value)) {
			pairfree(&vp);
			return NULL;
		}
		vp->flags.do_xlat = 0;
	} else {
		vp->flags.do_xlat = 1;
	}

	return vp;
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
const char *cf_section_value_find(const CONF_SECTION *cs, const char *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(cs, attr);

	return (cp ? cp->value : NULL);
}


CONF_SECTION *cf_section_find_name2(const CONF_SECTION *section,
				    const char *name1, const char *name2)
{
	const char	*their2;
	CONF_ITEM	*ci;

	if (!section || !name1) return NULL;

	for (ci = cf_sectiontoitem(section); ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;

		if (strcmp(cf_itemtosection(ci)->name1, name1) != 0)
			continue;

		their2 = cf_itemtosection(ci)->name2;

		if ((!name2 && !their2) ||
		    (name2 && their2 && (strcmp(name2, their2) == 0))) {
			return cf_itemtosection(ci);
		}
	}
	
	return NULL;
}

/*
 * Return the next pair after a CONF_PAIR
 * with a certain name (char *attr) If the requested
 * attr is NULL, any attr matches.
 */

CONF_PAIR *cf_pair_find_next(const CONF_SECTION *cs,
			     CONF_PAIR *pair, const char *attr)
{
	CONF_ITEM	*ci;

	if (!cs) return NULL;

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

	if (!name) return NULL;	/* can't find an un-named section */

	/*
	 *	Do the fast lookup if possible.
	 */
	if (cs->section_tree) {
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

	if (!section) return NULL;

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
 * Return the next section after a CONF_SECTION
 * with a certain name1 (char *name1). If the requested
 * name1 is NULL, any name1 matches.
 */

CONF_SECTION *cf_section_find_next(CONF_SECTION *section,
				   CONF_SECTION *subsection,
				   const char *name1)
{
	if (!section) return NULL;

	if (!section->item.parent) return NULL;

	return cf_subsection_find_next(section->item.parent, subsection, name1);
}

/*
 * Return the next item after a CONF_ITEM.
 */

CONF_ITEM *cf_item_find_next(CONF_SECTION *section, CONF_ITEM *item)
{
	if (!section) return NULL;

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

CONF_SECTION *cf_item_parent(CONF_ITEM *ci)
{
	if (!ci) return NULL;

	return ci->parent;
}

int cf_section_lineno(CONF_SECTION *section)
{
	return cf_sectiontoitem(section)->lineno;
}

const char *cf_pair_filename(CONF_PAIR *pair)
{
	return cf_pairtoitem(pair)->filename;
}

const char *cf_section_filename(CONF_SECTION *section)
{
	return cf_sectiontoitem(section)->filename;
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
	char *p;
	size_t name_len;
	CONF_DATA *cd;

	name_len = strlen(name) + 1;

	p = rad_malloc(sizeof(*cd) + name_len);
	cd = (CONF_DATA *) p;
	memset(cd, 0, sizeof(*cd));

	cd->item.type = CONF_ITEM_DATA;
	cd->item.parent = parent;
	cd->data = data;
	cd->free = data_free;

	p += sizeof(*cd);
	memcpy(p, name, name_len);
	cd->name = p;
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
		CONF_DATA mycd;

		mycd.name = name;
		mycd.flag = flag;
		return rbtree_finddata(cs->data_tree, &mycd);
	}

	return NULL;
}

/*
 *	Find data from a particular section.
 */
void *cf_data_find(CONF_SECTION *cs, const char *name)
{
	CONF_DATA *cd = cf_data_find_internal(cs, name, 0);

	if (cd) return cd->data;
	return NULL;
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

#if 0
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
#endif

int cf_section_template(CONF_SECTION *cs, CONF_SECTION *template)
{
	if (!cs || !template || cs->template || template->template) return -1;

	cs->template = template;

	return 0;
}


/*
 *	This is here to make the rest of the code easier to read.  It
 *	ties conffile.c to log.c, but it means we don't have to
 *	pollute every other function with the knowledge of the
 *	configuration internals.
 */
void cf_log_err(CONF_ITEM *ci, const char *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	radlog(L_ERR, "%s[%d]: %s", ci->filename, ci->lineno, buffer);
}


void cf_log_info(CONF_SECTION *cs, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (debug_flag > 1 && cf_log_config && cs) vradlog(L_DBG, fmt, ap);
	va_end(ap);
}

/*
 *	Wrapper to simplify the code.
 */
void cf_log_module(CONF_SECTION *cs, const char *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	if (debug_flag > 1 && cf_log_modules && cs) {
		vsnprintf(buffer, sizeof(buffer), fmt, ap);

		radlog(L_DBG, " Module: %s", buffer);
	}
	va_end(ap);
}

const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs)
{
	if (!cs) return NULL;

	return cs->variables;
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

int dump_config(CONF_SECTION *cs)
{
	return dump_config_section(cs, 0);
}
#endif

static const char *cf_pair_print_value(const CONF_PAIR *cp,
				       char *buffer, size_t buflen)
{
	char *p;

	if (!cp->value) return "";

	switch (cp->value_type) {
	default:
	case T_BARE_WORD:
		snprintf(buffer, buflen, "%s", cp->value);
		break;

	case T_SINGLE_QUOTED_STRING:
		snprintf(buffer, buflen, "'%s'", cp->value);
		break;

	case T_DOUBLE_QUOTED_STRING:
		buffer[0] = '"';
		fr_print_string(cp->value, strlen(cp->value),
				buffer + 1, buflen - 3);
		p = buffer + strlen(buffer); /* yuck... */
		p[0] = '"';
		p[1] = '\0';
		break;
	}

	return buffer;
}


int cf_pair2xml(FILE *fp, const CONF_PAIR *cp)
{
	fprintf(fp, "<%s>", cp->attr);
	if (cp->value) {
		char buffer[2048];

		char *p = buffer;
		const char *q = cp->value;

		while (*q && (p < (buffer + sizeof(buffer) - 1))) {
			if (q[0] == '&') {
				memcpy(p, "&amp;", 4);
				p += 5;

			} else if (q[0] == '<') {
				memcpy(p, "&lt;", 4);
				p += 4;

			} else if (q[0] == '>') {
				memcpy(p, "&gt;", 4);
				p += 4;

			} else {
				*(p++) = *q;
			}
			q++;
		}

		*p = '\0';
		fprintf(fp, "%s", buffer);
	}

	fprintf(fp, "</%s>\n", cp->attr);

	return 1;
}

int cf_section2xml(FILE *fp, const CONF_SECTION *cs)
{
	CONF_ITEM *ci, *next;

	/*
	 *	Section header
	 */
	fprintf(fp, "<%s>\n", cs->name1);
	if (cs->name2) {
		fprintf(fp, "<_name2>%s</_name2>\n", cs->name2);
	}

	/*
	 *	Loop over contents.
	 */
	for (ci = cs->children; ci; ci = next) {
		next = ci->next;

		switch (ci->type) {
		case CONF_ITEM_PAIR:
			if (!cf_pair2xml(fp, (CONF_PAIR *) ci)) return 0;
			break;

		case CONF_ITEM_SECTION:
			if (!cf_section2xml(fp, (CONF_SECTION *) ci)) return 0;
			break;

		default:	/* should really be an error. */
			break;
		
		}
	}

	fprintf(fp, "</%s>\n", cs->name1);

	return 1;		/* success */
}

int cf_pair2file(FILE *fp, const CONF_PAIR *cp)
{
	char buffer[2048];

	fprintf(fp, "\t%s = %s\n", cp->attr,
		cf_pair_print_value(cp, buffer, sizeof(buffer)));

	return 1;
}

int cf_section2file(FILE *fp, const CONF_SECTION *cs)
{
	const CONF_ITEM *ci, *next;

	/*
	 *	Section header
	 */
	if (!cs->name2) {
		fprintf(fp, "%s {\n", cs->name1);
	} else {
		fprintf(fp, "%s %s {\n",
			cs->name1, cs->name2);
	}

	/*
	 *	Loop over contents.
	 */
	for (ci = cs->children; ci; ci = next) {
		next = ci->next;

		switch (ci->type) {
		case CONF_ITEM_PAIR:
			if (!cf_pair2file(fp, (const CONF_PAIR *) ci)) return 0;
			break;

		case CONF_ITEM_SECTION:
			if (!cf_section2file(fp, (const CONF_SECTION *) ci)) return 0;
			break;

		default:	/* should really be an error. */
			break;
		
		}
	}

	fprintf(fp, "}\n");

	return 1;		/* success */
}
