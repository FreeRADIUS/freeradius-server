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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <ctype.h>

typedef enum conf_property {
	CONF_PROPERTY_INVALID = 0,
	CONF_PROPERTY_NAME,
	CONF_PROPERTY_INSTANCE,
} CONF_PROPERTY;

const FR_NAME_NUMBER conf_property_name[] = {
	{ "name",	CONF_PROPERTY_NAME},
	{ "instance",	CONF_PROPERTY_INSTANCE},

	{  NULL , -1 }
};

typedef enum conf_type {
	CONF_ITEM_INVALID = 0,
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION,
	CONF_ITEM_DATA
} CONF_ITEM_TYPE;

struct conf_item {
	struct conf_item *next;		//!< Sibling.
	struct conf_part *parent;	//!< Parent.
	int lineno;			//!< The line number the config item began on.
	char const *filename;		//!< The file the config item was parsed from.
	CONF_ITEM_TYPE type;		//!< Whether the config item is a config_pair, conf_section or conf_data.
};

/** Configuration AVP similar to a VALUE_PAIR
 *
 */
struct conf_pair {
	CONF_ITEM item;
	char const *attr;		//!< Attribute name
	char const *value;		//!< Attribute value
	FR_TOKEN op;			//!< Operator e.g. =, :=
	FR_TOKEN value_type;		//!< Quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
};

/** Internal data that is associated with a configuration section
 *
 */
struct conf_data {
	CONF_ITEM  item;
	char const *name;
	int	   flag;
	void	   *data;		//!< User data
	void       (*free)(void *);	//!< Free user data function
};

struct conf_part {
	CONF_ITEM item;
	char const	*name1;
	char const	*name2;
	FR_TOKEN	name2_type;

	CONF_ITEM	*children;
	CONF_ITEM	*tail;		//!< For speed.
	CONF_SECTION	*template;

	rbtree_t	*pair_tree;	//!< and a partridge..
	rbtree_t	*section_tree;	//!< no jokes here.
	rbtree_t	*name2_tree;	//!< for sections of the same name2
	rbtree_t	*data_tree;

	void		*base;
	int		depth;

	CONF_PARSER const *variables;
};

CONF_SECTION *root_config = NULL;


static int		cf_data_add_internal(CONF_SECTION *cs, char const *name, void *data,
					     void (*data_free)(void *), int flag);

static void		*cf_data_find_internal(CONF_SECTION const *cs, char const *name, int flag);

static char const 	*cf_expand_variables(char const *cf, int *lineno,
					     CONF_SECTION *outercs,
					     char *output, size_t outsize,
					     char const *input);

static CONF_SECTION	*cf_template_copy(CONF_SECTION *parent, CONF_SECTION const *template);

static void		cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci);

/*
 *	Isolate the scary casts in these tiny provably-safe functions
 */

/** Cast a CONF_ITEM to a CONF_PAIR
 *
 */
CONF_PAIR *cf_itemtopair(CONF_ITEM const *ci)
{
	CONF_PAIR *out;

	if (ci == NULL) return NULL;

	rad_assert(ci->type == CONF_ITEM_PAIR);

	memcpy(&out, &ci, sizeof(out));
	return out;
}

/** Cast a CONF_ITEM to a CONF_SECTION
 *
 */
CONF_SECTION *cf_itemtosection(CONF_ITEM const *ci)
{
	CONF_SECTION *out;

	if (ci == NULL) return NULL;

	rad_assert(ci->type == CONF_ITEM_SECTION);

	memcpy(&out, &ci, sizeof(out));
	return out;
}

/** Cast a CONF_PAIR to a CONF_ITEM
 *
 */
CONF_ITEM *cf_pairtoitem(CONF_PAIR const *cp)
{
	CONF_ITEM *out;

	if (cp == NULL) return NULL;

	memcpy(&out, &cp, sizeof(out));
	return out;
}

/** Cast a CONF_SECTION to a CONF_ITEM
 *
 */
CONF_ITEM *cf_sectiontoitem(CONF_SECTION const *cs)
{
	CONF_ITEM *out;

	if (cs == NULL) return NULL;

	memcpy(&out, &cs, sizeof(out));
	return out;
}

/** Cast CONF_DATA to a CONF_ITEM
 *
 */
static CONF_ITEM *cf_datatoitem(CONF_DATA const *cd)
{
	CONF_ITEM *out;

	if (cd == NULL) {
		return NULL;
	}

	memcpy(&out, &cd, sizeof(out));
	return out;
}

/*
 *	Create a new CONF_PAIR
 */
static CONF_PAIR *cf_pair_alloc(CONF_SECTION *parent, char const *attr,
				char const *value, FR_TOKEN op,
				FR_TOKEN value_type)
{
	CONF_PAIR *cp;

	if (!attr) return NULL;

	cp = talloc_zero(parent, CONF_PAIR);
	if (!cp) return NULL;

	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;
	cp->value_type = value_type;
	cp->op = op;

	cp->attr = talloc_typed_strdup(cp, attr);
	if (!cp->attr) {
	error:
		talloc_free(cp);
		return NULL;
	}

	if (value) {
		cp->value = talloc_typed_strdup(cp, value);
		if (!cp->value) goto error;
	}

	return cp;
}

static int _cf_data_free(CONF_DATA *cd)
{
	if (cd->free) cd->free(cd->data);

	return 0;
}

/*
 *	rbtree callback function
 */
static int pair_cmp(void const *a, void const *b)
{
	CONF_PAIR const *one = a;
	CONF_PAIR const *two = b;

	return strcmp(one->attr, two->attr);
}


/*
 *	rbtree callback function
 */
static int section_cmp(void const *a, void const *b)
{
	CONF_SECTION const *one = a;
	CONF_SECTION const *two = b;

	return strcmp(one->name1, two->name1);
}


/*
 *	rbtree callback function
 */
static int name2_cmp(void const *a, void const *b)
{
	CONF_SECTION const *one = a;
	CONF_SECTION const *two = b;

	rad_assert(strcmp(one->name1, two->name1) == 0);

	if (!one->name2 && !two->name2) return 0;
	if (one->name2 && !two->name2) return -1;
	if (!one->name2 && two->name2) return +1;

	return strcmp(one->name2, two->name2);
}


/*
 *	rbtree callback function
 */
static int data_cmp(void const *a, void const *b)
{
	int rcode;

	CONF_DATA const *one = a;
	CONF_DATA const *two = b;

	rcode = one->flag - two->flag;
	if (rcode != 0) return rcode;

	return strcmp(one->name, two->name);
}

static int _cf_section_free(CONF_SECTION *cs)
{
	/*
	 *	Name1 and name2 are allocated contiguous with
	 *	cs.
	 */
	if (cs->pair_tree) {
		rbtree_free(cs->pair_tree);
		cs->pair_tree = NULL;
	}
	if (cs->section_tree) {
		rbtree_free(cs->section_tree);
		cs->section_tree = NULL;
	}
	if (cs->name2_tree) {
		rbtree_free(cs->name2_tree);
		cs->name2_tree = NULL;
	}
	if (cs->data_tree) {
		rbtree_free(cs->data_tree);
		cs->data_tree = NULL;
	}

	return 0;
}


/*
 *	Allocate a CONF_SECTION
 */
CONF_SECTION *cf_section_alloc(CONF_SECTION *parent, char const *name1,
			       char const *name2)
{
	CONF_SECTION *cs;
	char buffer[1024];

	if (!name1) return NULL;

	if (name2) {
		if (strchr(name2, '$')) {
			name2 = cf_expand_variables(parent->item.filename,
						&parent->item.lineno,
						parent,
						buffer, sizeof(buffer), name2);
			if (!name2) {
				ERROR("Failed expanding section name");
				return NULL;
			}
		}
	}

	cs = talloc_zero(parent, CONF_SECTION);
	if (!cs) return NULL;

	cs->item.type = CONF_ITEM_SECTION;
	cs->item.parent = parent;

	cs->name1 = talloc_typed_strdup(cs, name1);
	if (!cs->name1) {
	error:
		talloc_free(cs);
		return NULL;
	}

	if (name2 && *name2) {
		cs->name2 = talloc_typed_strdup(cs, name2);
		if (!cs->name2) goto error;
	}

	cs->pair_tree = rbtree_create(cs, pair_cmp, NULL, 0);
	if (!cs->pair_tree) goto error;

	talloc_set_destructor(cs, _cf_section_free);

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

void cf_section_add(CONF_SECTION *parent, CONF_SECTION *cs)
{
	cf_item_add(parent, &(cs->item));
}

/*
 *	Replace pair in a given section with a new pair,
 *	of the given value.
 */
int cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, char const *value)
{
	CONF_PAIR *newp;
	CONF_ITEM *ci, *cn, **last;

	newp = cf_pair_alloc(cs, cp->attr, value, cp->op, cp->value_type);
	if (!newp) return -1;

	ci = &(cp->item);
	cn = &(newp->item);

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
	if (!cs || !ci) return;

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
		 *	For fast lookups, pairs and sections get
		 *	added to rbtree's.
		 */
		switch (ci->type) {
		case CONF_ITEM_PAIR:
			if (!rbtree_insert(cs->pair_tree, ci)) {
				CONF_PAIR *cp = cf_itemtopair(ci);

				if (strcmp(cp->attr, "confdir") == 0) break;
				if (!cp->value) break; /* module name, "ok", etc. */
			}
			break;

		case CONF_ITEM_SECTION: {
			CONF_SECTION *cs_new = cf_itemtosection(ci);
			CONF_SECTION *name1_cs;

			if (!cs->section_tree) {
				cs->section_tree = rbtree_create(cs, section_cmp, NULL, 0);
				if (!cs->section_tree) {
					ERROR("Out of memory");
					fr_exit_now(1);
				}
			}

			name1_cs = rbtree_finddata(cs->section_tree, cs_new);
			if (!name1_cs) {
				if (!rbtree_insert(cs->section_tree, cs_new)) {
					ERROR("Failed inserting section into tree");
					fr_exit_now(1);
				}
				break;
			}

#if 0
			/*
			 *	We'll ignore these checks for
			 *	now.  Various sections can be
			 *	duplicated, such as "listen",
			 *	"update", "if", "else", etc.
			 */
			if (!name1_cs->name2 && !cs_new->name2) {
				WARN("%s[%d] Duplicate configuration section \"%s { ...}\" %s %d",
				     ci->filename, ci->lineno, cs_new->name1,
				     name1_cs->item.filename, name1_cs->item.lineno);
				break;
			}

			if ((name1_cs->name2 && cs_new->name2) &&
			    (strcmp(name1_cs->name2, cs_new->name2) == 0)) {
				WARN("%s[%d] Duplicate configuration section \"%s %s { ...}\"",
				     ci->filename, ci->lineno, cs_new->name1, cs_new->name2);
				break;
			}
#endif

			/*
			 *	We already have a section of
			 *	this "name1".  Add a new
			 *	sub-section based on name2.
			 */
			if (!name1_cs->name2_tree) {
				name1_cs->name2_tree = rbtree_create(name1_cs, name2_cmp, NULL, 0);
				if (!name1_cs->name2_tree) {
					ERROR("Out of memory");
					fr_exit_now(1);
				}
			}

			/*
			 *	We don't care if this fails.
			 *	If the user tries to create
			 *	two sections of the same
			 *	name1/name2, the duplicate
			 *	section is just silently
			 *	ignored.
			 */
			rbtree_insert(name1_cs->name2_tree, cs_new);
			break;
		} /* was a section */

		case CONF_ITEM_DATA:
			if (!cs->data_tree) {
				cs->data_tree = rbtree_create(cs, data_cmp, NULL, 0);
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


CONF_ITEM *cf_reference_item(CONF_SECTION const *parentcs,
			     CONF_SECTION *outercs,
			     char const *ptr)
{
	CONF_PAIR *cp;
	CONF_SECTION *next;
	CONF_SECTION const *cs = outercs;
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
		 *	Just '.' means the current section
		 */
		if (*p == '\0') {
			return cf_sectiontoitem(cs);
		}

		/*
		 *	..foo means "foo from the section
		 *	enclosing this section" (etc.)
		 */
		while (*p == '.') {
			if (cs->item.parent) {
				cs = cs->item.parent;
			}

			/*
			 *	.. means the section
			 *	enclosing this section
			 */
			if (!*++p) {
				return cf_sectiontoitem(cs);
			}
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
				return &(next->item);
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
	if (cp) return &(cp->item);

	next = cf_section_sub_find(cs, p);
	if (next) return &(next->item);

	/*
	 *	"foo" is "in the current section, OR in main".
	 */
	if ((p == name) && (parentcs != NULL) && (cs != parentcs)) {
		cs = parentcs;
		goto retry;
	}

no_such_item:
	WARN("No such configuration item %s", ptr);
	return NULL;
}


CONF_SECTION *cf_top_section(CONF_SECTION *cs)
{
	if (!cs) return NULL;

	while (cs->item.parent != NULL) {
		cs = cs->item.parent;
	}

	return cs;
}


/*
 *	Expand the variables in an input string.
 */
static char const *cf_expand_variables(char const *cf, int *lineno,
				       CONF_SECTION *outercs,
				       char *output, size_t outsize,
				       char const *input)
{
	char *p;
	char const *end, *ptr;
	CONF_SECTION const *parentcs;
	char name[8192];

	/*
	 *	Find the master parent conf section.
	 *	We can't use main_config.config, because we're in the
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
			char *q;

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
				INFO("%s[%d]: Variable expansion missing }",
				       cf, *lineno);
				return NULL;
			}

			ptr += 2;

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (end - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Reference string is too large",
				       cf, *lineno);
				return NULL;
			}

			memcpy(name, ptr, end - ptr);
			name[end - ptr] = '\0';

			q = strchr(name, ':');
			if (q) {
				*(q++) = '\0';
			}

			ci = cf_reference_item(parentcs, outercs, name);
			if (!ci) {
				ERROR("%s[%d]: Reference \"%s\" not found", cf, *lineno, input);
				return NULL;
			}

			/*
			 *	The expansion doesn't refer to another item or section
			 *	it's the property of a section.
			 */
			if (q) {
				CONF_SECTION *mycs = cf_itemtosection(ci);

				if (ci->type != CONF_ITEM_SECTION) {
					ERROR("%s[%d]: Can only reference properties of sections", cf, *lineno);
					return NULL;
				}

				switch (fr_str2int(conf_property_name, q, CONF_PROPERTY_INVALID)) {
				case CONF_PROPERTY_NAME:
					strcpy(p, mycs->name1);
					break;

				case CONF_PROPERTY_INSTANCE:
					strcpy(p, mycs->name2 ? mycs->name2 : mycs->name1);
					break;

				default:
					ERROR("%s[%d]: Invalid property '%s'", cf, *lineno, q);
					return NULL;
				}
				p += strlen(p);
				ptr = end + 1;

			} else if (ci->type == CONF_ITEM_PAIR) {
				/*
				 *  Substitute the value of the variable.
				 */
				cp = cf_itemtopair(ci);
				if (!cp->value) {
					ERROR("%s[%d]: Reference \"%s\" has no value",
					       cf, *lineno, input);
					return NULL;
				}

				if (p + strlen(cp->value) >= output + outsize) {
					ERROR("%s[%d]: Reference \"%s\" is too long",
					       cf, *lineno, input);
					return NULL;
				}

				strcpy(p, cp->value);
				p += strlen(p);
				ptr = end + 1;

			} else if (ci->type == CONF_ITEM_SECTION) {
				CONF_SECTION *subcs;

				/*
				 *	Adding an entry again to a
				 *	section is wrong.  We don't
				 *	want an infinite loop.
				 */
				if (ci->parent == outercs) {
					ERROR("%s[%d]: Cannot reference different item in same section", cf, *lineno);
					return NULL;
				}

				/*
				 *	Copy the section instead of
				 *	referencing it.
				 */
				subcs = cf_template_copy(outercs, cf_itemtosection(ci));
				if (!subcs) {
					ERROR("%s[%d]: Failed copying reference %s", cf, *lineno, name);
					return NULL;
				}

				subcs->item.filename = ci->filename;
				subcs->item.lineno = ci->lineno;
				cf_item_add(outercs, &(subcs->item));

				ptr = end + 1;

			} else {
				ERROR("%s[%d]: Reference \"%s\" type is invalid", cf, *lineno, input);
				return NULL;
			}
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
				INFO("%s[%d]: Environment variable expansion missing }",
				       cf, *lineno);
				return NULL;
			}

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (end - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Environment variable name is too large",
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

			if (p + strlen(env) >= output + outsize) {
				ERROR("%s[%d]: Reference \"%s\" is too long",
				       cf, *lineno, input);
				return NULL;
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


		if (p >= (output + outsize)) {
			ERROR("%s[%d]: Reference \"%s\" is too long",
			       cf, *lineno, input);
			return NULL;
		}
	} /* loop over all of the input string. */

	*p = '\0';

	return output;
}

static char const parse_spaces[] = "                                                                                                                                                                                                                                                                ";

/** Validation function for ipaddr conffile types
 *
 */
static inline int fr_item_validate_ipaddr(CONF_SECTION *cs, char const *name, PW_TYPE type, char const *value,
					  fr_ipaddr_t *ipaddr)
{
	char ipbuf[128];

	if (strcmp(value, "*") == 0) {
		cf_log_info(cs, "%.*s\t%s = *", cs->depth, parse_spaces, name);
	} else if (strspn(value, ".0123456789abdefABCDEF:%[]/") == strlen(value)) {
		cf_log_info(cs, "%.*s\t%s = %s", cs->depth, parse_spaces, name, value);
	} else {
		cf_log_info(cs, "%.*s\t%s = %s IPv%s address [%s]", cs->depth, parse_spaces, name, value,
			    (ipaddr->af == AF_INET ? "4" : " 6"), ip_ntoh(ipaddr, ipbuf, sizeof(ipbuf)));
	}

	switch (type) {
	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_IPV6_ADDR:
	case PW_TYPE_IP_ADDR:
		switch (ipaddr->af) {
		case AF_INET:
		if (ipaddr->prefix != 32) {
			ERROR("Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted for non-prefix types",
			      ipaddr->prefix);

			return -1;
		}
			break;

		case AF_INET6:
		if (ipaddr->prefix != 128) {
			ERROR("Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted for non-prefix types",
			      ipaddr->prefix);

			return -1;
		}
			break;

		default:
			return -1;
		}
	default:
		return 0;
	}
}

/*
 *	Parses an item (not a CONF_ITEM) into the specified format,
 *	with a default value.
 *
 *	Returns -1 on error, -2 if deprecated, 0 for correctly parsed,
 *	and 1 if the default value was used.  Note that the default
 *	value will be used ONLY if the CONF_PAIR is NULL.
 */
int cf_item_parse(CONF_SECTION *cs, char const *name, int type, void *data, char const *dflt)
{
	int rcode;
	bool deprecated, required, attribute, secret;
	char **q;
	char const *value;
	CONF_PAIR const *cp = NULL;
	fr_ipaddr_t *ipaddr;
	char buffer[8192];

	if (!cs) return -1;

	deprecated = (type & PW_TYPE_DEPRECATED);
	required = (type & PW_TYPE_REQUIRED);
	attribute = (type & PW_TYPE_ATTRIBUTE);
	secret = (type & PW_TYPE_SECRET);

	type &= 0xff;		/* normal types are small */
	rcode = 0;

	if (attribute) {
		required = true;
	}

	cp = cf_pair_find(cs, name);
	if (cp) {
		value = cp->value;
	} else {
		rcode = 1;
		value = dflt;
	}

	if (!value) {
		if (required) {
			cf_log_err(&(cs->item), "Configuration item '%s' must have a value", name);
			return -1;
		}
		return rcode;
	}

	if (!*value && required) {
	is_required:
		if (!cp) {
			cf_log_err(&(cs->item), "Configuration item '%s' must not be empty", name);
		} else {
			cf_log_err(&(cp->item), "Configuration item '%s' must not be empty", name);
		}
		return -1;
	}

	if (deprecated) {
		cf_log_err(&(cs->item), "Configuration item \"%s\" is deprecated", name);

		return -2;
	}

	switch (type) {
	case PW_TYPE_BOOLEAN:
		/*
		 *	Allow yes/no and on/off
		 */
		if ((strcasecmp(value, "yes") == 0) ||
		    (strcasecmp(value, "on") == 0)) {
			*(bool *)data = true;
		} else if ((strcasecmp(value, "no") == 0) ||
			   (strcasecmp(value, "off") == 0)) {
			*(bool *)data = false;
		} else {
			*(bool *)data = false;
			cf_log_err(&(cs->item), "Invalid value \"%s\" for boolean "
			       "variable %s", value, name);
			return -1;
		}
		cf_log_info(cs, "%.*s\t%s = %s",
			    cs->depth, parse_spaces, name, value);
		break;

	case PW_TYPE_INTEGER:
	{
		unsigned long v = strtoul(value, 0, 0);

		/*
		 *	Restrict integer values to 0-INT32_MAX, this means
		 *	it will always be safe to cast them to a signed type
		 *	for comparisons, and imposes the same range limit as
		 *	before we switched to using an unsigned type to
		 *	represent config item integers.
		 */
		if (v > INT32_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", value,
				   name, INT32_MAX);
			return -1;
		}

		*(uint32_t *)data = v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, name, *(uint32_t *)data);
	}
		break;

	case PW_TYPE_SHORT:
	{
		unsigned long v = strtoul(value, 0, 0);

		if (v > UINT16_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", value,
				   name, UINT16_MAX);
			return -1;
		}
		*(uint16_t *)data = (uint16_t) v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, name, *(uint16_t *)data);
	}
		break;

	case PW_TYPE_INTEGER64:
		*(uint64_t *)data = strtoull(value, 0, 0);
		cf_log_info(cs, "%.*s\t%s = %" PRIu64, cs->depth, parse_spaces, name, *(uint64_t *)data);
		break;

	case PW_TYPE_SIGNED:
		*(int32_t *)data = strtol(value, 0, 0);
		cf_log_info(cs, "%.*s\t%s = %d", cs->depth, parse_spaces, name, *(int32_t *)data);
		break;

	case PW_TYPE_STRING:
		q = (char **) data;
		if (*q != NULL) {
			talloc_free(*q);
		}

		/*
		 *	Expand variables which haven't already been
		 *	expanded automagically when the configuration
		 *	file was read.
		 */
		if (value == dflt) {
			int lineno = 0;

			lineno = cs->item.lineno;

			value = cf_expand_variables("<internal>",
						    &lineno,
						    cs, buffer, sizeof(buffer),
						    value);
			if (!value) {
				cf_log_err(&(cs->item),"Failed expanding variable %s", name);
				return -1;
			}
		}

		if (required && (!value || !*value)) goto is_required;

		if (attribute) {
			if (!dict_attrbyname(value)) {
				if (!cp) {
					cf_log_err(&(cs->item), "No such attribute '%s' for configuration '%s'",
						      value, name);
				} else {
					cf_log_err(&(cp->item), "No such attribute '%s'",
						   value);
				}
				return -1;
			}
		}

		/*
		 *	Hide secrets when using "radiusd -X".
		 */
		if (secret && (debug_flag <= 2)) {
			cf_log_info(cs, "%.*s\t%s = <<< secret >>>",
				    cs->depth, parse_spaces, name);
		} else {
			cf_log_info(cs, "%.*s\t%s = \"%s\"",
				    cs->depth, parse_spaces, name, value ? value : "(null)");
		}
		*q = value ? talloc_typed_strdup(cs, value) : NULL;
		break;

		/*
		 *	This is the same as PW_TYPE_STRING,
		 *	except that we also "stat" the file, and
		 *	cache the result.
		 */
	case PW_TYPE_FILE_INPUT:
	case PW_TYPE_FILE_OUTPUT:
		q = (char **) data;
		if (*q != NULL) {
			free(*q);
		}

		/*
		 *	Expand variables which haven't already been
		 *	expanded automagically when the configuration
		 *	file was read.
		 */
		if ((value == dflt) && cs) {
			int lineno = 0;

			value = cf_expand_variables("?",
						    &lineno,
						    cs, buffer, sizeof(buffer),
						    value);
			if (!value) return -1;
		}

		if (required && (!value || !*value)) goto is_required;

		cf_log_info(cs, "%.*s\t%s = \"%s\"",
			    cs->depth, parse_spaces, name, value);
		*q = value ? talloc_typed_strdup(cs, value) : NULL;

		/*
		 *	If the filename exists and we're supposed to
		 *	read it, check it.
		 */
		if (*q && (type == PW_TYPE_FILE_INPUT)) {
			struct stat buf;

			if (stat(*q, &buf) < 0) {
				ERROR("Unable to open file \"%s\": %s",
				      value, fr_syserror(errno));
				return -1;
			}
		}
		break;

	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_IPV4_PREFIX:
		ipaddr = data;

		if (fr_pton4(ipaddr, value, 0, true, false) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
		}
		if (fr_item_validate_ipaddr(cs, name, type, value, ipaddr) < 0) return -1;
		break;

	case PW_TYPE_IPV6_ADDR:
	case PW_TYPE_IPV6_PREFIX:
		ipaddr = data;

		if (fr_pton6(ipaddr, value, 0, true, false) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
		}
		if (fr_item_validate_ipaddr(cs, name, type, value, ipaddr) < 0) return -1;
		break;

	case PW_TYPE_IP_ADDR:
	case PW_TYPE_IP_PREFIX:
		ipaddr = data;

		if (fr_pton(ipaddr, value, 0, true) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
		}
		if (fr_item_validate_ipaddr(cs, name, type, value, ipaddr) < 0) return -1;
		break;

	case PW_TYPE_TIMEVAL: {
		int sec;
		char *end;
		struct timeval tv;

		sec = strtoul(value, &end, 10);
		tv.tv_sec = sec;
		tv.tv_usec = 0;
		if (*end == '.') {
			sec = strlen(end + 1);

			if (sec > 6) {
				ERROR("Too much precision for timeval");
				return -1;
			}

			strcpy(buffer, "000000");
			memcpy(buffer, end + 1, sec);

			sec = strtoul(buffer, NULL, 10);
			tv.tv_usec = sec;
		}
		cf_log_info(cs, "%.*s\t%s = %d.%06d",
			    cs->depth, parse_spaces, name, (int) tv.tv_sec, (int) tv.tv_usec);
		memcpy(data, &tv, sizeof(tv));
		}
		break;

	default:
		/*
		 *	If we get here, it's a sanity check error.
		 *	It's not an error parsing the configuration
		 *	file.
		 */
		rad_assert(type > PW_TYPE_INVALID);
		rad_assert(type < PW_TYPE_MAX);

		ERROR("type '%s' is not supported in the configuration files",
		       fr_int2str(dict_attr_types, type, "?Unknown?"));
		return -1;
	} /* switch over variable type */

	if (!cp) {
		CONF_PAIR *cpn;

		cpn = cf_pair_alloc(cs, name, value, T_OP_SET, T_BARE_WORD);
		if (!cpn) return -1;
		cpn->item.filename = "<internal>";
		cpn->item.lineno = 0;
		cf_item_add(cs, &(cpn->item));
	}

	return rcode;
}


/*
 *	A copy of cf_section_parse that initializes pointers before
 *	parsing them.
 */
static void cf_section_parse_init(CONF_SECTION *cs, void *base,
				  CONF_PARSER const *variables)
{
	int i;
	void *data;

	for (i = 0; variables[i].name != NULL; i++) {
		if (variables[i].type == PW_TYPE_SUBSECTION) {
			CONF_SECTION *subcs;

			if (!variables[i].dflt) continue;

			subcs = cf_section_sub_find(cs, variables[i].name);

			/*
			 *	If there's no subsection in the
			 *	config, BUT the CONF_PARSER wants one,
			 *	then create an empty one.  This is so
			 *	that we can track the strings,
			 *	etc. allocated in the subsection.
			 */
			if (!subcs) {
				subcs = cf_section_alloc(cs, variables[i].name,
							 NULL);
				if (!subcs) return;

				subcs->item.filename = cs->item.filename;
				subcs->item.lineno = cs->item.lineno;
				cf_item_add(cs, &(subcs->item));
			}

			cf_section_parse_init(subcs, base,
					      (CONF_PARSER const *) variables[i].dflt);
			continue;
		}

		if ((variables[i].type != PW_TYPE_STRING) &&
		    (variables[i].type != PW_TYPE_FILE_INPUT) &&
		    (variables[i].type != PW_TYPE_FILE_OUTPUT)) {
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
		     CONF_PARSER const *variables)
{
	int ret;
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

			if (!variables[i].dflt || !subcs) {
				DEBUG2("Internal sanity check 1 failed in cf_section_parse %s",
				       variables[i].name);
				goto error;
			}

			if (cf_section_parse(subcs, base,
					     (CONF_PARSER const *) variables[i].dflt) < 0) {
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
		ret = cf_item_parse(cs, variables[i].name, variables[i].type, data, variables[i].dflt);
		if (ret < 0) {
			/*
			 *	Be nice, and print the name of the new config item.
			 */
			if ((ret == -2) && (variables[i + 1].offset == variables[i].offset) &&
			    (variables[i + 1].data == variables[i].data)) {
				cf_log_err(&(cs->item), "Replace \"%s\" with \"%s\"", variables[i].name,
					   variables[i + 1].name);
			}

			goto error;
		}
	} /* for all variables in the configuration section */

	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);

	cs->base = base;

	return 0;

 error:
	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);
	return -1;
}


static CONF_SECTION *cf_template_copy(CONF_SECTION *parent, CONF_SECTION const *template)
{
	CONF_ITEM *ci;
	CONF_SECTION *cs;

	cs = cf_section_alloc(parent, template->name1, template->name2);
	if (!cs) return NULL;

	for (ci = template->children; ci; ci = ci->next) {
		if (ci->type == CONF_ITEM_PAIR) {
			CONF_PAIR *cp1, *cp2;

			cp1 = cf_itemtopair(ci);
			cp2 = cf_pair_alloc(cs, cp1->attr, cp1->value, cp1->op, cp1->value_type);
			if (!cp2) return false;

			cp2->item.filename = cp1->item.filename;
			cp2->item.lineno = cp1->item.lineno;

			cf_item_add(cs, &(cp2->item));
			continue;
		}

		if (ci->type == CONF_ITEM_SECTION) {
			CONF_SECTION *subcs1, *subcs2;

			subcs1 = cf_itemtosection(ci);
			subcs2 = cf_template_copy(cs, subcs1);

			subcs2->item.filename = subcs1->item.filename;
			subcs2->item.lineno = subcs1->item.lineno;

			cf_item_add(cs, &(subcs2->item));
			continue;
		}

		/* ignore everything else */
	}

	return cs;
}


/*
 *	Merge the template so everyting else "just works".
 */
static bool cf_template_merge(CONF_SECTION *cs, CONF_SECTION const *template)
{
	CONF_ITEM *ci;

	if (!cs || !template) return true;

	cs->template = NULL;

	/*
	 *	Walk over the template, adding its' entries to the
	 *	current section.  But only if the entries don't
	 *	already exist in the current section.
	 */
	for (ci = template->children; ci; ci = ci->next) {
		if (ci->type == CONF_ITEM_PAIR) {
			CONF_PAIR *cp1, *cp2;

			/*
			 *	It exists, don't over-write it.
			 */
			cp1 = cf_itemtopair(ci);
			if (cf_pair_find(cs, cp1->attr)) {
				continue;
			}

			/*
			 *	Create a new pair with all of the data
			 *	of the old one.
			 */
			cp2 = cf_pair_alloc(cs, cp1->attr, cp1->value, cp1->op, cp1->value_type);
			if (!cp2) return false;

			cp2->item.filename = cp1->item.filename;
			cp2->item.lineno = cp1->item.lineno;

			cf_item_add(cs, &(cp2->item));
			continue;
		}

		if (ci->type == CONF_ITEM_SECTION) {
			CONF_SECTION *subcs1, *subcs2;

			subcs1 = cf_itemtosection(ci);
			rad_assert(subcs1 != NULL);

			subcs2 = cf_section_sub_find_name2(cs, subcs1->name1, subcs1->name2);
			if (subcs2) {
				/*
				 *	sub-sections get merged.
				 */
				if (!cf_template_merge(subcs2, subcs1)) {
					return false;
				}
				continue;
			}

			/*
			 *	Our section doesn't have a matching
			 *	sub-section.  Copy it verbatim from
			 *	the template.
			 */
			subcs2 = cf_template_copy(cs, subcs1);
			if (!subcs2) return false;

			subcs2->item.filename = subcs1->item.filename;
			subcs2->item.lineno = subcs1->item.lineno;

			cf_item_add(cs, &(subcs2->item));
			continue;
		}

		/* ignore everything else */
	}

	return true;
}

static char const *cf_local_file(char const *base, char const *filename,
				 char *buffer, size_t bufsize)
{
	size_t dirsize;
	char *p;

	strlcpy(buffer, base, bufsize);

	p = strrchr(buffer, FR_DIR_SEP);
	if (!p) return filename;
	if (p[1]) {		/* ./foo */
		p[1] = '\0';
	}

	dirsize = (p - buffer) + 1;

	if ((dirsize + strlen(filename)) >= bufsize) {
		return NULL;
	}

	strlcpy(p + 1, filename, bufsize - dirsize);

	return buffer;
}

static int seen_too_much(char const *filename, int lineno, char const *ptr)
{
	while (*ptr) {
		if (isspace(*ptr)) {
			ptr++;
			continue;
		}

		if (*ptr == '#') return false;

		break;
	}

	if (*ptr) {
		ERROR("%s[%d] Unexpected text %s.  See \"man unlang\"",
		       filename, lineno, ptr);
		return true;
	}

	return false;
}


/*
 *	Read a part of the config file.
 */
static int cf_section_read(char const *filename, int *lineno, FILE *fp,
			   CONF_SECTION *current)

{
	CONF_SECTION *this, *css, *nextcs;
	CONF_PAIR *cpn;
	char const *ptr, *start;
	char const *value;
	char buf[8192];
	char buf1[8192];
	char buf2[8192];
	char buf3[8192];
	FR_TOKEN t1, t2, t3;
	bool spaces = false;
	char *cbuf = buf;
	size_t len;
	fr_cond_t *cond = NULL;

	this = current;		/* add items here */

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		int at_eof;
		nextcs = NULL;

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
			ERROR("%s[%d]: Line too long",
			       filename, *lineno);
			return -1;
		}

		if (spaces) {
			ptr = cbuf;
			while (isspace((int) *ptr)) ptr++;

			if (ptr > cbuf) {
				memmove(cbuf, ptr, len - (ptr - cbuf));
				len -= (ptr - cbuf);
			}
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
			ERROR("%s[%d]: Continuation at EOF is illegal",
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
			/*
			 *	Check for "suppress spaces" magic.
			 */
			if (!spaces && (len > 2) && (cbuf[len - 2] == '"')) {
				spaces = true;
			}

			cbuf[len - 1] = '\0';
			cbuf += len - 1;
			continue;
		}

		ptr = cbuf = buf;
		spaces = false;

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
				ERROR("%s[%d]: Invalid expansion: %s",
				       filename, *lineno, ptr);
				return -1;
			}

			ptr += hack;

			t2 = gettoken(&ptr, buf2, sizeof(buf2), true);
			switch (t2) {
			case T_EOL:
			case T_HASH:
				goto do_bare_word;

			default:
				ERROR("%s[%d]: Invalid expansion: %s",
				       filename, *lineno, ptr);
				return -1;
			}
		} else {
			t1 = gettoken(&ptr, buf1, sizeof(buf1), true);
		}

		/*
		 *	The caller eats "name1 name2 {", and calls us
		 *	for the data inside of the section.  So if we
		 *	receive a closing brace, then it must mean the
		 *	end of the section.
		 */
	       if (t1 == T_RCBRACE) {
		       if (this == current) {
			       ERROR("%s[%d]: Too many closing braces",
				      filename, *lineno);
			       return -1;
		       }

		       /*
			*	Merge the template into the existing
			*	section.  This uses more memory, but
			*	means that templates now work with
			*	sub-sections, etc.
			*/
		       if (!cf_template_merge(this, this->template)) {
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
			bool relative = true;

			t2 = getword(&ptr, buf2, sizeof(buf2), true);
			if (t2 != T_EOL) {
			       ERROR("%s[%d]: Unexpected text after $INCLUDE",
				     filename, *lineno);
			       return -1;
			}

			if (buf2[0] == '$') relative = false;

			value = cf_expand_variables(filename, lineno, this, buf, sizeof(buf), buf2);
			if (!value) return -1;

			if (!FR_DIR_IS_RELATIVE(value)) relative = false;

			if (relative) {
				value = cf_local_file(filename, value, buf3,
						      sizeof(buf3));
				if (!value) {
					ERROR("%s[%d]: Directories too deep.",
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
#ifdef S_IWOTH
				/*
				 *	Security checks.
				 */
				if (stat(value, &stat_buf) < 0) {
					ERROR("%s[%d]: Failed reading directory %s: %s",
					       filename, *lineno,
					       value, fr_syserror(errno));
					return -1;
				}

				if ((stat_buf.st_mode & S_IWOTH) != 0) {
					ERROR("%s[%d]: Directory %s is globally writable.  Refusing to start due to "
					      "insecure configuration", filename, *lineno, value);
					return -1;
				}
#endif
				dir = opendir(value);
				if (!dir) {
					ERROR("%s[%d]: Error reading directory %s: %s",
					       filename, *lineno, value,
					       fr_syserror(errno));
					return -1;
				}

				/*
				 *	Read the directory, ignoring "." files.
				 */
				while ((dp = readdir(dir)) != NULL) {
					char const *p;

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
					 *	configuration section.
					 */
					if (cf_file_include(this, buf2) < 0) {
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
						WARN("Not including file %s: %s", value, fr_syserror(errno));
						continue;
					}
				}

				if (cf_file_include(this, value) < 0) {
					return -1;
				}
			}
			continue;
		} /* we were in an include */

	       if (strcasecmp(buf1, "$template") == 0) {
		       CONF_ITEM *ci;
		       CONF_SECTION *parentcs, *templatecs;
		       t2 = getword(&ptr, buf2, sizeof(buf2), true);

		       if (t2 != T_EOL) {
			       ERROR("%s[%d]: Unexpected text after $TEMPLATE", filename, *lineno);
			       return -1;
		       }

		       parentcs = cf_top_section(current);

		       templatecs = cf_section_sub_find(parentcs, "templates");
		       if (!templatecs) {
				ERROR("%s[%d]: No \"templates\" section for reference \"%s\"", filename, *lineno, buf2);
				return -1;
		       }

		       ci = cf_reference_item(parentcs, templatecs, buf2);
		       if (!ci || (ci->type != CONF_ITEM_SECTION)) {
				ERROR("%s[%d]: Reference \"%s\" not found", filename, *lineno, buf2);
				return -1;
		       }

		       if (!this) {
				ERROR("%s[%d]: Internal sanity check error in template reference", filename, *lineno);
				return -1;
		       }

		       if (this->template) {
				ERROR("%s[%d]: Section already has a template", filename, *lineno);
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
			ERROR("%s[%d]: Illegal configuration pair name \"%s\"", filename, *lineno, buf1);
			return -1;
		}

		/*
		 *	Handle if/elsif specially.
		 */
		if ((strcmp(buf1, "if") == 0) || (strcmp(buf1, "elsif") == 0)) {
			ssize_t slen;
			char const *error = NULL;
			char *p;
			CONF_SECTION *server;

			/*
			 *	if / elsif MUST be inside of a
			 *	processing section, which MUST in turn
			 *	be inside of a "server" directive.
			 */
			if (!this->item.parent) {
			invalid_location:
				ERROR("%s[%d]: Invalid location for '%s'",
				       filename, *lineno, buf1);
				return -1;
			}

			/*
			 *	If there's a ${...}.  If so, expand it.
			 */
			start = buf;
			if (strchr(ptr, '$') != NULL) {
				start = buf3;
				ptr = cf_expand_variables(filename, lineno,
							  this,
							  buf3, sizeof(buf3),
							  ptr);
				if (!ptr) {
					ERROR("%s[%d]: Parse error expanding ${...} in condition",
					      filename, *lineno);
					return -1;
				}
			} /* else leave it alone */

			p = strrchr(ptr, '{'); /* ugh */
			if (p) *p = '\0';

			server = this->item.parent;
			while ((strcmp(server->name1, "server") != 0) &&
			       (strcmp(server->name1, "policy") != 0)) {
				server = server->item.parent;
				if (!server) goto invalid_location;
			}

			nextcs = cf_section_alloc(this, buf1, ptr);
			if (!nextcs) {
				ERROR("%s[%d]: Failed allocating memory for section",
				      filename, *lineno);
				return -1;
			}
			nextcs->item.filename = talloc_strdup(nextcs, filename);
			nextcs->item.lineno = *lineno;

			slen = fr_condition_tokenize(nextcs, cf_sectiontoitem(nextcs), ptr, &cond,
						     &error, FR_COND_TWO_PASS);
			if (p) *p = '{';

			if (slen < 0) {
				size_t offset;
				char *spbuf;

				offset = -slen;
				offset += ptr - start;

				spbuf = malloc(offset + 1);
				memset(spbuf, ' ', offset);
				spbuf[offset] = '\0';

				ERROR("%s[%d]: Parse error in condition",
				       filename, *lineno);

				ERROR("%s", start);
				ERROR("%.*s^ %s", (int) offset, spbuf, error);
				talloc_free(nextcs);
				free(spbuf);
				return -1;
			}

			if ((size_t) slen >= (sizeof(buf2) - 1)) {
				talloc_free(nextcs);
				ERROR("%s[%d]: Condition is too large after \"%s\"",
				       filename, *lineno, buf1);
				return -1;
			}

			memcpy(buf2, ptr, slen);
			buf2[slen] = '\0';
			ptr += slen;
			t2 = T_BARE_WORD;

			if (gettoken(&ptr, buf3, sizeof(buf3), true) != T_LCBRACE) {
				talloc_free(nextcs);
				ERROR("%s[%d]: Expected '{'",
				       filename, *lineno);
				return -1;
			}

			/*
			 *	Swap the condition with trailing stuff for
			 *	the final condition.
			 */
			memcpy(&p, &nextcs->name2, sizeof(nextcs->name2));
			talloc_free(p);
			nextcs->name2 = talloc_typed_strdup(nextcs, buf2);

			goto section_alloc;
		}

		/*
		 *	Grab the next token.
		 */
		t2 = gettoken(&ptr, buf2, sizeof(buf2), true);
		switch (t2) {
		case T_EOL:
		case T_HASH:
		do_bare_word:
			t3 = t2;
			t2 = T_OP_EQ;
			value = NULL;
			goto do_set;

		case T_OP_INCRM:
		case T_OP_ADD:
		case T_OP_CMP_EQ:
		case T_OP_SUB:
		case T_OP_LE:
		case T_OP_GE:
		case T_OP_CMP_FALSE:
			if (!this || (strcmp(this->name1, "update") != 0)) {
				ERROR("%s[%d]: Invalid operator in assignment",
				       filename, *lineno);
				return -1;
			}
			/* FALL-THROUGH */

		case T_OP_EQ:
		case T_OP_SET:
			t3 = getstring(&ptr, buf3, sizeof(buf3), true);
			if (t3 == T_OP_INVALID) {
				ERROR("%s[%d]: Parse error: %s",
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
				ERROR("%s[%d]: Syntax error: Invalid string `...` in assignment",
				       filename, *lineno);
				return -1;
			}

			/*
			 *	Handle variable substitution via ${foo}
			 */
			switch (t3) {
			case T_BARE_WORD:
			case T_DOUBLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
				value = cf_expand_variables(filename, lineno, this, buf, sizeof(buf), buf3);
				if (!value) return -1;
				break;

			case T_EOL:
			case T_HASH:
				value = NULL;
				break;

			default:
				value = buf3;
			}

			/*
			 *	Add this CONF_PAIR to our CONF_SECTION
			 */
		do_set:
			cpn = cf_pair_alloc(this, buf1, value, t2, t3);
			if (!cpn) return -1;
			cpn->item.filename = talloc_strdup(cpn, filename);
			cpn->item.lineno = *lineno;
			cf_item_add(this, &(cpn->item));
			continue;

			/*
			 *	No '=', must be a section or sub-section.
			 */
		case T_BARE_WORD:
		case T_DOUBLE_QUOTED_STRING:
		case T_SINGLE_QUOTED_STRING:
			t3 = gettoken(&ptr, buf3, sizeof(buf3), true);
			if (t3 != T_LCBRACE) {
				ERROR("%s[%d]: Expecting section start brace '{' after \"%s %s\"",
				       filename, *lineno, buf1, buf2);
				return -1;
			}
			/* FALL-THROUGH */

		case T_LCBRACE:
		section_alloc:
			if (seen_too_much(filename, *lineno, ptr)) {
				if (cond) talloc_free(cond);
				return -1;
			}

			if (!cond) {
				css = cf_section_alloc(this, buf1,
						       t2 == T_LCBRACE ? NULL : buf2);
				if (!css) {
					ERROR("%s[%d]: Failed allocating memory for section",
					      filename, *lineno);
					return -1;
				}

				css->item.filename = talloc_strdup(css, filename);
				css->item.lineno = *lineno;
				cf_item_add(this, &(css->item));

			} else {
				css = nextcs;
				nextcs = NULL;

				cf_item_add(this, &(css->item));
				cf_data_add_internal(css, "if", cond, NULL, false);
				cond = NULL; /* eaten by the above line */
			}

			/*
			 *	There may not be a name2
			 */
			css->name2_type = (t2 == T_LCBRACE) ? T_OP_INVALID : t2;

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			continue;

		case T_OP_INVALID:
			ERROR("%s[%d]: Syntax error in '%s': %s", filename, *lineno, ptr, fr_strerror());

			return -1;

		default:
			ERROR("%s[%d]: Parse error after \"%s\": unexpected token \"%s\"",
			      filename, *lineno, buf1, fr_int2str(fr_tokens, t2, "<INVALID>"));

			return -1;
		}
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (feof(fp) && (this != current)) {
		ERROR("%s[%d]: EOF reached without closing brace for section %s starting at line %d",
		      filename, *lineno, cf_section_name1(this), cf_section_lineno(this));
		return -1;
	}

	return 0;
}

/*
 *	Include one config file in another.
 */
int cf_file_include(CONF_SECTION *cs, char const *filename)
{
	FILE		*fp;
	int		lineno = 0;
	struct stat	statbuf;
	time_t		*mtime;
	CONF_DATA	*cd;

	DEBUG2("including configuration file %s", filename);

	fp = fopen(filename, "r");
	if (!fp) {
		ERROR("Unable to open file \"%s\": %s",
		       filename, fr_syserror(errno));
		return -1;
	}

	if (stat(filename, &statbuf) == 0) {
#ifdef S_IWOTH
		if ((statbuf.st_mode & S_IWOTH) != 0) {
			fclose(fp);
			ERROR("Configuration file %s is globally writable.  "
			      "Refusing to start due to insecure configuration.", filename);
			return -1;
		}
#endif

#ifdef S_IROTH
		if (0 && (statbuf.st_mode & S_IROTH) != 0) {
			fclose(fp);
			ERROR("Configuration file %s is globally readable.  "
			      "Refusing to start due to insecure configuration", filename);
			return -1;
		}
#endif
	}

	if (cf_data_find_internal(cs, filename, PW_TYPE_FILE_INPUT)) {
		fclose(fp);
		ERROR("Cannot include the same file twice: \"%s\"", filename);

		return -1;
	}

	/*
	 *	Add the filename to the section
	 */
	mtime = talloc(cs, time_t);
	*mtime = statbuf.st_mtime;

	if (cf_data_add_internal(cs, filename, mtime, NULL, PW_TYPE_FILE_INPUT) < 0) {
		fclose(fp);
		ERROR("Internal error opening file \"%s\"",
		       filename);
		return -1;
	}

	cd = cf_data_find_internal(cs, filename, PW_TYPE_FILE_INPUT);
	if (!cd) {
		fclose(fp);
		ERROR("Internal error opening file \"%s\"",
		       filename);
		return -1;
	}

	if (!cs->item.filename) cs->item.filename = talloc_strdup(cs, filename);

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
CONF_SECTION *cf_file_read(char const *filename)
{
	char *p;
	CONF_PAIR *cp;
	CONF_SECTION *cs;

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs) return NULL;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_SET, T_BARE_WORD);
	if (!cp) return NULL;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cp->item.filename = "internal";
	cp->item.lineno = -1;
	cf_item_add(cs, &(cp->item));

	if (cf_file_include(cs, filename) < 0) {
		talloc_free(cs);
		return NULL;
	}

	return cs;
}


void cf_file_free(CONF_SECTION *cs)
{
	talloc_free(cs);
}


/*
 * Return a CONF_PAIR within a CONF_SECTION.
 */
CONF_PAIR *cf_pair_find(CONF_SECTION const *cs, char const *name)
{
	CONF_PAIR *cp, mycp;

	if (!cs || !name) return NULL;

	mycp.attr = name;
	cp = rbtree_finddata(cs->pair_tree, &mycp);
	if (cp) return cp;

	if (!cs->template) return NULL;

	return rbtree_finddata(cs->template->pair_tree, &mycp);
}

/*
 * Return the attr of a CONF_PAIR
 */

char const *cf_pair_attr(CONF_PAIR const *pair)
{
	return (pair ? pair->attr : NULL);
}

/*
 * Return the value of a CONF_PAIR
 */

char const *cf_pair_value(CONF_PAIR const *pair)
{
	return (pair ? pair->value : NULL);
}

FR_TOKEN cf_pair_operator(CONF_PAIR const *pair)
{
	return (pair ? pair->op : T_OP_INVALID);
}

/*
 * Return the value type, should be one of the following:
 * T_BARE_WORD, T_SINGLE_QUOTED_STRING, T_BACK_QUOTED_STRING
 * T_DOUBLE_QUOTED_STRING or T_OP_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_value_type(CONF_PAIR const *pair)
{
	return (pair ? pair->value_type : T_OP_INVALID);
}

/*
 * Turn a CONF_PAIR into a VALUE_PAIR
 * For now, ignore the "value_type" field...
 */
VALUE_PAIR *cf_pairtovp(CONF_PAIR *pair)
{
	if (!pair) {
		fr_strerror_printf("Internal error");
		return NULL;
	}

	if (!pair->value) {
		fr_strerror_printf("No value given for attribute %s", pair->attr);
		return NULL;
	}

	/*
	 *	false comparisons never match.  BUT if it's a "string"
	 *	or `string`, then remember to expand it later.
	 */
	if ((pair->op != T_OP_CMP_FALSE) &&
	    ((pair->value_type == T_DOUBLE_QUOTED_STRING) ||
	     (pair->value_type == T_BACK_QUOTED_STRING))) {
		VALUE_PAIR *vp;

		vp = pairmake(pair, NULL, pair->attr, NULL, pair->op);
		if (!vp) {
			return NULL;
		}

		if (pairmark_xlat(vp, pair->value) < 0) {
			talloc_free(vp);

			return NULL;
		}

		return vp;
	}

	return pairmake(pair, NULL, pair->attr, pair->value, pair->op);
}

/*
 * Return the first label of a CONF_SECTION
 */

char const *cf_section_name1(CONF_SECTION const *cs)
{
	return (cs ? cs->name1 : NULL);
}

/*
 * Return the second label of a CONF_SECTION
 */

char const *cf_section_name2(CONF_SECTION const *cs)
{
	return (cs ? cs->name2 : NULL);
}

/** Return name2 if set, else name1
 *
 */
char const *cf_section_name(CONF_SECTION const *cs)
{
	char const *name;

	name = cf_section_name2(cs);
	if (name) return name;

	return cf_section_name1(cs);
}

/*
 * Find a value in a CONF_SECTION
 */
char const *cf_section_value_find(CONF_SECTION const *cs, char const *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(cs, attr);

	return (cp ? cp->value : NULL);
}


CONF_SECTION *cf_section_find_name2(CONF_SECTION const *cs,
				    char const *name1, char const *name2)
{
	char const	*their2;
	CONF_ITEM const *ci;

	if (!cs || !name1) return NULL;

	for (ci = &(cs->item); ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;

		if (strcmp(cf_itemtosection(ci)->name1, name1) != 0) {
			continue;
		}

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

CONF_PAIR *cf_pair_find_next(CONF_SECTION const *cs,
			     CONF_PAIR const *pair, char const *attr)
{
	CONF_ITEM	*ci;

	if (!cs) return NULL;

	/*
	 *	If pair is NULL this must be a first time run
	 *	Find the pair with correct name
	 */

	if (!pair) return cf_pair_find(cs, attr);

	for (ci = pair->item.next; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR)
			continue;

		if (!attr || strcmp(cf_itemtopair(ci)->attr, attr) == 0)
			break;
	}

	return cf_itemtopair(ci);
}

/*
 * Find a CONF_SECTION, or return the root if name is NULL
 */

CONF_SECTION *cf_section_find(char const *name)
{
	if (name)
		return cf_section_sub_find(root_config, name);
	else
		return root_config;
}

/** Find a sub-section in a section
 *
 *	This finds ANY section having the same first name.
 *	The second name is ignored.
 */
CONF_SECTION *cf_section_sub_find(CONF_SECTION const *cs, char const *name)
{
	CONF_SECTION mycs;

	if (!cs || !name) return NULL;	/* can't find an un-named section */

	/*
	 *	No sub-sections have been defined, so none exist.
	 */
	if (!cs->section_tree) return NULL;

	mycs.name1 = name;
	mycs.name2 = NULL;
	return rbtree_finddata(cs->section_tree, &mycs);
}


/** Find a CONF_SECTION with both names.
 *
 */
CONF_SECTION *cf_section_sub_find_name2(CONF_SECTION const *cs,
					char const *name1, char const *name2)
{
	CONF_ITEM    *ci;

	if (!cs) cs = root_config;
	if (!cs) return NULL;

	if (name1) {
		CONF_SECTION mycs, *master_cs;

		if (!cs->section_tree) return NULL;

		mycs.name1 = name1;
		mycs.name2 = name2;

		master_cs = rbtree_finddata(cs->section_tree, &mycs);
		if (!master_cs) return NULL;

		/*
		 *	Look it up in the name2 tree.  If it's there,
		 *	return it.
		 */
		if (master_cs->name2_tree) {
			CONF_SECTION *subcs;

			subcs = rbtree_finddata(master_cs->name2_tree, &mycs);
			if (subcs) return subcs;
		}

		/*
		 *	We don't insert ourselves into the name2 tree.
		 *	So if there's nothing in the name2 tree, maybe
		 *	*we* are the answer.
		 */
		if (!master_cs->name2 && name2) return NULL;
		if (master_cs->name2 && !name2) return NULL;
		if (!master_cs->name2 && !name2) return master_cs;

		if (strcmp(master_cs->name2, name2) == 0) {
			return master_cs;
		}

		return NULL;
	}

	/*
	 *	Else do it the old-fashioned way.
	 */
	for (ci = cs->children; ci; ci = ci->next) {
		CONF_SECTION *subcs;

		if (ci->type != CONF_ITEM_SECTION)
			continue;

		subcs = cf_itemtosection(ci);
		if (!subcs->name2) {
			if (strcmp(subcs->name1, name2) == 0) break;
		} else {
			if (strcmp(subcs->name2, name2) == 0) break;
		}
	}

	return cf_itemtosection(ci);
}

/*
 * Return the next subsection after a CONF_SECTION
 * with a certain name1 (char *name1). If the requested
 * name1 is NULL, any name1 matches.
 */

CONF_SECTION *cf_subsection_find_next(CONF_SECTION const *section,
				      CONF_SECTION const *subsection,
				      char const *name1)
{
	CONF_ITEM	*ci;

	if (!section) return NULL;

	/*
	 * If subsection is NULL this must be a first time run
	 * Find the subsection with correct name
	 */

	if (!subsection) {
		ci = section->children;
	} else {
		ci = subsection->item.next;
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

CONF_SECTION *cf_section_find_next(CONF_SECTION const *section,
				   CONF_SECTION const *subsection,
				   char const *name1)
{
	if (!section) return NULL;

	if (!section->item.parent) return NULL;

	return cf_subsection_find_next(section->item.parent, subsection, name1);
}

/*
 * Return the next item after a CONF_ITEM.
 */

CONF_ITEM *cf_item_find_next(CONF_SECTION const *section, CONF_ITEM const *item)
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

CONF_SECTION *cf_item_parent(CONF_ITEM const *ci)
{
	if (!ci) return NULL;

	return ci->parent;
}

int cf_section_lineno(CONF_SECTION const *section)
{
	return section->item.lineno;
}

char const *cf_pair_filename(CONF_PAIR const *pair)
{
	return pair->item.filename;
}

char const *cf_section_filename(CONF_SECTION const *section)
{
	return section->item.filename;
}

int cf_pair_lineno(CONF_PAIR const *pair)
{
	return pair->item.lineno;
}

bool cf_item_is_section(CONF_ITEM const *item)
{
	return item->type == CONF_ITEM_SECTION;
}

bool cf_item_is_pair(CONF_ITEM const *item)
{
	return item->type == CONF_ITEM_PAIR;
}


static CONF_DATA *cf_data_alloc(CONF_SECTION *parent, char const *name,
				void *data, void (*data_free)(void *))
{
	CONF_DATA *cd;

	cd = talloc_zero(parent, CONF_DATA);
	if (!cd) return NULL;

	cd->item.type = CONF_ITEM_DATA;
	cd->item.parent = parent;
	cd->name = talloc_typed_strdup(cd, name);
	if (!cd->name) {
		talloc_free(cd);
		return NULL;
	}

	cd->data = data;
	cd->free = data_free;

	if (cd->free) {
		talloc_set_destructor(cd, _cf_data_free);
	}

	return cd;
}


static void *cf_data_find_internal(CONF_SECTION const *cs, char const *name,
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
void *cf_data_find(CONF_SECTION const *cs, char const *name)
{
	CONF_DATA *cd = cf_data_find_internal(cs, name, 0);

	if (cd) return cd->data;
	return NULL;
}


/*
 *	Add named data to a configuration section.
 */
static int cf_data_add_internal(CONF_SECTION *cs, char const *name,
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
int cf_data_add(CONF_SECTION *cs, char const *name,
		void *data, void (*data_free)(void *))
{
	return cf_data_add_internal(cs, name, data, data_free, 0);
}

/** Remove named data from a configuration section
 *
 */
void *cf_data_remove(CONF_SECTION *cs, char const *name)
{
	CONF_DATA mycd;
	CONF_DATA *cd;
	void *data;

	if (!cs || !name) return NULL;
	if (!cs->data_tree) return NULL;

	/*
	 *	Find the name in the tree, for speed.
	 */
	mycd.name = name;
	mycd.flag = 0;
	cd = rbtree_finddata(cs->data_tree, &mycd);
	if (!cd) return NULL;

	talloc_set_destructor(cd, NULL);	/* Disarm the destructor */
	rbtree_deletebydata(cs->data_tree, &mycd);

	data = cd->data;
	talloc_free(cd);

	return data;
}

/*
 *	This is here to make the rest of the code easier to read.  It
 *	ties conffile.c to log.c, but it means we don't have to
 *	pollute every other function with the knowledge of the
 *	configuration internals.
 */
void cf_log_err(CONF_ITEM const *ci, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (ci) {
		ERROR("%s[%d]: %s",
		       ci->filename ? ci->filename : "unknown",
		       ci->lineno ? ci->lineno : 0,
		       buffer);
	} else {
		ERROR("<unknown>[*]: %s", buffer);
	}
}

void cf_log_err_cs(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cs != NULL);

	ERROR("%s[%d]: %s",
	       cs->item.filename ? cs->item.filename : "unknown",
	       cs->item.lineno ? cs->item.lineno : 0,
	       buffer);
}

void cf_log_err_cp(CONF_PAIR const *cp, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cp != NULL);

	ERROR("%s[%d]: %s",
	       cp->item.filename ? cp->item.filename : "unknown",
	       cp->item.lineno ? cp->item.lineno : 0,
	       buffer);
}

void cf_log_info(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((debug_flag > 1) && cs) vradlog(L_DBG, fmt, ap);
	va_end(ap);
}

/*
 *	Wrapper to simplify the code.
 */
void cf_log_module(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	if (debug_flag > 1 && cs) {
		vsnprintf(buffer, sizeof(buffer), fmt, ap);

		DEBUG("%.*s# %s", cs->depth, parse_spaces, buffer);
	}
	va_end(ap);
}

const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs)
{
	if (!cs) return NULL;

	return cs->variables;
}

/*
 *	For "switch" and "case" statements.
 */
FR_TOKEN cf_section_name2_type(CONF_SECTION const *cs)
{
	if (!cs) return T_OP_INVALID;

	return cs->name2_type;
}
