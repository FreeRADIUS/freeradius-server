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
#include <freeradius-devel/md5.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <ctype.h>

bool check_config = false;

typedef enum conf_property {
	CONF_PROPERTY_INVALID = 0,
	CONF_PROPERTY_NAME,
	CONF_PROPERTY_INSTANCE,
} CONF_PROPERTY;

static const FR_NAME_NUMBER conf_property_name[] = {
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
	CONF_ITEM	item;
	char const	*attr;		//!< Attribute name
	char const	*value;		//!< Attribute value
	FR_TOKEN	op;		//!< Operator e.g. =, :=
	FR_TOKEN	lhs_type;	//!< Name quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
	FR_TOKEN	rhs_type;	//!< Value Quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
	bool		pass2;		//!< do expansion in pass2.
	bool		parsed;		//!< Was this item used during parsing?
};

/** Internal data that is associated with a configuration section
 *
 */
struct conf_data {
	CONF_ITEM  	item;
	char const 	*name;
	int	   	flag;
	void	   	*data;		//!< User data
	void       	(*free)(void *);	//!< Free user data function
};

struct conf_part {
	CONF_ITEM	item;
	char const	*name1;		//!< First name token.  Given ``foo bar {}`` would be ``foo``.
	char const	*name2;		//!< Second name token. Given ``foo bar {}`` would be ``bar``.

	FR_TOKEN	name2_type;	//!< The type of quoting around name2.

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

typedef struct cf_file_t {
	char const	*filename;
	CONF_SECTION	*cs;
	struct stat	buf;
	bool		from_dir;
} cf_file_t;

CONF_SECTION *root_config = NULL;
bool cf_new_escape = true;


static int		cf_data_add_internal(CONF_SECTION *cs, char const *name, void *data,
					     void (*data_free)(void *), int flag);

static void		*cf_data_find_internal(CONF_SECTION const *cs, char const *name, int flag);

static char const 	*cf_expand_variables(char const *cf, int *lineno,
					     CONF_SECTION *outercs,
					     char *output, size_t outsize,
					     char const *input, bool *soft_fail);

static int cf_file_include(CONF_SECTION *cs, char const *filename_in, bool from_dir);



/*
 *	Isolate the scary casts in these tiny provably-safe functions
 */

/** Cast a CONF_ITEM to a CONF_PAIR
 *
 */
CONF_PAIR *cf_item_to_pair(CONF_ITEM const *ci)
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
CONF_SECTION *cf_item_to_section(CONF_ITEM const *ci)
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
CONF_ITEM *cf_pair_to_item(CONF_PAIR const *cp)
{
	CONF_ITEM *out;

	if (cp == NULL) return NULL;

	memcpy(&out, &cp, sizeof(out));
	return out;
}

/** Cast a CONF_SECTION to a CONF_ITEM
 *
 */
CONF_ITEM *cf_section_to_item(CONF_SECTION const *cs)
{
	CONF_ITEM *out;

	if (cs == NULL) return NULL;

	memcpy(&out, &cs, sizeof(out));
	return out;
}

/** Cast CONF_DATA to a CONF_ITEM
 *
 */
static CONF_ITEM *cf_data_to_item(CONF_DATA const *cd)
{
	CONF_ITEM *out;

	if (cd == NULL) {
		return NULL;
	}

	memcpy(&out, &cd, sizeof(out));
	return out;
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

/*
 *	Functions for tracking filenames.
 */
static int filename_cmp(void const *a, void const *b)
{
	cf_file_t const *one = a;
	cf_file_t const *two = b;

	if (one->buf.st_dev < two->buf.st_dev) return -1;
	if (one->buf.st_dev > two->buf.st_dev) return +1;

	if (one->buf.st_ino < two->buf.st_ino) return -1;
	if (one->buf.st_ino > two->buf.st_ino) return +1;

	return 0;
}

static int cf_file_open(CONF_SECTION *cs, char const *filename, bool from_dir, FILE **fp_p)
{
	cf_file_t *file;
	CONF_DATA *cd;
	CONF_SECTION *top;
	rbtree_t *tree;
	int fd;
	FILE *fp;

	top = cf_top_section(cs);
	cd = cf_data_find_internal(top, "filename", 0);
	if (!cd) return -1;

	tree = cd->data;

	/*
	 *	If we're including a wildcard directory, then ignore
	 *	any files the users has already explicitly loaded in
	 *	that directory.
	 */
	if (from_dir) {
		cf_file_t my_file;

		my_file.cs = cs;
		my_file.filename = filename;

		if (stat(filename, &my_file.buf) < 0) goto error;

		file = rbtree_finddata(tree, &my_file);
		if (file && !file->from_dir) return 0;
	}

	DEBUG2("including configuration file %s", filename);

	fp = fopen(filename, "r");
	if (!fp) {
error:
		ERROR("Unable to open file \"%s\": %s",
		      filename, fr_syserror(errno));
		return -1;
	}

	fd = fileno(fp);

	file = talloc(tree, cf_file_t);
	if (!file) {
		fclose(fp);
		return -1;
	}

	file->filename = filename;
	file->cs = cs;
	file->from_dir = from_dir;

	if (fstat(fd, &file->buf) == 0) {
#ifdef S_IWOTH
		if ((file->buf.st_mode & S_IWOTH) != 0) {
			ERROR("Configuration file %s is globally writable.  "
			      "Refusing to start due to insecure configuration.", filename);

			fclose(fp);
			talloc_free(file);
			return -1;
		}
#endif
	}

	/*
	 *	We can include the same file twice.  e.g. when it
	 *	contains common definitions, such as for SQL.
	 *
	 *	Though the admin should really use templates for that.
	 */
	if (!rbtree_insert(tree, file)) {
		talloc_free(file);
	}

	*fp_p = fp;
	return 1;
}

/*
 *	Do some checks on the file
 */
static bool cf_file_check(CONF_SECTION *cs, char const *filename, bool check_perms)
{
	cf_file_t *file;
	CONF_DATA *cd;
	CONF_SECTION *top;
	rbtree_t *tree;

	top = cf_top_section(cs);
	cd = cf_data_find_internal(top, "filename", 0);
	if (!cd) return false;

	tree = cd->data;

	file = talloc(tree, cf_file_t);
	if (!file) return false;

	file->filename = filename;
	file->cs = cs;

	if (stat(filename, &file->buf) < 0) {
		ERROR("Unable to check file \"%s\": %s", filename, fr_syserror(errno));
		talloc_free(file);
		return false;
	}

	if (!check_perms) {
		talloc_free(file);
		return true;
	}

#ifdef S_IWOTH
	if ((file->buf.st_mode & S_IWOTH) != 0) {
		ERROR("Configuration file %s is globally writable.  "
		      "Refusing to start due to insecure configuration.", filename);
		talloc_free(file);
		return false;
	}
#endif

	/*
	 *	It's OK to include the same file twice...
	 */
	if (!rbtree_insert(tree, file)) {
		talloc_free(file);
	}

	return true;

}


typedef struct cf_file_callback_t {
	int		rcode;
	rb_walker_t	callback;
	CONF_SECTION	*modules;
} cf_file_callback_t;


/*
 *	Return 0 for keep going, 1 for stop.
 */
static int file_callback(void *ctx, void *data)
{
	cf_file_callback_t *cb = ctx;
	cf_file_t *file = data;
	struct stat buf;

	/*
	 *	The file doesn't exist or we can no longer read it.
	 */
	if (stat(file->filename, &buf) < 0) {
		cb->rcode = CF_FILE_ERROR;
		return 1;
	}

	/*
	 *	The file changed, we'll need to re-read it.
	 */
	if (file->buf.st_mtime != buf.st_mtime) {
		if (cb->callback(cb->modules, file->cs)) {
			cb->rcode |= CF_FILE_MODULE;
			DEBUG3("HUP: Changed module file %s", file->filename);
		} else {
			DEBUG3("HUP: Changed config file %s", file->filename);
			cb->rcode |= CF_FILE_CONFIG;
		}

		/*
		 *	Presume that the file will be immediately
		 *	re-read, so we update the mtime appropriately.
		 */
		file->buf.st_mtime = buf.st_mtime;
	}

	return 0;
}


/*
 *	See if any of the files have changed.
 */
int cf_file_changed(CONF_SECTION *cs, rb_walker_t callback)
{
	CONF_DATA *cd;
	CONF_SECTION *top;
	cf_file_callback_t cb;
	rbtree_t *tree;

	top = cf_top_section(cs);
	cd = cf_data_find_internal(top, "filename", 0);
	if (!cd) return true;

	tree = cd->data;

	cb.rcode = CF_FILE_NONE;
	cb.callback = callback;
	cb.modules = cf_section_sub_find(cs, "modules");

	(void) rbtree_walk(tree, RBTREE_IN_ORDER, file_callback, &cb);

	return cb.rcode;
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

/** Allocate a CONF_PAIR
 *
 * @param parent CONF_SECTION to hang this CONF_PAIR off of.
 * @param attr name.
 * @param value of CONF_PAIR.
 * @param op T_OP_EQ, T_OP_SET etc.
 * @param lhs_type T_BARE_WORD, T_DOUBLE_QUOTED_STRING, T_BACK_QUOTED_STRING
 * @param rhs_type T_BARE_WORD, T_DOUBLE_QUOTED_STRING, T_BACK_QUOTED_STRING
 * @return NULL on error, else a new CONF_SECTION parented by parent.
 */
CONF_PAIR *cf_pair_alloc(CONF_SECTION *parent, char const *attr, char const *value,
			 FR_TOKEN op, FR_TOKEN lhs_type, FR_TOKEN rhs_type)
{
	CONF_PAIR *cp;

	rad_assert(fr_equality_op[op] || fr_assignment_op[op]);
	if (!attr) return NULL;

	cp = talloc_zero(parent, CONF_PAIR);
	if (!cp) return NULL;

	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;
	cp->lhs_type = lhs_type;
	cp->rhs_type = rhs_type;
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

/** Duplicate a CONF_PAIR
 *
 * @param parent to allocate new pair in.
 * @param cp to duplicate.
 * @return NULL on error, else a duplicate of the input pair.
 */
CONF_PAIR *cf_pair_dup(CONF_SECTION *parent, CONF_PAIR *cp)
{
	CONF_PAIR *new;

	rad_assert(parent);
	rad_assert(cp);

	new = cf_pair_alloc(parent, cp->attr, cf_pair_value(cp),
			    cp->op, cp->lhs_type, cp->rhs_type);
	if (!new) return NULL;

	new->parsed = cp->parsed;
	new->item.lineno = cp->item.lineno;

	/*
	 *	Avoid mallocs if possible.
	 */
	if (!cp->item.filename || (parent->item.filename && !strcmp(parent->item.filename, cp->item.filename))) {
		new->item.filename = parent->item.filename;
	} else {
		new->item.filename = talloc_strdup(new, cp->item.filename);
	}

	return new;
}

/** Add a configuration pair to a section
 *
 * @param parent section to add pair to.
 * @param cp to add.
 */
void cf_pair_add(CONF_SECTION *parent, CONF_PAIR *cp)
{
	cf_item_add(parent, cf_pair_to_item(cp));
}

/** Allocate a CONF_SECTION
 *
 * @param parent CONF_SECTION to hang this CONF_SECTION off of.
 * @param name1 Primary name.
 * @param name2 Secondary name.
 * @return NULL on error, else a new CONF_SECTION parented by parent.
 */
CONF_SECTION *cf_section_alloc(CONF_SECTION *parent, char const *name1, char const *name2)
{
	CONF_SECTION *cs;
	char buffer[1024];

	if (!name1) return NULL;

	if (name2 && parent) {
		if (strchr(name2, '$')) {
			name2 = cf_expand_variables(parent->item.filename,
						    &parent->item.lineno,
						    parent,
						    buffer, sizeof(buffer), name2, NULL);
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

	if (name2) {
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

/** Duplicate a configuration section
 *
 * @note recursively duplicates any child sections.
 * @note does not duplicate any data associated with a section, or its child sections.
 *
 * @param parent section (may be NULL).
 * @param cs to duplicate.
 * @param name1 of new section.
 * @param name2 of new section.
 * @param copy_meta Copy additional meta data for a section (like template, base, depth and variables).
 * @return a duplicate of the existing section, or NULL on error.
 */
CONF_SECTION *cf_section_dup(CONF_SECTION *parent, CONF_SECTION const *cs,
			     char const *name1, char const *name2, bool copy_meta)
{
	CONF_SECTION *new, *subcs;
	CONF_PAIR *cp;
	CONF_ITEM *ci;

	new = cf_section_alloc(parent, name1, name2);

	if (copy_meta) {
		new->template = cs->template;
		new->base = cs->base;
		new->depth = cs->depth;
		new->variables = cs->variables;
	}

	new->item.lineno = cs->item.lineno;

	if (!cs->item.filename || (parent && (strcmp(parent->item.filename, cs->item.filename) == 0))) {
		new->item.filename = parent->item.filename;
	} else {
		new->item.filename = talloc_strdup(new, cs->item.filename);
	}

	for (ci = cs->children; ci; ci = ci->next) {
		switch (ci->type) {
		case CONF_ITEM_SECTION:
			subcs = cf_item_to_section(ci);
			subcs = cf_section_dup(new, subcs,
					       cf_section_name1(subcs), cf_section_name2(subcs),
					       copy_meta);
			if (!subcs) {
				talloc_free(new);
				return NULL;
			}
			cf_section_add(new, subcs);
			break;

		case CONF_ITEM_PAIR:
			cp = cf_pair_dup(new, cf_item_to_pair(ci));
			if (!cp) {
				talloc_free(new);
				return NULL;
			}
			cf_pair_add(new, cp);
			break;

		case CONF_ITEM_DATA: /* Skip data */
			break;

		case CONF_ITEM_INVALID:
			rad_assert(0);
		}
	}

	return new;
}

void cf_section_add(CONF_SECTION *parent, CONF_SECTION *cs)
{
	cf_item_add(parent, &(cs->item));
}

/** Replace pair in a given section with a new pair, of the given value.
 *
 * @param cs to replace pair in.
 * @param cp to replace.
 * @param value New value to assign to cp.
 * @return 0 on success, -1 on failure.
 */
int cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, char const *value)
{
	CONF_PAIR *newp;
	CONF_ITEM *ci, *cn, **last;

	newp = cf_pair_alloc(cs, cp->attr, value, cp->op, cp->lhs_type, cp->rhs_type);
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
void cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci)
{
#ifndef NDEBUG
	CONF_ITEM *first = ci;
#endif

	rad_assert((void *)cs != (void *)ci);

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
		rad_assert(ci->next != first);	/* simple cycle detection */

		cs->tail = ci;

		/*
		 *	For fast lookups, pairs and sections get
		 *	added to rbtree's.
		 */
		switch (ci->type) {
		case CONF_ITEM_PAIR:
			if (!rbtree_insert(cs->pair_tree, ci)) {
				CONF_PAIR *cp = cf_item_to_pair(ci);

				if (strcmp(cp->attr, "confdir") == 0) break;
				if (!cp->value) break; /* module name, "ok", etc. */
			}
			break;

		case CONF_ITEM_SECTION: {
			CONF_SECTION *cs_new = cf_item_to_section(ci);
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

	if (!cs) goto no_such_item;

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
			return cf_section_to_item(cs);
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
				return cf_section_to_item(cs);
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
	if (cp) {
		cp->parsed = true;	/* conf pairs which are referenced count as parsed */
		return &(cp->item);
	}

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
				       char const *input, bool *soft_fail)
{
	char *p;
	char const *end, *ptr;
	CONF_SECTION const *parentcs;
	char name[8192];

	if (soft_fail) *soft_fail = false;

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
				ERROR("%s[%d]: Variable expansion missing }",
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
				if (soft_fail) *soft_fail = true;
				ERROR("%s[%d]: Reference \"${%s}\" not found", cf, *lineno, name);
				return NULL;
			}

			/*
			 *	The expansion doesn't refer to another item or section
			 *	it's the property of a section.
			 */
			if (q) {
				CONF_SECTION *mycs = cf_item_to_section(ci);

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
				cp = cf_item_to_pair(ci);

				/*
				 *	If the thing we reference is
				 *	marked up as being expanded in
				 *	pass2, don't expand it now.
				 *	Let it be expanded in pass2.
				 */
				if (cp->pass2) {
					if (soft_fail) *soft_fail = true;

					ERROR("%s[%d]: Reference \"%s\" points to a variable which has not been expanded.",
					      cf, *lineno, input);
					return NULL;
				}

				/*
				 *	Might as well make
				 *	non-existent string be the
				 *	empty string.
				 */
				if (!cp->value) {
					*p = '\0';
					goto skip_value;
				}

				if (p + strlen(cp->value) >= output + outsize) {
					ERROR("%s[%d]: Reference \"%s\" is too long",
					       cf, *lineno, input);
					return NULL;
				}

				strcpy(p, cp->value);
				p += strlen(p);
			skip_value:
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
				subcs = cf_item_to_section(ci);
				subcs = cf_section_dup(outercs, subcs,
						       cf_section_name1(subcs), cf_section_name2(subcs),
						       false);
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
		} else if (strncmp(ptr, "$ENV{", 5) == 0) {
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
				ERROR("%s[%d]: Environment variable expansion missing }",
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
	case PW_TYPE_COMBO_IP_ADDR:
		switch (ipaddr->af) {
		case AF_INET:
			if (ipaddr->prefix == 32) return 0;

			cf_log_err(&(cs->item), "Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted for non-prefix types",
				   ipaddr->prefix);
			break;

		case AF_INET6:
			if (ipaddr->prefix == 128) return 0;

			cf_log_err(&(cs->item), "Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted for non-prefix types",
				   ipaddr->prefix);
			break;


		default:
			cf_log_err(&(cs->item), "Unknown address (%d) family passed for parsing IP address.", ipaddr->af);
			break;
		}

		return -1;

	default:
		break;
	}

	return 0;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * Takes fields from a #CONF_PARSER struct and uses them to parse the string value
 * of a #CONF_PAIR into a C data type matching the type argument.
 *
 * The format of the types are the same as #value_data_t types.
 *
 * @note The dflt value will only be used if no matching #CONF_PAIR is found. Empty strings will not
 *	 result in the dflt value being used.
 *
 * **PW_TYPE to data type mappings**
 * | PW_TYPE                 | Data type          | Dynamically allocated  |
 * | ----------------------- | ------------------ | ---------------------- |
 * | PW_TYPE_TMPL            | ``vp_tmpl_t``      | Yes                    |
 * | PW_TYPE_BOOLEAN         | ``bool``           | No                     |
 * | PW_TYPE_INTEGER         | ``uint32_t``       | No                     |
 * | PW_TYPE_SHORT           | ``uint16_t``       | No                     |
 * | PW_TYPE_INTEGER64       | ``uint64_t``       | No                     |
 * | PW_TYPE_SIGNED          | ``int32_t``        | No                     |
 * | PW_TYPE_STRING          | ``char const *``   | Yes                    |
 * | PW_TYPE_IPV4_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_IPV4_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_IPV6_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_IPV6_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_COMBO_IP_ADDR   | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_COMBO_IP_PREFIX | ``fr_ipaddr_t``    | No                     |
 * | PW_TYPE_TIMEVAL         | ``struct timeval`` | No                     |
 *
 * @param cs to search for matching #CONF_PAIR in.
 * @param name of #CONF_PAIR to search for.
 * @param type Data type to parse #CONF_PAIR value as.
 *	Should be one of the following ``data`` types, and one or more of the following ``flag`` types or'd together:
 *	- ``data`` #PW_TYPE_TMPL 		- @copybrief PW_TYPE_TMPL
 *					  	  Feeds the value into #tmpl_afrom_str. Value can be
 *					  	  obtained when processing requests, with #tmpl_expand or #tmpl_aexpand.
 *	- ``data`` #PW_TYPE_BOOLEAN		- @copybrief PW_TYPE_BOOLEAN
 *	- ``data`` #PW_TYPE_INTEGER		- @copybrief PW_TYPE_INTEGER
 *	- ``data`` #PW_TYPE_SHORT		- @copybrief PW_TYPE_SHORT
 *	- ``data`` #PW_TYPE_INTEGER64		- @copybrief PW_TYPE_INTEGER64
 *	- ``data`` #PW_TYPE_SIGNED		- @copybrief PW_TYPE_SIGNED
 *	- ``data`` #PW_TYPE_STRING		- @copybrief PW_TYPE_STRING
 *	- ``data`` #PW_TYPE_IPV4_ADDR		- @copybrief PW_TYPE_IPV4_ADDR (IPv4 address with prefix 32).
 *	- ``data`` #PW_TYPE_IPV4_PREFIX		- @copybrief PW_TYPE_IPV4_PREFIX (IPv4 address with variable prefix).
 *	- ``data`` #PW_TYPE_IPV6_ADDR		- @copybrief PW_TYPE_IPV6_ADDR (IPv6 address with prefix 128).
 *	- ``data`` #PW_TYPE_IPV6_PREFIX		- @copybrief PW_TYPE_IPV6_PREFIX (IPv6 address with variable prefix).
 *	- ``data`` #PW_TYPE_COMBO_IP_ADDR 	- @copybrief PW_TYPE_COMBO_IP_ADDR (IPv4/IPv6 address with
 *						  prefix 32/128).
 *	- ``data`` #PW_TYPE_COMBO_IP_PREFIX	- @copybrief PW_TYPE_COMBO_IP_PREFIX (IPv4/IPv6 address with
 *						  variable prefix).
 *	- ``data`` #PW_TYPE_TIMEVAL		- @copybrief PW_TYPE_TIMEVAL
 *	- ``flag`` #PW_TYPE_DEPRECATED		- @copybrief PW_TYPE_DEPRECATED
 *	- ``flag`` #PW_TYPE_REQUIRED		- @copybrief PW_TYPE_REQUIRED
 *	- ``flag`` #PW_TYPE_ATTRIBUTE		- @copybrief PW_TYPE_ATTRIBUTE
 *	- ``flag`` #PW_TYPE_SECRET		- @copybrief PW_TYPE_SECRET
 *	- ``flag`` #PW_TYPE_FILE_INPUT		- @copybrief PW_TYPE_FILE_INPUT
 *	- ``flag`` #PW_TYPE_NOT_EMPTY		- @copybrief PW_TYPE_NOT_EMPTY
 * @param data Pointer to a global variable, or pointer to a field in the struct being populated with values.
 * @param dflt value to use, if no #CONF_PAIR is found.
 * @return
 *	- 1 if default value was used.
 *	- 0 on success.
 *	- -1 on error.
 *	- -2 if deprecated.
 */
int cf_item_parse(CONF_SECTION *cs, char const *name, unsigned int type, void *data, char const *dflt)
{
	int rcode;
	bool deprecated, required, attribute, secret, file_input, cant_be_empty, tmpl, multi, file_exists;
	bool ignore_dflt;
	char **q;
	char const *value;
	CONF_PAIR *cp = NULL;
	fr_ipaddr_t *ipaddr;
	CONF_ITEM *c_item;
	char buffer[8192];

	if (!cs) {
		cf_log_err(&(cs->item), "No enclosing section for configuration item \"%s\"", name);
		return -1;
	}

	c_item = &cs->item;

	deprecated = (type & PW_TYPE_DEPRECATED);
	required = (type & PW_TYPE_REQUIRED);
	attribute = (type & PW_TYPE_ATTRIBUTE);
	secret = (type & PW_TYPE_SECRET);
	file_input = (type == PW_TYPE_FILE_INPUT);	/* check, not and */
	file_exists = (type == PW_TYPE_FILE_EXISTS);	/* check, not and */
	cant_be_empty = (type & PW_TYPE_NOT_EMPTY);
	tmpl = (type & PW_TYPE_TMPL);
	multi = (type & PW_TYPE_MULTI);
	ignore_dflt = (type & PW_TYPE_IGNORE_DEFAULT);

	if (attribute) required = true;
	if (required) cant_be_empty = true;	/* May want to review this in the future... */

	/*
	 *	Everything except templates must have a base type.
	 */
	if (!(type & 0xff) && !tmpl) {
		cf_log_err(c_item, "Configuration item \"%s\" must have a data type", name);
		return -1;
	}

	type &= 0xff;				/* normal types are small */

	rcode = 0;

	cp = cf_pair_find(cs, name);

	/*
	 *	No pairs match the configuration item name in the current
	 *	section, use the default value.
	 */
	if (!cp) {
		if (deprecated || ignore_dflt) return 0;	/* Don't set the default value */

		rcode = 1;
		value = dflt;
	/*
	 *	Something matched, used the CONF_PAIR value.
	 */
	} else {
		CONF_PAIR *next = cp;

		value = cp->value;
		cp->parsed = true;
		c_item = &cp->item;

		if (deprecated) {
			cf_log_err(c_item, "Configuration item \"%s\" is deprecated", name);
			return -2;
		}

		/*
		 *	A quick check to see if the next item is the same.
		 */
		if (!multi && cp->item.next && (cp->item.next->type == CONF_ITEM_PAIR)) {
			next = cf_item_to_pair(cp->item.next);

			if (strcmp(next->attr, name) == 0) {
				WARN("%s[%d]: Ignoring duplicate configuration item '%s'",
				     next->item.filename ? next->item.filename : "unknown",
				     next->item.lineno, name);
			}
		}

		if (multi) {
			while ((next = cf_pair_find_next(cs, next, name)) != NULL) {
				/*
				 *	@fixme We should actually validate
				 *	the value of the pairs too
				 */
				next->parsed = true;
			};
		}
	}

	if (!value) {
		if (required) {
			cf_log_err(c_item, "Configuration item \"%s\" must have a value", name);

			return -1;
		}
		return rcode;
	}

	if ((value[0] == '\0') && cant_be_empty) {
	cant_be_empty:
		cf_log_err(c_item, "Configuration item \"%s\" must not be empty (zero length)", name);
		if (!required) cf_log_err(c_item, "Comment item to silence this message");

		return -1;
	}


	/*
	 *	Process a value as a LITERAL template.  Once all of
	 *	the attrs and xlats are defined, the pass2 code
	 *	converts it to the appropriate type.
	 */
	if (tmpl) {
		vp_tmpl_t *vpt;

		if (!value) {
			*(vp_tmpl_t **)data = NULL;
			return 0;
		}

		rad_assert(!attribute);
		vpt = tmpl_alloc(cs, TMPL_TYPE_LITERAL, value, strlen(value));
		*(vp_tmpl_t **)data = vpt;

		return 0;
	}

	switch (type) {
	case PW_TYPE_BOOLEAN:
		/*
		 *	Allow yes/no, true/false, and on/off
		 */
		if ((strcasecmp(value, "yes") == 0) ||
		    (strcasecmp(value, "true") == 0) ||
		    (strcasecmp(value, "on") == 0)) {
			*(bool *)data = true;
		} else if ((strcasecmp(value, "no") == 0) ||
			   (strcasecmp(value, "false") == 0) ||
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

	case PW_TYPE_BYTE:
	{
		unsigned long v = strtoul(value, 0, 0);

		if (v > UINT8_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", value,
				   name, UINT8_MAX);
			return -1;
		}
		*(uint8_t *)data = (uint8_t) v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, name, *(uint8_t *)data);
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
						    value, NULL);
			if (!value) {
				cf_log_err(&(cs->item),"Failed expanding variable %s", name);
				return -1;
			}

		} else if (cf_new_escape && (cp->rhs_type == T_DOUBLE_QUOTED_STRING) && (strchr(value, '\\') != NULL)) {
			char const *p = value;
			char *s = buffer;
			char *end = buffer + sizeof(buffer);
			unsigned int x;

			/*
			 *	We pass !cf_new_escape() to gettoken() when we parse the RHS of a CONF_PAIR
			 *	above.  But gettoken() unescapes the \", and doesn't unescape anything else.
			 *	So we do it here.
			 */
			while (*p && (s < end)) {
				if (*p != '\\') {
					*(s++) = *(p++);
					continue;
				}

				p++;

				switch (*p) {
				case 'r':
					*s++ = '\r';
					break;
				case 'n':
					*s++ = '\n';
					break;
				case 't':
					*s++ = '\t';
					break;

				default:
					if (*p >= '0' && *p <= '9' &&
					    sscanf(p, "%3o", &x) == 1) {
						if (!x) {
							cf_log_err(&(cs->item), "Cannot have embedded zeros in value for %s", name);
							return -1;
						}

						*s++ = x;
						p += 2;
					} else
						*s++ = *p;
					break;
				}
				p++;
			}

			if (s == end) {
				cf_log_err(&(cs->item), "Failed expanding value for %s", name);
				return -1;
			}

			*s = '\0';

			value = buffer;
		}

		if (cant_be_empty && (value[0] == '\0')) goto cant_be_empty;

		if (attribute) {
			if (!dict_attrbyname(value)) {
				if (!cp) {
					cf_log_err(&(cs->item), "No such attribute '%s' for configuration '%s'",
						   value, name);
				} else {
					cf_log_err(&(cp->item), "No such attribute '%s'", value);
				}
				return -1;
			}
		}

		/*
		 *	Hide secrets when using "radiusd -X".
		 */
		if (secret && (rad_debug_lvl <= 2)) {
			cf_log_info(cs, "%.*s\t%s = <<< secret >>>",
				    cs->depth, parse_spaces, name);
		} else {
			cf_log_info(cs, "%.*s\t%s = \"%s\"",
				    cs->depth, parse_spaces, name, value ? value : "(null)");
		}
		*q = value ? talloc_typed_strdup(cs, value) : NULL;

		/*
		 *	If there's data AND it's an input file, check
		 *	that we can read it.  This check allows errors
		 *	to be caught as early as possible, during
		 *	server startup.
		 */
		if (*q && file_input && !cf_file_check(cs, *q, true)) {
			cf_log_err(&(cs->item), "Failed parsing configuration item \"%s\"", name);
			return -1;
		}

		if (*q && file_exists && !cf_file_check(cs, *q, false)) {
			cf_log_err(&(cs->item), "Failed parsing configuration item \"%s\"", name);
			return -1;
		}
		break;

	case PW_TYPE_IPV4_ADDR:
	case PW_TYPE_IPV4_PREFIX:
		ipaddr = data;

		if (fr_pton4(ipaddr, value, -1, true, false) < 0) {
		failed:
			cf_log_err(&(cs->item), "Failed parsing configuration item \"%s\" - %s", name, fr_strerror());
			return -1;
		}
		if (fr_item_validate_ipaddr(cs, name, type, value, ipaddr) < 0) return -1;
		break;

	case PW_TYPE_IPV6_ADDR:
	case PW_TYPE_IPV6_PREFIX:
		ipaddr = data;

		if (fr_pton6(ipaddr, value, -1, true, false) < 0) goto failed;
		if (fr_item_validate_ipaddr(cs, name, type, value, ipaddr) < 0) return -1;
		break;

	case PW_TYPE_COMBO_IP_ADDR:
	case PW_TYPE_COMBO_IP_PREFIX:
		ipaddr = data;

		if (fr_pton(ipaddr, value, -1, AF_UNSPEC, true) < 0) goto failed;
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
			size_t len;

			len = strlen(end + 1);

			if (len > 6) {
				cf_log_err(&(cs->item), "Too much precision for timeval");
				return -1;
			}

			/*
			 *	If they write "0.1", that means
			 *	"10000" microseconds.
			 */
			sec = strtoul(end + 1, NULL, 10);
			while (len < 6) {
				sec *= 10;
				len++;
			}

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

		cf_log_err(&(cs->item), "type '%s' is not supported in the configuration files",
		       fr_int2str(dict_attr_types, type, "?Unknown?"));
		return -1;
	} /* switch over variable type */

	if (!cp) {
		CONF_PAIR *cpn;

		cpn = cf_pair_alloc(cs, name, value, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
		if (!cpn) return -1;
		cpn->parsed = true;
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
				subcs = cf_section_alloc(cs, variables[i].name, NULL);
				if (!subcs) return;

				subcs->item.filename = cs->item.filename;
				subcs->item.lineno = cs->item.lineno;
				cf_item_add(cs, &(subcs->item));
			}
			if (base) {
				data = ((uint8_t *)base) + variables[i].offset;
			} else {
				data = NULL;
			}

			cf_section_parse_init(subcs, data, (CONF_PARSER const *) variables[i].dflt);
			continue;
		}

		if ((variables[i].type != PW_TYPE_STRING) &&
		    (variables[i].type != PW_TYPE_FILE_INPUT) &&
		    (variables[i].type != PW_TYPE_FILE_OUTPUT)) {
			continue;
		}

		if (variables[i].data) {
			*(char **) variables[i].data = NULL;
		} else if (base) {
			*(char **) (((char *)base) + variables[i].offset) = NULL;
		} else {
			continue;
		}
	} /* for all variables in the configuration section */
}


static void cf_section_parse_warn(CONF_SECTION *cs)
{
	CONF_ITEM *ci;

	for (ci = cs->children; ci; ci = ci->next) {
		/*
		 *	Don't recurse on sections. We can only safely
		 *	check conf pairs at the same level as the
		 *	section that was just parsed.
		 */
		if (ci->type == CONF_ITEM_SECTION) continue;
		if (ci->type == CONF_ITEM_PAIR) {
			CONF_PAIR *cp;

			cp = cf_item_to_pair(ci);
			if (cp->parsed) continue;

			WARN("%s[%d]: The item '%s' is defined, but is unused by the configuration",
			     cp->item.filename ? cp->item.filename : "unknown",
			     cp->item.lineno ? cp->item.lineno : 0,
				cp->attr);
		}

		/*
		 *	Skip everything else.
		 */
	}
}

/** Parse a configuration section into user-supplied variables
 *
 * @param cs to parse.
 * @param base pointer to a struct to fill with data.  Any buffers will also be talloced
 *	using this parent as a pointer.
 * @param variables mappings between struct fields and #CONF_ITEM s.
 * @return
 *	- 0 on success.
 *	- -1 on general error.
 *	- -2 if a deprecated #CONF_ITEM was found.
 */
int cf_section_parse(CONF_SECTION *cs, void *base, CONF_PARSER const *variables)
{
	int ret = 0;
	int i;
	void *data;

	cs->variables = variables; /* this doesn't hurt anything */

	if (!cs->name2) {
		cf_log_info(cs, "%.*s%s {", cs->depth, parse_spaces, cs->name1);
	} else {
		cf_log_info(cs, "%.*s%s %s {", cs->depth, parse_spaces, cs->name1, cs->name2);
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
			 *	Default in this case is overloaded to mean a pointer
			 *	to the CONF_PARSER struct for the subsection.
			 */
			if (!variables[i].dflt || !subcs) {
				ERROR("Internal sanity check 1 failed in cf_section_parse %s", variables[i].name);
				ret = -1;
				goto finish;
			}

			if (base) {
				data = ((uint8_t *)base) + variables[i].offset;
			} else {
				data = NULL;
			}

			ret = cf_section_parse(subcs, data, (CONF_PARSER const *) variables[i].dflt);
			if (ret < 0) goto finish;
			continue;
		} /* else it's a CONF_PAIR */

		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			ERROR("Internal sanity check 2 failed in cf_section_parse");
			ret = -1;
			goto finish;
		}

		/*
		 *	Parse the pair we found, or a default value.
		 */
		ret = cf_item_parse(cs, variables[i].name, variables[i].type, data, variables[i].dflt);
		switch (ret) {
		case 1:		/* Used default */
			ret = 0;
			break;

		case 0:		/* OK */
			break;

		case -1:	/* Parse error */
			goto finish;

		case -2:	/* Deprecated CONF ITEM */
			if ((variables[i + 1].offset == variables[i].offset) &&
			    (variables[i + 1].data == variables[i].data)) {
				cf_log_err(&(cs->item), "Replace \"%s\" with \"%s\"", variables[i].name,
					   variables[i + 1].name);
			} else {
				cf_log_err(&(cs->item), "Cannot use deprecated configuration item \"%s\"", variables[i].name);
			}
			goto finish;
		}
	} /* for all variables in the configuration section */

	/*
	 *	Ensure we have a proper terminator, type so we catch
	 *	missing terminators reliably
	 */
	rad_assert(variables[i].type == -1);

	/*
	 *	Warn about items in the configuration which weren't
	 *	checked during parsing.
	 */
	if (rad_debug_lvl >= 3) cf_section_parse_warn(cs);

	cs->base = base;

	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);

finish:
	return ret;
}


/*
 *	Check XLAT things in pass 2.  But don't cache the xlat stuff anywhere.
 */
int cf_section_parse_pass2(CONF_SECTION *cs, void *base, CONF_PARSER const *variables)
{
	int i;
	ssize_t slen;
	char const *error;
	char *value = NULL;
	xlat_exp_t *xlat;

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		CONF_PAIR *cp;
		void *data;

		/*
		 *	Handle subsections specially
		 */
		if (variables[i].type == PW_TYPE_SUBSECTION) {
			CONF_SECTION *subcs;
			subcs = cf_section_sub_find(cs, variables[i].name);

			if (cf_section_parse_pass2(subcs, (uint8_t *)base + variables[i].offset,
						   (CONF_PARSER const *) variables[i].dflt) < 0) {
				return -1;
			}
			continue;
		} /* else it's a CONF_PAIR */

		/*
		 *	Figure out which data we need to fix.
		 */
		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			data = NULL;
		}

		cp = cf_pair_find(cs, variables[i].name);
		xlat = NULL;

	redo:
		if (!cp || !cp->value || !data) continue;

		if ((cp->rhs_type != T_DOUBLE_QUOTED_STRING) &&
		    (cp->rhs_type != T_BARE_WORD)) continue;

		/*
		 *	Non-xlat expansions shouldn't have xlat!
		 */
		if (((variables[i].type & PW_TYPE_XLAT) == 0) &&
		    ((variables[i].type & PW_TYPE_TMPL) == 0)) {
			/*
			 *	Ignore %{... in shared secrets.
			 *	They're never dynamically expanded.
			 */
			if ((variables[i].type & PW_TYPE_SECRET) != 0) continue;

			if (strstr(cp->value, "%{") != NULL) {
				WARN("%s[%d]: Found dynamic expansion in string which will not be dynamically expanded",
				     cp->item.filename ? cp->item.filename : "unknown",
				     cp->item.lineno ? cp->item.lineno : 0);
			}
			continue;
		}

		/*
		 *	Parse (and throw away) the xlat string.
		 *
		 *	FIXME: All of these should be converted from PW_TYPE_XLAT
		 *	to PW_TYPE_TMPL.
		 */
		if ((variables[i].type & PW_TYPE_XLAT) != 0) {
			/*
			 *	xlat expansions should be parseable.
			 */
			value = talloc_strdup(cs, cp->value); /* modified by xlat_tokenize */
			xlat = NULL;

			slen = xlat_tokenize(cs, value, &xlat, &error);
			if (slen < 0) {
				char *spaces, *text;

			error:
				fr_canonicalize_error(cs, &spaces, &text, slen, cp->value);

				cf_log_err(&cp->item, "Failed parsing expanded string:");
				cf_log_err(&cp->item, "%s", text);
				cf_log_err(&cp->item, "%s^ %s", spaces, error);

				talloc_free(spaces);
				talloc_free(text);
				talloc_free(value);
				talloc_free(xlat);
				return -1;
			}

			talloc_free(value);
			talloc_free(xlat);
		}

		/*
		 *	Convert the LITERAL template to the actual
		 *	type.
		 */
		if ((variables[i].type & PW_TYPE_TMPL) != 0) {
			vp_tmpl_t *vpt;

			slen = tmpl_afrom_str(cs, &vpt, cp->value, talloc_array_length(cp->value) - 1,
					      cp->rhs_type,
					      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
			if (slen < 0) {
				error = fr_strerror();
				goto error;
			}

			/*
			 *	Sanity check
			 *
			 *	Don't add default - update with new types.
			 */
			switch (vpt->type) {
			/*
			 *	All attributes should have been defined by this point.
			 */
			case TMPL_TYPE_ATTR_UNDEFINED:
				cf_log_err(&cp->item, "Unknown attribute '%s'", vpt->tmpl_unknown_name);
				return -1;

			case TMPL_TYPE_LITERAL:
			case TMPL_TYPE_ATTR:
			case TMPL_TYPE_LIST:
			case TMPL_TYPE_DATA:
			case TMPL_TYPE_EXEC:
			case TMPL_TYPE_XLAT:
			case TMPL_TYPE_XLAT_STRUCT:
				break;

			case TMPL_TYPE_UNKNOWN:
			case TMPL_TYPE_REGEX:
			case TMPL_TYPE_REGEX_STRUCT:
			case TMPL_TYPE_NULL:
				rad_assert(0);
			}

			talloc_free(*(vp_tmpl_t **)data);
			*(vp_tmpl_t **)data = vpt;
		}

		/*
		 *	If the "multi" flag is set, check all of them.
		 */
		if ((variables[i].type & PW_TYPE_MULTI) != 0) {
			cp = cf_pair_find_next(cs, cp, cp->attr);
			goto redo;
		}
	} /* for all variables in the configuration section */

	return 0;
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
			cp1 = cf_item_to_pair(ci);
			if (cf_pair_find(cs, cp1->attr)) {
				continue;
			}

			/*
			 *	Create a new pair with all of the data
			 *	of the old one.
			 */
			cp2 = cf_pair_dup(cs, cp1);
			if (!cp2) return false;

			cp2->item.filename = cp1->item.filename;
			cp2->item.lineno = cp1->item.lineno;

			cf_item_add(cs, &(cp2->item));
			continue;
		}

		if (ci->type == CONF_ITEM_SECTION) {
			CONF_SECTION *subcs1, *subcs2;

			subcs1 = cf_item_to_section(ci);
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
			subcs2 = cf_section_dup(cs, subcs1,
						cf_section_name1(subcs1), cf_section_name2(subcs1),
						false);
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

static bool cf_md5_initted = false;
static FR_MD5_CTX conf_context;

void cf_md5_init(void)
{
	fr_md5_init(&conf_context);
	cf_md5_initted = true;
}


static void cf_md5_update(char const *p)
{
	if (!cf_md5_initted) return;

	fr_md5_update(&conf_context, (uint8_t const *)p, strlen(p));
}

void cf_md5_final(uint8_t *digest)
{
	if (!cf_md5_initted) {
		memset(digest, 0, MD5_DIGEST_LENGTH);
		return;
	}

	fr_md5_final(digest, &conf_context);
	cf_md5_initted = false;
}


/*
 *	Read a part of the config file.
 */
static int cf_section_read(char const *filename, int *lineno, FILE *fp,
			   CONF_SECTION *current)

{
	CONF_SECTION *this, *css;
	CONF_PAIR *cpn;
	char const *ptr;
	char const *value;
	char buf[8192];
	char buf1[8192];
	char buf2[8192];
	char buf3[8192];
	char buf4[8192];
	FR_TOKEN t1 = T_INVALID, t2, t3;
	bool has_spaces = false;
	bool pass2;
	char *cbuf = buf;
	size_t len;

	this = current;		/* add items here */

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		int at_eof;
		css = NULL;

		/*
		 *	Get data, and remember if we are at EOF.
		 */
		at_eof = (fgets(cbuf, sizeof(buf) - (cbuf - buf), fp) == NULL);
		cf_md5_update(cbuf);
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

		if (has_spaces) {
			ptr = cbuf;
			while (isspace((uint8_t) *ptr)) ptr++;

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
			while (*ptr && isspace((uint8_t) *ptr)) ptr++;

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
			if (!has_spaces && (len > 2) && (cbuf[len - 2] == '"')) {
				has_spaces = true;
			}

			cbuf[len - 1] = '\0';
			cbuf += len - 1;
			continue;
		}

		ptr = cbuf = buf;
		has_spaces = false;

	get_more:
		pass2 = false;

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
		       goto check_for_more;
	       }

	       if (t1 != T_BARE_WORD) goto skip_keywords;

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

			value = cf_expand_variables(filename, lineno, this, buf4, sizeof(buf4), buf2, NULL);
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
					int slen;

					if (dp->d_name[0] == '.') continue;

					/*
					 *	Check for valid characters
					 */
					for (p = dp->d_name; *p != '\0'; p++) {
						if (isalpha((uint8_t)*p) ||
						    isdigit((uint8_t)*p) ||
						    (*p == '-') ||
						    (*p == '_') ||
						    (*p == '.')) continue;
						break;
					}
					if (*p != '\0') continue;

					/*
					 *	Ignore config files generated by deb / rpm packaging updates.
					 */
					len = strlen(dp->d_name);
					if ((len > 10) && (strncmp(&dp->d_name[len - 10], ".dpkg-dist", 10) == 0)) {
					pkg_file:
						WARN("Ignoring packaging system produced file %s%s", value, dp->d_name);
					 	continue;
					}
					if ((len > 9) && (strncmp(&dp->d_name[len - 9], ".dpkg-old", 9) == 0)) goto pkg_file;
					if ((len > 7) && (strncmp(&dp->d_name[len - 7], ".rpmnew", 9) == 0)) goto pkg_file;
					if ((len > 8) && (strncmp(&dp->d_name[len - 8], ".rpmsave", 10) == 0)) goto pkg_file;

					slen = snprintf(buf2, sizeof(buf2), "%s%s",
							value, dp->d_name);
					if (slen >= (int) sizeof(buf2) || slen < 0) {
						ERROR("%s: Full file path is too long.", dp->d_name);
						closedir(dir);
						return -1;
					}
					if ((stat(buf2, &stat_buf) != 0) ||
					    S_ISDIR(stat_buf.st_mode)) continue;

					/*
					 *	Read the file into the current
					 *	configuration section.
					 */
					if (cf_file_include(this, buf2, true) < 0) {
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

				if (cf_file_include(this, value, false) < 0) {
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

		       this->template = cf_item_to_section(ci);
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
			fr_cond_t *cond = NULL;

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
			 *	Can only have "if" in 3 named sections.
			 */
			server = this->item.parent;
			while (server &&
			       (strcmp(server->name1, "server") != 0) &&
			       (strcmp(server->name1, "policy") != 0) &&
			       (strcmp(server->name1, "instantiate") != 0)) {
				server = server->item.parent;
				if (!server) goto invalid_location;
			}

			/*
			 *	Skip (...) to find the {
			 */
			slen = fr_condition_tokenize(this, cf_section_to_item(this), ptr, &cond,
						     &error, FR_COND_TWO_PASS);
			memcpy(&p, &ptr, sizeof(p));

			if (slen < 0) {
				if (p[-slen] != '{') goto cond_error;
				slen = -slen;
			}
			TALLOC_FREE(cond);

			/*
			 *	This hack is so that the NEXT stage
			 *	doesn't go "too far" in expanding the
			 *	variable.  We can parse the conditions
			 *	without expanding the ${...} stuff.
			 *	BUT we don't want to expand all of the
			 *	stuff AFTER the condition.  So we do
			 *	two passes.
			 *
			 *	The first pass is to discover the end
			 *	of the condition.  We then expand THAT
			 *	string, and do a second pass parsing
			 *	the expanded condition.
			 */
			p += slen;
			*p = '\0';

			/*
			 *	If there's a ${...}.  If so, expand it.
			 */
			if (strchr(ptr, '$') != NULL) {
				ptr = cf_expand_variables(filename, lineno,
							  this,
							  buf3, sizeof(buf3),
							  ptr, NULL);
				if (!ptr) {
					ERROR("%s[%d]: Parse error expanding ${...} in condition",
					      filename, *lineno);
					return -1;
				}
			} /* else leave it alone */

			css = cf_section_alloc(this, buf1, ptr);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section",
				      filename, *lineno);
				return -1;
			}
			css->item.filename = filename;
			css->item.lineno = *lineno;

			slen = fr_condition_tokenize(css, cf_section_to_item(css), ptr, &cond,
						     &error, FR_COND_TWO_PASS);
			*p = '{'; /* put it back */

		cond_error:
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(this, &spaces, &text, slen, ptr);

				ERROR("%s[%d]: Parse error in condition",
				      filename, *lineno);
				ERROR("%s[%d]: %s", filename, *lineno, text);
				ERROR("%s[%d]: %s^ %s", filename, *lineno, spaces, error);

				talloc_free(spaces);
				talloc_free(text);
				talloc_free(css);
				return -1;
			}

			if ((size_t) slen >= (sizeof(buf2) - 1)) {
				talloc_free(css);
				ERROR("%s[%d]: Condition is too large after \"%s\"",
				       filename, *lineno, buf1);
				return -1;
			}

			/*
			 *	Copy the expanded and parsed condition
			 *	into buf2.  Then, parse the text after
			 *	the condition, which now MUST be a '{.
			 *
			 *	If it wasn't '{' it would have been
			 *	caught in the first pass of
			 *	conditional parsing, above.
			 */
			memcpy(buf2, ptr, slen);
			buf2[slen] = '\0';
			ptr = p;

			if ((t3 = gettoken(&ptr, buf3, sizeof(buf3), true)) != T_LCBRACE) {
				talloc_free(css);
				ERROR("%s[%d]: Expected '{' %d",
				      filename, *lineno, t3);
				return -1;
			}

			/*
			 *	Swap the condition with trailing stuff for
			 *	the final condition.
			 */
			memcpy(&p, &css->name2, sizeof(css->name2));
			talloc_free(p);
			css->name2 = talloc_typed_strdup(css, buf2);

			cf_item_add(this, &(css->item));
			cf_data_add_internal(css, "if", cond, NULL, false);

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			css = NULL;
			goto check_for_more;
		}

	skip_keywords:
		/*
		 *	Grab the next token.
		 */
		t2 = gettoken(&ptr, buf2, sizeof(buf2), !cf_new_escape);
		switch (t2) {
		case T_EOL:
		case T_HASH:
		case T_COMMA:
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
		case T_OP_PREPEND:
			while (isspace((uint8_t) *ptr)) ptr++;

			/*
			 *	Be a little more forgiving.
			 */
			if (*ptr == '#') {
				t3 = T_HASH;
			} else

			/*
			 *	New parser: non-quoted strings are
			 *	bare words, and we parse everything
			 *	until the next newline, or the next
			 *	comma.  If they have { or } in a bare
			 *	word, well... too bad.
			 */
			if (cf_new_escape && (*ptr != '"') && (*ptr != '\'')
			    && (*ptr != '`') && (*ptr != '/')) {
				const char *q = ptr;

				t3 = T_BARE_WORD;
				while (*q && (*q >= ' ') && (*q != ',') &&
				       !isspace((uint8_t) *q)) q++;

				if ((size_t) (q - ptr) >= sizeof(buf3)) {
					ERROR("%s[%d]: Parse error: value too long",
					      filename, *lineno);
					return -1;
				}

				memcpy(buf3, ptr, (q - ptr));
				buf3[q - ptr] = '\0';
				ptr = q;

			} else {
				t3 = getstring(&ptr, buf3, sizeof(buf3), !cf_new_escape);
			}

			if (t3 == T_INVALID) {
				ERROR("%s[%d]: Parse error: %s",
				       filename, *lineno,
				       fr_strerror());
				return -1;
			}

			/*
			 *	Allow "foo" by itself, or "foo = bar"
			 */
			switch (t3) {
				bool soft_fail;

			case T_BARE_WORD:
			case T_DOUBLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
				value = cf_expand_variables(filename, lineno, this, buf4, sizeof(buf4), buf3, &soft_fail);
				if (!value) {
					if (!soft_fail) return -1;

					/*
					 *	References an item which doesn't exist,
					 *	or which is already marked up as being
					 *	expanded in pass2.  Wait for pass2 to
					 *	do the expansions.
					 */
					pass2 = true;
					value = buf3;
				}
				break;

			case T_EOL:
			case T_HASH:
				value = NULL;
				break;

			default:
				value = buf3;
				break;
			}

			/*
			 *	Add this CONF_PAIR to our CONF_SECTION
			 */
		do_set:
			cpn = cf_pair_alloc(this, buf1, value, t2, t1, t3);
			if (!cpn) return -1;
			cpn->item.filename = filename;
			cpn->item.lineno = *lineno;
			cpn->pass2 = pass2;
			cf_item_add(this, &(cpn->item));

			/*
			 *	Require a comma, unless there's a comment.
			 */
			while (isspace((uint8_t) *ptr)) ptr++;

			if (*ptr == ',') {
				ptr++;
				break;
			}

			/*
			 *	module # stuff!
			 *	foo = bar # other stuff
			 */
			if ((t3 == T_HASH) || (t3 == T_COMMA) || (t3 == T_EOL) || (*ptr == '#')) continue;

			if (!*ptr || (*ptr == '}')) break;

			ERROR("%s[%d]: Syntax error: Expected comma after '%s': %s",
			      filename, *lineno, value, ptr);
			return -1;

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
			css = cf_section_alloc(this, buf1,
					       t2 == T_LCBRACE ? NULL : buf2);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section",
				      filename, *lineno);
				return -1;
			}

			css->item.filename = filename;
			css->item.lineno = *lineno;
			cf_item_add(this, &(css->item));

			/*
			 *	There may not be a name2
			 */
			css->name2_type = (t2 == T_LCBRACE) ? T_INVALID : t2;

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			break;

		case T_INVALID:
			ERROR("%s[%d]: Syntax error in '%s': %s", filename, *lineno, ptr, fr_strerror());

			return -1;

		default:
			ERROR("%s[%d]: Parse error after \"%s\": unexpected token \"%s\"",
			      filename, *lineno, buf1, fr_int2str(fr_tokens, t2, "<INVALID>"));

			return -1;
		}

	check_for_more:
		/*
		 *	Done parsing one thing.  Skip to EOL if possible.
		 */
		while (isspace((uint8_t) *ptr)) ptr++;

		if (*ptr == '#') continue;

		if (*ptr) {
			goto get_more;
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
static int cf_file_include(CONF_SECTION *cs, char const *filename_in, bool from_dir)
{
	FILE		*fp;
	int		rcode;
	int		lineno = 0;
	char const	*filename;

	/*
	 *	So we only need to do this once.
	 */
	filename = talloc_strdup(cs, filename_in);

	/*
	 *	This may return "0" if we already loaded the file.
	 */
	rcode = cf_file_open(cs, filename, from_dir, &fp);
	if (rcode <= 0) return rcode;

	if (!cs->item.filename) cs->item.filename = filename;

	/*
	 *	Read the section.  It's OK to have EOF without a
	 *	matching close brace.
	 */
	if (cf_section_read(filename, &lineno, fp, cs) < 0) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}


/*
 *	Do variable expansion in pass2.
 *
 *	This is a breadth-first expansion.  "deep
 */
static int cf_section_pass2(CONF_SECTION *cs)
{
	CONF_ITEM *ci;

	for (ci = cs->children; ci; ci = ci->next) {
		char const *value;
		CONF_PAIR *cp;
		char buffer[8192];

		if (ci->type != CONF_ITEM_PAIR) continue;

		cp = cf_item_to_pair(ci);
		if (!cp->value || !cp->pass2) continue;

		rad_assert((cp->rhs_type == T_BARE_WORD) ||
			   (cp->rhs_type == T_DOUBLE_QUOTED_STRING) ||
			   (cp->rhs_type == T_BACK_QUOTED_STRING));

		value = cf_expand_variables(ci->filename, &ci->lineno, cs, buffer, sizeof(buffer), cp->value, NULL);
		if (!value) return -1;

		rad_const_free(cp->value);
		cp->value = talloc_typed_strdup(cp, value);
	}

	for (ci = cs->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION) continue;

		if (cf_section_pass2(cf_item_to_section(ci)) < 0) return -1;
	}

	return 0;
}


/*
 *	Bootstrap a config file.
 */
int cf_file_read(CONF_SECTION *cs, char const *filename)
{
	char *p;
	CONF_PAIR *cp;
	rbtree_t *tree;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	if (!cp) return -1;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cp->item.filename = "<internal>";
	cp->item.lineno = -1;
	cf_item_add(cs, &(cp->item));

	tree = rbtree_create(cs, filename_cmp, NULL, 0);
	if (!tree) return -1;

	cf_data_add_internal(cs, "filename", tree, NULL, 0);

	if (cf_file_include(cs, filename, false) < 0) return -1;

	/*
	 *	Now that we've read the file, go back through it and
	 *	expand the variables.
	 */
	if (cf_section_pass2(cs) < 0) return -1;

	return 0;
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
	return (pair ? pair->op : T_INVALID);
}

/** Return the value (lhs) type
 *
 * @param pair to extract value type from.
 * @return one of T_BARE_WORD, T_SINGLE_QUOTED_STRING, T_BACK_QUOTED_STRING
 *	T_DOUBLE_QUOTED_STRING or T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_attr_type(CONF_PAIR const *pair)
{
	return (pair ? pair->lhs_type : T_INVALID);
}

/** Return the value (rhs) type
 *
 * @param pair to extract value type from.
 * @return one of T_BARE_WORD, T_SINGLE_QUOTED_STRING, T_BACK_QUOTED_STRING
 *	T_DOUBLE_QUOTED_STRING or T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_value_type(CONF_PAIR const *pair)
{
	return (pair ? pair->rhs_type : T_INVALID);
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
	    ((pair->rhs_type == T_DOUBLE_QUOTED_STRING) ||
	     (pair->rhs_type == T_BACK_QUOTED_STRING))) {
		VALUE_PAIR *vp;

		vp = fr_pair_make(pair, NULL, pair->attr, NULL, pair->op);
		if (!vp) {
			return NULL;
		}

		if (fr_pair_mark_xlat(vp, pair->value) < 0) {
			talloc_free(vp);

			return NULL;
		}

		return vp;
	}

	return fr_pair_make(pair, NULL, pair->attr, pair->value, pair->op);
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

		if (strcmp(cf_item_to_section(ci)->name1, name1) != 0) {
			continue;
		}

		their2 = cf_item_to_section(ci)->name2;

		if ((!name2 && !their2) ||
		    (name2 && their2 && (strcmp(name2, their2) == 0))) {
			return cf_item_to_section(ci);
		}
	}

	return NULL;
}

/** Find a pair with a name matching attr, after specified pair.
 *
 * @param cs to search in.
 * @param pair to search from (may be NULL).
 * @param attr to find (may be NULL in which case any attribute matches).
 * @return the next matching CONF_PAIR or NULL if none matched.
 */
CONF_PAIR *cf_pair_find_next(CONF_SECTION const *cs,
			     CONF_PAIR const *pair, char const *attr)
{
	CONF_ITEM	*ci;

	if (!cs) return NULL;

	/*
	 *	If pair is NULL and we're trying to find a specific
	 *	attribute this must be a first time run.
	 *
	 *	Find the pair with correct name.
	 */
	if (!pair && attr) return cf_pair_find(cs, attr);

	/*
	 *	Start searching from the next child, or from the head
	 *	of the list of children (if no pair was provided).
	 */
	for (ci = pair ? pair->item.next : cs->children;
	     ci;
	     ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR) continue;

		if (!attr || strcmp(cf_item_to_pair(ci)->attr, attr) == 0) break;
	}

	return cf_item_to_pair(ci);
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

		subcs = cf_item_to_section(ci);
		if (!subcs->name2) {
			if (strcmp(subcs->name1, name2) == 0) break;
		} else {
			if (strcmp(subcs->name2, name2) == 0) break;
		}
	}

	return cf_item_to_section(ci);
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
		    (strcmp(cf_item_to_section(ci)->name1, name1) == 0))
			break;
	}

	return cf_item_to_section(ci);
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

/** Return the next item after a CONF_ITEM.
 *
 */
CONF_ITEM *cf_item_find_next(CONF_SECTION const *section, CONF_ITEM const *item)
{
	if (!section) return NULL;

	/*
	 *	If item is NULL this must be a first time run
	 * 	Return the first item
	 */
	if (item == NULL) {
		return section->children;
	} else {
		return item->next;
	}
}

static void _pair_count(int *count, CONF_SECTION const *cs)
{
	CONF_ITEM const *ci;

	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {

		if (cf_item_is_section(ci)) {
			_pair_count(count, cf_item_to_section(ci));
			continue;
		}

		(*count)++;
	}
}

/** Count the number of conf pairs beneath a section
 *
 * @param[in] cs to search for items in.
 * @return number of pairs nested within section.
 */
int cf_pair_count(CONF_SECTION const *cs)
{
	int count = 0;

	_pair_count(&count, cs);

	return count;
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

bool cf_item_is_data(CONF_ITEM const *item)
{
	return item->type == CONF_ITEM_DATA;
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

static void *cf_data_find_internal(CONF_SECTION const *cs, char const *name, int flag)
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

	cf_item_add(cs, cf_data_to_item(cd));

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
	CONF_ITEM *ci, *it;
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

	ci = cf_data_to_item(cd);
	if (cs->children == ci) {
		cs->children = ci->next;
		if (cs->tail == ci) cs->tail = NULL;
	} else {
		for (it = cs->children; it; it = it->next) {
			if (it->next == ci) {
				it->next = ci->next;
				if (cs->tail == ci) cs->tail = it;
				break;
			}
		}
	}

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
	if ((rad_debug_lvl > 1) && cs) vradlog(L_DBG, fmt, ap);
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
	if (rad_debug_lvl > 1 && cs) {
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
	if (!cs) return T_INVALID;

	return cs->name2_type;
}
