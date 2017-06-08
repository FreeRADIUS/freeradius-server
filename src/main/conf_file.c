/*
 * conf_file.c	Read the radiusd.conf file.
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
#include <fcntl.h>

bool check_config = false;
static uid_t conf_check_uid = (uid_t)-1;
static gid_t conf_check_gid = (gid_t)-1;
static CONF_PARSER conf_term = CONF_PARSER_TERMINATOR;

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
	CONF_ITEM_DATA,
#ifdef WITH_CONF_WRITE
	CONF_ITEM_COMMENT,
	CONF_ITEM_INCLUDE
#endif
} CONF_ITEM_TYPE;

struct cf_item {
	struct cf_item		*next;		//!< Sibling.
	struct cf_item		*parent;	//!< Parent.
	int			lineno;		//!< The line number the config item began on.
	char const		*filename;	//!< The file the config item was parsed from.
	CONF_ITEM_TYPE		type;		//!< Whether the config item is a config_pair, conf_section or cf_data.
};

/** Configuration AVP similar to a VALUE_PAIR
 *
 */
struct cf_pair {
	CONF_ITEM		item;		//!< Common set of fields.

	char const		*attr;		//!< Attribute name
#ifdef WITH_CONF_WRITE
	char const		*orig_value;	/* original value */
#endif
	char const		*value;		//!< Attribute value
	FR_TOKEN		op;		//!< Operator e.g. =, :=
	FR_TOKEN		lhs_type;	//!< Name quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
	FR_TOKEN		rhs_type;	//!< Value Quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
	bool			pass2;		//!< do expansion in pass2.
	bool			parsed;		//!< Was this item used during parsing?
};

/** A section grouping multiple #CONF_PAIR
 *
 */
struct cf_section {
	CONF_ITEM		item;		//!< Common set of fields.

	char const		*name1;		//!< First name token.  Given ``foo bar {}`` would be ``foo``.
	char const		*name2;		//!< Second name token. Given ``foo bar {}`` would be ``bar``.

	FR_TOKEN		name2_type;	//!< The type of quoting around name2.

	int			argc;		//!< number of additional arguments
	char const		**argv;		//!< additional arguments
	FR_TOKEN		*argv_type;

	CONF_ITEM		*children;
	CONF_ITEM		*tail;		//!< For speed.
	CONF_SECTION		*template;

	rbtree_t		*pair_tree;	//!< and a partridge..
	rbtree_t		*section_tree;	//!< no jokes here.
	rbtree_t		*name2_tree;	//!< for sections of the same name2
	rbtree_t		*data_tree;

	void			*base;
	int			depth;

	CONF_PARSER const	*variables;	//!< the section was parsed with.
};

/** Internal data that is associated with a configuration section
 *
 */
struct cf_data {
	CONF_ITEM  		item;		//!< Common set of fields.

	char const		*type;		//!< C type of data being stored.
	char const 		*name;		//!< Additional qualification of type.
	void const   		*data;		//!< User data.
	bool			free;		//!< Free user data function.
};

typedef enum cf_include_type {
	CONF_INCLUDE_FILE,
	CONF_INCLUDE_DIR,
	CONF_INCLUDE_FROMDIR,
} CONF_INCLUDE_TYPE;

#ifdef WITH_CONF_WRITE
typedef struct conf_comment {
	CONF_ITEM	item;
	char const	*comment;
} CONF_COMMENT;

typedef struct conf_include {
	CONF_ITEM	item;
	char const	*filename;
	CONF_INCLUDE_TYPE file_type;
} CONF_INCLUDE;
#endif

typedef struct cf_file_t {
	char const	*filename;
	CONF_SECTION	*cs;
	struct stat	buf;
} cf_file_t;


static char const 	*cf_expand_variables(char const *cf, int *lineno,
					     CONF_SECTION *outercs,
					     char *output, size_t outsize,
					     char const *input, bool *soft_fail);

static int cf_file_include(CONF_SECTION *cs, char const *filename_in, CONF_INCLUDE_TYPE file_type, char *buff[7]);



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

static int _cd_free(CONF_DATA *cd)
{
	void *to_free;

	memcpy(&to_free, cd->data, sizeof(to_free));

	if (cd->free) talloc_free(to_free);

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
	CONF_DATA const *one = a;
	CONF_DATA const *two = b;
	int		ret;

	if (one->type && !two->type) return +1;
	if (!one->type && two->type) return -1;

	if (one->type && two->type) {
		ret = strcmp(one->type, two->type);
		if (ret != 0) return ret;
	}

	if (one->name && !two->name) return +1;
	if (!one->name && two->name) return -1;

	if (one->name && two->name) return strcmp(one->name, two->name);

	return 0;
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

static FILE *cf_file_open(CONF_SECTION *cs, char const *filename)
{
	cf_file_t *file;
	CONF_SECTION *top;
	rbtree_t *tree;
	int fd;
	FILE *fp;

	top = cf_top_section(cs);
	tree = cf_data_find(top, rbtree_t, "filename");
	if (!tree) return NULL;

	fp = fopen(filename, "r");
	if (!fp) {
		ERROR("Unable to open file \"%s\": %s",
		      filename, fr_syserror(errno));
		return NULL;
	}

	fd = fileno(fp);

	file = talloc(tree, cf_file_t);
	if (!file) {
		fclose(fp);
		return NULL;
	}

	file->filename = filename;
	file->cs = cs;

	if (fstat(fd, &file->buf) == 0) {
#ifdef S_IWOTH
		if ((file->buf.st_mode & S_IWOTH) != 0) {
			ERROR("Configuration file %s is globally writable.  "
			      "Refusing to start due to insecure configuration.", filename);

			fclose(fp);
			talloc_free(file);
			return NULL;
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

	return fp;
}

/** Set the euid/egid used when performing file checks
 *
 * Sets the euid, and egid used when cf_file_check is called to check
 * permissions on conf items of type #FR_TYPE_FILE_INPUT.
 *
 * @note This is probably only useful for the freeradius daemon itself.
 *
 * @param uid to set, (uid_t)-1 to use current euid.
 * @param gid to set, (gid_t)-1 to use current egid.
 */
void cf_file_check_user(uid_t uid, gid_t gid)
{
	if (uid != 0) conf_check_uid = uid;
	if (gid != 0) conf_check_gid = gid;
}

/** Do some checks on the file as an "input" file.  i.e. one read by a module.
 *
 * @note Must be called with super user privileges.
 *
 * @param cs		currently being processed.
 * @param filename	to check.
 * @param check_perms	If true - will return false if file is world readable,
 *			or not readable by the unprivileged user/group.
 * @return
 *	- true if permissions are OK, or the file exists.
 *	- false if the file does not exist or the permissions are incorrect.
 */
static bool cf_file_check(CONF_SECTION *cs, char const *filename, bool check_perms)
{
	cf_file_t	*file;
	CONF_SECTION	*top;
	rbtree_t	*tree;
	int		fd = -1;

	top = cf_top_section(cs);
	tree = cf_data_find(top, rbtree_t, "filename");
	if (!tree) return false;

	file = talloc(tree, cf_file_t);
	if (!file) return false;

	file->filename = filename;
	file->cs = cs;

	if (!check_perms) {
		if (stat(filename, &file->buf) < 0) {
		perm_error:
			rad_file_error(errno);	/* Write error and euid/egid to error buff */
			ERROR("Unable to open file \"%s\": %s", filename, fr_strerror());
		error:
			if (fd >= 0) close(fd);
			talloc_free(file);
			return false;
		}
		talloc_free(file);
		return true;
	}

	/*
	 *	This really does seem to be the simplest way
	 *	to check that the file can be read with the
	 *	euid/egid.
	 */
	{
		uid_t euid = (uid_t)-1;
		gid_t egid = (gid_t)-1;

		if ((conf_check_gid != (gid_t)-1) && ((egid = getegid()) != conf_check_gid)) {
			if (setegid(conf_check_gid) < 0) {
				ERROR("Failed setting effective group ID for file check");
				goto error;
			}
		}
		if ((conf_check_uid != (uid_t)-1) && ((euid = geteuid()) != conf_check_uid)) {
			if (seteuid(conf_check_uid) < 0) {
				ERROR("Failed setting effective user ID for file check");
				goto error;
			}
		}
		fd = open(filename, O_RDONLY);
		if (conf_check_uid != euid) {
			if (seteuid(euid) < 0) {
				ERROR("Failed restoring effective user ID after file check");

				goto error;
			}
		}
		if (conf_check_gid != egid) {
			if (setegid(egid) < 0) {
				ERROR("Failed restoring effective group ID after file check");
				goto error;
			}
		}
	}

	if (fd < 0) goto perm_error;
	if (fstat(fd, &file->buf) < 0) goto perm_error;

	close(fd);

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
	if (!rbtree_insert(tree, file)) talloc_free(file);

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
	if (buf.st_mtime != file->buf.st_mtime) {

		if (cb->callback(cb->modules, file->cs)) {
			cb->rcode |= CF_FILE_MODULE;
			DEBUG3("HUP: Changed module file %s", file->filename);
		} else {
			DEBUG3("HUP: Changed config file %s", file->filename);
			cb->rcode |= CF_FILE_CONFIG;
		}
	}

	return 0;
}


/*
 *	See if any of the files have changed.
 */
int cf_file_changed(CONF_SECTION *cs, rb_walker_t callback)
{
	CONF_SECTION *top;
	cf_file_callback_t cb;
	rbtree_t *tree;

	top = cf_top_section(cs);
	tree = cf_data_find(top, rbtree_t, "filename");
	if (!tree) return true;

	cb.rcode = CF_FILE_NONE;
	cb.callback = callback;
	cb.modules = cf_subsection_find(cs, "modules");

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
		talloc_free(cs->pair_tree);
		cs->pair_tree = NULL;
	}
	if (cs->section_tree) {
		talloc_free(cs->section_tree);
		cs->section_tree = NULL;
	}
	if (cs->name2_tree) {
		talloc_free(cs->name2_tree);
		cs->name2_tree = NULL;
	}
	if (cs->data_tree) {
		talloc_free(cs->data_tree);
		cs->data_tree = NULL;
	}

	return 0;
}

/** Allocate a #CONF_PAIR
 *
 * @param parent #CONF_SECTION to hang this #CONF_PAIR off of.
 * @param attr name.
 * @param value of #CONF_PAIR.
 * @param op #T_OP_EQ, #T_OP_SET etc.
 * @param lhs_type #T_BARE_WORD, #T_DOUBLE_QUOTED_STRING, #T_BACK_QUOTED_STRING
 * @param rhs_type #T_BARE_WORD, #T_DOUBLE_QUOTED_STRING, #T_BACK_QUOTED_STRING
 * @return
 *	- NULL on error.
 *	- A new #CONF_SECTION parented by parent.
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
	cp->item.parent = cf_section_to_item(parent);
	cp->lhs_type = lhs_type;
	cp->rhs_type = rhs_type;
	cp->op = op;
	cp->item.filename = "<internal>"; /* will be over-written if necessary */

	cp->attr = talloc_typed_strdup(cp, attr);
	if (!cp->attr) {
	error:
		talloc_free(cp);
		return NULL;
	}

	if (value) {
#ifdef WITH_CONF_WRITE
		cp->orig_value = talloc_typed_strdup(cp, value);
#endif
		cp->value = talloc_typed_strdup(cp, value);
		if (!cp->value) goto error;
	}

	return cp;
}

/** Duplicate a #CONF_PAIR
 *
 * @param parent to allocate new pair in.
 * @param cp to duplicate.
 * @return
 *	- NULL on error.
 *	- A duplicate of the input pair.
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
	new->item.filename = cp->item.filename;

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

/** Allocate a #CONF_SECTION
 *
 * @param parent #CONF_SECTION to hang this #CONF_SECTION off of.
 * @param name1 Primary name.
 * @param name2 Secondary name.
 * @return
 *	- NULL on error.
 *	- A new #CONF_SECTION parented by parent.
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
	cs->item.parent = cf_section_to_item(parent);
	cs->item.filename = "<internal>"; /* will be over-written if necessary */

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
 * @return
 *	- A duplicate of the existing section.
 *	- NULL on error.
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
	new->item.filename = cs->item.filename;

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
#ifdef WITH_CONF_WRITE
		case CONF_ITEM_COMMENT:
		case CONF_ITEM_INCLUDE:
#endif
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
 * @return
 *	- 0 on success.
 *	- -1 on failure.
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
			     CONF_SECTION const *outercs,
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
				cs = cf_item_to_section(cs->item.parent);
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
			next = cf_subsection_find_name2(cs, p, r + 1);
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
			next = cf_subsection_find(cs, p);
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

	next = cf_subsection_find(cs, p);
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

	while (cs->item.parent != NULL) cs = cf_item_to_section(cs->item.parent);

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
				if (cf_item_to_section(ci->parent) == outercs) {
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

/** Validation function for ipaddr conf_file types
 *
 */
static inline int fr_item_validate_ipaddr(CONF_SECTION *cs, char const *name, fr_type_t type, char const *value,
					  fr_ipaddr_t *ipaddr)
{
	char ipbuf[128];

	if (strcmp(value, "*") == 0) {
		cf_log_info(cs, "%.*s\t%s = *", cs->depth, parse_spaces, name);
	} else if (strspn(value, ".0123456789abdefABCDEF:%[]/") == strlen(value)) {
		cf_log_info(cs, "%.*s\t%s = %s", cs->depth, parse_spaces, name, value);
	} else {
		cf_log_info(cs, "%.*s\t%s = %s IPv%s address [%s]", cs->depth, parse_spaces, name, value,
			    (ipaddr->af == AF_INET ? "4" : " 6"), fr_inet_ntoh(ipaddr, ipbuf, sizeof(ipbuf)));
	}

	switch (type) {
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_COMBO_IP_ADDR:
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


/** Fixup xlat expansions and attributes
 *
 * @note Despite the name, this is really the second phase of #cf_pair_parse.
 *
 * @param[out] base start of structure to write #vp_tmpl_t s to.
 * @param[in] cs CONF_SECTION to fixup.
 * @param[in] variables Array of CONF_PARSER structs to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure (parse errors etc...).
 */
int cf_section_parse_pass2(void *base, CONF_SECTION *cs, CONF_PARSER const variables[])
{

	int i;

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		bool		attribute, multi, is_tmpl, is_xlat;
		CONF_PAIR	*cp;
		void		*data;

		char const	*name = variables[i].name;
		int		type = variables[i].type;

		is_tmpl = (type & FR_TYPE_TMPL);
		is_xlat = (type & FR_TYPE_XLAT);
		attribute = (type & FR_TYPE_ATTRIBUTE);
		multi = (type & FR_TYPE_MULTI);

		type = FR_BASE_TYPE(type);		/* normal types are small */

		/*
		 *	It's a section, recurse!
		 */
		if (type == FR_TYPE_SUBSECTION) {
			uint8_t		*subcs_base;
			CONF_SECTION	*subcs = cf_subsection_find(cs, name);

			/*
			 *	Select base by whether this is a nested struct,
			 *	or a pointer to another struct.
			 */
			if (!base) {
				subcs_base = NULL;
			} else if (multi) {
				size_t		j, len;
				uint8_t		**array;

				array = (uint8_t **)((uint8_t *)base) + variables[i].offset;
				len = talloc_array_length(array);

				for (j = 0; j < len; j++) {
					if (cf_section_parse_pass2(array[j], subcs,
								   (CONF_PARSER const *)variables[i].dflt) < 0) {
						return -1;
					}
				}
				continue;
			} else if (variables[i].subcs_size) {
				subcs_base = (*(uint8_t **)((uint8_t *)base) + variables[i].offset);
			} else {
				subcs_base = (uint8_t *)base + variables[i].offset;
			}

			if (cf_section_parse_pass2(subcs_base, subcs,
						   (CONF_PARSER const *)variables[i].dflt) < 0) return -1;

			continue;
		}

		/*
		 *	Find the CONF_PAIR, may still not exist if there was
		 *	no default set for the CONF_PARSER.
		 */
		cp = cf_pair_find(cs, name);
		if (!cp) continue;

		/*
		 *	Figure out which data we need to fix.
		 */
		data = variables[i].data; /* prefer this. */
		if (!data && base) data = ((char *)base) + variables[i].offset;
		if (!data) continue;

		/*
		 *	Non-xlat expansions shouldn't have xlat!
		 */
		if (!is_xlat && !is_tmpl) {
			/*
			 *	Ignore %{... in shared secrets.
			 *	They're never dynamically expanded.
			 */
			if ((variables[i].type & FR_TYPE_SECRET) != 0) continue;

			if (strstr(cp->value, "%{") != NULL) {
				cf_log_err(&cp->item, "Found dynamic expansion in string which "
					   "will not be dynamically expanded");
				return -1;
			}
			continue;
		}

		/*
		 *	Parse (and throw away) the xlat string (for validation).
		 *
		 *	FIXME: All of these should be converted from FR_TYPE_XLAT
		 *	to FR_TYPE_TMPL.
		 */
		if (is_xlat) {
			char const	*error;
			ssize_t		slen;
			char		*value;
			xlat_exp_t	*xlat;

		redo:
			xlat = NULL;

			/*
			 *	xlat expansions should be parseable.
			 */
			value = talloc_strdup(cs, cp->value); /* modified by xlat_tokenize */
			slen = xlat_tokenize(cs, value, &xlat, &error);
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(cs, &spaces, &text, slen, cp->value);

				cf_log_err_cp(cp, "Failed parsing expanded string:");
				cf_log_err_cp(cp, "%s", text);
				cf_log_err_cp(cp, "%s^ %s", spaces, error);

				talloc_free(spaces);
				talloc_free(text);
				talloc_free(value);
				talloc_free(xlat);
				return -1;
			}

			talloc_free(value);
			talloc_free(xlat);

			/*
			 *	If the "multi" flag is set, check all of them.
			 */
			if (multi) {
				cp = cf_pair_find_next(cs, cp, cp->attr);
				if (cp) goto redo;
			}
			continue;

		/*
		 *	Parse the pair into a template
		 */
		} else if (is_tmpl) {
			ssize_t	slen;

			vp_tmpl_t **out = (vp_tmpl_t **)data;
			vp_tmpl_t *vpt;

			slen = tmpl_afrom_str(cs, &vpt, cp->value, talloc_array_length(cp->value) - 1,
					      cf_pair_value_type(cp),
					      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(vpt, &spaces, &text, slen, cp->value);

				cf_log_err_cp(cp, "%s", text);
				cf_log_err_cp(cp, "%s^ %s", spaces, fr_strerror());

				talloc_free(spaces);
				talloc_free(text);
				return -1;
			}

			if (attribute && (vpt->type != TMPL_TYPE_ATTR)) {
				cf_log_err(&cp->item, "Expected attr got %s",
					   fr_int2str(tmpl_names, vpt->type, "???"));
				return -1;
			}

			switch (vpt->type) {
			/*
			 *	All attributes should have been defined by this point.
			 */
			case TMPL_TYPE_ATTR_UNDEFINED:
				talloc_free(vpt);
				cf_log_err(&cp->item, "Unknown attribute '%s'", vpt->tmpl_unknown_name);
				return -1;

			case TMPL_TYPE_UNPARSED:
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
			/* Don't add default */
			}

			/*
			 *	Free the old value if we're overwriting
			 */
			TALLOC_FREE(*out);
			*(vp_tmpl_t **)out = vpt;
		}
	} /* for all variables in the configuration section */

	return 0;
}

/** Parses a #CONF_PAIR into a C data type
 *
 * @copybrief cf_pair_value
 * @see cf_pair_value
 *
 * @param[out] out Where to write the parsed value.
 * @param[in] ctx to allocate any dynamic buffers in.
 * @param[in] cs containing the cp.
 * @param[in] cp to parse.
 * @param[in] type to parse to.  May contain flags.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cf_pair_parse_value(TALLOC_CTX *ctx, void *out, CONF_SECTION *cs, CONF_PAIR *cp, unsigned int type)
{
	int		rcode = 0;
	bool		attribute, required, secret, file_input, cant_be_empty, tmpl, file_exists;

	fr_ipaddr_t	*ipaddr;
	ssize_t		slen;

	if (!cs) return -1;

	attribute = (type & FR_TYPE_ATTRIBUTE);
	required = (type & FR_TYPE_REQUIRED);
	secret = (type & FR_TYPE_SECRET);
	file_input = (type == FR_TYPE_FILE_INPUT);	/* check, not and */
	file_exists = (type == FR_TYPE_FILE_EXISTS);	/* check, not and */
	cant_be_empty = (type & FR_TYPE_NOT_EMPTY);
	tmpl = (type & FR_TYPE_TMPL);

	rad_assert(cp);
	rad_assert(!(type & FR_TYPE_ATTRIBUTE) || tmpl);	 /* Attribute flag only valid for templates */

	if (required) cant_be_empty = true;		/* May want to review this in the future... */

	type = FR_BASE_TYPE(type);					/* normal types are small */

	/*
	 *	Everything except templates must have a base type.
	 */
	if (!type && !tmpl) {
		cf_log_err_cp(cp, "Configuration pair \"%s\" must have a data type", cf_pair_attr(cp));
		return -1;
	}

	rad_assert(cp->value);

	/*
	 *	Check for zero length strings
	 */
	if ((cp->value[0] == '\0') && cant_be_empty) {
		cf_log_err_cp(cp, "Configuration pair \"%s\" must not be empty (zero length)", cf_pair_attr(cp));
		if (!required) cf_log_err_cp(cp, "Comment item to silence this message");
		rcode = -1;

	error:
		return rcode;
	}

	if (tmpl) {
		vp_tmpl_t *vpt;

		/*
		 *	This is so we produce TMPL_TYPE_ATTR_UNDEFINED template that
		 *	the bootstrap functions can use to create an attribute.
		 *
		 *	For other types of template such as xlats, we don't bother.
		 *	There's no reason bootstrap functions need access to the raw
		 *	xlat strings.
		 */
		if (attribute) {
			slen = tmpl_afrom_attr_str(cp, &vpt, cp->value, REQUEST_CURRENT, PAIR_LIST_REQUEST,
						   true, true);
			if (slen < 0) {
				char *spaces, *text;

				fr_canonicalize_error(ctx, &spaces, &text, slen, cp->value);

				cf_log_err(&cp->item, "Failed parsing attribute reference:");
				cf_log_err(&cp->item, "%s", text);
				cf_log_err(&cp->item, "%s^ %s", spaces, fr_strerror());

				talloc_free(spaces);
				talloc_free(text);
				goto error;
			}
			*(vp_tmpl_t **)out = vpt;
		}
		goto finish;
	}

	switch (type) {
	case FR_TYPE_BOOL:
		/*
		 *	Allow yes/no, true/false, and on/off
		 */
		if ((strcasecmp(cp->value, "yes") == 0) ||
		    (strcasecmp(cp->value, "true") == 0) ||
		    (strcasecmp(cp->value, "on") == 0)) {
			*(bool *)out = true;
		} else if ((strcasecmp(cp->value, "no") == 0) ||
			   (strcasecmp(cp->value, "false") == 0) ||
			   (strcasecmp(cp->value, "off") == 0)) {
			*(bool *)out = false;
		} else {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for boolean variable %s",
				   cp->value, cf_pair_attr(cp));
			rcode = -1;
			goto error;
		}
		cf_log_info(cs, "%.*s\t%s = %s", cs->depth, parse_spaces, cf_pair_attr(cp), cp->value);
		break;

	case FR_TYPE_UINT32:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		/*
		 *	Restrict integer values to 0-INT32_MAX, this means
		 *	it will always be safe to cast them to a signed type
		 *	for comparisons, and imposes the same range limit as
		 *	before we switched to using an unsigned type to
		 *	represent config item integers.
		 */
		if (v > INT32_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), INT32_MAX);
			rcode = -1;
			goto error;
		}

		*(uint32_t *)out = v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, cf_pair_attr(cp), *(uint32_t *)out);
	}
		break;

	case FR_TYPE_UINT8:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		if (v > UINT8_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), UINT8_MAX);
			rcode = -1;
			goto error;
		}
		*(uint8_t *)out = (uint8_t) v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, cf_pair_attr(cp), *(uint8_t *)out);
	}
		break;

	case FR_TYPE_UINT16:
	{
		unsigned long v = strtoul(cp->value, 0, 0);

		if (v > UINT16_MAX) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s, must be between 0-%u", cp->value,
				   cf_pair_attr(cp), UINT16_MAX);
			rcode = -1;
			goto error;
		}
		*(uint16_t *)out = (uint16_t) v;
		cf_log_info(cs, "%.*s\t%s = %u", cs->depth, parse_spaces, cf_pair_attr(cp), *(uint16_t *)out);
	}
		break;

	case FR_TYPE_UINT64:
		*(uint64_t *)out = strtoull(cp->value, NULL, 10);
		cf_log_info(cs, "%.*s\t%s = %" PRIu64, cs->depth, parse_spaces, cf_pair_attr(cp), *(uint64_t *)out);
		break;

	case FR_TYPE_SIZE:
	{
		if (fr_size_from_str((size_t *)out, cp->value) < 0) {
			cf_log_err(&(cs->item), "Invalid value \"%s\" for variable %s: %s", cp->value,
				   cf_pair_attr(cp), fr_strerror());
			rcode = -1;
			goto error;
		}
		cf_log_info(cs, "%.*s\t%s = %zu", cs->depth, parse_spaces, cf_pair_attr(cp), *(size_t *)out);
		break;
	}

	case FR_TYPE_INT32:
		*(int32_t *)out = strtol(cp->value, NULL, 10);
		cf_log_info(cs, "%.*s\t%s = %d", cs->depth, parse_spaces, cf_pair_attr(cp), *(int32_t *)out);
		break;

	case FR_TYPE_STRING:
	{
		char **str = out;

		/*
		 *	Hide secrets when using "radiusd -X".
		 */
		if (secret && (rad_debug_lvl < L_DBG_LVL_3)) {
			cf_log_info(cs, "%.*s\t%s = <<< secret >>>", cs->depth, parse_spaces, cf_pair_attr(cp));
		} else {
			cf_log_info(cs, "%.*s\t%s = \"%s\"", cs->depth, parse_spaces, cf_pair_attr(cp), cp->value);
		}

		/*
		 *	If there's out AND it's an input file, check
		 *	that we can read it.  This check allows errors
		 *	to be caught as early as possible, during
		 *	server startup.
		 */
		if (file_input && !cf_file_check(cs, cp->value, true)) {
			rcode = -1;
			goto error;
		}

		if (file_exists && !cf_file_check(cs, cp->value, false)) {
			rcode = -1;
			goto error;
		}

		/*
		 *	Free any existing buffers
		 */
		talloc_free(*str);
		*str = talloc_typed_strdup(cs, cp->value);
	}
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
		ipaddr = out;

		if (fr_inet_pton4(ipaddr, cp->value, -1, true, false, true) < 0) {
			cf_log_err(&(cp->item), "%s", fr_strerror());
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		ipaddr = out;

		if (fr_inet_pton6(ipaddr, cp->value, -1, true, false, true) < 0) {
			cf_log_err(&(cp->item), "%s", fr_strerror());
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
		ipaddr = out;

		if (fr_inet_pton(ipaddr, cp->value, -1, AF_UNSPEC, true, true) < 0) {
			cf_log_err(&(cp->item), "%s", fr_strerror());
			rcode = -1;
			goto error;
		}
		/* Also prints the IP to the log */
		if (fr_item_validate_ipaddr(cs, cf_pair_attr(cp), type, cp->value, ipaddr) < 0) {
			rcode = -1;
			goto error;
		}
		break;

	case FR_TYPE_TIMEVAL:
	{
		struct timeval tv;

		if (fr_timeval_from_str(&tv, cp->value) < 0) {
			cf_log_err(&(cp->item), "%s", fr_strerror());
			rcode = -1;
			goto error;
		}
		cf_log_info(cs, "%.*s\t%s = %d.%06d", cs->depth, parse_spaces, cf_pair_attr(cp),
			    (int)tv.tv_sec, (int)tv.tv_usec);
		memcpy(out, &tv, sizeof(tv));
	}
		break;

	default:
		/*
		 *	If we get here, it's a sanity check error.
		 *	It's not an error parsing the configuration
		 *	file.
		 */
		rad_assert(type > FR_TYPE_INVALID);
		rad_assert(type < FR_TYPE_MAX);

		cf_log_err(&(cp->item), "type '%s' (%i) is not supported in the configuration files",
			   fr_int2str(dict_attr_types, type, "?Unknown?"), type);
		rcode = -1;
		goto error;
	}

finish:
	cp->parsed = true;

	return rcode;
}

/** Allocate a pair using the dflt value and quotation
 *
 * The pair created by this function should fed to #cf_pair_parse for parsing.
 *
 * @param[out] out Where to write the CONF_PAIR we created with the default value.
 * @param[in] cs to parent the CONF_PAIR from.
 * @param[in] name of the CONF_PAIR to create.
 * @param[in] type of conf item being parsed (determines default quoting).
 * @param[in] dflt value to assign the CONF_PAIR.
 * @param[in] dflt_quote surrounding the CONF_PAIR.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cf_pair_default(CONF_PAIR **out, CONF_SECTION *cs, char const *name,
			   int type, char const *dflt, FR_TOKEN dflt_quote)
{
	int		lineno = 0;
	char const	*expanded;
	CONF_PAIR	*cp;
	char		buffer[8192];

	rad_assert(dflt);

	type = FR_BASE_TYPE(type);

	/*
	 *	Defaults may need their values expanding
	 */
	expanded = cf_expand_variables("<internal>", &lineno, cs, buffer, sizeof(buffer), dflt, NULL);
	if (!expanded) {
		cf_log_err(&(cs->item), "Failed expanding variable %s", name);
		return -1;
	}

	/*
	 *	If no default quote was set, determine it from the type
	 */
	if (dflt_quote == T_INVALID) {
		switch (type) {
		case FR_TYPE_STRING:
			dflt_quote = T_DOUBLE_QUOTED_STRING;
			break;

		case FR_TYPE_FILE_INPUT:
		case FR_TYPE_FILE_OUTPUT:
			dflt_quote = T_DOUBLE_QUOTED_STRING;
			break;

		default:
			dflt_quote = T_BARE_WORD;
			break;
		}
	}

	cp = cf_pair_alloc(cs, name, expanded, T_OP_EQ, T_BARE_WORD, dflt_quote);
	if (!cp) return -1;

	cp->parsed = true;

	/*
	 *	Set the rcode to indicate we used a default value
	 */
	*out = cp;

	return 1;
}

/** Parses a #CONF_PAIR into a C data type, with a default value.
 *
 * Takes fields from a #CONF_PARSER struct and uses them to parse the string value
 * of a #CONF_PAIR into a C data type matching the type argument.
 *
 * The format of the types are the same as #fr_value_box_t types.
 *
 * @note The dflt value will only be used if no matching #CONF_PAIR is found. Empty strings will not
 *	 result in the dflt value being used.
 *
 * **fr_type_t to data type mappings**
 * | fr_type_t               | Data type          | Dynamically allocated  |
 * | ----------------------- | ------------------ | ---------------------- |
 * | FR_TYPE_TMPL            | ``vp_tmpl_t``      | Yes                    |
 * | FR_TYPE_BOOL            | ``bool``           | No                     |
 * | FR_TYPE_UINT32          | ``uint32_t``       | No                     |
 * | FR_TYPE_UINT16          | ``uint16_t``       | No                     |
 * | FR_TYPE_UINT64          | ``uint64_t``       | No                     |
 * | FR_TYPE_INT32           | ``int32_t``        | No                     |
 * | FR_TYPE_STRING          | ``char const *``   | Yes                    |
 * | FR_TYPE_IPV4_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV4_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV6_ADDR       | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_IPV6_PREFIX     | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_COMBO_IP_ADDR   | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_COMBO_IP_PREFIX | ``fr_ipaddr_t``    | No                     |
 * | FR_TYPE_TIMEVAL         | ``struct timeval`` | No                     |
 *
 * @param[in] ctx	To allocate arrays and values in.
 * @param[in] cs	to search for matching #CONF_PAIR in.
 * @param[in] name	of #CONF_PAIR to search for.
 * @param[in] type	Data type to parse #CONF_PAIR value as.
 *			Should be one of the following ``data`` types,
 *			and one or more of the following ``flag`` types or'd together:
 *	- ``data`` #FR_TYPE_TMPL 		- @copybrief FR_TYPE_TMPL
 *					  	  Feeds the value into #tmpl_afrom_str. Value can be
 *					  	  obtained when processing requests, with #tmpl_expand or #tmpl_aexpand.
 *	- ``data`` #FR_TYPE_BOOL		- @copybrief FR_TYPE_BOOL
 *	- ``data`` #FR_TYPE_UINT32		- @copybrief FR_TYPE_UINT32
 *	- ``data`` #FR_TYPE_UINT16		- @copybrief FR_TYPE_UINT16
 *	- ``data`` #FR_TYPE_UINT64		- @copybrief FR_TYPE_UINT64
 *	- ``data`` #FR_TYPE_INT32		- @copybrief FR_TYPE_INT32
 *	- ``data`` #FR_TYPE_STRING		- @copybrief FR_TYPE_STRING
 *	- ``data`` #FR_TYPE_IPV4_ADDR		- @copybrief FR_TYPE_IPV4_ADDR (IPv4 address with prefix 32).
 *	- ``data`` #FR_TYPE_IPV4_PREFIX		- @copybrief FR_TYPE_IPV4_PREFIX (IPv4 address with variable prefix).
 *	- ``data`` #FR_TYPE_IPV6_ADDR		- @copybrief FR_TYPE_IPV6_ADDR (IPv6 address with prefix 128).
 *	- ``data`` #FR_TYPE_IPV6_PREFIX		- @copybrief FR_TYPE_IPV6_PREFIX (IPv6 address with variable prefix).
 *	- ``data`` #FR_TYPE_COMBO_IP_ADDR 	- @copybrief FR_TYPE_COMBO_IP_ADDR (IPv4/IPv6 address with
 *						  prefix 32/128).
 *	- ``data`` #FR_TYPE_COMBO_IP_PREFIX	- @copybrief FR_TYPE_COMBO_IP_PREFIX (IPv4/IPv6 address with
 *						  variable prefix).
 *	- ``data`` #FR_TYPE_TIMEVAL		- @copybrief FR_TYPE_TIMEVAL
 *	- ``flag`` #FR_TYPE_DEPRECATED		- @copybrief FR_TYPE_DEPRECATED
 *	- ``flag`` #FR_TYPE_REQUIRED		- @copybrief FR_TYPE_REQUIRED
 *	- ``flag`` #FR_TYPE_ATTRIBUTE		- @copybrief FR_TYPE_ATTRIBUTE
 *	- ``flag`` #FR_TYPE_SECRET		- @copybrief FR_TYPE_SECRET
 *	- ``flag`` #FR_TYPE_FILE_INPUT		- @copybrief FR_TYPE_FILE_INPUT
 *	- ``flag`` #FR_TYPE_NOT_EMPTY		- @copybrief FR_TYPE_NOT_EMPTY
 *	- ``flag`` #FR_TYPE_MULTI		- @copybrief FR_TYPE_MULTI
 *	- ``flag`` #FR_TYPE_IS_SET		- @copybrief FR_TYPE_IS_SET
 * @param[out] out	Pointer to a global variable, or pointer to a field in the struct being populated with values.
 * @param[in] dflt		value to use, if no #CONF_PAIR is found.
 * @param[in] dflt_quote	around the dflt value.
 * @return
 *	- 1 if default value was used, or if there was no CONF_PAIR or dflt.
 *	- 0 on success.
 *	- -1 on error.
 *	- -2 if deprecated.
 */
int cf_pair_parse(TALLOC_CTX *ctx, CONF_SECTION *cs,
		  char const *name, unsigned int type, void *out,
		  char const *dflt, FR_TOKEN dflt_quote)
{
	bool		multi, required, deprecated;
	size_t		count = 0;
	CONF_PAIR	*cp, *dflt_cp = NULL;

	rad_assert(!(type & FR_TYPE_TMPL) || !dflt || (dflt_quote != T_INVALID)); /* We ALWAYS need a quoting type for templates */

	multi = (type & FR_TYPE_MULTI);
	required = (type & FR_TYPE_REQUIRED);
	deprecated = (type & FR_TYPE_DEPRECATED);

	/*
	 *	If the item is multi-valued we allocate an array
	 *	to hold the multiple values.
	 */
	if (multi) {
		CONF_PAIR	*first;
		void		**array;
		size_t		i;

		/*
		 *	Easier than re-allocing
		 */
		for (cp = first = cf_pair_find(cs, name);
		     cp;
		     cp = cf_pair_find_next(cs, cp, name)) count++;

		/*
		 *	Multivalued, but there's no value, create a
		 *	default pair.
		 */
		if (!count) {
			if (deprecated) return 0;
			if (!dflt) {
				if (required) {
			need_value:
					cf_log_err_cs(cs, "Configuration item \"%s\" must have a value", name);
					return -1;
				}
				return 1;
			}

			if (cf_pair_default(&dflt_cp, cs, name, type, dflt, dflt_quote) < 0) return -1;
			cp = dflt_cp;
			count = 1;	/* Need one to hold the default */
		} else {
			cp = first;	/* reset */
		}

		if (deprecated) {
		deprecated:
			cf_log_err_cp(cp, "Configuration pair \"%s\" is deprecated", cf_pair_attr(cp));
			return -2;
		}

		/*
		 *	Tmpl is outside normal range
		 */
		if (type & FR_TYPE_TMPL) {
			array = (void **)talloc_zero_array(ctx, vp_tmpl_t *, count);
		/*
		 *	Allocate an array of values.
		 *
		 *	We don't NULL terminate.  Consumer must use
		 *	talloc_array_length().
		 */
		} else switch (FR_BASE_TYPE(type)) {
		case FR_TYPE_BOOL:
			array = (void **)talloc_zero_array(ctx, bool, count);
			break;

		case FR_TYPE_UINT32:
			array = (void **)talloc_zero_array(ctx, uint32_t, count);
			break;

		case FR_TYPE_UINT16:
			array = (void **)talloc_zero_array(ctx, uint16_t, count);
			break;

		case FR_TYPE_UINT64:
			array = (void **)talloc_zero_array(ctx, uint64_t, count);
			break;

		case FR_TYPE_INT32:
			array = (void **)talloc_zero_array(ctx, int32_t, count);
			break;

		case FR_TYPE_STRING:
			array = (void **)talloc_zero_array(ctx, char *, count);
			break;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_IPV6_PREFIX:
		case FR_TYPE_COMBO_IP_ADDR:
		case FR_TYPE_COMBO_IP_PREFIX:
			array = (void **)talloc_zero_array(ctx, fr_ipaddr_t, count);
			break;

		case FR_TYPE_TIMEVAL:
			array = (void **)talloc_zero_array(ctx, struct timeval, count);
			break;

		default:
			rad_assert(0);	/* Unsupported type */
			return -1;
		}

		for (i = 0; i < count; i++, cp = cf_pair_find_next(cs, cp, name)) {
			if (cf_pair_parse_value(array, &array[i], cs, cp, type) < 0) {
				talloc_free(array);
				talloc_free(dflt_cp);
				return -1;
			}
		}

		*(void **)out = array;
	/*
	 *	Single valued config item gets written to
	 *	the data pointer directly.
	 */
	} else {
		CONF_PAIR *next;

		cp = cf_pair_find(cs, name);
		if (!cp) {
			if (deprecated) return 0;
			if (!dflt) {
				if (required) goto need_value;
				return 1;
			}

			if (cf_pair_default(&dflt_cp, cs, name, type, dflt, dflt_quote) < 0) return -1;
			cp = dflt_cp;
		}

		next = cf_pair_find_next(cs, cp, name);
		if (next) {
			cf_log_err(&(next->item), "Invalid duplicate configuration item '%s'", name);
			return -1;
		}

		if (deprecated) goto deprecated;

		if (cf_pair_parse_value(ctx, out, cs, cp, type) < 0) {
			talloc_free(dflt_cp);
			return -1;
		}
	}

	/*
	 *	If we created a default cp and succeeded
	 *	in parsing the dflt value, add the new
	 *	cp to the enclosing section.
	 */
	if (dflt_cp) {
		cf_item_add(cs, &(dflt_cp->item));
		return 1;
	}

	return 0;
}

/** Pre-allocate a config section structure to allow defaults to be set
 *
 * @param cs		The parent subsection.
 * @param base		pointer or variable.
 * @param variables	that may have defaults in this config section.
 */
static int cf_section_parse_init(CONF_SECTION *cs, void *base, CONF_PARSER const *variables)
{
	int i;

	for (i = 0; variables[i].name != NULL; i++) {
		if ((FR_BASE_TYPE(variables[i].type) == FR_TYPE_SUBSECTION)) {
			CONF_SECTION *subcs;

			if (!variables[i].dflt) continue;

			subcs = cf_subsection_find(cs, variables[i].name);
			if (!subcs && (variables[i].type & FR_TYPE_REQUIRED)) {
				cf_log_err_cs(cs, "Missing %s {} subsection", variables[i].name);
				return -1;
			}

			/*
			 *	Set the is_set field for the subsection.
			 */
			if (variables[i].type & FR_TYPE_IS_SET) {
				bool *is_set;

				is_set = variables[i].data ? variables[i].is_set_ptr :
							     ((uint8_t *)base) + variables[i].is_set_offset;
				if (is_set) *is_set = !!subcs;
			}

			/*
			 *	If there's no subsection in the
			 *	config, BUT the CONF_PARSER wants one,
			 *	then create an empty one.  This is so
			 *	that we can track the strings,
			 *	etc. allocated in the subsection.
			 */
			if (!subcs) {
				subcs = cf_section_alloc(cs, variables[i].name, NULL);
				if (!subcs) return -1;

				cf_item_add(cs, &(subcs->item));
			}

			continue;
		}

		if ((FR_BASE_TYPE(variables[i].type) != FR_TYPE_STRING) &&
		    (variables[i].type != FR_TYPE_FILE_INPUT) &&
		    (variables[i].type != FR_TYPE_FILE_OUTPUT)) {
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

	return 0;
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
			if (cp->parsed || (ci->lineno < 0)) continue;

			WARN("%s[%d]: The item '%s' is defined, but is unused by the configuration",
			     ci->filename, ci->lineno,
			     cp->attr);
		}

		/*
		 *	Skip everything else.
		 */
	}
}

/** Parse a subsection
 *
 * @note Turns out using nested structures (instead of pointers) for subsections, was actually
 *	a pretty bad design decision, and will need to be fixed at some future point.
 *	For now we have a horrible hack where only multi-subsections get an array of structures
 *	of the appropriate size.
 *
 * @param[in] ctx		to allocate any additional structures under.
 * @param[out] out		pointer to a struct/pointer to fill with data.
 * @param[in] cs		to parse.
 * @param[in] name		of subsection to parse.
 * @param[in] type		flags.
 * @param[in] subcs_vars	CONF_PARSER definitions for the subsection.
 * @param[in] subcs_size	size of subsection structures to allocate.
 * @return
 *	- 0 on success.
 *	- -1 on general error.
 *	- -2 if a deprecated #CONF_ITEM was found.
 */
static int cf_subsection_parse(TALLOC_CTX *ctx, void *out, CONF_SECTION *cs,
			       char const *name, fr_type_t type, CONF_PARSER const *subcs_vars, size_t subcs_size)
{
	CONF_SECTION *subcs;
	int count, i, ret;
	uint8_t **array;

	rad_assert(type & FR_TYPE_SUBSECTION);

	subcs = cf_subsection_find(cs, name);
	rad_assert(subcs);	/* should have been pre-allocated earlier */

	/*
	 *	Handle the single subsection case (which is simple)
	 */
	if (!(type & FR_TYPE_MULTI)) {
		uint8_t *buff;

		/*
		 *	FIXME: We shouldn't allow nested structures like this.
		 *	Each subsection struct should be allocated separately so
		 *	we have a clean talloc hierarchy.
		 */
	 	if (!subcs_size) return cf_section_parse(ctx, out, subcs, subcs_vars);

		MEM(buff = talloc_array(ctx, uint8_t, subcs_size));
		ret = cf_section_parse(buff, buff, subcs, subcs_vars);
		if (ret < 0) {
			talloc_free(buff);
			return -1;
		}

		*((uint8_t **)out) = buff;
	}

	rad_assert(subcs_size);

	/*
	 *	Handle the multi subsection case (which is harder)
	 */
	for (subcs = cf_subsection_find(cs, name), count = 0;
	     subcs;
	     subcs = cf_subsection_find_next(cs, subcs, name), count++);

	/*
	 *	Allocate an array to hold the subsections
	 */
	MEM(array = talloc_array(ctx, uint8_t *, count));

	/*
	 *	Start parsing...
	 *
	 *	Note, we allocate each subsection structure individually
	 *	so that they can be used as talloc contexts and we can
	 *	keep the talloc hierarchy clean.
	 */
	for (subcs = cf_subsection_find(cs, name), i = 0;
	     subcs;
	     subcs = cf_subsection_find_next(cs, subcs, name), i++) {
		uint8_t *buff;

		MEM(buff = talloc_zero_array(array, uint8_t, subcs_size));
		array[i] = buff;

		ret = cf_section_parse(buff, buff, subcs, subcs_vars);
		if (ret < 0) {
			talloc_free(array);
			return ret;
		}
	}

	*((uint8_t ***)out) = array;

	return 0;
}

/** Parse a configuration section into user-supplied variables
 *
 * @param[in] ctx		to allocate any strings, or additional structures in.
 *				Usually the same as base, unless base is a nested struct.
 * @param[out] base		pointer to a struct to fill with data.
 * @param[in] cs		to parse.
 * @param[in] variables 	mappings between struct fields and #CONF_ITEM s.
 * @return
 *	- 0 on success.
 *	- -1 on general error.
 *	- -2 if a deprecated #CONF_ITEM was found.
 */
int cf_section_parse(TALLOC_CTX *ctx, void *base, CONF_SECTION *cs, CONF_PARSER const *variables)
{
	int	ret = 0;
	int	i;
	void	*data;
	bool	*is_set = NULL;

	/*
	 *	Hack for partially parsed sections.
	 */
	if (!variables) {
		cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);
		return 0;
	}

	cs->variables = variables; /* this doesn't hurt anything */

	if (!cs->name2) {
		cf_log_info(cs, "%.*s%s {", cs->depth, parse_spaces, cs->name1);
	} else {
		cf_log_info(cs, "%.*s%s %s {", cs->depth, parse_spaces, cs->name1, cs->name2);
	}

	if (cf_section_parse_init(cs, base, variables) < 0) return -1;

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	Handle subsections specially
		 */
		if (FR_BASE_TYPE(variables[i].type) == FR_TYPE_SUBSECTION) {
			if (cf_subsection_parse(ctx, (uint8_t *)base + variables[i].offset, cs,
						variables[i].name, variables[i].type,
						variables[i].subcs, variables[i].subcs_size) < 0) goto finish;
			continue;
		} /* else it's a CONF_PAIR */

		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((uint8_t *)base) + variables[i].offset;
		} else if (!rad_cond_assert(0)) {
			ret = -1;
			goto finish;
		}

		/*
		 *	Get pointer to where we need to write out
		 *	whether the pointer was set.
		 */
		if (variables[i].type & FR_TYPE_IS_SET) {
			is_set = variables[i].data ? variables[i].is_set_ptr :
						     ((uint8_t *)base) + variables[i].is_set_offset;
		}

		/*
		 *	Parse the pair we found, or a default value.
		 */
		ret = cf_pair_parse(ctx, cs, variables[i].name, variables[i].type, data,
				    variables[i].dflt, variables[i].quote);
		switch (ret) {
		case 1:		/* Used default (or not present) */
			if (is_set) *is_set = false;
			ret = 0;
			break;

		case 0:		/* OK */
			if (is_set) *is_set = true;
			break;

		case -1:	/* Parse error */
			goto finish;

		case -2:	/* Deprecated CONF ITEM */
			if ((variables[i + 1].offset && (variables[i + 1].offset == variables[i].offset)) ||
			    (variables[i + 1].data && (variables[i + 1].data == variables[i].data))) {
				cf_log_err(&(cs->item), "Replace \"%s\" with \"%s\"", variables[i].name,
					   variables[i + 1].name);
			}
			goto finish;
		}
	} /* for all variables in the configuration section */

	/*
	 *	Ensure we have a proper terminator, type so we catch
	 *	missing terminators reliably
	 */
	rad_cond_assert(variables[i].type == conf_term.type);

	cs->base = base;

	/*
	 *	Hack for partially parsed sections.  We don't print
	 *	out the final "}", that will be printed out when the
	 *	caller re-calls us with 'variable=NULL'.  And, we don't warn about unused
	 */
	if (variables[i].offset == 1) return ret;

	/*
	 *	Warn about items in the configuration which weren't
	 *	checked during parsing.
	 */
	if (rad_debug_lvl >= 3) cf_section_parse_warn(cs);

	cf_log_info(cs, "%.*s}", cs->depth, parse_spaces);

finish:
	return ret;
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

			subcs2 = cf_subsection_find_name2(cs, subcs1->name1, subcs1->name2);
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

static bool invalid_location(CONF_SECTION *this, char const *name, char const *filename, int lineno)
{
	/*
	 *	if / elsif MUST be inside of a
	 *	processing section, which MUST in turn
	 *	be inside of a "server" directive.
	 */
	if (!this || !this->item.parent) {
	invalid_location:
		ERROR("%s[%d]: Invalid location for '%s'",
		      filename, lineno, name);
		return true;
	}

	/*
	 *	Can only have "if" in 3 named sections.
	 */
	this = cf_item_to_section(this->item.parent);
	while ((strcmp(this->name1, "server") != 0) &&
	       (strcmp(this->name1, "policy") != 0) &&
	       (strcmp(this->name1, "instantiate") != 0)) {
		this = cf_item_to_section(this->item.parent);
		if (!this) goto invalid_location;
	}

	return false;
}

#ifdef WITH_CONF_WRITE
static void cf_comment_add(CONF_SECTION *cs, int lineno, char const *ptr)
{
	CONF_COMMENT *cc;

	cc = talloc_zero(cs, CONF_COMMENT);
	cc->item.type = CONF_ITEM_COMMENT;
	cc->item.parent = cs;
	cc->item.filename = cs->item.filename;
	cc->item.lineno = lineno;
	cc->comment = talloc_typed_strdup(cc, ptr);


	cf_item_add(cs, &(cc->item));
}

static void cf_include_add(CONF_SECTION *cs, char const *filename, CONF_INCLUDE_TYPE file_type)
{
	CONF_INCLUDE *cc;

	cc = talloc_zero(cs, CONF_INCLUDE);
	cc->item.type = CONF_ITEM_INCLUDE;
	cc->item.parent = cs;
	cc->item.filename = cs->item.filename;
	cc->item.lineno = 0;
	cc->filename = talloc_typed_strdup(cc, filename);
	cc->file_type = file_type;

	cf_item_add(cs, &(cc->item));
}
#endif


/*
 *	Read a part of the config file.
 */
static int cf_section_read(char const *filename, int *lineno, FILE *fp,
			   CONF_SECTION *current, char *buff[7])

{
	CONF_SECTION	*this, *css;
	CONF_PAIR	*cpn;
	char const	*ptr;
	char const	*value;
#ifdef WITH_CONF_WRITE
	char const	*orig_value = NULL;
#endif

	FR_TOKEN	t1 = T_INVALID, t2, t3;
	bool		has_spaces = false;
	bool		pass2;
	char		*cbuff;
	size_t		len;

	this = current;		/* add items here */

	cbuff = buff[0];

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		int at_eof;
		css = NULL;

		/*
		 *	Get data, and remember if we are at EOF.
		 */
		at_eof = (fgets(cbuff, talloc_array_length(buff[0]) - (cbuff - buff[0]), fp) == NULL);
		(*lineno)++;

		/*
		 *	We read the entire 8k worth of data: complain.
		 *	Note that we don't care if the last character
		 *	is \n: it's still forbidden.  This means that
		 *	the maximum allowed length of text is 8k-1, which
		 *	should be plenty.
		 */
		len = strlen(cbuff);
		if ((cbuff + len + 1) >= (buff[0] + talloc_array_length(buff[0]))) {
			ERROR("%s[%d]: Line too long", filename, *lineno);
		error:
			return -1;
		}

		if (has_spaces) {
			ptr = cbuff;
			while (isspace((int) *ptr)) ptr++;

			if (ptr > cbuff) {
				memmove(cbuff, ptr, len - (ptr - cbuff));
				len -= (ptr - cbuff);
			}
		}

		/*
		 *	Not doing continuations: check for edge
		 *	conditions.
		 */
		if (cbuff == buff[0]) {
			if (at_eof) break;

			ptr = buff[0];
			while (*ptr && isspace((int) *ptr)) ptr++;

#ifdef WITH_CONF_WRITE
			/*
			 *	This is where all of the comments are handled
			 */
			if (*ptr == '#') {
				cf_comment_add(this, *lineno, ptr + 1);
			}
#endif

			if (!*ptr || (*ptr == '#')) continue;

		} else if (at_eof || (len == 0)) {
			ERROR("%s[%d]: Continuation at EOF is illegal", filename, *lineno);
			goto error;
		}

		/*
		 *	See if there's a continuation.
		 */
		while ((len > 0) &&
		       ((cbuff[len - 1] == '\n') || (cbuff[len - 1] == '\r'))) {
			len--;
			cbuff[len] = '\0';
		}

		if ((len > 0) && (cbuff[len - 1] == '\\')) {
			/*
			 *	Check for "suppress spaces" magic.
			 */
			if (!has_spaces && (len > 2) && (cbuff[len - 2] == '"')) {
				has_spaces = true;
			}

			cbuff[len - 1] = '\0';
			cbuff += len - 1;
			continue;
		}

		ptr = cbuff = buff[0];
		has_spaces = false;

	get_more:
		pass2 = false;

		/*
		 *	The parser is getting to be evil.
		 */
		while ((*ptr == ' ') || (*ptr == '\t')) ptr++;

		if (((ptr[0] == '%') && (ptr[1] == '{')) ||
		    (ptr[0] == '`')) {
			ssize_t slen;

			if (ptr[0] == '%') {
				slen = rad_copy_variable(buff[1], ptr);
			} else {
				slen = rad_copy_string(buff[1], ptr);
			}
			if (slen <= 0) {
				char *spaces, *text;

				fr_canonicalize_error(current, &spaces, &text, slen, ptr);

				ERROR("%s[%d]: %s", filename, *lineno, text);
				ERROR("%s[%d]: %s^ Invalid expansion", filename, *lineno, spaces);

				talloc_free(spaces);
				talloc_free(text);

				goto error;
			}

			ptr += slen;

			t2 = gettoken(&ptr, buff[2], talloc_array_length(buff[2]), true);
			switch (t2) {
			case T_HASH:
			case T_EOL:
				goto do_bare_word;

			default:
				ERROR("%s[%d]: Invalid expansion: %s",  filename, *lineno, ptr);
				goto error;
			}
		} else {
			t1 = gettoken(&ptr, buff[1], talloc_array_length(buff[1]), true);
		}

		/*
		 *	The caller eats "name1 name2 {", and calls us
		 *	for the data inside of the section.  So if we
		 *	receive a closing brace, then it must mean the
		 *	end of the section.
		 */
	       if (t1 == T_RCBRACE) {
		       if (this == current) {
			       ERROR("%s[%d]: Too many closing braces", filename, *lineno);
			       goto error;
		       }

		       /*
			*	Merge the template into the existing
			*	section.  This uses more memory, but
			*	means that templates now work with
			*	sub-sections, etc.
			*/
		       if (!cf_template_merge(this, this->template)) goto error;

		       this = cf_item_to_section(this->item.parent);
		       goto check_for_more;
	       }

	       if (t1 != T_BARE_WORD) goto skip_keywords;

		/*
		 *	Allow for $INCLUDE files
		 *
		 *      This *SHOULD* work for any level include.
		 *      I really really really hate this file.  -cparker
		 */
	       if ((strcasecmp(buff[1], "$INCLUDE") == 0) ||
		   (strcasecmp(buff[1], "$-INCLUDE") == 0)) {
			bool relative = true;

			t2 = getword(&ptr, buff[2], talloc_array_length(buff[2]), true);
			if (t2 != T_EOL) {
			       ERROR("%s[%d]: Unexpected text after $INCLUDE", filename, *lineno);
			       goto error;
			}

			if (buff[2][0] == '$') relative = false;

			value = cf_expand_variables(filename, lineno, this, buff[4], talloc_array_length(buff[4]),
						    buff[2], NULL);
			if (!value) goto error;

			if (!FR_DIR_IS_RELATIVE(value)) relative = false;

			if (relative) {
				value = cf_local_file(filename, value, buff[3], talloc_array_length(buff[3]));
				if (!value) {
					ERROR("%s[%d]: Directories too deep", filename, *lineno);
					goto error;
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
				char *my_directory;

				my_directory = talloc_strdup(this, value);

				DEBUG2("including files in directory %s", my_directory);

#ifdef WITH_CONF_WRITE
				/*
				 *	We print this out, but don't
				 *	actually open a file based on
				 *	it.
				 */
				cf_include_add(this, my_directory, CONF_INCLUDE_DIR);
#endif

#ifdef S_IWOTH
				/*
				 *	Security checks.
				 */
				if (stat(my_directory, &stat_buf) < 0) {
					ERROR("%s[%d]: Failed reading directory %s: %s",
					       filename, *lineno,
					       my_directory, fr_syserror(errno));
					talloc_free(my_directory);
					goto error;
				}

				if ((stat_buf.st_mode & S_IWOTH) != 0) {
					ERROR("%s[%d]: Directory %s is globally writable.  Refusing to start due to "
					      "insecure configuration", filename, *lineno, my_directory);
					talloc_free(my_directory);
					goto error;
				}
#endif
				dir = opendir(my_directory);
				if (!dir) {
					ERROR("%s[%d]: Error reading directory %s: %s",
					      filename, *lineno, value,
					      fr_syserror(errno));
					talloc_free(my_directory);
					goto error;
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


					snprintf(buff[2], talloc_array_length(buff[2]), "%s%s",
						 my_directory, dp->d_name);
					if ((stat(buff[2], &stat_buf) != 0) ||
					    S_ISDIR(stat_buf.st_mode)) continue;

					/*
					 *	Read the file into the current
					 *	configuration section.
					 */
					if (cf_file_include(this, buff[2], CONF_INCLUDE_FROMDIR, buff) < 0) {
						closedir(dir);
						goto error;
					}
				}
				closedir(dir);
				talloc_free(my_directory);

			}  else
#endif
			{ /* it was a normal file */
				if (buff[1][1] == '-') {
					struct stat statbuf;

					if (stat(value, &statbuf) < 0) {
						WARN("Not including file %s: %s", value, fr_syserror(errno));
						continue;
					}
				}

				if (cf_file_include(this, value, CONF_INCLUDE_FILE, buff) < 0) goto error;
			}
			continue;
		} /* we were in an include */

	       if (strcasecmp(buff[1], "$template") == 0) {
		       CONF_ITEM *ci;
		       CONF_SECTION *parentcs, *templatecs;
		       t2 = getword(&ptr, buff[2], talloc_array_length(buff[2]), true);

		       if (t2 != T_EOL) {
				ERROR("%s[%d]: Unexpected text after $TEMPLATE", filename, *lineno);
				goto error;
		       }

		       parentcs = cf_top_section(current);

		       templatecs = cf_subsection_find(parentcs, "templates");
		       if (!templatecs) {
				ERROR("%s[%d]: No \"templates\" section for reference \"%s\"", filename, *lineno, buff[2]);
				goto error;
		       }

		       ci = cf_reference_item(parentcs, templatecs, buff[2]);
		       if (!ci || (ci->type != CONF_ITEM_SECTION)) {
				ERROR("%s[%d]: Reference \"%s\" not found", filename, *lineno, buff[2]);
				goto error;
		       }

		       if (!this) {
				ERROR("%s[%d]: Internal sanity check error in template reference", filename, *lineno);
				goto error;
		       }

		       if (this->template) {
				ERROR("%s[%d]: Section already has a template", filename, *lineno);
				goto error;
		       }

		       this->template = cf_item_to_section(ci);
		       continue;
	       }

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buff[1][0] == '_') {
			ERROR("%s[%d]: Illegal configuration pair name \"%s\"", filename, *lineno, buff[1]);
			goto error;
		}

		/*
		 *	Handle if/elsif specially.
		 */
		if ((strcmp(buff[1], "if") == 0) || (strcmp(buff[1], "elsif") == 0)) {
			ssize_t slen;
			char const *error = NULL;
			char *p;
			fr_cond_t *cond = NULL;

			if (invalid_location(this, buff[1], filename, *lineno)) goto error;

			/*
			 *	Skip (...) to find the {
			 */
			slen = fr_cond_tokenize(this, cf_section_to_item(this), ptr, &cond,
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
			 *	Nuke trailing spaces.  This hack
			 *	really belongs in the parser.
			 */
			while ((p > ptr) && (isspace((int) p[-1]))) {
				p--;
				*p = '\0';
			}

			/*
			 *	If there's a ${...}.  If so, expand it.
			 */
			if (strchr(ptr, '$') != NULL) {
				ptr = cf_expand_variables(filename, lineno,
							  this,
							  buff[3], talloc_array_length(buff[3]),
							  ptr, NULL);
				if (!ptr) {
					ERROR("%s[%d]: Parse error expanding ${...} in condition",
					      filename, *lineno);
					goto error;
				}
			} /* else leave it alone */

			css = cf_section_alloc(this, buff[1], ptr);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section", filename, *lineno);
				goto error;
			}
			css->item.filename = filename;
			css->item.lineno = *lineno;

			slen = fr_cond_tokenize(css, cf_section_to_item(css), ptr, &cond,
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
				goto error;
			}

			if ((size_t) slen >= (talloc_array_length(buff[2]) - 1)) {
				talloc_free(css);
				ERROR("%s[%d]: Condition is too large after \"%s\"", filename, *lineno, buff[1]);
				goto error;
			}

			/*
			 *	Copy the expanded and parsed condition
			 *	into buff[2].  Then, parse the text after
			 *	the condition, which now MUST be a '{.
			 *
			 *	If it wasn't '{' it would have been
			 *	caught in the first pass of
			 *	conditional parsing, above.
			 */
			memcpy(buff[2], ptr, slen);
			buff[2][slen] = '\0';
			ptr = p;

			if ((t3 = gettoken(&ptr, buff[3], talloc_array_length(buff[3]), true)) != T_LCBRACE) {
				talloc_free(css);
				ERROR("%s[%d]: Expected '{' %d", filename, *lineno, t3);
				goto error;
			}

			/*
			 *	Swap the condition with trailing stuff for
			 *	the final condition.
			 */
			memcpy(&p, &css->name2, sizeof(css->name2));
			talloc_free(p);
			css->name2 = talloc_typed_strdup(css, buff[2]);

			cf_data_add(css, cond, NULL, false);

		add_section:
			cf_item_add(this, &(css->item));

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			css = NULL;
			goto check_for_more;
		}

		/*
		 *	"map" sections have three arguments!
		 */
		if (strcmp(buff[1], "map") == 0) {
			char const *mod;
			char const *exp = NULL;
			char const *p;

			t2 = gettoken(&ptr, buff[2], talloc_array_length(buff[2]), false);

			if (invalid_location(this, buff[1], filename, *lineno)) {
				if (t2 != T_LCBRACE) {
					ERROR("%s[%d]: Invalid syntax for 'map'", filename, *lineno);
					goto error;
				}

				goto alloc_section;
			}

			if (t2 != T_BARE_WORD) {
				ERROR("%s[%d]: Expected module name after 'map'", filename, *lineno);
				goto error;
			}

			mod = cf_expand_variables(filename, lineno,
						  this,
						  buff[3], talloc_array_length(buff[3]),
						  buff[2], NULL);
			if (!mod) {
				ERROR("%s[%d]: Parse error expanding ${...} in map module name",
				      filename, *lineno);
				goto error;
			}

			p = ptr;
			t3 = gettoken(&p, buff[4], talloc_array_length(buff[4]), false);
			if (fr_str_tok[t3]) {
				ptr = p;

				exp = cf_expand_variables(filename, lineno,
							  this,
							  buff[5], talloc_array_length(buff[5]),
							  buff[4], NULL);
				if (!exp) {
					ERROR("%s[%d]: Parse error expanding ${...} in map module name",
					      filename, *lineno);
					goto error;
				}
			}

			if (gettoken(&ptr, buff[6], talloc_array_length(buff[6]), false) != T_LCBRACE) {
				ERROR("%s[%d]: Expecting section start brace '{' in 'map' definition",
				      filename, *lineno);
				goto error;
			}

			/*
			 *	Allocate the section
			 */
			css = cf_section_alloc(this, buff[1], mod);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section", filename, *lineno);
				goto error;
			}
			css->item.filename = filename;
			css->item.lineno = *lineno;
			css->name2_type = T_BARE_WORD;

			css->argc = 0;
			if (exp) {
				css->argv = talloc_array(css, char const *, 1);
				css->argv[0] = talloc_typed_strdup(css->argv, exp);
				css->argv_type = talloc_array(css, FR_TOKEN, 1);
				css->argv_type[0] = t3;
				css->argc++;
			}

			goto add_section;
		}

	skip_keywords:
		/*
		 *	Grab the next token.
		 */
		t2 = gettoken(&ptr, buff[2], talloc_array_length(buff[2]), false);
		switch (t2) {
		case T_HASH:
		case T_EOL:
		case T_COMMA:
		do_bare_word:
			t3 = t2;
			t2 = T_OP_EQ;
			value = NULL;
			goto do_set;

		case T_OP_INCRM:
		case T_OP_ADD:
		case T_OP_SUB:
		case T_OP_NE:
		case T_OP_GE:
		case T_OP_GT:
		case T_OP_LE:
		case T_OP_LT:
		case T_OP_CMP_EQ:
		case T_OP_CMP_FALSE:
			if (!this || ((strcmp(this->name1, "update") != 0) && (strcmp(this->name1, "map") != 0))) {
				ERROR("%s[%d]: Invalid operator in assignment",
				       filename, *lineno);
				goto error;
			}
			/* FALL-THROUGH */

		case T_OP_EQ:
		case T_OP_SET:
			while (isspace((int) *ptr)) ptr++;

			/*
			 *	New parser: non-quoted strings are
			 *	bare words, and we parse everything
			 *	until the next newline, or the next
			 *	comma.  If they have { or } in a bare
			 *	word, well... too bad.
			 */
			switch (*ptr) {
			case '"':
			case '\'':
			case '`':
			case '/':
				t3 = getstring(&ptr, buff[3], talloc_array_length(buff[3]), false);
				break;

			default:
			{
				const char *q = ptr;

				t3 = T_BARE_WORD;
				while (*q && (*q >= ' ') && (*q != ',') &&
				       !isspace(*q)) q++;

				if ((size_t) (q - ptr) >= talloc_array_length(buff[3])) {
					ERROR("%s[%d]: Parse error: value too long", filename, *lineno);
					goto error;
				}

				memcpy(buff[3], ptr, (q - ptr));
				buff[3][q - ptr] = '\0';
				ptr = q;
			}
			}

			if (t3 == T_INVALID) {
				ERROR("%s[%d]: Parse error: %s", filename, *lineno, fr_strerror());
				goto error;
			}

			/*
			 *	Allow "foo" by itself, or "foo = bar"
			 */
			switch (t3) {
				bool soft_fail;

			case T_BARE_WORD:
			case T_DOUBLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
#ifdef WITH_CONF_WRITE
				orig_value = buff[3];
#endif
				value = cf_expand_variables(filename, lineno, this, buff[4], talloc_array_length(buff[4]), buff[3], &soft_fail);
				if (!value) {
					if (!soft_fail) goto error;

					/*
					 *	References an item which doesn't exist,
					 *	or which is already marked up as being
					 *	expanded in pass2.  Wait for pass2 to
					 *	do the expansions.
					 */
					pass2 = true;
					value = buff[3];
				}
				break;

			case T_HASH:
			case T_EOL:
				value = NULL;
				break;

			default:
				value = buff[3];
				break;
			}

			/*
			 *	Add this CONF_PAIR to our CONF_SECTION
			 */
		do_set:
			cpn = cf_pair_alloc(this, buff[1], value, t2, t1, t3);
			if (!cpn) goto error;
			cpn->item.filename = filename;
			cpn->item.lineno = *lineno;
			cpn->pass2 = pass2;
			cf_item_add(this, &(cpn->item));

#ifdef WITH_CONF_WRITE
			if (orig_value) cpn->orig_value = talloc_typed_strdup(cpn, orig_value);
			orig_value = NULL;
#endif
			/*
			 *	Require a comma, unless there's a comment.
			 */
			while (isspace(*ptr)) ptr++;

			if (*ptr == ',') {
				ptr++;
				break;
			}

			/*
			 *	module # stuff!
			 *	foo = bar # other stuff
			 */
#ifdef WITH_CONF_WRITE
			if (*ptr == '#') {
				t3 = T_HASH;
				ptr++;
			}

			/*
			 *	Allocate a CONF_COMMENT, and add it to the list of children.
			 */
			if ((t3 == T_HASH) && (*ptr >= ' ')) {
				cf_comment_add(this, *lineno, ptr);
			}
#endif

			if ((t3 == T_HASH) || (t3 == T_COMMA) || (t3 == T_EOL) || (*ptr == '#')) continue;

			if (!*ptr || (*ptr == '}')) break;

			ERROR("%s[%d]: Syntax error: Expected comma after '%s': %s",
			      filename, *lineno, value, ptr);
			goto error;

			/*
			 *	No '=', must be a section or sub-section.
			 */
		case T_BARE_WORD:
		case T_DOUBLE_QUOTED_STRING:
		case T_SINGLE_QUOTED_STRING:
			t3 = gettoken(&ptr, buff[3], talloc_array_length(buff[3]), true);
			if (t3 != T_LCBRACE) {
				ERROR("%s[%d]: Expecting section start brace '{' after \"%s %s\"",
				      filename, *lineno, buff[1], buff[2]);
				goto error;
			}
			/* FALL-THROUGH */

		alloc_section:
		case T_LCBRACE:
			css = cf_section_alloc(this, buff[1],
					       t2 == T_LCBRACE ? NULL : buff[2]);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section",
				      filename, *lineno);
				goto error;
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

			goto error;

		default:
			ERROR("%s[%d]: Parse error after \"%s\": unexpected token \"%s\"",
			      filename, *lineno, buff[1], fr_int2str(fr_tokens_table, t2, "<INVALID>"));

			goto error;
		}

	check_for_more:
		/*
		 *	Done parsing one thing.  Skip to EOL if possible.
		 */
		while (isspace(*ptr)) ptr++;

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
		goto error;
	}

	return 0;
}

/*
 *	Include one config file in another.
 */
static int cf_file_include(CONF_SECTION *cs, char const *filename_in,
#ifndef WITH_CONF_WRITE
			   UNUSED
#endif
			   CONF_INCLUDE_TYPE file_type, char *buff[7])
{
	FILE		*fp;
	int		lineno = 0;
	char const	*filename;

	/*
	 *	So we only need to do this once.
	 */
	filename = talloc_strdup(cs, filename_in);

	DEBUG2("including configuration file %s", filename);

	fp = cf_file_open(cs, filename);
	if (!fp) return -1;

	if (!cs->item.filename) cs->item.filename = filename;

#ifdef WITH_CONF_WRITE
	/*
	 *	Instruct the parser that we've started to include a
	 *	file at this point.
	 */
	cf_include_add(cs, filename, file_type);
#endif

	/*
	 *	Read the section.  It's OK to have EOF without a
	 *	matching close brace.
	 */
	if (cf_section_read(filename, &lineno, fp, cs, buff) < 0) {
		fclose(fp);
		return -1;
	}

#ifdef WITH_CONF_WRITE
	/*
	 *	Instruct the parser that we've finished including a
	 *	file at this point.
	 */
	cf_include_add(cs, NULL, file_type);
#endif

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

		talloc_const_free(cp->value);
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
	int i;
	char *p;
	CONF_PAIR *cp;
	rbtree_t *tree;
	char **buff;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	if (!cp) return -1;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cf_item_add(cs, &(cp->item));

	tree = rbtree_create(cs, filename_cmp, NULL, 0);
	if (!tree) return -1;

	cf_data_add(cs, tree, "filename", false);

	/*
	 *	Allocate temporary buffers on the heap (so we don't use *all* the stack space)
	 */
	buff = talloc_array(cs, char *, 7);
	for (i = 0; i < 7; i++) {
		buff[i] = talloc_array(buff, char, 8192);
	}

	if (cf_file_include(cs, filename, CONF_INCLUDE_FILE, buff) < 0) {
		talloc_free(buff);
		return -1;
	}

	talloc_free(buff);

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
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_attr_type(CONF_PAIR const *pair)
{
	return (pair ? pair->lhs_type : T_INVALID);
}

/** Return the value (rhs) type
 *
 * @param pair to extract value type from.
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_value_type(CONF_PAIR const *pair)
{
	return (pair ? pair->rhs_type : T_INVALID);
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

char const *cf_section_argv(CONF_SECTION const *cs, int argc)
{
	if (!cs || !cs->argv || (argc < 0) || (argc > cs->argc)) return NULL;

	return cs->argv[argc];
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
 * @return the next matching #CONF_PAIR or NULL if none matched.
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

/** Find a sub-section in a section
 *
 *	This finds ANY section having the same first name.
 *	The second name is ignored.
 */
CONF_SECTION *cf_subsection_find(CONF_SECTION const *cs, char const *name)
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
CONF_SECTION *cf_subsection_find_name2(CONF_SECTION const *cs,
					char const *name1, char const *name2)
{
	CONF_ITEM    *ci;

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

	return cf_subsection_find_next(cf_item_to_section(section->item.parent), subsection, name1);
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

CONF_ITEM *cf_item_parent(CONF_ITEM const *ci)
{
	if (!ci) return NULL;

	return ci->parent;
}

CONF_SECTION *cf_section_parent(CONF_SECTION const *cs)
{
	if (!cs) return NULL;

	return cf_item_to_section(cs->item.parent);
}

CONF_SECTION *cf_pair_parent(CONF_PAIR const *cp)
{
	if (!cp) return NULL;

	return cf_item_to_section(cp->item.parent);
}

CONF_SECTION *cf_item_root(CONF_ITEM const *ci)
{
	CONF_ITEM *ci_p;

	if (!ci) return NULL;

	for (ci_p = ci->parent; ci_p->parent; ci_p = ci_p->parent);

	return cf_item_to_section(ci_p);
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

/** Allocate a new user data container
 *
 * @param[in] parent	#CONF_PAIR, or #CONF_SECTION to hang CONF_DATA off of.
 * @param[in] name	String identifier of the user data.
 * @param[in] data	being added.
 * @param[in] do_free	function, called when the parent #CONF_SECTION is being freed.
 * @return
 *	- CONF_DATA on success.
 *	- NULL on error.
 */
static CONF_DATA *cf_data_alloc(CONF_ITEM *parent, void const *data, char const *name, bool do_free)
{
	CONF_DATA *cd;

	cd = talloc_zero(parent, CONF_DATA);
	if (!cd) return NULL;

	cd->item.type = CONF_ITEM_DATA;
	cd->item.parent = parent;

	/*
	 *	strdup so if the data is freed, we can
	 *	still remove it from the section without
	 *	explosions.
	 */
	if (data) {
		cd->type = talloc_typed_strdup(cd, talloc_get_name(data));
		cd->data = data;
	}
	if (name) cd->name = talloc_typed_strdup(cd, name);

	if (do_free) {
		cd->free = true;
		talloc_set_destructor(cd, _cd_free);
	}

	return cd;
}

/** Find user data in a config section
 *
 * @param[in] cs	to add data to.
 * @param[in] type	of user data.  Used for name spacing and walking over a specific
 *			type of user data.
 * @param[in] name	String identifier of the user data.
 * @return
 *	- The user data.
 *	- NULL if no user data exists.
 */
void *_cf_data_find(CONF_SECTION const *cs, char const *type, char const *name)
{
	if (!cs || (!type && !name)) {
		cf_log_err_cs(cs, "Invalid arguments");
		return NULL;
	}

	/*
	 *	Find the name in the tree, for speed.
	 */
	if (cs->data_tree) {
		CONF_DATA mycd, *cd;

		mycd.type = type;
		mycd.name = name;
		cd = rbtree_finddata(cs->data_tree, &mycd);
		if (cd) {
			void *to_return;
			memcpy(&to_return, &cd->data, sizeof(to_return));

			return to_return;
		}
	}

	return NULL;
}

/** Add user data to a config section
 *
 * @param[in] cs	to add data to.
 * @param[in] data	to add.
 * @param[in] name	String identifier of the user data.
 * @param[in] do_free	Function to free user data when the CONF_SECTION is freed.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int _cf_data_add(CONF_SECTION *cs, void const *data, char const *name, bool do_free)
{
	CONF_DATA	*cd;
	char const	*type = NULL;

	if (!cs || (!data && !name)) {
		cf_log_err_cs(cs, "Invalid arguments");
		return -1;
	}

	if (data) type = talloc_get_name(data);

	/*
	 *	Already exists.  Can't add it.
	 */
	if (_cf_data_find(cs, type, name)) {
		cf_log_err_cs(cs, "Data of type %s with name %s already exists", type, name);
		return -1;
	}

	cd = cf_data_alloc(cf_section_to_item(cs), data, name, do_free);
	if (!cd) {
		cf_log_err_cs(cs, "Failed allocating data");
		return -1;
	}

	cf_item_add(cs, cf_data_to_item(cd));

	return 0;
}

/** Remove named data from a configuration section
 *
 * @param[in] cs	to remove data from.
 * @param[in] type	of user data.  Used for name spacing and walking over a specific
 *			type of user data.
 * @param[in] name	String identifier of the user data.
 * @return
 *	- The user data.
 *	- NULL if no matching data is found.
 */
void *_cf_data_remove(CONF_SECTION *cs, char const *type, char const *name)
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
	mycd.type = type;
	mycd.name = name;

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

	memcpy(&data, &cd->data, sizeof(data));
	talloc_free(cd);

	return data;
}

/** ctx data for a _cf_data_walk_call
 *
 */
typedef struct cf_data_walk_ctx {
	char const 	*type;		//!< of CONF_DATA we're iterating over.
	cf_walker_t	cb;		//!< cb to process CONF_DATA.
	void		*ctx;		//!< to pass to cb.
} cf_data_walk_ctx_t;

/** Wrap a cf_walker_t in an rb_walker_t
 *
 * @param[in] ctx	A cf_data_walk_ctx_t.
 * @param[in] data	A CONF_DATA entry.
 */
static int _cf_data_walk_cb(void *ctx, void *data)
{
	cf_data_walk_ctx_t	*cd_ctx = ctx;
	CONF_DATA		*cd = data;
	void			*mutable;
	int			ret;

	if ((cd->type != cd_ctx->type) && (strcmp(cd->type, cd_ctx->type) != 0)) return 0;

	memcpy(&mutable, &cd->data, sizeof(data));
	ret = cd_ctx->cb(mutable, cd_ctx->ctx);

	return ret;
}

/** Walk over a specific type of CONF_DATA
 *
 * @param[in] cs	containing the CONF_DATA to walk over.
 * @param[in] type	of CONF_DATA to walk over.
 * @param[in] cb	to call when we find CONF_DATA of the specified type.
 * @param[in] ctx	to pass to cb.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _cf_data_walk(CONF_SECTION *cs, char const *type, cf_walker_t cb, void *ctx)
{
	cf_data_walk_ctx_t cd_ctx = {
		.type = type,
		.cb = cb,
		.ctx = ctx
	};

	if (!cs->data_tree) return 0;

	return rbtree_walk(cs->data_tree, RBTREE_IN_ORDER, _cf_data_walk_cb, &cd_ctx);
}

/*
 *	This is here to make the rest of the code easier to read.  It
 *	ties conf_file.c to log.c, but it means we don't have to
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
		      ci->filename, ci->lineno,
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
	      cs->item.filename, cs->item.lineno,
	       buffer);
}

void cf_log_perr_cs(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cs != NULL);

	PERROR("%s[%d]: %s", cs->item.filename, cs->item.lineno, buffer);
}

void cf_log_err_cp(CONF_PAIR const *cp, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cp != NULL);

	ERROR("%s[%d]: %s", cp->item.filename, cp->item.lineno, buffer);
}

void cf_log_perr_cp(CONF_PAIR const *cp, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cp != NULL);

	PERROR("%s[%d]: %s", cp->item.filename, cp->item.lineno, buffer);
}

void cf_log_err_by_name(CONF_SECTION const *parent, char const *name, char const *fmt, ...)
{
	va_list ap;
	CONF_PAIR const *cp;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	cp = cf_pair_find(parent, name);
	if (cp) {
		ERROR("%s[%d]: %s",
		      cp->item.filename, cp->item.lineno,
		      buffer);
	} else {
		ERROR("%s[%d]: %s",
		      parent->item.filename, parent->item.lineno,
		      buffer);
	}

}

void cf_log_warn_cp(CONF_PAIR const *cp, char const *fmt, ...)
{
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	rad_assert(cp != NULL);

	WARN("%s[%d]: %s",
	     cp->item.filename, cp->item.lineno,
	     buffer);
}

void cf_log_warn(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (cs) fr_vlog(&default_log, L_WARN, fmt, ap);
	va_end(ap);
}

void cf_log_info(CONF_SECTION const *cs, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((rad_debug_lvl > 1) && cs) fr_vlog(&default_log, L_DBG, fmt, ap);
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

FR_TOKEN cf_section_argv_type(CONF_SECTION const *cs, int argc)
{
	if (!cs || !cs->argv_type || (argc < 0) || (argc > cs->argc)) return T_INVALID;

	return cs->argv_type[argc];
}

#ifdef WITH_CONF_WRITE
static char const parse_tabs[] = "																																																																																																																																																																																																								";

static ssize_t cf_string_write(FILE *fp, char const *string, size_t len, FR_TOKEN t)
{
	size_t outlen;
	char c;
	char buffer[2048];

	switch (t) {
	default:
		c = '\0';
		break;

	case T_DOUBLE_QUOTED_STRING:
		c = '"';
		break;

	case T_SINGLE_QUOTED_STRING:
		c = '\'';
		break;

	case T_BACK_QUOTED_STRING:
		c = '`';
		break;
	}

	if (c) fprintf(fp, "%c", c);

	outlen = fr_snprint(buffer, sizeof(buffer), string, len, c);
	fwrite(buffer, outlen, 1, fp);

	if (c) fprintf(fp, "%c", c);
	return 1;
}


static size_t cf_pair_write(FILE *fp, CONF_PAIR *cp)
{
	if (!cp->value) {
		fprintf(fp, "%s\n", cp->attr);
		return 0;
	}

	cf_string_write(fp, cp->attr, strlen(cp->attr), cp->lhs_type);
	fprintf(fp, " %s ", fr_int2str(fr_tokens_table, cp->op, "<INVALID>"));
	cf_string_write(fp, cp->orig_value, strlen(cp->orig_value), cp->rhs_type);
	fprintf(fp, "\n");

	return 1;		/* FIXME */
}


static FILE *cf_file_write(CONF_SECTION *cs, char const *filename)
{
	FILE *fp;
	char *p;
	char const *q;
	char buffer[8192];

	q = filename;
	if ((q[0] == '.') && (q[1] == '/')) q += 2;

	snprintf(buffer, sizeof(buffer), "%s/%s", main_config.write_dir, q);

	p = strrchr(buffer, '/');
	*p = '\0';
	if ((rad_mkdir(buffer, 0700, -1, -1) < 0) &&
	    (errno != EEXIST)) {
		cf_log_err_cs(cs, "Failed creating directory %s: %s",
			      buffer, strerror(errno));
		return NULL;
	}

	/*
	 *	And again, because rad_mkdir() butchers the buffer.
	 */
	snprintf(buffer, sizeof(buffer), "%s/%s", main_config.write_dir, q);

	fp = fopen(buffer, "a");
	if (!fp) {
		cf_log_err_cs(cs, "Failed creating file %s: %s",
			      buffer, strerror(errno));
		return NULL;
	}

	return fp;
}

size_t cf_section_write(FILE *in_fp, CONF_SECTION *cs, int depth)
{
	bool prev = false;
	CONF_ITEM *ci;
	FILE *fp = NULL;
	int fp_max = 0;
	FILE *array[32];

	/*
	 *	Default to writing to the FP we're given.
	 */
	fp = in_fp;
	array[0] = fp;
	fp_max = 0;

	/*
	 *	If we have somewhere to print, then print the section
	 *	name1, etc.
	 */
	if (fp) {
		fwrite(parse_tabs, depth, 1, fp);
		cf_string_write(fp, cs->name1, strlen(cs->name1), T_BARE_WORD);

		/*
		 *	FIXME: check for "if" or "elsif".  And if so, print
		 *	out the parsed condition, instead of the input text
		 *
		 *	cf_data_find(cs, CF_DATA_TYPE_UNLANG, "if");
		 */

		if (cs->name2) {
			fr_cond_t *c;

			fputs(" ", fp);

			c = cf_data_find(cs, fr_cond_t, NULL);
			if (c) {
				char buffer[1024];

				cond_snprint(buffer, sizeof(buffer), c);
				fprintf(fp, "(%s)", buffer);

			} else {	/* dump the string as-is */
				cf_string_write(fp, cs->name2, strlen(cs->name2), cs->name2_type);
			}
		}

		fputs(" {\n", fp);
	}

	/*
	 *	Loop over the children.  Either recursing, or opening
	 *	a new file.
	 */
	for (ci = cs->children; ci; ci = ci->next) {
		switch (ci->type) {
		case CONF_ITEM_SECTION:
			if (!fp) continue;

			cf_section_write(fp, cf_item_to_section(ci), depth + 1);
			break;

		case CONF_ITEM_PAIR:
			if (!fp) continue;

			/*
			 *	Ignore internal things.
			 */
			if (!ci->filename || (ci->filename[0] == '<')) break;

			fwrite(parse_tabs, depth + 1, 1, fp);
			cf_pair_write(fp, cf_item_to_pair(ci));
			if (!prev) fputs("\n", fp);
			prev = true;
			break;

		case CONF_ITEM_COMMENT:
			rad_assert(fp != NULL);

			prev = false;
			fwrite(parse_tabs, depth + 1, 1, fp);
			fprintf(fp, "#%s", ((CONF_COMMENT *)ci)->comment);
			break;

		case CONF_ITEM_INCLUDE:
			/*
			 *	Filename == open the new filename and use that.
			 *
			 *	NULL == close the previous filename
			 */
			if (((CONF_INCLUDE *) ci)->filename) {
				CONF_INCLUDE *cc = (CONF_INCLUDE *) ci;

				/*
				 *	Print out
				 *
				 *	$INCLUDE foo.conf
				 *	$INCLUDE foo/
				 *
				 *	but not the files included from the last one.
				 */
				if (fp && (cc->file_type != CONF_INCLUDE_FROMDIR)) {
					fprintf(fp, "$INCLUDE %s\n", ((CONF_INCLUDE *)ci)->filename);
				}

				/*
				 *	If it's a file, we write the
				 *	file.  We ignore the
				 *	directories.  They're just for printing.
				 */
				if (cc->file_type != CONF_INCLUDE_DIR) {
					fp = cf_file_write(cs, ((CONF_INCLUDE *) ci)->filename);
					if (!fp) return 0;

					fp_max++;
					array[fp_max] = fp;
				}
			} else {
				/*
				 *	We're done the current file.
				 */
				rad_assert(fp != NULL);
				rad_assert(fp_max > 0);
				fclose(fp);

				fp_max--;
				fp = array[fp_max];
			}
			break;

		default:
			break;
		}
	}

	if (fp) {
		fwrite(parse_tabs, depth, 1, fp);
		fputs("}\n\n", fp);
	}

	return 1;
}
#endif	/* WITH_CONF_WRITE */
