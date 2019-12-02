/*
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
 */

/**
 * $Id$
 * @file cf_file.c
 * @brief Read the radiusd.conf file.
 *
 * @note  Yep I should learn to use lex & yacc, or at least
 *	  write a decent parser. I know how to do that, really :)
 *	  miquels@cistron.nl
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/util.h>

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <ctype.h>
#include <fcntl.h>

bool check_config = false;
static uid_t conf_check_uid = (uid_t)-1;
static gid_t conf_check_gid = (gid_t)-1;

typedef enum conf_property {
	CONF_PROPERTY_INVALID = 0,
	CONF_PROPERTY_NAME,
	CONF_PROPERTY_INSTANCE,
} CONF_PROPERTY;

static fr_table_num_sorted_t const conf_property_name[] = {
	{ "instance",	CONF_PROPERTY_INSTANCE	},
	{ "name",	CONF_PROPERTY_NAME	}
};
static size_t conf_property_name_len = NUM_ELEMENTS(conf_property_name);

#define MAX_STACK (32)
typedef struct {
	FILE		*fp;			//!< FP we're reading
	char const     	*filename;		//!< filename we're reading
	int		lineno;			//!< line in that filename

	DIR		*dir;			//!< Or we're reading a directory
	char		*directory;		//!< directory name we're reading

	CONF_SECTION	*parent;		//!< which started this file
	CONF_SECTION	*current;		//!< sub-section we're reading
	CONF_SECTION	*special;		//!< map / update section

	int		braces;
	bool		from_dir;		//!< this file was read from $include foo/
} cf_stack_frame_t;

/*
 *	buff[0] is the data we read from the file
 *	buff[1] is name
 *	buff[2] is name2 OR value for pair
 *	buff[3] is a temporary buffer
 */
typedef struct {
	char		**buff;			//!< buffers for reading / parsing
	size_t		bufsize;		//!< size of the buffers
	int		depth;			//!< stack depth
	char const	*ptr;			//!< current parse pointer
	char		*fill;			//!< where we start filling the buffer from
	cf_stack_frame_t frame[MAX_STACK];	//!< stack frames
} cf_stack_t;

/*
 *	Expand the variables in an input string.
 *
 *	Input and output should be two different buffers, as the
 *	output may be longer than the input.
 */
char const *cf_expand_variables(char const *cf, int lineno,
				CONF_SECTION *outer_cs,
				char *output, size_t outsize,
				char const *input, ssize_t inlen, bool *soft_fail)
{
	char *p;
	char const *end, *next, *ptr;
	CONF_SECTION const *parent_cs;
	char name[8192];

	if (soft_fail) *soft_fail = false;

	/*
	 *	Find the master parent conf section.
	 *	We can't use main_config->root_cs, because we're in the
	 *	process of re-building it, and it isn't set up yet...
	 */
	parent_cs = cf_root(outer_cs);

	p = output;
	ptr = input;

	if (inlen < 0) {
		end = NULL;
	} else {
		end = input + inlen;
	}

	/*
	 *	Note that this CAN go over "end" if the input string
	 *	is malformed.  e.g. pass "${foo.bar}", and pass
	 *	"inlen=5".  Well, too bad.
	 */
	while (*ptr && (!end || (ptr < end))) {
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
			next = strchr(ptr, '}');
			if (next == NULL) {
				*p = '\0';
				ERROR("%s[%d]: Variable expansion '%s' missing '}'",
				     cf, lineno, input);
				return NULL;
			}

			ptr += 2;

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (next - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Reference string is too large",
				      cf, lineno);
				return NULL;
			}

			memcpy(name, ptr, next - ptr);
			name[next - ptr] = '\0';

			q = strchr(name, ':');
			if (q) {
				*(q++) = '\0';
			}

			ci = cf_reference_item(parent_cs, outer_cs, name);
			if (!ci) {
				if (soft_fail) *soft_fail = true;
				ERROR("%s[%d]: Reference \"${%s}\" not found", cf, lineno, name);
				return NULL;
			}

			/*
			 *	The expansion doesn't refer to another item or section
			 *	it's the property of a section.
			 */
			if (q) {
				CONF_SECTION *find = cf_item_to_section(ci);

				if (ci->type != CONF_ITEM_SECTION) {
					ERROR("%s[%d]: Can only reference properties of sections", cf, lineno);
					return NULL;
				}

				switch (fr_table_value_by_str(conf_property_name, q, CONF_PROPERTY_INVALID)) {
				case CONF_PROPERTY_NAME:
					strcpy(p, find->name1);
					break;

				case CONF_PROPERTY_INSTANCE:
					strcpy(p, find->name2 ? find->name2 : find->name1);
					break;

				default:
					ERROR("%s[%d]: Invalid property '%s'", cf, lineno, q);
					return NULL;
				}
				p += strlen(p);
				ptr = next + 1;

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
					      cf, lineno, input);
					return NULL;
				}

				if (!cp->value) {
					ERROR("%s[%d]: Reference \"%s\" has no value",
					      cf, lineno, input);
					return NULL;
				}

				if (p + strlen(cp->value) >= output + outsize) {
					ERROR("%s[%d]: Reference \"%s\" is too long",
					      cf, lineno, input);
					return NULL;
				}

				strcpy(p, cp->value);
				p += strlen(p);
				ptr = next + 1;

			} else if (ci->type == CONF_ITEM_SECTION) {
				CONF_SECTION *subcs;

				/*
				 *	Adding an entry again to a
				 *	section is wrong.  We don't
				 *	want an infinite loop.
				 */
				if (cf_item_to_section(ci->parent) == outer_cs) {
					ERROR("%s[%d]: Cannot reference different item in same section", cf, lineno);
					return NULL;
				}

				/*
				 *	Copy the section instead of
				 *	referencing it.
				 */
				subcs = cf_item_to_section(ci);
				subcs = cf_section_dup(outer_cs, outer_cs, subcs,
						       cf_section_name1(subcs), cf_section_name2(subcs),
						       false);
				if (!subcs) {
					ERROR("%s[%d]: Failed copying reference %s", cf, lineno, name);
					return NULL;
				}

				subcs->item.filename = ci->filename;
				subcs->item.lineno = ci->lineno;
				cf_item_add(outer_cs, &(subcs->item));

				ptr = next + 1;

			} else {
				ERROR("%s[%d]: Reference \"%s\" type is invalid", cf, lineno, input);
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
			next = strchr(ptr, '}');
			if (next == NULL) {
				*p = '\0';
				ERROR("%s[%d]: Environment variable expansion missing }",
				     cf, lineno);
				return NULL;
			}

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (next - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Environment variable name is too large",
				      cf, lineno);
				return NULL;
			}

			memcpy(name, ptr, next - ptr);
			name[next - ptr] = '\0';

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
				      cf, lineno, input);
				return NULL;
			}

			strcpy(p, env);
			p += strlen(p);
			ptr = next + 1;

		} else {
			/*
			 *	Copy it over verbatim.
			 */
			*(p++) = *(ptr++);
		}

		if (p >= (output + outsize)) {
			ERROR("%s[%d]: Reference \"%s\" is too long",
			      cf, lineno, input);
			return NULL;
		}
	} /* loop over all of the input string. */

	*p = '\0';

	return output;
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
	for (ci = template->item.child; ci; ci = ci->next) {
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

			subcs2 = cf_section_find(cs, subcs1->name1, subcs1->name2);
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
			subcs2 = cf_section_dup(cs, cs, subcs1,
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

/*
 *	Functions for tracking filenames.
 */
static int _filename_cmp(void const *a, void const *b)
{
	cf_file_t const *one = a, *two = b;
	int ret;

	ret = (one->buf.st_dev < two->buf.st_dev) - (one->buf.st_dev > two->buf.st_dev);
	if (ret != 0) return ret;

	return (one->buf.st_ino < two->buf.st_ino) - (one->buf.st_ino > two->buf.st_ino);
}

static int cf_file_open(CONF_SECTION *cs, char const *filename, bool from_dir, FILE **fp_p)
{
	cf_file_t *file;
	CONF_SECTION *top;
	rbtree_t *tree;
	int fd;
	FILE *fp;

	top = cf_root(cs);
	tree = cf_data_value(cf_data_find(top, rbtree_t, "filename"));
	rad_assert(tree);

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

		/*
		 *	The file was previously read by including it
		 *	explicitly.  After it was read, we have a
		 *	$INCLUDE of the directory it is in.  In that
		 *	case, we ignore the file.
		 *
		 *	However, if the file WAS read from a wildcard
		 *	$INCLUDE directory, then we read it again.
		 */
		if (file && !file->from_dir) return 1;
	}

	DEBUG2("including configuration file %s", filename);

	fp = fopen(filename, "r");
	if (!fp) {
	error:
		ERROR("Unable to open file \"%s\": %s", filename, fr_syserror(errno));
		return -1;
	}

	fd = fileno(fp);

	MEM(file = talloc(tree, cf_file_t));

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
	if (!rbtree_insert(tree, file)) talloc_free(file);

	*fp_p = fp;
	return 0;
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
bool cf_file_check(CONF_SECTION *cs, char const *filename, bool check_perms)
{
	cf_file_t	*file;
	CONF_SECTION	*top;
	rbtree_t	*tree;
	int		fd = -1;

	top = cf_root(cs);
	tree = cf_data_value(cf_data_find(top, rbtree_t, "filename"));
	if (!tree) return false;

	file = talloc(tree, cf_file_t);
	if (!file) return false;

	file->filename = filename;
	file->cs = cs;

	if (!check_perms) {
		if (stat(filename, &file->buf) < 0) {
		perm_error:
			rad_file_error(errno);	/* Write error and euid/egid to error buff */
			PERROR("Unable to open file \"%s\"", filename);
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
				ERROR("Failed setting effective group ID (%i) for file check: %s",
				      conf_check_gid, fr_syserror(errno));
				goto error;
			}
		}
		if ((conf_check_uid != (uid_t)-1) && ((euid = geteuid()) != conf_check_uid)) {
			if (seteuid(conf_check_uid) < 0) {
				ERROR("Failed setting effective user ID (%i) for file check: %s",
				      conf_check_uid, fr_syserror(errno));
				goto error;
			}
		}
		fd = open(filename, O_RDONLY);
		if (conf_check_uid != euid) {
			if (seteuid(euid) < 0) {
				ERROR("Failed restoring effective user ID (%i) after file check: %s",
				      euid, fr_syserror(errno));

				goto error;
			}
		}
		if (conf_check_gid != egid) {
			if (setegid(egid) < 0) {
				ERROR("Failed restoring effective group ID (%i) after file check: %s",
				      egid, fr_syserror(errno));
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

typedef struct {
	int		rcode;
	rb_walker_t	callback;
	CONF_SECTION	*modules;
} cf_file_callback_t;

/*
 *	Return 0 for keep going, 1 for stop.
 */
static int _file_callback(void *data, void *uctx)
{
	cf_file_callback_t	*cb = uctx;
	cf_file_t		*file = data;
	struct stat		buf;

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
 *	Do variable expansion in pass2.
 *
 *	This is a breadth-first expansion.  "deep
 */
int cf_section_pass2(CONF_SECTION *cs)
{
	CONF_ITEM *ci;

	for (ci = cs->item.child; ci; ci = ci->next) {
		char const	*value;
		CONF_PAIR	*cp;
		char		buffer[8192];

		if (ci->type != CONF_ITEM_PAIR) continue;

		cp = cf_item_to_pair(ci);
		if (!cp->value || !cp->pass2) continue;

		rad_assert((cp->rhs_quote == T_BARE_WORD) ||
			   (cp->rhs_quote == T_DOUBLE_QUOTED_STRING) ||
			   (cp->rhs_quote == T_BACK_QUOTED_STRING));

		value = cf_expand_variables(ci->filename, ci->lineno, cs, buffer, sizeof(buffer), cp->value, -1, NULL);
		if (!value) return -1;

		talloc_const_free(cp->value);
		cp->value = talloc_typed_strdup(cp, value);
	}

	for (ci = cs->item.child; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION) continue;

		if (cf_section_pass2(cf_item_to_section(ci)) < 0) return -1;
	}

	return 0;
}


static char const *cf_local_file(char const *base, char const *filename,
				 char *buffer, size_t bufsize)
{
	size_t	dirsize;
	char	*p;

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

static bool invalid_location(CONF_SECTION *parent, char const *name, char const *filename, int lineno)
{
	/*
	 *	if / elsif MUST be inside of a
	 *	processing section, which MUST in turn
	 *	be inside of a "server" directive.
	 */
	if (!parent || !parent->item.parent) {
	invalid_location:
		ERROR("%s[%d]: Invalid location for '%s'",
		      filename, lineno, name);
		return true;
	}

	/*
	 *	Can only have "if" in 3 named sections.
	 */
	parent = cf_item_to_section(parent->item.parent);
	while ((strcmp(parent->name1, "server") != 0) &&
	       (strcmp(parent->name1, "policy") != 0) &&
	       (strcmp(parent->name1, "instantiate") != 0)) {
		parent = cf_item_to_section(parent->item.parent);
		if (!parent) goto invalid_location;
	}

	return false;
}


/*
 *	Like gettoken(), but uses the new API which seems better for a
 *	host of reasons.
 */
static int cf_get_token(CONF_SECTION *parent, char const **ptr_p, FR_TOKEN *token, char *buffer, size_t buflen,
			char const *filename, int lineno)
{
	char const *ptr = *ptr_p;
	ssize_t slen;
	char const *error;
	char const *out;
	size_t outlen;

	/*
	 *	Discover the string content, returning what kind of
	 *	string it is.
	 *
	 *	Don't allow casts or regexes.  But do allow bare
	 *	%{...} expansions.
	 */
	slen = tmpl_preparse(&out, &outlen, ptr, token, &error, NULL, false, true);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(parent, &spaces, &text, slen, ptr);

		ERROR("%s[%d]: %s", filename, lineno, text);
		ERROR("%s[%d]: %s^ - %s", filename, lineno, spaces, error);

		talloc_free(spaces);
		talloc_free(text);
		return -1;
	}

	if ((size_t) slen >= buflen) {
		ERROR("%s[%d]: Name is too long", filename, lineno);
		return -1;
	}

	/*
	 *	Unescape it or copy it verbatim as necessary.
	 */
	if (!cf_expand_variables(filename, lineno, parent, buffer, buflen,
				 out, outlen, NULL)) {
		return -1;
	}

	ptr += slen;
	fr_skip_whitespace(ptr);

	*ptr_p = ptr;
	return 0;
}


static int process_include(cf_stack_t *stack, CONF_SECTION *parent, char const *ptr, bool required)
{
	bool relative = true;
	char const *value;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];

	/*
	 *	Can't do this inside of update / map.
	 */
	if (frame->special) {
		ERROR("%s[%d]: Parse error: Invalid location for $INCLUDE",
		      frame->filename, frame->lineno);
		return -1;
	}

	fr_skip_whitespace(ptr);

	/*
	 *	Grab all of the non-whitespace text.
	 */
	value = ptr;
	while (*ptr && !isspace((int) *ptr)) ptr++;

	/*
	 *	We're OK with whitespace after the filename.
	 */
	fr_skip_whitespace(ptr);

	/*
	 *	But anything else after the filename is wrong.
	 */
	if (*ptr) {
		ERROR("%s[%d]: Unexpected text after $INCLUDE", frame->filename, frame->lineno);
		return -1;
	}

	/*
	 *	Hack for ${confdir}/foo
	 */
	if (*value == '$') relative = false;

	value = cf_expand_variables(frame->filename, frame->lineno, parent, stack->buff[1], stack->bufsize,
				    value, ptr - value, NULL);
	if (!value) return -1;

	if (!FR_DIR_IS_RELATIVE(value)) relative = false;

	if (relative) {
		value = cf_local_file(frame->filename, value, stack->buff[2], stack->bufsize);
		if (!value) {
			ERROR("%s[%d]: Directories too deep", frame->filename, frame->lineno);
			return -1;
		}
	}

	/*
	 *	Allow $-INCLUDE for directories, too.
	 */
	if (!required) {
		struct stat statbuf;

		if (stat(value, &statbuf) < 0) {
			WARN("Not including file %s: %s", value, fr_syserror(errno));
			return 0;
		}
	}

	/*
	 *	The filename doesn't end in '/', so it must be a file.
	 */
	if (value[strlen(value) - 1] != '/') {
		if ((stack->depth + 1) >= MAX_STACK) {
			ERROR("%s[%d]: Directories too deep", frame->filename, frame->lineno);
			return -1;
		}

		stack->depth++;
		frame = &stack->frame[stack->depth];
		memset(frame, 0, sizeof(*frame));
		frame->fp = NULL;
		frame->parent = parent;
		frame->current = parent;
		frame->filename = talloc_strdup(frame->parent, value);
		frame->special = NULL;
		return 1;
	}

#ifdef HAVE_DIRENT_H
	/*
	 *	$INCLUDE foo/
	 *
	 *	Include ALL non-"dot" files in the directory.
	 *	careful!
	 */
	{
		DIR		*dir;
		struct stat stat_buf;
		char *directory;

		/*
		 *	We need to keep a copy of parent while the
		 *	included files mangle our buff[] array.
		 */
		directory = talloc_strdup(parent, value);

		cf_log_debug(parent, "Including files in directory \"%s\"", directory);

		dir = opendir(directory);
		if (!dir) {
			ERROR("%s[%d]: Error reading directory %s: %s",
			      frame->filename, frame->lineno, value,
			      fr_syserror(errno));
		error:
			talloc_free(directory);
			return -1;
		}
#ifdef S_IWOTH
		/*
		 *	Security checks.
		 */
		if (fstat(dirfd(dir), &stat_buf) < 0) {
			ERROR("%s[%d]: Failed reading directory %s: %s", frame->filename, frame->lineno,
			      directory, fr_syserror(errno));
			goto error;
		}

		if ((stat_buf.st_mode & S_IWOTH) != 0) {
			ERROR("%s[%d]: Directory %s is globally writable.  Refusing to start due to "
			      "insecure configuration", frame->filename, frame->lineno, directory);
			goto error;
		}
#endif

		/*
		 *	Directory plus next filename.
		 */
		if ((stack->depth + 2) >= MAX_STACK) {
			ERROR("%s[%d]: Directories too deep", frame->filename, frame->lineno);
			goto error;
		}

		stack->depth++;
		frame = &stack->frame[stack->depth];

		memset(frame, 0, sizeof(*frame));
		frame->dir = dir;
		frame->directory = directory;
		frame->parent = parent;
		frame->current = parent;
		frame->from_dir = true;

		/*
		 *	No "$INCLUDE dir/" inside of update / map.  That's dumb.
		 */
		frame->special = NULL;
		return 1;
	}
#else
	ERROR("%s[%d]: Error including %s: No support for directories!",
	      frame->filename, frame->lineno, value);
	return -1;
#endif
}


static int process_template(cf_stack_t *stack)
{
	CONF_ITEM *ci;
	CONF_SECTION *parent_cs, *templatecs;
	FR_TOKEN token;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;

	token = getword(&stack->ptr, stack->buff[2], stack->bufsize, true);
	if (token != T_EOL) {
		ERROR("%s[%d]: Unexpected text after $TEMPLATE", frame->filename, frame->lineno);
		return -1;
	}

	if (!parent) {
		ERROR("%s[%d]: Internal sanity check error in template reference", frame->filename, frame->lineno);
		return -1;
	}

	if (parent->template) {
		ERROR("%s[%d]: Section already has a template", frame->filename, frame->lineno);
		return -1;
	}

	parent_cs = cf_root(parent);

	templatecs = cf_section_find(parent_cs, "templates", NULL);
	if (!templatecs) {
		ERROR("%s[%d]: No \"templates\" section for reference \"%s\"",
		      frame->filename, frame->lineno, stack->buff[2]);
		return -1;
	}

	ci = cf_reference_item(parent_cs, templatecs, stack->buff[2]);
	if (!ci || (ci->type != CONF_ITEM_SECTION)) {
		ERROR("%s[%d]: Reference \"%s\" not found",
		      frame->filename, frame->lineno, stack->buff[2]);
		return -1;
	}

	parent->template = cf_item_to_section(ci);
	return 0;
}


static int cf_file_fill(cf_stack_t *stack);

static CONF_SECTION *process_if(cf_stack_t *stack)
{
	ssize_t slen = 0;
	char const *error = NULL;
	fr_cond_t *cond = NULL;
	CONF_DATA const *cd;
	fr_dict_t const *dict = NULL;
	CONF_SECTION *cs;
	char *p;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];

	/*
	 *	Short names are nicer.
	 */
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];

	/*
	 *	if / elsif
	 */
	if (invalid_location(parent, buff[1], frame->filename, frame->lineno)) return NULL;

	cd = cf_data_find_in_parent(parent, fr_dict_t **, "dictionary");
	if (!cd) {
		dict = fr_dict_internal();	/* HACK - To fix policy sections */
	} else {
		dict = *((fr_dict_t **)cf_data_value(cd));
	}

	/*
	 *	fr_cond_tokenize needs the current section, so we
	 *	create it first.  We don't pass a name2, as it hasn't
	 *	yet been parsed.
	 */
	cs = cf_section_alloc(parent, parent, buff[1], NULL);
	if (!cs) {
		cf_log_err(parent, "Failed allocating memory for section");
		return NULL;
	}
	cs->item.filename = frame->filename;
	cs->item.lineno = frame->lineno;

	/*
	 *	Skip (...) to find the {
	 */
	while (true) {
		slen = fr_cond_tokenize(cs, &cond, &error, dict, ptr);
		if (slen < 0) {
			ssize_t end = -slen;

			/*
			 *	For paranoia, check that "end" is valid.
			 */
			if ((ptr + end) > (stack->buff[0] + stack->bufsize)) {
				cf_log_err(parent, "Failed parsing condition");
				return NULL;
			}

			/*
			 *	The condition failed to parse at EOL.
			 *	Therefore we try to read another line.
			 */
			if (!ptr[end]) {
				int rcode;

				memcpy(&stack->fill, &ptr, sizeof(ptr)); /* const issues */
				stack->fill += end;
				rcode = cf_file_fill(stack);
				if (rcode < 0) return NULL;
				continue;
			}

			/*
			 *	@todo - suppress leading spaces
			 */
		}
		break;
	}

	/*
	 *	We either read the whole line, OR there was a
	 *	different error parsing the condition.
	 */
	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, ptr);

		cf_log_err(cs, "Parse error in condition");
		cf_log_err(cs, "%s", text);
		cf_log_err(cs, "%s^ %s", spaces, error);

		talloc_free(spaces);
		talloc_free(text);
		talloc_free(cs);
		return NULL;
	}

	/*
	 *	The input file buffer may be larger
	 *	than the buffer we put the condition
	 *	into.
	 */
	if ((size_t) slen >= (stack->bufsize - 1)) {
		cf_log_err(cs, "Condition is too large after \"%s\"", buff[1]);
		talloc_free(cs);
		return NULL;
	}

	/*
	 *	Copy the expanded and parsed condition into buff[2].
	 *	Then suppress any trailing whitespace.
	 */
	memcpy(buff[2], ptr, slen);
	buff[2][slen] = '\0';
	p = buff[2] + slen - 1;
	while ((p > buff[2]) && isspace((int) *p)) {
		*p = '\0';
		p--;
	}

	MEM(cs->name2 = talloc_typed_strdup(cs, buff[2]));
	cs->name2_quote = T_BARE_WORD;

	ptr += slen;
	fr_skip_whitespace(ptr);

	if (*ptr != '{') {
		cf_log_err(cs, "Expected '{' instead of %s", ptr);
		talloc_free(cs);
		return NULL;
	}
	ptr++;

	/*
	 *	Now that the CONF_SECTION and condition are OK, add
	 *	the condition to the CONF_SECTION.
	 */
	cf_data_add(cs, cond, NULL, false);
	stack->ptr = ptr;
	return cs;
}

static CONF_SECTION *process_map(cf_stack_t *stack)
{
	char const *mod;
	char const *value = NULL;
	CONF_SECTION *css;
	FR_TOKEN token;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];

	/*
	 *	Short names are nicer.
	 */
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];

	if (invalid_location(frame->current, "map", frame->filename, frame->lineno)) {
		ERROR("%s[%d]: Invalid syntax for 'map'", frame->filename, frame->lineno);
		return NULL;
	}

	if (cf_get_token(parent, &ptr, &token, buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	if (token != T_BARE_WORD) {
		ERROR("%s[%d]: Invalid syntax for 'map' - module name must not be a quoted string",
		      frame->filename, frame->lineno);
		return NULL;
	}
	mod = buff[1];

	/*
	 *	Maps without an expansion string are allowed, tho I
	 *	don't know why.
	 */
	if (*ptr == '{') {
		ptr++;
		goto alloc_section;
	}

	/*
	 *	Now get the expansion string.
	 */
	if (cf_get_token(parent, &ptr, &token, buff[2], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}
	if (!fr_str_tok[token]) {
		ERROR("%s[%d]: Expecting string expansions in 'map' definition",
		      frame->filename, frame->lineno);
		return NULL;
	}

	if (*ptr != '{') {
		ERROR("%s[%d]: Expecting section start brace '{' in 'map' definition",
		      frame->filename, frame->lineno);
		return NULL;
	}
	ptr++;
	value = buff[2];

alloc_section:
	/*
	 *	Allocate the section
	 */
	css = cf_section_alloc(parent, parent, "map", mod);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}
	css->item.filename = frame->filename;
	css->item.lineno = frame->lineno;
	css->name2_quote = T_BARE_WORD;

	css->argc = 0;
	if (value) {
		css->argv = talloc_array(css, char const *, 1);
		css->argv[0] = talloc_typed_strdup(css->argv, value);
		css->argv_quote = talloc_array(css, FR_TOKEN, 1);
		css->argv_quote[0] = token;
		css->argc++;
	}
	stack->ptr = ptr;
	frame->special = css;

	return css;
}


static int add_pair(CONF_SECTION *parent, char const *attr, char const *value,
		    FR_TOKEN name1_token, FR_TOKEN op_token, FR_TOKEN value_token,
		    char *buff, char const *filename, int lineno)
{
	CONF_DATA const *cd;
	CONF_PARSER *rule;
	CONF_PAIR *cp;
	bool pass2 = false;

	/*
	 *	If we have the value, expand any configuration
	 *	variables in it.
	 */
	if (value && *value) {
		bool		soft_fail;
		char const	*expanded;

		expanded = cf_expand_variables(filename, lineno, parent, buff, talloc_array_length(buff), value, -1, &soft_fail);
		if (expanded) {
			value = expanded;

		} else if (!soft_fail) {
			return -1;

		} else {
			/*
			 *	References an item which doesn't exist,
			 *	or which is already marked up as being
			 *	expanded in pass2.  Wait for pass2 to
			 *	do the expansions.
			 *
			 *	Leave the input value alone.
			 */
			pass2 = true;
		}
	}

	cp = cf_pair_alloc(parent, attr, value, op_token, name1_token, value_token);
	if (!cp) return -1;
	cp->item.filename = filename;
	cp->item.lineno = lineno;
	cp->pass2 = pass2;
	cf_item_add(parent, &(cp->item));

	cd = cf_data_find(CF_TO_ITEM(parent), CONF_PARSER, attr);
	if (!cd) return 0;

	rule = cf_data_value(cd);
	if ((rule->type & FR_TYPE_ON_READ) == 0) {
		return 0;
	}

	return rule->func(parent, NULL, NULL, cf_pair_to_item(cp), rule);
}

static fr_table_ptr_sorted_t unlang_keywords[] = {
	{ "elsif",	(void *) process_if },
	{ "if",		(void *) process_if },
	{ "map",	(void *) process_map },
};
static int unlang_keywords_len = NUM_ELEMENTS(unlang_keywords);

typedef CONF_SECTION *(*cf_process_func_t)(cf_stack_t *);

static int parse_input(cf_stack_t *stack)
{
	FR_TOKEN	name1_token, name2_token, value_token, op_token;
	char const	*value;
	CONF_SECTION	*css;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];
	cf_process_func_t process;

	/*
	 *	Short names are nicer.
	 */
	buff[0] = stack->buff[0];
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];
	buff[3] = stack->buff[3];

	/*
	 *	Catch end of a subsection.
	 */
	if (*ptr == '}') {
		/*
		 *	We're already at the parent section
		 *	which loaded this file.  We cannot go
		 *	back up another level.
		 *
		 *	This limitation means that we cannot
		 *	put half of a CONF_SECTION in one
		 *	file, and then the second half in
		 *	another file.  That's fine.
		 */
		if (parent == frame->parent) {
			ERROR("%s[%d]: Too many closing braces", frame->filename, frame->lineno);
			return -1;
		}

		rad_assert(frame->braces > 0);
		frame->braces--;

		/*
		 *	Merge the template into the existing
		 *	section.  parent uses more memory, but
		 *	means that templates now work with
		 *	sub-sections, etc.
		 */
		if (!cf_template_merge(parent, parent->template)) return -1;

		if (parent == frame->special) frame->special = NULL;

		frame->current = parent = cf_item_to_section(parent->item.parent);
		ptr++;
		stack->ptr = ptr;
		return 1;
	}

	/*
	 *	Found nothing to get excited over.  It MUST be
	 *	a key word.
	 */
	if (cf_get_token(parent, &ptr, &name1_token, buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return -1;
	}

	/*
	 *	See which unlang keywords are allowed
	 */
	process = (cf_process_func_t) fr_table_value_by_str(unlang_keywords, buff[1], NULL);
	if (process) {
		stack->ptr = ptr;
		css = process(stack);
		ptr = stack->ptr;
		if (!css) return -1;
		goto add_section;
	}

	/*
	 *	parent single word is done.  Create a CONF_PAIR.
	 */
	if (!*ptr || (*ptr == '#') || (*ptr == ',') || (*ptr == ';') || (*ptr == '}')) {
		value_token = T_INVALID;
		op_token = T_OP_EQ;
		value = NULL;
		goto do_set;
	}

	/*
	 *	A common pattern is: name { ...}
	 *	Check for it and skip ahead.
	 */
	if (*ptr == '{') {
		ptr++;
		name2_token = T_INVALID;
		value = NULL;
		goto alloc_section;
	}

	/*
	 *	We allow certain kinds of strings, attribute
	 *	references (i.e. foreach) and bare names that
	 *	start with a letter.  We also allow UTF-8
	 *	characters.
	 *
	 *	Once we fix the parser to be less generic, we
	 *	can tighten these rules.  Right now, it's
	 *	*technically* possible to define a module with
	 *	&foo or "with spaces" as the second name.
	 *	Which seems bad.  But the old parser allowed
	 *	it, so oh well.
	 */
	if ((*ptr == '"') || (*ptr == '`') || (*ptr == '\'') || (*ptr == '&') ||
	    ((*((uint8_t const *) ptr) & 0x80) != 0) || isalpha((int) *ptr)) {
		if (cf_get_token(parent, &ptr, &name2_token, buff[2], stack->bufsize,
				 frame->filename, frame->lineno) < 0) {
			return -1;
		}

		if (*ptr != '{') {
			ERROR("%s[%d]: Parse error: expected '{', got text \"%s\"",
			      frame->filename, frame->lineno, ptr);
			return -1;
		}
		ptr++;
		value = buff[2];

	alloc_section:
		css = cf_section_alloc(parent, parent, buff[1], value);
		if (!css) {
			ERROR("%s[%d]: Failed allocating memory for section",
			      frame->filename, frame->lineno);
			return -1;
		}

		css->item.filename = frame->filename;
		css->item.lineno = frame->lineno;
		css->name2_quote = name2_token;

		/*
		 *	Hack for better error messages in
		 *	nested sections.  parent information
		 *	should really be put into a parser
		 *	struct, as with tmpls.
		 */
		if (!frame->special && ((strcmp(css->name1, "update") == 0) ||
					(strcmp(css->name1, "filter") == 0))) {
			frame->special = css;
		}

	add_section:
		cf_item_add(parent, &(css->item));

		/*
		 *	The current section is now the child section.
		 */
		frame->current = parent = css;
		frame->braces++;
		css = NULL;
		stack->ptr = ptr;
		return 1;
	}

	/*
	 *	The next thing MUST be an operator.  All
	 *	operators start with one of these characters,
	 *	so we check for them first.
	 */
	if (!((*ptr == '=') || (*ptr == '!') || (*ptr == '>') || (*ptr == '<') ||
	      (*ptr == '-') || (*ptr == '+') || (*ptr == ':'))) {
		ERROR("%s[%d]: Parse error at unexpected text: %s",
		      frame->filename, frame->lineno, ptr);
		return -1;
	}

	/*
	 *	If we're not parsing a section, then the next
	 *	token MUST be an operator.
	 */
	name2_token = gettoken(&ptr, buff[2], stack->bufsize, false);
	switch (name2_token) {
	case T_OP_ADD:
	case T_OP_SUB:
	case T_OP_NE:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
	case T_OP_CMP_EQ:
	case T_OP_CMP_FALSE:
		if (!parent || !frame->special) {
			ERROR("%s[%d]: Invalid operator in assignment",
			      frame->filename, frame->lineno);
			return -1;
		}
		/* FALL-THROUGH */

	case T_OP_EQ:
	case T_OP_SET:
		fr_skip_whitespace(ptr);
		op_token = name2_token;
		break;

	default:
		ERROR("%s[%d]: Parse error after \"%s\": unexpected token \"%s\"",
		      frame->filename, frame->lineno, buff[1], fr_table_str_by_value(fr_tokens_table, name2_token, "<INVALID>"));

		return -1;
	}

	/*
	 *	MUST have something after the operator.
	 */
	if (!*ptr || (*ptr == '#') || (*ptr == ',') || (*ptr == ';')) {
		ERROR("%s[%d]: Syntax error: Expected to see a value after the operator '%s': %s",
		      frame->filename, frame->lineno, buff[2], ptr);
		return -1;
	}

	/*
	 *	foo = { ... } for nested groups.
	 *
	 *	As a special case, we allow sub-sections after '=', etc.
	 *
	 *	This syntax is only for inside of "update"
	 *	sections, and for attributes of type "group".
	 *	But the parser isn't (yet) smart enough to
	 *	know about that context.  So we just silently
	 *	allow it everywhere.
	 */
	if (*ptr == '{') {
		if (!frame->special) {
			ERROR("%s[%d]: Parse error: Invalid location for grouped attribute",
			      frame->filename, frame->lineno);
			return -1;
		}

		if (*buff[1] != '&') {
			ERROR("%s[%d]: Parse error: Expected '&' before attribute name",
			      frame->filename, frame->lineno);
			return -1;
		}

		if (!fr_assignment_op[name2_token]) {
			ERROR("%s[%d]: Parse error: Invalid assignment operator '%s' for group",
			      frame->filename, frame->lineno, buff[2]);
			return -1;
		}

		/*
		 *	Now that we've peeked ahead to
		 *	see the open brace, parse it
		 *	for real.
		 */
		ptr++;

		/*
		 *	Leave name2_token as the
		 *	operator (as a hack).  But
		 *	note that there's no actual
		 *	name2.  We'll deal with that
		 *	situation later.
		 */
		value = NULL;
		goto alloc_section;
	}

	/*
	 *	Parse the value for a CONF_PAIR.
	 */
	if (cf_get_token(parent, &ptr, &value_token, buff[2], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return -1;
	}
	value = buff[2];

	/*
	 *	Add parent CONF_PAIR to our CONF_SECTION
	 */
do_set:
	if (add_pair(parent, buff[1], value, name1_token, op_token, value_token, buff[3], frame->filename, frame->lineno) < 0) return -1;

	fr_skip_whitespace(ptr);

	/*
	 *	Skip semicolon if we see it after a
	 *	CONF_PAIR.  Also allow comma for
	 *	backwards compatablity with secret
	 *	things in v3.
	 */
	if ((*ptr == ';') || (*ptr == ',')) {
		ptr++;
		stack->ptr = ptr;
		return 1;
	}

	/*
	 *	Closing brace is allowed after a CONF_PAIR
	 *	definition.
	 */
	if (*ptr == '}') {
		stack->ptr = ptr;
		return 1;
	}

	/*
	 *	Anything OTHER than EOL or comment is a syntax
	 *	error.
	 */
	if (*ptr && (*ptr != '#')) {
		ERROR("%s[%d]: Syntax error: Unexpected text: %s",
		      frame->filename, frame->lineno, ptr);
		return -1;
	}

	/*
	 *	Since we're at EOL or comment, just drop the
	 *	text, and go read another line of text.
	 */
	return 0;
}


static int frame_readdir(cf_stack_t *stack)
{
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	struct dirent	*dp;
	struct stat stat_buf;
	CONF_SECTION *parent = frame->current;

	while ((dp = readdir(frame->dir)) != NULL) {
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

		snprintf(stack->buff[1], stack->bufsize, "%s%s",
			 frame->directory, dp->d_name);

		if (stat(stack->buff[1], &stat_buf) != 0) {
			ERROR("%s[%d]: Failed checking file %s: %s",
			      (frame - 1)->filename, (frame - 1)->lineno,
			      stack->buff[1], fr_syserror(errno));
			continue;
		}

		if (S_ISDIR(stat_buf.st_mode)) {
			WARN("%s[%d]: Ignoring directory %s",
			     (frame - 1)->filename, (frame - 1)->lineno,
			     stack->buff[1]);
			continue;
		}

		/*
		 *	Push the next filename onto the stack.
		 */
		stack->depth++;
		frame = &stack->frame[stack->depth];
		memset(frame, 0, sizeof(*frame));
		frame->fp = NULL;
		frame->parent = parent;
		frame->current = parent;
		frame->filename = talloc_strdup(frame->parent, stack->buff[1]);
		frame->lineno = 0;
		frame->from_dir = true;
		frame->special = NULL; /* can't do includes inside of update / map */
		return 1;
	}

	/*
	 *	Done reading the directory entry.  Close it, and go
	 *	back up a stack frame.
	 */
	closedir(frame->dir);
	frame->dir = NULL;
	talloc_free(frame->directory);
	stack->depth--;
	return 1;
}


static int cf_file_fill(cf_stack_t *stack)
{
	bool at_eof, has_spaces;
	size_t len;
	char const *ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];

read_more:
	has_spaces = false;

read_continuation:
	/*
	 *	Get data, and remember if we are at EOF.
	 */
	at_eof = (fgets(stack->fill, stack->bufsize - (stack->fill - stack->buff[0]), frame->fp) == NULL);
	frame->lineno++;

	/*
	 *	We read the entire 8k worth of data: complain.
	 *	Note that we don't care if the last character
	 *	is \n: it's still forbidden.  This means that
	 *	the maximum allowed length of text is 8k-1, which
	 *	should be plenty.
	 */
	len = strlen(stack->fill);
	if ((stack->fill + len + 1) >= (stack->buff[0] + stack->bufsize)) {
		ERROR("%s[%d]: Line too long", frame->filename, frame->lineno);
		return -1;
	}

	/*
	 *	Suppress leading whitespace after a
	 *	continuation line.
	 */
	if (has_spaces) {
		ptr = stack->fill;
		fr_skip_whitespace(ptr);

		if (ptr > stack->fill) {
			memmove(stack->fill, ptr, len - (ptr - stack->fill));
			len -= (ptr - stack->fill);
		}
	}

	/*
	 *	Skip blank lines when we're at the start of
	 *	the read buffer.
	 */
	if (stack->fill == stack->buff[0]) {
		if (at_eof) return 0;

		ptr = stack->buff[0];
		fr_skip_whitespace(ptr);

		if (!*ptr || (*ptr == '#')) goto read_more;

	} else if (at_eof || (len == 0)) {
		ERROR("%s[%d]: Continuation at EOF is illegal", frame->filename, frame->lineno);
		return -1;
	}

	/*
	 *	See if there's a continuation.
	 */
	while ((len > 0) &&
	       ((stack->fill[len - 1] == '\n') || (stack->fill[len - 1] == '\r'))) {
		len--;
		stack->fill[len] = '\0';
	}

	if ((len > 0) && (stack->fill[len - 1] == '\\')) {
		/*
		 *	Check for "suppress spaces" magic.
		 */
		if (!has_spaces && (len > 2) && (stack->fill[len - 2] == '"')) {
			has_spaces = true;
		}

		stack->fill[len - 1] = '\0';
		stack->fill += len - 1;
		goto read_continuation;
	}

	ptr = stack->fill;

	/*
	 *	We now have one full line of text in the input
	 *	buffer, without continuations.
	 */
	fr_skip_whitespace(ptr);

	/*
	 *	Nothing left, or just a comment.  Go read
	 *	another line of text.
	 */
	if (!*ptr || (*ptr == '#')) goto read_more;

	return 1;
}


/*
 *	Read a configuration file or files.
 */
static int cf_file_include(cf_stack_t *stack)
{
	CONF_SECTION	*parent;
	char const	*ptr;

	char		*buff[4];
	cf_stack_frame_t	*frame;
	int		rcode;

	/*
	 *	Short names are nicer.
	 */
	buff[0] = stack->buff[0];
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];
	buff[3] = stack->buff[3];

do_frame:
	frame = &stack->frame[stack->depth];
	parent = frame->current; /* add items here */

	/*
	 *	First try reading from the frame as a directory.  If
	 *	so, we push a filename onto the stack and then load
	 *	the filename.
	 */
	if (frame->dir) {
		rcode = frame_readdir(stack);
		if (rcode == 0) goto do_frame;
		if (rcode < 0) return -1;

		/*
		 *	Reset which frame we're looking at.
		 */
		frame = &stack->frame[stack->depth];
	}

	/*
	 *	Open the new file.  It either came from the first call
	 *	to the function, or was pushed onto the stack by
	 *	frame_readdir().
	 */
	if (!frame->fp) {
		rcode = cf_file_open(frame->parent, frame->filename, frame->from_dir, &frame->fp);
		if (rcode < 0) return -1;

		/*
		 *	Ignore this file
		 */
		if (rcode == 1) {
			cf_log_warn(frame->current, "Ignoring file %s - it was already read",
				    frame->filename);
			goto pop_stack;
		}
	}

	/*
	 *	Read, checking for line continuations ('\\' at EOL)
	 */
	for (;;) {
		/*
		 *	Fill the buffers with data.
		 */
		stack->fill = stack->buff[0];
		rcode = cf_file_fill(stack);
		if (rcode < 0) return -1;
		if (rcode == 0) break;

		/*
		 *	The text here MUST be at the start of a line,
		 *	OR have only whitespace in front of it.
		 */
		ptr = stack->buff[0];
		fr_skip_whitespace(ptr);

		if (*ptr == '$') {
			/*
			 *	Allow for $INCLUDE files
			 */
			if (strncasecmp(ptr, "$INCLUDE", 8) == 0) {
				ptr += 8;

				if (process_include(stack, parent, ptr, true) < 0) return -1;
				goto do_frame;
			}

			if (strncasecmp(ptr, "$-INCLUDE", 9) == 0) {
				ptr += 9;

				rcode = process_include(stack, parent, ptr, false);
				if (rcode < 0) return -1;
				if (rcode == 0) continue;
				goto do_frame;
			}

			/*
			 *	Allow for $TEMPLATE things
			 */
			if (strncasecmp(buff[1], "$TEMPLATE", 9) == 0) {
				ptr += 9;
				fr_skip_whitespace(ptr);

				stack->ptr = ptr;
				if (process_template(stack) < 0) return -1;
				continue;
			}

			ERROR("%s[%d]: Invalid text starting with '$'", frame->filename, frame->lineno);
			return -1;
		}

		/*
		 *	All of the file handling code is done.  Parse the input.
		 */		
		do {
			fr_skip_whitespace(ptr);
			if (!*ptr || (*ptr == '#')) break;

			stack->ptr = ptr;
			rcode = parse_input(stack);
			ptr = stack->ptr;

			if (rcode < 0) return -1;
			parent = frame->current;
		} while (rcode == 1);
	}

	rad_assert(frame->fp != NULL);

	/*
	 *	See if EOF was unexpected.
	 */
	if (feof(frame->fp) && (parent != frame->parent)) {
		ERROR("%s[%d]: EOF reached without closing brace for section %s starting at line %d",
		      frame->filename, frame->lineno, cf_section_name1(parent), cf_lineno(parent));
		return -1;
	}

	fclose(frame->fp);
	frame->fp = NULL;

pop_stack:
	/*
	 *	More things to read, go read them.
	 */
	if (stack->depth > 0) {
		stack->depth--;
		goto do_frame;
	}

	return 0;
}

static void cf_stack_cleanup(cf_stack_t *stack)
{
	cf_stack_frame_t *frame = &stack->frame[stack->depth];

	while (stack->depth >= 0) {
		if (frame->fp) {
			fclose(frame->fp);
			frame->fp = NULL;
		}
		if (frame->dir) {
			closedir(frame->dir);
			frame->dir = NULL;
			talloc_free(frame->directory);
		}

		frame--;
		stack->depth--;
	}

	talloc_free(stack->buff);
}

/*
 *	Bootstrap a config file.
 */
int cf_file_read(CONF_SECTION *cs, char const *filename)
{
	int		i;
	char		*p;
	CONF_PAIR	*cp;
	rbtree_t	*tree;
	cf_stack_t	stack;
	cf_stack_frame_t	*frame;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	if (!cp) return -1;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cf_item_add(cs, &(cp->item));

	MEM(tree = rbtree_talloc_create(cs, _filename_cmp, cf_file_t, NULL, 0));

	cf_data_add(cs, tree, "filename", false);

#ifndef NDEBUG
	memset(&stack, 0, sizeof(stack));
#endif

	/*
	 *	Allocate temporary buffers on the heap (so we don't use *all* the stack space)
	 */
	stack.buff = talloc_array(cs, char *, 4);
	for (i = 0; i < 4; i++) MEM(stack.buff[i] = talloc_array(stack.buff, char, 8192));

	stack.depth = 0;
	stack.bufsize = 8192;
	frame = &stack.frame[stack.depth];

	memset(frame, 0, sizeof(*frame));
	frame->parent = frame->current = cs;
	frame->filename = talloc_strdup(frame->parent, filename);
	cs->item.filename = frame->filename;

	if (cf_file_include(&stack) < 0) {
		cf_stack_cleanup(&stack);
		return -1;
	}

	talloc_free(stack.buff);

	/*
	 *	Now that we've read the file, go back through it and
	 *	expand the variables.
	 */
	if (cf_section_pass2(cs) < 0) {
		cf_log_err(cs, "Parsing config items failed");
		return -1;
	}

	return 0;
}

void cf_file_free(CONF_SECTION *cs)
{
	talloc_free(cs);
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

/*
 *	See if any of the files have changed.
 */
int cf_file_changed(CONF_SECTION *cs, rb_walker_t callback)
{
	CONF_SECTION		*top;
	cf_file_callback_t	cb;
	rbtree_t		*tree;

	top = cf_root(cs);
	tree = cf_data_value(cf_data_find(top, rbtree_t, "filename"));
	if (!tree) return true;

	cb.rcode = CF_FILE_NONE;
	cb.callback = callback;
	cb.modules = cf_section_find(cs, "modules", NULL);

	(void) rbtree_walk(tree, RBTREE_IN_ORDER, _file_callback, &cb);

	return cb.rcode;
}


static char const parse_tabs[] = "																																																																																																																																																																																																								";

static ssize_t cf_string_write(FILE *fp, char const *string, size_t len, FR_TOKEN t)
{
	size_t	outlen;
	char	c;
	char	buffer[2048];

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

static int cf_pair_write(FILE *fp, CONF_PAIR *cp)
{
	if (!cp->value) {
		fprintf(fp, "%s\n", cp->attr);
		return 0;
	}

	cf_string_write(fp, cp->attr, strlen(cp->attr), cp->lhs_quote);
	fprintf(fp, " %s ", fr_table_str_by_value(fr_tokens_table, cp->op, "<INVALID>"));
	cf_string_write(fp, cp->value, strlen(cp->value), cp->rhs_quote);
	fprintf(fp, "\n");

	return 1;		/* FIXME */
}


int cf_section_write(FILE *fp, CONF_SECTION *cs, int depth)
{
	CONF_ITEM	*ci;

	if (!fp || !cs) return -1;

	/*
	 *	Print the section name1, etc.
	 */
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

		c = cf_data_value(cf_data_find(cs, fr_cond_t, NULL));
		if (c) {
			char buffer[1024];

			cond_snprint(NULL, buffer, sizeof(buffer), c);
			fprintf(fp, "(%s)", buffer);

		} else {	/* dump the string as-is */
			cf_string_write(fp, cs->name2, strlen(cs->name2), cs->name2_quote);
		}
	}

	fputs(" {\n", fp);

	/*
	 *	Loop over the children.  Either recursing, or opening
	 *	a new file.
	 */
	for (ci = cs->item.child; ci; ci = ci->next) {
		switch (ci->type) {
		case CONF_ITEM_SECTION:
			cf_section_write(fp, cf_item_to_section(ci), depth + 1);
			break;

		case CONF_ITEM_PAIR:
			/*
			 *	Ignore internal things.
			 */
			if (!ci->filename || (ci->filename[0] == '<')) break;

			fwrite(parse_tabs, depth + 1, 1, fp);
			cf_pair_write(fp, cf_item_to_pair(ci));
			break;

		default:
			break;
		}
	}

	fwrite(parse_tabs, depth, 1, fp);
	fputs("}\n\n", fp);

	return 1;
}


CONF_ITEM *cf_reference_item(CONF_SECTION const *parent_cs,
			     CONF_SECTION const *outer_cs,
			     char const *ptr)
{
	CONF_PAIR		*cp;
	CONF_SECTION		*next;
	CONF_SECTION const	*cs = outer_cs;
	char			name[8192];
	char			*p;

	if (!ptr || (!parent_cs && !outer_cs)) return NULL;

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
		if (*p == '\0') return cf_section_to_item(cs);

		/*
		 *	..foo means "foo from the section
		 *	enclosing this section" (etc.)
		 */
		while (*p == '.') {
			if (cs->item.parent) cs = cf_item_to_section(cs->item.parent);

			/*
			 *	.. means the section
			 *	enclosing this section
			 */
			if (!*++p) return cf_section_to_item(cs);
		}

		/*
		 *	"foo.bar.baz" means "from the root"
		 */
	} else if (strchr(p, '.') != NULL) {
		if (!parent_cs) return NULL;
		cs = parent_cs;
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
			if (q[1] && q[1] != '.') return NULL;

			*r = '\0';
			*q = '\0';
			next = cf_section_find(cs, p, r + 1);
			*r = '[';
			*q = ']';

			/*
			 *	Points to a named instance of a section.
			 */
			if (!q[1]) {
				if (!next) return NULL;
				return &(next->item);
			}

			q++;	/* ensure we skip the ']' and '.' */

		} else {
			*q = '\0';
			next = cf_section_find(cs, p, NULL);
			*q = '.';
		}

		if (!next) break; /* it MAY be a pair in this section! */

		cs = next;
		p = q + 1;
	}

	if (!*p) return NULL;

retry:
	/*
	 *	Find it in the current referenced
	 *	section.
	 */
	cp = cf_pair_find(cs, p);
	if (cp) {
		cp->referenced = true;	/* conf pairs which are referenced count as used */
		return &(cp->item);
	}

	next = cf_section_find(cs, p, NULL);
	if (next) return &(next->item);

	/*
	 *	"foo" is "in the current section, OR in main".
	 */
	if ((p == name) && (parent_cs != NULL) && (cs != parent_cs)) {
		cs = parent_cs;
		goto retry;
	}

	return NULL;
}
