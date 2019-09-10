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

/*
 *	buff[0] is the data we read from the file
 *	buff[1] is name
 *	buff[2] is name2 OR value for pair
 *	buff[3] is a temporary buffer
 */
static int cf_file_include(CONF_SECTION *cs, char const *filename_in, CONF_INCLUDE_TYPE file_type,
			   char *buff[static 4], bool from_dir);

/*
 *	Expand the variables in an input string.
 *
 *	Input and output should be two different buffers, as the
 *	output may be longer than the input.
 */
char const *cf_expand_variables(char const *cf, int *lineno,
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
				     cf, *lineno, input);
				return NULL;
			}

			ptr += 2;

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (next - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Reference string is too large",
				      cf, *lineno);
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
				ERROR("%s[%d]: Reference \"${%s}\" not found", cf, *lineno, name);
				return NULL;
			}

			/*
			 *	The expansion doesn't refer to another item or section
			 *	it's the property of a section.
			 */
			if (q) {
				CONF_SECTION *find = cf_item_to_section(ci);

				if (ci->type != CONF_ITEM_SECTION) {
					ERROR("%s[%d]: Can only reference properties of sections", cf, *lineno);
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
					ERROR("%s[%d]: Invalid property '%s'", cf, *lineno, q);
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
				ptr = next + 1;

			} else if (ci->type == CONF_ITEM_SECTION) {
				CONF_SECTION *subcs;

				/*
				 *	Adding an entry again to a
				 *	section is wrong.  We don't
				 *	want an infinite loop.
				 */
				if (cf_item_to_section(ci->parent) == outer_cs) {
					ERROR("%s[%d]: Cannot reference different item in same section", cf, *lineno);
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
					ERROR("%s[%d]: Failed copying reference %s", cf, *lineno, name);
					return NULL;
				}

				subcs->item.filename = ci->filename;
				subcs->item.lineno = ci->lineno;
				cf_item_add(outer_cs, &(subcs->item));

				ptr = next + 1;

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
			next = strchr(ptr, '}');
			if (next == NULL) {
				*p = '\0';
				INFO("%s[%d]: Environment variable expansion missing }",
				     cf, *lineno);
				return NULL;
			}

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) (next - ptr) >= sizeof(name)) {
				ERROR("%s[%d]: Environment variable name is too large",
				      cf, *lineno);
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
				      cf, *lineno, input);
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
			      cf, *lineno, input);
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
		if (file) return 0;
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

		value = cf_expand_variables(ci->filename, &ci->lineno, cs, buffer, sizeof(buffer), cp->value, -1, NULL);
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


/*
 *	Like gettoken(), but uses the new API which seems better for a
 *	host of reasons.
 */
static int cf_get_token(CONF_SECTION *this, char const **ptr_p, FR_TOKEN *token, char *buffer, size_t buflen,
			char *buff2, char const *filename, int *lineno)
{
	char quote;
	char const *ptr = *ptr_p;
	ssize_t slen;
	char const *error;
	char const *out;
	size_t outlen;

	quote = *ptr;

	/*
	 *	Discover the string content, returning what kind of
	 *	string it is.
	 *
	 *	Don't allow casts or refgexes.  But do allow bar
	 *	%{...} expansions.
	 */
	slen = tmpl_preparse(&out, &outlen, ptr, token, &error, NULL, false, true);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(this, &spaces, &text, slen, ptr);

		ERROR("%s[%d]: %s", filename, *lineno, text);
		ERROR("%s[%d]: %s^ - %s", filename, *lineno, spaces, error);

		talloc_free(spaces);
		talloc_free(text);
		return -1;
	}

	if ((size_t) slen >= buflen) {
		ERROR("%s[%d]: Name is too long", filename, *lineno);
		return -1;
	}

	/*
	 *	Manually unescape things.
	 *
	 *	Note that a bare %{...} counts as a
	 *	double quoted string, even if it isn't
	 *	enclosed in double quotes.
	 */
	if (*token == T_DOUBLE_QUOTED_STRING) quote = '"';

	/*
	 *	Unescape it or copy it verbatim as necessary.
	 */
	if ((quote == '`') || (quote == '\'') || (quote == '"')) {
		outlen = fr_value_str_unescape((uint8_t *) buff2, out, outlen, quote);
		buffer[outlen] = '\0';

		if (!cf_expand_variables(filename, lineno, this, buffer, buflen,
					 buff2, outlen, NULL)) {
			return -1;
		}

	} else if ((out[0] == '$') && (out[1] == '{')) {
		if (!cf_expand_variables(filename, lineno, this, buffer, buflen,
					 out, outlen, NULL)) {
			return -1;
		}


	} else {
		memcpy(buffer, out, outlen);
		buffer[outlen] = '\0';
	}

	ptr += slen;
	fr_skip_whitespace(ptr);

	*ptr_p = ptr;
	return 0;
}


static int process_include(CONF_SECTION *this, char const *ptr, char *buff[static 4], char const *filename, int *lineno, bool required)
{
	bool relative = true;
	char const *value;

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
		ERROR("%s[%d]: Unexpected text after $INCLUDE", filename, *lineno);
		return -1;
	}

	/*
	 *	Hack for ${confdir}/foo
	 */
	if (*value == '$') relative = false;

	value = cf_expand_variables(filename, lineno, this, buff[1], talloc_array_length(buff[1]),
				    value, ptr - value, NULL);
	if (!value) return -1;

	if (!FR_DIR_IS_RELATIVE(value)) relative = false;

	if (relative) {
		value = cf_local_file(filename, value, buff[2], talloc_array_length(buff[2]));
		if (!value) {
			ERROR("%s[%d]: Directories too deep", filename, *lineno);
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
		return cf_file_include(this, value, CONF_INCLUDE_FILE, buff, false);
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
		struct dirent	*dp;
		struct stat stat_buf;
		char *my_directory;
		int rcode = -1;

		/*
		 *	We need to keep a copy of this while the
		 *	included files mangle our buff[] array.
		 */
		my_directory = talloc_strdup(this, value);

		cf_log_debug(this, "Including files in directory \"%s\"", my_directory);

#ifdef S_IWOTH
		/*
		 *	Security checks.
		 */
		if (stat(my_directory, &stat_buf) < 0) {
			ERROR("%s[%d]: Failed reading directory %s: %s", filename, *lineno,
			      my_directory, fr_syserror(errno));
			goto done;
		}

		if ((stat_buf.st_mode & S_IWOTH) != 0) {
			ERROR("%s[%d]: Directory %s is globally writable.  Refusing to start due to "
			      "insecure configuration", filename, *lineno, my_directory);
			goto done;
		}
#endif
		dir = opendir(my_directory);
		if (!dir) {
			ERROR("%s[%d]: Error reading directory %s: %s",
			      filename, *lineno, value,
			      fr_syserror(errno));
			goto done;
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


			snprintf(buff[1], talloc_array_length(buff[1]), "%s%s",
				 my_directory, dp->d_name);
			if ((stat(buff[1], &stat_buf) != 0) ||
			    S_ISDIR(stat_buf.st_mode)) continue;

			/*
			 *	Read the file into the current
			 *	configuration section.
			 */
			if (cf_file_include(this, buff[1], CONF_INCLUDE_FROMDIR, buff, true) < 0) {
				closedir(dir);
				goto done;
			}
		}
		rcode = 0;
		closedir(dir);

done:
		talloc_free(my_directory);
		return rcode;
	}
#else
	ERROR("%s[%d]: Error including %s: No support for directories!",
	      filename, *lineno, value);
	return -1;
#endif
}


static int process_template(CONF_SECTION *this, char const *ptr, char *buff[static 4], char const *filename, int *lineno)
{
	CONF_ITEM *ci;
	CONF_SECTION *parent_cs, *templatecs;
	FR_TOKEN token;

	token = getword(&ptr, buff[2], talloc_array_length(buff[2]), true);
	if (token != T_EOL) {
		ERROR("%s[%d]: Unexpected text after $TEMPLATE", filename, *lineno);
		return -1;
	}

	parent_cs = cf_root(this);

	templatecs = cf_section_find(parent_cs, "templates", NULL);
	if (!templatecs) {
		ERROR("%s[%d]: No \"templates\" section for reference \"%s\"", filename, *lineno, buff[2]);
		return -1;
	}

	ci = cf_reference_item(parent_cs, templatecs, buff[2]);
	if (!ci || (ci->type != CONF_ITEM_SECTION)) {
		ERROR("%s[%d]: Reference \"%s\" not found", filename, *lineno, buff[2]);
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
	return 0;
}


static CONF_SECTION *process_if(CONF_SECTION *this, char const **ptr_p, char *buff[static 4], char const *filename, int *lineno)
{
	ssize_t slen = 0;
	char const *error = NULL;
	fr_cond_t *cond = NULL;
	CONF_DATA const *cd;
	fr_dict_t const *dict = NULL;
	CONF_SECTION *css;
	char const *ptr = *ptr_p;

	/*
	 *	if / elsif
	 */
	if (invalid_location(this, buff[1], filename, *lineno)) return NULL;

	cd = cf_data_find_in_parent(this, fr_dict_t **, "dictionary");
	if (cd) dict = *((fr_dict_t **)cf_data_value(cd));

	/*
	 *	Skip (...) to find the {
	 */
	slen = fr_cond_tokenize(this, &cond, &error, dict,
				this, ptr, filename, *lineno);
	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(this, &spaces, &text, slen, ptr);

		ERROR("%s[%d]: Parse error in condition",
		      filename, *lineno);
		ERROR("%s[%d]: %s", filename, *lineno, text);
		ERROR("%s[%d]: %s^ %s", filename, *lineno, spaces, error);

		talloc_free(spaces);
		talloc_free(text);
		talloc_free(cond);
		return NULL;
	}

	/*
	 *	The input file buffer may be larger
	 *	than the buffer we put the condition
	 *	into.
	 */
	if ((size_t) slen >= (talloc_array_length(buff[2]) - 1)) {
		talloc_free(cond);
		ERROR("%s[%d]: Condition is too large after \"%s\"", filename, *lineno, buff[1]);
		return NULL;
	}

	/*
	 *	Copy the expanded and parsed condition
	 *	into buff[2].  Then, parse the text after
	 *	the condition, which now MUST be a '{.
	 */
	memcpy(buff[2], ptr, slen);
	buff[2][slen] = '\0';
	ptr += slen;

	fr_skip_whitespace(ptr);

	if (*ptr != '{') {
		ERROR("%s[%d]: Expected '{' instead of %s", filename, *lineno, ptr);
		talloc_free(cond);
		return NULL;
	}
	ptr++;

	css = cf_section_alloc(this, this, buff[1], buff[2]);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section", filename, *lineno);
		talloc_free(cond);
		return NULL;
	}
	css->item.filename = filename;
	css->item.lineno = *lineno;

	cf_data_add(css, cond, NULL, false);
	*ptr_p = ptr;
	return css;
}

static CONF_SECTION *process_map(CONF_SECTION *this, char const **ptr_p, char *buff[static 4], char const *filename, int *lineno)
{
	char const *mod;
	char const *exp = NULL;
	char const *ptr = *ptr_p;
	CONF_SECTION *css;
	FR_TOKEN token;

	if (invalid_location(this, "map", filename, *lineno)) {
		ERROR("%s[%d]: Invalid syntax for 'map'", filename, *lineno);
		return NULL;
	}

	/*
	 *	@fixme: call cf_get_token() which does all of this
	 */
	token = gettoken(&ptr, buff[2], talloc_array_length(buff[2]), false);
	if (token != T_BARE_WORD) {
		ERROR("%s[%d]: Expected module name after 'map'", filename, *lineno);
		return NULL;
	}

	/*
	 *	Allow module names to be expanded at load time.
	 */
	mod = cf_expand_variables(filename, lineno,
				  this,
				  buff[1], talloc_array_length(buff[1]),
				  buff[2], -1, NULL);
	if (!mod) {
		ERROR("%s[%d]: Failed expanding ${...} in map module name",
		      filename, *lineno);
		return NULL;
	}

	/*
	 *	Maps without an expansion string are allowed, tho I
	 *	don't know why.
	 */
	fr_skip_whitespace(ptr);
	if (*ptr == '{') {
		ptr++;
		goto alloc_section;
	}

	/*
	 *	Parse the map expansion, which now SHOULD be a string.
	 */
	token = gettoken(&ptr, buff[3], talloc_array_length(buff[3]), false);
	if (!fr_str_tok[token]) {
		ERROR("%s[%d]: Expecting string expansions in 'map' definition",
		      filename, *lineno);
		return NULL;
	}

	fr_skip_whitespace(ptr);
	if (*ptr != '{') {
		ERROR("%s[%d]: Expecting section start brace '{' in 'map' definition",
		      filename, *lineno);
		return NULL;
	}
	ptr++;

	exp = cf_expand_variables(filename, lineno,
				  this,
				  buff[2], talloc_array_length(buff[2]),
				  buff[3], -1, NULL);
	if (!exp) {
		ERROR("%s[%d]: Failed expanding ${...} in map expansion string",
		      filename, *lineno);
		return NULL;
	}

alloc_section:
	/*
	 *	Allocate the section
	 */
	css = cf_section_alloc(this, this, "map", mod);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section", filename, *lineno);
		return NULL;
	}
	css->item.filename = filename;
	css->item.lineno = *lineno;
	css->name2_quote = T_BARE_WORD;

	css->argc = 0;
	if (exp) {
		css->argv = talloc_array(css, char const *, 1);
		css->argv[0] = talloc_typed_strdup(css->argv, exp);
		css->argv_quote = talloc_array(css, FR_TOKEN, 1);
		css->argv_quote[0] = token;
		css->argc++;
	}
	*ptr_p = ptr;

	return css;
}


static int add_pair(CONF_SECTION *this, char const *attr, char const *value,
		    FR_TOKEN name1_token, FR_TOKEN op_token, FR_TOKEN value_token,
		    char *buff[static 4], char const *filename, int *lineno)
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

		expanded = cf_expand_variables(filename, lineno, this, buff[3], talloc_array_length(buff[3]), value, -1, &soft_fail);
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

	cp = cf_pair_alloc(this, attr, value, op_token, name1_token, value_token);
	if (!cp) return -1;
	cp->item.filename = filename;
	cp->item.lineno = *lineno;
	cp->pass2 = pass2;
	cf_item_add(this, &(cp->item));

	cd = cf_data_find(CF_TO_ITEM(this), CONF_PARSER, attr);
	if (!cd) return 0;

	rule = cf_data_value(cd);
	if ((rule->type & FR_TYPE_ON_READ) == 0) {
		return 0;
	}

	return rule->func(this, NULL, NULL, cf_pair_to_item(cp), rule);
}


/*
 *	Read a part of the config file.
 */
static int cf_section_read(char const *filename, int *lineno, FILE *fp,
			   CONF_SECTION *current, char *buff[static 4])

{
	CONF_SECTION	*this, *css;
	char const	*ptr;
	char const	*value;

	FR_TOKEN	name1_token = T_INVALID, name2_token, value_token, op_token;
	bool		has_spaces = false;
	bool		in_update = false;
	bool		in_map = false;
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

		/*
		 *	Suppress leading whitespace after a
		 *	continuation line.
		 */
		if (has_spaces) {
			ptr = cbuff;
			fr_skip_whitespace(ptr);

			if (ptr > cbuff) {
				memmove(cbuff, ptr, len - (ptr - cbuff));
				len -= (ptr - cbuff);
			}
		}

		/*
		 *	Skip blank lines when we're at the start of
		 *	the read buffer.
		 */
		if (cbuff == buff[0]) {
			if (at_eof) break;

			ptr = buff[0];
			fr_skip_whitespace(ptr);

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

		/*
		 *	We now have one full line of text in the input
		 *	buffer, without continuations.
		 */

	parse_line:
		fr_skip_whitespace(ptr);

		/*
		 *	The caller eats "name1 name2 {", and calls us
		 *	for the data inside of the section.  So if we
		 *	receive a closing brace, then it must mean the
		 *	end of the section.
		 */
		if (*ptr == '}') {
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
			ptr++;
			goto check_for_more;
		}

		/*
		 *	Allow for $INCLUDE files
		 */
		if (strncasecmp(ptr, "$INCLUDE", 8) == 0) {
			ptr += 8;

			if (process_include(this, ptr, buff, filename, lineno, true) < 0) goto error;
			continue;
		}

		if (strncasecmp(ptr, "$-INCLUDE", 9) == 0) {
			ptr += 9;

			if (process_include(this, ptr, buff, filename, lineno, false) < 0) goto error;
			continue;
		}

		/*
		 *	Allow for $TEMPLATE things
		 */
		if (strncasecmp(buff[1], "$TEMPLATE", 9) == 0) {
			ptr += 9;
			fr_skip_whitespace(ptr);

			if (process_template(this, ptr, buff, filename, lineno) < 0) goto error;
			continue;
		}

		/*
		 *	Found nothing to get excited over.  It MUST be
		 *	a key word.
		 */
		if (cf_get_token(this, &ptr, &name1_token, buff[1], talloc_array_length(buff[1]),
				 buff[2], filename, lineno) < 0) {
			goto error;
		}

		/*
		 *	This single word is done.  Create a CONF_PAIR.
		 */
		if (!*ptr || (*ptr == '#') || (*ptr == ',') || (*ptr == ';') || (*ptr == '}')) {
			value_token = T_INVALID;
			op_token = T_OP_EQ;
			value = NULL;
			goto do_set;
		}

		/*
		 *	Handle if/elsif specially.  This function will
		 *	update "ptr" to be the next thing that we
		 *	need.
		 */
		if ((strcmp(buff[1], "if") == 0) || (strcmp(buff[1], "elsif") == 0)) {
			css = process_if(this, &ptr, buff, filename, lineno);
			if (!css) goto error;
			goto add_section;
		}

		/*
		 *	"map" sections have three arguments!
		 *
		 *	map NAME ARGUMENT { ... }
		 */
		if ((strcmp(buff[1], "map") == 0) && (*ptr != '{')) {
			css = process_map(this, &ptr, buff, filename, lineno);
			if (!css) goto error;

			in_map = true;
			goto add_section;
		}

		/*
		 *	A common pattern is: name { ...}
		 *	Check for it and skip ahead.
		 */
		if (*ptr == '{') {
			ptr++;
			name2_token = T_LCBRACE;
			goto alloc_section;
		}

		/*
		 *	The next token could be one of many things.
		 */
		name2_token = gettoken(&ptr, buff[2], talloc_array_length(buff[2]), false);
		switch (name2_token) {
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
			if (!this || (!in_update && !in_map)) {
				ERROR("%s[%d]: Invalid operator in assignment",
				      filename, *lineno);
				goto error;
			}
			/* FALL-THROUGH */

		case T_OP_EQ:
		case T_OP_SET:
			fr_skip_whitespace(ptr);
			op_token = name2_token;

			/*
			 *	Non-quoted strings are bare words, and
			 *	we parse everything until the next
			 *	newline, or the next comma.  If they
			 *	have { or } in a bare word,
			 *	well... too bad.
			 */
			switch (*ptr) {
			case '#':
			case '\0':
				ERROR("%s[%d]: Syntax error: Expected to see a value after the operator '%s': %s",
				      filename, *lineno, buff[2], ptr);
				goto error;

			case '"':
			case '\'':
			case '`':
			case '/':
				value_token = getstring(&ptr, buff[2], talloc_array_length(buff[2]), false);
				break;

				/*
				 *	As a special case, we allow sub-sections after '=', etc.
				 *
				 *	This syntax is only for inside
				 *	of "update" sections, and for
				 *	attributes of type "group".
				 *	But the parser isn't (yet)
				 *	smart enough to know about
				 *	that context.  So we just
				 *	silently allow it everywhere.
				 */
			case '{':
				if (!in_update) {
					ERROR("%s[%d]: Parse error: Invalid location for grouped attribute",
					      filename, *lineno);
					goto error;
				}

				if (!fr_assignment_op[name2_token]) {
					ERROR("%s[%d]: Parse error: Invalid assignment operator '%s' for group",
					      filename, *lineno, buff[2]);
					goto error;
				}

				/*
				 *	Now that we've peeked ahead to
				 *	see the open brace, parse it
				 *	for real.
				 */
				ptr++;
				goto alloc_section;

			default:
			{
				const char *q = ptr;

				while (*q && (*q >= ' ') && (*q != ',') &&
				       !isspace(*q)) q++;

				if ((size_t) (q - ptr) >= talloc_array_length(buff[2])) {
					ERROR("%s[%d]: Parse error: value too long", filename, *lineno);
					goto error;
				}

				memcpy(buff[2], ptr, (q - ptr));
				buff[2][q - ptr] = '\0';
				ptr = q;

				value_token = T_BARE_WORD;
			}
			}
			value = buff[2];

			/*
			 *	Add this CONF_PAIR to our CONF_SECTION
			 */
		do_set:
			if (add_pair(this, buff[1], value, name1_token, op_token, value_token, buff, filename, lineno) < 0) goto error;

			fr_skip_whitespace(ptr);

			/*
			 *	Skip semicolon if we see it after a
			 *	CONF_PAIR.  Also allow comma for
			 *	backwards compatablity with secret
			 *	things in v3.
			 */
			if ((*ptr == ';') || (*ptr == ',')) {
				ptr++;
				goto check_for_more;
			}

			/*
			 *	Only a few things are allowed after a
			 *	CONF_PAIR definition.  EOL, comment,
			 *	or closing brace.
			 */
			if (!*ptr || (*ptr == '#') || (*ptr == '}')) goto check_for_more;

			/*
			 *	Any other character after the pair
			 *	name / value is an error.
			 */
			ERROR("%s[%d]: Syntax error: Unexpected text: %s",
			      filename, *lineno, ptr);
			goto error;

			/*
			 *	No operator, must be a section or sub-section.
			 */
		case T_BARE_WORD:
		case T_DOUBLE_QUOTED_STRING:
		case T_SINGLE_QUOTED_STRING:
			fr_skip_whitespace(ptr);
			if (*ptr != '{') {
				ERROR("%s[%d]: Expecting section start brace '{' after \"%s %s\"",
				      filename, *lineno, buff[1], buff[2]);
				goto error;
			}
			ptr++;
			/* FALL-THROUGH */

		alloc_section:
		case T_LCBRACE:
			css = cf_section_alloc(this, this, buff[1],
					       name2_token == T_LCBRACE ? NULL : buff[2]);
			if (!css) {
				ERROR("%s[%d]: Failed allocating memory for section",
				      filename, *lineno);
				goto error;
			}

			css->item.filename = filename;
			css->item.lineno = *lineno;

			/*
			 *	There may not be a name2
			 */
			css->name2_quote = (name2_token == T_LCBRACE) ? T_INVALID : name2_token;

			/*
			 *	Hack for better error messages in
			 *	nested sections.  This information
			 *	should really be put into a parser
			 *	struct, as with tmpls.
			 */
			if (!in_map && !in_update) in_update = (strcmp(css->name1, "update") == 0);

		add_section:
			cf_item_add(this, &(css->item));

			/*
			 *	The current section is now the child section.
			 */
			this = css;
			css = NULL;
			break;

		case T_INVALID:
			PERROR("%s[%d]: Syntax error in '%s'", filename, *lineno, ptr);

			goto error;

		default:
			ERROR("%s[%d]: Parse error after \"%s\": unexpected token \"%s\"",
			      filename, *lineno, buff[1], fr_table_str_by_value(fr_tokens_table, name2_token, "<INVALID>"));

			goto error;
		}

	check_for_more:
		/*
		 *	Done parsing one thing.  Skip to EOL if possible.
		 */
		fr_skip_whitespace(ptr);

		/*
		 *	There's more text at the end of the thing we
		 *	just parsed.  Try to grab some more.
		 */
		if (*ptr && (*ptr != '#')) goto parse_line;

		/*
		 *	Otherwise read another line of text from tbe
		 *	file.
		 */
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (feof(fp) && (this != current)) {
		ERROR("%s[%d]: EOF reached without closing brace for section %s starting at line %d",
		      filename, *lineno, cf_section_name1(this), cf_lineno(this));
		goto error;
	}

	return 0;
}

/*
 *	Include one config file in another.
 */
static int cf_file_include(CONF_SECTION *cs, char const *filename_in,
			   UNUSED CONF_INCLUDE_TYPE file_type, char *buff[static 4], bool from_dir)
{
	FILE		*fp = NULL;
	int		lineno = 0;
	char const	*filename;

	/*
	 *	So we only need to do this once.
	 */
	filename = talloc_strdup(cs, filename_in);

	if (cf_file_open(cs, filename, from_dir, &fp) < 0) return -1;

	if (!cs->item.filename) cs->item.filename = filename;

	/*
	 *	Read the section.  It's OK to have EOF without a
	 *	matching close brace.
	 */
	if (cf_section_read(filename, &lineno, fp, cs, buff) < 0) {
		ERROR("Failed parsing configuration file \"%s\"", filename);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
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
	char		**buff;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	if (!cp) return -1;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	cf_item_add(cs, &(cp->item));

	MEM(tree = rbtree_talloc_create(cs, _filename_cmp, cf_file_t, NULL, 0));

	cf_data_add(cs, tree, "filename", false);

	/*
	 *	Allocate temporary buffers on the heap (so we don't use *all* the stack space)
	 */
	buff = talloc_array(cs, char *, 4);
	for (i = 0; i < 4; i++) MEM(buff[i] = talloc_array(buff, char, 8192));

	if (cf_file_include(cs, filename, CONF_INCLUDE_FILE, buff, false) < 0) {
		talloc_free(buff);
		return -1;
	}

	talloc_free(buff);

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

			cond_snprint(buffer, sizeof(buffer), c);
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
		if (!parent_cs) goto no_such_item;
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
			if (q[1] && q[1] != '.') goto no_such_item;

			*r = '\0';
			*q = '\0';
			next = cf_section_find(cs, p, r + 1);
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
			next = cf_section_find(cs, p, NULL);
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

no_such_item:
	return NULL;
}
