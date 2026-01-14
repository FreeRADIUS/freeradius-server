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

#include <sys/errno.h>

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/util.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/skip.h>
#include <freeradius-devel/util/md5.h>

#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif

#ifdef HAVE_GLOB_H
#  include <glob.h>
#endif

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <fcntl.h>

#include <freeradius-devel/server/main_config.h>

bool check_config = false;
static uid_t conf_check_uid = (uid_t)-1;
static gid_t conf_check_gid = (gid_t)-1;

typedef enum conf_property {
	CONF_PROPERTY_INVALID = 0,
	CONF_PROPERTY_NAME,
	CONF_PROPERTY_INSTANCE,
} CONF_PROPERTY;

static fr_table_num_sorted_t const conf_property_name[] = {
	{ L("instance"),	CONF_PROPERTY_INSTANCE	},
	{ L("name"),	CONF_PROPERTY_NAME	}
};
static size_t conf_property_name_len = NUM_ELEMENTS(conf_property_name);

static fr_table_num_sorted_t const server_unlang_section[] = {
	{ L("accounting"),	true },
	{ L("add"),		true },
	{ L("authenticate"),	true },
	{ L("clear"),		true },
	{ L("deny"),		true },
	{ L("error"),		true },
	{ L("establish"),	true },
	{ L("finally"),		true },
	{ L("load"),		true },
	{ L("new"),		true },
	{ L("recv"),		true },
	{ L("send"),		true },
	{ L("store"),		true },
	{ L("verify"),		true },
};
static size_t server_unlang_section_len = NUM_ELEMENTS(server_unlang_section);

typedef enum {
	CF_STACK_FILE = 0,
#ifdef HAVE_DIRENT_H
	CF_STACK_DIR,
#endif
#ifdef HAVE_GLOB_H
	CF_STACK_GLOB
#endif
} cf_stack_file_t;

#define MAX_STACK (32)
typedef struct {
	cf_stack_file_t type;

	char const     	*filename;		//!< filename we're reading
	int		lineno;			//!< line in that filename

	union {
		struct {
			FILE		*fp;		//!< FP we're reading
		};

#ifdef HAVE_DIRENT_H
		struct {
			fr_heap_t	*heap;		//!< sorted heap of files
			char		*directory;	//!< directory name we're reading
		};
#endif

#ifdef HAVE_GLOB_H
		struct {
			size_t		gl_current;
			glob_t		glob;		//! reading glob()
			bool		required;
		};
#endif
	};

	CONF_SECTION	*parent;		//!< which started this file
	CONF_SECTION	*current;		//!< sub-section we're reading
	CONF_SECTION   	*at_reference;		//!< was this thing an @foo ?

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


static inline CC_HINT(always_inline) int cf_tmpl_rules_verify(CONF_SECTION *cs, tmpl_rules_t const *rules)
{
	if (cf_section_find_parent(cs, "policy", NULL)) {
		if (!fr_cond_assert_msg(!rules->attr.dict_def || (rules->attr.dict_def == fr_dict_internal()),
					"Protocol dictionary must be NULL not %s",
					fr_dict_root(rules->attr.dict_def)->name)) return -1;

	} else {
		if (!fr_cond_assert_msg(rules->attr.dict_def, "No protocol dictionary set")) return -1;
		if (!fr_cond_assert_msg(rules->attr.dict_def != fr_dict_internal(), "rules->attr.dict_def must not be the internal dictionary")) return -1;
	}

	if (!fr_cond_assert_msg(!rules->attr.allow_foreign, "rules->allow_foreign must be false")) return -1;
	if (!fr_cond_assert_msg(!rules->at_runtime, "rules->at_runtime must be false")) return -1;

	return 0;
}

#define RULES_VERIFY(_cs, _rules) if (cf_tmpl_rules_verify(_cs, _rules) < 0) return NULL

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
			ssize_t len;

			len = fr_skip_xlat(ptr, end);
			if (len <= 0) {
				ERROR("%s[%d]: Failed parsing variable expansion '%s''",
				      cf, lineno, input);
				return NULL;
			}

			next = ptr + len;
			ptr += 2;

			/*
			 *	Can't really happen because input lines are
			 *	capped at 8k, which is sizeof(name)
			 */
			if ((size_t) len >= sizeof(name)) {
				ERROR("%s[%d]: Reference string is too large",
				      cf, lineno);
				return NULL;
			}

			memcpy(name, ptr, len - 3);
			name[len - 3] = '\0';

			/*
			 *	Read configuration value from a file.
			 *
			 *	Note that this is "read binary data", and the contents aren't stripped of
			 *	CRLF.
			 */
			if (name[0] == '/') {
				int fd = open(name, O_RDONLY);
				struct stat buf;

				if (fd < 0) {
					ERROR("%s[%d]: Reference \"${%s}\" failed opening file - %s", cf, lineno, name, fr_syserror(errno));
					return NULL;
				}

				if (fstat(fd, &buf) < 0) {
				fail_fd:
					close(fd);
					ERROR("%s[%d]: Reference \"${%s}\" failed reading file - %s", cf, lineno, name, fr_syserror(errno));
					return NULL;
				}

				if (buf.st_size >= ((output + outsize) - p)) {
					close(fd);
					ERROR("%s[%d]: Reference \"${%s}\" file is too large (%zu >= %zu)", cf, lineno, name,
					      (size_t) buf.st_size, (size_t) ((output + outsize) - p));
					return NULL;
				}

				len = read(fd, p, (output + outsize) - p);
				if (len < 0) goto fail_fd;

				close(fd);
				p += len;
				*p = '\0';
				ptr = next;
				goto check_eos;
			}

			q = strchr(name, ':');
			if (q) {
				*(q++) = '\0';
			}

			ci = cf_reference_item(parent_cs, outer_cs, name);
			if (!ci) {
				if (soft_fail) *soft_fail = true;
				PERROR("%s[%d]: Failed finding reference \"${%s}\"", cf, lineno, name);
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
				ptr = next;

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
				ptr = next;

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

				cf_filename_set(subcs, ci->filename);
				cf_lineno_set(subcs, ci->lineno);

				ptr = next;

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

	check_eos:
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
 *	Merge the template so everything else "just works".
 */
static bool cf_template_merge(CONF_SECTION *cs, CONF_SECTION const *template)
{
	if (!cs || !template) return true;

	cs->template = NULL;

	/*
	 *	Walk over the template, adding its' entries to the
	 *	current section.  But only if the entries don't
	 *	already exist in the current section.
	 */
	cf_item_foreach(&template->item, ci) {
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
			cp2 = cf_pair_dup(cs, cp1, true);
			if (!cp2) return false;

			cf_filename_set(cp2, cp1->item.filename);
			cf_lineno_set(cp2, cp1->item.lineno);
			continue;
		}

		if (ci->type == CONF_ITEM_SECTION) {
			CONF_SECTION *subcs1, *subcs2;

			subcs1 = cf_item_to_section(ci);
			fr_assert(subcs1 != NULL);

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

			cf_filename_set(subcs2, subcs1->item.filename);
			cf_lineno_set(subcs2, subcs1->item.lineno);
			continue;
		}

		/* ignore everything else */
	}

	return true;
}

/*
 *	Functions for tracking files by inode
 */
static int8_t _inode_cmp(void const *one, void const *two)
{
	cf_file_t const *a = one, *b = two;

	CMP_RETURN(a, b, buf.st_dev);

	return CMP(a->buf.st_ino, b->buf.st_ino);
}

static int cf_file_open(CONF_SECTION *cs, char const *filename, bool from_dir, FILE **fp_p)
{
	cf_file_t *file;
	CONF_SECTION *top;
	fr_rb_tree_t *tree;
	int fd = -1;
	FILE *fp;

	top = cf_root(cs);
	tree = cf_data_value(cf_data_find(top, fr_rb_tree_t, "filename"));
	fr_assert(tree);

	/*
	 *	If we're including a wildcard directory, then ignore
	 *	any files the users has already explicitly loaded in
	 *	that directory.
	 */
	if (from_dir) {
		cf_file_t my_file;
		char const *r;
		int my_fd;

		my_file.cs = cs;
		my_file.filename = filename;

		/*
		 *	Find and open the directory containing filename so we can use
		 * 	 the "at"functions to avoid time of check/time of use insecurities.
		 */
		if (fr_dirfd(&my_fd, &r, filename) < 0) {
			ERROR("Failed to open directory containing %s", filename);
			return -1;
		}

		if (fstatat(my_fd, r, &my_file.buf, 0) < 0) goto error;

		file = fr_rb_find(tree, &my_file);

		/*
		 *	The file was previously read by including it
		 *	explicitly.  After it was read, we have a
		 *	$INCLUDE of the directory it is in.  In that
		 *	case, we ignore the file.
		 *
		 *	However, if the file WAS read from a wildcard
		 *	$INCLUDE directory, then we read it again.
		 */
		if (file && !file->from_dir) {
			if (my_fd != AT_FDCWD) close(my_fd);
			return 1;
		}
		fd = openat(my_fd, r, O_RDONLY, 0);
		fp = (fd < 0) ? NULL : fdopen(fd, "r");
		if (my_fd != AT_FDCWD) close(my_fd);
	} else {
		fp = fopen(filename, "r");
		if (fp) fd = fileno(fp);
	}

	DEBUG2("including configuration file %s", filename);

	if (!fp) {
	error:
		ERROR("Unable to open file \"%s\": %s", filename, fr_syserror(errno));
		return -1;
	}

	MEM(file = talloc(tree, cf_file_t));

	file->filename = talloc_strdup(file, filename);	/* The rest of the code expects this to be a talloced buffer */
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
	if (!fr_rb_insert(tree, file)) talloc_free(file);

	*fp_p = fp;
	return 0;
}

/** Set the euid/egid used when performing file checks
 *
 * Sets the euid, and egid used when cf_file_check is called to check
 * permissions on conf items of type #CONF_FLAG_FILE_READABLE
 *
 * @note This is probably only useful for the freeradius daemon itself.
 *
 * @param uid to set, (uid_t)-1 to use current euid.
 * @param gid to set, (gid_t)-1 to use current egid.
 */
void cf_file_check_set_uid_gid(uid_t uid, gid_t gid)
{
	if (uid != 0) conf_check_uid = uid;
	if (gid != 0) conf_check_gid = gid;
}

/** Perform an operation with the effect/group set to conf_check_gid and conf_check_uid
 *
 * @param filename		CONF_PAIR for the file being checked
 * @param cb			callback function to perform the check
 * @param uctx			user context for the callback
 * @return
 *	- CF_FILE_OTHER_ERROR if there was a problem modifying permissions
 *	- The return value from the callback
 */
cf_file_check_err_t cf_file_check_effective(char const *filename,
					    cf_file_check_err_t (*cb)(char const *filename, void *uctx), void *uctx)
{
	int ret;

	uid_t euid = (uid_t)-1;
	gid_t egid = (gid_t)-1;

	if ((conf_check_gid != (gid_t)-1) && ((egid = getegid()) != conf_check_gid)) {
		if (setegid(conf_check_gid) < 0) {
			fr_strerror_printf("Failed setting effective group ID (%d) for file check: %s",
					   (int) conf_check_gid, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;
		}
	}
	if ((conf_check_uid != (uid_t)-1) && ((euid = geteuid()) != conf_check_uid)) {
		if (seteuid(conf_check_uid) < 0) {
			fr_strerror_printf("Failed setting effective user ID (%d) for file check: %s",
					   (int) conf_check_uid, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;
		}
	}
	ret = cb(filename, uctx);
	if (conf_check_uid != euid) {
		if (seteuid(euid) < 0) {
			fr_strerror_printf("Failed restoring effective user ID (%d) after file check: %s",
					   (int) euid, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;
		}
	}
	if (conf_check_gid != egid) {
		if (setegid(egid) < 0) {
			fr_strerror_printf("Failed restoring effective group ID (%d) after file check: %s",
					   (int) egid, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;
		}
	}

	return ret;
}

/** Check if we can connect to a unix socket
 *
 * @param[in] filename		CONF_PAIR for the unix socket path
 * @param[in] uctx		user context, not used
 * @return
 *	- CF_FILE_OK if the socket exists and is a socket.
 *	- CF_FILE_NO_EXIST if the file doesn't exist.
 *	- CF_FILE_NO_PERMISSION if the file exists but is not accessible.
 *	- CF_FILE_NO_UNIX_SOCKET if the file exists but is not a socket.
 *	- CF_FILE_OTHER_ERROR any other error.
 */
cf_file_check_err_t cf_file_check_unix_connect(char const *filename, UNUSED void *uctx)
{
	int fd;
	cf_file_check_err_t ret = CF_FILE_OK;

	struct sockaddr_un addr = { .sun_family = AF_UNIX };

	fr_strerror_clear();

	if (talloc_strlen(filename) >= sizeof(addr.sun_path)) {
		fr_strerror_printf("Socket path \"%s\" to long", filename);
		return CF_FILE_OTHER_ERROR;
	}

	strlcpy(addr.sun_path, filename, sizeof(addr.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fr_strerror_printf("Failed checking permissions for \"%s\": %s",
				   filename, fr_syserror(errno));
		return CF_FILE_OTHER_ERROR;
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		fr_strerror_printf("Failed setting non-blocking mode for socket %s: %s",
				   filename, fr_syserror(errno));
		close(fd);
		return CF_FILE_OTHER_ERROR;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		switch (errno) {
		case EINPROGRESS:	/* This is fine */
			break;

		case ENOENT:
			fr_strerror_printf("Socket path \"%s\" does not exist", filename);
			ret = CF_FILE_NO_EXIST;
			break;

		case EACCES:
			fr_perm_file_error(errno);
			fr_strerror_printf_push("Socket path \"%s\" exists but is not accessible", filename);
			ret = CF_FILE_NO_PERMISSION;
			break;

		case ENOTSOCK:
			fr_strerror_printf("File \"%s\" is not a socket", filename);
			ret = CF_FILE_NO_UNIX_SOCKET;
			break;

		default:
			fr_strerror_printf("Failed connecting to socket %s: %s", filename, fr_syserror(errno));
			ret = CF_FILE_OTHER_ERROR;
			break;
		}
	}

	close(fd);

	return ret;
}

/** Check if file exists, and is a socket
 *
 * @param[in] filename		CONF_PAIR for the unix socket path
 * @param[in] uctx		user context, not used
 * @return
 *	- CF_FILE_OK if the socket exists and is a socket.
 *	- CF_FILE_NO_EXIST if the file doesn't exist.
 *	- CF_FILE_NO_PERMISSION if the file exists but is not accessible.
 *	- CF_FILE_NO_UNIX_SOCKET if the file exists but is not a socket.
 *	- CF_FILE_OTHER_ERROR any other error.
 */
cf_file_check_err_t cf_file_check_unix_perm(char const *filename, UNUSED void *uctx)
{
	struct stat buf;

	fr_strerror_clear();

	if (stat(filename, &buf) < 0) {
		switch (errno) {
		case ENOENT:
			fr_strerror_printf("Socket path \"%s\" does not exist", filename);
			return CF_FILE_NO_EXIST;

		case EPERM:
		case EACCES:
			fr_perm_file_error(errno);
			fr_strerror_printf_push("Socket path \"%s\" exists but is not accessible: %s",
				    filename, fr_syserror(errno));
			return CF_FILE_NO_PERMISSION;

		default:
			fr_strerror_printf("Unable to stat socket \"%s\": %s", filename, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;
		}
	}

	if (!S_ISSOCK(buf.st_mode)) {
		fr_strerror_printf("File \"%s\" is not a socket", filename);
		return CF_FILE_NO_UNIX_SOCKET;
	}

	return CF_FILE_OK;
}

/** Callback for cf_file_check to open a file and check permissions.
 *
 * This is used to check if a file exists, and is readable by the
 * unprivileged user/group.
 *
 * @param filename	currently being processed.
 * @param uctx		user context, which is a pointer to cf_file_t
 * @return
 *	- CF_FILE_OK if the file exists and is readable.
 *	- CF_FILE_NO_EXIST if the file does not exist.
 *	- CF_FILE_NO_PERMISSION if the file exists but is not accessible.
 *	- CF_FILE_OTHER_ERROR if there was any other error.
 */
cf_file_check_err_t cf_file_check_open_read(char const *filename, void *uctx)
{
	int fd;
	cf_file_t *file = uctx;

	fr_strerror_clear();

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
	error:
		if (fd >= 0) close(fd);

		switch (errno) {
		case ENOENT:
			fr_strerror_printf("File \"%s\" does not exist", filename);
			return CF_FILE_NO_EXIST;

		case EPERM:
		case EACCES:
			fr_perm_file_error(errno);
			fr_strerror_printf_push("File \"%s\" exists but is not accessible: %s",
						filename, fr_syserror(errno));
			return CF_FILE_NO_PERMISSION;

		default:
			fr_strerror_printf("Unable to open file \"%s\": %s", filename, fr_syserror(errno));
			return CF_FILE_OTHER_ERROR;

		}
	}

	if (file && fstat(fd, &file->buf) < 0) goto error;

	close(fd);
	return CF_FILE_OK;
}

/** Do some checks on the file as an "input" file.  i.e. one read by a module.
 *
 * @note Must be called with super user privileges.
 *
 * @param cp		currently being processed.
 * @param check_perms	If true - will return error if file is world readable,
 *			or not readable by the unprivileged user/group.
 * @return
 *	- CF_FILE_OK if the socket exists and is a socket.
 *	- CF_FILE_NO_EXIST if the file doesn't exist.
 *	- CF_FILE_NO_PERMISSION if the file exists but is not accessible.
 *	- CF_FILE_OTHER_ERROR any other error.
 */
cf_file_check_err_t cf_file_check(CONF_PAIR *cp, bool check_perms)
{
	cf_file_t		*file;
	CONF_SECTION		*top;
	fr_rb_tree_t		*tree;
	char const 		*filename = cf_pair_value(cp);
	cf_file_check_err_t	ret;

	top = cf_root(cp);
	tree = cf_data_value(cf_data_find(top, fr_rb_tree_t, "filename"));
	if (!tree) return false;

	file = talloc(tree, cf_file_t);
	if (!file) return false;

	file->filename = talloc_strdup(file, filename);	/* The rest of the code expects this to be talloced */
	file->cs = cf_item_to_section(cf_parent(cp));

	if (!check_perms) {
		if (stat(filename, &file->buf) < 0) {
			fr_perm_file_error(errno);	/* Write error and euid/egid to error buff */
			cf_log_perr(cp, "Unable to open file \"%s\"", filename);
		error:
			talloc_free(file);
			return CF_FILE_OTHER_ERROR;
		}
		talloc_free(file);
		return CF_FILE_OK;
	}

	/*
	 *	This really does seem to be the simplest way
	 *	to check that the file can be read with the
	 *	euid/egid.
	 */
	ret = cf_file_check_effective(filename, cf_file_check_open_read, file);
	if (ret < 0) {
		cf_log_perr(cp, "Permissions check failed");
		goto error;
	}
#ifdef S_IWOTH
	if ((file->buf.st_mode & S_IWOTH) != 0) {
		cf_log_perr(cp, "Configuration file %s is globally writable.  "
		            "Refusing to start due to insecure configuration.", filename);
		talloc_free(file);
		return CF_FILE_OTHER_ERROR;
	}
#endif

	/*
	 *	It's OK to include the same file twice...
	 */
	if (!fr_rb_insert(tree, file)) talloc_free(file);

	return CF_FILE_OK;
}

/*
 *	Do variable expansion in pass2.
 *
 *	This is a breadth-first expansion.  "deep
 */
int cf_section_pass2(CONF_SECTION *cs)
{
	cf_item_foreach(&cs->item, ci) {
		char const	*value;
		CONF_PAIR	*cp;
		char		buffer[8192];

		if (ci->type != CONF_ITEM_PAIR) continue;

		cp = cf_item_to_pair(ci);
		if (!cp->value || !cp->pass2) continue;

		fr_assert((cp->rhs_quote == T_BARE_WORD) ||
			  (cp->rhs_quote == T_HASH) ||
			  (cp->rhs_quote == T_DOUBLE_QUOTED_STRING) ||
			  (cp->rhs_quote == T_BACK_QUOTED_STRING));

		value = cf_expand_variables(ci->filename, ci->lineno, cs, buffer, sizeof(buffer), cp->value, -1, NULL);
		if (!value) return -1;

		talloc_const_free(cp->value);
		cp->value = talloc_typed_strdup(cp, value);
	}

	cf_item_foreach(&cs->item, ci) {
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

/*
 *	Like gettoken(), but uses the new API which seems better for a
 *	host of reasons.
 */
static int cf_get_token(CONF_SECTION *parent, char const **ptr_p, fr_token_t *token, char *buffer, size_t buflen,
			char const *filename, int lineno)
{
	char const *ptr = *ptr_p;
	ssize_t slen;
	char const *out;
	size_t outlen;

	/*
	 *	Discover the string content, returning what kind of
	 *	string it is.
	 *
	 *	Don't allow casts or regexes.  But do allow bare
	 *	%{...} expansions.
	 */
	slen = tmpl_preparse(&out, &outlen, ptr, strlen(ptr), token);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(parent, &spaces, &text, slen, ptr);

		ERROR("%s[%d]: %s", filename, lineno, text);
		ERROR("%s[%d]: %s^ - %s", filename, lineno, spaces, fr_strerror());

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

typedef struct cf_file_heap_t {
	char const		*filename;
	fr_heap_index_t		heap_id;
} cf_file_heap_t;

static int8_t filename_cmp(void const *one, void const *two)
{
	int ret;
	cf_file_heap_t const *a = one;
	cf_file_heap_t const *b = two;

	ret = strcmp(a->filename, b->filename);
	return CMP(ret, 0);
}


static int process_include(cf_stack_t *stack, CONF_SECTION *parent, char const *ptr, bool required, bool relative)
{
	char const *value;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];

	/*
	 *	Can't do this inside of update / map.
	 */
	if (parent->unlang == CF_UNLANG_ASSIGNMENT) {
		ERROR("%s[%d]: Parse error: Invalid location for $INCLUDE",
		      frame->filename, frame->lineno);
		return -1;
	}

	fr_skip_whitespace(ptr);

	/*
	 *	Grab all of the non-whitespace text.
	 */
	value = ptr;
	while (*ptr && !isspace((uint8_t) *ptr)) ptr++;

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

	if (strchr(value, '*') != 0) {
#ifndef HAVE_GLOB_H
		ERROR("%s[%d]: Filename globbing is not supported.", frame->filename, frame->lineno);
		return -1;
#else
		stack->depth++;
		frame = &stack->frame[stack->depth];
		memset(frame, 0, sizeof(*frame));

		frame->type = CF_STACK_GLOB;
		frame->required = required;
		frame->parent = parent;
		frame->current = parent;

		/*
		 *	For better debugging.
		 */
		frame->filename = frame[-1].filename;
		frame->lineno = frame[-1].lineno;

		if (glob(value, GLOB_ERR | GLOB_NOESCAPE, NULL, &frame->glob) < 0) {
			stack->depth--;
			ERROR("%s[%d]: Failed expanding '%s' - %s", frame->filename, frame->lineno,
				value, fr_syserror(errno));
			return -1;
		}

		/*
		 *	If nothing matches, that may be an error.
		 */
		if (frame->glob.gl_pathc == 0) {
			if (!required) {
				stack->depth--;
				return 0;
			}

			ERROR("%s[%d]: Failed expanding '%s' - No matching files", frame->filename, frame->lineno,
			      value);
			return -1;
		}

		return 1;
#endif
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

		frame->type = CF_STACK_FILE;
		frame->fp = NULL;
		frame->parent = parent;
		frame->current = parent;
		frame->filename = talloc_strdup(frame->parent, value);
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
		char		*directory;
		DIR		*dir;
		struct dirent	*dp;
		struct stat	stat_buf;
		cf_file_heap_t	*h;
#ifdef S_IWOTH
		int		my_fd;
#endif

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
		my_fd = dirfd(dir);
		fr_assert(my_fd >= 0);

		/*
		 *	Security checks.
		 */
		if (fstat(my_fd, &stat_buf) < 0) {
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
		*frame = (cf_stack_frame_t){
			.type = CF_STACK_DIR,
			.directory = directory,
			.parent = parent,
			.current = parent,
			.from_dir = true
		};

		MEM(frame->heap = fr_heap_alloc(frame->directory, filename_cmp, cf_file_heap_t, heap_id, 0));

		/*
		 *	Read the whole directory before loading any
		 *	individual file.  We stat() files to ensure
		 *	that they're readable.  We ignore
		 *	subdirectories and files with odd filenames.
		 */
		while ((dp = readdir(dir)) != NULL) {
			char const *p;
			size_t len;

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
				WARN("Ignoring packaging system produced file %s%s", frame->directory, dp->d_name);
			 	continue;
			}
			if ((len > 9) && (strncmp(&dp->d_name[len - 9], ".dpkg-old", 9) == 0)) goto pkg_file;
			if ((len > 7) && (strncmp(&dp->d_name[len - 7], ".rpmnew", 9) == 0)) goto pkg_file;
			if ((len > 8) && (strncmp(&dp->d_name[len - 8], ".rpmsave", 10) == 0)) goto pkg_file;

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

			MEM(h = talloc_zero(frame->heap, cf_file_heap_t));
			MEM(h->filename = talloc_typed_strdup(h, stack->buff[1]));
			h->heap_id = FR_HEAP_INDEX_INVALID;
			(void) fr_heap_insert(&frame->heap, h);
		}
		closedir(dir);
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
	fr_token_t token;
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

	/*
	 *	Allow in-line templates.
	 */
	templatecs = cf_section_find(cf_item_to_section(cf_parent(parent)), "template", stack->buff[2]);
	if (templatecs) {
		parent->template = templatecs;
		return 0;
	}

	parent_cs = cf_root(parent);

	templatecs = cf_section_find(parent_cs, "templates", NULL);
	if (!templatecs) {
		ERROR("%s[%d]: Cannot find template \"%s\", as no 'templates' section exists.",
		      frame->filename, frame->lineno, stack->buff[2]);
		return -1;
	}

	ci = cf_reference_item(parent_cs, templatecs, stack->buff[2]);
	if (!ci || (ci->type != CONF_ITEM_SECTION)) {
		PERROR("%s[%d]: Failed finding item \"%s\" in the 'templates' section.",
		       frame->filename, frame->lineno, stack->buff[2]);
		return -1;
	}

	parent->template = cf_item_to_section(ci);
	return 0;
}


static int cf_file_fill(cf_stack_t *stack);


static const bool terminal_end_section[UINT8_MAX + 1] = {
	['{'] = true,
};

static const bool terminal_end_line[UINT8_MAX + 1] = {
	[0] = true,

	['\r'] = true,
	['\n'] = true,

	['#'] = true,
	[','] = true,
	[';'] = true,
	['}'] = true,
};

static CONF_ITEM *process_if(cf_stack_t *stack)
{
	ssize_t		slen = 0;
	fr_dict_t const	*dict = NULL;
	CONF_SECTION	*cs;
	uint8_t const   *p;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];
	tmpl_rules_t	t_rules;

	/*
	 *	Short names are nicer.
	 */
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];
	buff[3] = stack->buff[3];

	dict = virtual_server_dict_by_child_ci(cf_section_to_item(parent));

	t_rules = (tmpl_rules_t) {
		.attr = {
			.dict_def = dict,
			.list_def = request_attr_request,
			.allow_unresolved = true,
			.allow_unknown = true
		},
		.literals_safe_for = FR_VALUE_BOX_SAFE_FOR_ANY,
	};

	/*
	 *	Create the CONF_SECTION.  We don't pass a name2, as it
	 *	hasn't yet been parsed.
	 */
	cs = cf_section_alloc(parent, parent, buff[1], NULL);
	if (!cs) {
		cf_log_err(parent, "Failed allocating memory for section");
		return NULL;
	}
	cf_filename_set(cs, frame->filename);
	cf_lineno_set(cs, frame->lineno);

	RULES_VERIFY(cs, &t_rules);

	/*
	 *	Keep "parsing" the condition until we hit EOL.
	 *
	 *
	 */
	while (true) {
		int rcode;
		bool eol;

		/*
		 *	Try to parse the condition.  We can have a parse success, or a parse failure.
		 */
		slen = fr_skip_condition(ptr, NULL, terminal_end_section, &eol);

		/*
		 *	Parse success means we stop reading more data.
		 */
		if (slen > 0) break;

		/*
		 *	Parse failures not at EOL are real errors.
		 */
		if (!eol) {
			slen = 0;
			fr_strerror_const("Unexpected EOF");
	error:
			cf_canonicalize_error(cs, slen, "Parse error in condition", ptr);
			talloc_free(cs);
			return NULL;
		}

		/*
		 *	Parse failures at EOL means that we read more data.
		 */
		p = (uint8_t const *) ptr + (-slen);

		/*
		 *	Auto-continue across CR LF until we reach the
		 *	end of the string.  We mash everything into one line.
		 */
		if (*p && (*p < ' ')) {
			while ((*p == '\r') || (*p == '\n')) {
				char *q;

				q = UNCONST(char *, p);
				*q = ' ';
				p++;
				continue;
			}

			/*
			 *	Hopefully the next line is already in
			 *	the buffer, and we don't have to read
			 *	more data.
			 */
			continue;
		}

		/*
		 *	Anything other than EOL is a problem at this point.
		 */
		if (*p) {
			fr_strerror_const("Unexpected text after condition");
			goto error;
		}

		/*
		 *	We hit EOL, so the parse error is really "read more data".
		 */
		stack->fill = UNCONST(char *, p);
		rcode = cf_file_fill(stack);
		if (rcode < 0) {
			cf_log_err(cs, "Failed parsing condition");
			return NULL;
		}
	}

	fr_assert((size_t) slen < (stack->bufsize - 1));

	ptr += slen;
	fr_skip_whitespace(ptr);

	if (*ptr != '{') {
		cf_log_err(cs, "Expected '{' instead of %s", ptr);
		talloc_free(cs);
		return NULL;
	}
	ptr++;

	/*
	 *	Save the parsed condition (minus trailing whitespace)
	 *	into a buffer.
	 */
	memcpy(buff[2], stack->ptr, slen);
	buff[2][slen] = '\0';

	while (slen > 0) {
		if (!isspace((uint8_t) buff[2][slen])) break;

		buff[2][slen] = '\0';
		slen--;
	}

	/*
	 *	Expand the variables in the pre-parsed condition.
	 */
	if (!cf_expand_variables(frame->filename, frame->lineno, parent,
				 buff[3], stack->bufsize, buff[2], slen, NULL)) {
		fr_strerror_const("Failed expanding configuration variable");
		return NULL;
	}

	MEM(cs->name2 = talloc_typed_strdup(cs, buff[3]));
	cs->name2_quote = T_BARE_WORD;

	stack->ptr = ptr;

	cs->allow_locals = true;
	cs->unlang = CF_UNLANG_ALLOW;
	return cf_section_to_item(cs);
}

static CONF_ITEM *process_map(cf_stack_t *stack)
{
	char const *mod;
	char const *value = NULL;
	CONF_SECTION *css;
	fr_token_t token;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];

	/*
	 *	Short names are nicer.
	 */
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];

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
	 *      Maps without an expansion string are allowed, though
	 *      it's not clear why.
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

	/*
	 *	Allocate the section
	 */
alloc_section:
	css = cf_section_alloc(parent, parent, "map", mod);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}
	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	css->name2_quote = T_BARE_WORD;

	css->argc = 0;
	if (value) {
		css->argv = talloc_array(css, char const *, 1);
		css->argv[0] = talloc_typed_strdup(css->argv, value);
		css->argv_quote = talloc_array(css, fr_token_t, 1);
		css->argv_quote[0] = token;
		css->argc++;
	}
	stack->ptr = ptr;
	css->unlang = CF_UNLANG_ASSIGNMENT;

	return cf_section_to_item(css);
}


static CONF_ITEM *process_subrequest(cf_stack_t *stack)
{
	char const *mod = NULL;
	CONF_SECTION *css;
	fr_token_t token;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*buff[4];
	int		values = 0;

	/*
	 *	Short names are nicer.
	 */
	buff[1] = stack->buff[1];
	buff[2] = stack->buff[2];
	buff[3] = stack->buff[3];

	/*
	 *	subrequest { ... } is allowed.
	 */
	fr_skip_whitespace(ptr);
	if (*ptr == '{') {
		ptr++;
		goto alloc_section;
	}

	/*
	 *	Get the name of the Packet-Type.
	 */
	if (cf_get_token(parent, &ptr, &token, buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	mod = buff[1];

        /*
	 *	subrequest Access-Request { ... } is allowed.
	 */
	if (*ptr == '{') {
		ptr++;
		goto alloc_section;
	}

	/*
	 *	subrequest Access-Request &foo { ... }
	 */
	if (cf_get_token(parent, &ptr, &token, buff[2], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	if (token != T_BARE_WORD) {
		ERROR("%s[%d]: The second argument to 'subrequest' must be an attribute reference",
		      frame->filename, frame->lineno);
		return NULL;
	}
	values++;

	if (*ptr == '{') {
		ptr++;
		goto alloc_section;
	}

	/*
	 *	subrequest Access-Request &foo &bar { ... }
	 */
	if (cf_get_token(parent, &ptr, &token, buff[3], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	if (token != T_BARE_WORD) {
		ERROR("%s[%d]: The third argument to 'subrequest' must be an attribute reference",
		      frame->filename, frame->lineno);
		return NULL;
	}
	values++;

	if (*ptr != '{') {
		ERROR("%s[%d]: Expecting section start brace '{' in 'subrequest' definition",
		      frame->filename, frame->lineno);
		return NULL;
	}
	ptr++;

	/*
	 *	Allocate the section
	 */
alloc_section:
	css = cf_section_alloc(parent, parent, "subrequest", mod);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}
	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	if (mod) css->name2_quote = T_BARE_WORD;

	css->argc = values;
	if (values) {
		int i;

		css->argv = talloc_array(css, char const *, values);
		css->argv_quote = talloc_array(css, fr_token_t, values);

		for (i = 0; i < values; i++) {
			css->argv[i] = talloc_typed_strdup(css->argv, buff[2 + i]);
			css->argv_quote[i] = T_BARE_WORD;
		}
	}

	stack->ptr = ptr;

	css->allow_locals = true;
	css->unlang = CF_UNLANG_ALLOW;
	return cf_section_to_item(css);
}

static CONF_ITEM *process_catch(cf_stack_t *stack)
{
	CONF_SECTION	*css;
	int		argc = 0;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;
	char		*name2 = NULL;
	char		*argv[RLM_MODULE_NUMCODES];

	while (true) {
		char const *p;
		size_t len;

		fr_skip_whitespace(ptr);

		/*
		 *      We have an open bracket, it's the end of the "catch" statement.
		 */
		if (*ptr == '{') {
			ptr++;
			break;
		}

		/*
		 *	The arguments have to be short, unquoted words.
		 */
		p = ptr;
		while (isalpha((uint8_t) *ptr)) ptr++;

		len = ptr - p;
		if (len > 16) {
			ERROR("%s[%d]: Invalid syntax for 'catch' - unknown rcode '%s'",
			      frame->filename, frame->lineno, p);
			return NULL;
		}

		if ((*ptr != '{') && !isspace((uint8_t) *ptr)) {
			ERROR("%s[%d]: Invalid syntax for 'catch' - unexpected text at '%s'",
			      frame->filename, frame->lineno, ptr);
			return NULL;
		}

		if (!name2) {
			name2 = talloc_strndup(NULL, p, len);
			continue;
		}

		if (argc > RLM_MODULE_NUMCODES) {
			ERROR("%s[%d]: Invalid syntax for 'catch' - too many arguments at'%s'",
			      frame->filename, frame->lineno, ptr);
			return NULL;
		}

		argv[argc++] = talloc_strndup(name2, p, len);
	}

	css = cf_section_alloc(parent, parent, "catch", name2);
	if (!css) {
		talloc_free(name2);
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}
	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	css->name2_quote = T_BARE_WORD;
	css->unlang = CF_UNLANG_ALLOW;

	css->argc = argc;
	if (argc) {
		int i;

		css->argv = talloc_array(css, char const *, argc + 1);
		css->argv_quote = talloc_array(css, fr_token_t, argc);
		css->argc = argc;

		for (i = 0; i < argc; i++) {
			css->argv[i] = talloc_typed_strdup(css->argv, argv[i]);
			css->argv_quote[i] = T_BARE_WORD;
		}

		css->argv[argc] = NULL;
	}
	talloc_free(name2);

	stack->ptr = ptr;

	return cf_section_to_item(css);
}

static int parse_error(cf_stack_t *stack, char const *ptr, char const *message)
{
	char *spaces, *text;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];

	if (!ptr) ptr = stack->ptr;

	/*
	 *	We must pass a _negative_ offset to this function.
	 */
	fr_canonicalize_error(NULL, &spaces, &text, stack->ptr - ptr, stack->ptr);

	ERROR("%s[%d]: %s", frame->filename, frame->lineno, text);
	ERROR("%s[%d]: %s^ - %s", frame->filename, frame->lineno, spaces, message);

	talloc_free(spaces);
	talloc_free(text);
	return -1;
}

static int parse_type_name(cf_stack_t *stack, char const **ptr_p, char const *type_ptr, fr_type_t *type_p)
{
	fr_type_t type;
	fr_token_t token;
	char const *ptr = *ptr_p;
	char const *ptr2;

	/*
	 *	Parse an explicit type.
	 */
	type = fr_table_value_by_str(fr_type_table, stack->buff[1], FR_TYPE_NULL);
	switch (type) {
	default:
		break;

	case FR_TYPE_NULL:
	case FR_TYPE_VOID:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_MAX:
		(void) parse_error(stack, type_ptr, "Unknown or invalid variable type in 'foreach'");
		return -1;
	}

	fr_skip_whitespace(ptr);
	ptr2 = ptr;

	/*
	 *	Parse the variable name.  @todo - allow '-' in names.
	 */
	token = gettoken(&ptr, stack->buff[2], stack->bufsize, false);
	if (token != T_BARE_WORD) {
		(void) parse_error(stack, ptr2, "Invalid variable name for key in 'foreach'");
		return -1;
	}
	fr_skip_whitespace(ptr);

	*ptr_p = ptr;
	*type_p = type;

	return 0;
}

/*
 *	foreach &User-Name {  - old and deprecated
 *
 *	foreach value (...) { - automatically define variable
 *
 *	foreach string value ( ...) { - data type for variable
 *
 *	foreach string key, type value (..) { - key is "string", value is as above
 */
static CONF_ITEM *process_foreach(cf_stack_t *stack)
{
	fr_token_t	token;
	fr_type_t	type;
	CONF_SECTION	*css;
	char const	*ptr = stack->ptr, *ptr2, *type_ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;

	css = cf_section_alloc(parent, parent, "foreach", NULL);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}

	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	css->name2_quote = T_BARE_WORD;
	css->unlang = CF_UNLANG_ALLOW;
	css->allow_locals = true;

	/*
	 *	Get the first argument to "foreach".  For backwards
	 *	compatibility, it could be an attribute reference.
	 */
	type_ptr = ptr;
	if (cf_get_token(parent, &ptr, &token, stack->buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	if (token != T_BARE_WORD) {
	invalid_argument:
		(void) parse_error(stack, type_ptr, "Unexpected argument to 'foreach'");
		return NULL;
	}

	fr_skip_whitespace(ptr);

	/*
	 *	foreach foo { ...
	 *
	 *	Deprecated and don't use.
	 */
	if (*ptr == '{') {
		css->name2 = talloc_typed_strdup(css, stack->buff[1]);

		ptr++;
		stack->ptr = ptr;

		cf_log_warn(css, "Using deprecated syntax.  Please use new the new 'foreach' syntax.");
		return cf_section_to_item(css);
	}

	fr_skip_whitespace(ptr);

	/*
	 *	foreach value (...) {
	 */
	if (*ptr == '(') {
		type = FR_TYPE_NULL;
		strcpy(stack->buff[2], stack->buff[1]); /* so that we can parse expression in buff[1] */
		goto alloc_argc_2;
	}

	/*
	 *	on input, type name is in stack->buff[1]
	 *	on output, variable name is in stack->buff[2]
	 */
	if (parse_type_name(stack, &ptr, type_ptr, &type) < 0) return NULL;

	/*
	 *	if we now have an expression block, then just have variable type / name.
	 */
	if (*ptr == '(') goto alloc_argc_2;

	/*
	 *	There's a comma.  the first "type name" is for the key.  We skip the comma, and parse the
	 *	second "type name" as being for the value.
	 *
	 *	foreach type key, type value (...)
	 */
	if (*ptr == ',') {
		/*
		 *	We have 4 arguments, [var-type, var-name, key-type, key-name]
		 *
		 *	We don't really care about key-type, but we might care later.
		 */
		css->argc = 4;
		css->argv = talloc_array(css, char const *, css->argc);
		css->argv_quote = talloc_array(css, fr_token_t, css->argc);

		css->argv[2] = fr_type_to_str(type);
		css->argv_quote[2] = T_BARE_WORD;

		css->argv[3] = talloc_typed_strdup(css->argv, stack->buff[2]);
		css->argv_quote[3] = T_BARE_WORD;

		ptr++;
		fr_skip_whitespace(ptr);
		type_ptr = ptr;

		/*
		 *	Now parse "type value"
		 */
		token = gettoken(&ptr, stack->buff[1], stack->bufsize, false);
		if (token != T_BARE_WORD) goto invalid_argument;

		if (parse_type_name(stack, &ptr, type_ptr, &type) < 0) return NULL;

		if (!fr_type_is_leaf(type)) {
			(void) parse_error(stack, type_ptr, "Invalid data type for 'key' variable");
			return NULL;
		}
	}

	/*
	 *	The thing to loop over must now be in an expression block.
	 */
	if (*ptr != '(') {
		(void) parse_error(stack, ptr, "Expected (...) after 'foreach' variable definition");
		return NULL;
	}

	goto parse_expression;

alloc_argc_2:
	css->argc = 2;
	css->argv = talloc_array(css, char const *, css->argc);
	css->argv_quote = talloc_array(css, fr_token_t, css->argc);


parse_expression:
	/*
	 *	"(" whitespace EXPRESSION whitespace ")"
	 */
	ptr++;
	fr_skip_whitespace(ptr);
	ptr2 = ptr;

	if (cf_get_token(parent, &ptr, &token, stack->buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	/*
	 *	We can do &foo[*] or %func(...), but not "...".
	 */
	if (token != T_BARE_WORD) {
		(void) parse_error(stack, ptr2, "Invalid reference in 'foreach'");
		return NULL;
	}

	fr_skip_whitespace(ptr);
	if (*ptr != ')') {
		(void) parse_error(stack, ptr, "Missing ')' in 'foreach'");
		return NULL;
	}
	ptr++;
	fr_skip_whitespace(ptr);

	if (*ptr != '{') {
		(void) parse_error(stack, ptr, "Expected '{' in 'foreach'");
		return NULL;
	}

	css->name2 = talloc_typed_strdup(css, stack->buff[1]);

	/*
	 *	Add in the extra arguments
	 */
	css->argv[0] = fr_type_to_str(type);
	css->argv_quote[0] = T_BARE_WORD;

	css->argv[1] = talloc_typed_strdup(css->argv, stack->buff[2]);
	css->argv_quote[1] = T_BARE_WORD;

	ptr++;
	stack->ptr = ptr;

	return cf_section_to_item(css);
}


static int add_pair(CONF_SECTION *parent, char const *attr, char const *value,
		    fr_token_t name1_token, fr_token_t op_token, fr_token_t value_token,
		    char *buff, char const *filename, int lineno)
{
	CONF_DATA const *cd;
	conf_parser_t *rule;
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
	cf_filename_set(cp, filename);
	cf_lineno_set(cp, lineno);
	cp->pass2 = pass2;

	cd = cf_data_find(CF_TO_ITEM(parent), conf_parser_t, attr);
	if (!cd) return 0;

	rule = cf_data_value(cd);
	if (!rule->on_read) return 0;

	/*
	 *	Do the on_read callback after adding the value.
	 */
	return rule->on_read(parent, NULL, NULL, cf_pair_to_item(cp), rule);
}

/*
 *	switch (cast) foo {
 */
static CONF_ITEM *process_switch(cf_stack_t *stack)
{
	size_t		match_len;
	fr_type_t	type = FR_TYPE_NULL;
	fr_token_t	name2_quote = T_BARE_WORD;
	CONF_SECTION	*css;
	char const	*ptr = stack->ptr;
	cf_stack_frame_t *frame = &stack->frame[stack->depth];
	CONF_SECTION	*parent = frame->current;

	fr_skip_whitespace(ptr);
	if (*ptr == '(') {
		char const *start;

		ptr++;
		start = ptr;

		while (isalpha(*ptr)) ptr++;

		if (*ptr != ')') {
			ERROR("%s[%d]: Missing ')' in cast",
			      frame->filename, frame->lineno);
			return NULL;
		}

		type = fr_table_value_by_longest_prefix(&match_len, fr_type_table,
							start, ptr - start, FR_TYPE_MAX);
		if (type == FR_TYPE_MAX) {
			ERROR("%s[%d]: Unknown data type '%.*s' in cast",
			      frame->filename, frame->lineno, (int) (ptr - start), start);
			return NULL;
		}

		if (!fr_type_is_leaf(type)) {
			ERROR("%s[%d]: Invalid data type '%.*s' in cast",
			      frame->filename, frame->lineno, (int) (ptr - start), start);
			return NULL;
		}

		ptr++;
		fr_skip_whitespace(ptr);
	}

	/*
	 *	Get the argument to the switch statement
	 */
	if (cf_get_token(parent, &ptr, &name2_quote, stack->buff[1], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return NULL;
	}

	css = cf_section_alloc(parent, parent, "switch", NULL);
	if (!css) {
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return NULL;
	}

	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	css->name2_quote = name2_quote;
	css->unlang = CF_UNLANG_ALLOW;
	css->allow_locals = true;

	fr_skip_whitespace(ptr);

	if (*ptr != '{') {
		(void) parse_error(stack, ptr, "Expected '{' in 'switch'");
		return NULL;
	}

	css->name2 = talloc_typed_strdup(css, stack->buff[1]);

	/*
	 *	Add in the extra argument.
	 */
	if (type != FR_TYPE_NULL) {
		css->argc = 1;
		css->argv = talloc_array(css, char const *, css->argc);
		css->argv_quote = talloc_array(css, fr_token_t, css->argc);

		css->argv[0] = fr_type_to_str(type);
		css->argv_quote[0] = T_BARE_WORD;
	}

	ptr++;
	stack->ptr = ptr;

	return cf_section_to_item(css);
}


static fr_table_ptr_sorted_t unlang_keywords[] = {
	{ L("catch"),		(void *) process_catch },
	{ L("elsif"),		(void *) process_if },
	{ L("foreach"),		(void *) process_foreach },
	{ L("if"),		(void *) process_if },
	{ L("map"),		(void *) process_map },
	{ L("subrequest"),	(void *) process_subrequest },
	{ L("switch"),		(void *) process_switch }
};
static int unlang_keywords_len = NUM_ELEMENTS(unlang_keywords);

typedef CONF_ITEM *(*cf_process_func_t)(cf_stack_t *);

static int parse_input(cf_stack_t *stack)
{
	fr_token_t	name1_token, name2_token, value_token, op_token;
	char const	*value;
	CONF_SECTION	*css;
	char const	*ptr = stack->ptr;
	char const	*ptr2;
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

	fr_assert(parent != NULL);

	/*
	 *	Catch end of a subsection.
	 *
	 *	frame->current is the new thing we just created.
	 *	frame->parent is the parent of the current frame
	 *	frame->at_reference is the original frame->current, before the @reference
	 *	parent is the parent we started with when we started this section.
	 */
	if (*ptr == '}') {
		/*
		 *	No pushed braces means that we're already in
		 *      the parent section which loaded this file.  We
		 *      cannot go back up another level.
		 *
		 *      This limitation means that we cannot put half
		 *      of a CONF_SECTION in one file, and then the
		 *      second half in another file.  That's fine.
		 */
		if (frame->braces == 0) {
			return parse_error(stack, ptr, "Too many closing braces");
		}

		/*
		 *	Reset the current and parent to the original
		 *	section, before we were parsing the
		 *	@reference.
		 */
		if (frame->at_reference) {
			frame->current = frame->parent = frame->at_reference;
			frame->at_reference = NULL;

		} else {
			/*
			 *	Go back up one section, because we can.
			 */
			frame->current = frame->parent = cf_item_to_section(frame->current->item.parent);
		}

		fr_assert(frame->braces > 0);
		frame->braces--;

		/*
		 *	Merge the template into the existing
		 *	section.  parent uses more memory, but
		 *	means that templates now work with
		 *	sub-sections, etc.
		 */
		if (!cf_template_merge(parent, parent->template)) return -1;

		ptr++;
		stack->ptr = ptr;
		return 1;
	}

	/*
	 *	Found nothing to get excited over.  It MUST be
	 *	a key word.
	 */
	ptr2 = ptr;
	switch (parent->unlang) {
	default:
		/*
		 *	The LHS is a bare word / keyword in normal configuration file syntax.
		 */
		name1_token = gettoken(&ptr, buff[1], stack->bufsize, false);
		if (name1_token == T_EOL) return 0;

		if (name1_token == T_INVALID) {
			return parse_error(stack, ptr2, fr_strerror());
		}

		if (name1_token != T_BARE_WORD) {
			return parse_error(stack, ptr2, "Invalid location for quoted string");
		}

		fr_skip_whitespace(ptr);
		break;

	case CF_UNLANG_ALLOW:
	case CF_UNLANG_EDIT:
	case CF_UNLANG_ASSIGNMENT:
		/*
		 *	The LHS can be an xlat expansion, attribute reference, etc.
		 */
		if (cf_get_token(parent, &ptr, &name1_token, buff[1], stack->bufsize,
				 frame->filename, frame->lineno) < 0) {
			return -1;
		}
		break;
	}

	/*
	 *	Check if the thing we just parsed is an unlang keyword.
	 */
	if ((name1_token == T_BARE_WORD) && isalpha((uint8_t) *buff[1])) {
		process = (cf_process_func_t) fr_table_value_by_str(unlang_keywords, buff[1], NULL);
		if (process) {
			CONF_ITEM *ci;

			/*
			 *	Disallow keywords outside of unlang sections.
			 *
			 *	We don't strictly need to do this with the more state-oriented parser, but
			 *	people keep putting unlang into random places in the configuration files,
			 *	which is wrong.
			 */
			if (parent->unlang != CF_UNLANG_ALLOW) {
				return parse_error(stack, ptr2, "Invalid location for unlang keyword");
			}

			stack->ptr = ptr;
			ci = process(stack);
			if (!ci) return -1;

			ptr = stack->ptr;
			if (cf_item_is_section(ci)) {
				parent->allow_locals = false;
				css = cf_item_to_section(ci);
				goto add_section;
			}

			/*
			 *	Else the item is a pair, and the call to process() it already added it to the
			 *	current section.
			 */
			goto added_pair;
		}

		/*
		 *	The next token isn't text, so we ignore it.
		 */
		if (!isalnum((int) *ptr)) goto check_for_eol;
	}

	/*
	 *	See if this thing is a variable definition.
	 */
	if ((name1_token == T_BARE_WORD) && parent->allow_locals) {
		fr_type_t type;
		char const *ptr3;

		type = fr_table_value_by_str(fr_type_table, buff[1], FR_TYPE_NULL);
		if (type == FR_TYPE_NULL) {
			parent->allow_locals = false;
			goto check_for_eol;
		}

		if (type == FR_TYPE_TLV) goto parse_name2;

		/*
		 *	group {
		 *
		 *	is a section.
		 */
		if (type == FR_TYPE_GROUP) {
			fr_skip_whitespace(ptr);
			if (*ptr == '{') {
				ptr++;
				value = NULL;
				name2_token = T_BARE_WORD;
				goto alloc_section;
			}

		} else if (!fr_type_is_leaf(type)) {
			/*
			 *	Other structural types are allowed.
			 */
			return parse_error(stack, ptr2, "Invalid data type for local variable.  Must be 'tlv' or else a non-structrul type");
		}

		/*
		 *	We don't have an operator, so set it to a magic value.
		 */
		op_token = T_OP_CMP_TRUE;

		/*
		 *	Parse the name of the local variable, and use it as the "value" for the CONF_PAIR.
		 */
		ptr3 = ptr;
		if (cf_get_token(parent, &ptr, &value_token, buff[2], stack->bufsize,
				 frame->filename, frame->lineno) < 0) {
			return -1;
		}

		if (value_token != T_BARE_WORD) {
			return parse_error(stack, ptr3, "Invalid name");
		}

		value = buff[2];

		/*
		 *	Non-structural things must be variable definitions.
		 */
		if (fr_type_is_leaf(type)) goto alloc_pair;

		/*
		 *	Parse:	group foo
		 *	   vs   group foo { ...
		 */
		fr_skip_whitespace(ptr);

		if (*ptr != '{') goto alloc_pair;

		ptr++;
		name2_token = T_BARE_WORD;
		goto alloc_section;
	}

	/*
	 *	We've parsed the LHS thing.  The RHS might be empty, or an operator, or another word, or an
	 *	open bracket.
	 */
check_for_eol:
	if (!*ptr || (*ptr == '#') || (*ptr == ',') || (*ptr == ';') || (*ptr == '}')) {
		/*
		 *	Only unlang sections can have module references.
		 *
		 *	We also allow bare words in edit lists, where the RHS is a list of values.
		 *
		 *	@todo - detail "suppress" requires bare words :(
		 */
		parent->allow_locals = false;
		value_token = T_INVALID;
		op_token = T_OP_EQ;
		value = NULL;
		goto alloc_pair;
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
	 *	Parse the thing after the first word.  It can be an operator, or the second name for a section.
	 */
	ptr2 = ptr;
	switch (parent->unlang) {
	default:
		/*
		 *	Configuration sections can only have '=' after the
		 *	first word, OR a second word which is the second name
		 *	of a configuration section.
		 */
		if (*ptr == '=') goto operator;

		/*
		 *	Section name2 can only be alphanumeric or UTF-8.
		 */
	parse_name2:
		if (!(isalpha((uint8_t) *ptr) || isdigit((uint8_t) *ptr) || (*(uint8_t const *) ptr >= 0x80))) {
			/*
			 *	Maybe they missed a closing brace somewhere?
			 */
			name2_token = gettoken(&ptr, buff[2], stack->bufsize, false); /* can't be EOL */
			if (fr_assignment_op[name2_token]) {
				return parse_error(stack, ptr2, "Unexpected operator, was expecting a configuration section.  Is there a missing '}' somewhere?");
			}

			return parse_error(stack, ptr2, "Invalid second name for configuration section");
		}

		name2_token = gettoken(&ptr, buff[2], stack->bufsize, false); /* can't be EOL */
		if (name1_token == T_INVALID) {
			return parse_error(stack, ptr2, fr_strerror());
		}

		if (name1_token != T_BARE_WORD) {
			return parse_error(stack, ptr2, "Unexpected quoted string after section name");
		}

		fr_skip_whitespace(ptr);

		if (*ptr != '{') {
			return parse_error(stack, ptr, "Missing '{' for configuration section");
		}

		ptr++;
		value = buff[2];
		goto alloc_section;

	case CF_UNLANG_ASSIGNMENT:
		/*
		 *	The next thing MUST be an operator.  We don't support nested attributes in "update" or
		 *	"map" sections.
		 */
		goto operator;

	case CF_UNLANG_EDIT:
		/*
		 *	The next thing MUST be an operator.  Edit sections always do operations, even on
		 *	lists.  i.e. there is no second name section when editing a list.
		 */
		goto operator;

	case CF_UNLANG_ALLOW:
		/*
		 *	'case ::foo' is allowed.  For generality, we just expect that the second argument to
		 *	'case' is not an operator.
		 */
		if ((strcmp(buff[1], "case") == 0) ||
		    (strcmp(buff[1], "limit") == 0) ||
		    (strcmp(buff[1], "timeout") == 0)) {
			break;
		}

		/*
		 *	It's not a string, bare word, or attribute reference.  It must be an operator.
		 */
		if (!((*ptr == '"') || (*ptr == '`') || (*ptr == '\'') || ((*ptr == '&') && (ptr[1] != '=')) ||
		      ((*((uint8_t const *) ptr) & 0x80) != 0) || isalpha((uint8_t) *ptr) || isdigit((uint8_t) *ptr))) {
			goto operator;
		}
		break;
	}

	/*
	 *	The second name could be a bare word, xlat expansion, string etc.
	 */
	if (cf_get_token(parent, &ptr, &name2_token, buff[2], stack->bufsize,
			 frame->filename, frame->lineno) < 0) {
		return -1;
	}

	if (*ptr != '{') {
		return parse_error(stack, ptr, "Expected '{'");
	}
	ptr++;
	value = buff[2];

alloc_section:
	parent->allow_locals = false;

	/*
	 *	@policy foo { ...}
	 *
	 *	Means "add foo to the policy section".  And if
	 *	policy{} doesn't exist, create it, and then mark up
	 *	policy{} with a flag "we need to merge it", so that
	 *	when we read the actual policy{}, we merge the
	 *	contents together, instead of creating a second
	 *	policy{}.
	 *
	 *	@todo - allow for '.' in @.ref  Or at least test it. :(
	 *
	 *	@todo - allow for two section names @ref foo bar {...}
	 *
	 *	@todo - maybe we can use this to overload things in
	 *	virtual servers, and in modules?
	 */
	if (buff[1][0] == '@') {
		CONF_ITEM *ci;
		CONF_SECTION *root;
		char const *name = &buff[1][1];

		if (!value) {
			ERROR("%s[%d]: Missing section name for reference", frame->filename, frame->lineno);
			return -1;
		}

		root = cf_root(parent);

		ci = cf_reference_item(root, parent, name);
		if (!ci) {
			if (name[1] == '.') {
				PERROR("%s[%d]: Failed finding reference \"%s\"", frame->filename, frame->lineno, name);
				return -1;
			}

			css = cf_section_alloc(root, root, name, NULL);
			if (!css) goto oom;

			cf_filename_set(css, frame->filename);
			cf_lineno_set(css, frame->lineno);
			css->name2_quote = name2_token;
			css->unlang = CF_UNLANG_NONE;
			css->allow_locals = false;
			css->at_reference = true;
			parent = css;

			/*
			 *	Copy this code from below. :(
			 */
			if (cf_item_to_section(parent->item.parent) == root) {
				if (strcmp(css->name1, "server") == 0) css->unlang = CF_UNLANG_SERVER;
				if (strcmp(css->name1, "policy") == 0) css->unlang = CF_UNLANG_POLICY;
				if (strcmp(css->name1, "modules") == 0) css->unlang = CF_UNLANG_MODULES;
				if (strcmp(css->name1, "templates") == 0) css->unlang = CF_UNLANG_CAN_HAVE_UPDATE;
			}

		} else {
			if (!cf_item_is_section(ci)) {
				ERROR("%s[%d]: Reference \"%s\" is not a section", frame->filename, frame->lineno, name);
				return -1;
			}

			/*
			 *	Set the new parent and ensure we're
			 *	not creating a duplicate section.
			 */
			parent = cf_item_to_section(ci);
			css = cf_section_find(parent, value, NULL);
			if (css) {
				ERROR("%s[%d]: Reference \"%s\" already contains a \"%s\" section at %s[%d]",
				      frame->filename, frame->lineno, name, value,
				      css->item.filename, css->item.lineno);
				return -1;
			}
		}

		/*
		 *	We're processing a section.  The @reference is
		 *	OUTSIDE of this section.
		 */
		fr_assert(frame->current == frame->parent);
		frame->at_reference = frame->parent;
		name2_token = T_BARE_WORD;

		css = cf_section_alloc(parent, parent, value, NULL);
	} else {
		/*
		 *	Check if there's already an auto-created
		 *	section of this name.  If so, just use that
		 *	section instead of allocating a new one.
		 */
		css = cf_section_find(parent, buff[1], value);
		if (css && css->at_reference) {
			css->at_reference = false;
		} else {
			css = cf_section_alloc(parent, parent, buff[1], value);
		}
	}

	if (!css) {
	oom:
		ERROR("%s[%d]: Failed allocating memory for section",
		      frame->filename, frame->lineno);
		return -1;
	}

	cf_filename_set(css, frame->filename);
	cf_lineno_set(css, frame->lineno);
	css->name2_quote = name2_token;
	css->unlang = CF_UNLANG_NONE;
	css->allow_locals = false;

	/*
	 *	Only a few top-level sections allow "unlang"
	 *	statements.  And for those, "unlang"
	 *	statements are only allowed in child
	 *	subsection.
	 */
	switch (parent->unlang) {
	case CF_UNLANG_NONE:
		if (!parent->item.parent) {
			if (strcmp(css->name1, "server") == 0) css->unlang = CF_UNLANG_SERVER;
			if (strcmp(css->name1, "policy") == 0) css->unlang = CF_UNLANG_POLICY;
			if (strcmp(css->name1, "modules") == 0) css->unlang = CF_UNLANG_MODULES;
			if (strcmp(css->name1, "templates") == 0) css->unlang = CF_UNLANG_CAN_HAVE_UPDATE;

		} else if ((cf_item_to_section(parent->item.parent)->unlang == CF_UNLANG_MODULES) &&
			   (strcmp(css->name1, "update") == 0)) {
			/*
			 *	Module configuration can contain "update" statements.
			 */
			css->unlang = CF_UNLANG_ASSIGNMENT;
			css->allow_locals = false;
		}
		break;

		/*
		 *	It's a policy section - allow unlang inside of child sections.
		 */
	case CF_UNLANG_POLICY:
		css->unlang = CF_UNLANG_ALLOW;
		css->allow_locals = true;
		break;

		/*
		 *	A virtual server has processing sections, but only a limited number of them.
		 *	Rather than trying to autoload them and glue the interpreter into the conf
		 *	file parser, we just hack it.
		 */
	case CF_UNLANG_SERVER:
		// git grep SECTION_NAME src/process/ src/lib/server/process.h | sed 's/.*SECTION_NAME("//;s/",.*//' | sort -u
		if (fr_table_value_by_str(server_unlang_section, css->name1, false)) {
			css->unlang = CF_UNLANG_ALLOW;
			css->allow_locals = true;
			break;
		}

		/*
		 *	Allow local variables, but no unlang statements.
		 */
		if (strcmp(css->name1, "dictionary") == 0) {
			css->unlang = CF_UNLANG_DICTIONARY;
			css->allow_locals = true;
			break;
		}

		/*
		 *	ldap sync has "update" a few levels down.
		 */
		if (strcmp(css->name1, "listen") == 0) {
			css->unlang = CF_UNLANG_CAN_HAVE_UPDATE;
		}
		break;

		/*
		 *	Virtual modules in the "modules" section can have unlang.
		 */
	case CF_UNLANG_MODULES:
		if ((strcmp(css->name1, "group") == 0) ||
		    (strcmp(css->name1, "load-balance") == 0) ||
		    (strcmp(css->name1, "redundant") == 0) ||
		    (strcmp(css->name1, "redundant-load-balance") == 0)) {
			css->unlang = CF_UNLANG_ALLOW;
			css->allow_locals = true;
		} else {
			css->unlang = CF_UNLANG_CAN_HAVE_UPDATE;
		}
		break;

	case CF_UNLANG_EDIT:
		/*
		 *	Edit sections can only have children which are edit sections.
		 */
		css->unlang = CF_UNLANG_EDIT;
		break;

	case CF_UNLANG_ALLOW:
		/*
		 *	If we are doing list assignment, then don't allow local variables.  The children are
		 *	also then all edit sections, and not unlang statements.
		 *
		 *	If we're not doing list assignment, then name2 has to be a bare word, string, etc.
		 */
		css->allow_locals = !fr_list_assignment_op[name2_token];
		if (css->allow_locals) {
			/*
			 *	@todo - tighten this up for "actions" sections, and module rcode
			 *	over-rides.
			 *
			 *	Perhaps the best way to do that is to change the syntax for module
			 *	over-rides, so that the parser doesn't have to guess.  :(
			 */
			css->unlang = CF_UNLANG_ALLOW;
		} else {
			css->unlang = CF_UNLANG_EDIT;
		}
		break;

		/*
		 *	We can (maybe?) do nested assignments inside of an old-style "update" or "map" section
		 */
	case CF_UNLANG_ASSIGNMENT:
		css->unlang = CF_UNLANG_ASSIGNMENT;
		break;

	case CF_UNLANG_DICTIONARY:
		css->unlang = CF_UNLANG_DICTIONARY;
		css->allow_locals = true;
		break;

	case CF_UNLANG_CAN_HAVE_UPDATE:
		if (strcmp(css->name1, "update") == 0) {
			css->unlang = CF_UNLANG_ASSIGNMENT;
		} else {
			css->unlang = CF_UNLANG_CAN_HAVE_UPDATE;
		}
		break;
	}

add_section:
	/*
	 *	The current section is now the child section.
	 */
	frame->current = css;
	frame->braces++;
	css = NULL;
	stack->ptr = ptr;
	return 1;


	/*
	 *	If we're not parsing a section, then the next
	 *	token MUST be an operator.
	 */
operator:
	ptr2 = ptr;
	name2_token = gettoken(&ptr, buff[2], stack->bufsize, false);
	switch (name2_token) {
	case T_OP_ADD_EQ:
	case T_OP_SUB_EQ:
	case T_OP_AND_EQ:
	case T_OP_OR_EQ:
	case T_OP_NE:
	case T_OP_RSHIFT_EQ:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LSHIFT_EQ:
	case T_OP_LE:
	case T_OP_LT:
	case T_OP_CMP_EQ:
	case T_OP_CMP_FALSE:
	case T_OP_SET:
	case T_OP_PREPEND:
		/*
		 *	Allow more operators in unlang statements, edit sections, and old-style "update" sections.
		 */
		if ((parent->unlang != CF_UNLANG_ALLOW) && (parent->unlang != CF_UNLANG_EDIT) && (parent->unlang != CF_UNLANG_ASSIGNMENT)) {
			return parse_error(stack, ptr2, "Invalid operator for assignment");
		}
		FALL_THROUGH;

	case T_OP_EQ:
		/*
		 *	Configuration variables can only use =
		 */
		fr_skip_whitespace(ptr);
		op_token = name2_token;
		break;

	default:
		return parse_error(stack, ptr2, "Syntax error, the input should be an assignment operator");
	}

	/*
	 *	MUST have something after the operator.
	 */
	if (!*ptr || (*ptr == '#') || (*ptr == ',') || (*ptr == ';')) {
		return parse_error(stack, ptr, "Missing value after operator");
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
		if ((parent->unlang != CF_UNLANG_ALLOW) && (parent->unlang != CF_UNLANG_EDIT)) {
			return parse_error(stack, ptr, "Invalid location for nested attribute assignment");
		}

		if (!fr_list_assignment_op[name2_token]) {
			return parse_error(stack, ptr, "Invalid assignment operator for list");
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

	fr_skip_whitespace(ptr);

	/*
	 *	Parse the value for a CONF_PAIR.
	 *
	 *	If it's unlang or an edit section, the RHS can be an expression.
	 */
	if ((parent->unlang == CF_UNLANG_ALLOW) || (parent->unlang == CF_UNLANG_EDIT)) {
		bool eol;
		ssize_t slen;

		ptr2 = ptr;

		/*
		 *	If the RHS is an expression (foo) or function %foo(), then mark it up as an expression.
		 */
		if ((*ptr == '(') || (*ptr == '%')) {
			/* nothing  */

		} else if (cf_get_token(parent, &ptr2, &value_token, buff[2], stack->bufsize,
					frame->filename, frame->lineno) == 0) {
			/*
			 *	We have one token (bare word), followed by EOL.  It's just a token.
			 */
			fr_skip_whitespace(ptr2);
			if (terminal_end_line[(uint8_t) *ptr2]) {
				parent->allow_locals = false;
				ptr = ptr2;
				value = buff[2];
				goto alloc_pair;
			}
		} /* else it looks like an expression */

		/*
		 *	Parse the text as an expression.
		 *
		 *	Note that unlike conditions, expressions MUST use \ at the EOL for continuation.
		 *	If we automatically read past EOL, as with:
		 *
		 *		&foo := (bar -
		 *			 baz)
		 *
		 *	That works, mostly.  Until the user forgets to put the trailing ')', and then
		 *	the parse is bad enough that it tries to read to EOF, or to some other random
		 *	parse error.
		 *
		 *	So the simplest way to avoid utter craziness is to simply require a signal which
		 *	says "yes, I intended to put this over multiple lines".
		 */
		slen = fr_skip_condition(ptr, NULL, terminal_end_line, &eol);
		if (slen < 0) {
			return parse_error(stack, ptr + (-slen), fr_strerror());
		}

		/*
		 *	We parsed until the end of the string, but the condition still needs more data.
		 */
		if (eol) {
			return parse_error(stack, ptr + slen, "Expression is unfinished at end of line");
		}

		/*
		 *	Keep a copy of the entire RHS.
		 */
		memcpy(buff[2], ptr, slen);
		buff[2][slen] = '\0';

		value = buff[2];

		/*
		 *	Mark it up as an expression
		 *
		 *	@todo - we should really just call cf_data_add() to add a flag, but this is good for
		 *	now.  See map_afrom_cp()
		 */
		value_token = T_HASH;

		/*
		 *	Skip terminal characters
		 */
		ptr += slen;
		if ((*ptr == ',') || (*ptr == ';')) ptr++;

#if 0
	} else if ((parent->unlang != CF_UNLANG_ASSIGNMENT) &&
		   ((*ptr == '`') || (*ptr == '%') || (*ptr == '('))) {
		/*
		 *	Config sections can't use backticks, xlat expansions, or expressions.
		 *
		 *	Except module configurations can have key = %{...}
		 */
		return parse_error(stack, ptr, "Invalid value for assignment in configuration file");
#endif

	} else {
		if (cf_get_token(parent, &ptr, &value_token, buff[2], stack->bufsize,
				 frame->filename, frame->lineno) < 0) {
			return -1;
		}
		value = buff[2];
	}

	/*
	 *	We have an attribute assignment, which means that we no longer allow local variables to be
	 *	defined.
	 */
	parent->allow_locals = false;

alloc_pair:
	if (add_pair(parent, buff[1], value, name1_token, op_token, value_token, buff[3], frame->filename, frame->lineno) < 0) return -1;

added_pair:
	fr_skip_whitespace(ptr);

	/*
	 *	Skip semicolon if we see it after a
	 *	CONF_PAIR.  Also allow comma for
	 *	backwards compatibility with secret
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
		return parse_error(stack, ptr, "Unexpected text after configuration item");
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
	CONF_SECTION *parent = frame->current;
	cf_file_heap_t *h;

	h = fr_heap_pop(&frame->heap);
	if (!h) {
		/*
		 *	Done reading the directory entry.  Close it, and go
		 *	back up a stack frame.
		 */
		talloc_free(frame->directory);
		stack->depth--;
		return 1;
	}

	/*
	 *	Push the next filename onto the stack.
	 */
	stack->depth++;
	frame = &stack->frame[stack->depth];
	memset(frame, 0, sizeof(*frame));

	frame->type = CF_STACK_FILE;
	frame->fp = NULL;
	frame->parent = parent;
	frame->current = parent;
	frame->filename = h->filename;
	frame->lineno = 0;
	frame->from_dir = true;
	return 1;
}


static fr_md5_ctx_t *cf_md5_ctx = NULL;

void cf_md5_init(void)
{
	cf_md5_ctx = fr_md5_ctx_alloc();
}


static void cf_md5_update(char const *p)
{
	if (!cf_md5_ctx) return;

	fr_md5_update(cf_md5_ctx, (uint8_t const *)p, strlen(p));
}

void cf_md5_final(uint8_t *digest)
{
	if (!cf_md5_ctx) {
		memset(digest, 0, MD5_DIGEST_LENGTH);
		return;
	}

	fr_md5_final(digest, cf_md5_ctx);
	fr_md5_ctx_free(&cf_md5_ctx);
	cf_md5_ctx = NULL;
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
	cf_md5_update(stack->fill);
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

	cf_stack_frame_t	*frame;
	int		rcode;

do_frame:
	frame = &stack->frame[stack->depth];
	parent = frame->current; /* add items here */

	switch (frame->type) {
#ifdef HAVE_GLOB_H
	case CF_STACK_GLOB:
		if (frame->gl_current == frame->glob.gl_pathc) {
			globfree(&frame->glob);
			goto pop_stack;
		}

		/*
		 *	Process the filename as an include.
		 */
		if (process_include(stack, parent, frame->glob.gl_pathv[frame->gl_current++], frame->required, false) < 0) return -1;

		/*
		 *	Run the correct frame.  If the file is NOT
		 *	required, then the call to process_include()
		 *	may return 0, and we just process the next
		 *	glob.  Otherwise, the call to
		 *	process_include() may return a directory or a
		 *	filename.  Go handle that.
		 */
		goto do_frame;
#endif

#ifdef HAVE_DIRENT_H
	case CF_STACK_DIR:
		rcode = frame_readdir(stack);
		if (rcode == 0) goto do_frame;
		if (rcode < 0) return -1;

		/*
		 *	Reset which frame we're looking at.
		 */
		frame = &stack->frame[stack->depth];
		fr_assert(frame->type == CF_STACK_FILE);
		break;
#endif

	case CF_STACK_FILE:
		break;
	}

#ifndef NDEBUG
	/*
	 *	One last sanity check.
	 */
	if (frame->type != CF_STACK_FILE) {
		cf_log_err(frame->current, "%s: Internal sanity check failed", __FUNCTION__);
		goto pop_stack;
	}
#endif

	/*
	 *	Open the new file if necessary.  It either came from
	 *	the first call to the function, or was pushed onto the
	 *	stack by another function.
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

				if (process_include(stack, parent, ptr, true, true) < 0) return -1;
				goto do_frame;
			}

			if (strncasecmp(ptr, "$-INCLUDE", 9) == 0) {
				ptr += 9;

				rcode = process_include(stack, parent, ptr, false, true);
				if (rcode < 0) return -1;
				if (rcode == 0) continue;
				goto do_frame;
			}

			/*
			 *	Allow for $TEMPLATE things
			 */
			if (strncasecmp(ptr, "$TEMPLATE", 9) == 0) {
				ptr += 9;
				fr_skip_whitespace(ptr);

				stack->ptr = ptr;
				if (process_template(stack) < 0) return -1;
				continue;
			}

			return parse_error(stack, ptr, "Unknown $... keyword");
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

	fr_assert(frame->fp != NULL);

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
		switch (frame->type) {
		case CF_STACK_FILE:
			if (frame->fp) fclose(frame->fp);
			frame->fp = NULL;
			break;

#ifdef HAVE_DIRENT_H
		case CF_STACK_DIR:
			talloc_free(frame->directory);
			break;
#endif

#ifdef HAVE_GLOB_H
		case CF_STACK_GLOB:
			globfree(&frame->glob);
			break;
#endif
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
	fr_rb_tree_t	*tree;
	cf_stack_t	stack;
	cf_stack_frame_t	*frame;

	cp = cf_pair_alloc(cs, "confdir", filename, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
	if (!cp) return -1;

	p = strrchr(cp->value, FR_DIR_SEP);
	if (p) *p = '\0';

	MEM(tree = fr_rb_inline_talloc_alloc(cs, cf_file_t, node, _inode_cmp, NULL));

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

	frame->type = CF_STACK_FILE;
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

static char const parse_tabs[] = "																																																																																																																																																																																																								";

static ssize_t cf_string_write(FILE *fp, char const *string, size_t len, fr_token_t t)
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
		fputs(" ", fp);

#if 0
		c = cf_data_value(cf_data_find(cs, fr_cond_t, NULL));
		if (c) {
			char buffer[1024];

			cond_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), c);
			fprintf(fp, "(%s)", buffer);
		} else
#endif
			cf_string_write(fp, cs->name2, strlen(cs->name2), cs->name2_quote);
	}

	fputs(" {\n", fp);

	/*
	 *	Loop over the children.  Either recursing, or opening
	 *	a new file.
	 */
	cf_item_foreach(&cs->item, ci) {
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
	char			name[8192], *p;
	char const		*name2;

	if (!ptr || (!parent_cs && !outer_cs)) {
		fr_strerror_const("Invalid argument");
		return NULL;
	}

	if (!*ptr) {
		fr_strerror_const("Empty string is invalid");
		return NULL;
	}

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
		if (*p == '\0') return cf_section_to_item(cs); /* const issues */

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
			if (!*++p) return cf_section_to_item(cs); /* const issues */
		}

		/*
		 *	"foo.bar.baz" means "from the given root"
		 */
	} else if (strchr(p, '.') != NULL) {
		if (!parent_cs) {
		missing_parent:
			fr_strerror_const("Missing parent configuration section");
			return NULL;
		}
		cs = parent_cs;

		/*
		 *	"foo" could be from the current section, either as a
		 *	section or as a pair.
		 *
		 *	If that isn't found, search from the given root.
		 */
	} else {
		next = cf_section_find(cs, p, NULL);
		if (!next && cs->template) next = cf_section_find(cs->template, p, NULL);
		if (next) return &(next->item);

		cp = cf_pair_find(cs, p);
		if (!cp && cs->template) cp = cf_pair_find(cs->template, p);
		if (cp) return &(cp->item);

		if (!parent_cs) goto missing_parent;
		cs = parent_cs;
	}

	/*
	 *	Chop the string into pieces, and look up the pieces.
	 */
	while (*p) {
		char *n1, *n2, *q;

		n1 = p;
		n2 = NULL;
		q = p;

		fr_assert(*q);

		/*
		 *	Look for a terminating '.' or '[', to get name1 and possibly name2.
		 */
		while (*q != '\0') {
			/*
			 *	foo.bar -> return "foo"
			 */
			if (*q == '.') {
				*q++ = '\0'; /* leave 'q' after the '.' */
				break;
			}

			/*
			 *	name1 is anything up to '[' or EOS.
			 */
			if (*q != '[') {
				q++;
				continue;
			}

			/*
			 *	Found "name1[", look for "name2]" or "name2]."
			 */
			*q++ = '\0';
			n2 = q;

			while (*q != '\0') {
				if (*q == '[') {
					fr_strerror_const("Invalid reference, '[' cannot be used inside of a '[...]' block");
					return NULL;
				}

				if (*q != ']') {
					q++;
					continue;
				}

				/*
				 *	We've found the trailing ']'
				 */
				*q++ = '\0';

				/*
				 *	"name2]"
				 */
				if (!*q) break;

				/*
				 *	Must be "name2]."
				 */
				if (*q++ == '.') break;

				fr_strerror_const("Invalid reference, ']' is not followed by '.'");
				return NULL;
			}

			if (n2) break;

			/*
			 *	"name1[name2", but not "name1[name2]"
			 */
			fr_strerror_printf("Invalid reference after '%s', missing close ']'", n2);
			return NULL;
		}
		p = q;		/* get it ready for the next round */

		/*
		 *	End of the string.  The thing could be a section with
		 *	two names, a section with one name, or a pair.
		 *
		 *	And if we don't find the thing we're looking for here,
		 *	check the template section.
		 */
		if (!*p) {
			/*
			 *	Two names, must be a section.
			 */
			if (n2) {
				next = cf_section_find(cs, n1, n2);
				if (!next && cs->template) next = cf_section_find(cs->template, n1, n2);
				if (next) return &(next->item);

			fail:
				name2 = cf_section_name2(cs);
				fr_strerror_printf("Parent section %s%s%s { ... } does not contain a %s %s { ... } configuration section",
						   cf_section_name1(cs),
						   name2 ? " " : "", name2 ? name2 : "",
						   n1, n2);
				return NULL;
			}

			/*
			 *	One name, the final thing can be a section or a pair.
			 */
			next = cf_section_find(cs, n1, NULL);
			if (!next && cs->template) next = cf_section_find(cs->template, n1, NULL);

			if (next) return &(next->item);

			cp = cf_pair_find(cs, n1);
			if (!cp && cs->template) cp = cf_pair_find(cs->template, n1);
			if (cp) return &(cp->item);

			name2 = cf_section_name2(cs);
			fr_strerror_printf("Parent section %s%s%s  { ... } does not contain a %s configuration item",
					   cf_section_name1(cs),
					   name2 ? " " : "", name2 ? name2 : "",
					   n1);
			return NULL;
		}

		/*
		 *	There's more to the string.  The thing we're looking
		 *	for MUST be a configuration section.
		 */
		next = cf_section_find(cs, n1, n2);
		if (!next && cs->template) next = cf_section_find(cs->template, n1, n2);
		if (next) {
			cs = next;
			continue;
		}

		if (n2) goto fail;

		name2 = cf_section_name2(cs);
		fr_strerror_printf("Parent section %s%s%s { ... } does not contain a %s { ... } configuration section",
				   cf_section_name1(cs),
				   name2 ? " " : "", name2 ? name2 : "",
				   n1);
		return NULL;
	}

	/*
	 *	We've fallen off of the end of the string.  This should not have happened!
	 */
	fr_strerror_const("Cannot parse reference");
	return NULL;
}

/*
 *	Only for unit_test_map
 */
void cf_section_set_unlang(CONF_SECTION *cs)
{
	fr_assert(cs->unlang == CF_UNLANG_NONE);
	fr_assert(!cs->item.parent);

	cs->unlang = CF_UNLANG_ALLOW;
}
