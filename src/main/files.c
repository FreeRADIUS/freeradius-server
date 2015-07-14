/*
 * files.c	Read config files into memory.
 *
 * Version:     $Id$
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
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>

/*
 *	Debug code.
 */
#if 0
static void debug_pair_list(PAIR_LIST *pl)
{
	VALUE_PAIR *vp;

	while(pl) {
		printf("Pair list: %s\n", pl->name);
		printf("** Check:\n");
		for(vp = pl->check; vp; vp = vp->next) {
			printf("    ");
			fprint_attr_val(stdout, vp);
			printf("\n");
		}
		printf("** Reply:\n");
		for(vp = pl->reply; vp; vp = vp->next) {
			printf("    ");
			fprint_attr_val(stdout, vp);
			printf("\n");
		}
		pl = pl->next;
	}
}
#endif

/*
 *	Free a PAIR_LIST
 */
void pairlist_free(PAIR_LIST **pl)
{
	talloc_free(*pl);
	*pl = NULL;
}


#define FIND_MODE_NAME  0
#define FIND_MODE_WANT_REPLY 1
#define FIND_MODE_HAVE_REPLY 2

/*
 *	Read the users, huntgroups or hints file.
 *	Return a PAIR_LIST.
 */
int pairlist_read(TALLOC_CTX *ctx, char const *file, PAIR_LIST **list, int complain)
{
	FILE *fp;
	int mode = FIND_MODE_NAME;
	char entry[256];
	char buffer[8192];
	char const *ptr;
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	PAIR_LIST *pl = NULL, *t;
	PAIR_LIST **last = &pl;
	int lineno = 0;
	int entry_lineno = 0;
	FR_TOKEN parsecode;
#ifdef HAVE_REGEX_H
	VALUE_PAIR *vp;
	vp_cursor_t cursor;
#endif
	char newfile[8192];

	DEBUG2("reading pairlist file %s", file);

	/*
	 *	Open the file.  The error message should be a little
	 *	more useful...
	 */
	if ((fp = fopen(file, "r")) == NULL) {
		if (!complain)
			return -1;
		ERROR("Couldn't open %s for reading: %s",
				file, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Read the entire file into memory for speed.
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		lineno++;

		if (!feof(fp) && (strchr(buffer, '\n') == NULL)) {
			fclose(fp);
			ERROR("%s[%d]: line too long", file, lineno);
			pairlist_free(&pl);
			return -1;
		}

		/*
		 *	If the line contains nothing but whitespace,
		 *	ignore it.
		 */
		ptr = buffer;
		while (isspace((int) *ptr)) ptr++;

		if (*ptr == '#' || *ptr == '\n' || !*ptr) continue;

parse_again:
		if (mode == FIND_MODE_NAME) {
			/*
			 *	The user's name MUST be the first text on the line.
			 */
			if (isspace((int) buffer[0]))  {
				ERROR("%s[%d]: Entry does not begin with a user name",
				      file, lineno);
				fclose(fp);
				return -1;
			}

			/*
			 *	Get the name.
			 */		      
			ptr = buffer;
			getword(&ptr, entry, sizeof(entry), false);
			entry_lineno = lineno;

			/*
			 *	Include another file if we see
			 *	$INCLUDE filename
			 */
			if (strcasecmp(entry, "$INCLUDE") == 0) {
				while (isspace((int) *ptr)) ptr++;

				/*
				 *	If it's an absolute pathname,
				 *	then use it verbatim.
				 *
				 *	If not, then make the $include
				 *	files *relative* to the current
				 *	file.
				 */
				if (FR_DIR_IS_RELATIVE(ptr)) {
					char *p;

					strlcpy(newfile, file,
						sizeof(newfile));
					p = strrchr(newfile, FR_DIR_SEP);
					if (!p) {
						p = newfile + strlen(newfile);
						*p = FR_DIR_SEP;
					}
					getword(&ptr, p + 1, sizeof(newfile) - 1 - (p - newfile), false);
				} else {
					getword(&ptr, newfile, sizeof(newfile), false);
				}

				t = NULL;

				if (pairlist_read(ctx, newfile, &t, 0) != 0) {
					pairlist_free(&pl);
					ERROR("%s[%d]: Could not open included file %s: %s",
					       file, lineno, newfile, fr_syserror(errno));
					fclose(fp);
					return -1;
				}
				*last = t;

				/*
				 *	t may be NULL, it may have one
				 *	entry, or it may be a linked list
				 *	of entries.  Go to the end of the
				 *	list.
				 */
				while (*last)
					last = &((*last)->next);
				continue;
			} /* $INCLUDE ... */

			/*
			 *	Parse the check values
			 */
			rad_assert(check_tmp == NULL);
			rad_assert(reply_tmp == NULL);
			parsecode = fr_pair_list_afrom_str(ctx, ptr, &check_tmp);
			if (parsecode == T_INVALID) {
				pairlist_free(&pl);
				ERROR("%s[%d]: Parse error (check) for entry %s: %s",
					file, lineno, entry, fr_strerror());
				fclose(fp);
				return -1;
			}

			if (parsecode != T_EOL) {
				pairlist_free(&pl);
				talloc_free(check_tmp);
				ERROR("%s[%d]: Invalid text after check attributes for entry %s",
				      file, lineno, entry);
				fclose(fp);
				return -1;
			}

#ifdef HAVE_REGEX_H
			/*
			 *	Do some more sanity checks.
			 */
			for (vp = fr_cursor_init(&cursor, &check_tmp);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
				if (((vp->op == T_OP_REG_EQ) ||
				     (vp->op == T_OP_REG_NE)) &&
				    (vp->da->type != PW_TYPE_STRING)) {
					pairlist_free(&pl);
					talloc_free(check_tmp);
					ERROR("%s[%d]: Cannot use regular expressions for non-string attributes in entry %s",
					      file, lineno, entry);
					fclose(fp);
					return -1;
				}
			}
#endif

			/*
			 *	The reply MUST be on a new line.
			 */
			mode = FIND_MODE_WANT_REPLY;
			continue;
		}

		/*
		 *	We COULD have a reply, OR we could have a new entry.
		 */
		if (mode == FIND_MODE_WANT_REPLY) {
			if (!isspace((int) buffer[0])) goto create_entry;

			mode = FIND_MODE_HAVE_REPLY;
		}

		/*
		 *	mode == FIND_MODE_HAVE_REPLY
		 */

		/*
		 *	The previous line ended with a comma, and then
		 *	we have the start of a new entry!
		 */
		if (!isspace((int) buffer[0])) {
		trailing_comma:
			pairlist_free(&pl);
			talloc_free(check_tmp);
			talloc_free(reply_tmp);
			ERROR("%s[%d]: Invalid comma after the reply attributes.  Please delete it.",
			      file, lineno);
			fclose(fp);
			return -1;
		}

		/*
		 *	Parse the reply values.  If there's a trailing
		 *	comma, keep parsing the reply values.
		 */
		parsecode = fr_pair_list_afrom_str(ctx, buffer, &reply_tmp);
		if (parsecode == T_COMMA) {
			continue;
		}

		/*
		 *	We expect an EOL.  Anything else is an error.
		 */
		if (parsecode != T_EOL) {
			pairlist_free(&pl);
			talloc_free(check_tmp);
			talloc_free(reply_tmp);
			ERROR("%s[%d]: Parse error (reply) for entry %s: %s",
			      file, lineno, entry, fr_strerror());
			fclose(fp);
			return -1;
		}

	create_entry:
		/*
		 *	Done with this entry...
		 */
		MEM(t = talloc_zero(ctx, PAIR_LIST));

		if (check_tmp) fr_pair_steal(t, check_tmp);
		if (reply_tmp) fr_pair_steal(t, reply_tmp);

		t->check = check_tmp;
		t->reply = reply_tmp;
		t->lineno = entry_lineno;
		check_tmp = NULL;
		reply_tmp = NULL;

		t->name = talloc_typed_strdup(t, entry);

		*last = t;
		last = &(t->next);

		/*
		 *	Look for a name.  If we came here because
		 *	there were no reply attributes, then re-parse
		 *	the current line, instead of reading another one.
		 */
		mode = FIND_MODE_NAME;
		if (feof(fp)) break;
		if (!isspace((int) buffer[0])) goto parse_again;
	}

	/*
	 *	We're at EOF.  If we're supposed to read more, that's
	 *	an error.
	 */
	if (mode == FIND_MODE_HAVE_REPLY) goto trailing_comma;

	/*
	 *	We had an entry, but no reply attributes.  That's OK.
	 */
	if (mode == FIND_MODE_WANT_REPLY) goto create_entry;

	/*
	 *	Else we were looking for an entry.  We didn't get one
	 *	because we were at EOF, so that's OK.
	 */

	fclose(fp);

	*list = pl;
	return 0;
}
