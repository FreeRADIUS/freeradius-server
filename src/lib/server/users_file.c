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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/users_file.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>

static inline void line_error_marker(char const *src_file, int src_line,
				     char const *user_file, int user_line,
				     fr_sbuff_t *sbuff, char const *error)
{
	char			*end;
	fr_sbuff_marker_t	start;

	fr_sbuff_marker(&start, sbuff);
	end = fr_sbuff_adv_to_chr(sbuff, SIZE_MAX, '\n');
	if (!end) end = fr_sbuff_end(sbuff);
	fr_sbuff_set(sbuff, &start);

	fr_log_marker(LOG_DST, L_ERR, src_file, src_line,
		      fr_sbuff_start(sbuff), end - fr_sbuff_start(sbuff),
		      fr_sbuff_used(sbuff), error, "%s[%d]: ", user_file, user_line);
}
/** Print out a line oriented error marker at the current position of the sbuff
 *
 * @param[in] _sbuff	to print error for.
 * @param[in] _error	message.
 */
#define ERROR_MARKER(_sbuff, _error) line_error_marker(__FILE__, __LINE__, file, lineno, _sbuff, _error)

static inline void line_error_marker_adj(char const *src_file, int src_line,
					 char const *user_file, int user_line,
					 fr_sbuff_t *sbuff, ssize_t marker_idx, char const *error)
{
	char			*end;
	fr_sbuff_marker_t	start;

	fr_sbuff_marker(&start, sbuff);
	end = fr_sbuff_adv_to_chr(sbuff, SIZE_MAX, '\n');
	if (!end) end = fr_sbuff_end(sbuff);
	fr_sbuff_set(sbuff, &start);

	fr_log_marker(LOG_DST, L_ERR, src_file, src_line,
		      fr_sbuff_current(sbuff), end - fr_sbuff_current(sbuff),
		      marker_idx, error, "%s[%d]: ", user_file, user_line);
}
/** Print out a line oriented error marker relative to the current position of the sbuff
 *
 * @param[in] _sbuff	to print error for.
 * @param[in] _idx	Where the error occurred.
 * @param[in] _error	message.
 */
#define ERROR_MARKER_ADJ(_sbuff, _idx, _error) line_error_marker_adj(__FILE__, __LINE__, file, lineno, _sbuff, _idx, _error)

/*
 *	Free a PAIR_LIST
 */
void pairlist_free(PAIR_LIST_LIST *pl)
{
	talloc_free(pl);
}

static fr_table_num_sorted_t const check_cmp_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
	{ L("+="),	T_OP_ADD		},
	{ L(":="),	T_OP_SET		},
	{ L("<"),	T_OP_LT			},
	{ L("<="),	T_OP_LE			},
	{ L("="),	T_OP_EQ			},
	{ L("=*"),	T_OP_CMP_TRUE		},
	{ L("=="),	T_OP_CMP_EQ		},
	{ L("=~"),	T_OP_REG_EQ		},
	{ L(">"),	T_OP_GT			},
	{ L(">="),	T_OP_GE			}
};
static size_t check_cmp_op_table_len = NUM_ELEMENTS(check_cmp_op_table);

static const fr_sbuff_term_t name_terms = FR_SBUFF_TERMS(
		L("\t"),
		L("\n"),
		L(" "),
		L("#"),
);

static fr_sbuff_parse_rules_t const rhs_term = {
	.escapes = &(fr_sbuff_unescape_rules_t){
		.chr = '\\',
		/*
		 *	Allow barewords to contain whitespace
		 *	if they're escaped.
		 */
		.subs = {
			['\t'] = '\t',
			['\n'] = '\n',
			[' '] = ' '
		},
		.do_hex = true,
		.do_oct = false
	},
	.terminals = &FR_SBUFF_TERMS(
		L(""),
		L("\t"),
		L("\n"),
		L("#"),
		L(","),
	)
};

/*
 *	Caller saw a $INCLUDE at the start of a line.
 */
static int users_include(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_sbuff_t *sbuff, PAIR_LIST_LIST *list,
			 char const *file, int lineno)
{
	size_t		len;
	char		*newfile, *p, c;
	fr_sbuff_marker_t name;

	fr_sbuff_advance(sbuff, 8);

	/*
	 *	Skip spaces after the $INCLUDE.
	 */
	if (fr_sbuff_adv_past_blank(sbuff, SIZE_MAX, NULL) == 0) {
	    	ERROR_MARKER(sbuff, "Unexpected text after $INCLUDE");
		return -1;
	}

	/*
	 *	Remember when the name started, and skip over the name
	 *	until spaces, comments, or LF
	 */
	fr_sbuff_marker(&name, sbuff);
	len = fr_sbuff_adv_until(sbuff, SIZE_MAX, &name_terms, 0);
	if (len == 0) {
	    	ERROR_MARKER(sbuff, "No filename after $INCLUDE");
		fr_sbuff_marker_release(&name);
		return -1;
	}

	/*
	 *	If the input file is a relative path, try to copy the
	 *	leading directory from it.  If there's no leading
	 *	directory, just use the $INCLUDE name as-is.
	 *
	 *	If there is a leading directory in the input name,
	 *	paste that as the directory to the $INCLUDE name.
	 *
	 *	Otherwise the $INCLUDE name is an absolute path, use
	 *	it as -is.
	 */
	c = *fr_sbuff_current(&name);
	if (c != '/') {
		p = strrchr(file, '/');

		if (!p) goto copy_name;

		newfile = talloc_asprintf(NULL, "%.*s/%.*s",
					  (int) (p - file), file,
					  (int) len, fr_sbuff_current(&name));
	} else {
	copy_name:
		newfile = talloc_asprintf(NULL, "%.*s", (int) len, fr_sbuff_current(&name));
	}
	fr_sbuff_marker_release(&name);

	/*
	 *	Skip spaces and comments after the name.
	 */
	fr_sbuff_adv_past_blank(sbuff, SIZE_MAX, NULL);
	if (fr_sbuff_next_if_char(sbuff, '#')) {
		(void) fr_sbuff_adv_to_chr(sbuff, SIZE_MAX, '\n');
	}

	/*
	 *	There's no LF, but if we skip non-spaces and
	 *	non-comments to find the LF, then there must be extra
	 *	text after the filename.  That's an error.
	 *
	 *	Unless the line has EOF after the filename.  in which
	 *	case this error will get hit, too.
	 */
	if (!fr_sbuff_is_char(sbuff, '\n') &&
	    (fr_sbuff_adv_to_chr(sbuff, SIZE_MAX, '\n') != NULL)) {
	    	ERROR_MARKER(sbuff, "Unexpected text after filename");
		talloc_free(newfile);
		return -1;
	}

	/*
	 *	Read the $INCLUDEd file recursively.
	 */
	if (pairlist_read(ctx, dict, newfile, list, 0) != 0) {
		ERROR("%s[%d]: Could not read included file %s: %s",
		      file, lineno, newfile, fr_syserror(errno));
		talloc_free(newfile);
		return -1;
	}
	talloc_free(newfile);

	return 0;
}


/*
 *	Read the users file. Return a PAIR_LIST.
 */
int pairlist_read(TALLOC_CTX *ctx, fr_dict_t const *dict, char const *file, PAIR_LIST_LIST *list, int complain)
{
	char			*q;
	int			order = 0;
	int			lineno		= 1;
	map_t			*new_map;
	FILE			*fp;
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_file_t	fctx;
	tmpl_rules_t		lhs_rules, rhs_rules;
	char			*filename = talloc_strdup(ctx, file);
	char			buffer[8192];

	DEBUG2("Reading file %s", file);

	/*
	 *	Open the file.  The error message should be a little
	 *	more useful...
	 */
	if ((fp = fopen(file, "r")) == NULL) {
		if (!complain) return -1;

		ERROR("Couldn't open %s for reading: %s", file, fr_syserror(errno));
		return -1;
	}

	fr_sbuff_init_file(&sbuff, &fctx, buffer, sizeof(buffer), fp, SIZE_MAX);

	lhs_rules = (tmpl_rules_t) {
		.dict_def = dict,
		.request_def = REQUEST_CURRENT,
		.prefix = TMPL_ATTR_REF_PREFIX_AUTO,
		.disallow_qualifiers = true, /* for now, until more tests are made */

		/*
		 *	Otherwise the tmpl code returns 0 when asked
		 *	to parse unknown names.  So we say "please
		 *	parse unknown names as unresolved attributes",
		 *	and then do a second pass to complain that the
		 *	thing isn't known.
		 */
		.allow_unresolved = true,
	};
	rhs_rules = (tmpl_rules_t) {
		.dict_def = dict,
		.request_def = REQUEST_CURRENT,
		.prefix = TMPL_ATTR_REF_PREFIX_YES,
		.disallow_qualifiers = true, /* for now, until rlm_files supports it */
	};

	while (true) {
		size_t		len;
		ssize_t		slen;
		bool		comma;
		bool		leading_spaces;
		PAIR_LIST	*t;

		/*
		 *	If the line is empty or has only comments,
		 *	then we don't care about leading spaces.
		 */
		leading_spaces = (fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL) > 0);
		if (fr_sbuff_next_if_char(&sbuff, '#')) {
			(void) fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\n');
		}
		if (fr_sbuff_next_if_char(&sbuff, '\n')) {
			lineno++;
			continue;
		}

		/*
		 *	We're trying to read a name.  It MUST have
		 *	been at the start of the line.  So whatever
		 *	this is, it's wrong.
		 */
		if (leading_spaces) {
	    		ERROR_MARKER(&sbuff, "Entry does not begin with a user name");
		fail:
			fclose(fp);
			return -1;
		}

		/*
		 *	$INCLUDE filename
		 */
		if (fr_sbuff_is_str(&sbuff, "$INCLUDE", 8)) {
			/*
			 *	Temporary list for include entries to be read into
			 */
			PAIR_LIST_LIST tmp_list;

			pairlist_list_init(&tmp_list);
			if (users_include(ctx, dict, &sbuff, &tmp_list, file, lineno) < 0) goto fail;

			/*
			 *	The file may have read no entries, one
			 *	entry, or it may be a linked list of
			 *	entries.  Set the order of the entries
			 *	then move them to the end of the main list.
			 */
			t = NULL;
			while ((t = fr_dlist_next(&tmp_list.head, t))) {
				t->order = order++;
			}

			fr_dlist_move(&list->head, &tmp_list.head);

			if (fr_sbuff_next_if_char(&sbuff, '\n')) {
				lineno++;
				continue;
			}

			/*
			 *	The next character is not LF, but the
			 *	function skipped to LF.  So, by
			 *	process of elimination, we must be at
			 *	EOF.
			 */
			break;
		} /* else it wasn't $INCLUDE */

		/*
		 *	We MUST be either at a valid entry, OR at EOF.
		 */
		MEM(t = talloc_zero(ctx, PAIR_LIST));
		fr_map_list_init(&t->check);
		fr_map_list_init(&t->reply);
		t->filename = filename;
		t->lineno = lineno;
		t->order = order++;

		/*
		 *	Copy the name from the entry.
		 */
		len = fr_sbuff_out_abstrncpy_until(t, &q, &sbuff, SIZE_MAX, &name_terms, NULL);
		if (len == 0) {
			talloc_free(t);
			break;
		}
		t->name = q;

		lhs_rules.list_def = PAIR_LIST_CONTROL;
		comma = false;

check_item:
		/*
		 *	Skip spaces before the item, and allow the
		 *	check list to end on comment or LF.
		 *
		 *	Note that we _don't_ call map_afrom_substr() to
		 *	skip spaces, as it will skip LF, too!
		 */
		(void) fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
		if (fr_sbuff_is_char(&sbuff, '#')) goto check_item_comment;
		if (fr_sbuff_is_char(&sbuff, '\n')) goto check_item_end;

		/*
		 *	Try to parse the check item.
		 */
		slen = map_afrom_substr(t, &new_map, &sbuff, check_cmp_op_table, check_cmp_op_table_len,
				       &lhs_rules, &rhs_rules, &rhs_term);
		if (!new_map) {
	    		ERROR_MARKER_ADJ(&sbuff, slen, fr_strerror());
		fail_entry:
			talloc_free(t);
			goto fail;
		}

		/*
		 *	The map "succeeded", but no map was created.
		 *	It must have hit a terminal character, OR EOF.
		 *
		 *	Except we've already skipped spaces, tabs,
		 *	comments, and LFs.  So the only thing which is
		 *	left is a comma.
		 */
		if (!new_map) {
			if (fr_sbuff_is_char(&sbuff, ',')) {
				ERROR_MARKER(&sbuff, "Unexpected extra comma reading check pair");

				goto fail_entry;
			}

			/*
			 *	Otherwise map_afrom_substr() returned
			 *	nothing, because there's no more
			 *	input.
			 */

		add_entry:
			fr_dlist_insert_tail(&list->head, &t);
			break;
		}
		fr_assert(new_map->lhs != NULL);
		fr_assert(new_map->rhs != NULL);

		if (!tmpl_is_attr(new_map->lhs)) {
			ERROR("%s[%d]: Unknown attribute '%s'",
			      file, lineno, new_map->lhs->name);
			goto fail_entry;
		}

		if (tmpl_contains_regex(new_map->rhs)) {
			if (!((new_map->op == T_OP_REG_EQ) ||
			      (new_map->op == T_OP_REG_NE))) {
				ERROR("%s[%d]: Unexpected regular expression on RHS of check item",
				      file, line);
				goto fail_entry;
			}

			if (!tmpl_is_attr(new_map->lhs)) {
				ERROR("%s[%d]: LHS of regular expression check must be an attribute",
				      file, lineno);
				goto fail_entry;
			}

			/*
			 *	The default rules say that the check
			 *	items look at the control list, but
			 *	for regexes we want to look at the
			 *	request list.
			 */
			tmpl_attr_set_list(new_map->lhs, PAIR_LIST_REQUEST);

			if (tmpl_is_regex_uncompiled(new_map->rhs) &&
			    (tmpl_regex_compile(new_map->rhs, false) < 0)) {
				ERROR("%s[%d]: Failed compiling regular expression /%s/ - %s",
				      file, lineno, new_map->rhs->name, fr_strerror());
				return -1;
			}

			goto do_insert;
		}

		/*
		 *	@todo - update map_afrom_substr() to check for
		 *	regexes, too.  Maybe even normalize /foo/ =~ bar
		 */
		if (tmpl_contains_regex(new_map->lhs)) {
			ERROR("%s[%d]: Unexpected regular expression on LHS of check item",
			      file, lineno, new_map->rhs->name);
			goto fail_entry;
		}

		if (!tmpl_is_data(new_map->rhs) && !tmpl_is_exec(new_map->rhs) &&
		    !tmpl_contains_xlat(new_map->rhs)) {
			ERROR("%s[%d]: Invalid RHS '%s' for check item",
			      file, lineno, new_map->rhs->name);
			goto fail_entry;
		}

	do_insert:
		fr_dlist_insert_tail(&t->check, new_map);

		/*
		 *	There can be spaces before any comma.
		 */
		(void) fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);

		/*
		 *	Allow a comma after this item.  But remember
		 *	if we had a comma.
		 */
		if (fr_sbuff_next_if_char(&sbuff, ',')) {
			comma = true;
			goto check_item;
		}
		comma = false;

	check_item_comment:
		/*
		 *	There wasn't a comma after the item, so the
		 *	next thing MUST be a comment, LF, EOF.
		 *
		 *	If there IS stuff before the LF, then it's
		 *	unknown text.
		 */
		if (fr_sbuff_next_if_char(&sbuff, '#')) {
			(void) fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\n');
		}
	check_item_end:
		if (fr_sbuff_next_if_char(&sbuff, '\n')) {
			/*
			 *	The check item list ended with a comma.
			 *	That's bad.
			 */
			if (comma) {
				ERROR_MARKER(&sbuff, "Invalid comma ending the check item list");
				goto fail_entry;
			}

			lineno++;
			goto setup_reply;
		}

		/*
		 *	We didn't see SPACE LF or SPACE COMMENT LF.
		 *	There's something else going on.
		 */
		if (fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\n') != NULL) {
			ERROR_MARKER(&sbuff, "Unexpected text after check item");
			goto fail_entry;
		}

		/*
		 *	The next character is not LF, but we
		 *	skipped to LF above.  So, by process
		 *	of elimination, we must be at EOF.
		 */
		if (!fr_sbuff_is_char(&sbuff, '\n')) {
			goto add_entry;
		}

setup_reply:
		/*
		 *	Setup the reply items.
		 */
		lhs_rules.list_def = PAIR_LIST_REPLY;
		comma = false;

reply_item:
		/*
		 *	Reply items start with spaces.  If there's no
		 *	spaces, then the current entry is done.  Add
		 *	it to the list, and go back to reading the
		 *	user name or $INCLUDE.
		 */
		if (fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL) == 0) {
			if (comma) {
				ERROR("%s[%d]: Unexpected trailing comma in previous line", file, lineno);
				goto fail_entry;
			}

			/*
			 *	The line doesn't begin with spaces.
			 *	The list of reply items MUST be
			 *	finished.  Go look for an entry name.
			 *
			 *	Note that we don't allow comments in
			 *	the middle of the reply item list.  Oh
			 *	well.
			 */
			fr_dlist_insert_tail(&list->head, t);
			continue;

		} else if (lineno == (t->lineno + 1)) {
			fr_assert(comma == false);

		} else if (!comma) {
			ERROR("%s[%d]: Missing comma in previous line", file, lineno);
			goto fail_entry;
		}

		/*
		 *	SPACES COMMENT or SPACES LF means "end of
		 *	reply item list"
		 */
		if (fr_sbuff_is_char(&sbuff, '#')) {
			(void) fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\n');
		}
		if (fr_sbuff_next_if_char(&sbuff, '\n')) {
			lineno++;
			goto add_entry;
		}

next_reply_item:
		/*
		 *	Unlike check items, we don't skip spaces or
		 *	comments here.  All of the code paths which
		 *	lead to here have already checked for those
		 *	cases.
		 */
		slen = map_afrom_substr(t, &new_map, &sbuff, map_assignment_op_table, map_assignment_op_table_len,
				       &lhs_rules, &rhs_rules, &rhs_term);
		if (!new_map) {
			ERROR_MARKER_ADJ(&sbuff, slen, fr_strerror());
			goto fail;
		}

		/*
		 *	The map "succeeded", but no map was created.
		 *	Maybe we hit a terminal string, or EOF.
		 *
		 *	We can't have hit space/tab, as that was
		 *	checked for at "reply_item", and again after
		 *	map_afrom_substr(), if we actually got
		 *	something.
		 *
		 *	What's left is a comment, comma, LF, or EOF.
		 */
		if (!new_map) {
			(void) fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
			if (fr_sbuff_is_char(&sbuff, ',')) {
				ERROR_MARKER(&sbuff, "Unexpected extra comma reading reply pair");
				goto fail_entry;
			}

			if (fr_sbuff_is_char(&sbuff, '#')) goto reply_item_comment;
			if (fr_sbuff_is_char(&sbuff, '\n')) goto reply_item_end;

			/*
			 *	We didn't read anything, but none of
			 *	the terminal characters match.  It must be EOF.
			 */
			goto add_entry;
		}
		fr_assert(new_map->lhs != NULL);
		fr_assert(new_map->rhs != NULL);

		if (!tmpl_is_attr(new_map->lhs)) {
			ERROR("%s[%d]: Unknown attribute '%s'",
			      file, lineno, new_map->lhs->name);
			goto fail_entry;
		}

		if (!tmpl_is_data(new_map->rhs) && !tmpl_is_exec(new_map->rhs) &&
		    !tmpl_contains_xlat(new_map->rhs)) {
			ERROR("%s[%d]: Invalid RHS '%s' for reply item",
			      file, lineno, new_map->rhs->name);
			goto fail_entry;
		}

		fr_assert(tmpl_list(new_map->lhs) == PAIR_LIST_REPLY);

		fr_dlist_insert_tail(&t->reply, new_map);

		(void) fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);

		/*
		 *	Commas separate entries on the same line.  And
		 *	we allow spaces after commas, too.
		 */
		if (fr_sbuff_next_if_char(&sbuff, ',')) {
			comma = true;
			(void) fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
		} else {
			comma = false;
		}

		/*
		 *	Comments or LF will end this particular line.
		 *
		 *	Reading the next line will cause a complaint
		 *	if this line ended with a comma.
		 */
	reply_item_comment:
		if (fr_sbuff_next_if_char(&sbuff, '#')) {
			(void) fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\n');
		}
	reply_item_end:
		if (fr_sbuff_next_if_char(&sbuff, '\n')) {
			lineno++;
			goto reply_item;
		}

		/*
		 *	Not comment or LF, the content MUST be another
		 *	pair.
		 */
		if (comma) goto next_reply_item;

		ERROR_MARKER(&sbuff, "Unexpected text after reply");
		goto fail_entry;
	}

	/*
	 *	Else we were looking for an entry.  We didn't get one
	 *	because we were at EOF, so that's OK.
	 */

	fclose(fp);

	return 0;
}
