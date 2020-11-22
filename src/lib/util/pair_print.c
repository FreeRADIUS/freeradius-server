/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Pair serialisation API
 *
 * @file src/lib/util/pair_print.c
 *
 * @copyright 2020 The FreeRADIUS server project
 */
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>

/** Print the value of an attribute to a string
 *
 * @param[in] out	Where to write the string.
 * @param[in] vp	to print.
 * @param[in] quote	Char to add before and after printed value,
 *			if 0 no char will be added, if < 0 raw string
 *			will be added.
 * @return
 *	- >= 0 length of data written to out.
 *	- <0 the number of bytes we would have needed to write
 *	  the complete string to out.
 */
ssize_t fr_pair_print_value_quoted(fr_sbuff_t *out, fr_pair_t const *vp, fr_token_t quote)
{
	fr_sbuff_t	our_out;
	fr_pair_t	*child;
	fr_cursor_t	cursor;

	VP_VERIFY(vp);

	/*
	 *	Legacy crap that needs to be removed
	 */
	if (vp->type == VT_XLAT) {
		char const *quote_str = fr_table_str_by_value(fr_token_quotes_table, quote, "");

		return fr_sbuff_in_sprintf(out, "%s%s%s", quote_str, vp->xlat, quote_str);
	}

	switch (vp->da->type) {
	/*
	 *	For structural types descend down
	 */
	case FR_TYPE_STRUCTURAL:
		/*
		 *	Serialize all child VPs as full quoted
		 *	<pair> = ["]<child>["]
		 */
		our_out = FR_SBUFF_NO_ADVANCE(out);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, '{', ' ');
		for (child = fr_cursor_init(&cursor, &vp->vp_group);
		     child != NULL;
		     child = fr_cursor_next(&cursor)) {
			FR_SBUFF_RETURN(fr_pair_print, &our_out, vp, child);
			if (fr_cursor_next_peek(&cursor)) FR_SBUFF_IN_CHAR_RETURN(&our_out, ',', ' ');
		}
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ', '}');

		return fr_sbuff_set(out, &our_out);

	/*
	 *	For simple types just print the box
	 */
	default:
		return fr_value_box_print_quoted(out, &vp->data, quote);
	}
}

/** Print one attribute and value to a string
 *
 * Print a fr_pair_t in the format:
@verbatim
	<attribute_name> <op> <value>
@endverbatim
 * to a string.
 *
 * @param[in] out	Where to write the string.
 * @param[in] parent	If not NULL, only print OID components from
 *			this parent to the VP.
 * @param[in] vp	to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
ssize_t fr_pair_print(fr_sbuff_t *out, fr_pair_t const *parent, fr_pair_t const *vp)
{
	char const		*token = NULL;
	fr_sbuff_t		our_out = FR_SBUFF_NO_ADVANCE(out);
	fr_dict_attr_t const	*parent_da = NULL;

	if (!out) return 0;

	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if (parent && (parent->da->type != FR_TYPE_GROUP)) parent_da = parent->da;

	FR_DICT_ATTR_OID_PRINT_RETURN(&our_out, parent_da, vp->da);
	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');
	FR_SBUFF_IN_STRCPY_RETURN(&our_out, token);
	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');
	FR_SBUFF_RETURN(fr_pair_print_value_quoted, &our_out, vp, T_DOUBLE_QUOTED_STRING);

	return fr_sbuff_set(out, &our_out);
}

/** Print one attribute and value to FP
 *
 * Complete string with '\\t' and '\\n' is written to buffer before printing to
 * avoid issues when running with multiple threads.
 *
 * @param fp to output to.
 * @param vp to print.
 */
void fr_pair_fprint(FILE *fp, fr_pair_t const *parent, fr_pair_t const *vp)
{
	char		buff[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buff, sizeof(buff));

	if (!fp) return;
	VP_VERIFY(vp);

	fr_sbuff_in_char(&sbuff, '\t');
	fr_pair_print(&sbuff, parent, vp);
	fr_sbuff_in_char(&sbuff, '\n');

	fputs(buff, fp);
}


/** Print a list of attributes and enumv
 *
 * @param[in] log to output to.
 * @param[in] vp to print.
 * @param[in] file where the message originated
 * @param[in] line where the message originated
 */
void _fr_pair_list_log(fr_log_t const *log, int lvl, fr_pair_t const *vp, char const *file, int line)
{
	fr_pair_t *our_vp;
	fr_cursor_t cursor;

	memcpy(&our_vp, &vp, sizeof(vp)); /* const work-arounds */

	for (vp = fr_cursor_init(&cursor, &our_vp); vp; vp = fr_cursor_next(&cursor)) {\
		switch (vp->da->type) {
		case FR_TYPE_STRUCTURAL:
			fr_log(log, L_DBG, file, line, "%*s%s {", lvl * 2, "", vp->da->name);
			_fr_pair_list_log(log, lvl + 1, vp->vp_group, file, line);
			fr_log(log, L_DBG, file, line, "%*s}", lvl * 2, "");
			break;

		default:
			fr_log(log, L_DBG, file, line, "%*s%pP", lvl * 2, "", vp);
		}
	}
}

/** Useful for calling from debuggers
 *
 */
void fr_pair_list_debug(fr_pair_t const *vp)
{
	_fr_pair_list_log(&default_log, 0, vp, "<internal>", 0);
}
