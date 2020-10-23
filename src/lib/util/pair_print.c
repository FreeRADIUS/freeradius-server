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
	fr_pair_t	*child, *head;
	fr_cursor_t	cursor;

	VP_VERIFY(vp);

	/*
	 *	Legacy crap that needs to be removed
	 */
	if (vp->type == VT_XLAT) {
		char const *quote_str = fr_table_str_by_value(fr_token_quotes_table, quote, "");

		return fr_sbuff_in_sprintf(out, "%s%s%s", quote_str, vp->xlat, quote_str);
	}

	/*
	 *	For simple types just print the box
	 */
	if (vp->da->type != FR_TYPE_GROUP) {
		return fr_value_box_print_quoted(out, &vp->data, quote);
	}

	/*
	 *	Serialize all child VPs as full quoted
	 *	<pair> = ["]<child>["]
	 */
	our_out = FR_SBUFF_NO_ADVANCE(out);

	head = vp->vp_ptr;
	if (!fr_cond_assert(head != NULL)) return 0;

	FR_SBUFF_IN_CHAR_RETURN(&our_out, '{', ' ');
	for (child = fr_cursor_init(&cursor, &head);
	     child != NULL;
	     child = fr_cursor_next(&cursor)) {
		VP_VERIFY(child);

		FR_SBUFF_RETURN(fr_pair_print, &our_out, child);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ',', ' ');
	}

	if (fr_sbuff_used(&our_out)) {
		fr_sbuff_set(&our_out, fr_sbuff_current(&our_out) - 2);
		*fr_sbuff_current(&our_out) = '\0';
	}

	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ', '}');

	return fr_sbuff_set(out, &our_out);
}

/** Print one attribute and value to a string
 *
 * Print a fr_pair_t in the format:
@verbatim
	<attribute_name>[:tag] <op> [q]<value>[q]
@endverbatim
 * to a string.
 *
 * @param[in] out	Where to write the string.
 * @param[in] vp	to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
ssize_t fr_pair_print(fr_sbuff_t *out, fr_pair_t const *vp)
{
	char const	*token = NULL;
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

	if (!out) return 0;

	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%s %s ", vp->da->name, token);
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
void fr_pair_fprint(FILE *fp, fr_pair_t const *vp)
{
	char		buff[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buff, sizeof(buff));

	if (!fp) return;
	VP_VERIFY(vp);

	fr_sbuff_in_char(&sbuff, '\t');
	fr_pair_print(&sbuff, vp);
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
void _fr_pair_list_log(fr_log_t const *log, fr_pair_t const *vp, char const *file, int line)
{
	fr_pair_t *our_vp;
	fr_cursor_t cursor;

	memcpy(&our_vp, &vp, sizeof(vp)); /* const work-arounds */

	for (vp = fr_cursor_init(&cursor, &our_vp); vp; vp = fr_cursor_next(&cursor)) {
		fr_log(log, L_DBG, file, line, "\t%pP", vp);
	}
}
