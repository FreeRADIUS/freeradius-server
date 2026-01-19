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

/*
 *	Groups are printed from the referenced attribute.
 *
 *	@todo - parent should _never_ be vp->da.
 */
#define fr_pair_reset_parent(parent) do {		\
	if (!parent) break;				\
	fr_assert((parent != vp->da) || (parent->type == FR_TYPE_GROUP)); \
	fr_assert(fr_type_is_structural(parent->type));	\
	if (parent->type == FR_TYPE_GROUP) {		\
		parent = fr_dict_attr_ref(parent);	\
		if (parent->flags.is_root) {		\
			parent = NULL;			\
			break;				\
	        }					\
	}						\
	if (parent->dict != vp->da->dict) parent = NULL; \
  } while (0)

/** Pair serialisation API
 *
 * @file src/lib/util/pair_print.c
 *
 * @copyright 2020 The FreeRADIUS server project
 */
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/pair_legacy.h>

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
	ssize_t		slen;

	PAIR_VERIFY(vp);

	our_out = FR_SBUFF(out);

	switch (vp->vp_type) {
	/*
	 *	For structural types descend down
	 */
	case FR_TYPE_STRUCTURAL:
		if (fr_pair_list_empty(&vp->vp_group)) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '{', ' ', '}');

		} else {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '{', ' ');

			FR_SBUFF_RETURN(fr_pair_list_print, &our_out, vp->da, &vp->vp_group);

			FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ', '}');
		}

		FR_SBUFF_SET_RETURN(out, &our_out);

	/*
	 *	For simple types just print the box
	 */
	default:
		/*
		 *	If it's raw / unknown and not octets, print the cast before the type.
		 *
		 *	Otherwise on parsing, we don't know how to interpret the value. :(
		 */
		if ((vp->da->flags.is_raw || vp->da->flags.is_unknown) &&
		    (vp->vp_type != FR_TYPE_OCTETS)) {
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "(%s) ", fr_type_to_str(vp->vp_type));
		}

		slen = fr_value_box_print_quoted(&our_out, &vp->data, quote);
		if (slen <= 0) return slen;
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Print either a quoted value, an enum, or a normal value.
 *
 */
static ssize_t fr_pair_print_value(fr_sbuff_t *out, fr_pair_t const *vp)
{
	fr_sbuff_t		our_out = FR_SBUFF(out);
	char const		*name;

	if ((name = fr_value_box_enum_name(&vp->data)) != NULL) {
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ':', ':');
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, name);
	} else {

		FR_SBUFF_RETURN(fr_pair_print_value_quoted, &our_out, vp, T_DOUBLE_QUOTED_STRING);
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Print an attribute name.
 *
 * @param[in] out	Where to write the string.
 * @param[in] parent	If not NULL, only print OID components from
 *			this parent to the VP.
 * @param[in,out] vp_p	to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
ssize_t fr_pair_print_name(fr_sbuff_t *out, fr_dict_attr_t const *parent, fr_pair_t const **vp_p)
{
	char const		*token;
	fr_pair_t const		*vp = *vp_p;
	fr_sbuff_t		our_out = FR_SBUFF(out);

	/*
	 *	Omit the union if we can.  But if the child is raw, then always print it.  That way it's
	 *	clearer what's going on.
	 */
	if (vp->vp_type == FR_TYPE_UNION) {
		fr_pair_t *child = fr_pair_list_head(&vp->vp_group);

		if (!child->da->flags.is_unknown &&
		    (fr_pair_list_num_elements(&vp->vp_group) == 1)) {
			parent = vp->da;
			vp = fr_pair_list_head(&vp->vp_group);
		}
	}

	fr_pair_reset_parent(parent);

	if (vp->vp_raw) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");
	FR_DICT_ATTR_OID_PRINT_RETURN(&our_out, parent, vp->da, false);

	/*
	 *	Mash the nesting levels if we're asked to do that, and if each structural child has only one
	 *	member.
	 */
	if (vp->da->flags.allow_flat) {
		bool raw = vp->vp_raw;
		fr_dict_attr_t const *root = parent;
		fr_sbuff_marker_t m;

		fr_sbuff_marker(&m, &our_out);

		while (fr_type_is_structural(vp->vp_type) &&
		       (fr_pair_list_num_elements(&vp->vp_group) == 1)) {
			parent = vp->da;
			vp = fr_pair_list_head(&vp->vp_group);

			fr_pair_reset_parent(parent);

			FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			FR_DICT_ATTR_OID_PRINT_RETURN(&our_out, parent, vp->da, false);
		}

		/*
		 *	If the root attribute is an internal group, then look for aliases in the protocol
		 *	root.
		 *
		 *	Otherwise the root attribute is a protocol group.  The protocol dictionary or library
		 *	can add aliases.
		 */
		if (!root || root->flags.internal) root = fr_dict_root(vp->da->dict);

		if (!raw && (vp->da->depth > (root->depth + 1)) && (fr_dict_attr_by_name(NULL, root, vp->da->name) == vp->da)) {
			fr_sbuff_set(&our_out, &m);
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			FR_SBUFF_IN_STRCPY_RETURN(&our_out, vp->da->name);
		}
	}

	/*
	 *	Print the operator for the _last_ attribute, which is generally what we want.
	 */
	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');
	FR_SBUFF_IN_STRCPY_RETURN(&our_out, token);
	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');

	*vp_p = vp;
	FR_SBUFF_SET_RETURN(out, &our_out);
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
ssize_t fr_pair_print(fr_sbuff_t *out, fr_dict_attr_t const *parent, fr_pair_t const *vp)
{
	fr_sbuff_t		our_out = FR_SBUFF(out);

	PAIR_VERIFY(vp);

	FR_SBUFF_RETURN(fr_pair_print_name, &our_out, parent, &vp);

	FR_SBUFF_RETURN(fr_pair_print_value, &our_out, vp);

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Print one attribute and value to a string with escape rules
 *
 *  Similar to fr_pair_print(), but secrets are omitted.  This function duplicates parts of the functionality
 *  of fr_pair_print(). fr_pair_print_value_quoted(), and fr_value_box_print_quoted(), but for the special
 *  case of secure strings.
 *
 *  Note that only secrets of type "string" and "octets" are omitted.  Other "secret" data types are still
 *  printed as-is.
 *
 *  "octets" are still printed as "<<< secret >>>".  Which won't parse correctly, but that's fine.  Because
 *  omitted data is not meant to be parsed into real data.
 *
 * @param[in] out	Where to write the string.
 * @param[in] parent	If not NULL, only print OID components from
 *			this parent to the VP.
 * @param[in] vp	to print.

 * @return
 *	- < 0 on error
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
ssize_t fr_pair_print_secure(fr_sbuff_t *out, fr_dict_attr_t const *parent, fr_pair_t const *vp)
{
	fr_sbuff_t		our_out = FR_SBUFF(out);

	PAIR_VERIFY(vp);

	FR_SBUFF_RETURN(fr_pair_print_name, &our_out, parent, &vp);

	if (fr_type_is_leaf(vp->vp_type)) {
		if (!vp->data.secret) {
			FR_SBUFF_RETURN(fr_pair_print_value, &our_out, vp);

		} else {
			switch (vp->vp_type) {
			case FR_TYPE_STRING:
			case FR_TYPE_OCTETS:
				FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "<<< secret >>>");
				break;

			default:
				fr_assert(0); /* see dict_tokenize.c, which enforces parsing of "secret" in dictionaries */
				FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "<<< secret >>>");
				break;
			}
		}
	} else {
		fr_pair_t *child;
		fr_dcursor_t cursor;

		fr_assert(fr_type_is_structural(vp->vp_type));

		FR_SBUFF_IN_CHAR_RETURN(&our_out, '{', ' ');
		for (child = fr_pair_dcursor_init(&cursor, &vp->vp_group);
		     child != NULL;
		     child = fr_dcursor_next(&cursor)) {
			FR_SBUFF_RETURN(fr_pair_print_secure, &our_out, vp->da, child);
			if (fr_dcursor_next_peek(&cursor)) FR_SBUFF_IN_CHAR_RETURN(&our_out, ',', ' ');
		}
		FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ', '}');
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Print a pair list
 *
 * @param[in] out	Where to write the string.
 * @param[in] parent	parent da to start from
 * @param[in] list	pair list
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
ssize_t fr_pair_list_print(fr_sbuff_t *out, fr_dict_attr_t const *parent, fr_pair_list_t const *list)
{
	fr_pair_t	*vp;
	fr_sbuff_t	our_out = FR_SBUFF(out);

	vp = fr_pair_list_head(list);
	if (!vp) {
		FR_SBUFF_IN_CHAR_RETURN(out, '\0');
		return fr_sbuff_used(out);
	}

	fr_pair_reset_parent(parent);

	while (true) {
		FR_SBUFF_RETURN(fr_pair_print, &our_out, parent, vp);
		vp = fr_pair_list_next(list, vp);
		if (!vp) break;

		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, ", ");
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

static void fr_pair_list_log_sbuff(fr_log_t const *log, int lvl, fr_pair_t const *parent, fr_pair_list_t const *list, char const *file, int line, fr_sbuff_t *sbuff)
{
	fr_pair_list_foreach(list, vp) {
		fr_pair_t const *child = vp;

		PAIR_VERIFY_WITH_LIST(list, vp);

		fr_sbuff_set_to_start(sbuff);

		if (fr_pair_print_name(sbuff, parent ? parent->da : NULL, &child) <= 0) return;

		/*
		 *	Recursively print grouped attributes.
		 */
		switch (child->vp_type) {
		case FR_TYPE_STRUCTURAL:
			fr_log(log, L_DBG, file, line, "%*s%*s{", lvl * 2, "",
			       (int) fr_sbuff_used(sbuff), fr_sbuff_start(sbuff));
			_fr_pair_list_log(log, lvl + 1, child, &child->vp_group, file, line);
			fr_log(log, L_DBG, file, line, "%*s}", lvl * 2, "");
			break;

		default:
			if (fr_pair_print_value(sbuff, child) < 0) break;

			fr_log(log, L_DBG, file, line, "%*s%*s", lvl * 2, "",
			       (int) fr_sbuff_used(sbuff), fr_sbuff_start(sbuff));
		}
	}
}


/** Print a list of attributes and enumv
 *
 * @param[in] log	to output to.
 * @param[in] lvl	depth in structural attribute.
 * @param[in] parent	parent attribute
 * @param[in] list	to print.
 * @param[in] file	where the message originated
 * @param[in] line	where the message originated
 */
void _fr_pair_list_log(fr_log_t const *log, int lvl, fr_pair_t const *parent, fr_pair_list_t const *list, char const *file, int line)
{
	fr_sbuff_t sbuff;
	char buffer[1024];

	buffer[0] = '\0';

	fr_sbuff_init_out(&sbuff, buffer, sizeof(buffer));

	fr_pair_list_log_sbuff(log, lvl, parent, list, file, line, &sbuff);
}

static void fr_pair_list_debug_sbuff(FILE *fp, int lvl, fr_pair_t const *parent, fr_pair_list_t const *list, fr_sbuff_t *sbuff)
{
	fr_pair_list_foreach(list, vp) {
		fr_pair_t const *child = vp;

		PAIR_VERIFY_WITH_LIST(list, vp);

		fr_sbuff_set_to_start(sbuff);

		if (fr_pair_print_name(sbuff, parent ? parent->da : NULL, &child) <= 0) return;

		/*
		 *	Recursively print grouped attributes.
		 */
		switch (child->vp_type) {
		case FR_TYPE_STRUCTURAL:
			fprintf(fp, "%*s%*s{\n", lvl * 2, "", (int) fr_sbuff_used(sbuff), fr_sbuff_start(sbuff));
			_fr_pair_list_debug(fp, lvl + 1, child, &child->vp_group);
			fprintf(fp, "%*s}\n", lvl * 2, "");
			break;

		default:
			if (fr_value_box_print_quoted(sbuff, &child->data, T_DOUBLE_QUOTED_STRING) < 0) break;

			fprintf(fp, "%*s%*s\n", lvl * 2, "", (int) fr_sbuff_used(sbuff), fr_sbuff_start(sbuff));
		}
	}
}

/** Print a list of attributes and enumv
 *
 * @param[in] fp	to output to.
 * @param[in] lvl	depth in structural attribute.
 * @param[in] parent	parent attribute
 * @param[in] list	to print.
 */
void _fr_pair_list_debug(FILE *fp, int lvl, fr_pair_t const *parent, fr_pair_list_t const *list)
{
	fr_sbuff_t sbuff;
	char buffer[1024];

	buffer[0] = '\0';

	fr_sbuff_init_out(&sbuff, buffer, sizeof(buffer));

	fr_pair_list_debug_sbuff(fp, lvl, parent, list, &sbuff);
}

/** Dumps a list to the default logging destination - Useful for calling from debuggers
 *
 */
void fr_pair_list_debug(FILE *fp, fr_pair_list_t const *list)
{
	_fr_pair_list_debug(fp, 0, NULL, list);
}


/** Dumps a pair to the default logging destination - Useful for calling from debuggers
 *
 */
void fr_pair_debug(FILE *fp, fr_pair_t const *pair)
{
	fr_sbuff_t sbuff;
	char buffer[1024];

	buffer[0] = '\0';

	fr_sbuff_init_out(&sbuff, buffer, sizeof(buffer));

	(void) fr_pair_print(&sbuff, NULL, pair);

	fprintf(fp, "%pV\n", fr_box_strvalue_len(fr_sbuff_start(&sbuff), fr_sbuff_used(&sbuff)));
}

static const char spaces[] = "                                                                                                                                ";

static void fprintf_pair_list(FILE *fp, fr_pair_list_t const *list, int depth)
{
	fr_pair_list_foreach(list, vp) {
		fprintf(fp, "%.*s", depth, spaces);

		if (fr_type_is_leaf(vp->vp_type)) {
			fr_fprintf(fp, "%s %s %pV\n", vp->da->name, fr_tokens[vp->op], &vp->data);
			continue;
		}

		fr_assert(fr_type_is_structural(vp->vp_type));

		fprintf(fp, "%s = {\n", vp->da->name);
		fprintf_pair_list(fp, &vp->vp_group, depth + 1);
		fprintf(fp, "%.*s}\n", depth, spaces);
	}
}

void fr_fprintf_pair_list(FILE *fp, fr_pair_list_t const *list)
{
	fprintf_pair_list(fp, list, 0);
}

/*
 *	print.c doesn't include pair.h, and doing so causes too many knock-on effects.
 */
void fr_fprintf_pair(FILE *fp, char const *msg, fr_pair_t const *vp)
{
	if (msg) fputs(msg, fp);

	if (fr_type_is_leaf(vp->vp_type)) {
		fr_fprintf(fp, "%s %s %pV\n", vp->da->name, fr_tokens[vp->op], &vp->data);
	} else {
		fr_assert(fr_type_is_structural(vp->vp_type));

		fprintf(fp, "%s = {\n", vp->da->name);
		fprintf_pair_list(fp, &vp->vp_group, 1);
		fprintf(fp, "}\n");
	}
}
