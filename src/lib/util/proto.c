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

/** Protocol encoder/decoder support functions
 *
 * @file src/lib/util/proto.c
 *
 * @copyright 2015 The FreeRADIUS server project
 */
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/pair.h>

void fr_proto_print(char const *file, int line, char const *fmt, ...)
{
	va_list		ap;
	char		*buff;

	va_start(ap, fmt);
	buff = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);

	fr_log(&default_log, L_DBG, file, line, "msg: %pV", fr_box_strvalue_buffer(buff));

	talloc_free(buff);
}

DIAG_OFF(format-nonliteral)
void fr_proto_print_hex_data(char const *file, int line, uint8_t const *data, size_t data_len, char const *fmt, ...)
{
	va_list		ap;
	char		*msg;

	if (fmt) {
		va_start(ap, fmt);
		msg = talloc_vasprintf(NULL, fmt, ap);
		va_end(ap);
		fr_log(&default_log, L_DBG, file, line, "hex: -- %s --", msg);
		talloc_free(msg);
	}
	fr_log_hex(&default_log, L_DBG, file, line, data, data_len, "hex: ");
}

void fr_proto_print_hex_marker(char const *file, int line, uint8_t const *data, size_t data_len, ssize_t slen, char const *fmt, ...)
{
	va_list		ap;
	char		*msg;

	if (fmt) {
		va_start(ap, fmt);
		msg = talloc_vasprintf(NULL, fmt, ap);
		va_end(ap);
		fr_log(&default_log, L_DBG, file, line, "hex: -- %s --", msg);
		talloc_free(msg);
	}
	fr_log_hex_marker(&default_log, L_DBG, file, line, data, data_len, slen, "current position", "hex: ");
}
DIAG_ON(format-nonliteral)

void fr_proto_da_stack_print(char const *file, int line, char const *func, fr_da_stack_t *da_stack, unsigned int depth)
{
	int		i = da_stack->depth;

	fr_log(&default_log, L_DBG, file, line, "stk: Currently in %s", func);
	for (i--; i >= 0; i--) {
		fr_log(&default_log, L_DBG, file, line,
		       "stk: %s [%i] %s: %s, vendor: 0x%x (%u), attr: 0x%x (%u)",
		       (i == (int)depth) ? ">" : " ", i,
		       fr_table_str_by_value(fr_value_box_type_table, da_stack->da[i]->type, "?Unknown?"),
		       da_stack->da[i]->name,
		       fr_dict_vendor_num_by_da(da_stack->da[i]), fr_dict_vendor_num_by_da(da_stack->da[i]),
		       da_stack->da[i]->attr, da_stack->da[i]->attr);
	}
	fr_log(&default_log, L_DBG, file, line, "stk:");
}

/** Implements the default iterator to encode pairs belonging to a specific dictionary that are not internal
 *
 * @param[in,out] prev	The fr_pair_t before curr. Will be updated to point to the
 *			pair before the one returned, or the last pair in the list
 *			if no matching pairs found.
 * @param[in] to_eval	The fr_pair_t after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_t.
 * @param[in] uctx	The fr_dict_t to search for.
 * @return
 *	- Next matching fr_pair_t.
 *	- NULL if not more matching fr_pair_ts could be found.
 */
void *fr_proto_next_encodable(void **prev, void *to_eval, void *uctx)
{
	fr_pair_t	*c, *p;
	fr_dict_t	*dict = talloc_get_type_abort(uctx, fr_dict_t);

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if ((c->da->dict == dict) && (!c->da->flags.internal)) break;
	}

	*prev = p;

	return c;
}

/** Build a complete DA stack from the da back to the root
 *
 * @param[out] stack	to populate.
 * @param[in] da	to build the stack for.
 */
void fr_proto_da_stack_build(fr_da_stack_t *stack, fr_dict_attr_t const *da)
{
	fr_dict_attr_t const **cached;

	if (!da) return;

	/*
	 *	See if we have a cached da stack available
	 */
	cached = fr_dict_attr_da_stack(da);
	if (cached) {
		/*
		 *	da->da_stack[0] is dict->root
		 */
		memcpy(&stack->da[0], &cached[1], sizeof(stack->da[0]) * da->depth);

	} else {
		fr_dict_attr_t const	*da_p, **da_o;

		/*
		 *	Unknown attributes don't have a da->da_stack.
		 */
		da_p = da;
		da_o = stack->da + (da->depth - 1);

		while (da_o >= stack->da) {
			*da_o-- = da_p;
			da_p = da_p->parent;
		}
	}

	stack->depth = da->depth;
	stack->da[stack->depth] = NULL;
}

/** Complete the DA stack for a child attribute
 *
 * @param[out] stack		to populate.
 * @param[in] parent		to populate from.
 * @param[in] da		to populate to.
 */
void fr_proto_da_stack_build_partial(fr_da_stack_t *stack, fr_dict_attr_t const *parent, fr_dict_attr_t const *da)
{
	fr_dict_attr_t const	*da_p, **da_q, **da_o;

	if (!parent) {
		fr_proto_da_stack_build(stack, da);
		return;
	}

	da_p = da;
	da_q = stack->da + (parent->depth - 1);
	da_o = stack->da + (da->depth - 1);

	while (da_o >= da_q) {
		*da_o-- = da_p;
		da_p = da_p->parent;
	}

	stack->depth = da->depth;
	stack->da[stack->depth] = NULL;
}
