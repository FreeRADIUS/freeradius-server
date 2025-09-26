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
 *
 * @file xlat_alloc.c
 * @brief Functions to allocate different types of xlat nodes
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>


#define _XLAT_PRIVATE
#include <freeradius-devel/unlang/xlat_priv.h>

xlat_exp_head_t *_xlat_exp_head_alloc(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx)
{
	xlat_exp_head_t *head;

	MEM(head = talloc_zero(ctx, xlat_exp_head_t));

	fr_dlist_init(&head->dlist, xlat_exp_t, entry);
	head->flags = XLAT_FLAGS_INIT;
#ifndef NDEBUG
	head->file = file;
	head->line = line;
#endif

	return head;
}

/** Set the type of an xlat node
 *
 * Also initialises any xlat_exp_head necessary
 *
 * @param[in] node	to set type for.
 * @param[in] type	to set.
 */
void _xlat_exp_set_type(NDEBUG_LOCATION_ARGS xlat_exp_t *node, xlat_type_t type)
{
	/*
	 *	Do nothing if it's the same type
	 */
	if (node->type == type) return;

	/*
	 *	Free existing lists if present
	 */
	if (node->type != 0) switch (node->type) {
	case XLAT_GROUP:
		TALLOC_FREE(node->group);
		break;

	case XLAT_FUNC_UNRESOLVED:
		if (type == XLAT_FUNC) goto done;  /* Just switching from unresolved to resolved */
		FALL_THROUGH;

	case XLAT_FUNC:
		TALLOC_FREE(node->call.args);
		break;

	case XLAT_TMPL:
		if (node->vpt && (node->fmt == node->vpt->name)) (void) talloc_steal(node, node->fmt);

		/*
		 *	Converting a tmpl to a box.  If the tmpl is data, we can then just steal the contents
		 *	of the box.
		 */
		if (type == XLAT_BOX) {
			tmpl_t *vpt = node->vpt;

			if (!vpt) break;

			fr_assert(tmpl_rules_cast(vpt) == FR_TYPE_NULL);

			if (!tmpl_is_data(vpt)) {
				talloc_free(vpt);
				break;
			}

			/*
			 *	Initialize the box from the tmpl data.  And then do NOT re-initialize the box
			 *	later.
			 */
			node->flags = XLAT_FLAGS_INIT;
			fr_value_box_steal(node, &node->data, tmpl_value(vpt));
			talloc_free(vpt);
			goto done;
		}

		TALLOC_FREE(node->vpt);
		break;

	default:
		break;
	}

	/*
	 *	Alloc new lists to match the type
	 */
	switch (type) {
	case XLAT_GROUP:
		node->group = _xlat_exp_head_alloc(NDEBUG_LOCATION_VALS node);
		node->flags = node->group->flags;
		break;

	case XLAT_FUNC:
		node->flags = XLAT_FLAGS_INIT;
		break;

	case XLAT_FUNC_UNRESOLVED:
		node->flags = XLAT_FLAGS_INIT;
		node->flags.needs_resolving = true;
		break;

	case XLAT_BOX:
		node->flags = XLAT_FLAGS_INIT;
		fr_value_box_init_null(&node->data);
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		node->flags = (xlat_flags_t) {};
		break;
#endif

	case XLAT_ONE_LETTER:
		/*
		 *	%% is pure.  Everything else is not.
		 */
		fr_assert(node->fmt);

		if (node->fmt[0] != '%') {
			node->flags = (xlat_flags_t) {};
		} else {
			node->flags = XLAT_FLAGS_INIT;
		}
		break;

	default:
		node->flags = XLAT_FLAGS_INIT;
		break;
	}

done:
	node->type = type;
}

static xlat_exp_t *xlat_exp_alloc_pool(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, unsigned int extra_hdrs, size_t extra)
{
	xlat_exp_t *node;

	MEM(node = talloc_zero_pooled_object(ctx, xlat_exp_t, extra_hdrs, extra));
	node->flags = XLAT_FLAGS_INIT;
	node->quote = T_BARE_WORD;
#ifndef NDEBUG
	node->file = file;
	node->line = line;
#endif

	return node;
}

/** Allocate an xlat node with no name, and no type set
 *
 * @param[in] ctx	to allocate node in.
 * @return A new xlat node.
 */
xlat_exp_t *_xlat_exp_alloc_null(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx)
{
	return xlat_exp_alloc_pool(NDEBUG_LOCATION_VALS ctx, 0, 0);
}

/** Allocate an xlat node
 *
 * @param[in] ctx	to allocate node in.
 * @param[in] type	of the node.
 * @param[in] in	original input string.
 * @param[in] inlen	the length of the original input string.
 * @return A new xlat node.
 */
xlat_exp_t *_xlat_exp_alloc(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, xlat_type_t type, char const *in, size_t inlen)
{
	xlat_exp_t *node;
	unsigned int extra_hdrs;
	size_t extra;

	/*
	 *	Figure out how much extra memory we
	 *	need to allocate for this node type.
	 */
	switch (type) {
	case XLAT_GROUP:
		extra_hdrs = 1;
		extra = sizeof(xlat_exp_head_t);
		break;

	case XLAT_FUNC:
		extra_hdrs = 1;
		extra = sizeof(xlat_exp_head_t);
		break;

	default:
		extra_hdrs = 0;
		extra = 0;
	}

	node = xlat_exp_alloc_pool(NDEBUG_LOCATION_VALS
				   ctx,
				   (in != NULL) + extra_hdrs,
				   inlen + extra);
	_xlat_exp_set_type(NDEBUG_LOCATION_VALS node, type);

	node->quote = T_BARE_WORD; /* ensure that this is always initialized */

	if (!in) return node;

	node->fmt = talloc_bstrndup(node, in, inlen);
	switch (type) {
	case XLAT_BOX:
		fr_value_box_strdup_shallow(&node->data, NULL, node->fmt, false);
		break;

	default:
		break;
	}

	return node;
}

/** Set the tmpl for a node, along with flags and the name.
 *
 * @param[in] node	to set fmt for.
 * @param[in] vpt	the tmpl to set
 */
void xlat_exp_set_vpt(xlat_exp_t *node, tmpl_t *vpt)
{
	if (tmpl_contains_xlat(vpt)) {
		node->flags = tmpl_xlat(vpt)->flags;
	}

	if (tmpl_is_exec(vpt) || tmpl_contains_attr(vpt)) {
		node->flags = (xlat_flags_t) {};
	}

	node->flags.needs_resolving |= tmpl_needs_resolving(vpt);

	node->vpt = vpt;
	xlat_exp_set_name_shallow(node, vpt->name);
}

/** Set the function for a node
 *
 * @param[in] node	to set fmt for.
 * @param[in] func	to set
 * @param[in] dict	the dictionary to set
 */
void xlat_exp_set_func(xlat_exp_t *node, xlat_t const *func, fr_dict_t const *dict)
{
	node->call.func = func;
	node->call.dict = dict;
	node->flags = func->flags;
	node->flags.impure_func = !func->flags.pure;

	if (!dict) node->flags.needs_resolving = true;
}

void xlat_exp_finalize_func(xlat_exp_t *node)
{
	if (!node->call.args) return;

	node->call.args->is_argv = true;

	if (node->type == XLAT_FUNC_UNRESOLVED) return;

	xlat_flags_merge(&node->flags, &node->call.args->flags);

	/*
	 *	We might not be able to purify the function call, but perhaps we can purify the arguments to it.
	 */
	node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
	node->flags.impure_func = !node->call.func->flags.pure;
}


/** Set the format string for an xlat node
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 * @param[in] len	of fmt string.
 */
void xlat_exp_set_name(xlat_exp_t *node, char const *fmt, size_t len)
{
	fr_assert(node->fmt != fmt);

	if (node->fmt) talloc_const_free(node->fmt);
	MEM(node->fmt = talloc_bstrndup(node, fmt, len));
}

/** Set the format string for an xlat node, copying from a talloc'd buffer
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 */
void xlat_exp_set_name_buffer(xlat_exp_t *node, char const *fmt)
{
	if (node->fmt) {
		if (node->fmt == fmt) {
			(void) talloc_steal(node, fmt);
		} else {
			talloc_const_free(node->fmt);
		}
	}
	MEM(node->fmt = talloc_typed_strdup_buffer(node, fmt));
}

/** Set the format string for an xlat node from a pre-existing buffer
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 */
void xlat_exp_set_name_shallow(xlat_exp_t *node, char const *fmt)
{
	fr_assert(node->fmt != fmt);

	if (node->fmt) talloc_const_free(node->fmt);
	node->fmt = talloc_get_type_abort_const(fmt, char);
}

/** Copy all nodes in the input list to the output list
 *
 * @param[in] ctx	to allocate new nodes in.
 * @param[out] out	Where to write new nodes.
 * @param[in] in	Input nodes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int CC_HINT(nonnull) _xlat_copy_internal(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, xlat_exp_head_t *out, xlat_exp_head_t const *in)
{
	xlat_exp_head_t *head = NULL;

	xlat_flags_merge(&out->flags, &in->flags);

	/*
	 *	Copy everything in the list of nodes
	 */
	xlat_exp_foreach(in, p) {
		xlat_exp_t *node;

		(void)talloc_get_type_abort(p, xlat_exp_t);

		/*
		 *	Ensure the format string is valid...  At this point
		 *	they should all be talloc'd strings.
		 */
		MEM(node = xlat_exp_alloc(ctx, p->type,
					  talloc_get_type_abort_const(p->fmt, char), talloc_array_length(p->fmt) - 1));

		node->quote = p->quote;
		node->flags = p->flags;

		switch (p->type) {
		case XLAT_INVALID:
			fr_strerror_printf("Cannot copy xlat node of type \"invalid\"");
		error:
			talloc_free(head);
			return -1;

		case XLAT_BOX:
			if (unlikely(fr_value_box_copy(node, &node->data, &p->data) < 0)) goto error;
			break;

		case XLAT_ONE_LETTER: /* Done with format */
		case XLAT_FUNC_UNRESOLVED:
			break;

		case XLAT_FUNC:
			/*
			 *	Only copy the function pointer, and whether this
			 *	is ephemeral.
			 *
			 *	All instance data is specific to the xlat node and
			 *	cannot be duplicated.
			 *
			 *	The node xlat nodes will need to be registered in
			 *	the xlat instantiation table later.
			 */
			node->call.func = p->call.func;
			node->call.dict = p->call.dict;
			node->call.ephemeral = p->call.ephemeral;
			node->call.args = xlat_exp_head_alloc(node);
			node->call.args->is_argv = true;
			if (unlikely(_xlat_copy_internal(NDEBUG_LOCATION_VALS
							 node, node->call.args, p->call.args) < 0)) goto error;
			break;

		case XLAT_TMPL:
			node->vpt = tmpl_copy(node, p->vpt);
			break;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			node->regex_index = p->regex_index;
			break;
#endif

		case XLAT_GROUP:
			if (unlikely(_xlat_copy_internal(NDEBUG_LOCATION_VALS
							 node, node->group, p->group) < 0)) goto error;
			break;
		}

		xlat_exp_insert_tail(out, node);
	}

	return 0;
}

int _xlat_copy(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, xlat_exp_head_t *out, xlat_exp_head_t const *in)
{
	int ret;

	if (!in) return 0;

	XLAT_HEAD_VERIFY(in);
	ret = _xlat_copy_internal(NDEBUG_LOCATION_VALS ctx, out, in);
	XLAT_HEAD_VERIFY(out);

	return ret;
}

#ifdef WITH_VERIFY_PTR
void xlat_exp_verify(xlat_exp_t const *node)
{
	(void)talloc_get_type_abort_const(node, xlat_exp_t);

	switch (node->type) {
	case XLAT_GROUP:
		xlat_exp_head_verify(node->group);
		(void)talloc_get_type_abort_const(node->fmt, char);
		return;

	case XLAT_FUNC:
		fr_assert(node->call.args->is_argv);

		xlat_exp_foreach(node->call.args, arg) {
			fr_assert(arg->type == XLAT_GROUP);

			/*
			 *	We can't do this yet, because the old function argument parser doesn't do the
			 *	right thing.
			 */
//			fr_assert(arg->quote == T_BARE_WORD);
		}

		xlat_exp_head_verify(node->call.args);
		(void)talloc_get_type_abort_const(node->fmt, char);
		return;

	case XLAT_TMPL: {
		tmpl_t const *vpt = node->vpt;

		if (node->quote != node->vpt->quote) {
			if (node->vpt->quote == T_SOLIDUS_QUOTED_STRING) {
				/*
				 *	m'foo' versus /foo/
				 */
				fr_assert(node->quote != T_BARE_WORD);
			} else {
				/*
				 *	Mismatching quotes are bad.
				 */
				fr_assert(node->quote == T_BARE_WORD);
			}
		}

		if (tmpl_is_attr(vpt)) {
			fr_dict_attr_t const *da;
			da = tmpl_attr_tail_da(node->vpt);

			if (tmpl_rules_cast(node->vpt) != FR_TYPE_NULL) {
				/*
				 *	Casts must be omitted, unless we're using a cast as a way to get rid
				 *	of enum names.
				 */
				if (tmpl_rules_cast(node->vpt) == da->type) {
					fr_assert(da->flags.has_value);
				}

			} else if (node->quote != T_BARE_WORD) {
				fr_assert(da->type != FR_TYPE_STRING);
			}

			return;
		}

		/*
		 *	Casts should have been hoisted.
		 */
		if (tmpl_is_data(node->vpt)) {
			fr_assert(tmpl_rules_cast(node->vpt) == FR_TYPE_NULL);
		}

#if 0
		/*
		 *	@todo - xlats SHOULD have been hoisted, unless they're quoted or cast.
		 */
		if (tmpl_is_xlat(node->vpt)) {
			fr_assert((node->vpt->quote != T_BARE_WORD) ||
				  (tmpl_rules_cast(node->vpt) != FR_TYPE_NULL));
			return;
		}
#endif

		if (tmpl_is_exec(node->vpt) || tmpl_is_exec_unresolved(node->vpt)) {
			fr_assert(node->quote == T_BACK_QUOTED_STRING);
			fr_assert(!node->flags.constant);
			fr_assert(!node->flags.pure);
			fr_assert(!node->flags.can_purify);
		}

		return;
	}

	case XLAT_BOX:
		fr_assert(node->flags.constant);
		fr_assert(node->flags.pure);
//		fr_assert(node->flags.can_purify);
		break;

	default:
		break;
	}
}

/** Performs recursive validation of node lists
 */
void xlat_exp_head_verify(xlat_exp_head_t const *head)
{
	(void)talloc_get_type_abort_const(head, xlat_exp_head_t);

	xlat_exp_foreach(head, node) xlat_exp_verify(node);
}
#endif
