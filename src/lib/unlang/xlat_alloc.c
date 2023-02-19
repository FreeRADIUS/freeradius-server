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
#include <freeradius-devel/unlang/xlat.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/types.h>

#define _XLAT_PRIVATE
#include <freeradius-devel/unlang/xlat_priv.h>

xlat_exp_head_t *_xlat_exp_head_alloc(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx)
{
	xlat_exp_head_t *head;

	MEM(head = talloc_zero(ctx, xlat_exp_head_t));

	fr_dlist_init(&head->dlist, xlat_exp_t, entry);
	head->flags.pure = true;
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
	case XLAT_ALTERNATE:
		TALLOC_FREE(node->alternate[0]);
		TALLOC_FREE(node->alternate[1]);
		break;

	case XLAT_GROUP:
		TALLOC_FREE(node->group);
		break;

	case XLAT_FUNC:
	case XLAT_FUNC_UNRESOLVED:
		if (type != XLAT_FUNC) {
			TALLOC_FREE(node->call.args); /* Just switching from unresolved to resolved */
		} else goto done;
		break;

	default:
		break;
	}

	/*
	 *	Alloc new lists to match the type
	 */
	switch (type) {
	case XLAT_ALTERNATE:
		node->alternate[0] = _xlat_exp_head_alloc(NDEBUG_LOCATION_VALS node);
		node->alternate[1] = _xlat_exp_head_alloc(NDEBUG_LOCATION_VALS node);
		break;

	case XLAT_GROUP:
		node->group = _xlat_exp_head_alloc(NDEBUG_LOCATION_VALS node);
		break;

	case XLAT_FUNC:
	case XLAT_FUNC_UNRESOLVED:
		node->call.args = _xlat_exp_head_alloc(NDEBUG_LOCATION_VALS node);
		break;

	default:
		break;
	}

done:
	node->type = type;
}

static xlat_exp_t *xlat_exp_alloc_pool(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, unsigned int extra_hdrs, size_t extra)
{
	xlat_exp_t *node;

	MEM(node = talloc_zero_pooled_object(ctx, xlat_exp_t, extra_hdrs, extra));
	node->flags.pure = true;	/* everything starts pure */
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
	case XLAT_ALTERNATE:
		extra_hdrs = 2;
		extra = sizeof(xlat_exp_head_t) * 2;
		break;

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

/** Set the format string for an xlat node
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 */
void xlat_exp_set_name_buffer_shallow(xlat_exp_t *node, char const *fmt)
{
	if (node->fmt) talloc_const_free(node->fmt);
	node->fmt = talloc_get_type_abort(fmt, char);
}
