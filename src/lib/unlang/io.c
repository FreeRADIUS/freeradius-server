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
 * @file unlang/io.c
 * @brief Shim I/O worker functions for running fake requests.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/io/listen.h>
#include "unlang_priv.h"

/** Allocate a child request based on the parent.
 *
 * @param[in] parent		spawning the child request.
 * @param[in] namespace		the child request operates in. If NULL the parent's namespace is used.
 * @param[in] detachable	Allow/disallow the child to be detached.
 * @return
 *      - The new child request.
 *	- NULL on error.
 */
request_t *unlang_io_subrequest_alloc(request_t *parent, fr_dict_t const *namespace, bool detachable)
{
	request_t		*child;

	child = request_alloc(detachable ? NULL : parent,
			      (&(request_init_args_t){
			      		.parent = parent,
			      		.namespace = namespace,
			      		.detachable = detachable
			      }));
	if (!child) return NULL;

	/*
	 *	Child gets its parent's interpreter
	 */
	((unlang_stack_t *)child->stack)->intp = ((unlang_stack_t *)parent->stack)->intp;

	/*
	 *	Push the child, and set it's top frame to be true.
	 */
	child->log.unlang_indent = parent->log.unlang_indent;

	/*
	 *	Initialize some basic information for the child.
	 *
	 *	Note that we do NOT initialize child->backlog, as the
	 *	child is never resumable... the parent is resumable.
	 */
	child->number = parent->number;
	child->el = parent->el;
	child->backlog = parent->backlog;

	/*
	 *	Initialize all of the async fields.
	 */
	child->async = talloc_zero(child, fr_async_t);

#define COPY_FIELD(_x) child->async->_x = parent->async->_x
	COPY_FIELD(recv_time);
	fr_assert(request_is_internal(child));

	REQUEST_VERIFY(child);

	return child;
}
