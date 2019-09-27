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

/** Run the interpreter after creating a subrequest.
 *
 * Just run some "unlang", but don't do anything else.
 *
 * This is a shim function added to 'fake' requests by the subrequest and parallel keywords.
 */
rlm_rcode_t unlang_io_process_interpret(UNUSED void const *instance, REQUEST *request)
{
	rlm_rcode_t rcode;

	REQUEST_VERIFY(request);

	rcode = unlang_interpret_resume(request);

	/*
	 *	We've yielded, and can keep running.  Do so.
	 */
	if ((rcode == RLM_MODULE_YIELD) &&
	    (request->master_state != REQUEST_STOP_PROCESSING)) {
		return RLM_MODULE_YIELD;
	}

	/*
	 *	Either we're done naturally, or we're forcibly done.  Stop.
	 *
	 *	If we have a parent, then we're running synchronously
	 *	with it.  Allow the parent to resume.
	 */
	if (request->parent) unlang_interpret_resumable(request->parent);

	/*
	 *	Don't bother setting request->reply->code.
	 */
	return RLM_MODULE_HANDLED;
}

/** Allocate a child request based on the parent.
 *
 * @param[in] parent		spawning the child request.
 * @param[in] namespace		the child request operates in. If NULL the parent's namespace is used.
 * @param[in] detachable	Allow/disallow the child to be detached.
 * @return
 *      - The new child request.
 *	- NULL on error.
 */
REQUEST *unlang_io_subrequest_alloc(REQUEST *parent, fr_dict_t const *namespace, bool detachable)
{
	REQUEST			*child;

	if (!detachable) {
		child = request_alloc_fake(parent, namespace);
	} else {
		child = request_alloc_detachable(parent, namespace);
	}
	if (!child) return NULL;

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
	child->server_cs = parent->server_cs;
	child->backlog = parent->backlog;

	/*
	 *	Initialize all of the async fields.
	 */
	child->async = talloc_zero(child, fr_async_t);

#define COPY_FIELD(_x) child->async->_x = parent->async->_x
	COPY_FIELD(listen);
	COPY_FIELD(recv_time);
	child->async->original_recv_time = &child->async->recv_time;
	child->async->fake = true;

	/*
	 *	Always set the "process" function to the local
	 *	bare-bones function which just runs on section of
	 *	"unlang", and doesn't send replies or anything else.
	 */
	child->async->process = unlang_io_process_interpret;

	/*
	 *	Note that we don't do time tracking on the child.
	 *	Instead, all of it is done in the context of the
	 *	parent.
	 */
	fr_dlist_init(&child->async->tracking.list, fr_time_tracking_t, list.entry);

	return child;
}
