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
 * @file tls/virtual_server.c
 * @brief Calls a section in the TLS policy virtual server.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/server/virtual_servers.h>

#include "attrs.h"
#include "base.h"
#include "cache.h"

/** Push a request to perform a policy action using a virtual server
 *
 * This function will setup a TLS subrequest to run a virtual server section.
 *
 * @param[out] child		to run as a subrequest of the parent.
 * @param[in] resume		Function to call after the virtual server
 *      			finishes processing the request. uctx will
 *				be a pointer to the provided tls_session.
 * @param[in] conf		the tls configuration.
 * @param[in] tls_session	The current tls_session.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
unlang_action_t fr_tls_call_push(request_t *child, unlang_function_t resume,
				 fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	fr_assert(tls_session->cache);

	/*
	 *	Sets up a dispatch frame in the parent
	 *	and a result processing frame in the child.
	 */
	if (unlang_subrequest_child_push(NULL, child,
					 &(unlang_subrequest_session_t){
						.enable = true,
						.unique_ptr = tls_session
					 },
					 true, UNLANG_SUB_FRAME) < 0) {
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Setup a function to execute after the
	 *	subrequest completes.
	 */
	if (unlang_function_push(child, NULL, resume,
				 NULL, UNLANG_SUB_FRAME, tls_session) < 0) return UNLANG_ACTION_FAIL;

	/*
	 *	Now the child and parent stacks are both
	 *	setup correctly, push a virtual server
	 *	call into the subrequest to run the section
	 *	specified by Packet-Type.
	 */
	if (unlang_call_push(child, conf->virtual_server, UNLANG_SUB_FRAME) < 0) {
		request_detach(child);
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}
#endif
