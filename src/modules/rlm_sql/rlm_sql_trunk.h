#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_sql_trunk.h
 * @brief Macros to reduce boilerplate in trunk SQL drivers
 *
 * @copyright 2024 The FreeRADIUS server project
 */
RCSIDH(rlm_sql_trunk_h, "$Id$")

/** Allocate an SQL trunk connection
 *
 * @param[in] tconn		Trunk handle.
 * @param[in] el		Event list which will be used for I/O and timer events.
 * @param[in] conn_conf		Configuration of the connection.
 * @param[in] log_prefix	What to prefix log messages with.
 * @param[in] uctx		User context passed to trunk_alloc.
 */
#define SQL_TRUNK_CONNECTION_ALLOC \
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */ \
static connection_t *sql_trunk_connection_alloc(trunk_connection_t *tconn, fr_event_list_t *el, \
						   connection_conf_t const *conn_conf, \
						   char const *log_prefix, void *uctx) \
{ \
	connection_t		*conn; \
	rlm_sql_thread_t	*thread = talloc_get_type_abort(uctx, rlm_sql_thread_t); \
	conn = connection_alloc(tconn, el, \
				   &(connection_funcs_t){ \
				   	.init = _sql_connection_init, \
				   	.close = _sql_connection_close \
				   }, \
				   conn_conf, log_prefix, thread->inst); \
	if (!conn) { \
		PERROR("Failed allocating state handler for new SQL connection"); \
		return NULL; \
	} \
	return conn; \
}

#define SQL_QUERY_RESUME \
static unlang_action_t sql_query_resume(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx) \
{ \
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t); \
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL; \
	RETURN_MODULE_OK; \
}

#define SQL_QUERY_FAIL \
static void sql_request_fail(request_t *request, void *preq, UNUSED void *rctx, \
			     UNUSED trunk_request_state_t state, UNUSED void *uctx) \
{ \
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t); \
	query_ctx->treq = NULL; \
	if (query_ctx->rcode == RLM_SQL_OK) query_ctx->rcode = RLM_SQL_ERROR; \
	if (request) unlang_interpret_mark_runnable(request); \
}
