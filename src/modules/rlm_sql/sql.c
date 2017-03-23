/*
 *  sql.c		rlm_sql - FreeRADIUS SQL Module
 *		Main code directly taken from ICRADIUS
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_sql (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/rad_assert.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

/*
 *	Translate rlm_sql rcodes to humanly
 *	readable reason strings.
 */
const FR_NAME_NUMBER sql_rcode_table[] = {
	{ "success",		RLM_SQL_OK		},
	{ "need alt query",	RLM_SQL_ALT_QUERY	},
	{ "server error",	RLM_SQL_ERROR		},
	{ "query invalid",	RLM_SQL_QUERY_INVALID	},
	{ "no connection",	RLM_SQL_RECONNECT	},
	{ "no more rows",	RLM_SQL_NO_MORE_ROWS	},
	{ NULL, 0 }
};

/** Look up a FD in the thread's FD to request map
 *
 * @param thread specific data
 * @param fd to look for
 * @return
 *  - #rlm_sql_fd_map_t pointer to map element
 *  - NULL if FD isn't in map
 */
rlm_sql_fd_map_t* sql_lookup_fd_map(rlm_sql_thread_t *thread, int fd)
{
	rlm_sql_t const *inst = thread->inst;
	rlm_sql_fd_map_t *curr = thread->fd_map;

	while (curr) {
		if (curr->fd == fd) break;

		curr = curr->next;
	}

	if (!curr) {
		ERROR("Failed looking up %d in FD map", fd);
	}

	return curr;
}

/** Talloc desctructor for #rlm_sql_fd_map_t
 *
 * The destructor can only be called if the request times out
 * In such a case, the underlying SQL query is left hanging.
 * We therefore close connection to DB to free up whatever memory is used.
 * We also need to removes map element from the thread's chained list
 * and remove the timer on the query.
 *
 * @param map_elt #rlm_sql_fd_map_t being freed
 * @return
 *  - 0
 */
static int sql_free_fd_map(rlm_sql_fd_map_t *map_elt)
{
	rlm_sql_handle_t *handle = map_elt->handle;

	/*
	 * Remove element from chained list before freeing memory
	 */
	if (map_elt->prev) {
		map_elt->prev->next = map_elt->next;
	} else {
		*map_elt->head = map_elt->next;
	}
	if (map_elt->next) {
		map_elt->next->prev = map_elt->prev;
	}

	/*
	 * Delete timer
	 */
	fr_event_timer_delete(handle->thread->el, &map_elt->ev);

	/*
	 * If request is canceled, close connection to force any ongoing query to be cancelled
	 */
	fr_connection_close(handle->thread->pool, NULL, handle);

	return 0;
}

/** Update thread's FD to request map
 *
 * Get FD from DB connection handler and map FD to request being processed.
 * Update IO hadnlers for FD
 *
 * @param inst #rlm_sql_t instance
 * @param handle #rlm_sql_handle_t DB connection instance
 * @param request to add to map
 * @param thread specific data
 */
static void sql_update_fd_map(rlm_sql_t const *inst, rlm_sql_handle_t *handle, REQUEST *request, rlm_sql_thread_t *thread)
{
	rlm_sql_fd_map_t *prev = NULL, *curr = thread->fd_map;
	int fd = (inst->driver->sql_get_fd)(handle);

	if (fd < 0) {
		ERROR("Failed getting FD, can't update FD map");
	} else {
		while (curr) {
			if (curr->fd == fd) break;

			prev = curr;
			curr = curr->next;
		}

		if (curr) {
			DEBUG4("Updating request for fd %d", fd);
			curr->request = request;
		} else {
			DEBUG4("Inserting request for fd %d", fd);
			curr = talloc_zero(request, rlm_sql_fd_map_t);
			talloc_set_destructor(curr, sql_free_fd_map);
			curr->fd = fd;
			curr->request = request;
			curr->handle = handle;

			/*
			 * Add eletement to chained list
			 */
			if (prev) {
				curr->prev = prev;
				prev->next = curr;
			} else {
				thread->fd_map = curr;
				curr->prev = NULL;
			}
			curr->head = &thread->fd_map;
		}

		sql_set_io_event_handlers(inst, SQL_READ_WRITE, thread, fd, curr);
	}
}

/** Delete FD from thread's FD to request map
 *
 * Remove map element from chained list and remove IO handlers for FD
 *
 * @param inst #rlm_sql_t instance
 * @param handle #rlm_sql_handle_t DB connection instance
 * @param thread specific data
 */
static void sql_delete_fd_map(rlm_sql_t const *inst, rlm_sql_handle_t *handle, rlm_sql_thread_t *thread)
{
	rlm_sql_fd_map_t *curr = thread->fd_map;
	int fd = (inst->driver->sql_get_fd)(handle);

	if (fd < 0) {
		ERROR("Failed getting FD, can't delete entry from FD map");
	} else {
		while (curr) {
			if (curr->fd == fd) break;

			curr = curr->next;
		}

		if (!curr) {
			DEBUG4("fd %d not found in map", fd);
		} else {
			DEBUG4("Deleting map entry for fd %d", fd);
			/*
			 * Remove element from chained list
			 */
			if (curr->prev) {
				curr->prev->next = curr->next;
			} else {
				*curr->head = curr->next;
			}
			if (curr->next) {
				curr->next->prev = curr->prev;
			}

			/*
			 * Unregister IO handlers for FD
			 */
			sql_set_io_event_handlers(inst, SQL_REMOVE, thread, fd, curr);

			/*
			 * Disable destructor as it's only to handle case where object
			 * is freed because request (talloc ctx) is freed to.
			 */
			talloc_set_destructor(curr, NULL);
			talloc_free(curr);
		}
	}
}

void *mod_conn_create(TALLOC_CTX *ctx, void *thread, struct timeval const *timeout)
{
	int rcode;
	rlm_sql_thread_t *t = thread;
	rlm_sql_t const *inst = t->inst;
	rlm_sql_handle_t *handle;

	/*
	 *	Connections cannot be alloced from the inst or
	 *	pool contexts due to threading issues.
	 */
	handle = talloc_zero(ctx, rlm_sql_handle_t);
	if (!handle) return NULL;

	handle->log_ctx = talloc_pool(handle, 2048);
	if (!handle->log_ctx) {
		talloc_free(handle);
		return NULL;
	}

	/*
	 *	Handle requires a pointer to the SQL inst so the
	 *	destructor has access to the module configuration.
	 */
	handle->inst = inst;

	handle->thread = t;

	rcode = (inst->driver->sql_socket_init)(handle, inst->config, timeout);
	if (rcode != 0) {
	fail:
		/*
		 *	Destroy any half opened connections.
		 */
		talloc_free(handle);
		return NULL;
	}

	if (inst->config->connect_query) {
		if (rlm_sql_select_query(inst, NULL, &handle, inst->config->connect_query) != RLM_SQL_OK) goto fail;
		(inst->driver->sql_finish_select_query)(handle, inst->config);
	}

	return handle;
}

/*************************************************************************
 *
 *	Function: sql_fr_pair_list_afrom_str
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_fr_pair_list_afrom_str(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **head, rlm_sql_row_t row)
{
	VALUE_PAIR *vp;
	char const *ptr, *value;
	char buf[FR_MAX_STRING_LEN];
	char do_xlat = 0;
	FR_TOKEN token, op = T_EOL;

	/*
	 *	Verify the 'Attribute' field
	 */
	if (!row[2] || row[2][0] == '\0') {
		REDEBUG("Attribute field is empty or NULL, skipping the entire row");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[4] != NULL && row[4][0] != '\0') {
		ptr = row[4];
		op = gettoken(&ptr, buf, sizeof(buf), false);
		if (!fr_assignment_op[op] && !fr_equality_op[op]) {
			REDEBUG("Invalid op \"%s\" for attribute %s", row[4], row[2]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		op = T_OP_CMP_EQ;
		REDEBUG("The op field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		REDEBUG("You MUST FIX THIS if you want the configuration to behave as you expect");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
	if (!row[3]) {
		REDEBUG("Value field is empty or NULL, skipping the entire row");
		return -1;
	}

	value = row[3];

	/*
	 *	If we have a new-style quoted string, where the
	 *	*entire* string is quoted, do xlat's.
	 */
	if (row[3] != NULL &&
	   ((row[3][0] == '\'') || (row[3][0] == '`') || (row[3][0] == '"')) &&
	   (row[3][0] == row[3][strlen(row[3])-1])) {

		token = gettoken(&value, buf, sizeof(buf), false);
		switch (token) {
		/*
		 *	Take the unquoted string.
		 */
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			value = buf;
			break;

		/*
		 *	Mark the pair to be allocated later.
		 */
		case T_BACK_QUOTED_STRING:
			do_xlat = 1;

			/* FALL-THROUGH */

		/*
		 *	Keep the original string.
		 */
		default:
			value = row[3];
			break;
		}
	}

	/*
	 *	Create the pair
	 */
	vp = fr_pair_make(ctx, NULL, row[2], NULL, op);
	if (!vp) {
		REDEBUG("Failed to create the pair: %s", fr_strerror());
		return -1;
	}

	if (do_xlat) {
		if (fr_pair_mark_xlat(vp, value) < 0) {
			REDEBUG("Error marking pair for xlat: %s", fr_strerror());

			talloc_free(vp);
			return -1;
		}
	} else {
		if (fr_pair_value_from_str(vp, value, -1) < 0) {
			REDEBUG("Error parsing value: %s", fr_strerror());

			talloc_free(vp);
			return -1;
		}
	}

	/*
	 *	Add the pair into the packet
	 */
	fr_pair_add(head, vp);
	return 0;
}

/** Call the driver's sql_fetch_row function
 *
 * Calls the driver's sql_fetch_row logging any errors. On success, will
 * write row data to ``(*handle)->row``.
 *
 * @param out Where to write row data.
 * @param inst Instance of #rlm_sql_t.
 * @param request The Current request, may be NULL.
 * @param handle Handle to retrieve errors for.
 * @return
 *	- #RLM_SQL_OK on success.
 *	- other #sql_rcode_t constants on error.
 */
sql_rcode_t rlm_sql_fetch_row(rlm_sql_row_t *out, rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle)
{
	sql_rcode_t ret;

	if (!*handle || !(*handle)->conn) return RLM_SQL_ERROR;

	/*
	 *	We can't implement reconnect logic here, because the caller
	 *	may require the original connection to free up queries or
	 *	result sets associated with that connection.
	 */
	ret = (inst->driver->sql_fetch_row)(out, *handle, inst->config);
	switch (ret) {
	case RLM_SQL_OK:
		rad_assert(*out != NULL);
		return ret;

	case RLM_SQL_NO_MORE_ROWS:
		rad_assert(*out == NULL);
		return ret;

	default:
		ROPTIONAL(RERROR, ERROR, "Error fetching row");
		rlm_sql_print_error(inst, request, *handle, false);
		return ret;
	}
}

/** Retrieve any errors from the SQL driver
 *
 * Retrieves errors from the driver from the last operation and writes them to
 * to request/global log, in the ERROR, WARN, INFO and DEBUG categories.
 *
 * @param inst Instance of rlm_sql.
 * @param request Current request, may be NULL.
 * @param handle Handle to retrieve errors for.
 * @param force_debug Force all errors to be logged as debug messages.
 */
void rlm_sql_print_error(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t *handle, bool force_debug)
{
	char const	*driver;
	sql_log_entry_t	log[20];
	size_t		num, i;

	num = (inst->driver->sql_error)(handle->log_ctx, log, (sizeof(log) / sizeof(*log)), handle, inst->config);
	if (num == 0) {
		ROPTIONAL(RERROR, ERROR, "Unknown error");
		return;
	}

	driver = inst->config->sql_driver_name;

	for (i = 0; i < num; i++) {
		if (force_debug) goto debug;

		switch (log[i].type) {
		case L_ERR:
			ROPTIONAL(RERROR, ERROR, "%s: %s", driver, log[i].msg);
			break;

		case L_WARN:
			ROPTIONAL(RWARN, WARN, "%s: %s", driver, log[i].msg);
			break;

		case L_INFO:
			ROPTIONAL(RINFO, INFO, "%s: %s", driver, log[i].msg);
			break;

		case L_DBG:
		default:
		debug:
			ROPTIONAL(RDEBUG, DEBUG, "%s: %s", driver, log[i].msg);
			break;
		}
	}

	talloc_free_children(handle->log_ctx);
}

static rlm_rcode_t rlm_sql_query_retry(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);

/** Call the driver's sql_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_query)(handle, inst->config);``
 *	after they're done with the result.
 *
 * #param request Current request.
 * @param inst #rlm_sql_t instance data.
 * @param thread #rlm_sql_thread_t thread data.
 * @param ctx #rlm_sql_query_ctx_t thread specific function context.
 * @return
 *	- #RLM_MODULE_OK if not yielding. See ctx->rcode for actual SQL return status
 *	- #RLM_MODULE_YIELD if the driver is async and needs to yield
 */
rlm_rcode_t rlm_sql_query(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_thread_t *t = thread;
	rlm_sql_query_ctx_t *query_ctx = ctx;

	query_ctx->rcode = RLM_SQL_ERROR;

	/* Caller should check they have a valid handle */
	rad_assert(*query_ctx->handle);

	/* There's no query to run, return an error */
	if (query_ctx->query[0] == '\0') {
		if (request) REDEBUG("Zero length query");

		query_ctx->rcode = RLM_SQL_QUERY_INVALID;

		return RLM_MODULE_OK;
	}

	/*
	 *  t->pool may be NULL is this function is called by mod_conn_create.
	 */
	query_ctx->max_attempts = t->pool ? fr_connection_pool_state(t->pool)->num : 0;

	query_ctx->curr_attempt = 0;
	query_ctx->next_step = SELECT_QUERY_START;

	return rlm_sql_query_retry(request, instance, thread, ctx);
}

static rlm_rcode_t rlm_sql_query_retry(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_thread_t *t = thread;
	rlm_sql_query_ctx_t *query_ctx = ctx;
	rlm_sql_t const *inst = instance;

	/*
	 *  Here we try with each of the existing connections, then try to create
	 *  a new connection, then give up.
	 */
	do {
		if (query_ctx->next_step == SELECT_QUERY_START) {
			ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query);

			query_ctx->sql_ret = (inst->driver->sql_query)(*query_ctx->handle, inst->config, query_ctx->query);

			if (query_ctx->sql_ret == RLM_SQL_YIELD) {
				query_ctx->next_step = SELECT_QUERY_RESUME;
				sql_update_fd_map(inst, *query_ctx->handle, request, (rlm_sql_thread_t *)thread);
				return unlang_yield(request, rlm_sql_query_retry, NULL, ctx);
			}
		}

		/*
		 * In case the driver is asynchronous, get the current query status
		 */
		if (query_ctx->sql_ret == RLM_SQL_YIELD)
			query_ctx->sql_ret = (inst->driver->sql_query_status)(*query_ctx->handle, inst->config);

		switch (query_ctx->sql_ret) {
		/*
		 * We might not have enough data available.
		 */
		case RLM_SQL_YIELD:
			sql_update_fd_map(inst, *query_ctx->handle, request, (rlm_sql_thread_t *)thread);
			return unlang_yield(request, rlm_sql_query_retry, NULL, ctx);

		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			/*
			 * Delete FD map entry before reconnecting
			 */
			sql_delete_fd_map(inst, *query_ctx->handle, (rlm_sql_thread_t *)thread);
			*query_ctx->handle = fr_connection_reconnect(t->pool, request, *query_ctx->handle);
			/* Reconnection failed */
			if (!*query_ctx->handle) {
				query_ctx->rcode = RLM_SQL_RECONNECT;
				return RLM_MODULE_OK;
			}

			/* Reconnection succeeded, try again with the new handle */
			query_ctx->curr_attempt++;
			continue;

		/*
		 *	These are bad and should make rlm_sql return invalid
		 */
		case RLM_SQL_QUERY_INVALID:
			rlm_sql_print_error(inst, request, *query_ctx->handle, false);
			(inst->driver->sql_finish_query)(*query_ctx->handle, inst->config);
			break;

		/*
		 *	Server or client errors.
		 *
		 *	If the driver claims to be able to distinguish between
		 *	duplicate row errors and other errors, and we hit a
		 *	general error treat it as a failure.
		 *
		 *	Otherwise rewrite it to RLM_SQL_ALT_QUERY.
		 */
		case RLM_SQL_ERROR:
			if (inst->driver->flags & RLM_SQL_RCODE_FLAGS_ALT_QUERY) {
				rlm_sql_print_error(inst, request, *query_ctx->handle, false);
				(inst->driver->sql_finish_query)(*query_ctx->handle, inst->config);
				break;
			}
			query_ctx->sql_ret = RLM_SQL_ALT_QUERY;
			/* FALL-THROUGH */

		/*
		 *	Driver suggested using an alternative query
		 */
		case RLM_SQL_ALT_QUERY:
			rlm_sql_print_error(inst, request, *query_ctx->handle, true);
			(inst->driver->sql_finish_query)(*query_ctx->handle, inst->config);
			break;

		case RLM_SQL_CLOSE:
			sql_delete_fd_map(inst, *query_ctx->handle, (rlm_sql_thread_t *)thread);
			*query_ctx->handle = fr_connection_reconnect(t->pool, request, *query_ctx->handle);
			query_ctx->sql_ret = RLM_SQL_ERROR;
			break;
		}

		sql_delete_fd_map(inst, *query_ctx->handle, (rlm_sql_thread_t *)thread);

		query_ctx->rcode = query_ctx->sql_ret;
		return RLM_MODULE_OK;
	} while (query_ctx->curr_attempt < (query_ctx->max_attempts + 1));


	ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	query_ctx->rcode = RLM_SQL_ERROR;

	return RLM_MODULE_OK;
}

static rlm_rcode_t rlm_sql_select_query_retry(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);

/** Call the driver's sql_select_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_select_query)(handle, inst->config);``
 *	after they're done with the result.
 *
 * #param request Current request.
 * @param inst #rlm_sql_t instance data.
 * @param thread #rlm_sql_thread_t thread data.
 * @param ctx #rlm_sql_query_ctx_t thread specific function context.
 * @return
 *	- #RLM_MODULE_OK if not yielding. See ctx->rcode for actual SQL return status
 *	- #RLM_MODULE_YIELD if the driver is async and needs to yield
 */
rlm_rcode_t rlm_sql_select_query(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_thread_t *t = thread;
	rlm_sql_query_ctx_t *select_query_ctx = ctx;

	select_query_ctx->rcode = RLM_SQL_ERROR;

	/* Caller should check they have a valid handle */
	rad_assert(*select_query_ctx->handle);

	/* There's no query to run, return an error */
	if (select_query_ctx->query[0] == '\0') {
		if (request) REDEBUG("Zero length query");

		select_query_ctx->rcode = RLM_SQL_QUERY_INVALID;

		return RLM_MODULE_OK;
	}

	/*
	 *  inst->pool may be NULL is this function is called by mod_conn_create.
	 */
	select_query_ctx->max_attempts = t->pool ? fr_connection_pool_state(t->pool)->num : 0;

	select_query_ctx->curr_attempt = 0;
	select_query_ctx->next_step = SELECT_QUERY_START;

	return rlm_sql_select_query_retry(request, instance, thread, ctx);
}

static rlm_rcode_t rlm_sql_select_query_retry(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_thread_t *t = thread;
	rlm_sql_query_ctx_t *select_query_ctx = ctx;
	rlm_sql_t const *inst = instance;

	/*
	 *  For sanity, for when no connections are viable, and we can't make a new one
	 */
	do {
		if (select_query_ctx->next_step == SELECT_QUERY_START) {
			ROPTIONAL(RDEBUG2, DEBUG2, "Executing select query: %s", select_query_ctx->query);

			select_query_ctx->sql_ret = (inst->driver->sql_select_query)(*select_query_ctx->handle, inst->config, select_query_ctx->query);

			/*
			 * If query executed outside scope of request (request is NULL), disable async
			 */
			if (select_query_ctx->sql_ret == RLM_SQL_YIELD) { // && request) {
				select_query_ctx->next_step = SELECT_QUERY_RESUME;
				sql_update_fd_map(inst, *select_query_ctx->handle, request, (rlm_sql_thread_t *)thread);
				return unlang_yield(request, rlm_sql_select_query_retry, NULL, ctx);
			}
		}

		/*
		 * In case the driver is asynchronous, get the current query status
		 */
		if (select_query_ctx->sql_ret == RLM_SQL_YIELD)
			select_query_ctx->sql_ret = (inst->driver->sql_select_query_status)(*select_query_ctx->handle, inst->config);

		switch (select_query_ctx->sql_ret) {
		/*
		 * We might not have enough data available.
		 */
		case RLM_SQL_YIELD:
			sql_update_fd_map(inst, *select_query_ctx->handle, request, (rlm_sql_thread_t *)thread);
			return unlang_yield(request, rlm_sql_select_query_retry, NULL, ctx);

		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			/*
			 * Delete FD map entry before reconnecting
			 */
			sql_delete_fd_map(inst, *select_query_ctx->handle, (rlm_sql_thread_t *)thread);
			*select_query_ctx->handle = fr_connection_reconnect(t->pool, request, *select_query_ctx->handle);
			/* Reconnection failed */
			if (!*select_query_ctx->handle) {
				select_query_ctx->rcode = RLM_SQL_RECONNECT;
				return RLM_MODULE_OK;
			}

			/* Reconnection succeeded, try again with the new handle */
			select_query_ctx->curr_attempt++;
			select_query_ctx->next_step = SELECT_QUERY_START;
			continue;

		case RLM_SQL_CLOSE:
			sql_delete_fd_map(inst, *select_query_ctx->handle, (rlm_sql_thread_t *)thread);
			*select_query_ctx->handle = fr_connection_reconnect(t->pool, request, *select_query_ctx->handle);
			select_query_ctx->sql_ret = RLM_SQL_ERROR;
			break;

		case RLM_SQL_QUERY_INVALID:
		case RLM_SQL_ERROR:
		default:
			rlm_sql_print_error(inst, request, *select_query_ctx->handle, false);
			(inst->driver->sql_finish_select_query)(*select_query_ctx->handle, inst->config);
			break;
		}

		sql_delete_fd_map(inst, *select_query_ctx->handle, (rlm_sql_thread_t *)thread);

		select_query_ctx->rcode = select_query_ctx->sql_ret;
		return RLM_MODULE_OK;
	} while (select_query_ctx->curr_attempt < (select_query_ctx->max_attempts + 1));

	 ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	 select_query_ctx->rcode = RLM_SQL_ERROR;

	 return RLM_MODULE_OK;
}

/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
static rlm_rcode_t sql_getvpdata_resume(REQUEST *request, void *instance, void *thread, void *ctx);

rlm_rcode_t sql_getvpdata(REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_getvpdata_ctx_t *sql_getvpdata_ctx = talloc_get_type_abort(ctx, rlm_sql_getvpdata_ctx_t);
	rlm_sql_query_ctx_t *select_query_ctx;

	rad_assert(request);

	sql_getvpdata_ctx->select_query_ctx = talloc_zero(sql_getvpdata_ctx, rlm_sql_query_ctx_t);

	select_query_ctx = sql_getvpdata_ctx->select_query_ctx;
	select_query_ctx->handle = sql_getvpdata_ctx->handle;
	select_query_ctx->query = sql_getvpdata_ctx->query;

	return unlang_two_step_process(request, rlm_sql_select_query, select_query_ctx, sql_getvpdata_resume, sql_getvpdata_ctx);
}

static rlm_rcode_t sql_getvpdata_resume(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_getvpdata_ctx_t *sql_getvpdata_ctx = talloc_get_type_abort(ctx, rlm_sql_getvpdata_ctx_t);
	rlm_sql_query_ctx_t *select_query_ctx = sql_getvpdata_ctx->select_query_ctx;
	rlm_sql_row_t	row;
	TALLOC_CTX *talloc_ctx = sql_getvpdata_ctx->talloc_ctx;
	rlm_sql_t const *inst = instance;

	rad_assert(talloc_ctx);

	sql_getvpdata_ctx->rows = 0;

	/* error handled by rlm_sql_select_query */
	sql_getvpdata_ctx->rcode = select_query_ctx->rcode;

	if (select_query_ctx->rcode == RLM_SQL_OK) {
		while (rlm_sql_fetch_row(&row, inst, request, sql_getvpdata_ctx->handle) == RLM_SQL_OK) {
			if (sql_fr_pair_list_afrom_str(talloc_ctx, request, &sql_getvpdata_ctx->attr, row) != 0) {
				REDEBUG("Error parsing user data from database result");

				(inst->driver->sql_finish_select_query)(*sql_getvpdata_ctx->handle, inst->config);

				return RLM_MODULE_FAIL;
			}
			sql_getvpdata_ctx->rows++;
		}
		(inst->driver->sql_finish_select_query)(*sql_getvpdata_ctx->handle, inst->config);
	}

	return RLM_MODULE_OK;
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t const *inst, REQUEST *request, sql_acct_section_t *section, char const *query)
{
	int fd;
	char const *filename = NULL;
	char *expanded = NULL;
	size_t len;
	bool failed = false;	/* Write the log message outside of the critical region */

	filename = inst->config->logfile;
	if (section && section->logfile) filename = section->logfile;

	if (!filename || !*filename) {
		return;
	}

	if (xlat_aeval(request, &expanded, request, filename, NULL, NULL) < 0) {
		return;
	}

	fd = exfile_open(inst->ef, request, filename, 0640, true);
	if (fd < 0) {
		ERROR("Couldn't open logfile '%s': %s", expanded, fr_syserror(errno));

		talloc_free(expanded);
		return;
	}

	len = strlen(query);
	if ((write(fd, query, len) < 0) || (write(fd, ";\n", 2) < 0)) {
		failed = true;
	}

	if (failed) ERROR("Failed writing to logfile '%s': %s", expanded, fr_syserror(errno));

	talloc_free(expanded);
	exfile_close(inst->ef, request, fd);
}
