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

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/rad_assert.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

#ifdef HAVE_PTHREAD_H
#endif

static int _sql_conn_free(rlm_sql_handle_t *conn)
{
	rlm_sql_t *inst = conn->inst;

	rad_assert(inst);

	exec_trigger(NULL, inst->cs, "modules.sql.close", false);

	return 0;
}

static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	int rcode;
	rlm_sql_t *inst = instance;
	rlm_sql_handle_t *handle;

	/*
	 *	Connections cannot be alloced from the inst or
	 *	pool contexts due to threading issues.
	 */
	handle = talloc_zero(ctx, rlm_sql_handle_t);
	if (!handle) return NULL;

	/*
	 *	Handle requires a pointer to the SQL inst so the
	 *	destructor has access to the module configuration.
	 */
	handle->inst = inst;

	/*
	 *	When something frees this handle the destructor set by
	 *	the driver will be called first, closing any open sockets.
	 *	Then we call our destructor to trigger an modules.sql.close
	 *	event, then all the memory is freed.
	 */
	talloc_set_destructor(handle, _sql_conn_free);

	rcode = (inst->module->sql_socket_init)(handle, inst->config);
	if (rcode != 0) {
	fail:
		exec_trigger(NULL, inst->cs, "modules.sql.fail", true);

		/*
		 *	Destroy any half opened connections.
		 */
		talloc_free(handle);
		return NULL;
	}

	if (inst->config->open_query && *inst->config->open_query) {
		if (rlm_sql_select_query(&handle, inst, inst->config->open_query)) {
			goto fail;
		}
		(inst->module->sql_finish_select_query)(handle, inst->config);
	}

	exec_trigger(NULL, inst->cs, "modules.sql.open", false);
	return handle;
}

/*************************************************************************
 *
 *	Function: sql_socket_pool_init
 *
 *	Purpose: Connect to the sql server, if possible
 *
 *************************************************************************/
int sql_socket_pool_init(rlm_sql_t * inst)
{
	inst->pool = fr_connection_pool_module_init(inst->cs, inst, mod_conn_create, NULL, NULL);
	if (!inst->pool) return -1;

	return 1;
}

/*************************************************************************
 *
 *     Function: sql_poolfree
 *
 *     Purpose: Clean up and free sql pool
 *
 *************************************************************************/
void sql_poolfree(rlm_sql_t * inst)
{
	fr_connection_pool_delete(inst->pool);
}


/*************************************************************************
 *
 *	Function: sql_get_socket
 *
 *	Purpose: Return a SQL handle from the connection pool
 *
 *************************************************************************/
rlm_sql_handle_t * sql_get_socket(rlm_sql_t * inst)
{
	return fr_connection_get(inst->pool);
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL handle back to the connection pool
 *
 *************************************************************************/
int sql_release_socket(rlm_sql_t * inst, rlm_sql_handle_t * handle)
{
	fr_connection_release(inst->pool, handle);
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_userparse(TALLOC_CTX *ctx, VALUE_PAIR **head, rlm_sql_row_t row)
{
	VALUE_PAIR *vp;
	char const *ptr, *value;
	char buf[MAX_STRING_LEN];
	char do_xlat = 0;
	FR_TOKEN token, operator = T_EOL;

	/*
	 *	Verify the 'Attribute' field
	 */
	if (!row[2] || row[2][0] == '\0') {
		ERROR("rlm_sql: The 'Attribute' field is empty or NULL, skipping the entire row");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[4] != NULL && row[4][0] != '\0') {
		ptr = row[4];
		operator = gettoken(&ptr, buf, sizeof(buf), false);
		if ((operator < T_OP_ADD) ||
		    (operator > T_OP_CMP_EQ)) {
			ERROR("rlm_sql: Invalid operator \"%s\" for attribute %s", row[4], row[2]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		operator = T_OP_CMP_EQ;
		ERROR("rlm_sql: The 'op' field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		ERROR("rlm_sql: You MUST FIX THIS if you want the configuration to behave as you expect");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
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
			value = NULL;
			do_xlat = 1;
			break;

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
	vp = pairmake(ctx, NULL, row[2], NULL, operator);
	if (!vp) {
		ERROR("rlm_sql: Failed to create the pair: %s",
		       fr_strerror());
		return -1;
	}

	if (do_xlat) {
		if (pairmark_xlat(vp, value) < 0) {
			ERROR("rlm_sql: Error marking pair for xlat");

			talloc_free(vp);
			return -1;
		}
	} else {
		if (pairparsevalue(vp, value, 0) < 0) {
			ERROR("rlm_sql: Error parsing value: %s", fr_strerror());

			talloc_free(vp);
			return -1;
		}
	}

	/*
	 *	Add the pair into the packet
	 */
	pairadd(head, vp);
	return 0;
}


/*************************************************************************
 *
 *	Function: rlm_sql_fetch_row
 *
 *	Purpose: call the module's sql_fetch_row and implement re-connect
 *
 *************************************************************************/
int rlm_sql_fetch_row(rlm_sql_handle_t **handle, rlm_sql_t *inst)
{
	int ret;

	if (!*handle || !(*handle)->conn) {
		return -1;
	}

	/*
	 * We can't implement reconnect logic here, because the caller may require
	 * the original connection to free up queries or result sets associated with
	 * that connection.
	 */
	ret = (inst->module->sql_fetch_row)(*handle, inst->config);
	if (ret < 0) {
		char const *error = (inst->module->sql_error)(*handle, inst->config);
		ERROR("rlm_sql (%s): Error fetching row: %s",
		       inst->config->xlat_name, error ? error : "<UNKNOWN>");
	}

	return ret;
}

static void rlm_sql_query_error(rlm_sql_handle_t *handle, rlm_sql_t *inst)
{
	char const *p, *q;

	p = (inst->module->sql_error)(handle, inst->config);
	if (!p) {
		ERROR("rlm_sql (%s): Unknown query error", inst->config->xlat_name);
		return;
	}

	/*
	 *	Some drivers are nice and provide us with a ^ pointer to
	 *	the place in the query string where the error occurred.
	 *
	 *	For this to be useful we need to split log messages on
	 *	\n and output each of the lines individually.
	 */
	while ((q = strchr(p, '\n'))) {
		ERROR("rlm_sql (%s): %.*s", inst->config->xlat_name, (int) (q - p), p);
		p = q + 1;
	}

	if (*p != '\0') {
		ERROR("rlm_sql (%s): %s", inst->config->xlat_name, p);
	}
}

static void rlm_sql_query_debug(rlm_sql_handle_t *handle, rlm_sql_t *inst)
{
	char const *p, *q;

	p = (inst->module->sql_error)(handle, inst->config);
	if (!p) {
		return;
	}

	/*
	 *	Some drivers are nice and provide us with a ^ pointer to
	 *	the place in the query string where the error occurred.
	 *
	 *	For this to be useful we need to split log messages on
	 *	\n and output each of the lines individually.
	 */
	while ((q = strchr(p, '\n'))) {
		DEBUG2("rlm_sql (%s): %.*s", inst->config->xlat_name, (int) (q - p), p);
		p = q + 1;
	}

	if (*p != '\0') {
		DEBUG2("rlm_sql (%s): %s", inst->config->xlat_name, p);
	}
}

/** Call the driver's sql_query method, reconnecting if necessary.
 *
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 *	  previous reconnection attempt has failed.
 * @param inst rlm_sql instance data.
 * @param query to execute. Should not be zero length.
 * @return RLM_SQL_OK on success, RLM_SQL_RECONNECT if a new handle is required (also sets *handle = NULL),
 *         RLM_SQL_QUERY_ERROR/RLM_SQL_ERROR on invalid query or connection error, RLM_SQL_DUPLICATE on constraints
 *         violation.
 */
sql_rcode_t rlm_sql_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i;

	/* There's no query to run, return an error */
	if (query[0] == '\0') return RLM_SQL_QUERY_ERROR;

	/* There's no handle, we need a new one */
	if (!*handle) return RLM_SQL_RECONNECT;

	/* For sanity, for when no connections are viable, and we can't make a new one */
	for (i = fr_connection_get_num(inst->pool); i >= 0; i--) {
		DEBUG("rlm_sql (%s): Executing query: '%s'", inst->config->xlat_name, query);

		ret = (inst->module->sql_query)(*handle, inst->config, query);
		switch (ret) {
		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			*handle = fr_connection_reconnect(inst->pool, *handle);
			/* Reconnection failed */
			if (!*handle) return RLM_SQL_RECONNECT;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		case RLM_SQL_QUERY_ERROR:
		case RLM_SQL_ERROR:
			rlm_sql_query_error(*handle, inst);
			break;

		case RLM_SQL_DUPLICATE:
			rlm_sql_query_debug(*handle, inst);
			break;

		}

		return ret;
	}

	ERROR("rlm_sql (%s): Hit reconnection limit", inst->config->xlat_name);

	return RLM_SQL_ERROR;
}

/** Call the driver's sql_select_query method, reconnecting if necessary.
 *
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 *	  previous reconnection attempt has failed.
 * @param inst rlm_sql instance data.
 * @param query to execute. Should not be zero length.
 * @return RLM_SQL_OK on success, RLM_SQL_RECONNECT if a new handle is required (also sets *handle = NULL),
 *         RLM_SQL_QUERY_ERROR/RLM_SQL_ERROR on invalid query or connection error.
 */
sql_rcode_t rlm_sql_select_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i;

	/* There's no query to run, return an error */
	if (query[0] == '\0') return RLM_SQL_QUERY_ERROR;

	/* There's no handle, we need a new one */
	if (!*handle) return RLM_SQL_RECONNECT;

	/* For sanity, for when no connections are viable, and we can't make a new one */
	for (i = fr_connection_get_num(inst->pool); i >= 0; i--) {
		DEBUG("rlm_sql (%s): Executing query: '%s'", inst->config->xlat_name, query);

		ret = (inst->module->sql_select_query)(*handle, inst->config, query);
		switch (ret) {
		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			*handle = fr_connection_reconnect(inst->pool, *handle);
			/* Reconnection failed */
			if (!*handle) return RLM_SQL_RECONNECT;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		case RLM_SQL_QUERY_ERROR:
		case RLM_SQL_ERROR:
		default:
			rlm_sql_query_error(*handle, inst);
			break;
		}

		return ret;
	}

	ERROR("rlm_sql (%s): Hit reconnection limit", inst->config->xlat_name);

	return RLM_SQL_ERROR;
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int sql_getvpdata(rlm_sql_t * inst, rlm_sql_handle_t **handle,
		  TALLOC_CTX *ctx, VALUE_PAIR **pair, char const *query)
{
	rlm_sql_row_t row;
	int     rows = 0;

	if (rlm_sql_select_query(handle, inst, query)) {
		return -1;
	}

	while (rlm_sql_fetch_row(handle, inst) == 0) {
		row = (*handle)->row;
		if (!row)
			break;
		if (sql_userparse(ctx, pair, row) != 0) {
			ERROR("rlm_sql (%s): Error parsing user data from database result", inst->config->xlat_name);

			(inst->module->sql_finish_select_query)(*handle, inst->config);

			return -1;
		}
		rows++;
	}
	(inst->module->sql_finish_select_query)(*handle, inst->config);

	return rows;
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t *inst, REQUEST *request,
		       sql_acct_section_t *section, char const *query)
{
	int fd;
	char const *filename = NULL;
	char *expanded = NULL;
	size_t len;
	bool failed = false;	/* Write the log message outside of the critical region */

	if (section) {
		filename = section->logfile;
	} else {
		filename = inst->config->logfile;
	}

	if (!filename) {
		return;
	}

	if (radius_axlat(&expanded, request, filename, NULL, NULL) < 0) {
		return;
	}

	fd = fr_logfile_open(inst->lf, filename, 0640);
	if (fd < 0) {
		ERROR("rlm_sql (%s): Couldn't open logfile '%s': %s", inst->config->xlat_name,
		      expanded, fr_syserror(errno));

		talloc_free(expanded);
		return;
	}

	len = strlen(query);
	if ((write(fd, query, len) < 0) || (write(fd, ";\n", 2) < 0)) {
		failed = true;
	}

	if (failed) {
		ERROR("rlm_sql (%s): Failed writing to logfile '%s': %s", inst->config->xlat_name, expanded,
		      fr_syserror(errno));
	}

	talloc_free(expanded);
	fr_logfile_close(inst->lf, fd);
}
