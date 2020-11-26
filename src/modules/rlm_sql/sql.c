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
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2001 Chad Miller (cmiller@surfsouth.com)
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_sql (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include	<freeradius-devel/server/base.h>
#include	<freeradius-devel/util/debug.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

/*
 *	Translate rlm_sql rcodes to humanly
 *	readable reason strings.
 */
fr_table_num_sorted_t const sql_rcode_description_table[] = {
	{ L("need alt query"),	RLM_SQL_ALT_QUERY	},
	{ L("no connection"),	RLM_SQL_RECONNECT	},
	{ L("no more rows"),	RLM_SQL_NO_MORE_ROWS	},
	{ L("query invalid"),	RLM_SQL_QUERY_INVALID	},
	{ L("server error"),	RLM_SQL_ERROR		},
	{ L("success"),		RLM_SQL_OK		}
};
size_t sql_rcode_description_table_len = NUM_ELEMENTS(sql_rcode_description_table);

fr_table_num_sorted_t const sql_rcode_table[] = {
	{ L("alternate"),		RLM_SQL_ALT_QUERY	},
	{ L("empty"),		RLM_SQL_NO_MORE_ROWS	},
	{ L("error"),		RLM_SQL_ERROR		},
	{ L("invalid"),		RLM_SQL_QUERY_INVALID	},
	{ L("ok"),			RLM_SQL_OK		},
	{ L("reconnect"),		RLM_SQL_RECONNECT	}
};
size_t sql_rcode_table_len = NUM_ELEMENTS(sql_rcode_table);

void *sql_mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
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
 *	Function: sql_pair_list_afrom_str
 *
 *	Purpose: Read entries from the database and fill fr_pair_t structures
 *
 *************************************************************************/
int sql_pair_list_afrom_str(TALLOC_CTX *ctx, request_t *request, fr_cursor_t *cursor, rlm_sql_row_t row)
{
	fr_pair_t		*vp;
	char const		*ptr, *value;
	char			buf[FR_MAX_STRING_LEN];
	char			do_xlat = 0;
	fr_dict_attr_t const	*da;
	fr_token_t		token, op = T_EOL;

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
		 *	Mark the pair to be allocated later.
		 */
		case T_BACK_QUOTED_STRING:
			do_xlat = 1;
			FALL_THROUGH;

		/*
		 *	Take the unquoted string.
		 */
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			value = buf;
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
	 *	Search in our local dictionary
	 *	falling back to internal.
	 */
	da = fr_dict_attr_by_oid(NULL, fr_dict_root(request->dict), row[2]);
	if (!da) {
		da = fr_dict_attr_by_oid(NULL, fr_dict_root(fr_dict_internal()), row[2]);
		if (!da) {
			RPEDEBUG("Failed creating pair from SQL data");
			return -1;
		}
	}

	MEM(vp = fr_pair_afrom_da(ctx, da));
	vp->op = op;

	if (do_xlat) {
		if (fr_pair_mark_xlat(vp, value) < 0) {
			RPEDEBUG("Error marking pair for xlat");

			talloc_free(vp);
			return -1;
		}
	} else {
		if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
			RPEDEBUG("Error parsing value");

			talloc_free(vp);
			return -1;
		}
	}

	/*
	 *	Add the pair into the packet
	 */
	fr_cursor_append(cursor, vp);
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
sql_rcode_t rlm_sql_fetch_row(rlm_sql_row_t *out, rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t **handle)
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
		fr_assert(*out != NULL);
		return ret;

	case RLM_SQL_NO_MORE_ROWS:
		fr_assert(*out == NULL);
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
void rlm_sql_print_error(rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t *handle, bool force_debug)
{
	char const	*driver;
	sql_log_entry_t	log[20];
	size_t		num, i;

	num = (inst->driver->sql_error)(handle->log_ctx, log, (NUM_ELEMENTS(log)), handle, inst->config);
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
			ROPTIONAL(RDEBUG2, DEBUG2, "%s: %s", driver, log[i].msg);
			break;
		}
	}

	talloc_free_children(handle->log_ctx);
}

/** Call the driver's sql_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_query)(handle, inst->config);``
 *	after they're done with the result.
 *
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 * 	previous reconnection attempt has failed.
 * @param request Current request.
 * @param inst #rlm_sql_t instance data.
 * @param query to execute. Should not be zero length.
 * @return
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_RECONNECT if a new handle is required (also sets *handle = NULL).
 *	- #RLM_SQL_QUERY_INVALID, #RLM_SQL_ERROR on invalid query or connection error.
 *	- #RLM_SQL_ALT_QUERY on constraints violation.
 */
sql_rcode_t rlm_sql_query(rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t **handle, char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i, count;

	/* Caller should check they have a valid handle */
	fr_assert(*handle);

	/* There's no query to run, return an error */
	if (query[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by sql_mod_conn_create.
	 */
	count = inst->pool ? fr_pool_state(inst->pool)->num : 0;

	/*
	 *  Here we try with each of the existing connections, then try to create
	 *  a new connection, then give up.
	 */
	for (i = 0; i < (count + 1); i++) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query);

		ret = (inst->driver->sql_query)(*handle, inst->config, query);
		switch (ret) {
		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			*handle = fr_pool_connection_reconnect(inst->pool, request, *handle);
			/* Reconnection failed */
			if (!*handle) return RLM_SQL_RECONNECT;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		/*
		 *	These are bad and should make rlm_sql return invalid
		 */
		case RLM_SQL_QUERY_INVALID:
			rlm_sql_print_error(inst, request, *handle, false);
			(inst->driver->sql_finish_query)(*handle, inst->config);
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
				rlm_sql_print_error(inst, request, *handle, false);
				(inst->driver->sql_finish_query)(*handle, inst->config);
				break;
			}
			ret = RLM_SQL_ALT_QUERY;
			FALL_THROUGH;

		/*
		 *	Driver suggested using an alternative query
		 */
		case RLM_SQL_ALT_QUERY:
			rlm_sql_print_error(inst, request, *handle, true);
			(inst->driver->sql_finish_query)(*handle, inst->config);
			break;

		}

		return ret;
	}

	ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	return RLM_SQL_ERROR;
}

/** Call the driver's sql_select_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_select_query)(handle, inst->config);``
 *	after they're done with the result.
 *
 * @param inst #rlm_sql_t instance data.
 * @param request Current request.
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 *	  previous reconnection attempt has failed.
 * @param query to execute. Should not be zero length.
 * @return
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_RECONNECT if a new handle is required (also sets *handle = NULL).
 *	- #RLM_SQL_QUERY_INVALID, #RLM_SQL_ERROR on invalid query or connection error.
 */
sql_rcode_t rlm_sql_select_query(rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t **handle, char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i, count;

	/* Caller should check they have a valid handle */
	fr_assert(*handle);

	/* There's no query to run, return an error */
	if (query[0] == '\0') {
		if (request) REDEBUG("Zero length query");

		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by sql_mod_conn_create.
	 */
	count = inst->pool ? fr_pool_state(inst->pool)->num : 0;

	/*
	 *  For sanity, for when no connections are viable, and we can't make a new one
	 */
	for (i = 0; i < (count + 1); i++) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing select query: %s", query);

		ret = (inst->driver->sql_select_query)(*handle, inst->config, query);
		switch (ret) {
		case RLM_SQL_OK:
			break;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			*handle = fr_pool_connection_reconnect(inst->pool, request, *handle);
			/* Reconnection failed */
			if (!*handle) return RLM_SQL_RECONNECT;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		case RLM_SQL_QUERY_INVALID:
		case RLM_SQL_ERROR:
		default:
			rlm_sql_print_error(inst, request, *handle, false);
			(inst->driver->sql_finish_select_query)(*handle, inst->config);
			break;
		}

		return ret;
	}

	ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	return RLM_SQL_ERROR;
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int sql_getvpdata(TALLOC_CTX *ctx, rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t **handle,
		  fr_cursor_t *cursor, char const *query)
{
	rlm_sql_row_t	row;
	int		rows = 0;
	sql_rcode_t	rcode;

	fr_assert(request);

	rcode = rlm_sql_select_query(inst, request, handle, query);
	if (rcode != RLM_SQL_OK) return -1; /* error handled by rlm_sql_select_query */

	while (rlm_sql_fetch_row(&row, inst, request, handle) == RLM_SQL_OK) {
		if (sql_pair_list_afrom_str(ctx, request, cursor, row) != 0) {
			REDEBUG("Error parsing user data from database result");

			(inst->driver->sql_finish_select_query)(*handle, inst->config);

			return -1;
		}
		rows++;
	}
	(inst->driver->sql_finish_select_query)(*handle, inst->config);

	return rows;
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t const *inst, request_t *request, sql_acct_section_t *section, char const *query)
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

	fd = exfile_open(inst->ef, request, filename, 0640);
	if (fd < 0) {
		ERROR("Couldn't open logfile '%s': %s", expanded, fr_syserror(errno));

		talloc_free(expanded);
		/* coverity[missing_unlock] */
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
