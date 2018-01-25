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
	char buf[MAX_STRING_LEN];
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
 * write row data to (*handle)->row.
 *
 * @param inst Instance of rlm_sql.
 * @param request The Current request, may be NULL.
 * @param handle Handle to retrieve errors for.
 * @return on success RLM_SQL_OK, other sql_rcode_t constants on error.
 */
sql_rcode_t rlm_sql_fetch_row(rlm_sql_t *inst, REQUEST *request, rlm_sql_handle_t **handle)
{
	int ret;

	if (!*handle || !(*handle)->conn) return RLM_SQL_ERROR;

	/*
	 *	We can't implement reconnect logic here, because the caller
	 *	may require the original connection to free up queries or
	 *	result sets associated with that connection.
	 */
	ret = (inst->module->sql_fetch_row)(*handle, inst->config);
	if (ret < 0) {
		MOD_ROPTIONAL(RERROR, ERROR, "Error fetching row");

		rlm_sql_print_error(inst, request, *handle, false);
	}

	return ret;
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
void rlm_sql_print_error(rlm_sql_t *inst, REQUEST *request, rlm_sql_handle_t *handle, bool force_debug)
{
	char const	*driver;
	sql_log_entry_t	log[20];
	size_t		num, i;

	num = (inst->module->sql_error)(handle->log_ctx, log, (sizeof(log) / sizeof(*log)), handle, inst->config);
	if (num == 0) {
		MOD_ROPTIONAL(RERROR, ERROR, "Unknown error");
		return;
	}

	driver = inst->config->sql_driver_name;

	for (i = 0; i < num; i++) {
		if (force_debug) goto debug;

		switch (log[i].type) {
		case L_ERR:
			MOD_ROPTIONAL(RERROR, ERROR, "%s: %s", driver, log[i].msg);
			break;

		case L_WARN:
			MOD_ROPTIONAL(RWARN, WARN, "%s: %s", driver, log[i].msg);
			break;

		case L_INFO:
			MOD_ROPTIONAL(RINFO, INFO, "%s: %s", driver, log[i].msg);
			break;

		case L_DBG:
		default:
		debug:
			MOD_ROPTIONAL(RDEBUG, DEBUG, "%s: %s", driver, log[i].msg);
			break;
		}
	}

	talloc_free_children(handle->log_ctx);
}

/** Call the driver's sql_query method, reconnecting if necessary.
 *
 * @note Caller must call (inst->module->sql_finish_query)(handle, inst->config);
 *	after they're done with the result.
 *
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 * 	previous reconnection attempt has failed.
 * @param request Current request.
 * @param inst rlm_sql instance data.
 * @param query to execute. Should not be zero length.
 * @return RLM_SQL_OK on success, RLM_SQL_RECONNECT if a new handle is required
 *	(also sets *handle = NULL), RLM_SQL_QUERY_INVALID/RLM_SQL_ERROR on invalid query or
 *	connection error, RLM_SQL_ALT_QUERY on constraints violation.
 */
sql_rcode_t rlm_sql_query(rlm_sql_t *inst, REQUEST *request, rlm_sql_handle_t **handle, char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i, count;

	/* Caller should check they have a valid handle */
	rad_assert(*handle);

	/* There's no query to run, return an error */
	if (query[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by mod_conn_create.
	 */
	count = inst->pool ? fr_connection_pool_get_num(inst->pool) : 0;

	/*
	 *  Here we try with each of the existing connections, then try to create
	 *  a new connection, then give up.
	 */
	for (i = 0; i < (count + 1); i++) {
		MOD_ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query);

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

		/*
		 *	These are bad and should make rlm_sql return invalid
		 */
		case RLM_SQL_QUERY_INVALID:
			rlm_sql_print_error(inst, request, *handle, false);
			(inst->module->sql_finish_query)(*handle, inst->config);
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
			if (inst->module->flags & RLM_SQL_RCODE_FLAGS_ALT_QUERY) {
				rlm_sql_print_error(inst, request, *handle, false);
				(inst->module->sql_finish_query)(*handle, inst->config);
				break;
			}
			ret = RLM_SQL_ALT_QUERY;
			/* FALL-THROUGH */

		/*
		 *	Driver suggested using an alternative query
		 */
		case RLM_SQL_ALT_QUERY:
			rlm_sql_print_error(inst, request, *handle, true);
			(inst->module->sql_finish_query)(*handle, inst->config);
			break;

		}

		return ret;
	}

	MOD_ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	return RLM_SQL_ERROR;
}

/** Call the driver's sql_select_query method, reconnecting if necessary.
 *
 * @note Caller must call (inst->module->sql_finish_select_query)(handle, inst->config);
 *	after they're done with the result.
 *
 * @param inst rlm_sql instance data.
 * @param request Current request.
 * @param handle to query the database with. *handle should not be NULL, as this indicates
 *	  previous reconnection attempt has failed.
 * @param query to execute. Should not be zero length.
 * @return RLM_SQL_OK on success, RLM_SQL_RECONNECT if a new handle is required (also sets *handle = NULL),
 *         RLM_SQL_QUERY_INVALID/RLM_SQL_ERROR on invalid query or connection error.
 */
sql_rcode_t rlm_sql_select_query(rlm_sql_t *inst, REQUEST *request, rlm_sql_handle_t **handle,  char const *query)
{
	int ret = RLM_SQL_ERROR;
	int i, count;

	/* Caller should check they have a valid handle */
	rad_assert(*handle);

	/* There's no query to run, return an error */
	if (query[0] == '\0') {
		if (request) REDEBUG("Zero length query");

		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by mod_conn_create.
	 */
	count = inst->pool ? fr_connection_pool_get_num(inst->pool) : 0;

	/*
	 *  For sanity, for when no connections are viable, and we can't make a new one
	 */
	for (i = 0; i < (count + 1); i++) {
		MOD_ROPTIONAL(RDEBUG2, DEBUG2, "Executing select query: %s", query);

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

		case RLM_SQL_QUERY_INVALID:
		case RLM_SQL_ERROR:
		default:
			rlm_sql_print_error(inst, request, *handle, false);
			(inst->module->sql_finish_select_query)(*handle, inst->config);
			break;
		}

		return ret;
	}

	MOD_ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	return RLM_SQL_ERROR;
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int sql_getvpdata(TALLOC_CTX *ctx, rlm_sql_t *inst, REQUEST *request, rlm_sql_handle_t **handle,
		  VALUE_PAIR **pair, char const *query)
{
	rlm_sql_row_t	row;
	int		rows = 0;
	sql_rcode_t	rcode;

	rad_assert(request);

	rcode = rlm_sql_select_query(inst, request, handle, query);
	if (rcode != RLM_SQL_OK) return -1; /* error handled by rlm_sql_select_query */

	while (rlm_sql_fetch_row(inst, request, handle) == RLM_SQL_OK) {
		row = (*handle)->row;
		if (!row) break;
		if (sql_fr_pair_list_afrom_str(ctx, request, pair, row) != 0) {
			REDEBUG("Error parsing user data from database result");

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

	filename = inst->config->logfile;
	if (section && section->logfile) filename = section->logfile;

	if (!filename || !*filename) {
		return;
	}

	if (radius_axlat(&expanded, request, filename, NULL, NULL) < 0) {
		return;
	}

	fd = exfile_open(inst->ef, expanded, 0640);
	if (fd < 0) {
		ERROR("rlm_sql (%s): Couldn't open logfile '%s': %s", inst->name,
		      expanded, fr_syserror(errno));

		talloc_free(expanded);
		return;
	}

	len = strlen(query);
	if ((write(fd, query, len) < 0) || (write(fd, ";\n", 2) < 0)) {
		failed = true;
	}

	if (failed) {
		ERROR("rlm_sql (%s): Failed writing to logfile '%s': %s", inst->name, expanded,
		      fr_syserror(errno));
	}

	talloc_free(expanded);
	exfile_close(inst->ef, fd);
}
