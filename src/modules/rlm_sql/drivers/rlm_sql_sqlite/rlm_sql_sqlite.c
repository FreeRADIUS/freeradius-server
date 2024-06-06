/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file rlm_sql_sqlite.c
 * @brief SQLite driver.
 *
 * @copyright 2013 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2007 Apple Inc.
 */
RCSID("$Id$")

#define LOG_PREFIX "sql - sqlite"
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "rlm_sql.h"
#include "config.h"

#define BOOTSTRAP_MAX (1048576 * 10)

/*
 *	Allow us to use versions < 3.6.0 beta0
 */
#ifndef SQLITE_OPEN_NOMUTEX
#  define SQLITE_OPEN_NOMUTEX 0
#endif

#ifndef HAVE_SQLITE3_INT64
typedef sqlite_int64 sqlite3_int64;
#endif

typedef struct {
	sqlite3 *db;
	sqlite3_stmt *statement;
	int col_count;
} rlm_sql_sqlite_conn_t;

typedef struct {
	char const	*filename;
	bool		bootstrap;
} rlm_sql_sqlite_t;

static const conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_OUTPUT | CONF_FLAG_REQUIRED, rlm_sql_sqlite_t, filename) },
	CONF_PARSER_TERMINATOR
};

/** Convert an sqlite status code to an sql_rcode_t
 *
 * @param status to convert.
 * @return
 *	- RLM_SQL_OK - If no errors found.
 *	- RLM_SQL_ERROR - If a known, non-fatal, error occurred.
 *	- RLM_SQL_ALT_QUERY - If a constraints violation occurred.
 *	- RLM_SQL_RECONNECT - Anything else, we assume the connection can no longer be used.
 */
static sql_rcode_t sql_error_to_rcode(int status)
{
	/*
	 *	Lowest byte is error category, other byte may contain
	 *	the extended error, depending on version.
	 */
	switch (status & 0xff) {
	/*
	 *	Not errors
	 */
	case SQLITE_OK:
	case SQLITE_DONE:
	case SQLITE_ROW:
		return RLM_SQL_OK;
	/*
	 *	User/transient errors
	 */
	case SQLITE_ERROR:	/* SQL error or missing database */
	case SQLITE_FULL:
	case SQLITE_MISMATCH:
	case SQLITE_BUSY:	/* Can be caused by database locking */
		return RLM_SQL_ERROR;

	/*
	 *	Constraints violations
	 */
	case SQLITE_CONSTRAINT:
		return RLM_SQL_ALT_QUERY;

	/*
	 *	Errors with the handle, that probably require reinitialisation
	 */
	default:
		return RLM_SQL_RECONNECT;
	}
}

/** Determine if an error occurred, and what type of error it was
 *
 * @param db handle to extract error from (may be NULL).
 * @param status to check (if unused, set to SQLITE_OK).
 * @return
 *	- RLM_SQL_OK - If no errors found.
 *	- RLM_SQL_ERROR - If a known, non-fatal, error occurred.
 *	- RLM_SQL_ALT_QUERY - If a constraints violation occurred.
 *	- RLM_SQL_RECONNECT - Anything else. We assume the connection can no longer be used.
 */
static sql_rcode_t sql_check_error(sqlite3 *db, int status)
{
	int hstatus = SQLITE_OK;

	if (db) {
		hstatus = sqlite3_errcode(db);
		switch (hstatus & 0xff) {
		case SQLITE_OK:
		case SQLITE_DONE:
		case SQLITE_ROW:
			hstatus = SQLITE_OK;
			break;

		default:
			break;
		}
	}

	switch (status & 0xff) {
	case SQLITE_OK:
	case SQLITE_DONE:
	case SQLITE_ROW:
		status = SQLITE_OK;
		break;

	default:
		break;
	}

	if (status != SQLITE_OK) return sql_error_to_rcode(status);
	if (hstatus != SQLITE_OK) return sql_error_to_rcode(status);

	return RLM_SQL_OK;
}

/** Print an error to the global debug log
 *
 * If status does not indicate success, write an error to the global error log.
 *
 * @note The error code will be appended to the fmt string in the format ": code 0x<hex> (<int>)[: <string>]".
 *
 * @param db handle to extract error from (may be NULL).
 * @param status to check (if unused, set to SQLITE_OK).
 * @param fmt to prepend.
 * @param ... arguments to fmt.
 */
static void sql_print_error(sqlite3 *db, int status, char const *fmt, ...)
	CC_HINT(format (printf, 3, 4)) CC_HINT(nonnull (3));
static void sql_print_error(sqlite3 *db, int status, char const *fmt, ...)
{
	va_list ap;
	char *p;
	int hstatus = SQLITE_OK;

	if (db) {
		hstatus = sqlite3_errcode(db);
		switch (hstatus & 0xff) {
		case SQLITE_OK:
		case SQLITE_DONE:
		case SQLITE_ROW:
			hstatus = SQLITE_OK;
			break;

		default:
			break;
		}
	}

	switch (status & 0xff) {
	case SQLITE_OK:
	case SQLITE_DONE:
	case SQLITE_ROW:
		status = SQLITE_OK;
		break;

	default:
		break;
	}

	/*
	 *	No errors!
	 */
	if ((hstatus == SQLITE_OK) && (status == SQLITE_OK)) return;

	/*
	 *	At least one error...
	 */
	va_start(ap, fmt);
	MEM(p = talloc_vasprintf(NULL, fmt, ap));
	va_end(ap);

	/*
	 *	Disagreement between handle, and function return code,
	 *	print them both.
	 */
	if ((status != SQLITE_OK) && (status != hstatus)) {
#ifdef HAVE_SQLITE3_ERRSTR
		ERROR("%s: Code 0x%04x (%i): %s", p, status, status, sqlite3_errstr(status));
#else
		ERROR("%s: Code 0x%04x (%i)", p, status, status);
#endif
	}

	if (hstatus != SQLITE_OK) ERROR("%s: Code 0x%04x (%i): %s",
					p, hstatus, hstatus, sqlite3_errmsg(db));
}

#ifdef HAVE_SQLITE3_OPEN_V2
static int sql_loadfile(TALLOC_CTX *ctx, sqlite3 *db, char const *filename)
{
	ssize_t		len;
	int		statement_len, statement_cnt = 0;
	char		*buffer;
	char const	*p;
	int		cl;
	FILE		*f;
	struct stat	finfo;

	int status;
	sqlite3_stmt *statement;
	char const *z_tail;

	INFO("Executing SQL statements from file \"%s\"", filename);

	f = fopen(filename, "r");
	if (!f) {
		ERROR("Failed opening SQL file \"%s\": %s", filename,
		       fr_syserror(errno));

		return -1;
	}

	if (fstat(fileno(f), &finfo) < 0) {
		ERROR("Failed stating SQL file \"%s\": %s", filename,
		       fr_syserror(errno));

		fclose(f);

		return -1;
	}

	if (finfo.st_size > BOOTSTRAP_MAX) {
		too_big:
		ERROR("Size of SQL (%zu) file exceeds limit (%uk)",
		       (size_t) finfo.st_size / 1024, BOOTSTRAP_MAX / 1024);

		fclose(f);

		return -1;
	}

	MEM(buffer = talloc_array(ctx, char, finfo.st_size + 1));
	len = fread(buffer, sizeof(char), finfo.st_size, f);
	if (len > finfo.st_size) {
		talloc_free(buffer);
		goto too_big;
	}

	if (!len) {
		if (ferror(f)) {
			ERROR("Error reading SQL file: %s", fr_syserror(errno));

			fclose(f);
			talloc_free(buffer);

			return -1;
		}

		DEBUG("Ignoring empty SQL file");

		fclose(f);
		talloc_free(buffer);

		return 0;
	}

	buffer[len] = '\0';
	fclose(f);

	/*
	 *	Check if input data is UTF-8.  Allow CR/LF \t, too.
	 */
	for (p = buffer; p < (buffer + len); p += cl) {
		if (*p < ' ') {
			if ((*p != 0x0a) && (*p != 0x0d) && (*p != '\t')) break;
			cl = 1;
		} else {
			cl = fr_utf8_char((uint8_t const *) p, -1);
			if (!cl) break;
		}
	}

	if ((p - buffer) != len) {
		ERROR("Bootstrap file contains non-UTF8 char at offset %zu", p - buffer);
		talloc_free(buffer);
		return -1;
	}

	p = buffer;
	while (*p) {
		statement_len = len - (p - buffer);
#ifdef HAVE_SQLITE3_PREPARE_V2
		status = sqlite3_prepare_v2(db, p, statement_len, &statement, &z_tail);
#else
		status = sqlite3_prepare(db, p, statement_len, &statement, &z_tail);
#endif

		if (sql_check_error(db, status) != RLM_SQL_OK) {
			sql_print_error(db, status, "Failed preparing statement %i", statement_cnt);
			talloc_free(buffer);
			return -1;
		}

		/*
		 *	No SQL statement was found
		 */
		if (!statement) break;

		status = sqlite3_step(statement);
		if (sql_check_error(db, status) != RLM_SQL_OK) {
			sql_print_error(db, status, "Failed executing statement %i", statement_cnt);
			sqlite3_finalize(statement);
			talloc_free(buffer);
			return -1;
		}

		status = sqlite3_finalize(statement);
		if (sql_check_error(db, status) != RLM_SQL_OK) {
			sql_print_error(db, status, "Failed finalizing statement %i", statement_cnt);
			talloc_free(buffer);
			return -1;
		}

		statement_cnt++;
		p = z_tail;
	}

	talloc_free(buffer);
	return 0;
}
#endif

static int _sql_socket_destructor(rlm_sql_sqlite_conn_t *conn)
{
	int status = 0;

	DEBUG2("Socket destructor called, closing socket");

	if (conn->db) {
		status = sqlite3_close(conn->db);
		if (status != SQLITE_OK) WARN("Got SQLite error when closing socket: %s",
					      sqlite3_errmsg(conn->db));
	}

	return 0;
}

static void _sql_greatest(sqlite3_context *ctx, int num_values, sqlite3_value **values)
{
	int i;
	sqlite3_int64 value, max = 0;

	for (i = 0; i < num_values; i++) {
		value = sqlite3_value_int64(values[i]);
		if (value > max) {
			max = value;
		}
	}

	sqlite3_result_int64(ctx, max);
}

static sql_rcode_t CC_HINT(nonnull) sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t const *config,
					    UNUSED fr_time_delta_t timeout)
{
	rlm_sql_sqlite_conn_t	*conn;
	rlm_sql_sqlite_t	*inst = talloc_get_type_abort(handle->inst->driver_submodule->data, rlm_sql_sqlite_t);

	int status;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_sqlite_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	INFO("Opening SQLite database \"%s\"", inst->filename);
#ifdef HAVE_SQLITE3_OPEN_V2
	status = sqlite3_open_v2(inst->filename, &(conn->db), SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
#else
	status = sqlite3_open(inst->filename, &(conn->db));
#endif

	if (!conn->db || (sql_check_error(conn->db, status) != RLM_SQL_OK)) {
		sql_print_error(conn->db, status, "Error opening SQLite database \"%s\"", inst->filename);
#ifdef HAVE_SQLITE3_OPEN_V2
		if (!inst->bootstrap) {
			INFO("Use the sqlite driver 'bootstrap' option to automatically create the database file");
		}
#endif
		return RLM_SQL_ERROR;
	}
	status = sqlite3_busy_timeout(conn->db, fr_time_delta_to_sec(config->query_timeout));
	if (sql_check_error(conn->db, status) != RLM_SQL_OK) {
		sql_print_error(conn->db, status, "Error setting busy timeout");
		return RLM_SQL_ERROR;
	}

	/*
	 *	Enable extended return codes for extra debugging info.
	 */
#ifdef HAVE_SQLITE3_EXTENDED_RESULT_CODES
	status = sqlite3_extended_result_codes(conn->db, 1);
	if (sql_check_error(conn->db, status) != RLM_SQL_OK) {
		sql_print_error(conn->db, status, "Error enabling extended result codes");
		return RLM_SQL_ERROR;
	}
#endif

#ifdef HAVE_SQLITE3_CREATE_FUNCTION_V2
	status = sqlite3_create_function_v2(conn->db, "GREATEST", -1, SQLITE_ANY, NULL,
					    _sql_greatest, NULL, NULL, NULL);
#else
	status = sqlite3_create_function(conn->db, "GREATEST", -1, SQLITE_ANY, NULL,
					 _sql_greatest, NULL, NULL);
#endif
	if (sql_check_error(conn->db, status) != RLM_SQL_OK) {
		sql_print_error(conn->db, status, "Failed registering 'GREATEST' sql function");
		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static unlang_action_t sql_select_query(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_sqlite_conn_t	*conn = query_ctx->handle->conn;
	char const		*z_tail;
	int			status;

#ifdef HAVE_SQLITE3_PREPARE_V2
	status = sqlite3_prepare_v2(conn->db, query_ctx->query_str, strlen(query_ctx->query_str), &conn->statement, &z_tail);
#else
	status = sqlite3_prepare(conn->db, query_ctx->query_str, strlen(query_ctx->query_str), &conn->statement, &z_tail);
#endif

	conn->col_count = 0;

	query_ctx->rcode = sql_check_error(conn->db, status);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;
	RETURN_MODULE_OK;
}


static unlang_action_t sql_query(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_sqlite_conn_t	*conn = query_ctx->handle->conn;
	char const		*z_tail;
	int			status;

#ifdef HAVE_SQLITE3_PREPARE_V2
	status = sqlite3_prepare_v2(conn->db, query_ctx->query_str, strlen(query_ctx->query_str), &conn->statement, &z_tail);
#else
	status = sqlite3_prepare(conn->db, query_ctx->query_str, strlen(query_ctx->query_str), &conn->statement, &z_tail);
#endif
	query_ctx->rcode = sql_check_error(conn->db, status);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	status = sqlite3_step(conn->statement);
	query_ctx->rcode = sql_check_error(conn->db, status);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;
	RETURN_MODULE_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	if (conn->statement) return sqlite3_column_count(conn->statement);

	return 0;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	int		fields, i;
	char const	**names;

	fields = sqlite3_column_count(conn->statement);
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = sqlite3_column_name(conn->statement, i);
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_handle_t	*handle = query_ctx->handle;
	int			status, i = 0;
	rlm_sql_sqlite_conn_t	*conn = handle->conn;
	char			**row;

	TALLOC_FREE(query_ctx->row);

	/*
	 *	Executes the SQLite query and iterates over the results
	 */
	status = sqlite3_step(conn->statement);

	/*
	 *	Error getting next row
	 */
	if (sql_check_error(conn->db, status) != RLM_SQL_OK) {
	error:
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}

	/*
	 *	No more rows to process (we're done)
	 */
	if (status == SQLITE_DONE) {
		query_ctx->rcode =  RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	/*
	 *	We only need to do this once per result set, because
	 *	the number of columns won't change.
	 */
	if (conn->col_count == 0) {
		conn->col_count = sql_num_fields(handle, &query_ctx->inst->config);
		if (conn->col_count == 0) goto error;
	}

	/*
	 *	Free the previous result (also gets called on finish_query)
	 */
	MEM(row = query_ctx->row = talloc_zero_array(query_ctx, char *, conn->col_count + 1));

	for (i = 0; i < conn->col_count; i++) {
		switch (sqlite3_column_type(conn->statement, i)) {
		case SQLITE_INTEGER:
			MEM(row[i] = talloc_typed_asprintf(row, "%d", sqlite3_column_int(conn->statement, i)));
			break;

		case SQLITE_FLOAT:
			MEM(row[i] = talloc_typed_asprintf(row, "%f", sqlite3_column_double(conn->statement, i)));
			break;

		case SQLITE_TEXT:
		{
			char const *p;
			p = (char const *) sqlite3_column_text(conn->statement, i);

			if (p) MEM(row[i] = talloc_typed_strdup(row, p));
		}
			break;

		case SQLITE_BLOB:
		{
			uint8_t const *p;
			size_t len;

			p = sqlite3_column_blob(conn->statement, i);
			if (p) {
				len = sqlite3_column_bytes(conn->statement, i);

				MEM(row[i] = talloc_zero_array(row, char, len + 1));
				memcpy(row[i], p, len);
			}
		}
			break;

		default:
			break;
		}
	}

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_sqlite_conn_t *conn = query_ctx->handle->conn;

	if (conn->statement) {
		TALLOC_FREE(query_ctx->row);

		(void) sqlite3_finalize(conn->statement);
		conn->statement = NULL;
		conn->col_count = 0;
	}

	/*
	 *	There's no point in checking the code returned by finalize
	 *	as it'll have already been encountered elsewhere in the code.
	 *
	 *	It's just the last error that occurred processing the
	 *	statement.
	 */
	return RLM_SQL_OK;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param query_ctx Query context to retrieve error for.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_sqlite_conn_t *conn = query_ctx->handle->conn;
	char const *error;

	fr_assert(outlen > 0);

	error = sqlite3_errmsg(conn->db);
	if (!error) return 0;

	out[0].type = L_ERR;
	out[0].msg = error;

	return 1;
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	return sql_free_result(query_ctx, config);
}

static int sql_affected_rows(fr_sql_query_t *query_ctx,
			     UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_sqlite_conn_t *conn = query_ctx->handle->conn;

	if (conn->db) return sqlite3_changes(conn->db);

	return -1;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_t const		*parent = talloc_get_type_abort(mctx->mi->parent->data, rlm_sql_t);
	rlm_sql_config_t const	*config = &parent->config;
	rlm_sql_sqlite_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_sqlite_t);
	bool			exists;
	struct stat		buf;
	int			fd;
	char const		*r;

	if (!inst->filename) {
		MEM(inst->filename = talloc_typed_asprintf(inst, "%s/%s",
							   main_config->raddb_dir, config->sql_db));
	}

	/*
	 *	We will try to create the database if it doesn't exist, up to and
	 * 	including creating the directory it should live in, in which case
	 *	we get to call fr_dirfd() again. Hence failing this first fr_dirfd()
	 *	just means the database isn't there.
	 */
	if (fr_dirfd(&fd, &r, inst->filename) < 0) {
		exists = false;
	} else if (fstatat(fd, r, &buf, 0) == 0) {
		exists = true;
	} else if (errno == ENOENT) {
		exists = false;
	} else {
		ERROR("Database exists, but couldn't be opened: %s", fr_syserror(errno));
		close(fd);
		return -1;
	}

	if (cf_pair_find(mctx->mi->conf, "bootstrap")) {
		inst->bootstrap = true;
	}

	if (inst->bootstrap && !exists) {
#ifdef HAVE_SQLITE3_OPEN_V2
		int		status;
		int		ret;
		char const	*p;
		char		*buff;
		sqlite3		*db = NULL;
		CONF_PAIR	*cp;

		INFO("Database \"%s\" doesn't exist, creating it and loading schema", inst->filename);

		p = strrchr(inst->filename, '/');
		if (p) {
			size_t len = (p - inst->filename) + 1;

			buff = talloc_array(mctx->mi->conf, char, len);
			strlcpy(buff, inst->filename, len);
		} else {
			MEM(buff = talloc_typed_strdup(mctx->mi->conf, inst->filename));
		}

		ret = fr_mkdir(NULL, buff, -1, 0700, NULL, NULL);
		talloc_free(buff);
		if (ret < 0) {
			PERROR("Failed creating directory for SQLite database");

			return -1;
		}
		(void) fr_dirfd(&fd, &r, inst->filename);

		status = sqlite3_open_v2(inst->filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
		if (!db) {
#  ifdef HAVE_SQLITE3_ERRSTR
			ERROR("Failed creating opening/creating SQLite database: %s",
			      sqlite3_errstr(status));
#  else
			ERROR("Failed creating opening/creating SQLite database, got code (%i)",
			      status);
#  endif

			goto unlink;
		}

		if (sql_check_error(db, status) != RLM_SQL_OK) {
			(void) sqlite3_close(db);

			goto unlink;
		}

		/*
		 *	Execute multiple bootstrap SQL files in order
		 */
		for (cp = cf_pair_find(mctx->mi->conf, "bootstrap");
		     cp;
		     cp = cf_pair_find_next(mctx->mi->conf, cp, "bootstrap")) {
			p = cf_pair_value(cp);
			if (!p) continue;

			ret = sql_loadfile(mctx->mi->conf, db, p);
			if (ret < 0) goto unlink;
		}

		status = sqlite3_close(db);
		if (status != SQLITE_OK) {
		/*
		 *	Safer to use sqlite3_errstr here, just in case the handle is in a weird state
		 */
#  ifdef HAVE_SQLITE3_ERRSTR
			ERROR("Error closing SQLite handle: %s", sqlite3_errstr(status));
#  else
			ERROR("Error closing SQLite handle, got code (%i)", status);
#  endif
			goto unlink;
		}

		if (ret < 0) {
		unlink:
			if ((unlinkat(fd, r, 0) < 0) && (errno != ENOENT)) {
				ERROR("Error removing partially initialised database: %s",
				      fr_syserror(errno));
			}
			close(fd);
			return -1;
		}
#else
		WARN("sqlite3_open_v2() not available, cannot bootstrap database. "
		       "Upgrade to SQLite >= 3.5.1 if you need this functionality");
#endif
	}

	close(fd);
	return 0;
}

static int mod_load(void)
{
	if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER) {
		WARN("libsqlite version changed since the server was built");
		WARN("linked: %s built: %s", sqlite3_libversion(), SQLITE_VERSION);
	}
	INFO("libsqlite version: %s", sqlite3_libversion());

	return 0;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_sqlite;
rlm_sql_driver_t rlm_sql_sqlite = {
	.common = {
		.name				= "sql_sqlite",
		.magic				= MODULE_MAGIC_INIT,
		.inst_size			= sizeof(rlm_sql_sqlite_t),
		.config				= driver_config,
		.onload				= mod_load,
		.instantiate			= mod_instantiate
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_fields			= sql_fields,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query
};
