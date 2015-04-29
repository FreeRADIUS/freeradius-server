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
 * @copyright 2013 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2007 Apple Inc.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

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
typedef sqlite3_int64 sqlite_int64
#endif

typedef struct rlm_sql_sqlite_conn {
	sqlite3 *db;
	sqlite3_stmt *statement;
	int col_count;
} rlm_sql_sqlite_conn_t;

typedef struct rlm_sql_sqlite_config {
	char const	*filename;
	uint32_t	busy_timeout;
} rlm_sql_sqlite_config_t;

static const CONF_PARSER driver_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED, rlm_sql_sqlite_config_t, filename), NULL },
	{ "busy_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_sqlite_config_t, busy_timeout), "200" },
	{NULL, -1, 0, NULL, NULL}
};

static sql_rcode_t sql_check_error(sqlite3 *db)
{
	int error = sqlite3_errcode(db);

	/*
	 *	Lowest byte is error category, other byte may contain
	 *	the extended error, depending on version.
	 */
	switch (error & 0xff) {
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
		ERROR("rlm_sql_sqlite: Handle is unusable, error (%d): %s", error, sqlite3_errmsg(db));
		return RLM_SQL_RECONNECT;
	}
}

#ifdef HAVE_SQLITE3_OPEN_V2
static int sql_loadfile(TALLOC_CTX *ctx, sqlite3 *db, char const *filename)
{
	ssize_t len;
	char *buffer;
	char *p, *q, *s;
	int cl;
	FILE *f;
	struct stat finfo;

	int status;
	sqlite3_stmt *statement;
	char const *z_tail;

	INFO("rlm_sql_sqlite: Executing SQL statements from file \"%s\"", filename);

	f = fopen(filename, "r");
	if (!f) {
		ERROR("rlm_sql_sqlite: Failed opening SQL file \"%s\": %s", filename,
		       fr_syserror(errno));

		return -1;
	}

	if (fstat(fileno(f), &finfo) < 0) {
		ERROR("rlm_sql_sqlite: Failed stating SQL file \"%s\": %s", filename,
		       fr_syserror(errno));

		fclose(f);

		return -1;
	}

	if (finfo.st_size > BOOTSTRAP_MAX) {
		too_big:
		ERROR("rlm_sql_sqlite: Size of SQL (%zu) file exceeds limit (%uk)",
		       (size_t) finfo.st_size / 1024, BOOTSTRAP_MAX / 1024);

		fclose(f);

		return -1;
	}

	MEM(buffer = talloc_array(ctx, char, finfo.st_size + 1));
	len = fread(buffer, sizeof(char), finfo.st_size + 1, f);
	if (len > finfo.st_size) {
		talloc_free(buffer);
		goto too_big;
	}

	if (!len) {
		if (ferror(f)) {
			ERROR("rlm_sql_sqlite: Error reading SQL file: %s", fr_syserror(errno));

			fclose(f);
			talloc_free(buffer);

			return -1;
		}

		DEBUG("rlm_sql_sqlite: Ignoring empty SQL file");

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
			cl = fr_utf8_char((uint8_t *) p);
			if (!cl) break;
		}
	}

	if ((p - buffer) != len) {
		ERROR("rlm_sql_sqlite: Bootstrap file contains non-UTF8 char at offset %zu", p - buffer);
		talloc_free(buffer);
		return -1;
	}

	/*
	 *	Statement delimiter is ;\n
	 */
	s = p = buffer;
	while ((q = strchr(p, ';'))) {
		if (q[1] != '\n') {
			p = q + 1;
			continue;
		}

		*q = '\0';

#ifdef HAVE_SQLITE3_PREPARE_V2
		(void) sqlite3_prepare_v2(db, s, len, &statement, &z_tail);
#else
		(void) sqlite3_prepare(db, s, len, &>statement, &z_tail);
#endif
		if (sql_check_error(db) != RLM_SQL_OK) {
			talloc_free(buffer);
			return -1;
		}

		(void) sqlite3_step(statement);
		status = sql_check_error(db);

		(void) sqlite3_finalize(statement);
		if ((status != RLM_SQL_OK) || sql_check_error(db)) {
			talloc_free(buffer);
			return -1;
		}

		p = s = q + 1;
	}

	talloc_free(buffer);
	return 0;
}
#endif

static int mod_instantiate(CONF_SECTION *conf, rlm_sql_config_t *config)
{
	static bool version_done;

	bool exists;
	rlm_sql_sqlite_config_t *driver;
	struct stat buf;

	if (!version_done) {
		version_done = true;

		if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER) {
			WARN("rlm_sql_sqlite: libsqlite version changed since the server was built");
			WARN("rlm_sql_sqlite: linked: %s built: %s", sqlite3_libversion(), SQLITE_VERSION);
		}
		INFO("rlm_sql_sqlite: libsqlite version: %s", sqlite3_libversion());
	}

	MEM(driver = config->driver = talloc_zero(config, rlm_sql_sqlite_config_t));
	if (cf_section_parse(conf, driver, driver_config) < 0) {
		return -1;
	}
	if (!driver->filename) {
		MEM(driver->filename = talloc_typed_asprintf(driver, "%s/%s", get_radius_dir(), config->sql_db));
	}

	if (stat(driver->filename, &buf) == 0) {
		exists = true;
	} else if (errno == ENOENT) {
		exists = false;
	} else {
		ERROR("rlm_sql_sqlite: Database exists, but couldn't be opened: %s", fr_syserror(errno));
		return -1;
	}

	if (cf_pair_find(conf, "bootstrap") && !exists) {
#  ifdef HAVE_SQLITE3_OPEN_V2
		int status;
		int ret;
		char const *p;
		char *buff;
		sqlite3 *db = NULL;
		CONF_PAIR *cp;

		INFO("rlm_sql_sqlite: Database doesn't exist, creating it and loading schema");

		p = strrchr(driver->filename, '/');
		if (p) {
			size_t len = (p - driver->filename) + 1;

			buff = talloc_array(conf, char, len);
			strlcpy(buff, driver->filename, len);
		} else {
			MEM(buff = talloc_typed_strdup(conf, driver->filename));
		}

		ret = rad_mkdir(buff, 0700, -1, -1);
		talloc_free(buff);
		if (ret < 0) {
			ERROR("rlm_sql_sqlite: Failed creating directory for SQLite database: %s", fr_syserror(errno));

			return -1;
		};

		status = sqlite3_open_v2(driver->filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
		if (!db) {
#    ifdef HAVE_SQLITE3_ERRSTR
			ERROR("rlm_sql_sqlite: Failed creating opening/creating SQLite database: %s",
			      sqlite3_errstr(status));
#    else
			ERROR("rlm_sql_sqlite: Failed creating opening/creating SQLite database, got code (%i)",
			      status);
#    endif

			goto unlink;
		}

		if (sql_check_error(db) != RLM_SQL_OK) {
			(void) sqlite3_close(db);

			goto unlink;
		}

		/*
		 *	Execute multiple bootstrap SQL files in order
		 */
		for (cp = cf_pair_find(conf, "bootstrap");
		     cp;
		     cp = cf_pair_find_next(conf, cp, "bootstrap")) {
			p = cf_pair_value(cp);
			if (!p) continue;

			ret = sql_loadfile(conf, db, p);
			if (ret < 0) goto unlink;
		}

		status = sqlite3_close(db);
		if (status != SQLITE_OK) {
		/*
		 *	Safer to use sqlite3_errstr here, just in case the handle is in a weird state
		 */
#  ifdef HAVE_SQLITE3_ERRSTR
			ERROR("rlm_sql_sqlite: Error closing SQLite handle: %s", sqlite3_errstr(status));
#  else
			ERROR("rlm_sql_sqlite: Error closing SQLite handle, got code (%i)", status);
#  endif
			goto unlink;
		}

		if (ret < 0) {
		unlink:
			if ((unlink(driver->filename) < 0) && (errno != ENOENT)) {
				ERROR("rlm_sql_sqlite: Error removing partially initialised database: %s",
				      fr_syserror(errno));
			}
			return -1;
		}
#else
		WARN("rlm_sql_sqlite: sqlite3_open_v2() not available, cannot bootstrap database. "
		       "Upgrade to SQLite >= 3.5.1 if you need this functionality");
#endif
	}

	return 0;
}

static int _sql_socket_destructor(rlm_sql_sqlite_conn_t *conn)
{
	int status = 0;

	DEBUG2("rlm_sql_sqlite: Socket destructor called, closing socket");

	if (conn->db) {
		status = sqlite3_close(conn->db);
		if (status != SQLITE_OK) {
			WARN("rlm_sql_sqlite: Got SQLite error when closing socket: %s", sqlite3_errmsg(conn->db));
		}
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

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn;
	rlm_sql_sqlite_config_t *driver = config->driver;

	int status;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_sqlite_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	INFO("rlm_sql_sqlite: Opening SQLite database \"%s\"", driver->filename);
#ifdef HAVE_SQLITE3_OPEN_V2
	status = sqlite3_open_v2(driver->filename, &(conn->db), SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
#else
	status = sqlite3_open(driver->filename, &(conn->db));
#endif
	if (!conn->db) {
#ifdef HAVE_SQLITE3_ERRSTR
		ERROR("rlm_sql_sqlite: Failed creating opening/creating SQLite: %s", sqlite3_errstr(status));
#else
		ERROR("rlm_sql_sqlite: Failed creating opening/creating SQLite database error code (%i)",
		      status);
#endif

		return RLM_SQL_ERROR;
	}
	if (sql_check_error(conn->db) != RLM_SQL_OK) return RLM_SQL_ERROR;

	status = sqlite3_busy_timeout(conn->db, driver->busy_timeout);
	if (status != SQLITE_OK) ERROR("rlm_sql_sqlite: Failed setting busy timeout");

	/*
	 *	Enable extended return codes for extra debugging info.
	 */
#ifdef HAVE_SQLITE3_EXTENDED_RESULT_CODES
	(void) sqlite3_extended_result_codes(conn->db, 1);
#endif
	if (sql_check_error(conn->db) != RLM_SQL_OK) return RLM_SQL_ERROR;

#ifdef HAVE_SQLITE3_CREATE_FUNCTION_V2
	status = sqlite3_create_function_v2(conn->db, "GREATEST", -1, SQLITE_ANY, NULL,
					    _sql_greatest, NULL, NULL, NULL);
#else
	status = sqlite3_create_function(conn->db, "GREATEST", -1, SQLITE_ANY, NULL,
					 _sql_greatest, NULL, NULL);
#endif
	if (status != SQLITE_OK) {
		ERROR("rlm_sql_sqlite: Failed registering 'GREATEST' sql function: %s", sqlite3_errmsg(conn->db));
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;
	char const *z_tail;

#ifdef HAVE_SQLITE3_PREPARE_V2
	(void) sqlite3_prepare_v2(conn->db, query, strlen(query), &conn->statement, &z_tail);
#else
	(void) sqlite3_prepare(conn->db, query, strlen(query), &conn->statement, &z_tail);
#endif

	conn->col_count = 0;

	return sql_check_error(conn->db);
}


static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	int status;
	rlm_sql_sqlite_conn_t *conn = handle->conn;
	char const *z_tail;

#ifdef HAVE_SQLITE3_PREPARE_V2
	status = sqlite3_prepare_v2(conn->db, query, strlen(query), &conn->statement, &z_tail);
#else
	status = sqlite3_prepare(conn->db, query, strlen(query), &conn->statement, &z_tail);
#endif
	if (status != SQLITE_OK) return sql_check_error(conn->db);

	(void) sqlite3_step(conn->statement);

	return sql_check_error(conn->db);
}

static sql_rcode_t sql_store_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	if (conn->statement) {
		return sqlite3_column_count(conn->statement);
	}

	return 0;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	if (conn->statement) {
		return sqlite3_data_count(conn->statement);
	}

	return 0;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	int		fields, i;
	char const	**names;

	fields = sqlite3_column_count(conn->statement);
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_zero_array(handle, char const *, fields + 1));

	for (i = 0; i < fields; i++) names[i] = sqlite3_column_name(conn->statement, i);
	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	int status;
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	int i = 0;

	char **row;

	*out = NULL;

	/*
	 *	Executes the SQLite query and interates over the results
	 */
	status = sqlite3_step(conn->statement);

	/*
	 *	Error getting next row
	 */
	if (sql_check_error(conn->db) != RLM_SQL_OK) return RLM_SQL_ERROR;

	/*
	 *	No more rows to process (were done)
	 */
	if (status == SQLITE_DONE) return 1;

	/*
	 *	We only need to do this once per result set, because
	 *	the number of columns won't change.
	 */
	if (conn->col_count == 0) {
		conn->col_count = sql_num_fields(handle, config);
		if (conn->col_count == 0) return RLM_SQL_ERROR;
	}

	/*
	 *	Free the previous result (also gets called on finish_query)
	 */
	talloc_free(handle->row);
	MEM(row = handle->row = talloc_zero_array(handle->conn, char *, conn->col_count + 1));

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

				if (p) {
					MEM(row[i] = talloc_typed_strdup(row, p));
				}
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

	*out = row;

	return 0;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	if (conn->statement) {
		TALLOC_FREE(handle->row);

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
	return 0;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the sql_log_entry array.
 */
static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;
	char const *error;

	rad_assert(outlen > 0);

	error = sqlite3_errmsg(conn->db);
	if (!error) return 0;

	out[0].type = L_ERR;
	out[0].msg = error;

	return 1;
}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_free_result(handle, config);
}

static int sql_affected_rows(rlm_sql_handle_t *handle,
			     UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sqlite_conn_t *conn = handle->conn;

	if (conn->db) {
		return sqlite3_changes(conn->db);
	}

	return -1;
}


/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_sqlite;
rlm_sql_module_t rlm_sql_sqlite = {
	.name				= "rlm_sql_sqlite",
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.mod_instantiate		= mod_instantiate,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_store_result		= sql_store_result,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_fields			= sql_fields,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query
};
