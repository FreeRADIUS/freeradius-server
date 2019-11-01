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
 * @file rlm_sql_mongo.c
 * @brief Mongo driver.
 *
 * @copyright 2019 Network RADIUS SARL
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <mongoc.h>

#include "rlm_sql.h"

#define MAX_ROWS (64)

typedef struct rlm_sql_mongo_config {
	char			*appname; /* what we tell Mongo we are */
	mongoc_ssl_opt_t	tls;
	mongoc_client_pool_t	*pool;
} rlm_sql_mongo_config_t;

typedef struct rlm_sql_mongo_conn {
	rlm_sql_mongo_config_t *driver;
	bson_t		*result;
	bson_error_t	error;
	int		cur_row;
	int		num_fields;		//!< number of columns
	int		affected_rows;		//!< only for writes

	int		num_rows;		//!< for selects
	bson_t		**bson_row;		//!< copy of selected document

	char		**row;			//!< really fields, i.e. columns
} rlm_sql_mongo_conn_t;

static CONF_PARSER tls_config[] = {
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mongo_config_t, tls.pem_file), NULL },
	{ "certificate_password", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_mongo_config_t, tls.pem_pwd), NULL },
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mongo_config_t, tls.ca_file), NULL },
	{ "ca_dir", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mongo_config_t, tls.ca_dir), NULL },
	{ "crl_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mongo_config_t, tls.crl_file), NULL },
	{ "weak_cert_validation", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_mongo_config_t, tls.weak_cert_validation), NULL },
	{ "allow_invalid_hostname", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_mongo_config_t, tls.allow_invalid_hostname), NULL },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER driver_config[] = {
	{ "appname",  PW_TYPE_STRING, offsetof(rlm_sql_mongo_config_t, appname), NULL, NULL},

	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },
	CONF_PARSER_TERMINATOR
};

/*
 *	This is only accessed fromt the main server thread, so it
 *	doesn't need locks.
 */
static int use_count = 0;

#define BSON_DESTROY(_x) do { if (_x) { bson_destroy(_x); _x = NULL; }} while (0)

static int _sql_destructor(rlm_sql_mongo_config_t *driver)
{
	if (driver->pool) {
		mongoc_client_pool_destroy(driver->pool);
		driver->pool = NULL;
	}

	use_count--;
	if (use_count == 0) {
		mongoc_cleanup();
	}

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, rlm_sql_config_t *config)
{
	rlm_sql_mongo_config_t	*driver;
	mongoc_uri_t *uri;
	bson_error_t error;

	MEM(driver = config->driver = talloc_zero(config, rlm_sql_mongo_config_t));
	if (cf_section_parse(conf, driver, driver_config) < 0) {
		return -1;
	}

	/*
	 *	Initialize the C library if necessary.
	 */
	if (use_count == 0) {
		mongoc_init();
	}
	use_count++;

	uri = mongoc_uri_new_with_error(config->sql_server, &error);
	if (!uri) {
		ERROR("Failed to parse server URI string '%s': %s",
		      config->sql_server, error.message);
		return -1;
	}

	driver->pool = mongoc_client_pool_new(uri);
	mongoc_client_pool_set_error_api(driver->pool, 2);

	if (driver->tls.ca_dir || driver->tls.ca_file) {
		mongoc_client_pool_set_ssl_opts(driver->pool, &driver->tls);
	}

	mongoc_uri_destroy(uri);
	talloc_set_destructor(driver, _sql_destructor);

	return 0;
}

static void sql_conn_free(rlm_sql_mongo_conn_t *conn)
{
	if (conn->bson_row) {
		int i;

		for (i = 0; i < conn->num_rows; i++) {
			BSON_DESTROY(conn->bson_row[i]);
		}

		TALLOC_FREE(conn->bson_row);
		conn->result = NULL; /* reference to conn->bson_row[0] */
	}
	conn->num_rows = 0;

	BSON_DESTROY(conn->result);
	TALLOC_FREE(conn->row);
	conn->num_fields = 0;
}

static int _sql_socket_destructor(rlm_sql_mongo_conn_t *conn)
{
	DEBUG2("rlm_sql_mongo: Socket destructor called, closing socket.");
	sql_conn_free(conn);
	return 0;
}

static int CC_HINT(nonnull) sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_mongo_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	conn->driver = config->driver;

	DEBUG2("rlm_sql_mongo: Socket initialized.");
	return 0;
}

/*
 *	Only return the number of columns if there's an actual result.
 */
static int sql_num_fields(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t *conn = handle->conn;

	return conn->num_fields;
}

static int sql_affected_rows(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t *conn = handle->conn;

	return conn->affected_rows;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t *conn = handle->conn;

	sql_conn_free(conn);

	return 0;
}


static CC_HINT(nonnull) sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
					      char const *query)
{
	rlm_sql_mongo_conn_t *conn = handle->conn;
	char const *p, *q;
	char *str, *r, *end;
	bool aggregate = false;
	bool findandmodify = false;
	bool find = false;
	bool insert = false;
	char *ptr;
	mongoc_client_t *client;
	bson_t *bson = NULL;
	bool rcode;
	bson_iter_t iter;
	mongoc_collection_t *collection;
	bson_t *bson_query, *bson_update, *bson_sort, *bson_fields;
	char name[256];
	char command[256];

	conn->affected_rows = 0;
	conn->cur_row = 0;

	client = NULL;
	collection = NULL;
	bson_query = bson_update = bson_sort = bson_fields = NULL;

	/*
	 *	Ensure that we use whatever results come back now not
	 *	whatever was left over from before.  Also, if the
	 *	query / connection fails, that there is less to clean up.
	 */
	BSON_DESTROY(conn->result);

	/*
	 *	See what kind of query it is.  Aggregate queries
	 *	require a different API, so they are handled differently.
	 *
	 *	The query string is "db.COLLECTION.COMMAND( ... json ... )
	 *
	 *	We parse the string to see what's up.
	 */
	p = query;
	while (isspace((int) *p)) p++;

	if (strncmp(p, "db.", 3) != 0) {
		ERROR("rlm_sql_mongo: Invalid query - must start with 'db.'");
		return RLM_SQL_QUERY_INVALID;
	}
	p += 3;

	/*
	 *	Get the collection name.
	 */
	ptr = name;
	while (*p) {
		/*
		 *	Stop if we hit the next delimiter, and skip
		 *	it.
		 */
		if (*p == '.') {
			*ptr = '\0';
			p++;
			break;
		}

		if ((size_t) (ptr - name) >= sizeof(name)) {
			ERROR("rlm_sql_mongo: Invalid query - collection name is too long");
			return RLM_SQL_QUERY_INVALID;
		}

		*(ptr++) = *(p++);
	}

	/*
	 *	Get the command name.  There's no real need to copy it
	 *	here, but it's fine.
	 */
	ptr = command;
	while (*p) {
		/*
		 *	Allow whitespace after the command name, and
		 *	before the bracket.
		 */
		if (isspace((int) *p)) {
			*ptr = '\0';
			while (*p && isspace((int) *p)) p++;

			if (*p != '(') {
				ERROR("rlm_sql_mongo: Invalid query - no starting '('");
				return RLM_SQL_QUERY_INVALID;
			}
		}

		/*
		 *	Stop if we hit the brace holding the json, and
		 *	skip it.
		 */
		if (*p == '(') {
			*ptr = '\0';
			p++;
			break;
		}

		if ((size_t) (ptr - command) >= sizeof(command)) {
			ERROR("rlm_sql_mongo: Invalid query - command name is too long");
			return RLM_SQL_QUERY_INVALID;
		}

		*(ptr++) = *(p++);
	}

	/*
	 *	Look for the ending ')'.
	 */
	q = strrchr(p, ')');
	if (!q) {
		ERROR("rlm_sql_mongo: Invalid query - no ending ')'");
		return RLM_SQL_QUERY_INVALID;
	}

	if (q[1] != '\0') {
		ERROR("rlm_sql_mongo: Invalid query - Unexpected text after ')'");
		return RLM_SQL_QUERY_INVALID;
	}

	if (strcasecmp(command, "findOne") == 0) {
	        find = true;

	} else if (strcasecmp(command, "findAndModify") == 0) {
		findandmodify = true;

	} else if (strcasecmp(command, "aggregate") == 0) {
		aggregate = true;

	} else if (strcasecmp(command, "insert") == 0) {
		insert = true;

	} else {
		ERROR("rlm_sql_mongo: Invalid query - Unknown / unsupported Mongo command '%s'",
			command);
		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *	Take a second pass over the query, moving single quotes to double quotes.
	 */
	str = talloc_strndup(NULL, p, (size_t) (q - p));
	end = str + (q - p);
	for (r = str; r < end; r++) {
		if (*r == '\'') *r = '"';
	}

	/*
	 *	<whew>  p && q now enclose the json blob.
	 */
	bson = bson_new_from_json((uint8_t const *) str, q - p, &conn->error);
	talloc_free(str);
	if (!bson) {
		ERROR("rlm_sql_mongo: Invalid query - json is malfomed - %s",
		      conn->error.message);
		return RLM_SQL_QUERY_INVALID;
	}

	/*
	 *	Get the client connection, run the command, and return
	 *	the connection to the pool.
	 *
	 *	Note that MongoC has it's own thread-safe thread pool
	 *	connection handling.
	 *
	 *	The total number of clients that can be created from
	 *	this pool is limited by the URI option “maxPoolSize”,
	 *	default 100. If this number of clients has been
	 *	created and all are in use, the "pop" call will block
	 *	until another thread has done a "push".
	 */
	client = mongoc_client_pool_pop(conn->driver->pool);
	collection = mongoc_client_get_collection(client, config->sql_db, name);

	if (findandmodify) {
		bson_t bson_reply;
		bson_value_t const *value;
		bson_iter_t child;
		bool upsert, remove, update;
		uint8_t const *document;
		uint32_t document_len;

		upsert = remove = update = false;

		/*
		 *	Parse the various fields.
		 */
		if (bson_iter_init_find(&iter, bson, "query")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("rlm_sql_mongo: 'query' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_query = bson_new_from_data(document, document_len);
			if (!bson_query) {
				DEBUG("rlm_sql_mongo: Failed parsing 'query'");
				goto error;
			}
		} else {
			DEBUG("rlm_sql_mongo: No 'query' subdocument found.");
			goto error;
		}

		if (bson_iter_init_find(&iter, bson, "update")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("rlm_sql_mongo: 'update' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_update = bson_new_from_data(document, document_len);

			if (!bson_update) {
				DEBUG("rlm_sql_mongo: Failed parsing 'update'");
				goto error;
			}

			update = true;
		}

		if (bson_iter_init_find(&iter, bson, "sort")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("rlm_sql_mongo: 'sort' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_sort = bson_new_from_data(document, document_len);

			if (!bson_sort) {
				DEBUG("rlm_sql_mongo: Failed parsing 'sort'");
				goto error;
			}
		}

		if (bson_iter_init_find(&iter, bson, "fields")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("rlm_sql_mongo: 'fields' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_fields = bson_new_from_data(document, document_len);

			if (!bson_fields) {
				DEBUG("rlm_sql_mongo: Failed parsing 'fields'");
				goto error;
			}
		}

		if (bson_iter_init_find(&iter, bson, "upsert")) {
			if (!BSON_ITER_HOLDS_BOOL(&iter)) {
				DEBUG("rlm_sql_mongo: 'upsert' does not hold a boolean.");
				goto error;
			}

			upsert = bson_iter_as_bool(&iter);
		}

		if (bson_iter_init_find(&iter, bson, "remove")) {
			if (!BSON_ITER_HOLDS_BOOL(&iter)) {
				DEBUG("rlm_sql_mongo: 'remove' does not hold a boolean.");
				goto error;
			}

			remove = bson_iter_as_bool(&iter);
		}

		if (!update && !remove) {
			WARN("rlm_sql_mongo: 'findAndModify' requires 'update' or 'remove'.  Query will likely fail");
		}

		rcode = mongoc_collection_find_and_modify(collection, bson_query,
							  bson_sort, bson_update, bson_fields,
							  remove, upsert,
							  true, &bson_reply,
							  &conn->error);
		BSON_DESTROY(bson_query);
		BSON_DESTROY(bson_update);
		BSON_DESTROY(bson_sort);
		BSON_DESTROY(bson_fields);

		/*
		 *	See just what the heck was returned.
		 */
		if (rad_debug_lvl >= 3) {
			str = bson_as_canonical_extended_json (&bson_reply, NULL);
			if (str) {
				DEBUG3("bson reply: %s\n", str);
				bson_free(str);
			}
		}

		/*
		 *	If we've removed something, we've affected a
		 *	row.
		 */
		if (remove) {
			conn->affected_rows = 1;
			goto done_reply;
		}

		/*
		 *	Retrieve the number of affected documents
		 */
		if (bson_iter_init_find(&iter, &bson_reply, "lastErrorObject") &&
		    BSON_ITER_HOLDS_DOCUMENT(&iter) &&
		    bson_iter_recurse(&iter, &child) &&
		    bson_iter_find(&child, "n") &&
		    BSON_ITER_HOLDS_INT32(&child)) {
			value = bson_iter_value(&child);
			conn->affected_rows = value->value.v_int32;
			DEBUG3("Query updated %u documents", value->value.v_int32);
		}

		if (!conn->affected_rows) {
			WARN("rlm_sql_mongo: No document updated for query.");
		}

		if (!bson_iter_init_find(&iter, &bson_reply, "value")) {
			DEBUG3("reply has no 'value'");
			goto done_reply;
		}

		/*
		 *	The actual result is in the "value" of the
		 *	reply.  It should be a document.
		 */
		if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
			DEBUG3("reply 'value' is not a document");
			goto done_reply;
		}

		/*
		 *	If the query returns a scalar, the scalar is
		 *	in "value.value".  The top-level "value"
		 *	document also contains copies of the other
		 *	fields used by the query, and we don't care
		 *	about those other fields.
		 */
		if (!bson_iter_recurse(&iter, &child) ||
		    !bson_iter_find(&child, "value")) {
			DEBUG3("reply has no 'value.value'");
			goto done_reply;
		}

		/*
		 *	"value.value" should hold something tangible.
		 */
		if (!BSON_ITER_HOLDS_UTF8(&child) &&
		    !BSON_ITER_HOLDS_INT32(&child) &&
		    !BSON_ITER_HOLDS_TIMESTAMP(&child) &&
		    !BSON_ITER_HOLDS_INT64(&child)) {
			DEBUG3("reply has 'value.value' is not utf8 / int32 / int64 / timestamp");
			goto done_reply;
		}

		/*
		 *	Finally, grab the value.
		 */
		value = bson_iter_value(&child);
		if (!value) {
			DEBUG3("reply has 'value.value', but it cannot be parsed");
			goto done_reply;
		}

		/*
		 *      Synthesize a new result from the scalar value.
		 *
		 *      This work is done so that fetch_row() has a
		 *      consistent type of result to work with.
		 */
		conn->result = bson_new();
		(void) bson_append_value(conn->result, "scalar", 6, value);

	done_reply:
		bson_destroy(&bson_reply);

	} else if (insert) {
		if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, bson, NULL, &conn->error)) {
			goto print_error;
		}

		bson_destroy(bson);
		mongoc_client_pool_push(conn->driver->pool, client);
		mongoc_collection_destroy(collection);
		conn->num_fields = 0;

		return RLM_SQL_OK;

	} else {
		mongoc_cursor_t *cursor;
		bson_t const *doc;

		/*
		 *	findOne versus aggregate.  For findOne, we
		 *	limit the results to (drumroll) one.
		 */
		if (find) {
			bson_t *opts = BCON_NEW("limit", BCON_INT64 (1));
			cursor = mongoc_collection_find_with_opts(collection, bson, opts, NULL);
			bson_destroy(opts);

		} else {
			rad_assert(aggregate == true);
			cursor = mongoc_collection_aggregate(collection, MONGOC_QUERY_NONE, bson, NULL, NULL);
		}

		conn->num_rows = 0;
		conn->bson_row = talloc_zero_array(conn, bson_t *, MAX_ROWS);

		/*
		 *	Copy the documents.
		 */
		while (mongoc_cursor_next(cursor, &doc)) {
			conn->bson_row[conn->num_rows] = bson_copy(doc);

			if (rad_debug_lvl >= 3) {
				str = bson_as_canonical_extended_json (doc, NULL);
				if (str) {
					DEBUG3("rlm_sql_mongo got result into row %d: %s", conn->num_rows, str);
					bson_free(str);
				}
			}

			conn->num_rows++;
			if (conn->num_rows >= MAX_ROWS) break;
		}

		if (mongoc_cursor_error(cursor, &conn->error)) {
			DEBUG("rlm_sql_mongo: Failed running query: %s",
			      conn->error.message);
			rcode = false;
		} else {
			rcode = true;
		}

		mongoc_cursor_destroy(cursor);

		/*
		 *	As a hack to simplify the later code.
		 */
		conn->result = conn->bson_row[0];
	}

	mongoc_client_pool_push(conn->driver->pool, client);
	client = NULL;
	mongoc_collection_destroy(collection);
	collection = NULL;

	if (!conn->result) {
		DEBUG("rlm_sql_mongo: Query got no result");
		BSON_DESTROY(bson);
		(void) sql_free_result(handle, config);
		return RLM_SQL_OK;		
	}

	if (!rcode) {
	print_error:
		DEBUG("rlm_sql_mongo: Failed running command: %s",
		       conn->error.message);

	error:
		if (client) mongoc_client_pool_push(conn->driver->pool, client);
		if (collection) mongoc_collection_destroy(collection);
		BSON_DESTROY(bson);
		BSON_DESTROY(bson_query);
		BSON_DESTROY(bson_update);
		BSON_DESTROY(bson_sort);
		BSON_DESTROY(bson_fields);
		(void) sql_free_result(handle, config);
		return RLM_SQL_ERROR;
	}

	/*
	 *	No more need for this.
	 */
	BSON_DESTROY(bson);

	/*
	 *	Count the number of fields in the first row.  This is
	 *	the number of fields that each row must have.
	 */
	conn->num_fields = 0;
	if (!bson_iter_init(&iter, conn->result)) goto error;

	while (bson_iter_next(&iter)) {
		conn->num_fields++;
	}

	/*
	 *	And let sql_fetch_row do the actual work of parsing the bson.
	 */

	return RLM_SQL_OK;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t * handle, rlm_sql_config_t *config, char const *query)
{
	return sql_query(handle, config, query);
}

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t *conn = handle->conn;
	int i, num_fields;
	bson_t *bson;
	bson_iter_t iter;

	handle->row = NULL;

	if (conn->num_rows) {
		DEBUG("getting result from row %d = %p", conn->cur_row,
		      conn->bson_row[conn->cur_row]);
		bson = conn->bson_row[conn->cur_row++];
	} else {
		bson = conn->result;
	}

	TALLOC_FREE(conn->row);

	if (!bson) {
		DEBUG("No more rows");
		return RLM_SQL_NO_MORE_ROWS;
	}

	if (!bson_iter_init(&iter, bson)) return RLM_SQL_NO_MORE_ROWS;

	/*
	 *	Find the number of fields in this row.
	 */
	num_fields = 0;
	while (bson_iter_next(&iter)) {
		num_fields++;
	}

	if (!bson_iter_init(&iter, bson)) return RLM_SQL_NO_MORE_ROWS;

	/*
	 *	If this row has a different number of columns than the
	 *	first one, all bets are off.  Stop processing the
	 *	result.
	 */
	if (num_fields != conn->num_fields) return RLM_SQL_NO_MORE_ROWS;

	conn->row = talloc_zero_array(conn, char *, conn->num_fields + 1);

	if (!bson_iter_init(&iter, bson)) return RLM_SQL_NO_MORE_ROWS;

	/*
	 *	We have to call this to get the FIRST element.
	 */
	if (!bson_iter_next(&iter)) return RLM_SQL_OK;

	for (i = 0; i < conn->num_fields; i++) {
		bson_value_t const *value;

		if (conn->row[i]) TALLOC_FREE(conn->row[i]);

		DEBUG3("rlm_sql_mongo: key '%s' at field %d", bson_iter_key(&iter), i);

		value = bson_iter_value(&iter);
		if (!value) {
			DEBUG("rlm_sql_mongo: Iteration returned no value at field %d", i);
			return RLM_SQL_NO_MORE_ROWS;
		}

		switch (value->value_type) {
		case BSON_TYPE_INT32:
			conn->row[i] = talloc_asprintf(conn->row, "%u", value->value.v_int32);
			break;

		case BSON_TYPE_INT64:
			conn->row[i] = talloc_asprintf(conn->row, "%" PRIu64, value->value.v_int64);
			break;

			/*
			 *	In milliseconds, as a 64-bit number.
			 */
		case BSON_TYPE_TIMESTAMP:
			conn->row[i] = talloc_asprintf(conn->row, "%" PRIu64, value->value.v_datetime / 1000);
			break;

		case BSON_TYPE_UTF8:
			conn->row[i] = talloc_asprintf(conn->row, "%.*s", value->value.v_utf8.len, value->value.v_utf8.str);
			break;

		default:
			conn->row[i] = talloc_asprintf(conn->row, "??? unknown bson type %u ???", value->value_type);
			break;
		}

		handle->row = conn->row;

		if (!bson_iter_next(&iter)) break;
	}

	return RLM_SQL_OK;
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
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mongo_conn_t	*conn = handle->conn;

	rad_assert(outlen > 0);

	out[0].type = L_ERR;
	out[0].msg = talloc_asprintf(ctx, "%u.%u: %s", conn->error.domain, conn->error.code, conn->error.message);
	return 1;
}

/*
 *	Escape strings.  Note that we escape things for json: " and \, and 0x00
 *	We also escape single quotes, as they're used in the queries.
 */
static size_t sql_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char			*p, *end;
	char const		*q;

	end = out + outlen;
	p = out;
	q = in;

	while (*q) {				  
		if ((*q == '\'') || (*q == '"') || (*q == '\\')) {
			if ((end - p) <= 2) break;

			*(p++) = '\\';

		} else {
			if ((end - p) <= 1) break;
		}

		*(p++) = *(q++);
	}

	*(p++) = '\0';

	return p - out;
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_mongo;
rlm_sql_module_t rlm_sql_mongo = {
	.name				= "rlm_sql_mongo",
	.mod_instantiate		= mod_instantiate,
	.sql_socket_init		= sql_socket_init,
	.sql_finish_query		= sql_free_result,
	.sql_finish_select_query	= sql_free_result,
	.sql_num_fields			= sql_num_fields,
	.sql_affected_rows		= sql_affected_rows,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_fetch_row			= sql_fetch_row,
	.sql_error			= sql_error,
	.sql_escape_func		= sql_escape_func
};
