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
 * @copyright 2023 The FreeRADIUS server project.
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#define LOG_PREFIX "sql - mongodb"
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/json/base.h>

#include <mongoc.h>

#include "rlm_sql.h"

typedef enum {
	SERVER_WARNINGS_AUTO = 0,
	SERVER_WARNINGS_YES,
	SERVER_WARNINGS_NO
} rlm_sql_mongo_warnings;

static fr_table_num_sorted_t const server_warnings_table[] = {
	{ L("auto"),	SERVER_WARNINGS_AUTO	},
	{ L("no"),		SERVER_WARNINGS_NO	},
	{ L("yes"),	SERVER_WARNINGS_YES	}
};
static size_t server_warnings_table_len = NUM_ELEMENTS(server_warnings_table);

#define MAX_ROWS (64)

typedef struct {
	mongoc_client_pool_t	*pool;	//!< A connection pool.
	bson_t		*result;
	bson_error_t	error;
	int		cur_row;
	int		num_fields;		//!< number of columns
	int		affected_rows;		//!< only for writes

	int		num_rows;		//!< for selects
	bson_t		**bson_row;		//!< copy of selected document

	char		**row;			//!< really fields, i.e. columns
} rlm_sql_mongo_conn_t;

typedef struct {
	char 				*uri_string;	//!< A string containing a URI.
	bool  				has_appname;	//!< Flag checking if 'appname' is already in URI connection.
	mongoc_ssl_opt_t		tls;		//!< This structure is used to set the TLS options for a mongoc_client_pool_t.

	char const			*warnings_str;		//!< Whether we always query the server for additional warnings.
	rlm_sql_mongo_warnings		warnings;		//!< Appear to work with NDB cluster
} rlm_sql_mongo_t;

static CONF_PARSER tls_config[] = {
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, rlm_sql_mongo_t, tls.pem_file) },
	{ FR_CONF_OFFSET("certificate_password", FR_TYPE_STRING, rlm_sql_mongo_t, tls.pem_pwd) },
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, rlm_sql_mongo_t, tls.ca_file) },
	{ FR_CONF_OFFSET("ca_dir", FR_TYPE_FILE_INPUT, rlm_sql_mongo_t, tls.ca_dir) },
	{ FR_CONF_OFFSET("crl_file", FR_TYPE_FILE_INPUT, rlm_sql_mongo_t, tls.crl_file) },
	{ FR_CONF_OFFSET("weak_cert_validation", FR_TYPE_BOOL, rlm_sql_mongo_t, tls.weak_cert_validation) },
	{ FR_CONF_OFFSET("allow_invalid_hostname", FR_TYPE_BOOL, rlm_sql_mongo_t, tls.allow_invalid_hostname) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER driver_config[] = {
	{ FR_CONF_OFFSET("warnings", FR_TYPE_STRING, rlm_sql_mongo_t, warnings_str), .dflt = "auto" },

	{ FR_CONF_POINTER("tls", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) tls_config },
	CONF_PARSER_TERMINATOR
};

/*
 *	This is only accessed fromt the main server thread, so it
 *	doesn't need locks.
 */
#define BSON_DESTROY(_x) do { if (_x) { bson_destroy(_x); _x = NULL; }} while (0)

static void show_servers(mongoc_client_t *client)
{
   bson_t *b = BCON_NEW ("ping", BCON_INT32 (1));
   bson_error_t error;
   mongoc_server_description_t **sds;
   bool r;
   size_t i, n;

   DEBUG2("Show servers");

   /* ensure client has connected */
   r = mongoc_client_command_simple(client, "db", b, NULL, NULL, &error);
   if (!r) {
      MONGOC_ERROR ("could not connect: %s", error.message);
      return;
   }

   sds = mongoc_client_get_server_descriptions(client, &n);

   for (i = 0; i < n; ++i) DEBUG ("\t--> %s", mongoc_server_description_host(sds[i])->host_and_port);

   mongoc_server_descriptions_destroy_all(sds, n);
   bson_destroy(b);
}

static int mod_load(void)
{
	/*
	 *	Initialize the C library if necessary.
	 */
	mongoc_init();

	INFO("libmongoc version: %s, libbson version: %s", mongoc_get_version(), bson_get_version());

	return 0;
}

static void mod_unload(void)
{
	/*
	 * exactly once at the end of your program to release all
	 * memory and other resources allocated by the driver.
	 */
	mongoc_cleanup();
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_sql_t const		*parent = talloc_get_type_abort(mctx->inst->parent->data, rlm_sql_t);
	rlm_sql_mongo_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_sql_mongo_t);
	rlm_sql_config_t const	*config = &parent->config;
	int			warnings;

	warnings = fr_table_value_by_str(server_warnings_table, inst->warnings_str, -1);
	if (warnings < 0) {
		ERROR("Invalid warnings value \"%s\", must be yes, no, or auto", inst->warnings_str);
		return -1;
	}
	inst->warnings = (rlm_sql_mongo_warnings)warnings;

	/* Be able to accept single 'host' and just append the mongdodb:// prefix */
	if (strncmp(config->sql_server, "mongodb://", 10) == 0) {
		inst->uri_string = talloc_strdup(inst, config->sql_server);
	} else {
		/*
		 * .... or, lets build a uri as described in
		 * http://mongoc.org/libmongoc/current/mongoc_uri_new_with_error.html?highlight=mongoc_uri_new_with_error
		 */
		inst->uri_string = talloc_strdup(inst, "mongodb://");

		if (config->sql_login) {
			inst->uri_string = talloc_asprintf_append(inst->uri_string, "%s", config->sql_login);
		}

		if (config->sql_login && config->sql_password) {
			inst->uri_string = talloc_asprintf_append(inst->uri_string, ":");
		}

		if (config->sql_password) {
			inst->uri_string = talloc_asprintf_append(inst->uri_string, "%s", config->sql_password);
		}

		if (config->sql_login && config->sql_password) {
			inst->uri_string = talloc_asprintf_append(inst->uri_string, "@");
		}

		if (config->sql_server) {
			inst->uri_string = talloc_strdup_append_buffer(inst->uri_string, config->sql_server);
		}

		if (config->sql_port) {
			inst->uri_string = talloc_asprintf_append(inst->uri_string, ":%i", config->sql_port);
		}

		if (config->sql_db) {
			inst->has_appname = true;
			inst->uri_string = talloc_asprintf_append(inst->uri_string, "/?appname=%s", config->sql_db);
		}
	}

	return 0;
}

static int sql_conn_free(rlm_sql_mongo_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket.");

	if (conn->bson_row) {
		int i;

		for (i = 0; i < conn->num_rows; i++) BSON_DESTROY(conn->bson_row[i]);

		TALLOC_FREE(conn->bson_row);
		conn->result = NULL; /* reference to conn->bson_row[0] */
	}
	conn->num_rows = 0;

	BSON_DESTROY(conn->result);
	TALLOC_FREE(conn->row);
	conn->num_fields = 0;

	return 0;
}

static int _sql_socket_destructor(rlm_sql_mongo_conn_t *conn)
{
	int ret;

	ret = sql_conn_free(conn);

	if (conn->pool) mongoc_client_pool_destroy(conn->pool);

	return ret;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, UNUSED fr_time_delta_t timeout)
{
	rlm_sql_mongo_t 	*inst = talloc_get_type_abort(handle->inst->driver_submodule->dl_inst->data, rlm_sql_mongo_t);
	rlm_sql_mongo_conn_t *conn;
	mongoc_uri_t *uri;
	bson_error_t error;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_mongo_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	DEBUG2("Socket initialized using %s", inst->uri_string);

	uri = mongoc_uri_new_with_error(inst->uri_string, &error);
	if (!uri) {
		ERROR("Failed to parse server URI string '%s': %s", inst->uri_string, error.message);
		return -1;
	}

	conn->pool = mongoc_client_pool_new(uri);
	if (!conn->pool) {
		ERROR("Failed to parse server URI string '%s'", inst->uri_string);
		mongoc_uri_destroy(uri);
		return -1;
	}
	mongoc_uri_destroy(uri);

	/*
	 * Register the application name only if the uri is no using the appname.
	 * so we can track it in the profile logs on the server. In that case we
	 * only should call _pool_set_appname if it wasn't set.
	 */
	if (config->sql_db && !inst->has_appname) mongoc_client_pool_set_appname(conn->pool, config->sql_db);

	/* This function can only be called once on a pool, and must be called before the first call */
	if (inst->warnings == SERVER_WARNINGS_AUTO ||
		inst->warnings == SERVER_WARNINGS_YES) {
		mongoc_client_pool_set_error_api(conn->pool, MONGOC_ERROR_API_VERSION_2);
	}

	if (inst->tls.ca_dir || inst->tls.ca_file) mongoc_client_pool_set_ssl_opts(conn->pool, &inst->tls);

	return RLM_SQL_OK;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	if (conn->result) return conn->num_rows;

	return 0;
}

/*
 *	Only return the number of columns if there's an actual result.
 */
static int sql_num_fields(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	return conn->num_fields;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	int		i = 0;
	char const	**names;
	bson_iter_t 	iter;

	if (conn->num_fields <= 0 || !bson_iter_init(&iter, conn->result)) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, conn->num_fields));

	while(bson_iter_next(&iter)) names[i++] = talloc_strdup(names, bson_iter_key(&iter));

	*out = names;

	return RLM_SQL_OK;
}

static int sql_affected_rows(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	return conn->affected_rows;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	sql_conn_free(conn);

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, char const *query)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);
	char const *p, *q;
	char *str, *r, *end;
	bool aggregate = false;
	bool findandmodify = false;
	bool find = false;
	bool insert = false;
	bool remove = false;
	bool rcode;
	char *ptr;
	char name[256];
	char command[256];
	mongoc_client_t *client = NULL;
	bson_t *bson = NULL;
	bson_iter_t iter;
	mongoc_collection_t *collection = NULL;
	bson_t *bson_query = NULL, *bson_update = NULL, *bson_sort = NULL, *bson_fields = NULL;

	conn->affected_rows = 0;
	conn->cur_row = 0;

	fr_assert(conn->pool != NULL);

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

	fr_skip_whitespace(p);
	if (strncmp(p, "db.", 3) != 0) {
		ERROR("Invalid query - must start with 'db.'");
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
			ERROR("Invalid query - collection name is too long");
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
		if (isspace((uint8_t) *p)) {
			*ptr = '\0';

			fr_skip_whitespace(p);
			if (*p != '(') {
				ERROR("Invalid query - no starting '('");
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
			ERROR("Invalid query - command name is too long");
			return RLM_SQL_QUERY_INVALID;
		}

		*(ptr++) = *(p++);
	}

	/*
	 *	Look for the ending ')'.
	 */
	q = strrchr(p, ')');
	if (!q) {
		ERROR("Invalid query - no ending ')'");
		return RLM_SQL_QUERY_INVALID;
	}

	if (q[1] != '\0') {
		ERROR("Invalid query - Unexpected text after ')'");
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
	} else if (strcasecmp(command, "remove") == 0) {
		remove = true;
	} else {
		ERROR("Invalid query - Unknown / unsupported Mongo command '%s'", command);
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
		ERROR("Invalid query - json is malfomed - %s", conn->error.message);
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
	client = mongoc_client_pool_pop(conn->pool);
	if (!client) goto print_error;

	show_servers(client);

	collection = mongoc_client_get_collection(client, config->sql_db, name);
	if (!collection) goto print_error;

	if (findandmodify) {
		bson_t bson_reply;
		bson_value_t const *value;
		bson_iter_t child;
		bool upsert, update;
		uint8_t const *document;
		uint32_t document_len;

		upsert = remove = update = false;

		/*
		 *	Parse the various fields.
		 */
		if (bson_iter_init_find(&iter, bson, "query")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("'query' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_query = bson_new_from_data(document, document_len);
			if (!bson_query) {
				DEBUG("Failed parsing 'query'");
				goto error;
			}
		} else {
			DEBUG("No 'query' subdocument found.");
			goto error;
		}

		if (bson_iter_init_find(&iter, bson, "update")) {
			if (!(BSON_ITER_HOLDS_DOCUMENT(&iter) || BSON_ITER_HOLDS_ARRAY(&iter))) {
				DEBUG("'update' does not hold a document or array.");
				goto error;
			}

			if (BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				bson_iter_document(&iter, &document_len, &document);
			} else {
				bson_iter_array(&iter, &document_len, &document);
			}

			bson_update = bson_new_from_data(document, document_len);

			if (!bson_update) {
				DEBUG("Failed parsing 'update'");
				goto error;
			}

			update = true;
		}

		if (bson_iter_init_find(&iter, bson, "sort")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("'sort' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_sort = bson_new_from_data(document, document_len);

			if (!bson_sort) {
				DEBUG("Failed parsing 'sort'");
				goto error;
			}
		}

		if (bson_iter_init_find(&iter, bson, "fields")) {
			if (!BSON_ITER_HOLDS_DOCUMENT(&iter)) {
				DEBUG("'fields' does not hold a document.");
				goto error;
			}

			bson_iter_document(&iter, &document_len, &document);
			bson_fields = bson_new_from_data(document, document_len);

			if (!bson_fields) {
				DEBUG("Failed parsing 'fields'");
				goto error;
			}
		}

		if (bson_iter_init_find(&iter, bson, "upsert")) {
			if (!BSON_ITER_HOLDS_BOOL(&iter)) {
				DEBUG("'upsert' does not hold a boolean.");
				goto error;
			}

			upsert = bson_iter_as_bool(&iter);
		}

		if (bson_iter_init_find(&iter, bson, "remove")) {
			if (!BSON_ITER_HOLDS_BOOL(&iter)) {
				DEBUG("'remove' does not hold a boolean.");
				goto error;
			}

			remove = bson_iter_as_bool(&iter);
		}

		if (!update && !remove) {
			WARN("'findAndModify' requires 'update' or 'remove'.  Query will likely fail");
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
		if (fr_debug_lvl >= 3) {
			str = bson_as_canonical_extended_json (&bson_reply, NULL);
			if (str) {
				DEBUG3("bson reply: %s", str);
				bson_free(str);
			}
		}

		/*
		 *	If we've removed something, we've affected a row.
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

		if (!conn->affected_rows) WARN("No document updated for query.");

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
		if (!bson_iter_recurse(&iter, &child) || !bson_iter_find(&child, "value")) {
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
		if (!bson_append_value(conn->result, "scalar", 6, value)) {
			DEBUG2("Failed append 'scalar' command.");
			goto error;
		}

	done_reply:
		bson_destroy(&bson_reply);

	} else if (insert) {
		if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, bson, NULL, &conn->error)) goto print_error;

		bson_destroy(bson);
		mongoc_client_pool_push(conn->pool, client);
		mongoc_collection_destroy(collection);
		conn->num_fields = 0;

		return RLM_SQL_OK;

	} else if (remove) {
		if (!mongoc_collection_remove(collection, MONGOC_REMOVE_NONE, bson, NULL, &conn->error)) goto print_error;

		bson_destroy(bson);
		mongoc_client_pool_push(conn->pool, client);
		mongoc_collection_destroy(collection);
		conn->num_fields = 0;

		return RLM_SQL_OK;

	} else if (remove) {
		if (!mongoc_collection_remove(collection, MONGOC_REMOVE_NONE, bson, NULL, &conn->error)) goto print_error;

		bson_destroy(bson);
		mongoc_client_pool_push(conn->pool, client);
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
			bson_t *opts;

			opts = BCON_NEW("limit", BCON_INT64 (1));
			cursor = mongoc_collection_find_with_opts(collection, bson, opts, NULL);
			bson_destroy(opts);

		} else {
			fr_assert(aggregate == true);
			(void)aggregate;
			cursor = mongoc_collection_aggregate(collection, MONGOC_QUERY_NONE, bson, NULL, NULL);
		}

		conn->num_rows = 0;
		conn->bson_row = talloc_zero_array(conn, bson_t *, MAX_ROWS);

		/*
		 *	Copy the documents.
		 */
		while (mongoc_cursor_next(cursor, &doc)) {
			conn->bson_row[conn->num_rows] = bson_copy(doc);

			if (fr_debug_lvl >= 3) {
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
			DEBUG("Failed running query: %s", conn->error.message);
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

	mongoc_client_pool_push(conn->pool, client);
	client = NULL;
	mongoc_collection_destroy(collection);
	collection = NULL;

	if (!conn->result) {
		DEBUG("Query got no result");
		BSON_DESTROY(bson);
		return RLM_SQL_OK;
	}

	if (!rcode) {
	print_error:
		DEBUG("Failed running command: %s", conn->error.message);

	error:
		if (client) mongoc_client_pool_push(conn->pool, client);
		if (collection) mongoc_collection_destroy(collection);

		BSON_DESTROY(bson);
		BSON_DESTROY(bson_query);
		BSON_DESTROY(bson_update);
		BSON_DESTROY(bson_sort);
		BSON_DESTROY(bson_fields);

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

	while (bson_iter_next(&iter)) conn->num_fields++;

	/*
	 *	And let sql_fetch_row do the actual work of parsing the bson.
	 */
	return RLM_SQL_OK;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, char const *query)
{
#if !defined(NDEBUG) && defined(HAVE_JSON)
	/* */
	if (fr_debug_lvl >= L_DBG_LVL_4) {
		char *p, *end, *json;
		const char *jstring;

		p = json = talloc_strdup(NULL, query);
		fr_skip_whitespace(p);

		/*
		 *	We should extract only the content in "db.$function( ... jSON ... )"
		 * to be possible dump the jSON in pretty format. Helpful to troubleshoot.
		 */
		p = strchr(p, '(');
		if (p) {
			if (*p == '(') p += 1;

			end = p + strlen(p);
			if (end && *(end-1) == ')') *(end - 1) = '\0';

			jstring = json_object_to_json_string_ext(json_tokener_parse(p), JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY);
			if (jstring) {
				char *jtmp;

				jtmp = talloc_strdup(NULL, jstring);

				DEBUG4("DEBUG jSON Query:");
				DEBUG4("---");
				for (p = strtok(jtmp, "\n"); p; p = strtok(NULL, "\n")) DEBUG2("%s", p);
				DEBUG4("---");

				talloc_free(jtmp);
			}
		}

		talloc_free(json);
	}
#endif

	return sql_query(handle, config, query);
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);
	int i, num_fields;
	bson_t *bson;
	bson_iter_t iter;

	*out = NULL;

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
	while (bson_iter_next(&iter)) num_fields++;

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

		DEBUG3("key '%s' at field %d", bson_iter_key(&iter), i);

		value = bson_iter_value(&iter);
		if (!value) {
			DEBUG("Iteration returned no value at field %d", i);
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

	*out = handle->row;

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
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], UNUSED size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mongo_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mongo_conn_t);

	fr_assert(outlen > 0);

	out[0].type = L_ERR;
	out[0].msg = talloc_asprintf(ctx, "%u.%u: %s", conn->error.domain, conn->error.code, conn->error.message);

	return 1;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_mongo;
rlm_sql_driver_t rlm_sql_mongo = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_mongo",
		.inst_size			= sizeof(rlm_sql_mongo_t),
		.config				= driver_config,
		.onload				= mod_load,
		.unload				= mod_unload,
		.bootstrap			= mod_bootstrap
	},
	.flags					= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.number					= 11,

	.sql_socket_init		= sql_socket_init,
	.sql_query				= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_fields			= sql_fields,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error				= sql_error,
	.sql_finish_query		= sql_free_result,
	.sql_finish_select_query	= sql_free_result
};
