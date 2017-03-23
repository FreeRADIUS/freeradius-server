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
 * @file rlm_sql.c
 * @brief Implements SQL 'users' file, and SQL accounting.
 *
 * @copyright 2012-2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Mike Machado <mike@innercite.com>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_sql (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/map_proc.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/exfile.h>

#include <sys/stat.h>

#include "rlm_sql.h"

extern rad_module_t rlm_sql;

/*
 *	So we can do pass2 xlat checks on the queries.
 */
static const CONF_PARSER query_config[] = {
	{ FR_CONF_OFFSET("query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_MULTI, rlm_sql_config_t, accounting.query) },
	CONF_PARSER_TERMINATOR
};

/*
 *	For now hard-code the subsections.  This isn't perfect, but it
 *	helps the average case.
 */
static const CONF_PARSER type_config[] = {
	{ FR_CONF_POINTER("accounting-on", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) query_config },
	{ FR_CONF_POINTER("accounting-off", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) query_config },
	{ FR_CONF_POINTER("start", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) query_config },
	{ FR_CONF_POINTER("interim-update", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) query_config },
	{ FR_CONF_POINTER("stop", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) query_config },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER acct_config[] = {
	{ FR_CONF_OFFSET("reference", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, accounting.reference), .dflt = ".query" },
	{ FR_CONF_OFFSET("logfile", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, accounting.logfile) },

	{ FR_CONF_POINTER("type", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) type_config },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER postauth_config[] = {
	{ FR_CONF_OFFSET("reference", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, postauth.reference), .dflt = ".query" },
	{ FR_CONF_OFFSET("logfile", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, postauth.logfile) },

	{ FR_CONF_OFFSET("query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_MULTI, rlm_sql_config_t, postauth.query) },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("driver", PW_TYPE_STRING, rlm_sql_config_t, sql_driver_name), .dflt = "rlm_sql_null" },
	{ FR_CONF_OFFSET("server", PW_TYPE_STRING, rlm_sql_config_t, sql_server), .dflt = "" },	/* Must be zero length so drivers can determine if it was set */
	{ FR_CONF_OFFSET("port", PW_TYPE_INTEGER, rlm_sql_config_t, sql_port), .dflt = "0" },
	{ FR_CONF_OFFSET("login", PW_TYPE_STRING, rlm_sql_config_t, sql_login), .dflt = "" },
	{ FR_CONF_OFFSET("password", PW_TYPE_STRING | PW_TYPE_SECRET, rlm_sql_config_t, sql_password), .dflt = "" },
	{ FR_CONF_OFFSET("radius_db", PW_TYPE_STRING, rlm_sql_config_t, sql_db), .dflt = "radius" },
	{ FR_CONF_OFFSET("read_groups", PW_TYPE_BOOLEAN, rlm_sql_config_t, read_groups), .dflt = "yes" },
	{ FR_CONF_OFFSET("read_profiles", PW_TYPE_BOOLEAN, rlm_sql_config_t, read_profiles), .dflt = "yes" },
	{ FR_CONF_OFFSET("read_clients", PW_TYPE_BOOLEAN, rlm_sql_config_t, do_clients), .dflt = "no" },
	{ FR_CONF_OFFSET("delete_stale_sessions", PW_TYPE_BOOLEAN, rlm_sql_config_t, delete_stale_sessions), .dflt = "yes" },
	{ FR_CONF_OFFSET("sql_user_name", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, query_user), .dflt = "" },
	{ FR_CONF_OFFSET("group_attribute", PW_TYPE_STRING, rlm_sql_config_t, group_attribute) },
	{ FR_CONF_OFFSET("logfile", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sql_config_t, logfile) },
	{ FR_CONF_OFFSET("default_user_profile", PW_TYPE_STRING, rlm_sql_config_t, default_profile), .dflt = "" },
	{ FR_CONF_OFFSET("client_query", PW_TYPE_STRING, rlm_sql_config_t, client_query), .dflt = "SELECT id,nasname,shortname,type,secret FROM nas" },
	{ FR_CONF_OFFSET("open_query", PW_TYPE_STRING, rlm_sql_config_t, connect_query) },

	{ FR_CONF_OFFSET("authorize_check_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, authorize_check_query) },
	{ FR_CONF_OFFSET("authorize_reply_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, authorize_reply_query) },

	{ FR_CONF_OFFSET("authorize_group_check_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, authorize_group_check_query) },
	{ FR_CONF_OFFSET("authorize_group_reply_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, authorize_group_reply_query) },
	{ FR_CONF_OFFSET("group_membership_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, groupmemb_query) },
#ifdef WITH_SESSION_MGMT
	{ FR_CONF_OFFSET("simul_count_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, simul_count_query) },
	{ FR_CONF_OFFSET("simul_verify_query", PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_NOT_EMPTY, rlm_sql_config_t, simul_verify_query) },
#endif
	{ FR_CONF_OFFSET("safe_characters", PW_TYPE_STRING, rlm_sql_config_t, allowed_chars), .dflt = "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },

	/*
	 *	This only works for a few drivers.
	 */
	{ FR_CONF_OFFSET("query_timeout", PW_TYPE_INTEGER, rlm_sql_config_t, query_timeout) },

	{ FR_CONF_POINTER("accounting", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) acct_config },

	{ FR_CONF_POINTER("post-auth", PW_TYPE_SUBSECTION, NULL), .subcs = (void const *) postauth_config },
	CONF_PARSER_TERMINATOR
};

static size_t sql_escape_for_xlat_func(REQUEST *request, char *out, size_t outlen, char const *in, void *arg);

/*
 *	Fall-Through checking function from rlm_files.c
 */
static sql_fall_through_t fall_through(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = fr_pair_find_by_num(vp, 0, PW_FALL_THROUGH, TAG_ANY);

	return tmp ? tmp->vp_integer : FALL_THROUGH_DEFAULT;
}

/*
 *	Yucky prototype.
 */
static int generate_sql_clients(rlm_sql_t *inst);
static size_t sql_escape_func(REQUEST *, char *out, size_t outlen, char const *in, void *arg);

#if 0
/** Execute an arbitrary SQL query
 *
 *  For selects the first value of the first column will be returned,
 *  for inserts, updates and deletes the number of rows affected will be
 *  returned instead.
 */
static ssize_t sql_xlat(UNUSED TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	rlm_sql_handle_t	*handle = NULL;
	rlm_sql_row_t		row;
	rlm_sql_t const		*inst = mod_inst;
	sql_rcode_t		rcode;
	ssize_t			ret = 0;
	char const		*p;

	handle = fr_connection_get(inst->pool, request);	/* connection pool should produce error */
	if (!handle) return 0;

	rlm_sql_query_log(inst, request, NULL, fmt);

	/*
	 *	Trim whitespace for the prefix check
	 */
	for (p = fmt; is_whitespace(p); p++);

	/*
	 *	If the query starts with any of the following prefixes,
	 *	then return the number of rows affected
	 */
	if ((strncasecmp(p, "insert", 6) == 0) ||
	    (strncasecmp(p, "update", 6) == 0) ||
	    (strncasecmp(p, "delete", 6) == 0)) {
		int numaffected;

		rcode = rlm_sql_query(inst, request, &handle, fmt);
		if (rcode != RLM_SQL_OK) {
		query_error:
			RERROR("SQL query failed: %s", fr_int2str(sql_rcode_table, rcode, "<INVALID>"));

			ret = -1;
			goto finish;
		}

		numaffected = (inst->driver->sql_affected_rows)(handle, inst->config);
		if (numaffected < 1) {
			RDEBUG("SQL query affected no rows");
			(inst->driver->sql_finish_query)(handle, inst->config);

			goto finish;
		}

		MEM(*out = talloc_asprintf(request, "%d", numaffected));
		ret = talloc_array_length(*out) - 1;

		(inst->driver->sql_finish_query)(handle, inst->config);

		goto finish;
	} /* else it's a SELECT statement */

	rcode = rlm_sql_select_query(inst, request, &handle, fmt);
	if (rcode != RLM_SQL_OK) goto query_error;

	rcode = rlm_sql_fetch_row(&row, inst, request, &handle);
	switch (rcode) {
	case RLM_SQL_OK:
		if (row[0]) break;

		RDEBUG("NULL value in first column of result");
		(inst->driver->sql_finish_select_query)(handle, inst->config);
		ret = -1;

		goto finish;

	case RLM_SQL_NO_MORE_ROWS:
		RDEBUG("SQL query returned no results");
		(inst->driver->sql_finish_select_query)(handle, inst->config);
		ret = -1;

		goto finish;

	default:
		(inst->driver->sql_finish_select_query)(handle, inst->config);
		goto query_error;
	}

	*out = talloc_bstrndup(request, row[0], strlen(row[0]));
	ret = talloc_array_length(*out) - 1;

	(inst->driver->sql_finish_select_query)(handle, inst->config);

finish:
	fr_connection_release(inst->pool, request, handle);

	return ret;
}
#endif

/** Converts a string value into a #VALUE_PAIR
 *
 * @param[in,out] ctx to allocate #VALUE_PAIR (s).
 * @param[out] out where to write the resulting #VALUE_PAIR.
 * @param[in] request The current request.
 * @param[in] map to process.
 * @param[in] uctx The value to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _sql_map_proc_get_value(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, void *uctx)
{
	VALUE_PAIR	*vp;
	char const	*value = uctx;

	vp = fr_pair_afrom_da(ctx, map->lhs->tmpl_da);
	/*
	 *	Buffer not always talloced, sometimes it's
	 *	just a pointer to a field in a result struct.
	 */
	if (fr_pair_value_from_str(vp, value, strlen(value)) < 0) {
		char *escaped;

		escaped = fr_asprint(vp, value, talloc_array_length(value) - 1, '"');
		REDEBUG("Failed parsing value \"%s\" for attribute %s: %s", escaped,
			map->lhs->tmpl_da->name, fr_strerror());
		talloc_free(vp); /* also frees escaped */

		return -1;
	}

	vp->op = map->op;
	*out = vp;

	return 0;
}

/*
 *	Verify the result of the map.
 */
static int sql_map_verify(CONF_SECTION *cs, UNUSED void *mod_inst, UNUSED void *proc_inst,
			  vp_tmpl_t const *src, UNUSED vp_map_t const *maps)
{
	if (!src) {
		cf_log_err_cs(cs, "Missing SQL query");

		return -1;
	}

	return 0;
}

#if 0
/** Executes a SELECT query and maps the result to server attributes
 *
 * @param mod_inst #rlm_sql_t instance.
 * @param proc_inst Instance data for this specific mod_proc call (unused).
 * @param request The current request.
 * @param query string to execute.
 * @param maps Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned or columns matched.
 *	- #RLM_MODULE_UPDATED if one or more #VALUE_PAIR were added to the #REQUEST.
 *	- #RLM_MODULE_FAIL if a fault occurred.
 */
static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, REQUEST *request,
				vp_tmpl_t const *query, vp_map_t const *maps)
{
	rlm_sql_t		*inst = talloc_get_type_abort(mod_inst, rlm_sql_t);
	rlm_sql_handle_t	*handle = NULL;

	int			i, j;

	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	sql_rcode_t		ret;

	vp_map_t const		*map;

	rlm_sql_row_t		row;

	int			rows = 0;
	int			field_cnt;
	char const		**fields = NULL, *map_rhs;
	char			map_rhs_buff[128];

	char			*query_str = NULL;

#define MAX_SQL_FIELD_INDEX (64)

	int			field_index[MAX_SQL_FIELD_INDEX];
	bool			found_field = false;	/* Did we find any matching fields in the result set ? */

	rad_assert(inst->driver->sql_fields);		/* Should have been caught during validation... */

	if (tmpl_aexpand(request, &query_str, request, query, sql_escape_for_xlat_func, inst) < 0) {
		return RLM_MODULE_FAIL;
	}

	for (i = 0; i < MAX_SQL_FIELD_INDEX; i++) field_index[i] = -1;

	/*
	 *	Add SQL-User-Name attribute just in case it is needed
	 *	We could search the string fmt for SQL-User-Name to see if this is
	 * 	needed or not
	 */
	sql_set_user(inst, request, NULL);

	handle = fr_connection_get(inst->pool, request);		/* connection pool should produce error */
	if (!handle) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	rlm_sql_query_log(inst, request, NULL, query_str);

	ret = rlm_sql_select_query(inst, request, &handle, query_str);
	if (ret != RLM_SQL_OK) {
		RERROR("SQL query failed: %s", fr_int2str(sql_rcode_table, ret, "<INVALID>"));
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	/*
	 *	Not every driver provides an sql_num_rows function
	 */
	if (inst->driver->sql_num_rows) {
		ret = inst->driver->sql_num_rows(handle, inst->config);
		if (ret == 0) {
			RDEBUG2("Server returned an empty result");
			rcode = RLM_MODULE_NOOP;
			(inst->driver->sql_finish_select_query)(handle, inst->config);
			goto finish;
		}

		if (ret < 0) {
			RERROR("Failed retrieving row count");
		error:
			rcode = RLM_MODULE_FAIL;
			(inst->driver->sql_finish_select_query)(handle, inst->config);
			goto finish;
		}
	}

	/*
	 *	Map proc only registered if driver provides an sql_fields function
	 */
	ret = (inst->driver->sql_fields)(&fields, handle, inst->config);
	if (ret != RLM_SQL_OK) {
		RERROR("Failed retrieving field names: %s", fr_int2str(sql_rcode_table, ret, "<INVALID>"));
		goto error;
	}
	rad_assert(fields);
	field_cnt = talloc_array_length(fields);

	if (RDEBUG_ENABLED3) for (j = 0; j < field_cnt; j++) RDEBUG3("Got field: %s", fields[j]);

	/*
	 *	Iterate over the maps, it's O(N2)ish but probably
	 *	faster than building a radix tree each time the
	 *	map set is evaluated (map->rhs can be dynamic).
	 */
	for (map = maps, i = 0;
	     map && (i < MAX_SQL_FIELD_INDEX);
	     map = map->next, i++) {
		/*
		 *	Expand the RHS to get the name of the SQL field
		 */
		if (tmpl_expand(&map_rhs, map_rhs_buff, sizeof(map_rhs_buff),
				request, map->rhs, NULL, NULL) < 0) {
			RERROR("Failed getting field name: %s", fr_strerror());
			goto error;
		}

		for (j = 0; j < field_cnt; j++) {
			if (strcmp(fields[j], map_rhs) != 0) continue;
			field_index[i] = j;
			found_field = true;
		}
	}

	/*
	 *	Couldn't resolve any map RHS values to fields
	 *	in the result set.
	 */
	if (!found_field) {
		RDEBUG("No fields matching map found in query result");
		rcode = RLM_MODULE_NOOP;
		(inst->driver->sql_finish_select_query)(handle, inst->config);
		goto finish;
	}

	/*
	 *	We've resolved all the maps to result indexes, now convert
	 *	the values at those indexes into VALUE_PAIRs.
	 *
	 *	Note: Not all SQL client libraries provide a row count,
	 *	so we have to do the count here.
	 */
	while (((ret = rlm_sql_fetch_row(&row, inst, request, &handle)) == RLM_SQL_OK)) {
		rows++;
		for (map = maps, j = 0;
		     map && (j < MAX_SQL_FIELD_INDEX);
		     map = map->next, j++) {
			if (field_index[j] < 0) continue;	/* We didn't find the map RHS in the field set */
			if (map_to_request(request, map, _sql_map_proc_get_value, row[field_index[j]]) < 0) goto error;
		}
	}

	if (ret == RLM_SQL_ERROR) goto error;

	if (rows == 0) {
		RDEBUG("SQL query returned no results");
		rcode = RLM_MODULE_NOOP;
	}

	(inst->driver->sql_finish_select_query)(handle, inst->config);

finish:
	talloc_free(query_str);
	talloc_free(fields);
	fr_connection_release(inst->pool, request, handle);

	return rcode;
}
#endif

#if 0
static int generate_sql_clients(rlm_sql_t *inst)
{
	rlm_sql_handle_t *handle;
	rlm_sql_row_t row;
	unsigned int i = 0;
	int ret = 0;
	RADCLIENT *c;

	DEBUG("Processing generate_sql_clients");
	DEBUG("Query is: %s", inst->config->client_query);

	handle = fr_connection_get(inst->pool, NULL);
	if (!handle) return -1;

	if (rlm_sql_select_query(inst, NULL, &handle, inst->config->client_query) != RLM_SQL_OK) return -1;

	while (rlm_sql_fetch_row(&row, inst, NULL, &handle) == RLM_SQL_OK) {
		char *server = NULL;
		i++;

		/*
		 *  The return data for each row MUST be in the following order:
		 *
		 *  0. Row ID (currently unused)
		 *  1. Name (or IP address)
		 *  2. Shortname
		 *  3. Type
		 *  4. Secret
		 *  5. Virtual Server (optional)
		 */
		if (!row[0]){
			ERROR("No row id found on pass %d", i);
			continue;
		}
		if (!row[1]){
			ERROR("No nasname found for row %s", row[0]);
			continue;
		}
		if (!row[2]){
			ERROR("No short name found for row %s", row[0]);
			continue;
		}
		if (!row[4]){
			ERROR("No secret found for row %s", row[0]);
			continue;
		}

		if (((inst->driver->sql_num_fields)(handle, inst->config) > 5) && (row[5] != NULL) && *row[5]) {
			server = row[5];
		}

		DEBUG("Adding client %s (%s) to %s clients list",
		      row[1], row[2], server ? server : "global");

		/* FIXME: We should really pass a proper ctx */
		c = client_afrom_query(NULL,
				      row[1],	/* identifier */
				      row[4],	/* secret */
				      row[2],	/* shortname */
				      row[3],	/* type */
				      server,	/* server */
				      false);	/* require message authenticator */
		if (!c) {
			continue;
		}

		if (!client_add(NULL, c)) {
			WARN("Failed to add client, possible duplicate?");

			client_free(c);
			ret = -1;
			break;
		}

		DEBUG("Client \"%s\" (%s) added", c->longname, c->shortname);
	}

	(inst->driver->sql_finish_select_query)(handle, inst->config);
	fr_connection_release(inst->pool, NULL, handle);

	return ret;
}
#endif

/** xlat escape function for drivers which do not provide their own
 *
 */
static size_t sql_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, void *arg)
{
	rlm_sql_handle_t	*handle = arg;
	rlm_sql_t const		*inst = handle->inst;
	size_t			len = 0;

	while (in[0]) {
		size_t utf8_len;

		/*
		 *	Allow all multi-byte UTF8 characters.
		 */
		utf8_len = fr_utf8_char((uint8_t const *) in, -1);
		if (utf8_len > 1) {
			if (outlen <= utf8_len) break;

			memcpy(out, in, utf8_len);
			in += utf8_len;
			out += utf8_len;

			outlen -= utf8_len;
			len += utf8_len;
			continue;
		}

		/*
		 *	Because we register our own escape function
		 *	we're now responsible for escaping all special
		 *	chars in an xlat expansion or attribute value.
		 */
		switch (in[0]) {
		case '\n':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 'n';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;

		case '\r':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 'r';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;

		case '\t':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 't';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;
		}

		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr(inst->config->allowed_chars, *in) == NULL) {
			/*
			 *	Only 3 or less bytes available.
			 */
			if (outlen <= 3) {
				break;
			}

			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			in++;
			out += 3;
			outlen -= 3;
			len += 3;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
		 */
		*out = *in;
		out++;
		in++;
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

/** Passed as the escape function to map_proc and sql xlat methods
 *
 * The variant reserves a connection for the escape functions to use, and releases it after
 * escaping is complete.
 */
static size_t sql_escape_for_xlat_func(REQUEST *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			ret;
	rlm_sql_t		*inst = talloc_get_type_abort(arg, rlm_sql_t);
	rlm_sql_handle_t	*handle;

	handle = fr_connection_get(inst->pool, request);
	if (!handle) {
		out[0] = '\0';
		return 0;
	}
	ret = inst->sql_escape_func(request, out, outlen, in, handle);
	fr_connection_release(inst->pool, request, handle);

	return ret;
}

/*
 *	Set the SQL user name.
 *
 *	We don't call the escape function here. The resulting string
 *	will be escaped later in the queries xlat so we don't need to
 *	escape it twice. (it will make things wrong if we have an
 *	escape candidate character in the username)
 */
int sql_set_user(rlm_sql_t const *inst, REQUEST *request, char const *username)
{
	char *expanded = NULL;
	VALUE_PAIR *vp = NULL;
	char const *sqluser;
	ssize_t len;

	rad_assert(request->packet != NULL);

	if (username != NULL) {
		sqluser = username;
	} else if (inst->config->query_user[0] != '\0') {
		sqluser = inst->config->query_user;
	} else {
		return 0;
	}

	len = xlat_aeval(request, &expanded, request, sqluser, NULL, NULL);
	if (len < 0) {
		return -1;
	}

	vp = fr_pair_afrom_da(request->packet, inst->sql_user);
	if (!vp) {
		talloc_free(expanded);
		return -1;
	}

	fr_pair_value_strsteal(vp, expanded);
	RDEBUG2("SQL-User-Name set to '%s'", vp->vp_strvalue);
	vp->op = T_OP_SET;

	/*
	 *	Delete any existing SQL-User-Name, and replace it with ours.
	 */
	fr_pair_delete_by_num(&request->packet->vps, vp->da->vendor, vp->da->attr, TAG_ANY);
	fr_pair_add(&request->packet->vps, vp);

	return 0;
}

/*
 *	Do a set/unset user, so it's a bit clearer what's going on.
 */
#define sql_unset_user(_i, _r) fr_pair_delete_by_num(&_r->packet->vps, _i->sql_user->vendor, _i->sql_user->attr, TAG_ANY)

#if 0
static int sql_get_grouplist(rlm_sql_t const *inst, rlm_sql_handle_t **handle, REQUEST *request,
			     rlm_sql_grouplist_t **phead)
{
	char    *expanded = NULL;
	int     num_groups = 0;
	rlm_sql_row_t row;
	rlm_sql_grouplist_t *entry;
	int ret;

	/* NOTE: sql_set_user should have been run before calling this function */

	entry = *phead = NULL;

	if (!inst->config->groupmemb_query || !*inst->config->groupmemb_query) return 0;
	if (xlat_aeval(request, &expanded, request, inst->config->groupmemb_query,
			 inst->sql_escape_func, *handle) < 0) return -1;

	ret = rlm_sql_select_query(inst, request, handle, expanded);
	talloc_free(expanded);
	if (ret != RLM_SQL_OK) return -1;

	while (rlm_sql_fetch_row(&row, inst, request, handle) == RLM_SQL_OK) {
		if (!row[0]){
			RDEBUG("row[0] returned NULL");
			(inst->driver->sql_finish_select_query)(*handle, inst->config);
			talloc_free(entry);
			return -1;
		}

		if (!*phead) {
			*phead = talloc_zero(*handle, rlm_sql_grouplist_t);
			entry = *phead;
		} else {
			entry->next = talloc_zero(*phead, rlm_sql_grouplist_t);
			entry = entry->next;
		}
		entry->next = NULL;
		entry->name = talloc_typed_strdup(entry, row[0]);

		num_groups++;
	}

	(inst->driver->sql_finish_select_query)(*handle, inst->config);

	return num_groups;
}
#endif

static rlm_rcode_t sql_get_grouplist_resume(REQUEST *request, void *instance, void *thread, void *ctx);

/*
 * Get group list
 * Yield if SQL driver supports async queries.
 */
static rlm_rcode_t sql_get_grouplist(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_query_ctx_t *select_query_ctx;

	select_query_ctx = talloc_zero(ctx, rlm_sql_query_ctx_t);
	sql_process_group_ctx->sql_query_ctx = select_query_ctx;


	/* NOTE: sql_set_user should have been run before calling this function */

	if (!inst->config->groupmemb_query || !*inst->config->groupmemb_query) {
		sql_process_group_ctx->sql_getvpdata_ctx->rows = 0;
		return RLM_MODULE_OK;
	}
	if (xlat_aeval(request, &sql_process_group_ctx->sql_getvpdata_ctx->query, request, inst->config->groupmemb_query,
			 inst->sql_escape_func, *sql_process_group_ctx->sql_getvpdata_ctx->handle) < 0) {
		sql_process_group_ctx->rcode = RLM_MODULE_FAIL;
		return RLM_MODULE_OK;
	}

	/*
	 * Update handle & query for select_query context
	 */
	select_query_ctx->handle = sql_process_group_ctx->sql_getvpdata_ctx->handle;
	select_query_ctx->query = sql_process_group_ctx->sql_getvpdata_ctx->query;

	return unlang_two_step_process(request, rlm_sql_select_query, select_query_ctx, sql_get_grouplist_resume, ctx);
}

static rlm_rcode_t sql_get_grouplist_resume(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	rlm_sql_row_t row;
	rlm_sql_grouplist_t *entry;

	entry = sql_process_group_ctx->group_list = NULL;
	sql_process_group_ctx->sql_getvpdata_ctx->rows = 0;

	talloc_free(sql_process_group_ctx->sql_getvpdata_ctx->query);

	if (sql_process_group_ctx->sql_query_ctx->rcode == RLM_SQL_OK) {
		sql_process_group_ctx->rcode = RLM_MODULE_OK;

		while (rlm_sql_fetch_row(&row, inst, request, sql_process_group_ctx->sql_getvpdata_ctx->handle) == RLM_SQL_OK) {
			if (!row[0]){
				RDEBUG("row[0] returned NULL");
				(inst->driver->sql_finish_select_query)(*sql_process_group_ctx->sql_getvpdata_ctx->handle, inst->config);
				talloc_free(entry);
				sql_process_group_ctx->rcode = RLM_MODULE_FAIL;
				goto finish;
			}

			if (!sql_process_group_ctx->group_list) {
				sql_process_group_ctx->group_list = talloc_zero(*sql_process_group_ctx->sql_getvpdata_ctx->handle, rlm_sql_grouplist_t);
				entry = sql_process_group_ctx->group_list;
			} else {
				entry->next = talloc_zero(sql_process_group_ctx->group_list, rlm_sql_grouplist_t);
				entry = entry->next;
			}
			entry->next = NULL;
			entry->name = talloc_typed_strdup(entry, row[0]);

			sql_process_group_ctx->sql_getvpdata_ctx->rows++;
		}

		(inst->driver->sql_finish_select_query)(*sql_process_group_ctx->sql_getvpdata_ctx->handle, inst->config);
	} else {
		/* Propagate error */
		sql_process_group_ctx->rcode = RLM_MODULE_FAIL;
	}

finish:
	return RLM_MODULE_OK;
}

/*
 * sql groupcmp function. That way we can do group comparisons (in the users file for example)
 * with the group memberships reciding in sql
 * The group membership query should only return one element which is the username. The returned
 * username will then be checked with the passed check string.
 */
static int sql_groupcmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *request_vp,
			VALUE_PAIR *check, UNUSED VALUE_PAIR *check_pairs,
			UNUSED VALUE_PAIR **reply_pairs) CC_HINT(nonnull (1, 2, 4));

static int sql_groupcmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *request_vp,
			VALUE_PAIR *check, UNUSED VALUE_PAIR *check_pairs,
			UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_sql_handle_t	*handle;
	rlm_sql_t const		*inst = instance;
	rlm_sql_grouplist_t	*head, *entry;

#if 0
	/*
	 *	No group queries, don't do group comparisons.
	 */
	if (!inst->config->groupmemb_query) {
		RWARN("Cannot do group comparison when group_membership_query is not set");
		return 1;
	}

	RDEBUG("sql_groupcmp");

	if (check->vp_length == 0){
		RDEBUG("sql_groupcmp: Illegal group name");
		return 1;
	}

	/*
	 *	Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, NULL) < 0)
		return 1;

	/*
	 *	Get a socket for this lookup
	 */
	handle = fr_connection_get(inst->pool, request);
	if (!handle) {
		return 1;
	}

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (sql_get_grouplist(inst, &handle, request, &head) < 0) {
		REDEBUG("Error getting group membership");
		fr_connection_release(inst->pool, request, handle);
		return 1;
	}

	for (entry = head; entry != NULL; entry = entry->next) {
		if (strcmp(entry->name, check->vp_strvalue) == 0){
			RDEBUG("sql_groupcmp finished: User is a member of group %s",
			       check->vp_strvalue);
			talloc_free(head);
			fr_connection_release(inst->pool, request, handle);
			return 0;
		}
	}

	/* Free the grouplist */
	talloc_free(head);
	fr_connection_release(inst->pool, request, handle);
#endif

	RDEBUG("sql_groupcmp finished: User is NOT a member of group %s", check->vp_strvalue);

	return 1;
}

static rlm_rcode_t rlm_sql_process_groups_init(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);
static rlm_rcode_t rlm_sql_process_groups_loop(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);
static rlm_rcode_t rlm_sql_process_groups_do_nothing(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);
static rlm_rcode_t rlm_sql_process_groups_finish(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);

static rlm_rcode_t rlm_sql_process_groups(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	rad_assert(ctx);

	rad_assert(request->packet != NULL);

	if (!inst->config->groupmemb_query) {
		RWARN("Cannot do check groups when group_membership_query is not set");

		return rlm_sql_process_groups_do_nothing(request, instance, thread, ctx);
	}

	/*
	 *	Get the list of groups this user is a member of
	 */
	return unlang_two_step_process(request, sql_get_grouplist, ctx, rlm_sql_process_groups_init, ctx);
}

static rlm_rcode_t rlm_sql_process_groups_do_nothing(UNUSED REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);

	sql_process_group_ctx->do_fall_through = FALL_THROUGH_DEFAULT;

	/*
	 *	Didn't add group attributes or allocate
	 *	memory, so don't do anything else.
	 */
	sql_process_group_ctx->rcode = RLM_MODULE_NOTFOUND;
	return RLM_MODULE_OK;
}

static rlm_rcode_t rlm_sql_process_groups_init(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);

	sql_process_group_ctx->rcode = RLM_MODULE_NOOP;

	sql_process_group_ctx->head = sql_process_group_ctx->group_list;

	if (sql_process_group_ctx->sql_query_ctx->rcode != RLM_SQL_OK) {
		REDEBUG("Error retrieving group list");

		sql_process_group_ctx->rcode = RLM_MODULE_FAIL;
		return RLM_MODULE_OK;
	}
	if (sql_process_group_ctx->sql_getvpdata_ctx->rows == 0) {
		RDEBUG2("User not found in any groups");

		return rlm_sql_process_groups_do_nothing(request, instance, thread, ctx);
	}
	rad_assert(sql_process_group_ctx->head);

	RDEBUG2("User found in the group table");

	/*
	 *	Add the Sql-Group attribute to the request list so we know
	 *	which group we're retrieving attributes for
	 */
	sql_process_group_ctx->sql_group = pair_make_request(inst->group_da->name, NULL, T_OP_EQ);
	if (!sql_process_group_ctx->sql_group) {
		REDEBUG("Error creating %s attribute", inst->group_da->name);
		sql_process_group_ctx->rcode = RLM_MODULE_FAIL;

		return rlm_sql_process_groups_finish(request, instance, thread, ctx);
	}

	sql_process_group_ctx->entry = sql_process_group_ctx->head;

	sql_process_group_ctx->next_step = PROCESS_GROUP_PRE_CHECK;

	return rlm_sql_process_groups_loop(request, instance, thread, ctx);
}

static rlm_rcode_t rlm_sql_process_groups_loop(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);

	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	do {
	next:
		switch (sql_process_group_ctx->next_step) {
		case PROCESS_GROUP_PRE_CHECK:
			rad_assert(sql_process_group_ctx->entry != NULL);
			fr_pair_value_strcpy(sql_process_group_ctx->sql_group, sql_process_group_ctx->entry->name);

			/*
			 *	No group check query, process group replies
			 */
			if (!inst->config->authorize_group_check_query) {
				sql_process_group_ctx->next_step = PROCESS_GROUP_PRE_REPLY;
				goto next;
			}

			/*
			 *	Expand the group query
			 */
			if (xlat_aeval(request, &sql_process_group_ctx->sql_getvpdata_ctx->query, request,
				       inst->config->authorize_group_check_query,
				       inst->sql_escape_func, *sql_process_group_ctx->sql_getvpdata_ctx->handle) < 0) {
				REDEBUG("Error generating query");
				sql_process_group_ctx->rcode = RLM_MODULE_FAIL;

				return rlm_sql_process_groups_finish(request, instance, thread, ctx);
			}

			sql_process_group_ctx->sql_getvpdata_ctx->talloc_ctx = request;
			sql_process_group_ctx->next_step = PROCESS_GROUP_POST_CHECK;

			/*
			 *	Retrieve the group check attributes.
			 */
			return unlang_two_step_process(request, sql_getvpdata, sql_process_group_ctx->sql_getvpdata_ctx,
						       rlm_sql_process_groups_loop, sql_process_group_ctx);

		case PROCESS_GROUP_POST_CHECK:
			TALLOC_FREE(sql_process_group_ctx->sql_getvpdata_ctx->query);

			if (sql_process_group_ctx->sql_getvpdata_ctx->rcode != RLM_SQL_OK) {
				REDEBUG("Error retrieving check pairs for group %s", sql_process_group_ctx->entry->name);
				sql_process_group_ctx->rcode = RLM_MODULE_FAIL;

				return rlm_sql_process_groups_finish(request, instance, thread, ctx);
			}

			/*
			 *	If we got check rows we need to process them before we decide to
			 *	process the reply rows.
			 */
			if ((sql_process_group_ctx->sql_getvpdata_ctx->rows > 0) &&
			    (paircompare(request, request->packet->vps, sql_process_group_ctx->sql_getvpdata_ctx->attr,
			    		 &request->reply->vps) != 0)) {
				fr_pair_list_free(&sql_process_group_ctx->sql_getvpdata_ctx->attr);
				break;
			}

			RDEBUG2("Group \"%s\": Conditional check items matched", sql_process_group_ctx->entry->name);
			sql_process_group_ctx->rcode = RLM_MODULE_OK;

			RDEBUG2("Group \"%s\": Merging assignment check items", sql_process_group_ctx->entry->name);
			RINDENT();
			for (vp = fr_pair_cursor_init(&cursor, &sql_process_group_ctx->sql_getvpdata_ctx->attr);
				 vp;
				 vp = fr_pair_cursor_next(&cursor)) {
				if (!fr_assignment_op[vp->op]) continue;

				rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
			}
			REXDENT();
			radius_pairmove(request, &request->control, sql_process_group_ctx->sql_getvpdata_ctx->attr, true);
			sql_process_group_ctx->sql_getvpdata_ctx->attr = NULL;
			sql_process_group_ctx->next_step = PROCESS_GROUP_PRE_REPLY;

			/* FALL-THROUGH */

		case PROCESS_GROUP_PRE_REPLY:
			/*
			 *	If there's no reply query configured, then we assume
			 *	FALL_THROUGH_NO, which is the same as the users file if you
			 *	had no reply attributes.
			 */
			if (!inst->config->authorize_group_reply_query) {
				sql_process_group_ctx->do_fall_through = FALL_THROUGH_DEFAULT;
				break;
			}

			/*
			 *	Now get the reply pairs since the paircompare matched
			 */
			if (xlat_aeval(request, &sql_process_group_ctx->sql_getvpdata_ctx->query, request,
				       inst->config->authorize_group_reply_query,
				       inst->sql_escape_func, *sql_process_group_ctx->sql_getvpdata_ctx->handle) < 0) {
				REDEBUG("Error generating query");
				sql_process_group_ctx->rcode = RLM_MODULE_FAIL;

				return rlm_sql_process_groups_finish(request, instance, thread, ctx);
			}

			sql_process_group_ctx->sql_getvpdata_ctx->talloc_ctx = request->reply;
			sql_process_group_ctx->next_step = PROCESS_GROUP_POST_REPLY;

			return unlang_two_step_process(request, sql_getvpdata, sql_process_group_ctx->sql_getvpdata_ctx,
						       rlm_sql_process_groups_loop, sql_process_group_ctx);

		case PROCESS_GROUP_POST_REPLY:
			TALLOC_FREE(sql_process_group_ctx->sql_getvpdata_ctx->query);



			if (sql_process_group_ctx->sql_getvpdata_ctx->rcode != RLM_SQL_OK) {
				REDEBUG("Error retrieving reply pairs for group %s", sql_process_group_ctx->entry->name);
				sql_process_group_ctx->rcode = RLM_MODULE_FAIL;

				return rlm_sql_process_groups_finish(request, instance, thread, ctx);
			}

			if (sql_process_group_ctx->sql_getvpdata_ctx->rows == 0) {
				sql_process_group_ctx->do_fall_through = FALL_THROUGH_DEFAULT;
				continue;
			}

			rad_assert(sql_process_group_ctx->sql_getvpdata_ctx->attr != NULL); /* coverity, among others */
			sql_process_group_ctx->do_fall_through = fall_through(sql_process_group_ctx->sql_getvpdata_ctx->attr);

			RDEBUG2("Group \"%s\": Merging reply items", sql_process_group_ctx->entry->name);
			sql_process_group_ctx->rcode = RLM_MODULE_OK;

			rdebug_pair_list(L_DBG_LVL_2, request, sql_process_group_ctx->sql_getvpdata_ctx->attr, NULL);

			radius_pairmove(request, &request->reply->vps, sql_process_group_ctx->sql_getvpdata_ctx->attr, true);
			sql_process_group_ctx->sql_getvpdata_ctx->attr = NULL;

			break;

		default:
			REDEBUG("Invalid next_step while processing groups: %d", sql_process_group_ctx->next_step);
			break;
		}

		/*
		 *	Continue with next group
		 */
		sql_process_group_ctx->entry = sql_process_group_ctx->entry->next;
		sql_process_group_ctx->next_step = PROCESS_GROUP_PRE_CHECK;
	} while (sql_process_group_ctx->entry != NULL && (sql_process_group_ctx->do_fall_through == FALL_THROUGH_YES));

	return rlm_sql_process_groups_finish(request, instance, thread, ctx);
}

static rlm_rcode_t rlm_sql_process_groups_finish(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_process_groups_ctx_t *sql_process_group_ctx = talloc_get_type_abort(ctx, rlm_sql_process_groups_ctx_t);

	talloc_free(sql_process_group_ctx->head);
	fr_pair_delete_by_num(&request->packet->vps, 0, inst->group_da->attr, TAG_ANY);

	return RLM_MODULE_OK;
}

static int mod_detach(void *instance)
{
	rlm_sql_t	*inst = instance;

	if (inst->pool) fr_connection_pool_free(inst->pool);

	/*
	 *	We need to explicitly free all children, so if the driver
	 *	parented any memory off the instance, their destructors
	 *	run before we unload the bytecode for them.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(inst);

	/*
	 *	Decrements the reference count. The driver object won't be unloaded
	 *	until all instances of rlm_sql that use it have been destroyed.
	 */
	talloc_decrease_ref_count(inst->driver_handle);

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_sql_t	*inst = instance;
	CONF_SECTION	*driver_cs;
	char const	*name;

	/*
	 *	Hack...
	 */
	inst->config = &inst->myconfig;
	inst->cs = conf;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	/*
	 *	Accomodate full and partial driver names
	 */
	name = strrchr(inst->config->sql_driver_name, '_');
	if (!name) {
		name = inst->config->sql_driver_name;
	} else {
		name++;
	}

	/*
	 *	Get the module's subsection or allocate one
	 */
	driver_cs = cf_section_sub_find(conf, name);
	if (!driver_cs) {
		driver_cs = cf_section_alloc(conf, name, NULL);
		if (!driver_cs) return -1;
	}

	/*
	 *	Load the driver
	 */
	inst->driver_handle = dl_module(driver_cs, dl_module_by_symbol(&rlm_sql), name, DL_TYPE_SUBMODULE);
	if (!inst->driver_handle) return -1;
	inst->driver = (rlm_sql_driver_t const *)inst->driver_handle->common;

	/*
	 *	Pre-allocate the driver's instance data,
	 *	and parse the driver's configuration.
	 */
	if (dl_module_instance_data_alloc(&inst->driver_inst, inst, inst->driver_handle, driver_cs) < 0) {
	error:
		talloc_decrease_ref_count(inst->driver_handle);
		return -1;
	}

	rad_assert(!inst->driver_handle->common->inst_size || inst->driver_inst);

	/*
	 *	Call the driver's instantiate function (if set)
	 */
	if (inst->driver->mod_instantiate && (inst->driver->mod_instantiate(inst->config,
									    inst->driver_inst,
									    driver_cs)) < 0) return -1;
#ifndef NDEBUG
	if (inst->driver_inst) module_instance_read_only(inst->driver_inst, inst->driver->name);
#endif

	/*
	 *	@fixme Inst should be passed to all driver callbacks
	 *	instead of being stored here.
	 */
	inst->config->driver = inst->driver_inst;

	/*
	 *	Register the group comparison attribute
	 */
	if (inst->config->groupmemb_query) {
		char buffer[256];

		char const *group_attribute;

		if (inst->config->group_attribute) {
			group_attribute = inst->config->group_attribute;
		} else if (cf_section_name2(conf)) {
			snprintf(buffer, sizeof(buffer), "%s-SQL-Group", inst->name);
			group_attribute = buffer;
		} else {
			group_attribute = "SQL-Group";
		}

		/*
		 *	Checks if attribute already exists.
		 */
		if (paircompare_register_byname(group_attribute, fr_dict_attr_by_num(NULL, 0, PW_USER_NAME),
						false, sql_groupcmp, inst) < 0) {
			ERROR("Failed registering group comparison: %s", fr_strerror());
			goto error;
		}

		inst->group_da = fr_dict_attr_by_name(fr_dict_internal, group_attribute);
		if (!inst->group_da) {
			ERROR("Failed resolving group attribute \"%s\"", group_attribute);
			goto error;
		}
	}

#if 0
	/*
	 *	Register the SQL xlat function
	 */
	xlat_register(inst, inst->name, sql_xlat, sql_escape_for_xlat_func, NULL, 0, 0);

	/*
	 *	Register the SQL map processor function
	 */
	if (inst->driver->sql_fields) map_proc_register(inst, inst->name, mod_map_proc, sql_map_verify, 0);
#endif

	return 0;
}


static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_sql_t *inst = instance;

	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->config->sql_driver_name, "rlm_sql_", 8) != 0) {
		ERROR("\"%s\" is NOT an SQL driver!", inst->config->sql_driver_name);
		return -1;
	}

	/*
	 *	We need authorize_group_check_query or authorize_group_reply_query
	 *	if group_membership_query is set.
	 *
	 *	Or we need group_membership_query if authorize_group_check_query or
	 *	authorize_group_reply_query is set.
	 */
	if (!inst->config->groupmemb_query) {
		if (inst->config->authorize_group_check_query) {
			WARN("Ignoring authorize_group_reply_query as group_membership_query is not configured");
		}

		if (inst->config->authorize_group_reply_query) {
			WARN("Ignoring authorize_group_check_query as group_membership_query is not configured");
		}

		if (!inst->config->read_groups) {
			WARN("Ignoring read_groups as group_membership_query is not configured");
			inst->config->read_groups = false;
		}
	} /* allow the group check / reply queries to be NULL */

	/*
	 *	This will always exist, as cf_section_parse_init()
	 *	will create it if it doesn't exist.  However, the
	 *	"reference" config item won't exist in an auto-created
	 *	configuration.  So if that doesn't exist, we ignore
	 *	the whole subsection.
	 */
	inst->config->accounting.cs = cf_section_sub_find(conf, "accounting");
	inst->config->accounting.reference_cp = (cf_pair_find(inst->config->accounting.cs, "reference") != NULL);

	inst->config->postauth.cs = cf_section_sub_find(conf, "post-auth");
	inst->config->postauth.reference_cp = (cf_pair_find(inst->config->postauth.cs, "reference") != NULL);

	/*
	 *	Cache the SQL-User-Name fr_dict_attr_t, so we can be slightly
	 *	more efficient about creating SQL-User-Name attributes.
	 */
	inst->sql_user = fr_dict_attr_by_name(NULL, "SQL-User-Name");
	if (!inst->sql_user) {
		return -1;
	}

	/*
	 *	Export these methods, too.  This avoids RTDL_GLOBAL.
	 */
	inst->sql_set_user		= sql_set_user;
	inst->sql_query			= rlm_sql_query;
	inst->sql_select_query		= rlm_sql_select_query;
	inst->sql_fetch_row		= rlm_sql_fetch_row;

	/*
	 *	Either use the module specific escape function
	 *	or our default one.
	 */
	inst->sql_escape_func = inst->driver->sql_escape_func ?
				inst->driver->sql_escape_func :
				sql_escape_func;

	inst->ef = module_exfile_init(inst, conf, 256, 30, true, NULL, NULL);
	if (!inst->ef) {
		cf_log_err_cs(conf, "Failed creating log file context");
		return -1;
	}

#if 0
	/*
	 *	Initialise the connection pool for this instance
	 */
	INFO("Attempting to connect to database \"%s\"", inst->config->sql_db);

	if (inst->config->do_clients) {
		if (generate_sql_clients(inst) == -1){
			ERROR("Failed to load clients from SQL");
			return -1;
		}
	}
#endif

	return RLM_MODULE_OK;
}

/** Create a thread specific pool
 *
 * Each request uses its own connection.
 * Each thread therefore needs a pool of connections to handle multiple requests in parallel
 *
 * @param[in] conf		section containing the configuration of this module instance.
 * @param[in] instance	of rlm_sql_t.
 * @param[in] el		The event list serviced by this thread.
 * @param[in] thread	specific data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(CONF_SECTION const *conf, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_sql_t			*inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_thread_t	*t = talloc_get_type_abort(thread, rlm_sql_thread_t);
	CONF_SECTION		*my_conf;

	t->el = el;
	t->inst = instance;

	/*
	 *	Temporary hack to make config parsing
	 *	thread safe.
	 */
	my_conf = cf_section_dup(NULL, conf, cf_section_name1(conf), cf_section_name2(conf), true);
	t->pool = fr_connection_pool_init(NULL, my_conf, t, mod_conn_create, NULL, inst->name);
	talloc_free(my_conf);

	if (!t->pool) {
		ERROR("Pool instantiation failed");
		return -1;
	}

	return 0;
}

static rlm_rcode_t mod_authorize_release(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_error(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_pre_check(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_post_check(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_pre_reply(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_post_reply(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_pre_group(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_post_group(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_pre_profile(REQUEST *request, void *instance, void *thread, void *ctx);
static rlm_rcode_t mod_authorize_post_profile(REQUEST *request, void *instance, void *thread, void *ctx);

static rlm_rcode_t mod_authorize(void *instance, void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authorize(void *instance, void *thread, REQUEST *request)
{
	rlm_sql_thread_t *t = talloc_get_type_abort(thread, rlm_sql_thread_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_zero(request, rlm_sql_authorize_ctx_t);

	/*
	 * Initialise authorize thread context
	 */
	authorize_ctx->rcode = RLM_MODULE_NOOP;
	authorize_ctx->do_fall_through = FALL_THROUGH_DEFAULT;

	rad_assert(request->packet != NULL);
	rad_assert(request->reply != NULL);

	if (!inst->config->authorize_check_query && !inst->config->authorize_reply_query &&
	    !inst->config->read_groups && !inst->config->read_profiles) {
		RWDEBUG("No authorization checks configured, returning noop");

		return RLM_MODULE_NOOP;
	}

	/*
	 *	Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Reserve a socket
	 *
	 *	After this point use goto error or goto release to cleanup socket temporary pairlists and
	 *	temporary attributes.
	 */
	authorize_ctx->handle = fr_connection_get(t->pool, request);
	if (!authorize_ctx->handle) {
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, authorize_ctx);
	}

	authorize_ctx->sql_getvpdata_ctx = talloc_zero(authorize_ctx, rlm_sql_getvpdata_ctx_t);
	authorize_ctx->sql_getvpdata_ctx->handle = &authorize_ctx->handle;

	return mod_authorize_pre_check(request, instance, thread, authorize_ctx);
}

static rlm_rcode_t mod_authorize_pre_check(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	/*
	 * If check query not defined, proceed to get replies
	 */
	if (!inst->config->authorize_check_query) {
		return mod_authorize_pre_reply(request, instance, thread, ctx);
	}

	/*
	 *	Query the check table to find any conditions associated with this user/realm/whatever...
	 */
	if (xlat_aeval(request, &authorize_ctx->sql_getvpdata_ctx->query, request, inst->config->authorize_check_query,
			 inst->sql_escape_func, authorize_ctx->handle) < 0) {
		REDEBUG("Failed generating query");
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, ctx);
	}

	authorize_ctx->sql_getvpdata_ctx->talloc_ctx = request;

	return unlang_two_step_process(request, sql_getvpdata, authorize_ctx->sql_getvpdata_ctx, mod_authorize_post_check, authorize_ctx);
}

static rlm_rcode_t mod_authorize_post_check(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);

	TALLOC_FREE(authorize_ctx->sql_getvpdata_ctx->query);
	if (authorize_ctx->sql_getvpdata_ctx->rcode != RLM_SQL_OK) {
		REDEBUG("Failed getting check attributes");
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, ctx);
	}

	if (authorize_ctx->sql_getvpdata_ctx->rows == 0)
		return mod_authorize_pre_group(request, instance, thread, ctx);	/* Don't need to free VPs we don't have */

	/*
	 *	Only do this if *some* check pairs were returned
	 */
	RDEBUG2("User found in radcheck table");
	authorize_ctx->user_found = true;
	if (paircompare(request, request->packet->vps, authorize_ctx->sql_getvpdata_ctx->attr, &request->reply->vps) != 0) {
		fr_pair_list_free(&authorize_ctx->sql_getvpdata_ctx->attr);
		authorize_ctx->sql_getvpdata_ctx->attr = NULL;

		return mod_authorize_pre_group(request, instance, thread, ctx);
	}

	RDEBUG2("Conditional check items matched, merging assignment check items");
	RINDENT();
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	for (vp = fr_pair_cursor_init(&cursor, &authorize_ctx->sql_getvpdata_ctx->attr);
		 vp;
		 vp = fr_pair_cursor_next(&cursor)) {
		if (!fr_assignment_op[vp->op]) continue;

		rdebug_pair(2, request, vp, NULL);
	}
	REXDENT();
	radius_pairmove(request, &request->control, authorize_ctx->sql_getvpdata_ctx->attr, true);

	authorize_ctx->rcode = RLM_MODULE_OK;
	authorize_ctx->sql_getvpdata_ctx->attr = NULL;

	return mod_authorize_pre_reply(request, instance, thread, ctx);
}

static rlm_rcode_t mod_authorize_pre_reply(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	/*
	 * If reply query not defined, proceed to process groups
	 */
	if (!inst->config->authorize_reply_query) {
		return mod_authorize_pre_group(request, instance, thread, ctx);
	}

	/*
	 *	Now get the reply pairs since the paircompare matched
	 */
	if (xlat_aeval(request, &authorize_ctx->sql_getvpdata_ctx->query, request, inst->config->authorize_reply_query,
			 inst->sql_escape_func, authorize_ctx->handle) < 0) {
		REDEBUG("Error generating query");
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, ctx);
	}

	authorize_ctx->sql_getvpdata_ctx->talloc_ctx = request->reply;
	return unlang_two_step_process(request, sql_getvpdata, authorize_ctx->sql_getvpdata_ctx,
				mod_authorize_post_reply, authorize_ctx);
}

static rlm_rcode_t mod_authorize_post_reply(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);

	TALLOC_FREE(authorize_ctx->sql_getvpdata_ctx->query);
	if (authorize_ctx->sql_getvpdata_ctx->rcode != RLM_SQL_OK) {
		REDEBUG("SQL query error getting reply attributes");
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, ctx);
	}

	if (authorize_ctx->sql_getvpdata_ctx->rows == 0)
		return mod_authorize_pre_group(request, instance, thread, ctx);

	authorize_ctx->do_fall_through = fall_through(authorize_ctx->sql_getvpdata_ctx->attr);

	RDEBUG2("User found in radreply table, merging reply items");
	authorize_ctx->user_found = true;

	rdebug_pair_list(L_DBG_LVL_2, request, authorize_ctx->sql_getvpdata_ctx->attr, NULL);

	radius_pairmove(request, &request->reply->vps, authorize_ctx->sql_getvpdata_ctx->attr, true);

	authorize_ctx->rcode = RLM_MODULE_OK;
	authorize_ctx->sql_getvpdata_ctx->attr = NULL;

	return mod_authorize_pre_group(request, instance, thread, ctx);
}

static rlm_rcode_t mod_authorize_pre_group(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	/*
	 *	Neither group checks or profiles will work without
	 *	a group membership query.
	 */
	if (!inst->config->groupmemb_query)
		return mod_authorize_release(request, instance, thread, ctx);

	/*
	 * If we shouldn't get group attributes, proceed to process profiles
	 */
	 if (!((authorize_ctx->do_fall_through == FALL_THROUGH_YES) ||
	    (inst->config->read_groups && (authorize_ctx->do_fall_through == FALL_THROUGH_DEFAULT)))) {

		return mod_authorize_pre_profile(request, instance, thread, ctx);
	}

	RDEBUG3("... falling-through to group processing");

	/*
	 * Copy DB handle to group context
	 */
	if (!authorize_ctx->sql_process_group_ctx) {
		authorize_ctx->sql_process_group_ctx = talloc_zero(authorize_ctx, rlm_sql_process_groups_ctx_t);
		authorize_ctx->sql_process_group_ctx->sql_getvpdata_ctx = talloc_zero(authorize_ctx, rlm_sql_getvpdata_ctx_t);
	}
	authorize_ctx->sql_process_group_ctx->sql_getvpdata_ctx->handle = authorize_ctx->sql_getvpdata_ctx->handle;

	return unlang_two_step_process(request, rlm_sql_process_groups, authorize_ctx->sql_process_group_ctx,
				mod_authorize_post_group, authorize_ctx);
}

static rlm_rcode_t mod_authorize_post_group(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);

	switch (authorize_ctx->sql_process_group_ctx->rcode) {
	/*
	 *	Nothing bad happened, continue...
	 */
	case RLM_MODULE_UPDATED:
		authorize_ctx->rcode = RLM_MODULE_UPDATED;
		/* FALL-THROUGH */
	case RLM_MODULE_OK:
		if (authorize_ctx->rcode != RLM_MODULE_UPDATED) {
			authorize_ctx->rcode = RLM_MODULE_OK;
		}
		/* FALL-THROUGH */
	case RLM_MODULE_NOOP:
		authorize_ctx->user_found = true;
		break;

	case RLM_MODULE_NOTFOUND:
		break;

	default:
		authorize_ctx->rcode = authorize_ctx->sql_process_group_ctx->rcode;

		return mod_authorize_release(request, instance, thread, ctx);
	}

	return mod_authorize_pre_profile(request, instance, thread, ctx);
}

static rlm_rcode_t mod_authorize_pre_profile(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	/*
	 *	Repeat the group processing with the default profile or User-Profile
	 */
	 if (!((authorize_ctx->do_fall_through == FALL_THROUGH_YES) ||
	    (inst->config->read_profiles && (authorize_ctx->do_fall_through == FALL_THROUGH_DEFAULT)))) {

		return mod_authorize_release(request, instance, thread, ctx);
	}

	/*
	 *  Check for a default_profile or for a User-Profile.
	 */
	RDEBUG3("... falling-through to profile processing");
	authorize_ctx->user_profile = fr_pair_find_by_num(request->control, 0, PW_USER_PROFILE, TAG_ANY);

	char const *profile = authorize_ctx->user_profile ?
			      authorize_ctx->user_profile->vp_strvalue :
			      inst->config->default_profile;

	if (!profile || !*profile)
		return mod_authorize_release(request, instance, thread, ctx);

	RDEBUG2("Checking profile %s", profile);

	if (sql_set_user(inst, request, profile) < 0) {
		REDEBUG("Error setting profile");
		authorize_ctx->rcode = RLM_MODULE_FAIL;

		return mod_authorize_error(request, instance, thread, ctx);
	}

	/*
	 * Copy DB handle to group context
	 */
	if (!authorize_ctx->sql_process_group_ctx) {
 		authorize_ctx->sql_process_group_ctx = talloc_zero(authorize_ctx, rlm_sql_process_groups_ctx_t);
 		authorize_ctx->sql_process_group_ctx->sql_getvpdata_ctx = talloc_zero(authorize_ctx, rlm_sql_getvpdata_ctx_t);
 	}
	authorize_ctx->sql_process_group_ctx->sql_getvpdata_ctx->handle = authorize_ctx->sql_getvpdata_ctx->handle;

	return unlang_two_step_process(request, rlm_sql_process_groups, authorize_ctx->sql_process_group_ctx,
				mod_authorize_post_profile, authorize_ctx);
}

static rlm_rcode_t mod_authorize_post_profile(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);

	switch (authorize_ctx->sql_process_group_ctx->rcode) {
	/*
	 *	Nothing bad happened, continue...
	 */
	case RLM_MODULE_UPDATED:
		authorize_ctx->rcode = RLM_MODULE_UPDATED;
		/* FALL-THROUGH */
	case RLM_MODULE_OK:
		if (authorize_ctx->rcode != RLM_MODULE_UPDATED) {
			authorize_ctx->rcode = RLM_MODULE_OK;
		}
		/* FALL-THROUGH */
	case RLM_MODULE_NOOP:
		authorize_ctx->user_found = true;
		break;

	case RLM_MODULE_NOTFOUND:
		break;

	default:
		authorize_ctx->rcode = authorize_ctx->sql_process_group_ctx->rcode;
	}

	return mod_authorize_release(request, instance, thread, ctx);
}

static rlm_rcode_t mod_authorize_release(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_thread_t *t = thread;

	/*
	 *	At this point the key (user) hasn't be found in the check table, the reply table
	 *	or the group mapping table, and there was no matching profile.
	 */
	if (!authorize_ctx->user_found) {
		authorize_ctx->rcode = RLM_MODULE_NOTFOUND;
	}

	fr_connection_release(t->pool, request, authorize_ctx->handle);
	sql_unset_user(inst, request);

	return authorize_ctx->rcode;
}

static rlm_rcode_t mod_authorize_error(REQUEST *request, void *instance, UNUSED void *thread, void *ctx)
{
	rlm_sql_authorize_ctx_t *authorize_ctx = talloc_get_type_abort(ctx, rlm_sql_authorize_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_thread_t *t = thread;

	fr_pair_list_free(&authorize_ctx->sql_getvpdata_ctx->attr);
	sql_unset_user(inst, request);

	fr_connection_release(t->pool, request, authorize_ctx->handle);

	return authorize_ctx->rcode;
}

static rlm_rcode_t acct_redundant_loop(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);
static rlm_rcode_t acct_redundant_finish(REQUEST *request, void *instance, UNUSED void *thread, void *ctx);
/*
 *	Generic function for failing between a bunch of queries.
 *
 *	Uses the same principle as rlm_linelog, expanding the 'reference' config
 *	item using xlat to figure out what query it should execute.
 *
 *	If the reference matches multiple config items, and a query fails or
 *	doesn't update any rows, the next matching config item is used.
 *
 */
static rlm_rcode_t acct_redundant(rlm_sql_t *inst, rlm_sql_thread_t *thread,
								  REQUEST *request, sql_acct_section_t *section)
{
	rlm_sql_acct_redundant_ctx_t *acct_redundant_ctx = talloc_zero(request, rlm_sql_acct_redundant_ctx_t);

	CONF_ITEM		*item;

	char			path[FR_MAX_STRING_LEN];
	char			*p = path;

	acct_redundant_ctx->rcode = RLM_MODULE_OK;
	acct_redundant_ctx->section = section;

	rad_assert(section);

	if (section->reference[0] != '.') {
		*p++ = '.';
	}

	if (xlat_eval(p, sizeof(path) - (p - path), request, section->reference, NULL, NULL) < 0) {
		acct_redundant_ctx->rcode = RLM_MODULE_FAIL;

		return acct_redundant_finish(request, inst, thread, acct_redundant_ctx);
	}

	/*
	 *	If we can't find a matching config item we do
	 *	nothing so return RLM_MODULE_NOOP.
	 */
	item = cf_reference_item(NULL, section->cs, path);
	if (!item) {
		RWDEBUG("No such configuration item %s", path);
		acct_redundant_ctx->rcode = RLM_MODULE_NOOP;

		return acct_redundant_finish(request, inst, thread, acct_redundant_ctx);
	}
	if (cf_item_is_section(item)){
		RWDEBUG("Sections are not supported as references");
		acct_redundant_ctx->rcode = RLM_MODULE_NOOP;

		return acct_redundant_finish(request, inst, thread, acct_redundant_ctx);
	}

	acct_redundant_ctx->pair = cf_item_to_pair(item);
	acct_redundant_ctx->attr = cf_pair_attr(acct_redundant_ctx->pair);

	RDEBUG2("Using query template '%s'", acct_redundant_ctx->attr);

	acct_redundant_ctx->handle = fr_connection_get(thread->pool, request);
	if (!acct_redundant_ctx->handle) {
		acct_redundant_ctx->rcode = RLM_MODULE_FAIL;

		return acct_redundant_finish(request, inst, thread, acct_redundant_ctx);
	}

	acct_redundant_ctx->sql_query_ctx = talloc_zero(acct_redundant_ctx, rlm_sql_query_ctx_t);
	acct_redundant_ctx->sql_query_ctx->handle = &acct_redundant_ctx->handle;

	sql_set_user(inst, request, NULL);

	acct_redundant_ctx->next_step = ACCT_REDUNDANT_START;

	return acct_redundant_loop(request, inst, thread, acct_redundant_ctx);
}

static rlm_rcode_t acct_redundant_loop(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_acct_redundant_ctx_t *acct_redundant_ctx = talloc_get_type_abort(ctx, rlm_sql_acct_redundant_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);

	char const	*value;
	int			numaffected = 0;

	while (true) {
		switch (acct_redundant_ctx->next_step) {
		case ACCT_REDUNDANT_START:
			value = cf_pair_value(acct_redundant_ctx->pair);
			if (!value) {
				RDEBUG("Ignoring null query");
				acct_redundant_ctx->rcode = RLM_MODULE_NOOP;

				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);
			}

			if (xlat_aeval(request, &acct_redundant_ctx->sql_query_ctx->query, request, value,
						   inst->sql_escape_func, acct_redundant_ctx->handle) < 0) {
				acct_redundant_ctx->rcode = RLM_MODULE_FAIL;

				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);
			}

			if (!*acct_redundant_ctx->sql_query_ctx->query) {
				RDEBUG("Ignoring null query");
				acct_redundant_ctx->rcode = RLM_MODULE_NOOP;
				talloc_free(acct_redundant_ctx->sql_query_ctx->query);

				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);
			}

			rlm_sql_query_log(inst, request, acct_redundant_ctx->section, acct_redundant_ctx->sql_query_ctx->query);

			acct_redundant_ctx->next_step = ACCT_REDUNDANT_RESUME;

			return unlang_two_step_process(request, rlm_sql_query, acct_redundant_ctx->sql_query_ctx,
										   acct_redundant_loop, ctx);

		case ACCT_REDUNDANT_RESUME:
			TALLOC_FREE(acct_redundant_ctx->sql_query_ctx->query);
			RDEBUG("SQL query returned: %s", fr_int2str(sql_rcode_table, acct_redundant_ctx->sql_query_ctx->sql_ret, "<INVALID>"));

			switch (acct_redundant_ctx->sql_query_ctx->sql_ret) {
			/*
			 *  Query was a success! Now we just need to check if it did anything.
			 */
			case RLM_SQL_OK:
				break;

			/*
			 *  A general, unrecoverable server fault.
			 */
			case RLM_SQL_ERROR:
			/*
			 *  If we get RLM_SQL_RECONNECT it means all connections in the pool
			 *  were exhausted, and we couldn't create a new connection,
			 *  so we do not need to call fr_connection_release.
			 */
			case RLM_SQL_RECONNECT:
				acct_redundant_ctx->rcode = RLM_MODULE_FAIL;
				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);

			/*
			 *  Query was invalid, this is a terminal error, but we still need
			 *  to do cleanup, as the connection handle is still valid.
			 */
			case RLM_SQL_QUERY_INVALID:
				acct_redundant_ctx->rcode = RLM_MODULE_INVALID;
				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);

			/*
			 *  Driver found an error (like a unique key constraint violation)
			 *  that hinted it might be a good idea to try an alternative query.
			 */
			case RLM_SQL_ALT_QUERY:
				goto next;
			}
			rad_assert(acct_redundant_ctx->handle);

			/*
			 *  We need to have updated something for the query to have been
			 *  counted as successful.
			 */
			numaffected = (inst->driver->sql_affected_rows)(acct_redundant_ctx->handle, inst->config);
			(inst->driver->sql_finish_query)(acct_redundant_ctx->handle, inst->config);
			RDEBUG("%i record(s) updated", numaffected);

			if (numaffected > 0)
				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);	/* A query succeeded, were done! */
		next:
			/*
			 *  We assume all entries with the same name form a redundant
			 *  set of queries.
			 */
			acct_redundant_ctx->pair = cf_pair_find_next(acct_redundant_ctx->section->cs, acct_redundant_ctx->pair,
														 acct_redundant_ctx->attr);

			if (!acct_redundant_ctx->pair) {
				RDEBUG("No additional queries configured");
				acct_redundant_ctx->rcode = RLM_MODULE_NOOP;

				return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);
			}

			acct_redundant_ctx->next_step = ACCT_REDUNDANT_START;
			RDEBUG("Trying next query...");
		}
	}

	return acct_redundant_finish(request, instance, thread, acct_redundant_ctx);
}

static rlm_rcode_t acct_redundant_finish(REQUEST *request, void *instance, void *thread, void *ctx)
{
	rlm_sql_acct_redundant_ctx_t *acct_redundant_ctx = talloc_get_type_abort(ctx, rlm_sql_acct_redundant_ctx_t);
	rlm_sql_t const *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_thread_t *t = talloc_get_type_abort(thread, rlm_sql_thread_t);

	talloc_free(acct_redundant_ctx->sql_query_ctx->query);
	fr_connection_release(t->pool, request, acct_redundant_ctx->handle);
	sql_unset_user(inst, request);

	return acct_redundant_ctx->rcode;
}

#ifdef WITH_ACCOUNTING

/*
 *	Accounting: Insert or update session data in our sql table
 */
static rlm_rcode_t mod_accounting(void *instance, void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_accounting(void *instance, void *thread, REQUEST *request)
{
	rlm_sql_t *inst = talloc_get_type_abort(instance, rlm_sql_t);

	if (inst->config->accounting.reference_cp) {
		return acct_redundant(inst, thread, request, &inst->config->accounting);
	}

	return RLM_MODULE_NOOP;
}

#endif

#ifdef WITH_SESSION_MGMT
/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t mod_checksimul(void *instance, UNUSED void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_checksimul(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	rlm_sql_handle_t 	*handle = NULL;
	rlm_sql_t const		*inst = instance;
	rlm_sql_row_t		row;
	int			check = 0;
	uint32_t		ipno = 0;
	char const     		*call_num = NULL;
	VALUE_PAIR		*vp;
	int			ret;
	uint32_t		nas_addr = 0;
	uint32_t		nas_port = 0;

	char 			*expanded = NULL;

	/* If simul_count_query is not defined, we don't do any checking */
	if (!inst->config->simul_count_query) {
		RWDEBUG("Simultaneous-Use checking requires 'simul_count_query' to be configured");
		return RLM_MODULE_NOOP;
	}

	if ((!request->username) || (request->username->vp_length == 0)) {
		REDEBUG("Zero Length username not permitted");

		return RLM_MODULE_INVALID;
	}

	if (sql_set_user(inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	/* initialize the sql socket */
	handle = fr_connection_get(inst->pool, request);
	if (!handle) {
		sql_unset_user(inst, request);
		return RLM_MODULE_FAIL;
	}

	if (xlat_aeval(request, &expanded, request, inst->config->simul_count_query,
			 inst->sql_escape_func, handle) < 0) {
		fr_connection_release(inst->pool, request, handle);
		sql_unset_user(inst, request);
		return RLM_MODULE_FAIL;
	}

	if (rlm_sql_select_query(inst, request, &handle, expanded) != RLM_SQL_OK) {
		rcode = RLM_MODULE_FAIL;
		goto release;	/* handle may no longer be valid */
	}

	ret = rlm_sql_fetch_row(&row, inst, request, &handle);
	if (ret != RLM_SQL_OK) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}
	request->simul_count = atoi(row[0]);

	(inst->driver->sql_finish_select_query)(handle, inst->config);
	TALLOC_FREE(expanded);

	if (request->simul_count < request->simul_max) {
		rcode = RLM_MODULE_OK;
		goto finish;
	}

	/*
	 *	Looks like too many sessions, so let's start verifying
	 *	them, unless told to rely on count query only.
	 */
	if (!inst->config->simul_verify_query) {
		rcode = RLM_MODULE_OK;

		goto finish;
	}

	if (xlat_aeval(request, &expanded, request, inst->config->simul_verify_query,
			 inst->sql_escape_func, handle) < 0) {
		rcode = RLM_MODULE_FAIL;

		goto finish;
	}

	if (rlm_sql_select_query(inst, request, &handle, expanded) != RLM_SQL_OK) goto release;

	/*
	 *      Setup some stuff, like for MPP detection.
	 */
	request->simul_count = 0;

	if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_FRAMED_IP_ADDRESS, TAG_ANY)) != NULL) {
		ipno = vp->vp_ipaddr;
	}

	if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_CALLING_STATION_ID, TAG_ANY)) != NULL) {
		call_num = vp->vp_strvalue;
	}

	while (rlm_sql_fetch_row(&row, inst, request, &handle) == RLM_SQL_OK) {
		if (!row[2]){
			RDEBUG("Cannot zap stale entry. No username present in entry");
			rcode = RLM_MODULE_FAIL;

			goto finish;
		}

		if (!row[1]){
			RDEBUG("Cannot zap stale entry. No session id in entry");
			rcode = RLM_MODULE_FAIL;

			goto finish;
		}

		if (row[3]) {
			nas_addr = inet_addr(row[3]);
		}

		if (row[4]) {
			nas_port = atoi(row[4]);
		}

		check = rad_check_ts(nas_addr, nas_port, row[2], row[1]);
		if (check == 0) {
			/*
			 *	Stale record - zap it.
			 */
			if (inst->config->delete_stale_sessions == true) {
				uint32_t framed_addr = 0;
				char proto = 0;
				int sess_time = 0;

				if (row[5])
					framed_addr = inet_addr(row[5]);
				if (row[7]){
					if (strcmp(row[7], "PPP") == 0)
						proto = 'P';
					else if (strcmp(row[7], "SLIP") == 0)
						proto = 'S';
				}
				if (row[8])
					sess_time = atoi(row[8]);
				session_zap(request, nas_addr, nas_port,
					    row[2], row[1], framed_addr,
					    proto, sess_time);
			}
		}
		else if (check == 1) {
			/*
			 *	User is still logged in.
			 */
			++request->simul_count;

			/*
			 *      Does it look like a MPP attempt?
			 */
			if (row[5] && ipno && inet_addr(row[5]) == ipno) {
				request->simul_mpp = 2;
			} else if (row[6] && call_num && !strncmp(row[6],call_num,16)) {
				request->simul_mpp = 2;
			}
		} else {
			/*
			 *      Failed to check the terminal server for
			 *      duplicate logins: return an error.
			 */
			REDEBUG("Failed to check the terminal server for user '%s'.", row[2]);

			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
	}

finish:
	(inst->driver->sql_finish_select_query)(handle, inst->config);
release:
	fr_connection_release(inst->pool, request, handle);
	talloc_free(expanded);
	sql_unset_user(inst, request);

	/*
	 *	The Auth module apparently looks at request->simul_count,
	 *	not the return value of this module when deciding to deny
	 *	a call for too many sessions.
	 */
	return rcode;
}
#endif

/*
 *	Postauth: Write a record of the authentication attempt
 */
static rlm_rcode_t mod_post_auth(void *instance, void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_post_auth(void *instance, void *thread, REQUEST *request)
{
	rlm_sql_t *inst = talloc_get_type_abort(instance, rlm_sql_t);

	if (inst->config->postauth.reference_cp) {
		return acct_redundant(inst, thread, request, &inst->config->postauth);
	}

	return RLM_MODULE_NOOP;
}

/*
 *	Execute postauth_query after authentication
 */


/* globally exported name */
rad_module_t rlm_sql = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sql",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_sql_t),
	.thread_inst_size	= sizeof(rlm_sql_thread_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.thread_instantiate	= mod_thread_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_accounting,
#endif
#ifdef WITH_SESSION_MGMT
		[MOD_SESSION]		= mod_checksimul,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
