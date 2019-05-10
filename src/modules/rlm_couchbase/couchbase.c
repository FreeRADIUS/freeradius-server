/*
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
 */

/**
 * $Id$
 *
 * @brief Wrapper functions around the libcouchbase Couchbase client driver.
 * @file couchbase.c
 *
 * @author Aaron Hurt (ahurt@anbcs.com)
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_couchbase - "

#include <freeradius-devel/server/base.h>

DIAG_OFF(documentation)
#include <libcouchbase/couchbase.h>
#include <libcouchbase/n1ql.h>
DIAG_ON(documentation)

#include "couchbase.h"

/** Couchbase callback for cluster statistics requests
 *
 * @param instance Couchbase connection instance.
 * @param cookie   Couchbase cookie for returning information from callbacks.
 * @param error    Couchbase error object.
 * @param resp     Couchbase statistics response object.
 */
void couchbase_stat_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_server_stat_resp_t *resp)
{
	if (error != LCB_SUCCESS) {
		/* log error */
		ERROR("(stats_callback) %s (0x%x)", lcb_strerror(instance, error), error);
	}
	/* silent compiler */
	(void)cookie;
	(void)resp;
}

/** Couchbase callback for store (write) operations
 *
 * @param instance  Couchbase connection instance.
 * @param cookie    Couchbase cookie for returning information from callbacks.
 * @param operation Couchbase storage operation object.
 * @param error     Couchbase error object.
 * @param resp      Couchbase store operation response object.
 */
void couchbase_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation,
			      lcb_error_t error, const lcb_store_resp_t *resp)
{
	if (error != LCB_SUCCESS) {
		/* log error */
		ERROR("(store_callback) %s (0x%x)", lcb_strerror(instance, error), error);
	}
	/* silent compiler */
	(void)cookie;
	(void)operation;
	(void)resp;
}

/** Couchbase callback for get (read) operations
 *
 * @param instance Couchbase connection instance.
 * @param cookie   Couchbase cookie for returning information from callbacks.
 * @param error    Couchbase error object.
 * @param resp     Couchbase get operation response object.
 */
void couchbase_get_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_get_resp_t *resp)
{
	cookie_u cu;                            /* union of const and non const pointers */
	cu.cdata = cookie;                      /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;     /* set our cookie struct using non-const member */
	const char *bytes = resp->v.v0.bytes;   /* the payload of this chunk */
	lcb_size_t nbytes = resp->v.v0.nbytes;  /* length of this data chunk */

	/* check error */
	switch (error) {
	case LCB_SUCCESS:
		/* check for valid bytes */
		if (bytes && nbytes > 1) {
			/* debug */
			DEBUG("(get_callback) got %zu bytes", nbytes);
			/* parse string to json object */
			c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);
			/* switch on tokener error */
			switch ((c->jerr = json_tokener_get_error(c->jtok))) {
			case json_tokener_continue:
				/* check object - should be null */
				if (c->jobj != NULL) {
					ERROR("(get_callback) object not null on continue!");
				}
				break;
			case json_tokener_success:
				/* do nothing */
				break;
			default:
				/* log error */
				ERROR("(get_callback) json parsing error: %s",
				      json_tokener_error_desc(c->jerr));
				break;
			}
		}
		break;

	case LCB_KEY_ENOENT:
		/* ignored */
		DEBUG("(get_callback) key does not exist");
		break;

	default:
		/* log error */
		ERROR("(get_callback) %s (0x%x)", lcb_strerror(instance, error), error);
		break;
	}
}

/** Couchbase callback for http (view) operations
 *
 * @param request  Couchbase http request object.
 * @param instance Couchbase connection instance.
 * @param cookie   Couchbase cookie for returning information from callbacks.
 * @param error    Couchbase error object.
 * @param resp     Couchbase http response object.
 */
void couchbase_http_data_callback(lcb_http_request_t request, lcb_t instance, const void *cookie,
				  lcb_error_t error, const lcb_http_resp_t *resp)
{
	cookie_u cu;                            /* union of const and non const pointers */
	cu.cdata = cookie;                      /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;     /* set our cookie struct using non-const member */
	const char *bytes = resp->v.v0.bytes;   /* the payload of this chunk */
	lcb_size_t nbytes = resp->v.v0.nbytes;  /* length of this data chunk */

	/* check error */
	switch (error) {
	case LCB_SUCCESS:
		/* check for valid bytes */
		if (bytes && nbytes > 1) {
			/* debug */
			DEBUG("(http_data_callback) got %zu bytes", nbytes);
			/* parse string to json object */
			c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);
			/* switch on tokener error */
			switch ((c->jerr = json_tokener_get_error(c->jtok))) {
			case json_tokener_continue:
				/* check object - should be null */
				if (c->jobj != NULL) ERROR("(http_data_callback) object not null on continue!");
				break;
			case json_tokener_success:
				/* do nothing */
				break;
			default:
				/* log error */
				ERROR("(http_data_callback) json parsing error: %s", json_tokener_error_desc(c->jerr));
				break;
			}
		}
		break;

	default:
		/* log error */
		ERROR("(http_data_callback) %s (0x%x)", lcb_strerror(instance, error), error);
		break;
	}
	/* silent compiler */
	(void)request;
}

/** Initialize a Couchbase connection instance
 *
 * Initialize all information relating to a Couchbase instance and configure available method callbacks.
 * This function forces synchronous operation and will wait for a connection or timeout.
 *
 * @param instance Empty (un-allocated) Couchbase instance object.
 * @param host       The Couchbase server or list of servers.
 * @param bucket     The Couchbase bucket to associate with the instance.
 * @param user       The Couchbase bucket user (NULL if none).
 * @param pass       The Couchbase bucket password (NULL if none).
 * @param timeout    Maximum time to wait for obtaining the initial configuration.
 * @param opts       Extra options to configure the libcouchbase.
 * @return           Couchbase error object.
 */
lcb_error_t couchbase_init_connection(lcb_t *instance, const char *host, const char *bucket, const char *user, const char *pass,
				      lcb_uint32_t timeout, const couchbase_opts_t *opts)
{
	lcb_error_t error;                      /* couchbase command return */
	struct lcb_create_st options;           /* init create struct */

	/* init options */
	memset(&options, 0, sizeof(options));

	/* assign couchbase create options */
	options.v.v0.host = host;
	options.v.v0.bucket = bucket;
	options.v.v0.user = user;
	options.v.v0.passwd = pass;

	/* create couchbase connection instance */
	error = lcb_create(instance, &options);
	if (error != LCB_SUCCESS) return error;

	error = lcb_cntl(*instance, LCB_CNTL_SET, LCB_CNTL_CONFIGURATION_TIMEOUT, &timeout);
	if (error != LCB_SUCCESS) return error;

	/* Couchbase extra api settings */
	if (opts != NULL) {
		const couchbase_opts_t *o = opts;

		for (; o != NULL; o = o->next) {
			error = lcb_cntl_string(*instance, o->key, o->val);
			if (error != LCB_SUCCESS) {
				ERROR("Failed to configure the couchbase with %s=%s", o->key, o->val);
				return error;
			}
		}
	}

	/* initiate connection */
	error = lcb_connect(*instance);
	if (error != LCB_SUCCESS) return error;

	/* set general method callbacks */
	lcb_set_stat_callback(*instance, couchbase_stat_callback);
	lcb_set_store_callback(*instance, couchbase_store_callback);
	lcb_set_get_callback(*instance, couchbase_get_callback);
	lcb_set_http_data_callback(*instance, couchbase_http_data_callback);
	/* wait on connection */
	lcb_wait(*instance);

	return LCB_SUCCESS;
}

/** Request Couchbase server statistics
 *
 * Setup and execute a request for cluster statistics and wait for the result.
 *
 * @param  instance Couchbase connection instance.
 * @param  cookie   Couchbase cookie for returning information from callbacks.
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_server_stats(lcb_t instance, const void *cookie)
{
	lcb_error_t error;                         /* couchbase command return */
	lcb_server_stats_cmd_t cmd;                /* server stats command stuct */
	const lcb_server_stats_cmd_t *commands[1]; /* server stats commands array */

	/* init commands */
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.name = "tap";
	cmd.v.v0.nname = strlen(cmd.v.v0.name);

	/* get statistics */
	if ((error = lcb_server_stats(instance, cookie, 1, commands)) == LCB_SUCCESS) {
		/* enter event look on success */
		lcb_wait(instance);
	}

	/* return error */
	return error;
}

/** Store a document by key in Couchbase
 *
 * Setup and execute a Couchbase set operation and wait for the result.
 *
 * @param  instance Couchbase connection instance.
 * @param  key      Document key to store in the database.
 * @param  document Document body to store in the database.
 * @param  expire   Expiration time for the document (0 = never)
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_set_key(lcb_t instance, const char *key, const char *document, int expire)
{
	lcb_error_t error;                  /* couchbase command return */
	lcb_store_cmd_t cmd;                /* store command stuct */
	const lcb_store_cmd_t *commands[1]; /* store commands array */

	/* init commands */
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.key = key;
	cmd.v.v0.nkey = strlen(cmd.v.v0.key);
	cmd.v.v0.bytes = document;
	cmd.v.v0.nbytes = strlen(cmd.v.v0.bytes);
	cmd.v.v0.exptime = expire;
	cmd.v.v0.operation = LCB_SET;

	/* store key/document in couchbase */
	if ((error = lcb_store(instance, NULL, 1, commands)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance);
	}

	/* return error */
	return error;
}

/** Retrieve a document by key from Couchbase
 *
 * Setup and execute a Couchbase get request and wait for the result.
 *
 * @param  instance Couchbase connection instance.
 * @param  cookie   Couchbase cookie for returning information from callbacks.
 * @param  key      Document key to fetch.
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_get_key(lcb_t instance, const void *cookie, const char *key)
{
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = cookie;                   /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */
	lcb_error_t error;                   /* couchbase command return */
	lcb_get_cmd_t cmd;                   /* get command struct */
	const lcb_get_cmd_t *commands[1];    /* get commands array */

	/* init commands */
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.key = key;
	cmd.v.v0.nkey = strlen(cmd.v.v0.key);

	/* clear cookie */
	memset(c, 0, sizeof(cookie_t));

	/* init tokener error */
	c->jerr = json_tokener_success;

	/* create token */
	c->jtok = json_tokener_new();

	/* debugging */
	DEBUG3("fetching document %s", key);

	/* get document */
	if ((error = lcb_get(instance, c, 1, commands)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance);
	}

	/* free token */
	json_tokener_free(c->jtok);

	/* return error */
	return error;
}

/** Query a Couchbase design document view
 *
 * Setup and execute a Couchbase view request and wait for the result.
 *
 * @param  instance Couchbase connection instance.
 * @param  cookie   Couchbase cookie for returning information from callbacks.
 * @param  path     The fully qualified view path including the design document and view name.
 * @param  post     The post payload (NULL for none).
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_query_view(lcb_t instance, const void *cookie, const char *path, const char *post)
{
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = cookie;                   /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */
	lcb_error_t error;                   /* couchbase command return */
	lcb_http_cmd_t cmd;                  /* http command struct */
	const lcb_http_cmd_t *commands;      /* http commands array */

	commands = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.path = path;
	cmd.v.v0.npath = strlen(cmd.v.v0.path);
	cmd.v.v0.body = post;
	cmd.v.v0.nbody = post ? strlen(post) : 0;
	cmd.v.v0.method = post ? LCB_HTTP_METHOD_POST : LCB_HTTP_METHOD_GET;
	cmd.v.v0.chunked = 1;
	cmd.v.v0.content_type = "application/json";

	/* clear cookie */
	memset(c, 0, sizeof(cookie_t));

	/* init tokener error */
	c->jerr = json_tokener_success;

	/* create token */
	c->jtok = json_tokener_new();

	/* debugging */
	DEBUG3("fetching view %s", path);

	/* query the view */
	if ((error = lcb_make_http_request(instance, c, LCB_HTTP_TYPE_VIEW, commands, NULL)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance);
	}

	/* free token */
	json_tokener_free(c->jtok);

	/* return error */
	return error;
}

/** Couchbase callback for N1QL operations
 *
 * @param instance Couchbase connection instance.
 * @param cbtype   Couchbase callback type.
 * @param resp     Couchbase query response object.
 */
static void couchbase_n1ql_callback(lcb_t instance, int cbtype, const lcb_RESPN1QL *resp) {
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = resp->cookie;             /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */

	if (resp->rc != LCB_SUCCESS) {
		ERROR("(couchbase_n1ql_callback) %s (0x%x)", lcb_strerror(instance, resp->rc), resp->rc);
		return;
	}

	if (!resp->row || resp->nrow < 1) {
		ERROR("Result is too short");
		return;
	}

	if (resp->rflags & LCB_RESP_F_FINAL) return;

	DEBUG4("(couchbase_n1ql_callback) got %zu bytes: %.*s, callback-type: %s\n", resp->nrow,
			(int)resp->nrow, resp->row, lcb_strcbtype(cbtype));

	c->jobj = json_tokener_parse_ex(c->jtok, resp->row, resp->nrow);

	switch ((c->jerr = json_tokener_get_error(c->jtok))) {
	case json_tokener_continue:
		if (c->jobj != NULL) {
			ERROR("(couchbase_n1ql_callback) object not null on continue!");
			return;
		}

		break;
	case json_tokener_success:
		break;
	default:
		ERROR("(couchbase_n1ql_callback) json parsing error: %s", json_tokener_error_desc(c->jerr));
		break;
	}
}

/** Query a Couchbase using N1QL
 *
 * Setup and execute a Couchbase view request and wait for the result.
 *
 * @param  instance Couchbase connection instance.
 * @param  cookie   Couchbase cookie for returning information from callbacks.
 * @param  query    The fully qualified view path including the design document and view name.
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_query_n1ql(lcb_t instance, const void *cookie, const char *query)
{
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = cookie;                   /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */
	lcb_error_t rc;                      /* couchbase command return */
	lcb_N1QLPARAMS *nparams;             /* Object to store the N1QL */
	lcb_CMDN1QL cmd = {                  /* Object to store the query callback */
		.callback = couchbase_n1ql_callback,
		.cmdflags = LCB_CMDN1QL_F_PREPCACHE
	};

	rad_assert(query != NULL);

	memset(c, 0, sizeof(cookie_t));

	c->jerr = json_tokener_success;
	c->jtok = json_tokener_new();

	/* debugging */
	DEBUG4("fetching N1QL: %s", query);

	nparams = lcb_n1p_new();
	rc = lcb_n1p_setstmtz(nparams, query);

	if (rc == LCB_SUCCESS) rc = lcb_n1p_setconsistency(nparams, LCB_N1P_CONSISTENCY_REQUEST);
	if (rc == LCB_SUCCESS) rc = lcb_n1p_mkcmd(nparams, &cmd);
	if (rc == LCB_SUCCESS) rc = lcb_n1ql_query(instance, c, &cmd);	
	if (rc == LCB_SUCCESS) lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		ERROR("(couchbase_query_n1ql) %s (0x%x)", lcb_strerror(instance, rc), rc);
	}

	lcb_n1p_free(nparams);

	/* free token */
	json_tokener_free(c->jtok);

	/* return error */
	return rc;
}

