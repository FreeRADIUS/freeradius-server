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
 * @author Aaron Hurt <ahurt@anbcs.com>
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <libcouchbase/couchbase.h>

#include "couchbase.h"
#include "jsonc_missing.h"

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
		ERROR("rlm_couchbase: (stats_callback) %s (0x%x)", lcb_strerror(instance, error), error);
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
		ERROR("rlm_couchbase: (store_callback) %s (0x%x)", lcb_strerror(instance, error), error);
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
			DEBUG("rlm_couchbase: (get_callback) got %zu bytes", nbytes);
			/* parse string to json object */
			c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);
			/* switch on tokener error */
			switch ((c->jerr = json_tokener_get_error(c->jtok))) {
			case json_tokener_continue:
				/* check object - should be null */
				if (c->jobj != NULL) {
					ERROR("rlm_couchbase: (get_callback) object not null on continue!");
				}
				break;
			case json_tokener_success:
				/* do nothing */
				break;
			default:
				/* log error */
				ERROR("rlm_couchbase: (get_callback) json parsing error: %s",
				      json_tokener_error_desc(c->jerr));
				break;
			}
		}
		break;

	case LCB_KEY_ENOENT:
		/* ignored */
		DEBUG("rlm_couchbase: (get_callback) key does not exist");
		break;

	default:
		/* log error */
		ERROR("rlm_couchbase: (get_callback) %s (0x%x)", lcb_strerror(instance, error), error);
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
			DEBUG("rlm_couchbase: (http_data_callback) got %zu bytes", nbytes);
			/* parse string to json object */
			c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);
			/* switch on tokener error */
			switch ((c->jerr = json_tokener_get_error(c->jtok))) {
			case json_tokener_continue:
				/* check object - should be null */
				if (c->jobj != NULL) {
					ERROR("rlm_couchbase: (http_data_callback) object not null on continue!");
				}
				break;
			case json_tokener_success:
				/* do nothing */
				break;
			default:
				/* log error */
				ERROR("rlm_couchbase: (http_data_callback) json parsing error: %s",
				      json_tokener_error_desc(c->jerr));
				break;
			}
		}
		break;

	default:
		/* log error */
		ERROR("rlm_couchbase: (http_data_callback) %s (0x%x)", lcb_strerror(instance, error), error);
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
 * @param host     The Couchbase server or list of servers.
 * @param bucket   The Couchbase bucket to associate with the instance.
 * @param pass     The Couchbase bucket password (NULL if none).
 * @return          Couchbase error object.
 */
lcb_error_t couchbase_init_connection(lcb_t *instance, const char *host, const char *bucket, const char *pass)
{
	lcb_error_t error;                      /* couchbase command return */
	struct lcb_create_st options;           /* init create struct */

	/* init options */
	memset(&options, 0, sizeof(options));

	/* assign couchbase create options */
	options.v.v0.host = host;
	options.v.v0.bucket = bucket;

	/* assign user and password if they were both passed */
	if (bucket != NULL && pass != NULL) {
		options.v.v0.user = bucket;
		options.v.v0.passwd = pass;
	}

	/* create couchbase connection instance */
	if ((error = lcb_create(instance, &options)) != LCB_SUCCESS) {
		/* return error */
		return error;
	}

	/* initiate connection */
	if ((error = lcb_connect(*instance)) == LCB_SUCCESS) {
		/* set general method callbacks */
		lcb_set_stat_callback(*instance, couchbase_stat_callback);
		lcb_set_store_callback(*instance, couchbase_store_callback);
		lcb_set_get_callback(*instance, couchbase_get_callback);
		lcb_set_http_data_callback(*instance, couchbase_http_data_callback);
		/* wait on connection */
		lcb_wait(*instance);
	} else {
		/* return error */
		return error;
	}

	/* return instance */
	return error;
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
	DEBUG3("rlm_couchbase: fetching document %s", key);

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
	DEBUG3("rlm_couchbase: fetching view %s", path);

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
