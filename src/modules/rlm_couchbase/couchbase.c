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
 * @copyright 2013-2022 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX "couchbase"

#include <freeradius-devel/util/version.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/json/base.h>

#include "couchbase.h"

static _Thread_local request_t *fr_couchbase_request;

/** Set the thread local request
 *
 * @param[in] request	all helper and C functions callable from rlm_couchbase should use.
 */
void fr_couchbase_set_request(request_t *request)
{
	fr_couchbase_request = request;
}

/** Get the thread local request
 *
 * @return request all helper and C functions callable from rlm_couchbase should use.
 */
request_t *fr_couchbase_get_request(void)
{
	return fr_couchbase_request;
}

/** Couchbase callback for cluster statistics requests.
 *
 * @param instance  Couchbase connection instance.
 * @param cbtype    Couchbase callback type.
 * @param rb        Couchbase response base.
 */
#if 0
void couchbase_stats_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb)
{
	const lcb_RESPSTATS *resp = (const lcb_RESPSTATS *)rb;
	lcb_STATUS rc = lcb_respstats_status(resp);

	if (rc != LCB_SUCCESS) {
		/* log error */
		ERROR("(stats_callback) %s (0x%x)", lcb_strerror_long(rc), rc);
	}
}
#endif

/** Couchbase callback for store (write) operations
 *
 * @param instance  Couchbase connection instance.
 * @param cbtype    Couchbase callback type.
 * @param rb        Couchbase response base.
 */
void couchbase_store_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb)
{
	const lcb_RESPSTORE *resp = (const lcb_RESPSTORE *)rb;
	lcb_STATUS rc = lcb_respstore_status(resp);

	if (rc != LCB_SUCCESS) {
		/* log error */
		ERROR("(store_callback) %s (0x%x)", lcb_strerror_long(rc), rc);
	}
}

/** Couchbase callback for get (read) operations
 *
 * @param instance  Couchbase connection instance.
 * @param cbtype    Couchbase callback type.
 * @param rb        Couchbase response base.
 */
void couchbase_get_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb)
{
	const lcb_RESPGET *resp = (const lcb_RESPGET *)rb;
	lcb_STATUS rc = lcb_respget_status(resp);

	/* check error */
	switch (rc) {
	case LCB_SUCCESS:
	{
		const char *bytes;
		size_t nbytes;
		cookie_u cu;                           /* union of const and non const pointers */
		cookie_t *c;                           /* set our cookie struct using non-const member */
		uint8_t datatype;

		lcb_respget_datatype(resp, &datatype);
		if (!(datatype & LCB_VALUE_F_JSON)) {
			ERROR("(get_callback) object must be JSON");
			return;
		}

		/* check for valid bytes */
		lcb_respget_value(resp, &bytes, &nbytes);

		if (bytes && nbytes > 1) {
			/* debug */
			DEBUG3("(get_callback) got %zu bytes", nbytes);

			lcb_respget_cookie(resp, &cu.data);
			c = (cookie_t *)cu.data;           /* set our cookie struct using non-const member */

			/* parse string to json object */
			c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);

			/* switch on tokener error */
			switch ((c->jerr = json_tokener_get_error(c->jtok))) {
			case json_tokener_continue:
				/* check object - should be null */
				if (c->jobj != NULL) {
					DEBUG3("(get_callback) object not null on continue!");
				}
				break;
			case json_tokener_success:
				/* do nothing */
				break;
			default:
				/* log error */
				DEBUG3("(get_callback) json parsing error: %s",
				      json_tokener_error_desc(c->jerr));
				break;
			}
		}
		break;
	}

	case LCB_ERR_DOCUMENT_NOT_FOUND:
		/* ignored */
		WARN("(get_callback) key does not exist");
		break;

	default:
		/* log error */
		ERROR("(get_callback) %s (0x%x)", lcb_strerror_long(rc), rc);
		break;
	}
}

/** Couchbase callback for http (view) operations
 *
 * @param instance  Couchbase connection instance.
 * @param cbtype    Couchbase callback type.
 * @param rb        Couchbase response base.
 */
void couchbase_http_data_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb)
{
	const lcb_RESPHTTP *resp = (const lcb_RESPHTTP *)rb;
	lcb_STATUS rc = lcb_resphttp_status(resp);

	/* check error */
	switch (rc) {
	case LCB_SUCCESS:
	{
		char const *bytes;
		size_t nbytes;
		uint16_t http_status = 0;

		/* debug */
		lcb_resphttp_http_status(resp, &http_status);

		DEBUG3("(http_data_callback) Got HTTP Status: %d", http_status);

		/* check for valid bytes */
		lcb_resphttp_body(resp, &bytes, &nbytes);
		if (bytes && nbytes > 1) {
			cookie_u cu;     /* union of const and non const pointers */
			cookie_t *c;     /* set our cookie struct using non-const member */

			/* debug */
			/* we can't use REDEBUG() here, because that function is called by mod_instantiate -> mod_load_client_documents() */
			DEBUG3("(http_data_callback) Got %zu bytes", nbytes);

			lcb_resphttp_cookie(resp, &cu.data);
			c = (cookie_t *)cu.data;

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
	}

	default:
		/* log error */
		ERROR("(http_data_callback) %s (0x%x)", lcb_strerror_long(rc), rc);
		break;
	}
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
lcb_STATUS couchbase_init_connection(lcb_INSTANCE **instance, const char *host, const char *bucket, const char *user, const char *pass,
				      int64_t timeout, const couchbase_opts_t *opts)
{
	lcb_INSTANCE *cb_inst;
	lcb_CREATEOPTS *options = NULL;  /* init create struct */
	lcb_STATUS rc;                  /* couchbase command return */
	char *str_client;

	/* assign couchbase create options */
	rc = lcb_createopts_create(&options, LCB_TYPE_BUCKET);
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_createopts_create()");
		return rc;
	}

	rc = lcb_createopts_connstr(options, host, strlen(host));
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_createopts_connstr() using host '%s'", host);
	err1:
		lcb_createopts_destroy(options);
		return rc;
	}

	rc = lcb_createopts_bucket(options, bucket, strlen(bucket));
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_createopts_bucket() using bucket '%s'", bucket);
		goto err1;
	}

	rc = lcb_createopts_credentials(options, user, strlen(user), pass, strlen(pass));
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_createopts_credentials() using user '%s' and pass '%s'", user, pass);
		goto err1;
	}

	/* create couchbase connection instance */
	rc = lcb_create(&cb_inst, options);
	lcb_createopts_destroy(options);
	if (rc != LCB_SUCCESS) return rc;

	str_client = talloc_asprintf(NULL, "(FreeRADIUS/%s%s%s)", RADIUSD_VERSION_STRING,
				RADIUSD_VERSION_RELEASE_STRING, RADIUSD_VERSION_COMMIT_STRING);
	rc = lcb_cntl_string(cb_inst, "client_string", str_client);
	talloc_free(str_client);
	if (rc != LCB_SUCCESS) {
	err2:
		lcb_destroy(cb_inst);
		return rc;
	}

	rc = lcb_cntl_setu32(cb_inst, LCB_CNTL_OP_TIMEOUT, (int32_t)timeout);
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to set timeout");
		goto err2;
	}

	/* Couchbase extra api settings */
	if (opts != NULL) {
		const couchbase_opts_t *o = opts;

		for (; o != NULL; o = o->next) {
			rc = lcb_cntl_string(cb_inst, o->key, o->val);
			if (rc != LCB_SUCCESS) {
				ERROR("Failed to configure the couchbase with %s=%s", o->key, o->val);
				goto err2;
			}
		}
	}

	/* initiate connection */
	rc = lcb_connect(cb_inst);
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_wait()");
		goto err2;
	}

	/* wait on connection */
	rc = lcb_wait(cb_inst, LCB_WAIT_DEFAULT);
	if (rc != LCB_SUCCESS) {
		ERROR("Failed to call lcb_wait()");
		goto err2;
	}

	rc = lcb_get_bootstrap_status(cb_inst);
	if (rc != LCB_SUCCESS) {
		ERROR("Unable to bootstrap cluster: %s", lcb_strerror_short(rc));
		goto err2;
	}

	/* set general method callbacks */
	// lcb_install_callback(cb_inst, LCB_CALLBACK_STATS, couchbase_stats_callback);
	lcb_install_callback(cb_inst, LCB_CALLBACK_STORE, couchbase_store_callback);
	lcb_install_callback(cb_inst, LCB_CALLBACK_GET, couchbase_get_callback);
	lcb_install_callback(cb_inst, LCB_CALLBACK_HTTP, couchbase_http_data_callback);

	*instance = cb_inst;

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
lcb_STATUS couchbase_server_stats(lcb_INSTANCE *instance, const void *cookie)
{
	/*
	 * the 'stats' calls was removed from libcouchbase 3.3.0, let's see further versions.
	 */
#if 0
	lcb_STATUS rc;                             /* couchbase command return */
	lcb_server_stats_cmd_t cmd;                /* server stats command stuct */
	const lcb_server_stats_cmd_t *commands[1]; /* server stats commands array */

	/* init commands */
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.name = "tap";
	cmd.v.v0.nname = strlen(cmd.v.v0.name);

	/* get statistics */
	if ((rc = lcb_server_stats(instance, cookie, 1, commands)) == LCB_SUCCESS) {
		/* enter event look on success */
		lcb_wait(instance);
	}

	/* return error */
	return rc;
#else
	(void)cookie;
	(void)instance;
	return LCB_SUCCESS;
#endif
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
lcb_STATUS couchbase_store_key(lcb_INSTANCE *instance, const char *key, const char *document, int expire)
{
	lcb_STATUS rc;                      /* couchbase command return */
	lcb_CMDSTORE *cmd;                  /* store command stuct */

	/* init commands */
	lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);

	/* populate command struct */
	lcb_cmdstore_key(cmd, key, strlen(key));
	lcb_cmdstore_value(cmd, document, strlen(document));
	lcb_cmdstore_expiry(cmd, expire);

	/* store key/document in couchbase */
	if ((rc = lcb_store(instance, NULL, cmd)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance, LCB_WAIT_DEFAULT);
	}

	/* return error */
	lcb_cmdstore_destroy(cmd);

	return rc;
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
lcb_STATUS couchbase_get_key(lcb_INSTANCE *instance, const void *cookie, const char *key)
{
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = cookie;                   /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */
	lcb_STATUS rc;                   /* couchbase command return */
	lcb_CMDGET *cmd;                   /* get command struct */

	/* init commands */
	lcb_cmdget_create(&cmd);

	/* populate command struct */
 	lcb_cmdget_key(cmd, key, strlen(key));

	/* clear cookie */
	memset(c, 0, sizeof(cookie_t));

	/* init tokener error */
	c->jerr = json_tokener_success;

	/* create token */
	c->jtok = json_tokener_new();

	/* debugging */
	DEBUG3("fetching document %s", key);

	/* get document */
	if ((rc = lcb_get(instance, c, cmd)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance, LCB_WAIT_DEFAULT);
	}

	/* free token */
	json_tokener_free(c->jtok);

	lcb_cmdget_destroy(cmd);

	/* return error */
	return rc;
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
lcb_STATUS couchbase_query_view(lcb_INSTANCE *instance, const void *cookie, const char *path, const char *post)
{
	cookie_u cu;                         /* union of const and non const pointers */
	cu.cdata = cookie;                   /* set const union member to cookie passed from couchbase */
	cookie_t *c = (cookie_t *) cu.data;  /* set our cookie struct using non-const member */
	lcb_STATUS rc;                       /* couchbase command return */
	lcb_CMDHTTP *cmd;                    /* http command struct */
	lcb_HTTP_METHOD method = LCB_HTTP_METHOD_GET;
	char const *content_type = "application/json";

	/* populate command struct */
	lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_VIEW);

	lcb_cmdhttp_path(cmd, path, strlen(path));

	if (post) {
		method = LCB_HTTP_METHOD_POST;
		lcb_cmdhttp_body(cmd, post, strlen(post));
	}

	lcb_cmdhttp_method(cmd, method);
	lcb_cmdhttp_streaming(cmd, true);
	lcb_cmdhttp_content_type(cmd, content_type, strlen(content_type));

	/* clear cookie */
	memset(c, 0, sizeof(cookie_t));

	/* init tokener error */
	c->jerr = json_tokener_success;

	/* create token */
	c->jtok = json_tokener_new();

	/* debugging */
	/* we can't use REDEBUG() here, because that function is called by mod_instantiate -> mod_load_client_documents() */
	DEBUG3("fetching view %s", path);

	/* query the view */
	if ((rc = lcb_http(instance, c, cmd)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance, LCB_WAIT_DEFAULT);
	}

	/* free token */
	json_tokener_free(c->jtok);

	lcb_cmdhttp_destroy(cmd);

	/* return error */
	return rc;
}
