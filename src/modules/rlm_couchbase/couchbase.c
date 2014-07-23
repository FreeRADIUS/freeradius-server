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

/*
 * $Id$
 *
 * @brief Wrapper functions around the libcouchbase Couchbase client driver.
 * @file couchbase.c
 *
 * @copyright 2013-2014 Aaron Hurt <ahurt@anbcs.com>
 */

RCSID("$Id$");

#include <freeradius-devel/radiusd.h>

#include <libcouchbase/couchbase.h>
#include <json.h>

#include "couchbase.h"
#include "jsonc_missing.h"

/* general couchbase error callback */
void couchbase_error_callback(lcb_t instance, lcb_error_t error, const char *errinfo) {
	/* log error */
	ERROR("rlm_couchbase: (error_callback) %s (0x%x), %s", lcb_strerror(instance, error), error, errinfo);
}

/* couchbase value store callback */
void couchbase_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation, lcb_error_t error, const lcb_store_resp_t *resp) {
	if (error != LCB_SUCCESS) {
		/* log error */
		ERROR("rlm_couchbase: (store_callback) %s (0x%x)", lcb_strerror(instance, error), error);
	}
	/* silent compiler */
	(void)cookie;
	(void)operation;
	(void)resp;
}

/* couchbase value get callback */
void couchbase_get_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_get_resp_t *resp) {
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
			/* build json object */
			c->jobj = json_tokener_parse_verbose(bytes, &c->jerr);
			/* switch on current error status */
			switch (c->jerr) {
			case json_tokener_success:
				/* do nothing */
				break;

			default:
				/* log error */
				ERROR("rlm_couchbase: (get_callback) JSON Tokener error: %s", json_tokener_error_desc(c->jerr));
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

/* connect to couchbase */
lcb_t couchbase_init_connection(const char *host, const char *bucket, const char *pass) {
	lcb_t instance;                         /* couchbase instance */
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
	if ((error = lcb_create(&instance, &options)) != LCB_SUCCESS) {
		/* log error and return */
		ERROR("rlm_couchbase: failed to create couchbase instance: %s (0x%x)", lcb_strerror(NULL, error), error);
		/* return instance */
		return instance;
	}

	/* initiate connection */
	if ((error = lcb_connect(instance)) == LCB_SUCCESS) {
		/* set general method callbacks */
		lcb_set_error_callback(instance, couchbase_error_callback);
		lcb_set_get_callback(instance, couchbase_get_callback);
		lcb_set_store_callback(instance, couchbase_store_callback);
		/* wait on connection */
		lcb_wait(instance);
	} else {
		/* log error */
		ERROR("rlm_couchbase: Failed to initiate couchbase connection: %s (0x%x)", lcb_strerror(NULL, error), error);
	}

	/* return instance */
	return instance;
}

/* store document/key in couchbase */
lcb_error_t couchbase_set_key(lcb_t instance, const char *key, const char *document, int expire) {
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

/* pull document from couchbase by key */
lcb_error_t couchbase_get_key(lcb_t instance, const void *cookie, const char *key) {
	lcb_error_t error;                  /* couchbase command return */
	lcb_get_cmd_t cmd;                  /* get command struct */
	const lcb_get_cmd_t *commands[1];   /* get commands array */

	/* init commands */
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));

	/* populate command struct */
	cmd.v.v0.key = key;
	cmd.v.v0.nkey = strlen(cmd.v.v0.key);

	/* get document */
	if ((error = lcb_get(instance, cookie, 1, commands)) == LCB_SUCCESS) {
		/* enter event loop on success */
		lcb_wait(instance);
	}

	/* return error */
	return error;
}
