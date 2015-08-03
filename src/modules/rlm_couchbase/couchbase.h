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
 * @brief Couchbase wrapper function prototypes and datatypes.
 * @file couchbase.h
 *
 * @author Aaron Hurt <ahurt@anbcs.com>
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

#ifndef _couchbase_h_
#define _couchbase_h_

RCSIDH(couchbase_h, "$Id$")

#include <libcouchbase/couchbase.h>

#include "jsonc_missing.h"

/** Information relating to the parsing of Couchbase document payloads
 *
 * This structure holds various references to json-c objects used when parsing
 * Couchbase document payloads.
 */
typedef struct cookie_t {
	json_object *jobj;              //!< JSON objects handled by the json-c library.
	json_tokener *jtok;             //!< JSON tokener objects handled by the json-c library.
	enum json_tokener_error jerr;   //!< Error values produced by the json-c library.
} cookie_t;

/** Union of constant and non-constant pointers
 *
 * This is used to squelch compiler warnings about casting when passing data
 * between functions expecting different data types.
 */
typedef union cookie_u {
	const void *cdata;    //!< Constant pointer to cookie payload (@p cookie_t).
	void *data;           //!< Non-constant pointer to data payload (@p cookie_t).
} cookie_u;

/* couchbase statistics callback */
void couchbase_stat_callback(lcb_t instance, const void *cookie, lcb_error_t error,
	const lcb_server_stat_resp_t *resp);

/* store a key/document in couchbase */
void couchbase_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation,
	lcb_error_t error, const lcb_store_resp_t *item);

/* get a document by key from couchbase */
void couchbase_get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
	const lcb_get_resp_t *item);

/* couchbase http callback for data chunks */
void couchbase_http_data_callback(lcb_http_request_t request, lcb_t instance,
	const void *cookie, lcb_error_t error, const lcb_http_resp_t *resp);

/* create a couchbase instance and connect to the cluster */
lcb_error_t couchbase_init_connection(lcb_t *instance, const char *host, const char *bucket, const char *pass);

/* get server statistics */
lcb_error_t couchbase_server_stats(lcb_t instance, const void *cookie);

/* store document/key in couchbase */
lcb_error_t couchbase_set_key(lcb_t instance, const char *key, const char *document, int expire);

/* pull document from couchbase by key */
lcb_error_t couchbase_get_key(lcb_t instance, const void *cookie, const char *key);

/* query a couchbase view via http */
lcb_error_t couchbase_query_view(lcb_t instance, const void *cookie, const char *path, const char *post);

#endif /* _couchbase_h_ */
