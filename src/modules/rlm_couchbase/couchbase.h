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
 * @brief Couchbase wrapper function prototypes and datatypes.
 * @file couchbase.h
 *
 * @copyright 2013-2014 Aaron Hurt <ahurt@anbcs.com>
 */

#ifndef _couchbase_h_
#define _couchbase_h_

RCSIDH(couchbase_h, "$Id$");

#include <libcouchbase/couchbase.h>
#include <json.h>

/* struct to hold cookie data for couchbase callbacks */
typedef struct cookie_t {
	json_object *jobj;              /* json object */
	json_tokener *jtok;             /* json tokener */
	enum json_tokener_error jerr;   /* tokener error */
} cookie_t;

/* union of const and non const pointers */
typedef union cookie_u {
	const void *cdata;
	void *data;
} cookie_u;

/* general error callback */
void couchbase_error_callback(lcb_t instance, lcb_error_t error, const char *errinfo);

/* store a key/document in couchbase */
void couchbase_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation,
	lcb_error_t error, const lcb_store_resp_t *item);

/* get a document by key from couchbase */
void couchbase_get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
	const lcb_get_resp_t *item);

/* create a couchbase instance and connect to the cluster */
lcb_t couchbase_init_connection(const char *host, const char *bucket, const char *pass);

/* store document/key in couchbase */
lcb_error_t couchbase_set_key(lcb_t instance, const char *key, const char *document, int expire);

/* pull document from couchbase by key */
lcb_error_t couchbase_get_key(lcb_t instance, const void *cookie, const char *key);

#endif /* _couchbase_h_ */
