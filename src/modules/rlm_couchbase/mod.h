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
 * @brief Function prototypes and datatypes used in the module.
 * @file mod.h
 *
 * @copyright 2013-2014 Aaron Hurt <ahurt@anbcs.com>
 */

#ifndef _mod_h_
#define _mod_h_

RCSIDH(mod_h, "$Id$");

#include <libcouchbase/couchbase.h>
#include <json/json.h>

#include "jsonc_missing.h"

/* maximum size of a stored value */
#define MAX_VALUE_SIZE 20480

/* maximum length of a document key */
#define MAX_KEY_SIZE 250

/* configuration struct */
typedef struct rlm_couchbase_t {
	const char *acctkey;            /* accounting document key */
	const char *doctype;            /* value of 'docType' element name */
	char *server;                   /* couchbase server list */
	const char *bucket;             /* couchbase bucket */
	const char *pass;               /* couchbase bucket password */
	unsigned int expire;            /* document expire time in seconds */
	const char *userkey;            /* user document key */
	json_object *map;               /* json object to hold user defined attribute map */
	fr_connection_pool_t *pool;     /* connection pool */
} rlm_couchbase_t;

/* connection pool handle struct */
typedef struct rlm_couchbase_handle_t {
	void *handle;    /* real couchbsae instance */
	void *cookie;    /* couchbase cookie */
} rlm_couchbase_handle_t;

/* define functions */
void *mod_conn_create(void *instance);

int mod_conn_alive(UNUSED void *instance, void *handle);

int mod_conn_delete(UNUSED void *instance, void *handle);

int mod_build_attribute_element_map(CONF_SECTION *conf, void *instance);

int mod_attribute_to_element(const char *name, json_object *map, void *buf);

void *mod_json_object_to_value_pairs(json_object *json, const char *section, REQUEST *request);

json_object *mod_value_pair_to_json_object(REQUEST *request, VALUE_PAIR *vp);

int mod_ensure_start_timestamp(json_object *json, VALUE_PAIR *vps);

#endif /* _mod_h_ */
