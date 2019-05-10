#pragma once
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
 * @brief Function prototypes and datatypes used in the module.
 * @file mod.h
 *
 * @author Aaron Hurt (ahurt@anbcs.com)
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */
RCSIDH(mod_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/pool.h>

#include <freeradius-devel/json/base.h>

/* maximum size of a stored value */
#define MAX_VALUE_SIZE 20480

/* maximum length of a document key */
#define MAX_KEY_SIZE 250

/** The main module instance
 *
 * This struct contains the core module configuration.
 */
typedef struct {
	vp_tmpl_t		*acct_key;		//!< Accounting document key.
	char const		*doctype;		//!< Value of accounting 'docType' element name.
	uint32_t		expire;			//!< Accounting document expire time in seconds.

	char const		*server_raw;     	//!< Raw server string before parsing.
	char const		*server;         	//!< Couchbase server list.
	char const		*bucket;         	//!< Couchbase bucket.
	char const		*username;       	//!< Couchbase bucket username.
	char const		*password;       	//!< Couchbase bucket password.

	vp_tmpl_t		*user_key;       	//!< User document key.

	json_object		*map;           	//!< Json object to hold user defined attribute map.
	fr_pool_t		*pool;			//!< Connection pool.
	char const		*name;			//!< Module instance name.
	void			*api_opts;		//!< Couchbase API internal options.
} rlm_couchbase_t;

/** Couchbase instance specific information
 *
 * This struct contains the Couchbase connection handle as well as a
 * cookie pointer to store fetched document payloads.
 */
typedef struct {
	void *handle;    //!< Real couchbase instance.
	void *cookie;    //!< Couchbase cookie (@p cookie_u @p cookie_t).
} rlm_couchbase_handle_t;

/* define functions */
void *mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout);

int mod_conn_alive(UNUSED void *instance, void *handle);

int mod_build_attribute_element_map(CONF_SECTION *conf, void *instance);

int mod_attribute_to_element(const char *name, json_object *map, void *buf);

int mod_json_object_to_map(TALLOC_CTX *ctx, fr_cursor_t *out, REQUEST *request, json_object *json, pair_list_t list);

json_object *mod_value_pair_to_json_object(REQUEST *request, VALUE_PAIR *vp);

int mod_ensure_start_timestamp(json_object *json, VALUE_PAIR *vps);

int mod_build_api_opts(CONF_SECTION *conf, void *instance);

int mod_free_api_opts(void *instance);

