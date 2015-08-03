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
 * @author Aaron Hurt <ahurt@anbcs.com>
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

#ifndef _mod_h_
#define _mod_h_

RCSIDH(mod_h, "$Id$")

#include <freeradius-devel/radiusd.h>

#include <libcouchbase/couchbase.h>

#include "jsonc_missing.h"

/* maximum size of a stored value */
#define MAX_VALUE_SIZE 20480

/* maximum length of a document key */
#define MAX_KEY_SIZE 250

/** The main module instance
 *
 * This struct contains the core module configuration.
 */
typedef struct rlm_couchbase_t {
	char const		*acct_key;		//!< Accounting document key.
	char const		*doctype;		//!< Value of accounting 'docType' element name.
	uint32_t		expire;			//!< Accounting document expire time in seconds.

	char const		*server_raw;     	//!< Raw server string before parsing.
	char const		*server;         	//!< Couchbase server list.
	char const		*bucket;         	//!< Couchbase bucket.
	char const		*password;       	//!< Couchbase bucket password.

	const char		*user_key;       	//!< User document key.

	bool			read_clients;		//!< Toggle for loading client records.
	const char		*client_view;    	//!< Couchbase view that returns client documents.

	bool			check_simul;		//!< Toggle to enable simultaneous use checking.
	const char		*simul_view;     	//!< Couchbase view that returns accounting documents.

	bool			verify_simul;		//!< Toggle to enable user login state verification.
	const char		*simul_vkey;		//!< The query key to be used with simul_view.
	bool			delete_stale_sessions;	//!< Toggle to trigger zapping of stale sessions.

	json_object		*map;           	//!< Json object to hold user defined attribute map.
	fr_connection_pool_t	*pool;			//!< Connection pool.
} rlm_couchbase_t;

/** Couchbase instance specific information
 *
 * This struct contains the Couchbase connection handle as well as a
 * cookie pointer to store fetched document payloads.
 */
typedef struct rlm_couchbase_handle_t {
	void *handle;    //!< Real couchbase instance.
	void *cookie;    //!< Couchbase cookie (@p cookie_u @p cookie_t).
} rlm_couchbase_handle_t;

/* define functions */
void *mod_conn_create(TALLOC_CTX *ctx, void *instance);

int mod_build_attribute_element_map(CONF_SECTION *conf, void *instance);

int mod_attribute_to_element(const char *name, json_object *map, void *buf);

void *mod_json_object_to_value_pairs(json_object *json, const char *section, REQUEST *request);

json_object *mod_value_pair_to_json_object(REQUEST *request, VALUE_PAIR *vp);

int mod_ensure_start_timestamp(json_object *json, VALUE_PAIR *vps);

int mod_client_map_section(CONF_SECTION *client, CONF_SECTION const *map, json_object *json, char const *docid);

int mod_load_client_documents(rlm_couchbase_t *inst, CONF_SECTION *tmpl, CONF_SECTION *map);

#endif /* _mod_h_ */
