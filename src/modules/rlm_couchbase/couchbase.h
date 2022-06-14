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
 * @brief Couchbase wrapper function prototypes and datatypes.
 * @file couchbase.h
 *
 * @author Aaron Hurt (ahurt@anbcs.com)
 * @copyright 2013-2022 The FreeRADIUS Server Project.
 */
RCSIDH(couchbase_h, "$Id$")

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <libcouchbase/couchbase.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

#include <freeradius-devel/json/base.h>

/** Information relating to the parsing of Couchbase document payloads
 *
 * This structure holds various references to json-c objects used when parsing
 * Couchbase document payloads.
 */
typedef struct {
	json_object		*jobj;	//!< JSON objects handled by the json-c library.
	json_tokener		*jtok;	//!< JSON tokener objects handled by the json-c library.
	enum json_tokener_error	jerr;   //!< Error values produced by the json-c library.
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

/**
 * This may be used to provide a simple interface from a command line or higher
 * evel language to allow the setting of specific key-value pairs.
 *
 * Options ref: https://docs.couchbase.com/sdk-api/couchbase-c-client-2.5.6/group__lcb-cntl.html
 */
typedef struct couchbase_opts_s couchbase_opts_t;
struct couchbase_opts_s {
    char *key;				//!< Key value for lcb_cntl_string().
    char *val;				//!< Value for the key used in lcb_cntl_string().
    couchbase_opts_t *next; 		//!< Linked list.
};

extern HIDDEN fr_dict_attr_t const *attr_acct_status_type;
extern HIDDEN fr_dict_attr_t const *attr_acct_session_time;
extern HIDDEN fr_dict_attr_t const *attr_event_timestamp;

/* couchbase statistics callback */
// void couchbase_stats_callback(UNUSED lcb_INSTANCE *instance, UNUSED lcb_CALLBACK_TYPE cbtype, const lcb_RESPBASE *rb);

/* store a key/document in couchbase */
void couchbase_store_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb);

/* get a document by key from couchbase */
void couchbase_get_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb);

/* couchbase http callback for data chunks */
void couchbase_http_data_callback(UNUSED lcb_INSTANCE *instance, UNUSED int cbtype, const lcb_RESPBASE *rb);

/* create a couchbase instance and connect to the cluster */
lcb_STATUS couchbase_init_connection(lcb_INSTANCE **instance, const char *host, const char *bucket, const char *user,
					const char *pass, int64_t timeout, const couchbase_opts_t *opts);

/* get server statistics */
lcb_STATUS couchbase_server_stats(lcb_INSTANCE *instance, const void *cookie);

/* store document/key in couchbase */
lcb_STATUS couchbase_store_key(lcb_INSTANCE *instance, const char *key, const char *document, int expire);

/* pull document from couchbase by key */
lcb_STATUS couchbase_get_key(lcb_INSTANCE *instance, const void *cookie, const char *key);

/* query a couchbase view via http */
lcb_STATUS couchbase_query_view(lcb_INSTANCE *instance, const void *cookie, const char *path, const char *post);
