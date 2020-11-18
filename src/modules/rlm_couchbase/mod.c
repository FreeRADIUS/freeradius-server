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
 * @brief Utillity functions used in the module.
 * @file mod.c
 *
 * @author Aaron Hurt (ahurt@anbcs.com)
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_couchbase - "

#include <freeradius-devel/json/base.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map.h>

#include "mod.h"
#include "couchbase.h"

/** Delete a connection pool handle and free related resources
 *
 * Destroys the underlying Couchbase connection handle freeing any related
 * resources and closes the socket connection.
 *
 * @param  chandle The connection handle to destroy.
 * @return 0.
 */
static int _mod_conn_free(rlm_couchbase_handle_t *chandle)
{
	lcb_t cb_inst = chandle->handle;                /* couchbase instance */

	/* destroy/free couchbase instance */
	lcb_destroy(cb_inst);

	/* return */
	return 0;
}

/** Delete a object built by mod_build_api_opts()
 *
 * Release the underlying mod_build_api_opts() objects
 *
 * @param  instance The module instance.
 * @return 0.
 */
int mod_free_api_opts(void *instance)
{
	rlm_couchbase_t *inst = instance;	/* our module instance */
	couchbase_opts_t *opts = inst->api_opts;

	if (!opts) return 0;

	DEBUG("Releasing the couchbase api options");

	for (; opts != NULL; opts = opts->next) {
		if (opts->key) talloc_free(opts->key);
		if (opts->val) talloc_free(opts->val);
	}

	talloc_free(opts);

	/* return */
	return 0;
}

/** Build a couchbase_opts_t structure from the configuration "couchbase_api" list
 *
 * Parse the "couchbase_api" list from the module configuration file and store this
 * as a couchbase_opts_t object (key/value list).
 *
 * @param  conf     Configuration list.
 * @param  instance The module instance.
 * @return
 *	 - 0 on success.
 *	- -1 on failure.
 */
int mod_build_api_opts(CONF_SECTION *conf, void *instance)
{
	rlm_couchbase_t *inst = instance;	/* our module instance */
	CONF_SECTION *cs;                	/* module config list */
	CONF_ITEM *ci;                   	/* config item */
	CONF_PAIR *cp;                   	/* config pair */
	couchbase_opts_t *entry = NULL;			/* couchbase api options */

	/* find opts list */
	cs = cf_section_find(conf, "opts", NULL);

	/* check list */
	if (!cs) return 0;

	/* parse libcouchbase_opts list */
	cf_log_debug(cs, "opts {");

	for (ci = cf_item_next(cs, NULL); ci != NULL; ci = cf_item_next(cs, ci)) {
		/*
		 *	Ignore things we don't care about.
		 */
		if (!cf_item_is_pair(ci)) {
			continue;
		}

		/* get value pair from item */
		cp = cf_item_to_pair(ci);

		/* create opts object */
		if (!entry) {
			entry = talloc_zero(inst, couchbase_opts_t);
			inst->api_opts = entry;
		} else {
			entry->next = talloc_zero(inst->api_opts, couchbase_opts_t);
			entry = entry->next;
		}
		entry->next = NULL;
		entry->key = talloc_typed_strdup(entry, cf_pair_attr(cp));
		entry->val = talloc_typed_strdup(entry, cf_pair_value(cp));

		/* debugging */
		cf_log_debug(cs, "\t%s = \"%s\"", entry->key, entry->val);
	}

	cf_log_debug(cs, "}");

	/* return */
	return 0;
}

/** Create a new connection pool handle
 *
 * Create a new connection to Couchbase within the pool and initialize
 * information associated with the connection instance.
 *
 * @param  ctx      The connection parent context.
 * @param  instance The module instance.
 * @param  timeout  Maximum time to establish the connection.
 * @return
 *	- New connection handle.
 *	- NULL on error.
 */
void *mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	rlm_couchbase_t const *inst = talloc_get_type_abort_const(instance, rlm_couchbase_t);           /* module instance pointer */
	rlm_couchbase_handle_t *chandle = NULL;     	  /* connection handle pointer */
	cookie_t *cookie = NULL;                          /* couchbase cookie */
	lcb_t cb_inst;                                    /* couchbase connection instance */
	lcb_error_t cb_error;			          /* couchbase error status */
	couchbase_opts_t const *opts = inst->api_opts;	  /* couchbase extra API settings */

	/* create instance */
	cb_error = couchbase_init_connection(&cb_inst, inst->server, inst->bucket, inst->username,
					     inst->password, fr_time_delta_to_sec(timeout), opts);

	/* check couchbase instance */
	if (cb_error != LCB_SUCCESS) {
		ERROR("failed to initiate couchbase connection: %s (0x%x)",
		      lcb_strerror(NULL, cb_error), cb_error);
		/* destroy/free couchbase instance */
		lcb_destroy(cb_inst);
		/* fail */
		return NULL;
	}

	/* allocate memory for couchbase connection instance abstraction */
	chandle = talloc_zero(ctx, rlm_couchbase_handle_t);
	talloc_set_destructor(chandle, _mod_conn_free);

	/* allocate cookie off handle */
	cookie = talloc_zero(chandle, cookie_t);

	/* init tokener error and json object */
	cookie->jerr = json_tokener_success;
	cookie->jobj = NULL;

	/* populate handle */
	chandle->cookie = cookie;
	chandle->handle = cb_inst;

	/* return handle struct */
	return chandle;
}

/** Check the health of a connection handle
 *
 * Attempt to determing the state of the Couchbase connection by requesting
 * a cluster statistics report.  Mark the connection as failed if the request
 * returns anything other than success.
 *
 * @param  instance The module instance (currently unused).
 * @param  handle   The connection handle.
 * @return
 *	- 0 on success (alive).
 *	- -1 on failure (unavailable).
 */
int mod_conn_alive(UNUSED void *instance, void *handle)
{
	rlm_couchbase_handle_t *chandle = handle;   /* connection handle pointer */
	lcb_t cb_inst = chandle->handle;            /* couchbase instance */
	lcb_error_t cb_error = LCB_SUCCESS;         /* couchbase error status */

	/* attempt to get server stats */
	if ((cb_error = couchbase_server_stats(cb_inst, NULL)) != LCB_SUCCESS) {
		/* log error */
		ERROR("failed to get couchbase server stats: %s (0x%x)",
		      lcb_strerror(NULL, cb_error), cb_error);
		/* error out */
		return -1;
	}
	return 0;
}

/** Build a JSON object map from the configuration "map" list
 *
 * Parse the "map" list from the module configuration file and store this
 * as a JSON object (key/value list) in the module instance.  This map will be
 * used to lookup and map attributes for all incoming accounting requests.
 *
 * @param  conf     Configuration list.
 * @param  instance The module instance.
 * @return
 *	 - 0 on success.
 *	- -1 on failure.
 */
int mod_build_attribute_element_map(CONF_SECTION *conf, void *instance)
{
	rlm_couchbase_t *inst = instance;   /* our module instance */
	CONF_SECTION *cs;                   /* module config list */
	CONF_ITEM *ci;                      /* config item */
	CONF_PAIR *cp;                      /* conig pair */
	const char *attribute, *element;    /* attribute and element names */

	/* find update list */
	cs = cf_section_find(conf, "update", NULL);

	/* backwards compatibility */
	if (!cs) {
		cs = cf_section_find(conf, "map", NULL);
		WARN("found deprecated 'map' list - please change to 'update'");
	}

	/* check list */
	if (!cs) {
		ERROR("failed to find 'update' list in config");
		/* fail */
		return -1;
	}

	/* create attribute map object */
	inst->map = json_object_new_object();

	/* parse update list */
	for (ci = cf_item_next(cs, NULL); ci != NULL; ci = cf_item_next(cs, ci)) {
		/* validate item */
		if (!cf_item_is_pair(ci)) {
			ERROR("failed to parse invalid item in 'update' list");
			/* free map */
			if (inst->map) {
				json_object_put(inst->map);
			}
			/* fail */
			return -1;
		}

		/* get value pair from item */
		cp = cf_item_to_pair(ci);

		/* get pair name (attribute name) */
		attribute = cf_pair_attr(cp);

		/* get pair value (element name) */
		element = cf_pair_value(cp);

		/* add pair name and value */
		json_object_object_add(inst->map, attribute, json_object_new_string(element));

		/* debugging */
		DEBUG3("added attribute '%s' to element '%s' mapping", attribute, element);
	}

	/* debugging */
	DEBUG3("built attribute to element mapping %s", json_object_to_json_string(inst->map));

	/* return */
	return 0;
}

/** Map attributes to JSON element names
 *
 * Attempt to map the passed attribute name to the configured JSON element
 * name using the JSON object map mod_build_attribute_element_map().
 *
 * @param  name The character name of the requested attribute.
 * @param  map  The JSON object map to use for the lookup.
 * @param  buf  The buffer where the given element will be stored if found.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int mod_attribute_to_element(const char *name, json_object *map, void *buf)
{
	json_object *j_value;  /* json object values */

	/* clear buffer */
	memset((char *) buf, 0, MAX_KEY_SIZE);

	/* attempt to map attribute */
	if (json_object_object_get_ex(map, name, &j_value)) {
		/* copy and check size */
		if (strlcpy(buf, json_object_get_string(j_value), MAX_KEY_SIZE) >= MAX_KEY_SIZE) {
			/* oops ... this value is bigger than our buffer ... error out */
			ERROR("json map value larger than MAX_KEY_SIZE - %d", MAX_KEY_SIZE);
			/* return fail */
			return -1;
		}
		/* looks good */
		return 0;
	}

	/* debugging */
	DEBUG("skipping attribute with no map entry - %s", name);

	/* default return */
	return -1;
}

/** Build value pairs from the passed JSON object and add to the request
 *
 * Parse the passed JSON object and create value pairs that will be injected into
 * the given request for authorization.
 *
 * Example JSON document structure:
 * @code{.json}
 * {
 *   "docType": "raduser",
 *   "userName": "test",
 *   "control": {
 *     "SHA-Password": {
 *       "value": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
 *       "op": ":="
 *     }
 *   },
 *   "reply": {
 *     "Reply-Message": {
 *       "value": "Hidey Ho!",
 *       "op": "="
 *     }
 *   }
 * }
 * @endcode
 *
 * @param[in] ctx	to allocate maps in.
 * @param[in] out	Cursor to append maps to.
 * @param[in] request	The request to which the generated pairs should be added.
 * @param[in] json	The JSON object representation of the user document.
 * @param[in] list	The pair list PAIR_LIST_CONTROL or PAIR_LIST_REPLY.
 * @return
 *	- 1 if no section found.
 *	- 0 on success.
 *	- <0 on error.
 */
int mod_json_object_to_map(TALLOC_CTX *ctx, fr_cursor_t *out, request_t *request, json_object *json, pair_list_t list)
{
	json_object	*list_obj;
	char const	*list_name = fr_table_str_by_value(pair_list_table, list, "<INVALID>");

	/*
	 *	Check for a section matching the specified list
	 */
	if (!json_object_object_get_ex(json, list_name, &list_obj)) {
		RDEBUG2("Couldn't find \"%s\" key in json object - Not adding value pairs for this attribute list",
		        list_name);

		return 1;
	}

	/*
	 *	Check the key representing the list is a JSON object
	 */
	if (!fr_json_object_is_type(list_obj, json_type_object)) {
		RERROR("Invalid json type for \"%s\" key - Attribute lists must be json objects", list_name);

		return -1;
	}

	fr_cursor_tail(out);				/* Wind to the end */

	/*
	 *	Loop through the keys in this object.
	 *
	 *	Where attr_name is the key, and attr_value_obj is
	 *	the object containing the attributes value and
	 *	operator.
	 */
	json_object_object_foreach(list_obj, attr_name, attr_value_obj) {
	 	json_object		*value_obj, *op_obj;
	 	fr_dict_attr_t const	*da;
		fr_token_t		op;

		if (!fr_json_object_is_type(attr_value_obj, json_type_object)) {
			REDEBUG("Invalid json type for \"%s\" key - Attributes must be json objects", attr_name);

		error:
			fr_cursor_free_list(out);	/* Free any maps we added */
			return -1;
		}

		RDEBUG3("Parsing %s - \"%s\" : { %s }", list_name,
			attr_name, json_object_to_json_string(attr_value_obj));

		/*
		 *	Check we have a value key
		 */
		if (!json_object_object_get_ex(attr_value_obj, "value", &value_obj)) {
			REDEBUG("Missing \"value\" key in: %s - \"%s\" : { %s }", list_name,
			        attr_name, json_object_to_json_string(attr_value_obj));

			goto error;
		}

		/*
		 *	Parse the operator and check its valid
		 */
		if (json_object_object_get_ex(attr_value_obj, "op", &op_obj)) {
			char const *op_str;

			op_str = json_object_get_string(op_obj);
			if (!op_str) {
			bad_op:
				REDEBUG("Invalid \"op\" key in: %s - \"%s\" : { %s }", list_name,
					attr_name, json_object_to_json_string(attr_value_obj));

				goto error;
			}

			op = fr_table_value_by_str(fr_tokens_table, op_str, T_INVALID);
			if (!fr_assignment_op[op] && !fr_equality_op[op]) goto bad_op;
		} else {
			op = T_OP_SET;	/* The default */
		}

		/*
		 *	Lookup the string attr_name in the
		 *	request dictionary.
		 */
		da = fr_dict_attr_by_name(NULL, fr_dict_root(request->dict), attr_name);
		if (!da) {
			RPERROR("Invalid attribute \"%s\"", attr_name);
			goto error;
		}

		/*
		 *	Create a map representing the operation
		 */
		{
			fr_value_box_t	tmp = { .type = FR_TYPE_INVALID };
			map_t	*map;

			if (fr_json_object_to_value_box(ctx, &tmp, value_obj, da, true) < 0) {
			bad_value:
				RPERROR("Failed parsing value for \"%s\"", attr_name);
				goto error;
			}

			if (fr_value_box_cast_in_place(ctx, &tmp, da->type, da) < 0) {
				fr_value_box_clear(&tmp);
				goto bad_value;
			}

			if (map_afrom_value_box(ctx, &map,
						attr_name, T_BARE_WORD,
						&(tmpl_rules_t){
							.dict_def = request->dict,
							.list_def = list,
						},
						op,
						&tmp, true) < 0) {
				fr_value_box_clear(&tmp);
				goto bad_value;
			}

			fr_cursor_insert(out, map);
		}
	}

	return 0;
}

/** Convert value pairs to json objects
 *
 * Take the passed value pair and convert it to a json-c JSON object.
 * This code is heavily based on the fr_json_from_pair() function
 * from src/lib/print.c.
 *
 * @param  request The request object.
 * @param  vp      The value pair to convert.
 * @return A JSON object.
 */
json_object *mod_value_pair_to_json_object(request_t *request, fr_pair_t *vp)
{
	char value[255];    /* radius attribute value */

	/* add this attribute/value pair to our json output */
	{
		unsigned int i;

		switch (vp->vp_type) {
		case FR_TYPE_UINT32:
			i = vp->vp_uint32;
			goto print_int;

		case FR_TYPE_UINT16:
			i = vp->vp_uint16;
			goto print_int;

		case FR_TYPE_UINT8:
			i = vp->vp_uint8;

		print_int:
			/* skip if we have flags */
			if (vp->da->flags.has_value) break;
#ifdef HAVE_JSON_OBJECT_NEW_INT64
			/* debug */
			RDEBUG3("creating new int64 for unsigned 32 bit int/byte/short '%s'", vp->da->name);
			/* return as 64 bit int - JSON spec does not support unsigned ints */
			return json_object_new_int64(i);
#else
			/* debug */
			RDEBUG3("creating new int for unsigned 32 bit int/byte/short '%s'", vp->da->name);
			/* return as 64 bit int - JSON spec does not support unsigned ints */
			return json_object_new_int(i);
#endif

		case FR_TYPE_INT32:
#ifdef HAVE_JSON_OBJECT_NEW_INT64
			/* debug */
			RDEBUG3("creating new int64 for signed 32 bit integer '%s'", vp->da->name);
			/* return as 64 bit int - json-c represents all ints as 64 bits internally */
			return json_object_new_int64(vp->vp_int32);
#else
			RDEBUG3("creating new int for signed 32 bit integer '%s'", vp->da->name);
			/* return as signed int */
			return json_object_new_int(vp->vp_int32);
#endif

		case FR_TYPE_UINT64:
#ifdef HAVE_JSON_OBJECT_NEW_INT64
			/* debug */
			RDEBUG3("creating new int64 for 64 bit integer '%s'", vp->da->name);
			/* return as 64 bit int - because it is a 64 bit int */
			return json_object_new_int64(vp->vp_uint64);
#else
			/* warning */
			RWARN("skipping 64 bit integer attribute '%s' - please upgrade json-c to 0.10+", vp->da->name);
			break;
#endif

		default:
			/* silence warnings - do nothing */
		break;
		}
	}

	/* keep going if not set above */
	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		/* debug */
		RDEBUG3("assigning string '%s' as string", vp->da->name);
		/* return string value */
		return json_object_new_string(vp->vp_strvalue);

	default:
		/* debug */
		RDEBUG3("assigning unhandled '%s' as string", vp->da->name);
		/* get standard value */
		fr_pair_print_value_quoted(&FR_SBUFF_OUT(value, sizeof(value)), vp, T_BARE_WORD);
		/* return string value from above */
		return json_object_new_string(value);
	}
}

/** Ensure accounting documents always contain a valid timestamp
 *
 * Inspect the given JSON object representation of an accounting document
 * fetched from Couchbase and ensuse it contains a valid (non NULL) timestamp value.
 *
 * @param  json JSON object representation of an accounting document.
 * @param  vps  The value pairs associated with the current accounting request.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int mod_ensure_start_timestamp(json_object *json, fr_pair_t *vps)
{
	json_object *j_value;      /* json object value */
	struct tm tm;           /* struct to hold event time */
	time_t ts = 0;          /* values to hold time in seconds */
	fr_pair_t *vp;         /* values to hold value pairs */
	char value[255];        /* store radius attribute values and our timestamp */

	/* get our current start timestamp from our json body */
	if (json_object_object_get_ex(json, "startTimestamp", &j_value) == 0) {
		/* debugging ... this shouldn't ever happen */
		DEBUG("failed to find 'startTimestamp' in current json body");
		/* return */
		return -1;
	}

	/* check for null value */
	if (json_object_get_string(j_value) != NULL) {
		/* already set - nothing left to do */
		return 0;
	}

	/* get current event timestamp */
	if ((vp = fr_pair_find_by_da(&vps, attr_event_timestamp)) != NULL) {
		/* get seconds value from attribute */
		ts = fr_time_to_sec(vp->vp_date);
	} else {
		/* debugging */
		DEBUG("failed to find event timestamp in current request");
		/* return */
		return -1;
	}

	/* clear value */
	memset(value, 0, sizeof(value));

	/* get elapsed session time */
	if ((vp = fr_pair_find_by_da(&vps, attr_acct_session_time)) != NULL) {
		/* calculate diff */
		ts = (ts - vp->vp_uint32);
		/* calculate start time */
		size_t length = strftime(value, sizeof(value), "%b %e %Y %H:%M:%S %Z", localtime_r(&ts, &tm));
		/* check length */
		if (length > 0) {
			/* debugging */
			DEBUG("calculated start timestamp: %s", value);
			/* store new value in json body */
			json_object_object_add(json, "startTimestamp", json_object_new_string(value));
		} else {
			/* debugging */
			DEBUG("failed to format calculated timestamp");
			/* return */
			return -1;
		}
	}

	/* default return */
	return 0;
}

/** Handle client value processing for client_map_section()
 *
 * @param  out  Character output
 * @param  cp   Configuration pair
 * @param  data The client data
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _get_client_value(char **out, CONF_PAIR const *cp, void *data)
{
	json_object *j_value;

	if (!json_object_object_get_ex((json_object *)data, cf_pair_value(cp), &j_value)) {
		*out = NULL;
		return 0;
	}

	if (!j_value) return -1;

	*out = talloc_strdup(NULL, json_object_get_string(j_value));
	if (!*out) return -1;

	return 0;
}

/** Load client entries from Couchbase client documents on startup
 *
 * This function executes the view defined in the module configuration and loops
 * through all returned rows.  The view is called with "stale=false" to ensure the
 * most accurate data available when the view is called.  This will force an index
 * rebuild on this design document in Couchbase.  However, since this function is only
 * run once at server startup this should not be a concern.
 *
 * @param  inst The module instance.
 * @param  tmpl Default values for new clients.
 * @param  map  The client attribute configuration list.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int mod_load_client_documents(rlm_couchbase_t *inst, CONF_SECTION *tmpl, CONF_SECTION *map)
{
	rlm_couchbase_handle_t *handle = NULL; /* connection pool handle */
	char vpath[256], vid[MAX_KEY_SIZE], vkey[MAX_KEY_SIZE];  /* view path and fields */
	char error[512];                                         /* view error return */
	int idx = 0;                                             /* row array index counter */
	int retval = 0;                                          /* return value */
	lcb_error_t cb_error = LCB_SUCCESS;                      /* couchbase error holder */
	json_object *json, *j_value;                                /* json object holders */
	json_object *jrows = NULL;                               /* json object to hold view rows */
	CONF_SECTION *client;                                    /* freeradius config list */
	RADCLIENT *c;                                            /* freeradius client */

	/* get handle */
	handle = fr_pool_connection_get(inst->pool, NULL);

	/* check handle */
	if (!handle) return -1;

	/* set couchbase instance */
	lcb_t cb_inst = handle->handle;

	/* set cookie */
	cookie_t *cookie = handle->cookie;

	/* build view path */
	snprintf(vpath, sizeof(vpath), "%s?stale=false", inst->client_view);

	/* query view for document */
	cb_error = couchbase_query_view(cb_inst, cookie, vpath, NULL);

	/* check error and object */
	if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || !cookie->jobj) {
		/* log error */
		ERROR("failed to execute view request or parse return");
		/* set return */
		retval = -1;
		/* return */
		goto free_and_return;
	}

	/* debugging */
	DEBUG3("cookie->jobj == %s", json_object_to_json_string(cookie->jobj));

	/* check for error in json object */
	if (json_object_object_get_ex(cookie->jobj, "error", &json)) {
		/* build initial error buffer */
		strlcpy(error, json_object_get_string(json), sizeof(error));
		/* get error reason */
		if (json_object_object_get_ex(cookie->jobj, "reason", &json)) {
			/* append divider */
			strlcat(error, " - ", sizeof(error));
			/* append reason */
			strlcat(error, json_object_get_string(json), sizeof(error));
		}
		/* log error */
		ERROR("view request failed with error: %s", error);
		/* set return */
		retval = -1;
		/* return */
		goto free_and_return;
	}

	/* check for document id in return */
	if (!json_object_object_get_ex(cookie->jobj, "rows", &json)) {
		/* log error */
		ERROR("failed to fetch rows from view payload");
		/* set return */
		retval = -1;
		/* return */
		goto free_and_return;
	}

	/* get and hold rows */
	jrows = json_object_get(json);

	/* free cookie object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* debugging */
	DEBUG3("jrows == %s", json_object_to_json_string(jrows));

	/* check for valid row value */
	if (!fr_json_object_is_type(jrows, json_type_array) || json_object_array_length(jrows) < 1) {
		/* log error */
		ERROR("no valid rows returned from view: %s", vpath);
		/* set return */
		retval = -1;
		/* return */
		goto free_and_return;
	}

	/* loop across all row elements */
	for (idx = 0; (size_t)idx < (size_t)json_object_array_length(jrows); idx++) {
		/* fetch current index */
		json = json_object_array_get_idx(jrows, idx);

		/* get view id */
		if (json_object_object_get_ex(json, "id", &j_value)) {
			/* clear view id */
			memset(vid, 0, sizeof(vid));
			/* copy and check length */
			if (strlcpy(vid, json_object_get_string(j_value), sizeof(vid)) >= sizeof(vid)) {
				ERROR("id from row longer than MAX_KEY_SIZE (%d)",
				      MAX_KEY_SIZE);
				continue;
			}
		} else {
			WARN("failed to fetch id from row - skipping");
			continue;
		}

		/* get view key */
		if (json_object_object_get_ex(json, "key", &j_value)) {
			/* clear view key */
			memset(vkey, 0, sizeof(vkey));
			/* copy and check length */
			if (strlcpy(vkey, json_object_get_string(j_value), sizeof(vkey)) >= sizeof(vkey)) {
				ERROR("key from row longer than MAX_KEY_SIZE (%d)",
				      MAX_KEY_SIZE);
				continue;
			}
		} else {
			WARN("failed to fetch key from row - skipping");
			continue;
		}

		/* fetch document */
		cb_error = couchbase_get_key(cb_inst, cookie, vid);

		/* check error and object */
		if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || !cookie->jobj) {
			/* log error */
			ERROR("failed to execute get request or parse return");
			/* set return */
			retval = -1;
			/* return */
			goto free_and_return;
		}

		/* debugging */
		DEBUG3("cookie->jobj == %s", json_object_to_json_string(cookie->jobj));

		/* allocate conf list */
		client = tmpl ? cf_section_dup(NULL, NULL, tmpl, "client", vkey, true) :
				cf_section_alloc(NULL, NULL, "client", vkey);

		if (client_map_section(client, map, _get_client_value, cookie->jobj) < 0) {
			/* free config setion */
			talloc_free(client);
			/* set return */
			retval = -1;
			/* return */
			goto free_and_return;
		}

		/*
		 * @todo These should be parented from something.
		 */
		c = client_afrom_cs(NULL, client, false);
		if (!c) {
			ERROR("failed to allocate client");
			/* free config setion */
			talloc_free(client);
			/* set return */
			retval = -1;
			/* return */
			goto free_and_return;
		}

		/*
		 * Client parents the CONF_SECTION which defined it.
		 */
		talloc_steal(c, client);

		/* attempt to add client */
		if (!client_add(NULL, c)) {
			ERROR("failed to add client '%s' from '%s', possible duplicate?", vkey, vid);
			/* free client */
			client_free(c);
			/* set return */
			retval = -1;
			/* return */
			goto free_and_return;
		}

		/* debugging */
		DEBUG("client '%s' added", c->longname);

		/* free json object */
		if (cookie->jobj) {
			json_object_put(cookie->jobj);
			cookie->jobj = NULL;
		}
	}

	free_and_return:

	/* free rows */
	if (jrows) {
		json_object_put(jrows);
	}

	/* free json object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* release handle */
	if (handle) fr_pool_connection_release(inst->pool, NULL, handle);

	/* return */
	return retval;
}
