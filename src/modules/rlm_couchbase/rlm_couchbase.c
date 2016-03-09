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
 * @brief Integrate FreeRADIUS with the Couchbase document database.
 * @file rlm_couchbase.c
 *
 * @author Aaron Hurt <ahurt@anbcs.com>
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <libcouchbase/couchbase.h>

#include "mod.h"
#include "couchbase.h"
#include "jsonc_missing.h"

/**
 * Client Configuration
 */
static const CONF_PARSER client_config[] = {
	{ "view", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_couchbase_t, client_view), "_design/client/_view/by_name" },
	CONF_PARSER_TERMINATOR
};

/**
 * Module Configuration
 */
static const CONF_PARSER module_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_couchbase_t, server_raw), NULL },
	{ "bucket", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_couchbase_t, bucket), NULL },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_couchbase_t, password), NULL },
#ifdef WITH_ACCOUNTING
	{ "acct_key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_couchbase_t, acct_key), "radacct_%{%{Acct-Unique-Session-Id}:-%{Acct-Session-Id}}" },
	{ "doctype", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_couchbase_t, doctype), "radacct" },
	{ "expire", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_couchbase_t, expire), 0 },
#endif
	{ "user_key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_couchbase_t, user_key), "raduser_%{md5:%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}}" },
	{ "read_clients", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_couchbase_t, read_clients), NULL }, /* NULL defaults to "no" */
	{ "client", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) client_config },
#ifdef WITH_SESSION_MGMT
	{ "check_simul", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_couchbase_t, check_simul), NULL }, /* NULL defaults to "no" */
	{ "simul_view", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_couchbase_t, simul_view), "_design/acct/_view/by_user" },
	{ "simul_vkey", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_couchbase_t, simul_vkey), "%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}" },
	{ "verify_simul", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_couchbase_t, verify_simul), NULL }, /* NULL defaults to "no" */
#endif
	CONF_PARSER_TERMINATOR
};

/** Initialize the rlm_couchbase module
 *
 * Intialize the module and create the initial Couchbase connection pool.
 *
 * @param  conf     The module configuration.
 * @param  instance The module instance.
 * @return          Returns 0 on success, -1 on error.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	static bool version_done;

	rlm_couchbase_t *inst = instance;   /* our module instance */

	if (!version_done) {
		version_done = true;
		INFO("rlm_couchbase: json-c version: %s", json_c_version());
		INFO("rlm_couchbase: libcouchbase version: %s", lcb_get_version(NULL));
	}

	{
		char *server, *p;
		size_t len, i;
		bool sep = false;

		len = talloc_array_length(inst->server_raw);
		server = p = talloc_array(inst, char, len);
		for (i = 0; i < len; i++) {
			switch (inst->server_raw[i]) {
			case '\t':
			case ' ':
			case ',':
				/* Consume multiple separators occurring in sequence */
				if (sep == true) continue;

				sep = true;
				*p++ = ';';
				break;

			default:
				sep = false;
				*p++ = inst->server_raw[i];
				break;
			}
		}

		*p = '\0';
		inst->server = server;
	}

	/* setup item map */
	if (mod_build_attribute_element_map(conf, inst) != 0) {
		/* fail */
		return -1;
	}

	/* initiate connection pool */
	inst->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, NULL);

	/* check connection pool */
	if (!inst->pool) {
		ERROR("rlm_couchbase: failed to initiate connection pool");
		/* fail */
		return -1;
	}

	/* load clients if requested */
	if (inst->read_clients) {
		CONF_SECTION *cs, *map, *tmpl; /* conf section */

		/* attempt to find client section */
		cs = cf_section_sub_find(conf, "client");
		if (!cs) {
			ERROR("rlm_couchbase: failed to find client section while loading clients");
			/* fail */
			return -1;
		}

		/* attempt to find attribute subsection */
		map = cf_section_sub_find(cs, "attribute");
		if (!map) {
			ERROR("rlm_couchbase: failed to find attribute subsection while loading clients");
			/* fail */
			return -1;
		}

		tmpl = cf_section_sub_find(cs, "template");

		/* debugging */
		DEBUG("rlm_couchbase: preparing to load client documents");

		/* attempt to load clients */
		if (mod_load_client_documents(inst, tmpl, map) != 0) {
			/* fail */
			return -1;
		}
	}

	/* return okay */
	return 0;
}

/** Handle authorization requests using Couchbase document data
 *
 * Attempt to fetch the document assocaited with the requested user by
 * using the deterministic key defined in the configuration.  When a valid
 * document is found it will be parsed and the containing value pairs will be
 * injected into the request.
 *
 * @param  instance The module instance.
 * @param  request  The authorization request.
 * @return          Returns operation status (@p rlm_rcode_t).
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_couchbase_t *inst = instance;       /* our module instance */
	rlm_couchbase_handle_t *handle = NULL;  /* connection pool handle */
	char dockey[MAX_KEY_SIZE];              /* our document key */
	lcb_error_t cb_error = LCB_SUCCESS;     /* couchbase error holder */
	rlm_rcode_t rcode = RLM_MODULE_OK;      /* return code */

	/* assert packet as not null */
	rad_assert(request->packet != NULL);

	/* attempt to build document key */
	if (radius_xlat(dockey, sizeof(dockey), request, inst->user_key, NULL, NULL) < 0) {
		/* log error */
		RERROR("could not find user key attribute (%s) in packet", inst->user_key);
		/* return */
		return RLM_MODULE_FAIL;
	}

	/* get handle */
	handle = fr_connection_get(inst->pool);

	/* check handle */
	if (!handle) return RLM_MODULE_FAIL;

	/* set couchbase instance */
	lcb_t cb_inst = handle->handle;

	/* set cookie */
	cookie_t *cookie = handle->cookie;

	/* fetch document */
	cb_error = couchbase_get_key(cb_inst, cookie, dockey);

	/* check error */
	if (cb_error != LCB_SUCCESS || !cookie->jobj) {
		/* log error */
		RERROR("failed to fetch document or parse return");
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* debugging */
	RDEBUG3("parsed user document == %s", json_object_to_json_string(cookie->jobj));

	/* inject config value pairs defined in this json oblect */
	mod_json_object_to_value_pairs(cookie->jobj, "config", request);

	/* inject reply value pairs defined in this json oblect */
	mod_json_object_to_value_pairs(cookie->jobj, "reply", request);

	finish:

	/* free json object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* release handle */
	if (handle) {
		fr_connection_release(inst->pool, handle);
	}

	/* return */
	return rcode;
}

#ifdef WITH_ACCOUNTING
/** Write accounting data to Couchbase documents
 *
 * Handle accounting requests and store the associated data into JSON documents
 * in couchbase mapping attribute names to JSON element names per the module configuration.
 *
 * When an existing document already exists for the same accounting section the new attributes
 * will be merged with the currently existing data.  When conflicts arrise the new attribute
 * value will replace or be added to the existing value.
 *
 * @param instance The module instance.
 * @param request  The accounting request object.
 * @return Returns operation status (@p rlm_rcode_t).
 */
static rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
	rlm_couchbase_t *inst = instance;       /* our module instance */
	rlm_couchbase_handle_t *handle = NULL;  /* connection pool handle */
	rlm_rcode_t rcode = RLM_MODULE_OK;      /* return code */
	VALUE_PAIR *vp;                         /* radius value pair linked list */
	char dockey[MAX_KEY_SIZE];              /* our document key */
	char document[MAX_VALUE_SIZE];          /* our document body */
	char element[MAX_KEY_SIZE];             /* mapped radius attribute to element name */
	int status = 0;                         /* account status type */
	int docfound = 0;                       /* document found toggle */
	lcb_error_t cb_error = LCB_SUCCESS;     /* couchbase error holder */

	/* assert packet as not null */
	rad_assert(request->packet != NULL);

	/* sanity check */
	if ((vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) == NULL) {
		/* log debug */
		RDEBUG("could not find status type in packet");
		/* return */
		return RLM_MODULE_NOOP;
	}

	/* set status */
	status = vp->vp_integer;

	/* acknowledge the request but take no action */
	if (status == PW_STATUS_ACCOUNTING_ON || status == PW_STATUS_ACCOUNTING_OFF) {
		/* log debug */
		RDEBUG("handling accounting on/off request without action");
		/* return */
		return RLM_MODULE_OK;
	}

	/* get handle */
	handle = fr_connection_get(inst->pool);

	/* check handle */
	if (!handle) return RLM_MODULE_FAIL;

	/* set couchbase instance */
	lcb_t cb_inst = handle->handle;

	/* set cookie */
	cookie_t *cookie = handle->cookie;

	/* attempt to build document key */
	if (radius_xlat(dockey, sizeof(dockey), request, inst->acct_key, NULL, NULL) < 0) {
		/* log error */
		RERROR("could not find accounting key attribute (%s) in packet", inst->acct_key);
		/* set return */
		rcode = RLM_MODULE_NOOP;
		/* return */
		goto finish;
	}

	/* attempt to fetch document */
	cb_error = couchbase_get_key(cb_inst, cookie, dockey);

	/* check error and object */
	if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || !cookie->jobj) {
		/* log error */
		RERROR("failed to execute get request or parse returned json object");
		/* free and reset json object */
		if (cookie->jobj) {
			json_object_put(cookie->jobj);
			cookie->jobj = NULL;
		}
	/* check cookie json object */
	} else if (cookie->jobj) {
		/* set doc found */
		docfound = 1;
		/* debugging */
		RDEBUG3("parsed json body from couchbase: %s", json_object_to_json_string(cookie->jobj));
	}

	/* start json document if needed */
	if (docfound != 1) {
		/* debugging */
		RDEBUG("no existing document found - creating new json document");
		/* create new json object */
		cookie->jobj = json_object_new_object();
		/* set 'docType' element for new document */
		json_object_object_add(cookie->jobj, "docType", json_object_new_string(inst->doctype));
		/* default startTimestamp and stopTimestamp to null values */
		json_object_object_add(cookie->jobj, "startTimestamp", NULL);
		json_object_object_add(cookie->jobj, "stopTimestamp", NULL);
	}

	/* status specific replacements for start/stop time */
	switch (status) {
	case PW_STATUS_START:
		/* add start time */
		if ((vp = fr_pair_find_by_num(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY)) != NULL) {
			/* add to json object */
			json_object_object_add(cookie->jobj, "startTimestamp",
					       mod_value_pair_to_json_object(request, vp));
		}
		break;

	case PW_STATUS_STOP:
		/* add stop time */
		if ((vp = fr_pair_find_by_num(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY)) != NULL) {
			/* add to json object */
			json_object_object_add(cookie->jobj, "stopTimestamp",
					       mod_value_pair_to_json_object(request, vp));
		}
		/* check start timestamp and adjust if needed */
		mod_ensure_start_timestamp(cookie->jobj, request->packet->vps);
		break;

	case PW_STATUS_ALIVE:
		/* check start timestamp and adjust if needed */
		mod_ensure_start_timestamp(cookie->jobj, request->packet->vps);
		break;

	default:
		/* don't doing anything */
		rcode = RLM_MODULE_NOOP;
		/* return */
		goto finish;
	}

	/* loop through pairs and add to json document */
	for (vp = request->packet->vps; vp; vp = vp->next) {
		/* map attribute to element */
		if (mod_attribute_to_element(vp->da->name, inst->map, &element) == 0) {
			/* debug */
			RDEBUG3("mapped attribute %s => %s", vp->da->name, element);
			/* add to json object with mapped name */
			json_object_object_add(cookie->jobj, element, mod_value_pair_to_json_object(request, vp));
		}
	}

	/* copy json string to document and check size */
	if (strlcpy(document, json_object_to_json_string(cookie->jobj), sizeof(document)) >= sizeof(document)) {
		/* this isn't good */
		RERROR("could not write json document - insufficient buffer space");
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* debugging */
	RDEBUG3("setting '%s' => '%s'", dockey, document);

	/* store document/key in couchbase */
	cb_error = couchbase_set_key(cb_inst, dockey, document, inst->expire);

	/* check return */
	if (cb_error != LCB_SUCCESS) {
		RERROR("failed to store document (%s): %s (0x%x)", dockey, lcb_strerror(NULL, cb_error), cb_error);
	}

finish:
	/* free and reset json object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* release our connection handle */
	if (handle) {
		fr_connection_release(inst->pool, handle);
	}

	/* return */
	return rcode;
}
#endif

#ifdef WITH_SESSION_MGMT
/** Check if a given user is already logged in.
 *
 * Process accounting data to determine if a user is already logged in. Sets request->simul_count
 * to the current session count for this user.
 *
 * Check twice. If on the first pass the user exceeds his maximum number of logins, do a second
 * pass and validate all logins by querying the terminal server.
 *
 * @param instance The module instance.
 * @param request  The checksimul request object.
 * @return Returns operation status (@p rlm_rcode_t).
 */
static rlm_rcode_t mod_checksimul(void *instance, REQUEST *request) {
	rlm_couchbase_t *inst = instance;      /* our module instance */
	rlm_rcode_t rcode = RLM_MODULE_OK;     /* return code */
	rlm_couchbase_handle_t *handle = NULL; /* connection pool handle */
	char vpath[256], vkey[MAX_KEY_SIZE];   /* view path and query key */
	char docid[MAX_KEY_SIZE];              /* document id returned from view */
	char error[512];                       /* view error return */
	int idx = 0;                           /* row array index counter */
	char element[MAX_KEY_SIZE];            /* mapped radius attribute to element name */
	lcb_error_t cb_error = LCB_SUCCESS;    /* couchbase error holder */
	json_object *json, *jval;              /* json object holders */
	json_object *jrows = NULL;             /* json object to hold view rows */
	VALUE_PAIR *vp;                        /* value pair */
	uint32_t client_ip_addr = 0;           /* current client ip address */
	char const *client_cs_id = NULL;       /* current client calling station id */
	char *user_name = NULL;                /* user name from accounting document */
	char *session_id = NULL;               /* session id from accounting document */
	char *cs_id = NULL;                    /* calling station id from accounting document */
	uint32_t nas_addr = 0;                 /* nas address from accounting document */
	uint32_t nas_port = 0;                 /* nas port from accounting document */
	uint32_t framed_ip_addr = 0;           /* framed ip address from accounting document */
	char framed_proto = 0;                 /* framed proto from accounting document */
	int session_time = 0;                  /* session time from accounting document */

	/* do nothing if this is not enabled */
	if (inst->check_simul != true) {
		RWDEBUG("Simultaneous-Use checking requires 'simul_count_query' to be configured");
		return RLM_MODULE_NOOP;
	}

	/* ensure valid username in request */
	if ((!request->username) || (request->username->vp_length == 0)) {
		REDEBUG("Zero Length username not permitted");
		return RLM_MODULE_INVALID;
	}

	/* attempt to build view key */
	if (radius_xlat(vkey, sizeof(vkey), request, inst->simul_vkey, NULL, NULL) < 0) {
		/* log error */
		RERROR("could not find simultaneous use view key attribute (%s) in packet", inst->simul_vkey);
		/* return */
		return RLM_MODULE_FAIL;
	}

	/* get handle */
	handle = fr_connection_get(inst->pool);

	/* check handle */
	if (!handle) return RLM_MODULE_FAIL;

	/* set couchbase instance */
	lcb_t cb_inst = handle->handle;

	/* set cookie */
	cookie_t *cookie = handle->cookie;

	/* build view path */
	snprintf(vpath, sizeof(vpath), "%s?key=\"%s\"&stale=update_after",
		 inst->simul_view, vkey);

	/* query view for document */
	cb_error = couchbase_query_view(cb_inst, cookie, vpath, NULL);

	/* check error and object */
	if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || !cookie->jobj) {
		/* log error */
		RERROR("failed to execute view request or parse return");
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* debugging */
	RDEBUG3("cookie->jobj == %s", json_object_to_json_string(cookie->jobj));

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
		RERROR("view request failed with error: %s", error);
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* check for document id in return */
	if (!json_object_object_get_ex(cookie->jobj, "rows", &json)) {
		/* log error */
		RERROR("failed to fetch rows from view payload");
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* get and hold rows */
	jrows = json_object_get(json);

	/* free cookie object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* check for valid row value */
	if (!jrows || !json_object_is_type(jrows, json_type_array)) {
		/* log error */
		RERROR("no valid rows returned from view: %s", vpath);
		/* set return */
		rcode = RLM_MODULE_FAIL;
		/* return */
		goto finish;
	}

	/* debugging */
	RDEBUG3("jrows == %s", json_object_to_json_string(jrows));

	/* set the count */
	request->simul_count = json_object_array_length(jrows);

	/* debugging */
	RDEBUG("found %d open sessions for %s", request->simul_count, request->username->vp_strvalue);

	/* check count */
	if (request->simul_count < request->simul_max) {
		rcode = RLM_MODULE_OK;
		goto finish;
	}

	/*
	 * Current session count exceeds configured maximum.
	 * Continue on to verify the sessions if configured otherwise stop here.
	 */
	if (inst->verify_simul != true) {
		rcode = RLM_MODULE_OK;
		goto finish;
	}

	/* debugging */
	RDEBUG("verifying session count");

	/* reset the count */
	request->simul_count = 0;

	/* get client ip address for MPP detection below */
	if ((vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY)) != NULL) {
		client_ip_addr = vp->vp_ipaddr;
	}

	/* get calling station id for MPP detection below */
	if ((vp = fr_pair_find_by_num(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY)) != NULL) {
		client_cs_id = vp->vp_strvalue;
	}

	/* loop across all row elements */
	for (idx = 0; idx < json_object_array_length(jrows); idx++) {
		/* clear docid */
		memset(docid, 0, sizeof(docid));

		/* fetch current index */
		json = json_object_array_get_idx(jrows, idx);

		/* get document id */
		if (json_object_object_get_ex(json, "id", &jval)) {
			/* copy and check length */
			if (strlcpy(docid, json_object_get_string(jval), sizeof(docid)) >= sizeof(docid)) {
				RERROR("document id from row longer than MAX_KEY_SIZE (%d)", MAX_KEY_SIZE);
				continue;
			}
		}

		/* check for valid doc id */
		if (docid[0] == 0) {
			RWARN("failed to fetch document id from row - skipping");
			continue;
		}

		/* fetch document */
		cb_error = couchbase_get_key(cb_inst, cookie, docid);

		/* check error and object */
		if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || !cookie->jobj) {
			/* log error */
			RERROR("failed to execute get request or parse return");
			/* set return */
			rcode = RLM_MODULE_FAIL;
			/* return */
			goto finish;
		}

		/* debugging */
		RDEBUG3("cookie->jobj == %s", json_object_to_json_string(cookie->jobj));

		/* get element name for User-Name attribute */
		if (mod_attribute_to_element("User-Name", inst->map, &element) == 0) {
			/* get and check username element */
			if (!json_object_object_get_ex(cookie->jobj, element, &jval)){
				RDEBUG("cannot zap stale entry without username");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			/* copy json string value to user_name */
			user_name = talloc_typed_strdup(request, json_object_get_string(jval));
		} else {
			RDEBUG("failed to find map entry for User-Name attribute");
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/* get element name for Acct-Session-Id attribute */
		if (mod_attribute_to_element("Acct-Session-Id", inst->map, &element) == 0) {
			/* get and check session id element */
			if (!json_object_object_get_ex(cookie->jobj, element, &jval)){
				RDEBUG("cannot zap stale entry without session id");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			/* copy json string value to session_id */
			session_id = talloc_typed_strdup(request, json_object_get_string(jval));
		} else {
			RDEBUG("failed to find map entry for Acct-Session-Id attribute");
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/* get element name for NAS-IP-Address attribute */
		if (mod_attribute_to_element("NAS-IP-Address", inst->map, &element) == 0) {
			/* attempt to get and nas address element */
			if (json_object_object_get_ex(cookie->jobj, element, &jval)){
				nas_addr = inet_addr(json_object_get_string(jval));
			}
		}

		/* get element name for NAS-Port attribute */
		if (mod_attribute_to_element("NAS-Port", inst->map, &element) == 0) {
			/* attempt to get nas port element */
			if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
				nas_port = (uint32_t) json_object_get_int(jval);
			}
		}

		/* check terminal server */
		int check = rad_check_ts(nas_addr, nas_port, user_name, session_id);

		/* take action based on check return */
		if (check == 0) {
			/* stale record - zap it if enabled */
			if (inst->delete_stale_sessions) {
				/* get element name for Framed-IP-Address attribute */
				if (mod_attribute_to_element("Framed-IP-Address", inst->map, &element) == 0) {
					/* attempt to get framed ip address element */
					if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
						framed_ip_addr = inet_addr(json_object_get_string(jval));
					}
				}

				/* get element name for Framed-Port attribute */
				if (mod_attribute_to_element("Framed-Port", inst->map, &element) == 0) {
					/* attempt to get framed port element */
					if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
						if (strcmp(json_object_get_string(jval), "PPP") == 0) {
							framed_proto = 'P';
						} else if (strcmp(json_object_get_string(jval), "SLIP") == 0) {
							framed_proto = 'S';
						}
					}
				}

				/* get element name for Acct-Session-Time attribute */
				if (mod_attribute_to_element("Acct-Session-Time", inst->map, &element) == 0) {
					/* attempt to get session time element */
					if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
						session_time = json_object_get_int(jval);
					}
				}

				/* zap session */
				session_zap(request, nas_addr, nas_port, user_name, session_id,
					    framed_ip_addr, framed_proto, session_time);
			}
		} else if (check == 1) {
			/* user is still logged in - increase count */
			++request->simul_count;

			/* get element name for Framed-IP-Address attribute */
			if (mod_attribute_to_element("Framed-IP-Address", inst->map, &element) == 0) {
				/* attempt to get framed ip address element */
				if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
					framed_ip_addr = inet_addr(json_object_get_string(jval));
				} else {
					/* ensure 0 if not found */
					framed_ip_addr = 0;
				}
			}

			/* get element name for Calling-Station-Id attribute */
			if (mod_attribute_to_element("Calling-Station-Id", inst->map, &element) == 0) {
				/* attempt to get framed ip address element */
				if (json_object_object_get_ex(cookie->jobj, element, &jval)) {
					/* copy json string value to cs_id */
					cs_id = talloc_typed_strdup(request, json_object_get_string(jval));
				} else {
					/* ensure null if not found */
					cs_id = NULL;
				}
			}

			/* Does it look like a MPP attempt? */
			if (client_ip_addr && framed_ip_addr && framed_ip_addr == client_ip_addr) {
				request->simul_mpp = 2;
			} else if (client_cs_id && cs_id && !strncmp(cs_id, client_cs_id, 16)) {
				request->simul_mpp = 2;
			}

		} else {
			/* check failed - return error */
			REDEBUG("failed to check the terminal server for user '%s'", user_name);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/* free and reset document user name talloc */
		if (user_name) TALLOC_FREE(user_name);

		/* free and reset document calling station id talloc */
		if (cs_id) TALLOC_FREE(cs_id);

		/* free and reset document session id talloc */
		if (session_id) TALLOC_FREE(session_id);

		/* free and reset json object before fetching next row */
		if (cookie->jobj) {
			json_object_put(cookie->jobj);
			cookie->jobj = NULL;
		}
	}

	/* debugging */
	RDEBUG("Retained %d open sessions for %s after verification",
	       request->simul_count, request->username->vp_strvalue);

finish:
	if (user_name) talloc_free(user_name);
	if (cs_id) talloc_free(cs_id);
	if (session_id) talloc_free(session_id);

	/* free rows */
	if (jrows) json_object_put(jrows);

	/* free and reset json object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	if (handle) fr_connection_release(inst->pool, handle);

	/*
	 * The Auth module apparently looks at request->simul_count,
	 * not the return value of this module when deciding to deny
	 * a call for too many sessions.
	 */
	return rcode;
}
#endif

/** Detach the module
 *
 * Detach the module instance and free any allocated resources.
 *
 * @param  instance The module instance.
 * @return          Returns 0 (success) in all conditions.
 */
static int mod_detach(void *instance)
{
	rlm_couchbase_t *inst = instance;

	if (inst->map) json_object_put(inst->map);
	if (inst->pool) fr_connection_pool_free(inst->pool);

	return 0;
}

/*
 * Hook into the FreeRADIUS module system.
 */
extern module_t rlm_couchbase;
module_t rlm_couchbase = {
	.magic		= RLM_MODULE_INIT,
	.name		= "couchbase",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_couchbase_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
#ifdef WITH_SESSION_MGMT
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};
