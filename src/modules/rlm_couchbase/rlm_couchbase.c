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
 * @author Aaron Hurt (ahurt@anbcs.com)
 * @copyright 2013-2014 The FreeRADIUS Server Project.
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_couchbase - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base.h>

#include <freeradius-devel/json/base.h>

#include "mod.h"
#include "couchbase.h"

/**
 * Client Configuration
 */
static const CONF_PARSER client_config[] = {
	{ FR_CONF_OFFSET("view", FR_TYPE_STRING, rlm_couchbase_t, client_view), .dflt = "_design/client/_view/by_name" },
	CONF_PARSER_TERMINATOR
};

/**
 * Module Configuration
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_couchbase_t, server_raw) },
	{ FR_CONF_OFFSET("bucket", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_couchbase_t, bucket) },
	{ FR_CONF_OFFSET("username", FR_TYPE_STRING, rlm_couchbase_t, username) },
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING, rlm_couchbase_t, password) },
#ifdef WITH_ACCOUNTING
	{ FR_CONF_OFFSET("acct_key", FR_TYPE_TMPL, rlm_couchbase_t, acct_key), .dflt = "radacct_%{%{Acct-Unique-Session-Id}:-%{Acct-Session-Id}}", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("doctype", FR_TYPE_STRING, rlm_couchbase_t, doctype), .dflt = "radacct" },
	{ FR_CONF_OFFSET("expire", FR_TYPE_UINT32, rlm_couchbase_t, expire), .dflt = 0 },
#endif
	{ FR_CONF_OFFSET("user_key", FR_TYPE_TMPL, rlm_couchbase_t, user_key), .dflt = "raduser_%{md5:%{tolower:%{%{Stripped-User-Name}:-%{User-Name}}}}", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("read_clients", FR_TYPE_BOOL, rlm_couchbase_t, read_clients) }, /* NULL defaults to "no" */
	{ FR_CONF_POINTER("client", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) client_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_couchbase_dict[];
fr_dict_autoload_t rlm_couchbase_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_acct_status_type;
fr_dict_attr_t const *attr_acct_session_time;
fr_dict_attr_t const *attr_event_timestamp;

extern fr_dict_attr_autoload_t rlm_couchbase_dict_attr[];
fr_dict_attr_autoload_t rlm_couchbase_dict_attr[] = {
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_session_time, .name = "Acct-Session-Time", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_event_timestamp, .name = "Event-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_radius },
	{ NULL }
};

/** Handle authorization requests using Couchbase document data
 *
 * Attempt to fetch the document assocaited with the requested user by
 * using the deterministic key defined in the configuration.  When a valid
 * document is found it will be parsed and the containing value pairs will be
 * injected into the request.
 *
 * @param instance	The module instance.
 * @param thread	specific data.
 * @param request	The authorization request.
 * @return Operation status (#rlm_rcode_t).
 */
static rlm_rcode_t mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_couchbase_t const	*inst = talloc_get_type_abort_const(instance, rlm_couchbase_t);		/* our module instance */
	rlm_couchbase_handle_t	*handle = NULL;			/* connection pool handle */
	char			buffer[MAX_KEY_SIZE];
	char const		*dockey;			/* our document key */
	lcb_error_t		cb_error = LCB_SUCCESS;		/* couchbase error holder */
	rlm_rcode_t		rcode = RLM_MODULE_OK;		/* return code */
	ssize_t			slen;

	/* assert packet as not null */
	fr_assert(request->packet != NULL);

	/* attempt to build document key */
	slen = tmpl_expand(&dockey, buffer, sizeof(buffer), request, inst->user_key, NULL, NULL);
	if (slen < 0) return RLM_MODULE_FAIL;
	if ((dockey == buffer) && is_truncated((size_t)slen, sizeof(buffer))) {
		REDEBUG("Key too long, expected < " STRINGIFY(sizeof(buffer)) " bytes, got %zi bytes", slen);
		return RLM_MODULE_FAIL;
	}

	/* get handle */
	handle = fr_pool_connection_get(inst->pool, request);

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

	{
		TALLOC_CTX	*pool = talloc_pool(request, 1024);	/* We need to do lots of allocs */
		fr_cursor_t	maps, vlms;
		vp_map_t	*map_head = NULL, *map;
		vp_list_mod_t	*vlm_head = NULL, *vlm;

		fr_cursor_init(&maps, &map_head);

		/*
		 *	Convert JSON data into maps
		 */
		if ((mod_json_object_to_map(pool, &maps, request, cookie->jobj, PAIR_LIST_CONTROL) < 0) ||
		    (mod_json_object_to_map(pool, &maps, request, cookie->jobj, PAIR_LIST_REPLY) < 0) ||
		    (mod_json_object_to_map(pool, &maps, request, cookie->jobj, PAIR_LIST_REQUEST) < 0) ||
		    (mod_json_object_to_map(pool, &maps, request, cookie->jobj, PAIR_LIST_STATE) < 0)) {
		invalid:
			talloc_free(pool);
			rcode = RLM_MODULE_INVALID;
			goto finish;
		}

		fr_cursor_init(&vlms, &vlm_head);

		/*
		 *	Convert all the maps into list modifications,
		 *	which are guaranteed to succeed.
		 */
		for (map = fr_cursor_head(&maps);
		     map;
		     map = fr_cursor_next(&maps)) {
			if (map_to_list_mod(pool, &vlm, request, map, NULL, NULL) < 0) goto invalid;
			fr_cursor_insert(&vlms, vlm);
		}

		if (!vlm_head) {
			RDEBUG2("Nothing to update");
			talloc_free(pool);
			rcode = RLM_MODULE_NOOP;
			goto finish;
		}

		/*
		 *	Apply the list of modifications
		 */
		for (vlm = fr_cursor_head(&vlms);
		     vlm;
		     vlm = fr_cursor_next(&vlms)) {
			int ret;

			ret = map_list_mod_apply(request, vlm);	/* SHOULD NOT FAIL */
			if (!fr_cond_assert(ret == 0)) {
				talloc_free(pool);
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}

		talloc_free(pool);
	}

finish:
	/* free json object */
	if (cookie->jobj) {
		json_object_put(cookie->jobj);
		cookie->jobj = NULL;
	}

	/* release handle */
	if (handle) fr_pool_connection_release(inst->pool, request, handle);

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
 * @param instance	The module instance.
 * @param thread	specific data.
 * @param request	The accounting request object.
 * @return Operation status (#rlm_rcode_t).
 */
static rlm_rcode_t mod_accounting(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_couchbase_t const *inst = talloc_get_type_abort_const(instance, rlm_couchbase_t);       /* our module instance */
	rlm_couchbase_handle_t *handle = NULL;  /* connection pool handle */
	rlm_rcode_t rcode = RLM_MODULE_OK;      /* return code */
	VALUE_PAIR *vp;                         /* radius value pair linked list */
	char buffer[MAX_KEY_SIZE];
	char const *dockey;			/* our document key */
	char document[MAX_VALUE_SIZE];          /* our document body */
	char element[MAX_KEY_SIZE];             /* mapped radius attribute to element name */
	int status = 0;                         /* account status type */
	int docfound = 0;                       /* document found toggle */
	lcb_error_t cb_error = LCB_SUCCESS;     /* couchbase error holder */
	ssize_t slen;

	/* assert packet as not null */
	fr_assert(request->packet != NULL);

	/* sanity check */
	if ((vp = fr_pair_find_by_da(request->packet->vps, attr_acct_status_type, TAG_ANY)) == NULL) {
		/* log debug */
		RDEBUG2("could not find status type in packet");
		/* return */
		return RLM_MODULE_NOOP;
	}

	/* set status */
	status = vp->vp_uint32;

	/* acknowledge the request but take no action */
	if (status == FR_STATUS_ACCOUNTING_ON || status == FR_STATUS_ACCOUNTING_OFF) {
		/* log debug */
		RDEBUG2("handling accounting on/off request without action");
		/* return */
		return RLM_MODULE_OK;
	}

	/* get handle */
	handle = fr_pool_connection_get(inst->pool, request);

	/* check handle */
	if (!handle) return RLM_MODULE_FAIL;

	/* set couchbase instance */
	lcb_t cb_inst = handle->handle;

	/* set cookie */
	cookie_t *cookie = handle->cookie;

	/* attempt to build document key */
	slen = tmpl_expand(&dockey, buffer, sizeof(buffer), request, inst->acct_key, NULL, NULL);
	if (slen < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}
	if ((dockey == buffer) && is_truncated((size_t)slen, sizeof(buffer))) {
		REDEBUG("Key too long, expected < " STRINGIFY(sizeof(buffer)) " bytes, got %zi bytes", slen);
		rcode = RLM_MODULE_FAIL;
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
		RDEBUG2("no existing document found - creating new json document");
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
	case FR_STATUS_START:
		/* add start time */
		if ((vp = fr_pair_find_by_da(request->packet->vps, attr_acct_status_type, TAG_ANY)) != NULL) {
			/* add to json object */
			json_object_object_add(cookie->jobj, "startTimestamp",
					       mod_value_pair_to_json_object(request, vp));
		}
		break;

	case FR_STATUS_STOP:
		/* add stop time */
		if ((vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY)) != NULL) {
			/* add to json object */
			json_object_object_add(cookie->jobj, "stopTimestamp",
					       mod_value_pair_to_json_object(request, vp));
		}
		/* check start timestamp and adjust if needed */
		mod_ensure_start_timestamp(cookie->jobj, request->packet->vps);
		break;

	case FR_STATUS_ALIVE:
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
		fr_pool_connection_release(inst->pool, request, handle);
	}

	/* return */
	return rcode;
}
#endif


/** Detach the module
 *
 * Detach the module instance and free any allocated resources.
 *
 * @param  instance The module instance.
 * @return Returns 0 (success) in all conditions.
 */
static int mod_detach(void *instance)
{
	rlm_couchbase_t *inst = instance;

	if (inst->map) json_object_put(inst->map);
	if (inst->pool) fr_pool_free(inst->pool);
	if (inst->api_opts) mod_free_api_opts(inst);

	return 0;
}

/** Bootstrap the module
 *
 * Define attributes.
 *
 * @param conf to parse.
 * @param instance configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_couchbase_t	*inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	return 0;
}

/** Initialize the rlm_couchbase module
 *
 * Intialize the module and create the initial Couchbase connection pool.
 *
 * @param  conf     The module configuration.
 * @param  instance The module instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_couchbase_t *inst = instance;   /* our module instance */

	{
		char *server, *p;
		size_t len, i;
		bool sep = false;

		len = talloc_array_length(inst->server_raw) - 1;
		server = p = talloc_array(inst, char, len + 1);
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

	/* setup libcouchbase extra options */
	if (mod_build_api_opts(conf, inst) != 0) {
		/* fail */
		return -1;
	}

	/* initiate connection pool */
	inst->pool = module_connection_pool_init(conf, inst, mod_conn_create, mod_conn_alive, NULL, NULL, NULL);

	/* check connection pool */
	if (!inst->pool) {
		ERROR("failed to initiate connection pool");
		/* fail */
		return -1;
	}

	/* load clients if requested */
	if (inst->read_clients) {
		CONF_SECTION *cs, *map, *tmpl; /* conf section */

		/* attempt to find client section */
		cs = cf_section_find(conf, "client", NULL);
		if (!cs) {
			ERROR("failed to find client section while loading clients");
			/* fail */
			return -1;
		}

		/* attempt to find attribute subsection */
		map = cf_section_find(cs, "attribute", NULL);
		if (!map) {
			ERROR("failed to find attribute subsection while loading clients");
			/* fail */
			return -1;
		}

		tmpl = cf_section_find(cs, "template", NULL);

		/* debugging */
		DEBUG("preparing to load client documents");

		/* attempt to load clients */
		if (mod_load_client_documents(inst, tmpl, map) != 0) {
			/* fail */
			return -1;
		}
	}

	/* return okay */
	return 0;
}

static int mod_load(void)
{
	INFO("libcouchbase version: %s", lcb_get_version(NULL));
	fr_json_version_print();
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
	.bootstrap	= mod_bootstrap,
	.onload		= mod_load,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
	},
};
