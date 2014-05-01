/* junk */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <libcouchbase/couchbase.h>

#include <json/json.h>

#include "mod.h"
#include "couchbase.h"

/* map config to internal variables */
static const CONF_PARSER module_config[] = {
    {"acctkey", PW_TYPE_STRING_PTR, offsetof(rlm_couchbase_t, acctkey), NULL, "radacct_%{%{Acct-Unique-Session-Id}:-%{Acct-Session-Id}}"},
    {"doctype", PW_TYPE_STRING_PTR, offsetof(rlm_couchbase_t, doctype), NULL, "radacct"},
    {"server", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED, offsetof(rlm_couchbase_t, server), NULL, NULL},
    {"bucket", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED, offsetof(rlm_couchbase_t, bucket), NULL, NULL},
    {"pass", PW_TYPE_STRING_PTR, offsetof(rlm_couchbase_t, pass), NULL, NULL},
    {"expire", PW_TYPE_INTEGER, offsetof(rlm_couchbase_t, expire), NULL, 0},
    {"userkey", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED, offsetof(rlm_couchbase_t, userkey), NULL, "raduser_%{md5:%{tolower:%{User-Name}}}"},
    {NULL, -1, 0, NULL, NULL}     /* end the list */
};

/* initialize couchbase connection */
static int rlm_couchbase_instantiate(CONF_SECTION *conf, void *instance) {
    /* build instance */
    rlm_couchbase_t *inst = instance;

    /* fail on bad config */
    if (cf_section_parse(conf, inst, module_config) < 0) {
        ERROR("rlm_couchbase: failed to parse config");
        /* fail */
        return -1;
    }

    /* find map section */
    inst->map = cf_section_sub_find(conf, "map");

    /* check section */
    if (!inst->map) {
        ERROR("rlm_couchbase: failed to find 'map' section in config");
        /* fail */
        return -1;
    }

    /* initiate connection pool */
    inst->pool = fr_connection_pool_init(conf, inst, mod_conn_create, mod_conn_alive, mod_conn_delete, NULL);

    /* check connection pool */
    if (!inst->pool) {
        ERROR("rlm_couchbase: failed to initiate connection pool");
        /* fail */
        return -1;
    }

    /* return okay */
    return 0;
}

/* authorize users via couchbase */
static rlm_rcode_t rlm_couchbase_authorize(void *instance, REQUEST *request) {
    rlm_couchbase_t *inst = instance;       /* our module instance */
    void *handle = NULL;                    /* connection pool handle */
    VALUE_PAIR *vp;                         /* value pair pointer */
    char dockey[MAX_KEY_SIZE];              /* our document key */
    const char *uname = NULL;               /* username pointer */
    lcb_error_t cb_error = LCB_SUCCESS;     /* couchbase error holder */

    /* assert packet as not null */
    rad_assert(request->packet != NULL);

    /* prefer stripped user name */
    if ((vp = pairfind(request->packet->vps, PW_STRIPPED_USER_NAME, 0, TAG_ANY)) != NULL) {
        uname = vp->vp_strvalue;
    /* fallback to user-name */
    } else if ((vp = pairfind(request->packet->vps, PW_USER_NAME, 0, TAG_ANY)) != NULL) {
        uname = vp->vp_strvalue;
    /* fail */
    } else {
        /* log debug */
        RDEBUG("rlm_couchbase: failed to find valid username for authorization");
        /* return */
        return RLM_MODULE_FAIL;
    }

    /* get handle */
    handle = fr_connection_get(inst->pool);

    /* check handle */
    if (!handle) return RLM_MODULE_FAIL;

    /* set handle pointer */
    rlm_couchbase_handle_t *handle_t = handle;

    /* set couchbase instance */
    lcb_t cb_inst = handle_t->handle;

    /* set cookie */
    cookie_t *cookie = handle_t->cookie;

    /* check cookie */
    if (cookie) {
        /* clear cookie */
        memset(cookie, 0, sizeof(cookie_t));
    } else {
        /* free connection */
        fr_connection_release(inst->pool, handle);
        /* log error */
        RERROR("rlm_couchbase: could not zero cookie");
        /* return */
        return RLM_MODULE_FAIL;
    }

    /* attempt to build document key */
    if (radius_xlat(dockey, sizeof(dockey), request, inst->userkey, NULL, NULL) < 0) {
        /* log error */
        RERROR("rlm_couchbase: could not find user key attribute (%s) in packet", inst->userkey);
        /* release handle */
        fr_connection_release(inst->pool, handle);
        /* return */
        return RLM_MODULE_FAIL;
    }

    /* reset  cookie error status */
    cookie->jerr = json_tokener_success;

    /* fetch document */
    cb_error = couchbase_get_key(cb_inst, cookie, dockey);

    /* check error */
    if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success || cookie->jobj == NULL) {
        /* log error */
        RERROR("failed to fetch document or parse return");
        /* free json object */
        json_object_put(cookie->jobj);
        /* release handle */
        fr_connection_release(inst->pool, handle);
        /* return */
        return RLM_MODULE_FAIL;
    }

    /* release handle */
    fr_connection_release(inst->pool, handle);

    /* debugging */
    RDEBUG("parsed user document == %s", json_object_to_json_string(cookie->jobj));

    /* inject config value pairs defined in this json oblect */
    mod_json_object_to_value_pairs(cookie->jobj, "config", request);

    /* inject config value pairs defined in this json oblect */
    mod_json_object_to_value_pairs(cookie->jobj, "reply", request);

    /* return okay */
    return RLM_MODULE_OK;
}

/* misc data manipulation before recording accounting data */
static rlm_rcode_t rlm_couchbase_preacct(UNUSED void *instance, REQUEST *request) {
    VALUE_PAIR *vp;                         /* radius value pair linked list */

    /* assert packet as not null */
    rad_assert(request->packet != NULL);

    /* check if stripped-user-name already set */
    if (pairfind(request->packet->vps, PW_STRIPPED_USER_NAME, 0, TAG_ANY) != NULL) {
        /* debugging */
        RDEBUG("stripped-user-name already set - ignorning request");
        /* already set - do nothing */
        return RLM_MODULE_NOOP;
    }

    /* get user string */
    if ((vp = pairfind(request->packet->vps, PW_USER_NAME, 0, TAG_ANY)) != NULL) {
        char *domain = NULL, *uname = NULL, *buff = NULL;   /* username and domain containers */
        size_t size;                                        /* size of user name string */

        /* allocate buffer in the request and set size to one more than username length */
        buff = talloc_zero_size(request, (size = (strlen(vp->vp_strvalue) + 1)));

        /* pass to our split function */
        uname = mod_split_user_domain(vp->vp_strvalue, buff, size, &domain);

        /* check uname and set if needed */
        if (uname != NULL) {
            pairmake_packet("Stripped-User-Name", uname, T_OP_SET);
        }

        /* check domain and set if needed */
        if (domain != NULL) {
            pairmake_packet("Stripped-User-Domain", domain, T_OP_SET);
        }

        /* free uname */
        talloc_free(buff);

        /* return updated - continue with other modules */
        return RLM_MODULE_UPDATED;
    }

    /* return noop */
    return RLM_MODULE_NOOP;
}

/* write accounting data to couchbase */
static rlm_rcode_t rlm_couchbase_accounting(void *instance, REQUEST *request) {
    rlm_couchbase_t *inst = instance;   /* our module instance */
    void *handle = NULL;                /* connection pool handle */
    VALUE_PAIR *vp;                     /* radius value pair linked list */
    char dockey[MAX_KEY_SIZE];          /* our document key */
    char document[MAX_VALUE_SIZE];      /* our document body */
    char element[MAX_KEY_SIZE];         /* mapped radius attribute to element name */
    int status = 0;                     /* account status type */
    int docfound = 0;                   /* document found toggle */
    lcb_error_t cb_error = LCB_SUCCESS; /* couchbase error holder */

    /* assert packet as not null */
    rad_assert(request->packet != NULL);

    /* sanity check */
    if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) == NULL) {
        /* log debug */
        RDEBUG("rlm_couchbase: could not find status type in packet");
        /* return */
        return RLM_MODULE_NOOP;
    }

    /* set status */
    status = vp->vp_integer;

    /* acknowledge the request but take no action */
    if (status == PW_STATUS_ACCOUNTING_ON || status == PW_STATUS_ACCOUNTING_OFF) {
        /* log debug */
        RDEBUG("rlm_couchbase: handling accounting on/off request without action");
        /* return */
        return RLM_MODULE_OK;
    }

    /* get handle */
    handle = fr_connection_get(inst->pool);

    /* check handle */
    if (!handle) return RLM_MODULE_FAIL;

    /* set handle pointer */
    rlm_couchbase_handle_t *handle_t = handle;

    /* set couchbase instance */
    lcb_t cb_inst = handle_t->handle;

    /* set cookie */
    cookie_t *cookie = handle_t->cookie;

    /* check cookie */
    if (cookie) {
        /* clear cookie */
        memset(cookie, 0, sizeof(cookie_t));
    } else {
        /* free connection */
        fr_connection_release(inst->pool, handle);
        /* log error */
        RERROR("rlm_couchbase: could not zero cookie");
        /* return */
        return RLM_MODULE_FAIL;
    }

    /* attempt to build document key */
    if (radius_xlat(dockey, sizeof(dockey), request, inst->acctkey, NULL, NULL) < 0) {
        /* log error */
        RERROR("rlm_couchbase: could not find accounting key attribute (%s) in packet", inst->acctkey);
        /* release handle */
        fr_connection_release(inst->pool, handle);
        /* return */
        return RLM_MODULE_NOOP;
    }

    /* init cookie error status */
    cookie->jerr = json_tokener_success;

    /* attempt to fetch document */
    cb_error = couchbase_get_key(cb_inst, cookie, dockey);

    /* check error */
    if (cb_error != LCB_SUCCESS || cookie->jerr != json_tokener_success) {
        /* log error */
        RERROR("rlm_couchbase: failed to execute get request or parse returned json object");
        /* free json object */
        json_object_put(cookie->jobj); 
    } else {
        /* check cookie json object */
        if (cookie->jobj != NULL) {
            /* set doc found */
            docfound = 1;
            /* debugging */
            RDEBUG("parsed json body from couchbase: %s", json_object_to_json_string(cookie->jobj));
        }
    }

    /* start json document if needed */
    if (docfound != 1) {
        /* debugging */
        RDEBUG("document not found - creating new json document");
        /* create new json object */
        cookie->jobj = json_object_new_object();
        /* set 'docType' element for new document */
        json_object_object_add(cookie->jobj, "docType", json_object_new_string(inst->doctype));
        /* set start and stop times ... ensure we always have these elements */
        json_object_object_add(cookie->jobj, "startTimestamp", json_object_new_string("null"));
        json_object_object_add(cookie->jobj, "stopTimestamp", json_object_new_string("null"));
    }

    /* status specific replacements for start/stop time */
    switch (status) {
        case PW_STATUS_START:
            /* add start time */
            if ((vp = pairfind(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY)) != NULL) {
                /* add to json object */
                json_object_object_add(cookie->jobj, "startTimestamp", mod_value_pair_to_json_object(vp));
            }
        break;
        case PW_STATUS_STOP:
            /* add stop time */
            if ((vp = pairfind(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY)) != NULL) {
                /* add to json object */
                json_object_object_add(cookie->jobj, "stopTimestamp", mod_value_pair_to_json_object(vp));
            }
            /* check start timestamp and adjust if needed */
            mod_ensure_start_timestamp(cookie->jobj, request->packet->vps);
        case PW_STATUS_ALIVE:
            /* check start timestamp and adjust if needed */
            mod_ensure_start_timestamp(cookie->jobj, request->packet->vps);
        break;
        default:
            /* we shouldn't get here - free json object */
            json_object_put(cookie->jobj);
            /* release our connection handle */
            fr_connection_release(inst->pool, handle);
            /* return without doing anything */
            return RLM_MODULE_NOOP;
        break;
    }

    /* loop through pairs and add to json document */
    for (vp = request->packet->vps; vp; vp = vp->next) {
        /* map attribute to element */
        if (mod_attribute_to_element(vp->da->name, inst->map, &element) == 0) {
            /* debug */
            RDEBUG("mapped attribute %s => %s", vp->da->name, element);
            /* add to json object with mapped name */
            json_object_object_add(cookie->jobj, element, mod_value_pair_to_json_object(vp));
        }
    }

    /* make sure we have enough room in our document buffer */
    if ((unsigned int) json_object_get_string_len(cookie->jobj) > sizeof(document) - 1) {
        /* this isn't good */
        RERROR("rlm_couchbase: could not write json document - insufficient buffer space");
        /* free json output */
        json_object_put(cookie->jobj);
        /* release handle */
        fr_connection_release(inst->pool, handle);
        /* return */
        return RLM_MODULE_FAIL;
    } else {
        /* copy json string to document */
        strlcpy(document, json_object_to_json_string(cookie->jobj), sizeof(document));
        /* free json output */
        json_object_put(cookie->jobj);
    }

    /* debugging */
    RDEBUG("setting '%s' => '%s'", dockey, document);

    /* store document/key in couchbase */
    cb_error = couchbase_set_key(cb_inst, dockey, document, inst->expire);

    /* check return */
    if (cb_error != LCB_SUCCESS) {
        RERROR("rlm_couchbase: failed to store document (%s): %s (0x%x)", dockey, lcb_strerror(NULL, cb_error), cb_error);
    }

    /* release handle */
    fr_connection_release(inst->pool, handle);

    /* return */
    return RLM_MODULE_OK;
}

/* free any memory we allocated */
static int rlm_couchbase_detach(void *instance) {
    rlm_couchbase_t *inst = instance;  /* instance struct */

    /* destroy connection pool */
    fr_connection_pool_delete(inst->pool);

    /* return okay */
    return 0;
}

/* hook the module into freeradius */
module_t rlm_couchbase = {
    RLM_MODULE_INIT,
    "couchbase",
    RLM_TYPE_THREAD_SAFE,           /* type */
    sizeof(rlm_couchbase_t),
    module_config,
    rlm_couchbase_instantiate,      /* instantiation */
    rlm_couchbase_detach,           /* detach */
    {
        NULL,                       /* authentication */
        rlm_couchbase_authorize,    /* authorization */
        rlm_couchbase_preacct,      /* preaccounting */
        rlm_couchbase_accounting,   /* accounting */
        NULL,                       /* checksimul */
        NULL,                       /* pre-proxy */
        NULL,                       /* post-proxy */
        NULL                        /* post-auth */
    },
};
