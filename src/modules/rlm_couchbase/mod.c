/* blargs */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <json/json.h>

#include "couchbase.h"

#include "mod.h"

/* create new connection pool handle */
void *mod_conn_create(void *instance) {
    rlm_couchbase_t *inst = instance;           /* module instance pointer */
    rlm_couchbase_handle_t *chandle = NULL;     /* connection handle pointer */
    cookie_t *cookie = NULL;                    /* couchbase cookie */
    lcb_t cb_inst;                              /* couchbase connection instance */
    lcb_error_t cb_error = LCB_SUCCESS;         /* couchbase error status */

    /* create instance */
    cb_inst = couchbase_init_connection(inst->server, inst->bucket, inst->pass);

    /* check couchbase instance status */
    if ((cb_error = lcb_get_last_error(cb_inst)) != LCB_SUCCESS) {
        ERROR("rlm_couchbase: failed to initiate couchbase connection: %s (0x%x)", lcb_strerror(NULL, cb_error), cb_error);
        /* destroy/free couchbase instance */
        lcb_destroy(cb_inst);
        /* fail */
        return NULL;
    }

    /* allocate memory for couchbase connection instance abstraction */
    chandle = talloc_zero(inst, rlm_couchbase_handle_t);
    cookie = talloc_zero(chandle, cookie_t);

    /* initialize cookie error holder */
    cookie->jerr = json_tokener_success;

    /* populate handle with allocated structs */
    chandle->cookie = cookie;
    chandle->handle = cb_inst;

    /* return handle struct */
    return chandle;
}

/* verify valid couchbase connection handle */
int mod_conn_alive(UNUSED void *instance, void *handle) {
    rlm_couchbase_handle_t *chandle = handle;   /* connection handle pointer */
    lcb_t cb_inst = chandle->handle;            /* couchbase instance */
    lcb_error_t cb_error = LCB_SUCCESS;         /* couchbase error status */

    /* attempt to get server list */
    const char *const *servers = lcb_get_server_list(cb_inst);

    /* check error state and server list return */
    if (((cb_error = lcb_get_last_error(cb_inst)) != LCB_SUCCESS) || (servers == NULL)) {
        /* log error */
        ERROR("rlm_couchbase: failed to get couchbase server topology: %s (0x%x)", lcb_strerror(NULL, cb_error), cb_error);
        /* return false */
        return false;
    }
    return true;
}

/* free couchbase instance handle and any additional context memory */
int mod_conn_delete(UNUSED void *instance, void *handle) {
    rlm_couchbase_handle_t *chandle = handle;       /* connection instance handle */
    lcb_t cb_inst = chandle->handle;                /* couchbase instance */

    /* destroy/free couchbase instance */
    lcb_destroy(cb_inst);

    /* free handle */
    talloc_free(chandle);

    /* return */
    return true;
}

/* map free radius attribute to user defined json element name */
int mod_attribute_to_element(const char *name, CONF_SECTION *map, void *buf) {
    CONF_PAIR *cp;                      /* config pair */
    const char *attribute, *value;      /* config pair attibute and value */
    int length;                         /* attribute value length */

    /* clear buffer */
    memset((char *) buf, 0, MAX_KEY_SIZE);

    /* find pair */
    cp = cf_pair_find(map, name);

    /* check pair and map attribute */
    if (cp) {
        /* get pair attribute name */
        attribute = cf_pair_attr(cp);
        /* get pair value */
        value = cf_pair_value(cp);
        /* sanity check */
        if (attribute && value && (strcmp(attribute, name) == 0)) {
            /* get length */
            length = (strlen(value) + 1);
            /* check buffer size */
            if (length > MAX_KEY_SIZE -1) {
                /* oops ... this value is bigger than our buffer ... error out */
                ERROR("rlm_couchbase: map value larger than MAX_KEY_SIZE - %d", MAX_KEY_SIZE);
                /* return fail */
                return -1;
            } else {
                /* copy pair value to buffer */
                strlcpy(buf, value, length);
                /* return good */
                return 0;
            }
        }
    }

    /* debugging */
    DEBUG("rlm_couchbase: skipping attribute with no map entry - %s", name);

    /* default return */
    return -1;
}

/* inject value pairs into given request
 * that are defined in the passed json object
 */
void *mod_json_object_to_value_pairs(json_object *json, const char *section, REQUEST *request) {
    json_object *jobj, *jval, *jval2;   /* json object pointers */
    json_object_iter iter;              /* json object iterator */
    TALLOC_CTX *ctx;                    /* talloc context for pairmake */
    VALUE_PAIR *vp, **ptr;              /* value pair and value pair pointer for pairmake */

    /* assign ctx and vps for pairmake based on section */
    if (strcmp(section, "config") == 0) {
        ctx = request;
        ptr = &(request->config_items);
    } else if (strcmp(section, "reply") == 0) {
        ctx = request->reply;
        ptr = &(request->reply->vps);
    } else {
        /* log error - this shouldn't happen */
        RERROR("rlm_couchbase: invalid section passed for pairmake");
        /* return */
        return NULL;
    }

    /* get config payload */
    if (json_object_object_get_ex(json, section, &jobj)) {
        /* make sure we have the correct type */
        if (!json_object_is_type(jobj, json_type_object)) {
            /* log error */
            RERROR("rlm_couchbase: invalid json type for '%s' section - sections must be json objects", section);
            /* reuturn */
            return NULL;
        }
        /* loop through object */
        json_object_object_foreachC(jobj, iter) {
            /* debugging */
            RDEBUG("parsing '%s' attribute: %s => %s", section, iter.key, json_object_to_json_string(iter.val));
            /* check for appropriate type in value and op */
            if (!json_object_is_type(iter.val, json_type_object)) {
                /* log error */
                RERROR("rlm_couchbase: invalid json type for '%s' attribute - attributes must be json objects", iter.key);
                /* return */
                return NULL;
            }
            /* create pair from json object */
            if (json_object_object_get_ex(iter.val, "value", &jval) &&
                json_object_object_get_ex(iter.val, "op", &jval2)) {
                /* make correct pairs based on json object type */
                switch (json_object_get_type(jval)) {
                    case json_type_double:
                    case json_type_int:
                    case json_type_string:
                        /* debugging */
                        RDEBUG("adding '%s' attribute to '%s' section", iter.key, section);
                        /* add pair */
                        vp = pairmake(ctx, ptr, iter.key, json_object_get_string(jval),
                            fr_str2int(fr_tokens, json_object_get_string(jval2), 0));
                        /* check pair */
                        if (!vp) {
                            RERROR("rlm_couchbase: could not build '%s' attribute", fr_strerror());
                            /* return */
                            return NULL;
                        }
                    break;
                    case json_type_object:
                    case json_type_array:
                        /* log error - we want to handle these eventually */
                        RERROR("rlm_couchbase: skipping unhandled nested json object or array value pair object");
                    break;
                    default:
                        /* log error - this shouldn't ever happen */
                        RERROR("rlm_couchbase: skipping unhandled json type in value pair object");
                    break;
                }
            } else {
                /* log error */
                RERROR("rlm_couchbase: failed to get 'value' or 'op' element for '%s' attribute", iter.key);
            }
        }
    }

    /* return NULL */
    return NULL;
}

/* convert freeradius value/pair to json object
 * basic structure taken from freeradius function
 * vp_prints_value_json in src/lib/print.c */
json_object *mod_value_pair_to_json_object(REQUEST *request, VALUE_PAIR *vp) {
    char value[255];    /* radius attribute value */

    /* add this attribute/value pair to our json output */
    if (!vp->da->flags.has_tag) {
        switch (vp->da->type) {
            case PW_TYPE_INTEGER:
            case PW_TYPE_BYTE:
            case PW_TYPE_SHORT:
                /* skip if we have flags */
                if (vp->da->flags.has_value) break;
                /* debug */
                RDEBUG3("creating new int64 for unsigned 32 bit int/byte/short '%s'", vp->da->name);
                /* return as 64 bit int - json-c does not seem to support unsigned 32 bit ints */
                return json_object_new_int64(vp->vp_integer);
            break;
            case PW_TYPE_SIGNED:
                /* debug */
                RDEBUG3("creating new int64 for signed 32 bit integer '%s'", vp->da->name);
                /* return as 64 bit int - json-c represents all ints as 64 bits internally */
                return json_object_new_int64(vp->vp_signed);
            break;
            case PW_TYPE_INTEGER64:
                /* debug */
                RDEBUG3("creating new int64 for 64 bit integer '%s'", vp->da->name);
                /* return as 64 bit int - because it is a 64 bit int */
                return json_object_new_int64(vp->vp_integer64);
            break;
            default:
                /* silence warnings - do nothing */
            break;
        }
    }

    /* keep going if not set above */
    switch (vp->da->type) {
        case PW_TYPE_STRING:
            /* debug */
            RDEBUG3("assigning string '%s' as string", vp->da->name);
            /* return string value */
            return json_object_new_string(vp->vp_strvalue);
        default:
            /* debug */
            RDEBUG3("assigning unhandled '%s' as string", vp->da->name);
            /* get standard value */
            vp_prints_value(value, sizeof(value), vp, 0);
            /* return string value from above */
            return json_object_new_string(value);
        break;
    }
}

/* check current value of start timestamp in json body and update if needed */
int mod_ensure_start_timestamp(json_object *json, VALUE_PAIR *vps) {
    json_object *jval;      /* json object value */
    struct tm tm;           /* struct to hold event time */
    time_t ts = 0;          /* values to hold time in seconds */
    VALUE_PAIR *vp;         /* values to hold value pairs */
    char value[255];        /* store radius attribute values and our timestamp */

    /* get our current start timestamp from our json body */
    if (json_object_object_get_ex(json, "startTimestamp", &jval) == 0) {
        /* debugging ... this shouldn't ever happen */
        DEBUG("rlm_couchbase: failed to find start timestamp in current json body");
        /* return */
        return -1;
    }

    /* check the value */
    if (strcmp(json_object_get_string(jval), "null") != 0) {
        /* debugging */
        DEBUG("rlm_couchbase: start timestamp looks good - nothing to do");
        /* already set - nothing else to do */
        return 0;
    }

    /* get current event timestamp */
    if ((vp = pairfind(vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY)) != NULL) {
        /* get seconds value from attribute */
        ts = vp->vp_date;
    } else {
        /* debugging */
        DEBUG("rlm_couchbase: failed to find event timestamp in current request");
        /* return */
        return -1;
    }

    /* clear value */
    memset(value, 0, sizeof(value));

    /* get elapsed session time */
    if ((vp = pairfind(vps, PW_ACCT_SESSION_TIME, 0, TAG_ANY)) != NULL) {
        /* calculate diff */
        ts = (ts - vp->vp_integer);
        /* calculate start time */
        size_t length = strftime(value, sizeof(value), "%b %e %Y %H:%M:%S %Z", localtime_r(&ts, &tm));
        /* check length */
        if (length > 0) {
            /* debugging */
            DEBUG("rlm_couchbase: calculated start timestamp: %s", value);
            /* store new value in json body */
            json_object_object_add(json, "startTimestamp", json_object_new_string(value));
        } else {
            /* debugging */
            DEBUG("rlm_couchbase: failed to format calculated timestamp");
            /* return */
            return -1;
        }
    }

    /* default return */
    return 0;
}
