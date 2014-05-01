/* couchbase */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <libcouchbase/couchbase.h>

#include "couchbase.h"

/* general couchbase error callback */
void couchbase_error_callback(lcb_t instance, lcb_error_t error, const char *errinfo) {
    /* log error */
    ERROR("rlm_couchbase: (error_callback) %s (0x%x), %s", lcb_strerror(instance, error), error, errinfo);
}

/* couchbase value store callback */
void couchbase_store_callback(lcb_t instance, const void *cookie, lcb_storage_t operation, lcb_error_t error, const lcb_store_resp_t *resp) {
    if (error != LCB_SUCCESS) {
        /* log error */
        ERROR("rlm_couchbase: (store_callback) %s (0x%x)", lcb_strerror(instance, error), error);
    }
    /* silent compiler */
    (void)cookie;
    (void)operation;
    (void)resp;
}

/* couchbase value get callback */
void couchbase_get_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_get_resp_t *resp) {
    cookie_t *c = (cookie_t *) cookie;      /* our cookie struct */
    const char *bytes = resp->v.v0.bytes;   /* the payload of this chunk */
    lcb_size_t nbytes = resp->v.v0.nbytes;  /* length of this data chunk */

    /* check error */
    switch (error) {
        case LCB_SUCCESS:
            /* check for valid bytes */
            if (bytes && nbytes > 1) {
                /* debug */
                DEBUG("rlm_couchbase: (get_callback) got %zu bytes", nbytes);
                /* build json object */
                c->jobj = json_tokener_parse_verbose(bytes, &c->jerr);
                /* switch on current error status */
                switch (c->jerr) {
                    case json_tokener_success:
                        /* do nothing */
                    break;
                    default:
                        /* log error */
                        ERROR("rlm_couchbase: (get_callback) JSON Tokener error: %s", json_tokener_error_desc(c->jerr));
                    break;
                }
            }
        break;
        case LCB_KEY_ENOENT:
            /* ignored */
            DEBUG("rlm_couchbase: (get_callback) key does not exist");
        break;
        default:
            /* log error */
            ERROR("rlm_couchbase: (get_callback) %s (0x%x)", lcb_strerror(instance, error), error);
        break;
    }
}

/* couchbase http callback for data chunks */
void couchbase_http_data_callback(lcb_http_request_t request, lcb_t instance, const void *cookie, lcb_error_t error, const lcb_http_resp_t *resp) {
    cookie_t *c = (cookie_t *) cookie;      /* our cookie struct */
    const char *bytes = resp->v.v0.bytes;   /* the payload of this chunk */
    lcb_size_t nbytes = resp->v.v0.nbytes;  /* length of this data chunk */

    /* check error */
    switch (error) {
        case LCB_SUCCESS:
            /* check for valid bytes */
            if (bytes && nbytes > 1) {
                /* debug */
                DEBUG("rlm_couchbase: (http_data_callback) got %zu bytes", nbytes);
                /* build json object */
                c->jobj = json_tokener_parse_ex(c->jtok, bytes, nbytes);
                /* switch on current error status */
                switch ((c->jerr = json_tokener_get_error(c->jtok))) {
                    case json_tokener_continue:
                        /* do nothing */
                    break;
                    case json_tokener_success:
                        /* do nothing */
                    break;
                    default:
                        /* log error */
                        ERROR("rlm_couchbase: (http_data_callback) JSON Tokener error: %s", json_tokener_error_desc(c->jerr));
                    break;
                }
            }
        break;
        default:
            /* log error */
            ERROR("rlm_couchbase: (http_data_callback) %s (0x%x)", lcb_strerror(instance, error), error);
        break;
    }
    /* silent compiler */
    (void)request;
}

/* connect to couchbase */
lcb_t couchbase_init_connection(const char *host, const char *bucket, const char *pass) {
    lcb_t instance;                         /* couchbase instance */
    lcb_error_t error;                      /* couchbase command return */

    /* init create struct */
    struct lcb_create_st *options = calloc(1, sizeof(*options));

    /* assign couchbase create options */
    options->v.v0.host = host;
    options->v.v0.bucket = bucket;

    /* assign user and password if they were both passed */
    if (bucket != NULL && pass != NULL) {
        options->v.v0.user = bucket;
        options->v.v0.passwd = pass;
    }

    /* create couchbase connection instance */
    if ((error = lcb_create(&instance, options)) != LCB_SUCCESS) {
        /* log error and return */
        ERROR("rlm_couchbase: failed to create couchbase instance: %s (0x%x)", lcb_strerror(NULL, error), error);
        /* free options */
        free(options);
        /* return instance */
        return instance;
    }

    /* initiate connection */
    if ((error = lcb_connect(instance)) == LCB_SUCCESS) {
        /* set general method callbacks */
        lcb_set_error_callback(instance, couchbase_error_callback);
        lcb_set_get_callback(instance, couchbase_get_callback);
        lcb_set_store_callback(instance, couchbase_store_callback);
        lcb_set_http_data_callback(instance, couchbase_http_data_callback);
        /* wait on connection */
        lcb_wait(instance);
    } else {
        /* log error */
        ERROR("rlm_couchbase: Failed to initiate couchbase connection: %s (0x%x)", lcb_strerror(NULL, error), error);
    }

    /* free options */
    free(options);

    /* return instance */
    return instance;
}

/* store document/key in couchbase */
lcb_error_t couchbase_set_key(lcb_t instance, const char *key, const char *document, int expire) {
    lcb_error_t error;  /* couchbase command return */

    /* init store command struct */
    lcb_store_cmd_t *store = calloc(1, sizeof(lcb_store_cmd_t));

    /* populate command struct */
    store->version = 0;
    store->v.v0.key = key;
    store->v.v0.nkey = strlen(store->v.v0.key);
    store->v.v0.bytes = document;
    store->v.v0.nbytes = strlen(store->v.v0.bytes);
    store->v.v0.exptime = expire;
    store->v.v0.operation = LCB_SET;

    /* build commands array */
    const lcb_store_cmd_t *commands[] = { store };

    /* store key/document in couchbase */
    if ((error = lcb_store(instance, NULL, 1, commands)) == LCB_SUCCESS) {
        /* enter event loop on success */
        lcb_wait(instance);
    }

    /* free store */
    free(store);

    /* return error */
    return error;
}

/* touch document by key to update expire time */
lcb_error_t couchbase_touch_key(lcb_t instance, const char *key, lcb_time_t exptime) {
    lcb_error_t error;  /* couchbase command return */

    /* init touch command struct */
    lcb_touch_cmd_t *touch = calloc(1, sizeof(lcb_touch_cmd_t));

    /* populate struct */
    touch->version = 0;
    touch->v.v0.key = key;
    touch->v.v0.nkey = strlen(touch->v.v0.key);
    touch->v.v0.exptime = exptime;

    /* build commands array */
    const lcb_touch_cmd_t *commands[] = { touch };

    /* touch document */
    if ((error = lcb_touch(instance, NULL, 1, commands)) == LCB_SUCCESS) {
        /* enter event loop on success */
        lcb_wait(instance);
    }

    /* free touch */
    free(touch);

    /* return error */
    return error;
}

/* pull document from couchbase by key */
lcb_error_t couchbase_get_key(lcb_t instance, const void *cookie, const char *key) {
    lcb_error_t error;  /* couchbase command return */

    /* init get command struct */
    lcb_get_cmd_t *get = calloc(1, sizeof(lcb_get_cmd_t));

    /* populate command struct */
    get->version = 0;
    get->v.v0.key = key;
    get->v.v0.nkey = strlen(get->v.v0.key);

    /* build commands array */
    const lcb_touch_cmd_t *commands[] = { get };

    /* get document */
    if ((error = lcb_get(instance, cookie, 1, commands)) == LCB_SUCCESS) {
        /* enter event loop on success */
        lcb_wait(instance);
    }

    /* free get */
    free(get);

    /* return error */
    return error;
}

/* query a couchbase view via http */
lcb_error_t couchbase_query_view(lcb_t instance, const void *cookie, const char *path, const char *post) {
    lcb_error_t error;  /* couchbase command return */

    /* init view command struct */
    lcb_http_cmd_t *http = calloc(1, sizeof(lcb_http_cmd_t));

    /* populate command struct */
    http->version = 0;
    http->v.v0.path = path;
    http->v.v0.npath = strlen(http->v.v0.path);
    http->v.v0.body = post;
    http->v.v0.nbody = post ? strlen(post) : 0;
    http->v.v0.method = post ? LCB_HTTP_METHOD_POST : LCB_HTTP_METHOD_GET;
    http->v.v0.chunked = 1;
    http->v.v0.content_type = "application/json";

    /* query the view */
    if ((error = lcb_make_http_request(instance, cookie, LCB_HTTP_TYPE_VIEW, http, NULL)) == LCB_SUCCESS) {
        /* enter event loop on success */
        lcb_wait(instance);
    }

    /* free http */
    free(http);

    /* return error */
    return error;
}
