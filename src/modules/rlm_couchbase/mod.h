/* blargs */

#ifndef _UTIL_H
#define _UTIL_H

RCSIDH(util_h, "$Id$");

#include <json/json.h>

/* maximum size of a stored value */
#define MAX_VALUE_SIZE 20480

/* maximum length of a document key */
#define MAX_KEY_SIZE 250

/* configuration struct */
typedef struct rlm_couchbase_t {
    const char *acctkey;            /* accounting document key */
    const char *doctype;            /* value of 'docType' element name */
    const char *server;             /* couchbase server list */
    const char *bucket;             /* couchbase bucket */
    const char *pass;               /* couchbase bucket password */
    unsigned int expire;            /* document expire time in seconds */
    const char *userkey;            /* user document key */
    CONF_SECTION *map;              /* json object to hold user defined attribute map */
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

int mod_attribute_to_element(const char *name, CONF_SECTION *map, void *attribute);

void *mod_json_object_to_value_pairs(json_object *json, const char *section, REQUEST *request);

json_object *mod_value_pair_to_json_object(REQUEST *request, VALUE_PAIR *vp);

int mod_ensure_start_timestamp(json_object *json, VALUE_PAIR *vps);

#endif /* _UTIL_H */
