/*
 * rlm_zmq.c
 * vim: set expandtab ai ts=4 sw=4: 
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000,2011  The FreeRADIUS server project
 *
 * Copyright 2011       Roelf Diedericks <roelf@neology.co.za>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "json/json.h"
#include <zmq.h>

#ifndef HAVE_PTHREAD_H
/*
 *      This is a lot simpler than putting ifdef's around
 *      every use of the pthread functions.
 */
#define pthread_mutex_lock(a)
#define pthread_mutex_trylock(a) (0)
#define pthread_mutex_unlock(a)
#define pthread_mutex_init(a,b)
#define pthread_mutex_destroy(a)
#else
#include    <pthread.h>
#endif



typedef struct zmq_conn {
    void        *socket;
    char        locked;
#ifdef HAVE_PTHREAD_H
    pthread_mutex_t mutex;
#endif
} ZMQ_CONN;

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_zmq_t {
	char		*zmq_socket_path;
    int         zmq_send_control_pairs;
    void        *zmq_context;

    /* managed pool of zmq connections */
    int         num_conns;
    ZMQ_CONN    *conns;

#ifdef HAVE_PTHREAD_H
    pthread_mutex_t mutex;
#endif


	CONF_SECTION    *cs;
} rlm_zmq_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parser re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "zmq_socket_path",  PW_TYPE_STRING_PTR, offsetof(rlm_zmq_t,zmq_socket_path), NULL,  NULL},
  { "zmq_num_connections",  PW_TYPE_INTEGER, offsetof(rlm_zmq_t,num_conns), NULL,  "10"},
  { "zmq_send_control_pairs",  PW_TYPE_BOOLEAN, offsetof(rlm_zmq_t,zmq_send_control_pairs), NULL,  "no"},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};



static int zmq_init_conns(rlm_zmq_t *inst) 
{ 
    void *requester;
    int i=0;

    if ((pthread_mutex_trylock(&inst->mutex) != 0)) {
        /* someone else is already initializing the connections */
        return 0;
    }

    /* init the zmq context if it is not yet set for this instance */
    if (!inst->zmq_context) {
        radlog(L_INFO," ZMQ:zmq_init_conns: Initializing ZMQ context\n");
        inst->zmq_context=zmq_init(20);
        if (!inst->zmq_context) {
            radlog(L_ERR, "ZMQ:zmq_init_conns Unable to initialize context:%s",zmq_strerror(zmq_errno()));
            return 0;
        }
    }


    for(i=0;i<inst->num_conns;i++){
        radlog(L_DBG,"ZMQ:zmq_init_conns: initializing pooled socket id:%d",i);

        requester=zmq_socket(inst->zmq_context,ZMQ_REQ);
        if (!requester) {
            radlog(L_ERR,"ZMQ:zmq_init_conns: socket create failed %s\n", zmq_strerror(zmq_errno()));
            pthread_mutex_unlock(&(inst->mutex));
            return 0;
        }

        if ( zmq_connect(requester,inst->zmq_socket_path) <0 ) {
            radlog(L_ERR,"ZMQ:zmq_init_conns: socket connect failed %s\n", zmq_strerror(zmq_errno()));
            pthread_mutex_unlock(&(inst->mutex));
            return 0;
        }
        inst->conns[i].socket=requester;
        inst->conns[i].locked = 0;
    }
    pthread_mutex_unlock(&(inst->mutex));
    return 1;
}


/* acquire a zmq socket from the pool */
static inline int zmq_get_conn(ZMQ_CONN **ret, rlm_zmq_t *inst)
{
    register int i = 0;

    /* we initialize the zmq connection pool, and the zmq context upon the first request
     * for a zmq connection from the pool (via do_zmq) if the pool is empty
     *
     * This all might seem a bit strange -- to start up the zmq context and connections
     * upon the first request, but if this init happens during instance (zmq_instantiate), 
     * the zmq socket threads never get started when freeradius daemonizes. 
     *
     * It works fine with when debugging with 'radiusd -f' but not when running freeradius 
     * as a daemon
     * 
     * This is probably due to the fact that the zmq i/o threads get created before freeradius
     * forks during zmq_instantiate(), and the threads don't get inherited by the child that 
     * freeradius forks to daemonize.
     *
     * Thus, this little bit of hoopla, to init zmq and the socket pool upon the first call 
     * to zmq_get_conn. We locked with a mutex, to make sure that initialization doesn't 
     * happen multiple times, in case plenty of requests are already waiting for connections.
     */
    if (!inst->conns || !inst->zmq_context) {
        radlog(L_DBG,"ZMQ:zmq_get_conn: no connections yet, initializing sockets");
        if ( !zmq_init_conns(inst) ) {
            return -1;
        }
    }

    /* walk the connection pool and find a free socket */
    for(i=0;i<inst->num_conns;i++){
        radlog(L_DBG,"ZMQ:zmq_get_conn: checking pool socket, id: %d",i);
        if ((pthread_mutex_trylock(&inst->conns[i].mutex) == 0)) {
            if (inst->conns[i].locked == 1) {
                /* connection is already being used */
                pthread_mutex_unlock(&(inst->conns[i].mutex));
                continue;
            }
            /* found an unused connection */
            *ret = &inst->conns[i];
            inst->conns[i].locked = 1;
            radlog(L_DBG,"ZMQ:zmq_get_conn: got pool socket, id: %d",i);
            return i;
        }
    }
    return -1;
}

static inline void zmq_release_conn(int i, rlm_zmq_t *inst)
{
    ZMQ_CONN *conns = inst->conns;

    radlog(L_DBG,"ZMQ:zmq_release_conn: release pool socket, id: %d", i);
    conns[i].locked = 0;
    pthread_mutex_unlock(&(conns[i].mutex));
}


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int zmq_detach(void *instance)
{
    rlm_zmq_t *inst=(rlm_zmq_t *)instance;

    if (inst->zmq_context) {
        zmq_term(inst->zmq_context);
    }
    free(instance);
    return 0;
}

/*
 *	Instantiate the module
 */
static int zmq_instantiate(CONF_SECTION *conf, void **instance)
{
    rlm_zmq_t *inst;
    int i=0;

    /*
     *	Set up a storage area for instance data
     */
    inst = rad_malloc(sizeof(*inst));
    if (!inst) {
        return -1;
    }
    memset(inst, 0, sizeof(*inst));

    /*
     *	If the configuration parameters can't be parsed, then
     *	fail.
     */
    if (cf_section_parse(conf, inst, module_config) < 0) {
        free(inst);
        return -1;
    }

    if (!inst->zmq_socket_path) {
        radlog(L_ERR, "ZMQ: Must specify a zeromq socket path");
        zmq_detach(inst);
        return -1;
    }

    inst->zmq_context=NULL;

    /* init the connection pool's mutexes */
    inst->conns = malloc(sizeof(*(inst->conns))*inst->num_conns);
    for(i=0;i<inst->num_conns;i++){
        inst->conns[i].socket=NULL;
        inst->conns[i].locked = 0;
        pthread_mutex_init(&inst->conns[i].mutex, NULL);
    }

    /* mutex for socket pool initialisation */
    pthread_mutex_init(&inst->mutex, NULL);


    /* save the config section */
    inst->cs = conf;
    *instance = inst;

    return 0;
}



/* 
 * dump a radius request section in plain text 
 */

static void zmq_dump(VALUE_PAIR *vp, const char *section) {

    VALUE_PAIR  *nvp, *vpa, *vpn;
    char	namebuf[256];
    const   char *name;
    char	buffer[1024];
    int	attr, len;
    int i=0;


    nvp = paircopy(vp);

    while (nvp != NULL) {
        name =  nvp->name;
        attr = nvp->attribute;
        vpa = paircopy2(nvp,attr);

        if (vpa->next) {
            /* an attribute with multiple values, turn the values into json array */
            vpn = vpa;
            i=0;
            while (vpn) {
                len = vp_prints_value(buffer, sizeof(buffer),
                        vpn, FALSE);
                radlog(L_DBG,"ZMQ:DUMP: %s: %s[%d]=%s\n",section,name,i,buffer);
                vpn = vpn->next;
                i++;
            }
        } else {
            /* regular attribute with single value */
            if ((vpa->flags.has_tag) &&
                    (vpa->flags.tag != 0)) {
                snprintf(namebuf, sizeof(namebuf), "%s:%d",
                        nvp->name, nvp->flags.tag);
                name = namebuf;
            }

            len = vp_prints_value(buffer, sizeof(buffer),
                    vpa, FALSE);
            radlog(L_DBG,"ZMQ:DUMP %s: %s=%s\n",section,name,buffer);
        }

        pairfree(&vpa);
        vpa = nvp; while ((vpa != NULL) && (vpa->attribute == attr))
            vpa = vpa->next;
        pairdelete(&nvp, attr);
        nvp = vpa;
    }
}

/* 
 * build a json object from a chain of pairs,
 * placing them into  and place into the json hash called 'section' 
 */

static void zmq_build_json_req(json_object *json_req, VALUE_PAIR *vp, const char *section) {

    VALUE_PAIR  *nvp, *vpa, *vpn;
    char	namebuf[256];
    const   char *name;
    char	buffer[1024];
    int	attr, len;
    int i=0;


    json_object *section_obj=json_object_new_object();


    nvp = paircopy(vp);

    while (nvp != NULL) {
        name =  nvp->name;
        attr = nvp->attribute;
        vpa = paircopy2(nvp,attr);

        if (vpa->next) {
            /* an attribute with multiple values, turn the values into json array */
            vpn = vpa;
            json_object *arr_obj=json_object_new_array();
            i=0;
            while (vpn) {
                len = vp_prints_value(buffer, sizeof(buffer),
                        vpn, FALSE);
                radlog(L_DBG,"ZMQ: %s: %s[%d]=%s\n",section,name,i,buffer);
                json_object_array_add(arr_obj, json_object_new_string(buffer));
                vpn = vpn->next;
                i++;
            }
            json_object_object_add(section_obj, name, arr_obj);
        } else {
            /* regular attribute with single value */
            if ((vpa->flags.has_tag) &&
                    (vpa->flags.tag != 0)) {
                snprintf(namebuf, sizeof(namebuf), "%s:%d",
                        nvp->name, nvp->flags.tag);
                name = namebuf;
            }

            len = vp_prints_value(buffer, sizeof(buffer),
                    vpa, FALSE);
            radlog(L_DBG,"ZMQ: %s: %s=%s\n",section,name,buffer);
            json_object_object_add(section_obj, name, json_object_new_string(buffer));
        }

        pairfree(&vpa);
        vpa = nvp; while ((vpa != NULL) && (vpa->attribute == attr))
            vpa = vpa->next;
        pairdelete(&nvp, attr);
        nvp = vpa;
    }

    /* add this section to the main json object */
    json_object_object_add(json_req, section, section_obj);
}



/*
 * verify that a json object is a string and save it in a VP
 */
static int zmq_pairadd_json_obj(VALUE_PAIR **vp, const char *key, json_object *obj, int operator) {
    const char *val;
    VALUE_PAIR *vpp;

    if ( !obj ) {
        radlog(L_ERR,"ZMQ:\tadd: ERROR: Attribute %s is empty",key);

        return 0;
    }

    if ( json_object_is_type(obj,json_type_string) ) {
        val = json_object_get_string(obj);
        vpp = pairmake(key, val, operator);
        if (vpp != NULL) {
            pairadd(vp, vpp);
            radlog(L_DBG,"ZMQ:\tadd: Added pair %s = %s", key, val);
            return 1;
        } else {
            radlog(L_DBG,
                    "ZMQ:\tadd: ERROR: Failed to create pair %s = %s",
                    key, val);
        }
    } else {
        /* json_type_boolean,
           json_type_double,
           json_type_int,
           json_type_object,
           json_type_array,
           json_type_string
         */
        radlog(L_ERR,"ZMQ:\tadd: ERROR: json object is not a string %s is of type %d",key, json_object_get_type(obj));
    } 
    return 0;
}


/* 
 * decodes a chain of AVPs from a json hash's top level 'section'
 */
static int zmq_get_json_avps(json_object *json_resp, VALUE_PAIR **vp, const char *section)
{
    int      ret=0, i=0;
    const char *key; 
    struct json_object *val, *arrval, *obj; 
    struct lh_entry *entry;

    /*
       SV       *res_sv, **av_sv;
       AV       *av;
       char     *key;
       I32      key_len, len, i, j;
     */

    *vp = NULL;

    /* find the section */
    obj=json_object_object_get(json_resp,section);
    if (!obj)
        return 0;

    radlog(L_DBG," ZMQ:get_json_avps: ===== %s =====\n",section);       

    if (!json_object_is_type(obj,json_type_object)) {
        radlog(L_DBG,"ZMQ:get_json_avps: '%s' section is not an object, type is %d", section, json_object_get_type(obj));
        return 0;
    }

    /* iterate the entire 'section' and create VP's */
    for ( entry = json_object_get_object(obj)->head;
            (entry ? (key = (const char*)entry->k, val = (struct json_object*)entry->v, entry) : 0);
            entry = (struct lh_entry*)entry->next ) {

        if (!val) {
            radlog(L_ERR,"ZMQ: key=%s is empty, not adding",key);
            continue;
        }
        radlog(L_DBG,"ZMQ: key=%s val=%s",key, json_object_get_string(val));

        if (json_object_is_type(val,json_type_array)) {
            /* an attribute with array of values  */
            for(i=0; i < json_object_array_length(val); i++) {
                arrval = json_object_array_get_idx(val, i);
                radlog(L_DBG,"ZMQ:\tavp: %s[%d]=%s\n", key, i, json_object_get_string(arrval));
                ret = zmq_pairadd_json_obj(vp, key, arrval, T_OP_ADD)+ret;
            }
        } else if (json_object_is_type(val,json_type_string)) {
            /* plain old attribute-value */
            radlog(L_DBG,"ZMQ:\tavp: %s=%s\n", key, json_object_get_string(val));
            ret = zmq_pairadd_json_obj(vp, key, val, T_OP_EQ)+ret;
        } else {
            radlog(L_ERR,"ZMQ:\tavp: %s cannot handle this data type\n", key );
        }
    }
    radlog(L_DBG,"ZMQ:get_json_avps: ----- set %d %s VPs -----\n",ret,section); 

    return ret;
}



/* 
 * The main ZMQ handler.
 *
 * 1. we receive a request from one of the module callback handlers, 
 *    and encode it into json.
 * 2. we then find a free socket from the ZMQ socket pool, and make a ZMQ request.
 * 3. wait until a response arrives back from ZMQ, and deserialize the json 
 * 4. we update the original request structure with the response data
 */
static int do_zmq(void *instance, REQUEST *request, const char *request_type)
{

    rlm_zmq_t *inst=(rlm_zmq_t *)instance;
    int exitstatus=RLM_MODULE_UPDATED;
    json_object *json_req;
    json_object *statuscode;
    void *zmq_requester;
    ZMQ_CONN *conn;
    int conn_id=-1;
    VALUE_PAIR  *vp;

    radlog(L_DBG,"ZMQ:do_zmq(%s): socket(%s)\n", request_type, inst->zmq_socket_path);


    if ( (conn_id=zmq_get_conn(&conn, inst)) == -1 ) {
        radlog(L_ERR,"ZMQ: All ZMQ sockets (%d) are in use, consider increasing zmq_num_connections\n",inst->num_conns);
        return RLM_MODULE_FAIL;
    }

    zmq_requester=conn->socket;

    json_req = json_object_new_object();

    /* add the request type */
    json_object_object_add(json_req,"type", json_object_new_string(request_type));

    if (inst->zmq_send_control_pairs) {
        zmq_build_json_req(json_req,request->config_items,"control");
    }
    zmq_build_json_req(json_req,request->packet->vps,"request");
    zmq_build_json_req(json_req,request->reply->vps,"reply");

    if (request->proxy != NULL) {
        zmq_build_json_req(json_req,request->proxy->vps,"proxy");
    } 
    if (request->proxy_reply !=NULL) {
        zmq_build_json_req(json_req,request->proxy_reply->vps,"proxy_reply");
    }

    const char *request_str=json_object_to_json_string(json_req);
    int request_str_len=strlen(request_str);
    radlog(L_DBG,"ZMQ: REQUEST-JSON=%s\n", request_str );

    /* send it to the zmq queue */
    zmq_msg_t zmq_request;
    zmq_msg_init_size (&zmq_request, request_str_len);
    memcpy (zmq_msg_data (&zmq_request), request_str, request_str_len);
    zmq_send (zmq_requester, &zmq_request, 0);
    zmq_msg_close (&zmq_request);

    zmq_msg_t zmq_reply;
    zmq_msg_init (&zmq_reply);
    zmq_recv (zmq_requester, &zmq_reply, 0);
    const char *zmq_response=zmq_msg_data(&zmq_reply);
    radlog(L_DBG,"ZMQ: Received response %s\n", zmq_response );


    /* now convert the string back */
    json_object *json_resp = json_tokener_parse(zmq_response);

    /* we're done with the zmq reply*/
    zmq_msg_close (&zmq_reply);

    /* release the connection back to the pool */
    zmq_release_conn(conn_id,inst); 

    if (is_error(json_resp)) {
        radlog(L_DBG,"ZMQ: RESPONSE-JSON:unable to parse json response: %s\n", zmq_response );
        return RLM_MODULE_FAIL;
    }

    radlog(L_DBG,"ZMQ: RESPONSE-JSON = %s\n", json_object_to_json_string(json_resp) );


    /* stick the zmq response 'sections' back into freeradius structs */
    vp = NULL;

    /* request section */
    if (zmq_get_json_avps(json_resp, &vp, "request") > 0) {
        pairfree(&request->packet->vps);
        request->packet->vps = vp;
        vp = NULL;

        /*
         *  Update cached copies
         */
        request->username = pairfind(request->packet->vps,
                PW_USER_NAME);
        request->password = pairfind(request->packet->vps,
                PW_USER_PASSWORD);
        if (!request->password)
            request->password = pairfind(request->packet->vps,
                    PW_CHAP_PASSWORD);
    }

    /* control section */
    if (zmq_get_json_avps(json_resp, &vp, "control") > 0) {
        pairfree(&request->config_items);
        request->config_items = vp;
        vp = NULL;
    }

    /* reply section */
    if (zmq_get_json_avps(json_resp, &vp, "reply") > 0) {
        pairfree(&request->reply->vps);
        request->reply->vps = vp;
        vp = NULL;
    }

    /* proxy section */
    if (request->proxy && 
            zmq_get_json_avps(json_resp, &vp, "proxy") > 0) {
        pairfree(&request->proxy->vps);
        request->proxy->vps = vp;
        vp = NULL;
    }

    /* proxy_reply section */
    if (request->proxy_reply && 
            zmq_get_json_avps(json_resp, &vp, "proxy_reply") > 0) {
        pairfree(&request->proxy_reply->vps);
        request->proxy_reply->vps = vp;
        vp = NULL;
    }

    /* see if we got an exitcode, must be an integer */
    radlog(L_DBG,"ZMQ: examining status code\n");
    statuscode=json_object_object_get(json_resp,"statuscode");
    if (statuscode) {
        if ( json_object_is_type(statuscode,json_type_int) ) {
            exitstatus=json_object_get_int(statuscode);
            radlog(L_DBG,"ZMQ:response statuscode=%d\n", exitstatus);
        } else {
            radlog(L_ERR,"ZMQ:response statuscode is not an integer\n");
        }
    } else {
        /* default to 'updated' if statuscode was not explicitly supplied */
        exitstatus=RLM_MODULE_UPDATED;
        radlog(L_INFO," ZMQ:response statuscode was not supplied, defaulting to %d (RLM_MODULE_UPDATED)\n", exitstatus);
    }

    /* free the response json object */
    json_object_put(json_resp); 

    /* free the request json object */
    json_object_put(json_req); 

    /* debug -- a dump of everything's new state */
    zmq_dump(request->config_items,"control");
    zmq_dump(request->packet->vps,"request");
    zmq_dump(request->reply->vps,"reply");
    if (request->proxy) 
        zmq_dump(request->proxy->vps,"proxy");
    if (request->proxy_reply) 
        zmq_dump(request->proxy_reply->vps,"proxy_reply");

    return exitstatus;
}


/* a bunch of stubs, so we can figure out what we're being called as */
static int do_zmq_authenticate(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"authenticate");
}
static int do_zmq_authorize(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"authorize");
}
static int do_zmq_preacct(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"preacct");
}
static int do_zmq_accounting(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"accounting");
}
static int do_zmq_checksimul(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"checksimul");
}
static int do_zmq_pre_proxy(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"pre-proxy");
}
static int do_zmq_post_proxy(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"post-proxy");
}
static int do_zmq_post_auth(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"post-auth");
}
static int do_zmq_recv_coa(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"recv-coa");
}
static int do_zmq_send_coa(void *instance, REQUEST *request)
{
    return do_zmq(instance,request,"send-coa");
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_zmq = {
	RLM_MODULE_INIT,
	"zmq",
	RLM_TYPE_THREAD_SAFE,		/* type, we work hard on the threadsafe bits */
	zmq_instantiate,		    /* instantiation */
	zmq_detach,			        /* detach */
	{
		do_zmq_authenticate,    /* authentication */
		do_zmq_authorize,       /* authorization */
		do_zmq_preacct,         /* preaccounting */
		do_zmq_accounting,      /* accounting */
		do_zmq_checksimul,      /* checksimul */
		do_zmq_pre_proxy,       /* pre-proxy */
		do_zmq_post_proxy,      /* post-proxy */
		do_zmq_post_auth        /* post-auth */
#ifdef WITH_COA
		,
        do_zmq_recv_coa,        /* recv-coa */
        do_zmq_send_coa         /* send-coa */
#endif
	},
};
