/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_imap.c
 * @brief imap server authentication.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/curl/base.h>

/*
 *	A mapping of configuration file names to internal variables.
 */
static fr_dict_t 	const 		*dict_radius; /*dictionary for radius protocol*/
static fr_dict_t 	const 		*dict_freeradius; /*internal dictionary for server*/

static fr_dict_attr_t 	const 		*attr_auth_type;

static fr_dict_attr_t 	const 		*attr_user_password;
static fr_dict_attr_t 	const 		*attr_user_name;

extern fr_dict_autoload_t rlm_imap_dict[];
fr_dict_autoload_t rlm_imap_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t rlm_imap_dict_attr[];
fr_dict_attr_autoload_t rlm_imap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

typedef struct {
	fr_dict_enum_t        		*auth_type;
	char const        		*name;
	char const			*imap_URI;	//!<URL of imap server
	fr_time_delta_t 		timeout;	//!<Timeout for connection and server response
	fr_curl_tls_t			tls;
} rlm_imap_t;

typedef struct {
	rlm_imap_t const    		*inst;        //!< Instance of rlm_imap.
	fr_curl_handle_t    		*mhandle;    //!< Thread specific multi handle.  Serves as the dispatch and coralling structure for imap requests.
}rlm_imap_thread_t;

typedef struct {
	rlm_imap_t const    		*instance;    //!< This instance of rlm_imap.
	REQUEST           		*request;    //!< Current request.
} rlm_imap_request_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("imap_URI", FR_TYPE_STRING, rlm_imap_t, imap_URI) },
	{ FR_CONF_OFFSET("timeout",FR_TYPE_UINT32, rlm_imap_t, timeout) },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_imap_t, tls), .subcs = (void const *) tls_config },//!<loading the tls values
	CONF_PARSER_TERMINATOR
};

static int rlm_imap_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing,VALUE_PAIR *check,
			UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->vp_type == FR_TYPE_STRING);

	RINFO("imap-Paircmp called with \"%pV\"", &check->data);

	if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
	return 1;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_imap_t	*inst = instance;
	if (paircmp_register_by_name("imap-Paircmp", attr_user_name, false, rlm_imap_cmp, inst) < 0) {
		return -1;
	}
	return 0;
}
/*
*Check to see that we have a username and password
*print out the username
*if a value is missing return NOOP
*/
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR 			*vp;
	rlm_imap_t			*inst	= instance;

	vp = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	if (vp == NULL) return RLM_MODULE_NOOP;
	RDEBUG2("Authorizing: %pP", vp);
	vp = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	if (vp == NULL) return RLM_MODULE_NOOP;
	/*
	 *Check to see if there is already a section that will be working on the request
	 */
	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) return RLM_MODULE_NOOP;

	return RLM_MODULE_OK;
}
/*
 *Called when the IMAP server responds
 *It checks if the response was CURLE_OK
 *If it wasn't we returns REJECT, if it was we returns OK
*/
static rlm_rcode_t mod_authenticate_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	fr_curl_io_request_t     	*randle   = rctx;
	rlm_imap_t			*inst 	= instance;
	fr_curl_tls_t			*tls;
	long 				*curl_out;

	tls = &inst->tls;

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->tls_extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	RDEBUG2("CURL OUT: %ld", *curl_out);

	talloc_free(randle);
	return RLM_MODULE_OK;
}
/*
 * Checks that there is a User-Name and User-Password field in the request
 * Checks that User-Password is not Blank
 * Sets the: username, password
 * website URI
 * timeout information
 * and TLS information
 * Then it queues the request and yeilds until a response is given
 * When it responds, mod_authenticate_resume is called
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, void *thread, REQUEST *request)
{
	VALUE_PAIR const 		*username;
	VALUE_PAIR const 		*password;
	rlm_imap_t			*inst = instance;
	
	rlm_imap_thread_t       	*t = thread;
	fr_curl_io_request_t    	*randle;
    
	fr_time_delta_t        		timeout = inst->timeout;
	CURLcode        		ret;
	char const			*imap_URI = inst->imap_URI;

	randle = fr_curl_io_request_alloc(request);
	if (!randle){
	error:
		return RLM_MODULE_FAIL;
	}
	
	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}
	if (!password) {
		RDEBUG2("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}
	if (password->vp_length == 0) {
		RDEBUG2("\"User-Password\" must not be empty");
		return RLM_MODULE_INVALID;
	}
	
	SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
	SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);
	SET_OPTION(CURLOPT_URL, imap_URI);
    
	SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, timeout);
	SET_OPTION(CURLOPT_TIMEOUT_MS, timeout);

	if(fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;
    
	ret = fr_curl_io_request_enqueue(t->mhandle, request, randle);
    
	return unlang_module_yield(request, mod_authenticate_resume, NULL, randle);
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const        		*name;
	rlm_imap_t       		*inst = instance;
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->name = name;
	if (fr_dict_enum_add_name_next(fr_dict_attr_unconst(attr_auth_type), inst->name) < 0) {
		PERROR("Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, inst->name, -1);
	rad_assert(inst->auth_type);
	return 0;
}
/*
 * Initialize global curl instance
 */
static int mod_load(void)
{
	if (fr_curl_init() < 0) return -1;
	return 0;
}
/*
 * Close global curl instance
 */
static void mod_unload(void)
{
	fr_curl_free();
}
/*
 * Initialie a new thread with a curl instance
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_imap_thread_t    		*t = thread;
	fr_curl_handle_t    		*mhandle;

	t->inst = instance;
   
	mhandle = fr_curl_io_init(t, el, false);
	if (!mhandle) return -1;
	t->mhandle = mhandle;
	    
	return 0;
}
/*
 * Close the thread and free the memory
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
    rlm_imap_thread_t    *t = thread;
    talloc_free(t->mhandle);    /* Ensure this is shutdown before the pool */
    return 0;
}
/*
 * External module to call rlm_imap's functions
 */
extern module_t rlm_imap;
module_t rlm_imap = {
	.magic		        = RLM_MODULE_INIT,
	.name		        = "imap",
	.type		        = RLM_TYPE_THREAD_SAFE,
	.inst_size	        = sizeof(rlm_imap_t),
	.thread_inst_size   	= sizeof(rlm_imap_thread_t),
	.config		        = module_config,
	.onload            	= mod_load,
	.unload             	= mod_unload,
	.bootstrap          	= mod_bootstrap,
	.instantiate	    	= mod_instantiate,
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach      	= mod_thread_detach,
    
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
	},
};
