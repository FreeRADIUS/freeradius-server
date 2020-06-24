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
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/curl/base.h>

static fr_dict_t 	const 		*dict_radius; /*dictionary for radius protocol*/

static fr_dict_attr_t 	const 		*attr_user_password;
static fr_dict_attr_t 	const 		*attr_user_name;

extern fr_dict_autoload_t rlm_imap_dict[];
fr_dict_autoload_t rlm_imap_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t rlm_imap_dict_attr[];
fr_dict_attr_autoload_t rlm_imap_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL },
};

typedef struct {
	char const			*uri;		//!< URI of imap server
	fr_time_delta_t 		timeout;	//!< Timeout for connection and server response
	fr_curl_tls_t			tls;
} rlm_imap_t;

typedef struct {
	rlm_imap_t const    		*inst;		//!< Instance of rlm_imap.
	fr_curl_handle_t    		*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch and coralling structure for imap requests.
} rlm_imap_thread_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING, rlm_imap_t, uri) },
	{ FR_CONF_OFFSET("timeout",FR_TYPE_TIME_DELTA, rlm_imap_t, timeout) },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_imap_t, tls), .subcs = (void const *) fr_curl_tls_config },//!<loading the tls values
	CONF_PARSER_TERMINATOR
};

/*
 *	Called when the IMAP server responds
 *	It checks if the response was CURLE_OK
 *	If it wasn't we returns REJECT, if it was we returns OK
*/
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate_resume(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	rlm_imap_t			*inst = talloc_get_type_abort_const(mctx->instance, rlm_imap_t);
	fr_curl_io_request_t     	*randle = rctx;
	fr_curl_tls_t			*tls;
	long 				curl_out;
	long				curl_out_valid;

	tls = &inst->tls;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	talloc_free(randle);
	return RLM_MODULE_OK;
}

/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	Checks that User-Password is not Blank
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		and TLS information
 *
 *	Then it queues the request and yeilds until a response is given
 *	When it responds, mod_authenticate_resume is called.
 */
static rlm_rcode_t CC_HINT(nonnull(1,2)) mod_authenticate(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_imap_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_imap_t);
	rlm_imap_thread_t       *t = talloc_get_type_abort(mctx->thread, rlm_imap_thread_t);

	VALUE_PAIR const 	*username;
	VALUE_PAIR const 	*password;
	fr_curl_io_request_t    *randle;

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

	FR_CURL_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
	FR_CURL_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);

	FR_CURL_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "imap");
	FR_CURL_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));

	FR_CURL_SET_OPTION(CURLOPT_VERBOSE, 1L);

	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authenticate_resume, NULL, randle);
}

/*
 *	Initialize global curl instance
 */
static int mod_load(void)
{
	if (fr_curl_init() < 0) return -1;
	return 0;
}

/*
 *	Close global curl instance
 */
static void mod_unload(void)
{
	fr_curl_free();
}

/*
 *	Initialize a new thread with a curl instance
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
 *	Close the thread and free the memory
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
    rlm_imap_thread_t    *t = thread;

    talloc_free(t->mhandle);
    return 0;
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
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach      	= mod_thread_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
	},
};
