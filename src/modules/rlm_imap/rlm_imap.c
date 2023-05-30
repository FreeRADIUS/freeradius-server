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
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/slab.h>

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

extern global_lib_autoinst_t const * const rlm_imap_lib[];
global_lib_autoinst_t const * const rlm_imap_lib[] = {
	&fr_curl_autoinst,
	GLOBAL_LIB_TERMINATOR
};

typedef struct {
	char const			*uri;		//!< URI of imap server
	fr_time_delta_t 		timeout;	//!< Timeout for connection and server response
	fr_curl_tls_t			tls;
	fr_curl_conn_config_t		conn_config;	//!< Re-usable CURL handle config
} rlm_imap_t;

FR_SLAB_TYPES(imap, fr_curl_io_request_t)
FR_SLAB_FUNCS(imap, fr_curl_io_request_t)

typedef struct {
	imap_slab_list_t		*slab;		//!< Slab list for connection handles.
	fr_curl_handle_t    		*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch and coralling structure for imap requests.
} rlm_imap_thread_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING, rlm_imap_t, uri) },
	{ FR_CONF_OFFSET("timeout",FR_TYPE_TIME_DELTA, rlm_imap_t, timeout), .dflt = "5.0" },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_imap_t, tls), .subcs = (void const *) fr_curl_tls_config },//!<loading the tls values
	{ FR_CONF_OFFSET("connection", FR_TYPE_SUBSECTION, rlm_imap_t, conn_config), .subcs = (void const *) fr_curl_conn_config },
	CONF_PARSER_TERMINATOR
};

static void imap_io_module_signal(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	fr_curl_io_request_t	*randle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);
	rlm_imap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_imap_thread_t);
	CURLMcode		ret;

	RDEBUG2("Forcefully cancelling pending IMAP request");

	ret = curl_multi_remove_handle(t->mhandle->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->mhandle->transfers--;
	imap_slab_release(randle);
}

/*
 *	Called when the IMAP server responds
 *	It checks if the response was CURLE_OK
 *	If it wasn't we returns REJECT, if it was we returns OK
*/
static unlang_action_t CC_HINT(nonnull) mod_authenticate_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx,
								request_t *request)
{
	rlm_imap_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_imap_t);
	fr_curl_io_request_t     	*randle = talloc_get_type_abort(mctx->rctx, fr_curl_io_request_t);
	fr_curl_tls_t const		*tls;
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
		CURLcode result = randle->result;
		imap_slab_release(randle);
		switch(result) {
		case CURLE_PEER_FAILED_VERIFICATION:
		case CURLE_LOGIN_DENIED:
			RETURN_MODULE_REJECT;
		default:
			RETURN_MODULE_FAIL;
		}
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	imap_slab_release(randle);
	RETURN_MODULE_OK;
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
static unlang_action_t CC_HINT(nonnull(1,2)) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_imap_thread_t       *t = talloc_get_type_abort(mctx->thread, rlm_imap_thread_t);

	fr_pair_t const 	*username;
	fr_pair_t const 	*password;
	fr_curl_io_request_t    *randle;

	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	password = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);

	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (!password) {
		RDEBUG2("Attribute \"User-Password\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (password->vp_length == 0) {
		RDEBUG2("\"User-Password\" must not be empty");
		RETURN_MODULE_INVALID;
	}

	randle = imap_slab_reserve(t->slab);
	if (!randle){
		RETURN_MODULE_FAIL;
	}

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) {
	error:
		imap_slab_release(randle);
		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, mod_authenticate_resume, imap_io_module_signal, ~FR_SIGNAL_CANCEL, randle);
}

/** Clean up CURL handle on freeing
 *
 */
static int _mod_conn_free(fr_curl_io_request_t *randle)
{
	curl_easy_cleanup(randle->candle);

	return 0;
}

/** Callback to configure a CURL handle when it is allocated
 *
 */
static int imap_conn_alloc(fr_curl_io_request_t *randle, void *uctx)
{
	rlm_imap_t const	*inst = talloc_get_type_abort(uctx, rlm_imap_t);

	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
	error:
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}

	talloc_set_destructor(randle, _mod_conn_free);

#if CURL_AT_LEAST_VERSION(7,45,0)
	FR_CURL_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "imap");
#endif
	FR_CURL_SET_OPTION(CURLOPT_URL, inst->uri);
#if CURL_AT_LEAST_VERSION(7,85,0)
	FR_CURL_SET_OPTION(CURLOPT_PROTOCOLS_STR, "imap,imaps");
#else
	FR_CURL_SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_IMAP | CURLPROTO_IMAPS);
#endif
	FR_CURL_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));

	if (DEBUG_ENABLED3) FR_CURL_SET_OPTION(CURLOPT_VERBOSE, 1L);

	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) goto error;

	return 0;
}

/*
 *	Initialize a new thread with a curl instance
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_imap_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_imap_t);
	rlm_imap_thread_t    	*t = talloc_get_type_abort(mctx->thread, rlm_imap_thread_t);
	fr_curl_handle_t    	*mhandle;

	if (!(t->slab = imap_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
					     imap_conn_alloc, NULL, inst,
					     false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	mhandle = fr_curl_io_init(t, mctx->el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;
	return 0;
}

/*
 *	Close the thread and free the memory
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_imap_thread_t    		*t = talloc_get_type_abort(mctx->thread, rlm_imap_thread_t);

	talloc_free(t->mhandle);
	talloc_free(t->slab);
    	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_imap;
module_rlm_t rlm_imap = {
	.common = {
		.magic		        = MODULE_MAGIC_INIT,
		.name		        = "imap",
		.type		        = MODULE_TYPE_THREAD_SAFE,
		.inst_size	        = sizeof(rlm_imap_t),
		.thread_inst_size   	= sizeof(rlm_imap_thread_t),
		.config		        = module_config,
		.thread_instantiate 	= mod_thread_instantiate,
		.thread_detach      	= mod_thread_detach,
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate },
		MODULE_NAME_TERMINATOR
	}
};
