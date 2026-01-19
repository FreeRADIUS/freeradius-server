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
 * @file rlm_ftp.c
 * @brief Fetch objects from FTP endpoints
 *
 * @copyright 2025 NetworkRADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/curl/xlat.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>

#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/uri.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/xlat_func.h>

#define FTP_BODY_ALLOC_CHUNK		1024

typedef struct {
	fr_curl_conn_config_t	conn_config;	//!< Configuration of slab allocated connection handles.
	size_t			max_resp_size;	//!< Maximum size of incoming data.
	bool			binary;		//!< Do we expect binary data - and so output octets.
} rlm_ftp_t;

FR_SLAB_TYPES(ftp, fr_curl_io_request_t)
FR_SLAB_FUNCS(ftp, fr_curl_io_request_t)

typedef struct {
	rlm_ftp_t const		*inst;		//!< Instance of rlm_ftp.
	ftp_slab_list_t		*slab;		//!< Slab list for connection handles.
	fr_curl_handle_t	*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch
						//!< and coralling structure for FTP requests.
} rlm_ftp_thread_t;

typedef struct {
	fr_curl_io_request_t	*handle;	//!< curl easy handle servicing our request.
} rlm_ftp_xlat_rctx_t;

/*
 *	States for the response
 */
typedef enum {
	WRITE_STATE_INIT = 0,
	WRITE_STATE_POPULATED,
	WRITE_STATE_DISCARD,
} write_state_t;

/*
 *	Curl inbound data context (passed to CURLOPT_WRITEFUNCTION as CURLOPT_WRITEDATA)
 */
typedef struct {
	rlm_ftp_t const		*instance;	//!< This instance of rlm_ftp.

	request_t		*request;	//!< Current request.
	write_state_t		state;		//!< Decoder state.

	char			*buffer;	//!< Raw incoming FTP data.
	size_t		 	alloc;		//!< Space allocated for buffer.
	size_t		 	used;		//!< Space used in buffer.
} rlm_ftp_response_t;

/*
 *	Curl context data
 */
typedef struct {
	rlm_ftp_response_t	response;	//!< Response context data.
} rlm_ftp_curl_context_t;

static int ftp_uri_part_escape(fr_value_box_t *vb, void *uctx);

static fr_uri_part_t const ftp_uri_parts[] = {
	{ .name = "scheme", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":")), .part_adv = { [':'] = 1 }, .extra_skip = 2 },
	{ .name = "host", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":"), L("/")), .part_adv = { [':'] = 1, ['/'] = 2 }, .func = ftp_uri_part_escape },
	{ .name = "port", .safe_for = CURL_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("/")), .part_adv = { ['/'] = 1 } },
	{ .name = "method", .safe_for = CURL_URI_SAFE_FOR, .func = ftp_uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("max_resp_size", FR_TYPE_SIZE, 0, rlm_ftp_t, max_resp_size), .dflt = "16k" },
	{ FR_CONF_OFFSET("binary", rlm_ftp_t, binary), .dflt = "no" },

	{ FR_CONF_OFFSET_SUBSECTION("connection", 0, rlm_ftp_t, conn_config, fr_curl_conn_config) },

	CONF_PARSER_TERMINATOR
};

extern global_lib_autoinst_t const * const rlm_ftp_lib[];
global_lib_autoinst_t const * const rlm_ftp_lib[] = {
	&fr_curl_autoinst,
	GLOBAL_LIB_TERMINATOR
};

/** URL escape a single box forming part of a URL
 *
 * @param[in] vb		to escape
 * @param[in] uctx		UNUSED context containing CURL handle
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
static int ftp_uri_part_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	char	*escaped, *str;

	escaped = curl_easy_escape(fr_curl_tmp_handle(), vb->vb_strvalue, vb->vb_length);
	if (!escaped) return -1;

	/*
	 *	Returned string the same length - nothing changed
	 */
	if (strlen(escaped) == vb->vb_length) {
		curl_free(escaped);
		return 0;
	}

	str = talloc_typed_strdup(vb, escaped);
	fr_value_box_strdup_shallow_replace(vb, str, strlen(str));

	curl_free(escaped);

	return 0;
}

static xlat_action_t ftp_get_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					 UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_ftp_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_ftp_t);
	rlm_ftp_xlat_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, rlm_ftp_xlat_rctx_t);
	fr_curl_io_request_t	*handle = talloc_get_type_abort(rctx->handle, fr_curl_io_request_t);
	rlm_ftp_curl_context_t	*curl_ctx = talloc_get_type_abort(handle->uctx, rlm_ftp_curl_context_t);
	xlat_action_t		xa = XLAT_ACTION_DONE;

	switch (curl_ctx->response.state) {
	case WRITE_STATE_INIT:
	case WRITE_STATE_DISCARD:
		xa = XLAT_ACTION_FAIL;
		goto finish;

	case WRITE_STATE_POPULATED:
		break;
	}

	if (curl_ctx->response.used > 0) {
		fr_value_box_t *vb;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (inst->binary) {
			fr_value_box_memdup(vb, vb, NULL, (uint8_t *)curl_ctx->response.buffer, curl_ctx->response.used, true);
		} else {
			fr_value_box_bstrndup(vb, vb, NULL, curl_ctx->response.buffer, curl_ctx->response.used, true);
		}
		fr_dcursor_insert(out, vb);
	}

finish:
	ftp_slab_release(handle);
	talloc_free(rctx);

	return xa;
}

static void ftp_io_xlat_signal(xlat_ctx_t const *xctx, request_t *request, UNUSED fr_signal_t action)
{
	rlm_ftp_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_ftp_thread_t);
	rlm_ftp_xlat_rctx_t	*our_rctx = talloc_get_type_abort(xctx->rctx, rlm_ftp_xlat_rctx_t);
	fr_curl_io_request_t	*randle = talloc_get_type_abort(our_rctx->handle, fr_curl_io_request_t);
	CURLMcode		ret;

	RDEBUG2("Forcefully cancelling pending FTP request");

	ret = curl_multi_remove_handle(t->mhandle->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->mhandle->transfers--;

	ftp_slab_release(randle);
}


static size_t ftp_response_body(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_ftp_response_t	*ctx = userdata;
	request_t		*request = ctx->request; /* Used by RDEBUG */

	char const		*start = in, *end = start + (size * nmemb);
	char			*out;
	size_t			needed, chunk_len, total;

	/*
	 *	Get how much data we're being asked to write now, and the total amount of data we've written.
	 */
	chunk_len = (size_t) (end - start);
	total = ctx->used + chunk_len;

	if (!chunk_len) return 0; 	/* Nothing to process */

	/*
	 *	We had previously decided to discard the writes, just tell curl "yes, we wrote it all".
	 */
	if (ctx->state == WRITE_STATE_DISCARD) return chunk_len;

	/*
	 *	We're being asked to write too much data, free the buffer and discard all of the data.
	 */
	if (total > ctx->instance->max_resp_size) {
		REDEBUG("Incoming data (%zu bytes) exceeds max_body_in (%zu bytes).  Forcing discard",
			total, ctx->instance->max_resp_size);
		ctx->state = WRITE_STATE_DISCARD;
		TALLOC_FREE(ctx->buffer);
		ctx->alloc = 0;
		ctx->used  = 0;
		return chunk_len;
	}

	/*
	 *	If there's no buffer, then we can't have used any part of the buffer.
	 */
	fr_assert(ctx->buffer || !ctx->used);

	/*
	 *	Ensure that there's enough room in the buffer for all of the data that we need to write.
	 */
	needed = ROUND_UP(total, FTP_BODY_ALLOC_CHUNK);
	if (needed > ctx->alloc) {
		MEM(ctx->buffer = talloc_bstr_realloc(NULL, ctx->buffer, needed));
		ctx->alloc = needed;
	}

	out = ctx->buffer + ctx->used;
	memcpy(out, start, chunk_len);
	ctx->used = total;
	ctx->buffer[ctx->used] = '\0';

	return chunk_len;
}


static xlat_arg_parser_t const ftp_get_xlat_args[] = {
	{ .required = true, .safe_for = CURL_URI_SAFE_FOR, .type = FR_TYPE_STRING, .will_escape = true },	/* URL */
	XLAT_ARG_PARSER_TERMINATOR
};

/** Simple xlat to read data from an FTP URI
 *
 * Example:
@verbatim
%ftp.get('ftp://example.com/file.txt')
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ftp_get_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				  xlat_ctx_t const *xctx, request_t *request,
				  fr_value_box_list_t *in)
{
	rlm_ftp_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_ftp_thread_t);
	fr_curl_io_request_t	*randle = NULL;
	int			ret;
	fr_value_box_t		*uri_vb;
	rlm_ftp_curl_context_t	*curl_ctx;
	rlm_ftp_xlat_rctx_t	*rctx;

	XLAT_ARGS(in, &uri_vb);

	MEM(rctx = talloc(request, rlm_ftp_xlat_rctx_t));

	/*
	 *	Handle URI component escaping
	 */
	if (fr_uri_escape_list(&uri_vb->vb_group, ftp_uri_parts, NULL) < 0) {
		RPEDEBUG("Failed escaping URI");
	error:
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_list_concat_in_place(uri_vb,
					      uri_vb, &uri_vb->vb_group, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		REDEBUG("Concatenating URI");
		goto error;
	}

	/*
	 *	We get a connection from the pool here as the CURL object
	 *	is needed to use curl_easy_escape() for escaping
	 */
	randle = rctx->handle = ftp_slab_reserve(t->slab);
	if (!randle) return XLAT_ACTION_FAIL;

	randle->request = request;	/* Populate the request pointer for escape callbacks */
	curl_ctx = talloc_get_type_abort(randle->uctx, rlm_ftp_curl_context_t);
	curl_ctx->response.request = request;

	RDEBUG2("Sending FTP GET to \"%pV\"", uri_vb);

	/*
	 *  Configure various CURL options, and initialise the read/write
	 *  context data.
	 */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, uri_vb->vb_strvalue);
#if CURL_AT_LEAST_VERSION(7,85,0)
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS_STR, "ftp");
#else
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_FTP);
#endif
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEFUNCTION, ftp_response_body);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEDATA, &curl_ctx->response);

	/*
	 *  Send the CURL request
	 */
	ret = fr_curl_io_request_enqueue(t->mhandle, request, randle);
	if (ret < 0) {
		ftp_slab_release(randle);
		goto error;
	}

	return unlang_xlat_yield(request, ftp_get_xlat_resume, ftp_io_xlat_signal, ~FR_SIGNAL_CANCEL, rctx);
}

/** Cleans up after a FTP request.
 *
 * Resets all options associated with a CURL handle, and frees any headers
 * associated with it.
 *
 * Calls ftp_read_ctx_free and ftp_response_free to free any memory used by
 * context data.
 *
 * @param[in] randle to cleanup.
 * @param[in] uctx unused.
 */
static int _ftp_request_cleanup(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	rlm_ftp_curl_context_t	*ctx = talloc_get_type_abort(randle->uctx, rlm_ftp_curl_context_t);
	CURL			*candle = randle->candle;

	/*
	 *  Clear any previously configured options
	 */
	curl_easy_reset(candle);

#ifndef NDEBUG
	{
		CURLcode ret;
		/*
		 *  With curl 7.61 when a request in cancelled we get a result
		 *  with a NULL (invalid) pointer to private data.  This lets
		 *  us know that the request was returned to the slab.
		 */
		ret = curl_easy_setopt(candle, CURLOPT_PRIVATE, (void *)0xdeadc341);
		if (unlikely(ret != CURLE_OK)) {
			ERROR("Failed to set private data on curl easy handle %p: %s",
			      candle, curl_easy_strerror(ret));
		}
	}
#endif

	/*
	 *  Free response data
	 */
	TALLOC_FREE(ctx->response.buffer);
	ctx->response.alloc = 0;
	ctx->response.used = 0;

	randle->request = NULL;
	return 0;
}

static int _mod_conn_free(fr_curl_io_request_t *randle)
{
	curl_easy_cleanup(randle->candle);
	return 0;
}

static int ftp_conn_alloc(fr_curl_io_request_t *randle, void *uctx)
{
	rlm_ftp_t const		*inst = talloc_get_type_abort(uctx, rlm_ftp_t);
	rlm_ftp_curl_context_t	*curl_ctx = NULL;

	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}

	MEM(curl_ctx = talloc_zero(randle, rlm_ftp_curl_context_t));
	curl_ctx->response.instance = inst;

	randle->uctx = curl_ctx;
	talloc_set_destructor(randle, _mod_conn_free);

	ftp_slab_element_set_destructor(randle,  _ftp_request_cleanup, NULL);

	return 0;
}

/** Create a thread specific multihandle
 *
 * Easy handles representing requests are added to the curl multihandle
 * with the multihandle used for mux/demux.
 *
 * @param[in] mctx	Thread instantiation data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_ftp_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_ftp_t);
	rlm_ftp_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_ftp_thread_t);
	fr_curl_handle_t	*mhandle;

	t->inst = inst;

	if (!(t->slab = ftp_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
					    ftp_conn_alloc, NULL, inst, false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	mhandle = fr_curl_io_init(t, mctx->el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;

	return 0;
}

/** Cleanup all outstanding requests associated with this thread
 *
 * Destroys all curl easy handles, and then the multihandle associated
 * with this thread.
 *
 * @param[in] mctx	data to destroy.
 * @return 0
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_ftp_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_ftp_thread_t);

	talloc_free(t->mhandle);	/* Ensure this is shutdown before the pool */
	talloc_free(t->slab);

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t		*xlat;
	rlm_ftp_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ftp_t);

	if (unlikely(!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "get", ftp_get_xlat,
						       inst->binary ? FR_TYPE_OCTETS : FR_TYPE_STRING)))) return -1;
	xlat_func_args_set(xlat, ftp_get_xlat_args);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_ftp_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ftp_t);

	inst->conn_config.reuse.num_children = 1;
	inst->conn_config.reuse.child_pool_size = sizeof(rlm_ftp_curl_context_t);

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
extern module_rlm_t rlm_ftp;
module_rlm_t rlm_ftp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "ftp",
		.inst_size		= sizeof(rlm_ftp_t),
		.thread_inst_size	= sizeof(rlm_ftp_thread_t),
		.config			= module_config,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			MODULE_BINDING_TERMINATOR
		}
	}
};
