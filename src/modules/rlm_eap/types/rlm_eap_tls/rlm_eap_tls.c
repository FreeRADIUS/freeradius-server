/*
 * rlm_eap_tls.c  contains the interfaces that are called from eap
 *
 * Version:     $Id$
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
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 *
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/tls/openssl_user_macros.h>
#ifdef HAVE_OPENSSL_RAND_H
#  include <openssl/rand.h>
#endif
#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include "rlm_eap_tls.h"

typedef struct {
	SSL_CTX		*ssl_ctx;		//!< Thread local SSL_CTX.
} rlm_eap_tls_thread_t;

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("tls", FR_TYPE_STRING, rlm_eap_tls_t, tls_conf_name) },

	{ FR_CONF_OFFSET("require_client_cert", FR_TYPE_BOOL, rlm_eap_tls_t, req_client_cert), .dflt = "yes" },
	{ FR_CONF_OFFSET("include_length", FR_TYPE_BOOL, rlm_eap_tls_t, include_length), .dflt = "yes" },
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, rlm_eap_tls_t, virtual_server) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_eap_tls_dict[];
fr_dict_autoload_t rlm_eap_tls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_eap_tls_require_client_cert;
static fr_dict_attr_t const *attr_virtual_server;

extern fr_dict_attr_autoload_t rlm_eap_tls_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_tls_dict_attr[] = {
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_virtual_server, .name = "Virtual-Server", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

static unlang_action_t mod_handshake_done(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
					  UNUSED request_t *request)
{
	RETURN_MODULE_OK;
}

static unlang_action_t mod_handshake_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;

	if ((eap_tls_session->state == EAP_TLS_INVALID) || (eap_tls_session->state == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, eap_tls_session->state, "<INVALID>"));
	}

	switch (eap_tls_session->state) {
	/*
	 *	EAP-TLS handshake was successful, return an
	 *	EAP-TLS-Success packet here.
	 *
	 *	If a virtual server was configured, check that
	 *	it accepts the certificates, too.
	 */
	case EAP_TLS_ESTABLISHED:
	{
		eap_tls_prf_label_t prf_label;

		eap_crypto_prf_label_init(&prf_label, eap_session,
					  "client EAP encryption",
					  sizeof("client EAP encryption") - 1);

		if (eap_tls_success(request, eap_session, &prf_label) < 0) RETURN_MODULE_FAIL;

		/*
		 *	Result is always OK, even if we fail to persist the
		 *	session data.
		 */
		unlang_module_yield(request, mod_handshake_done, NULL, mctx->rctx);
		/*
		 *	Write the session to the session cache
		 *
		 *	We do this here (instead of relying on OpenSSL to call the
		 *	session caching callback), because we only want to write
		 *	session data to the cache if all phases were successful.
		 *
		 *	If we wrote out the cache data earlier, and the server
		 *	exited whilst the session was in progress, the supplicant
		 *	could resume the session (and get access) even if phase2
		 *	never completed.
		 */
		return fr_tls_cache_pending_push(request, tls_session);
	}

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		RETURN_MODULE_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
		REDEBUG("Received unexpected tunneled data after successful handshake");
		eap_tls_fail(request, eap_session);

		RETURN_MODULE_INVALID;

	/*
	 *	Anything else: fail.
	 *
	 *	Also, remove the session from the cache so that
	 *	the client can't re-use it.
	 */
	default:
		fr_tls_cache_deny(request, tls_session);
		*p_result = RLM_MODULE_REJECT;

		/*
		 *	We'll jump back to the caller
		 *	in the unlang stack if this
		 *	fails.
		 */
		return fr_tls_cache_pending_push(request, tls_session);	/* Run any pending cache clear operations */
	}
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static unlang_action_t mod_handshake_process(UNUSED rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
					     request_t *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);

	/*
	 *	Setup the resumption frame to process the result
	 */
	(void)unlang_module_yield(request, mod_handshake_resume, NULL, eap_session);

	/*
	 *	Process TLS layer until done.
	 */
	return eap_tls_process(request, eap_session);
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_tls_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_eap_tls_t);
	rlm_eap_tls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_tls_thread_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session;

	fr_pair_t		*vp;
	bool			client_cert;

	eap_session->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	/*
	 *	EAP-TLS always requires a client certificate.
	 */
	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, t->ssl_ctx, client_cert);
	if (!eap_tls_session) RETURN_MODULE_FAIL;

	eap_tls_session->include_length = inst->include_length;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		RETURN_MODULE_FAIL;
	}

	eap_session->process = mod_handshake_process;

	RETURN_MODULE_HANDLED;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_tls_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_eap_tls_t);
	rlm_eap_tls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_tls_thread_t);

	t->ssl_ctx = fr_tls_ctx_alloc(inst->tls_conf, false);
	if (!t->ssl_ctx) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_eap_tls_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_eap_tls_thread_t);

	if (likely(t->ssl_ctx != NULL)) SSL_CTX_free(t->ssl_ctx);
	t->ssl_ctx = NULL;

	return 0;
}

/*
 *	Attach the EAP-TLS module.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_tls_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_eap_tls_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	inst->tls_conf = eap_tls_conf_parse(conf, "tls");
	if (!inst->tls_conf) {
		cf_log_err(conf, "Failed initializing SSL context");
		return -1;
	}

	if (inst->virtual_server && !virtual_server_find(inst->virtual_server)) {
		cf_log_err_by_child(conf, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_tls;
rlm_eap_submodule_t rlm_eap_tls = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "eap_tls",
		.inst_size		= sizeof(rlm_eap_tls_t),
		.config			= submodule_config,
		.instantiate		= mod_instantiate,	/* Create new submodule instance */

		.thread_inst_size	= sizeof(rlm_eap_tls_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.provides		= { FR_EAP_METHOD_TLS },
	.session_init		= mod_session_init,	/* Initialise a new EAP session */
};
