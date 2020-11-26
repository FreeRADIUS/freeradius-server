/*
 * rlm_eap_peap.c  contains the interfaces that are called from eap
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
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_eap_peap - "

#include <freeradius-devel/eap/tls.h>
#include "eap_peap.h"

typedef struct {
	char const		*tls_conf_name;		//!< TLS configuration.
	fr_tls_conf_t		*tls_conf;

	bool			use_tunneled_reply;	//!< Use the reply attributes from the tunneled session in
							//!< the non-tunneled reply to the client.

	bool			copy_request_to_tunnel;	//!< Use SOME of the request attributes from outside of the
							//!< tunneled session in the tunneled request.
#ifdef WITH_PROXY
	bool			proxy_tunneled_request_as_eap;	//!< Proxy tunneled session as EAP, or as de-capsulated
							//!< protocol.
#endif
	char const		*virtual_server;	//!< Virtual server for inner tunnel session.

	bool			soh;			//!< Do we do SoH request?
	char const		*soh_virtual_server;
	bool			req_client_cert;	//!< Do we do require a client cert?
} rlm_eap_peap_t;

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("tls", FR_TYPE_STRING, rlm_eap_peap_t, tls_conf_name) },

	{ FR_CONF_DEPRECATED("copy_request_to_tunnel", FR_TYPE_BOOL, rlm_eap_peap_t, NULL), .dflt = "no" },

	{ FR_CONF_DEPRECATED("use_tunneled_reply", FR_TYPE_BOOL, rlm_eap_peap_t, NULL), .dflt = "no" },

#ifdef WITH_PROXY
	{ FR_CONF_OFFSET("proxy_tunneled_request_as_eap", FR_TYPE_BOOL, rlm_eap_peap_t, proxy_tunneled_request_as_eap), .dflt = "yes" },
#endif

	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_eap_peap_t, virtual_server) },

	{ FR_CONF_OFFSET("soh", FR_TYPE_BOOL, rlm_eap_peap_t, soh), .dflt = "no" },

	{ FR_CONF_OFFSET("require_client_cert", FR_TYPE_BOOL, rlm_eap_peap_t, req_client_cert), .dflt = "no" },

	{ FR_CONF_OFFSET("soh_virtual_server", FR_TYPE_STRING, rlm_eap_peap_t, soh_virtual_server) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_peap_dict[];
fr_dict_autoload_t rlm_eap_peap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_auth_type;
fr_dict_attr_t const *attr_eap_tls_require_client_cert;
fr_dict_attr_t const *attr_proxy_to_realm;
fr_dict_attr_t const *attr_soh_supported;

fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_freeradius_proxied_to;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_peap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_soh_supported, .name = "SoH-Supported", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "Vendor-Specific.FreeRADIUS.Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};


/*
 *	Allocate the PEAP per-session data
 */
static peap_tunnel_t *peap_alloc(TALLOC_CTX *ctx, rlm_eap_peap_t *inst)
{
	peap_tunnel_t *t;

	t = talloc_zero(ctx, peap_tunnel_t);

#ifdef WITH_PROXY
	t->proxy_tunneled_request_as_eap = inst->proxy_tunneled_request_as_eap;
#endif
	t->virtual_server = inst->virtual_server;
	t->soh = inst->soh;
	t->soh_virtual_server = inst->soh_virtual_server;
	t->session_resumption_state = PEAP_RESUMPTION_MAYBE;
	fr_pair_list_init(&t->soh_reply_vps);

	return t;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type(mctx->instance, rlm_eap_peap_t);

	rlm_rcode_t		rcode;
	eap_tls_status_t	status;

	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t	*tls_session = eap_tls_session->tls_session;
	peap_tunnel_t		*peap = NULL;

	if (tls_session->opaque) {
		peap = talloc_get_type_abort(tls_session->opaque, peap_tunnel_t);
	/*
	 *	Session resumption requires the storage of data, so
	 *	allocate it if it doesn't already exist.
	 */
	} else {
		peap = tls_session->opaque = peap_alloc(tls_session, inst);
	}

	status = eap_tls_process(request, eap_session);
	if ((status == EAP_TLS_INVALID) || (status == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	}

	switch (status) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case EAP_TLS_ESTABLISHED:
		peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		/*
		 *	FIXME: If the SSL session is established, grab the state
		 *	and EAP id from the inner tunnel, and update it with
		 *	the expected EAP id!
		 */
		RETURN_MODULE_HANDLED;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case EAP_TLS_RECORD_RECV_COMPLETE:
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding tunneled data");

	/*
	 *	We may need PEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) tls_session->opaque = peap_alloc(tls_session, inst);

	/*
	 *	Process the PEAP portion of the request.
	 */
	eap_peap_process(&rcode, request, eap_session, tls_session);
	switch (rcode) {
	case RLM_MODULE_REJECT:
		eap_tls_fail(request, eap_session);
		break;

	case RLM_MODULE_HANDLED:
		eap_tls_request(request, eap_session);
		break;

	case RLM_MODULE_OK:
	{
		static char keying_prf_label[] = "client EAP encryption";

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		if (eap_tls_success(request, eap_session,
				    keying_prf_label, sizeof(keying_prf_label) - 1,
				    NULL, 0) < 0) return 0;
	}
		break;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case RLM_MODULE_UPDATED:
		break;

	default:
		eap_tls_fail(request, eap_session);
		break;
	}

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static unlang_action_t mod_session_init(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(mctx->instance, rlm_eap_peap_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session;

	fr_pair_t		*vp;
	bool			client_cert;

	eap_session->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_tls_require_client_cert);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, inst->tls_conf, client_cert);
	if (!eap_tls_session) RETURN_MODULE_FAIL;

	/*
	 *	As it is a poorly designed protocol, PEAP uses
	 *	bits in the TLS header to indicate PEAP
	 *	version numbers.  For now, we only support
	 *	PEAP version 0, so it doesn't matter too much.
	 *	However, if we support later versions of PEAP,
	 *	we will need this flag to indicate which
	 *	version we're currently dealing with.
	 */
	eap_tls_session->base_flags = 0x00;

	/*
	 *	PEAP version 0 requires 'include_length = no',
	 *	so rather than hoping the user figures it out,
	 *	we force it here.
	 */
	eap_tls_session->include_length = false;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		RETURN_MODULE_FAIL;
	}

	eap_session->process = mod_process;

	RETURN_MODULE_HANDLED;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_peap_t		*inst = talloc_get_type_abort(instance, rlm_eap_peap_t);

	if (!virtual_server_find(inst->virtual_server)) {
		cf_log_err_by_child(cs, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	if (inst->soh_virtual_server) {
		if (!virtual_server_find(inst->soh_virtual_server)) {
			cf_log_err_by_child(cs, "soh_virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
			return -1;
		}
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eap_tls_conf_parse(cs, "tls");
	if (!inst->tls_conf) {
		ERROR("Failed initializing SSL context");
		return -1;
	}

	return 0;
}

static int mod_load(void)
{
	if (fr_soh_init() < 0) return -1;

	return 0;
}

static void mod_unload(void)
{
	fr_soh_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_peap;
rlm_eap_submodule_t rlm_eap_peap = {
	.name		= "eap_peap",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_PEAP },
	.inst_size	= sizeof(rlm_eap_peap_t),
	.config		= submodule_config,
	.onload		= mod_load,
	.unload		= mod_unload,
	.instantiate	= mod_instantiate,

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
