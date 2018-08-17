/*
 * rlm_eap_ttls.c  contains the interfaces that are called from eap
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
 * @copyright 2003 Alan DeKok <aland@freeradius.org>
 * @copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define LOG_PREFIX "rlm_eap_ttls - "

#include "eap_ttls.h"

typedef struct rlm_eap_ttls {
	/*
	 *	TLS configuration
	 */
	char const	*tls_conf_name;
	fr_tls_conf_t	*tls_conf;

	/*
	 *	RFC 5281 (TTLS) says that the length field MUST NOT be
	 *	in fragments after the first one.  However, we've done
	 *	it that way for years, and no one has complained.
	 *
	 *	In the interests of allowing the server to follow the
	 *	RFC, we add the option here.  If set to "no", it sends
	 *	the length field in ONLY the first fragment.
	 */
	bool		include_length;

	/*
	 *	Virtual server for inner tunnel session.
	 */
	char const	*virtual_server;

	/*
	 * 	Do we do require a client cert?
	 */
	bool		req_client_cert;
} rlm_eap_ttls_t;


static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("tls", FR_TYPE_STRING, rlm_eap_ttls_t, tls_conf_name) },
	{ FR_CONF_DEPRECATED("copy_request_to_tunnel", FR_TYPE_BOOL, rlm_eap_ttls_t, NULL), .dflt = "no" },
	{ FR_CONF_DEPRECATED("use_tunneled_reply", FR_TYPE_BOOL, rlm_eap_ttls_t, NULL), .dflt = "no" },
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_eap_ttls_t, virtual_server) },
	{ FR_CONF_OFFSET("include_length", FR_TYPE_BOOL, rlm_eap_ttls_t, include_length), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_client_cert", FR_TYPE_BOOL, rlm_eap_ttls_t, req_client_cert), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_eap_ttls_dict[];
fr_dict_autoload_t rlm_eap_ttls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_eap_tls_require_client_cert;
fr_dict_attr_t const *attr_proxy_to_realm;

fr_dict_attr_t const *attr_chap_challenge;
fr_dict_attr_t const *attr_ms_chap2_success;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_freeradius_proxied_to;
fr_dict_attr_t const *attr_ms_chap_challenge;
fr_dict_attr_t const *attr_reply_message;
fr_dict_attr_t const *attr_eap_channel_binding_message;
fr_dict_attr_t const *attr_user_name;
fr_dict_attr_t const *attr_user_password;
fr_dict_attr_t const *attr_vendor_specific;

extern fr_dict_attr_autoload_t rlm_eap_ttls_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_ttls_dict_attr[] = {
	{ .out = &attr_eap_tls_require_client_cert, .name = "EAP-TLS-Require-Client-Cert", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_proxy_to_realm, .name = "Proxy-To-Realm", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_freeradius_proxied_to, .name = "FreeRADIUS-Proxied-To", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_ms_chap_challenge, .name = "MS-CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_success, .name = "MS-CHAP2-Success", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_reply_message, .name = "Reply-Message", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_eap_channel_binding_message, .name = "EAP-Channel-Binding-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
	{ NULL }
};

/*
 *	Allocate the TTLS per-session data
 */
static ttls_tunnel_t *ttls_alloc(TALLOC_CTX *ctx, rlm_eap_ttls_t *inst)
{
	ttls_tunnel_t *t;

	t = talloc_zero(ctx, ttls_tunnel_t);
	t->virtual_server = inst->virtual_server;

	return t;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session);
static rlm_rcode_t mod_process(void *arg, eap_session_t *eap_session)
{
	int rcode;
	eap_tls_status_t	status;
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(arg, rlm_eap_ttls_t);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	tls_session_t		*tls_session = eap_tls_session->tls_session;
	ttls_tunnel_t		*tunnel = NULL;
	REQUEST			*request = eap_session->request;

	if (tls_session->opaque) tunnel = talloc_get_type_abort(tls_session->opaque, ttls_tunnel_t);

	eap_tls_session->include_length = inst->include_length;

	/*
	 *	Process TLS layer until done.
	 */
	status = eap_tls_process(eap_session);
	if ((status == EAP_TLS_INVALID) || (status == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_int2str(eap_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_int2str(eap_tls_status_table, status, "<INVALID>"));
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
		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG("Skipping Phase2 due to session resumption");
			goto do_keys;
		}

		if (tunnel && tunnel->authenticated) {
		do_keys:
			/*
			 *	Success: Automatically return MPPE keys.
			 */
			if (eap_tls_success(eap_session) < 0) return RLM_MODULE_FAIL;
			return RLM_MODULE_OK;
		} else {
			eap_tls_request(eap_session);
		}
		return RLM_MODULE_OK;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case EAP_TLS_HANDLED:
		return RLM_MODULE_HANDLED;

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
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding Diameter attributes");

	/*
	 *	We may need TTLS data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) tls_session->opaque = ttls_alloc(tls_session, inst);

	/*
	 *	Process the TTLS portion of the request.
	 */
	rcode = eap_ttls_process(eap_session, tls_session);
	switch (rcode) {
	case FR_CODE_ACCESS_REJECT:
		eap_tls_fail(eap_session);
		return RLM_MODULE_REJECT;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case FR_CODE_ACCESS_CHALLENGE:
		eap_tls_request(eap_session);
		return RLM_MODULE_OK;

		/*
		 *	Success: Automatically return MPPE keys.
		 */
	case FR_CODE_ACCESS_ACCEPT:
		if (eap_tls_success(eap_session) < 0) return 0;
		return RLM_MODULE_OK;

	/*
	 *	No response packet, MUST be proxying it.
	 *	The main EAP module will take care of discovering
	 *	that the request now has a "proxy" packet, and
	 *	will proxy it, rather than returning an EAP packet.
	 */
	case FR_CODE_STATUS_CLIENT:
#ifdef WITH_PROXY
		rad_assert(eap_session->request->proxy != NULL);
#endif
		return RLM_MODULE_OK;

	default:
		break;
	}

	/*
	 *	Something we don't understand: Reject it.
	 */
	eap_tls_fail(eap_session);
	return RLM_MODULE_INVALID;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static rlm_rcode_t mod_session_init(void *type_arg, eap_session_t *eap_session)
{
	eap_tls_session_t	*eap_tls_session;
	rlm_eap_ttls_t		*inst = talloc_get_type_abort(type_arg, rlm_eap_ttls_t);
	VALUE_PAIR		*vp;
	bool			client_cert;

	eap_session->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(eap_session->request->control, attr_eap_tls_require_client_cert, TAG_ANY);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	eap_session->opaque = eap_tls_session = eap_tls_session_init(eap_session, inst->tls_conf, client_cert);
	if (!eap_tls_session) return RLM_MODULE_FAIL;

	/*
	 *	Set up type-specific information.
	 */
	eap_tls_session->tls_session->prf_label = "ttls keying material";

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(eap_session) < 0) {
		talloc_free(eap_tls_session);
		return RLM_MODULE_FAIL;
	}

	eap_session->process = mod_process;

	return RLM_MODULE_OK;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_ttls_t *inst = talloc_get_type_abort(instance, rlm_eap_ttls_t);

	if (!virtual_server_find(inst->virtual_server)) {
		cf_log_err_by_name(cs, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
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

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_ttls;
rlm_eap_submodule_t rlm_eap_ttls = {
	.name		= "eap_ttls",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_TTLS },
	.inst_size	= sizeof(rlm_eap_ttls_t),
	.config		= submodule_config,
	.instantiate	= mod_instantiate,	/* Create new submodule instance */

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
