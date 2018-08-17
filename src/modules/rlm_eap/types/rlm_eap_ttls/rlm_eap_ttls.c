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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 * Copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_ttls.h"

typedef struct rlm_eap_ttls_t {
	/*
	 *	TLS configuration
	 */
	char const *tls_conf_name;
	fr_tls_server_conf_t *tls_conf;

	/*
	 *	Default tunneled EAP type
	 */
	char const *default_method_name;
	int default_method;

	/*
	 *	Use the reply attributes from the tunneled session in
	 *	the non-tunneled reply to the client.
	 */
	bool use_tunneled_reply;

	/*
	 *	Use SOME of the request attributes from outside of the
	 *	tunneled session in the tunneled request
	 */
	bool copy_request_to_tunnel;

	/*
	 *	RFC 5281 (TTLS) says that the length field MUST NOT be
	 *	in fragments after the first one.  However, we've done
	 *	it that way for years, and no one has complained.
	 *
	 *	In the interests of allowing the server to follow the
	 *	RFC, we add the option here.  If set to "no", it sends
	 *	the length field in ONLY the first fragment.
	 */
	bool include_length;

	/*
	 *	Virtual server for inner tunnel session.
	 */
	char const *virtual_server;

	/*
	 * 	Do we do require a client cert?
	 */
	bool req_client_cert;
} rlm_eap_ttls_t;


static CONF_PARSER module_config[] = {
	{ "tls", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ttls_t, tls_conf_name), NULL },
	{ "default_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ttls_t, default_method_name), "md5" },
	{ "copy_request_to_tunnel", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ttls_t, copy_request_to_tunnel), "no" },
	{ "use_tunneled_reply", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ttls_t, use_tunneled_reply), "no" },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ttls_t, virtual_server), NULL },
	{ "include_length", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ttls_t, include_length), "yes" },
	{ "require_client_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ttls_t, req_client_cert), "no" },
	CONF_PARSER_TERMINATOR
};


/*
 *	Attach the module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_ttls_t		*inst;

	*instance = inst = talloc_zero(cs, rlm_eap_ttls_t);
	if (!inst) return -1;

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	if (!inst->virtual_server) {
		ERROR("rlm_eap_ttls: A 'virtual_server' MUST be defined for security");
		return -1;
	}

	/*
	 *	Convert the name to an integer, to make it easier to
	 *	handle.
	 */
	inst->default_method = eap_name2type(inst->default_method_name);
	if (inst->default_method < 0) {
		ERROR("rlm_eap_ttls: Unknown EAP type %s",
		       inst->default_method_name);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		ERROR("rlm_eap_ttls: Failed initializing SSL context");
		return -1;
	}

	return 0;
}

/*
 *	Allocate the TTLS per-session data
 */
static ttls_tunnel_t *ttls_alloc(TALLOC_CTX *ctx, rlm_eap_ttls_t *inst)
{
	ttls_tunnel_t *t;

	t = talloc_zero(ctx, ttls_tunnel_t);

	t->default_method = inst->default_method;
	t->copy_request_to_tunnel = inst->copy_request_to_tunnel;
	t->use_tunneled_reply = inst->use_tunneled_reply;
	t->virtual_server = inst->virtual_server;
	return t;
}


/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static int mod_session_init(void *type_arg, eap_handler_t *handler)
{
	int		status;
	tls_session_t	*ssn;
	rlm_eap_ttls_t	*inst;
	VALUE_PAIR	*vp;
	bool		client_cert;
	REQUEST		*request = handler->request;

	inst = type_arg;

	handler->tls = true;

	/*
	 *	Check if we need a client certificate.
	 */

	/*
	 * EAP-TLS-Require-Client-Cert attribute will override
	 * the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_num(handler->request->config, PW_EAP_TLS_REQUIRE_CLIENT_CERT, 0, TAG_ANY);
	if (vp) {
		client_cert = vp->vp_integer ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	ssn = eaptls_session(handler, inst->tls_conf, client_cert);
	if (!ssn) {
		return 0;
	}

	handler->opaque = ((void *)ssn);

	/*
	 *	Set up type-specific information.
	 */
	ssn->prf_label = "ttls keying material";

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler->eap_ds, ssn->peap_flag);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	}
	if (status == 0) return 0;

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = PROCESS;

	return 1;
}


/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int mod_process(void *arg, eap_handler_t *handler)
{
	int rcode;
	int ret = 0;
	fr_tls_status_t	status;
	rlm_eap_ttls_t *inst = (rlm_eap_ttls_t *) arg;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	ttls_tunnel_t *t = (ttls_tunnel_t *) tls_session->opaque;
	REQUEST *request = handler->request;

	RDEBUG2("Authenticate");

	tls_session->length_flag = inst->include_length;

	/*
	 *	Process TLS layer until done.
	 */
	status = eaptls_process(handler);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	}

	/*
	 *	Make request available to any SSL callbacks
	 */
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);
	switch (status) {
	/*
	 *	EAP-TLS handshake was successful, tell the
	 *	client to keep talking.
	 *
	 *	If this was EAP-TLS, we would just return
	 *	an EAP-TLS-Success packet here.
	 */
	case FR_TLS_SUCCESS:
		if (SSL_session_reused(tls_session->ssl)) {
			RDEBUG("Skipping Phase2 due to session resumption");
			goto do_keys;
		}

		if (t && t->authenticated) {
			if (t->accept_vps) {
				RDEBUG2("Using saved attributes from the original Access-Accept");
				rdebug_pair_list(L_DBG_LVL_2, request, t->accept_vps, NULL);
				fr_pair_list_mcopy_by_num(handler->request->reply,
					   &handler->request->reply->vps,
					   &t->accept_vps, 0, 0, TAG_ANY);
			} else if (t->use_tunneled_reply) {
				RDEBUG2("No saved attributes in the original Access-Accept");
			}

		do_keys:
			/*
			 *	Success: Automatically return MPPE keys.
			 */
			ret = eaptls_success(handler, 0);
			goto done;
		} else {
			eaptls_request(handler->eap_ds, tls_session);
		}
		ret = 1;
		goto done;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case FR_TLS_HANDLED:
		ret = 1;
		goto done;

	/*
	 *	Handshake is done, proceed with decoding tunneled
	 *	data.
	 */
	case FR_TLS_OK:
		break;

	/*
	 *	Anything else: fail.
	 */
	default:
		ret = 0;
		goto done;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Proceeding to decode tunneled attributes");

	/*
	 *	We may need TTLS data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) {
		tls_session->opaque = ttls_alloc(tls_session, inst);
	}

	/*
	 *	Process the TTLS portion of the request.
	 */
	rcode = eapttls_process(handler, tls_session);
	switch (rcode) {
	case PW_CODE_ACCESS_REJECT:
		eaptls_fail(handler, 0);
		ret = 0;
		goto done;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case PW_CODE_ACCESS_CHALLENGE:
		eaptls_request(handler->eap_ds, tls_session);
		ret = 1;
		goto done;

		/*
		 *	Success: Automatically return MPPE keys.
		 */
	case PW_CODE_ACCESS_ACCEPT:
		ret = eaptls_success(handler, 0);
		goto done;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case PW_CODE_STATUS_CLIENT:
#ifdef WITH_PROXY
		rad_assert(handler->request->proxy != NULL);
#endif
		ret = 1;
		goto done;

	default:
		break;
	}

	/*
	 *	Something we don't understand: Reject it.
	 */
	eaptls_fail(handler, 0);

done:
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);

	return ret;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_ttls;
rlm_eap_module_t rlm_eap_ttls = {
	.name		= "eap_ttls",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
