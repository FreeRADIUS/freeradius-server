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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 * Copyright 2006 The FreeRADIUS server project
 */

RCSID("$Id$")

#include "eap_peap.h"

typedef struct rlm_eap_peap_t {
	char const *tls_conf_name;		//!< TLS configuration.
	fr_tls_server_conf_t *tls_conf;
	char const *default_method_name;	//!< Default tunneled EAP type.
	int default_method;

	char const *inner_eap_module;		//!< module name for inner EAP
	int auth_type_eap;
	bool use_tunneled_reply;		//!< Use the reply attributes from the tunneled session in
						//!< the non-tunneled reply to the client.

	bool copy_request_to_tunnel;		//!< Use SOME of the request attributes from outside of the
						//!< tunneled session in the tunneled request.
#ifdef WITH_PROXY
	bool proxy_tunneled_request_as_eap;	//!< Proxy tunneled session as EAP, or as de-capsulated
						//!< protocol.
#endif
	char const *virtual_server;		//!< Virtual server for inner tunnel session.

	bool soh;				//!< Do we do SoH request?
	char const *soh_virtual_server;
	bool req_client_cert;			//!< Do we do require a client cert?
} rlm_eap_peap_t;


static CONF_PARSER module_config[] = {
	{ "tls", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_peap_t, tls_conf_name), NULL },

	{ "default_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_peap_t, default_method_name), "mschapv2" },

	{ "inner_eap_module", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_peap_t, inner_eap_module), NULL },

	{ "copy_request_to_tunnel", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_peap_t, copy_request_to_tunnel), "no" },

	{ "use_tunneled_reply", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_peap_t, use_tunneled_reply), "no" },

#ifdef WITH_PROXY
	{ "proxy_tunneled_request_as_eap", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_peap_t, proxy_tunneled_request_as_eap), "yes" },
#endif

	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_peap_t, virtual_server), NULL },

	{ "soh", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_peap_t, soh), "no" },

	{ "require_client_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_peap_t, req_client_cert), "no" },

	{ "soh_virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_peap_t, soh_virtual_server), NULL },

	CONF_PARSER_TERMINATOR
};


/*
 *	Attach the module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_peap_t		*inst;
	DICT_VALUE const	*dv;

	*instance = inst = talloc_zero(cs, rlm_eap_peap_t);
	if (!inst) return -1;

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	if (!inst->virtual_server) {
		ERROR("rlm_eap_peap: A 'virtual_server' MUST be defined for security");
		return -1;
	}

	/*
	 *	Convert the name to an integer, to make it easier to
	 *	handle.
	 */
	inst->default_method = eap_name2type(inst->default_method_name);
	if (inst->default_method < 0) {
		ERROR("rlm_eap_peap: Unknown EAP type %s",
		       inst->default_method_name);
		return -1;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		ERROR("rlm_eap_peap: Failed initializing SSL context");
		return -1;
	}

	/*
	 *	Don't expose this if we don't need it.
	 */
	if (!inst->inner_eap_module) inst->inner_eap_module = "eap";

	dv = dict_valbyname(PW_AUTH_TYPE, 0, inst->inner_eap_module);
	if (!dv) {
		WARN("Failed to find 'Auth-Type %s' section in virtual server %s.  The server cannot proxy inner-tunnel EAP packets.",
		     inst->inner_eap_module, inst->virtual_server);
	} else {
		inst->auth_type_eap = dv->value;
	}

	return 0;
}

/*
 *	Allocate the PEAP per-session data
 */
static peap_tunnel_t *peap_alloc(TALLOC_CTX *ctx, rlm_eap_peap_t *inst)
{
	peap_tunnel_t *t;

	t = talloc_zero(ctx, peap_tunnel_t);

	t->default_method = inst->default_method;
	t->copy_request_to_tunnel = inst->copy_request_to_tunnel;
	t->use_tunneled_reply = inst->use_tunneled_reply;
#ifdef WITH_PROXY
	t->proxy_tunneled_request_as_eap = inst->proxy_tunneled_request_as_eap;
#endif
	t->virtual_server = inst->virtual_server;
	t->soh = inst->soh;
	t->soh_virtual_server = inst->soh_virtual_server;
	t->session_resumption_state = PEAP_RESUMPTION_MAYBE;

	return t;
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static int mod_session_init(void *type_arg, eap_handler_t *handler)
{
	int		status;
	tls_session_t	*ssn;
	rlm_eap_peap_t	*inst;
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
	ssn->prf_label = "client EAP encryption";

	/*
	 *	As it is a poorly designed protocol, PEAP uses
	 *	bits in the TLS header to indicate PEAP
	 *	version numbers.  For now, we only support
	 *	PEAP version 0, so it doesn't matter too much.
	 *	However, if we support later versions of PEAP,
	 *	we will need this flag to indicate which
	 *	version we're currently dealing with.
	 */
	ssn->peap_flag = 0x00;

	/*
	 *	PEAP version 0 requires 'include_length = no',
	 *	so rather than hoping the user figures it out,
	 *	we force it here.
	 */
	ssn->length_flag = false;

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
	fr_tls_status_t status;
	rlm_eap_peap_t *inst = (rlm_eap_peap_t *) arg;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	peap_tunnel_t *peap = tls_session->opaque;
	REQUEST *request = handler->request;

	/*
	 *	Session resumption requires the storage of data, so
	 *	allocate it if it doesn't already exist.
	 */
	if (!tls_session->opaque) {
		peap = tls_session->opaque = peap_alloc(tls_session, inst);
	}

	/*
	 *	Negotiate PEAP versions down.
	 */
	if ((handler->eap_ds->response->type.data[0] & 0x03) < tls_session->peap_flag) {
		tls_session->peap_flag = handler->eap_ds->response->type.data[0] & 0x03;
	}

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
		peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		break;

	/*
	 *	The TLS code is still working on the TLS
	 *	exchange, and it's a valid TLS request.
	 *	do nothing.
	 */
	case FR_TLS_HANDLED:
		/*
		 *	FIXME: If the SSL session is established, grab the state
		 *	and EAP id from the inner tunnel, and update it with
		 *	the expected EAP id!
		 */
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
	RDEBUG2("Session established.  Decoding tunneled attributes");

	/*
	 *	We may need PEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) {
		tls_session->opaque = peap_alloc(tls_session, inst);
	}

	/*
	 *	Process the PEAP portion of the request.
	 */
	rcode = eappeap_process(handler, tls_session, inst->auth_type_eap);
	switch (rcode) {
	case RLM_MODULE_REJECT:
		eaptls_fail(handler, 0);
		ret = 0;
		goto done;

	case RLM_MODULE_HANDLED:
		eaptls_request(handler->eap_ds, tls_session);
		ret = 1;
		goto done;

	case RLM_MODULE_OK:
		/*
		 *	Move the saved VP's from the Access-Accept to
		 *	our Access-Accept.
		 */
		peap = tls_session->opaque;
		if (peap->soh_reply_vps) {
			RDEBUG2("Using saved attributes from the SoH reply");
			rdebug_pair_list(L_DBG_LVL_2, request, peap->soh_reply_vps, NULL);
			fr_pair_list_mcopy_by_num(handler->request->reply,
				  &handler->request->reply->vps,
				  &peap->soh_reply_vps, 0, 0, TAG_ANY);
		}
		if (peap->accept_vps) {
			RDEBUG2("Using saved attributes from the original Access-Accept");
			rdebug_pair_list(L_DBG_LVL_2, request, peap->accept_vps, NULL);
			fr_pair_list_mcopy_by_num(handler->request->reply,
				  &handler->request->reply->vps,
				  &peap->accept_vps, 0, 0, TAG_ANY);
		} else if (peap->use_tunneled_reply) {
			RDEBUG2("No saved attributes in the original Access-Accept");
		}

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		ret = eaptls_success(handler, 0);
		goto done;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case RLM_MODULE_UPDATED:
#ifdef WITH_PROXY
		rad_assert(handler->request->proxy != NULL);
#endif
		ret = 1;
		goto done;

	default:
		break;
	}

	eaptls_fail(handler, 0);

done:
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);

	return ret;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_peap;
rlm_eap_module_t rlm_eap_peap = {
	.name		= "eap_peap",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
