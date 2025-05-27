/*
 * rlm_eap_teap.c  contains the interfaces that are called from eap
 *
 * Version:     $Id$
 *
 * Copyright (C) 2022 Network RADIUS SARL <legal@networkradius.com>
 *
 * This software may not be redistributed in any form without the prior
 * written consent of Network RADIUS.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_teap.h"

typedef struct rlm_eap_teap_t {
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
	 *	User tunneled EAP type
	 */
	char const *user_method_name;

	/*
	 *	Machine tunneled EAP type
	 */
	char const *machine_method_name;

	int eap_method[3];


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
	 * 	Do we do require a client cert?
	 */
	bool req_client_cert;

	char const *authority_identity;

	uint16_t	identity_type[2];

	char const	*identity_type_name;

	/*
	 *	Virtual server for inner tunnel session.
	 */
	char const *virtual_server;
} rlm_eap_teap_t;


static CONF_PARSER module_config[] = {
	{ "tls", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, tls_conf_name), NULL },
	{ "default_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, default_method_name), .dflt = "" },
	{ "copy_request_to_tunnel", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_teap_t, copy_request_to_tunnel), "no" },
	{ "use_tunneled_reply", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_teap_t, use_tunneled_reply), "no" },
	{ "require_client_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_teap_t, req_client_cert), "no" },
	{ "authority_identity", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_eap_teap_t, authority_identity), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, virtual_server), NULL },
	{ "identity_types", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, identity_type_name), NULL },

	{ "user_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, user_method_name), .dflt = "" },
	{ "machine_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_teap_t, machine_method_name), .dflt = "" },
	CONF_PARSER_TERMINATOR
};

static const bool allowed[PW_EAP_MAX_TYPES] = {
	[PW_EAP_SIM] = true,
	[PW_EAP_TLS] = true,
	[PW_EAP_MSCHAPV2] = true,
	[PW_EAP_PWD] = true,
};

/*
 *	Attach the module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_teap_t		*inst;

	*instance = inst = talloc_zero(cs, rlm_eap_teap_t);
	if (!inst) return -1;

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	if (!inst->virtual_server) {
		ERROR("rlm_eap_teap: A 'virtual_server' MUST be defined for security");
		return -1;
	}

	/*
	 *	Convert the name to an integer, to make it easier to
	 *	handle.
	 */
	if (inst->default_method_name && *inst->default_method_name) {
		inst->default_method = eap_name2type(inst->default_method_name);
		if (inst->default_method < 0) {
			ERROR("rlm_eap_teap: Unknown EAP type %s",
			      inst->default_method_name);
			return -1;
		}
	}

	/*
	 *	@todo - allow a special value like 'basic-password', which
	 *	means that we propose the Basic-Password-Auth-Req TLV during Phase 2.
	 *
	 *	@todo - and then also track the username across
	 *	multiple rounds, including some kind of State which
	 *	can be used to signal where we are in the negotiation
	 *	process.
	 */
	if (inst->user_method_name && *inst->user_method_name) {
		int method = eap_name2type(inst->user_method_name);

		if (method < 0) {
			ERROR("rlm_eap_teap: Unknown User EAP type %s",
			      inst->user_method_name);
			return -1;
		}

		if (!allowed[method]) {
			ERROR("rlm_eap_teap: Invalid User EAP type %s",
			      inst->user_method_name);
			return -1;
		}

		inst->eap_method[EAP_TEAP_IDENTITY_TYPE_USER] = method;
	}

	if (inst->machine_method_name && *inst->machine_method_name) {
		int method;

		method = eap_name2type(inst->machine_method_name);
		if (method < 0) {
			ERROR("rlm_eap_teap: Unknown Machine EAP type %s",
			      inst->machine_method_name);
			return -1;
		}

		if (!allowed[method]) {
			ERROR("rlm_eap_teap: Invalid Machine EAP type %s",
			      inst->machine_method_name);
			return -1;
		}

		inst->eap_method[EAP_TEAP_IDENTITY_TYPE_MACHINE] = method;
	}

	/*
	 *	Read tls configuration, either from group given by 'tls'
	 *	option, or from the eap-tls configuration.
	 */
	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		ERROR("rlm_eap_teap: Failed initializing SSL context");
		return -1;
	}

	/*
	 *	Parse default identities
	 */
	if (inst->identity_type_name) {
		char const *p;
		int i;

		p = inst->identity_type_name;
		i = 0;

		while (*p) {
			while (isspace((uint8_t) *p)) p++;

			if (strncasecmp(p, "user", 4) == 0) {
				inst->identity_type[i] = 1;
				p += 4;

			} else if (strncasecmp(p, "machine", 7) == 0) {
				inst->identity_type[i] = 2;
				p += 7;

			} else {
			invalid_identity:
				cf_log_err_cs(cs, "Invalid value in identity_types = '%s' at %s",
					      inst->identity_type_name, p);
				return -1;
			}

			if ((i == 1) && (inst->identity_type[0] == inst->identity_type[1])) {
				cf_log_err_cs(cs, "Duplicate value in identity_types = '%s' at %s",
					      inst->identity_type_name, p);
				return -1;
			}

			i++;

			while (isspace((uint8_t) *p)) p++;

			/*
			 *	We only support two things.
			 */
			if ((i == 2) && *p) goto invalid_identity;

			if (!*p) break;

			if (*p != ',') goto invalid_identity;

			p++;
		}
	}

	return 0;
}

/*
 *	Allocate the TEAP per-session data
 */
static teap_tunnel_t *teap_alloc(TALLOC_CTX *ctx, rlm_eap_teap_t *inst)
{
	teap_tunnel_t *t;

	t = talloc_zero(ctx, teap_tunnel_t);

	t->received_version = -1;
	t->default_method = inst->default_method;
	memcpy(&t->eap_method, &inst->eap_method, sizeof(t->eap_method));
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
	rlm_eap_teap_t	*inst;
	VALUE_PAIR	*vp;
	bool		client_cert;
	REQUEST		*request = handler->request;

	inst = type_arg;

	handler->tls = true;

	if (request->parent) {
		RWDEBUG("----------------------------------------------------------------------");
		RWDEBUG("You have configured TEAP to run inside of TEAP.  THIS WILL NOT WORK.");
		RWDEBUG("Supported inner methods for TEAP are EAP-TLS, EAP-MSCHAPv2, and PAP.");
		RWDEBUG("Other methods may work, but are not actively supported.");
		RWDEBUG("----------------------------------------------------------------------");
	}

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

	/*
	 *	Disallow TLS 1.3 for now.
	 */
	ssn = eaptls_session(handler, inst->tls_conf, client_cert, false);
	if (!ssn) {
		return 0;
	}

	handler->opaque = ((void *)ssn);

	/*
	 *	As TEAP is a unique special snowflake and wants to use its
	 *	own rolling MSK for MPPE we we set the label to NULL so in that
	 *	eaptls_gen_mppe_keys() is NOT called in eaptls_success.
	 */
	ssn->label = NULL;

	/*
	 *	Really just protocol version.
	 */
	ssn->peap_flag = EAP_TEAP_VERSION;

        /*
	 *	hostapd's wpa_supplicant gets upset if we include all the
	 *	S+L+O flags but is happy with S+O (TLS payload is zero bytes
	 *	for S anyway) - FIXME not true for early-data TLSv1.3!
	 */
	ssn->length_flag = false;

	vp = fr_pair_make(ssn, NULL, "FreeRADIUS-EAP-TEAP-Authority-ID", inst->authority_identity, T_OP_EQ);
	fr_pair_add(&ssn->outer_tlvs_server, vp);

	/*
	 *	Be nice about identity types.
	 */
	vp = fr_pair_find_by_num(request->state, PW_EAP_TEAP_TLV_IDENTITY_TYPE, VENDORPEC_FREERADIUS, TAG_ANY);
	if (vp) {
		RDEBUG("Found &session-state:FreeRADIUS-EAP-TEAP-Identity-Type, not setting from configuration");

	} else if (!inst->identity_type[0]) {
		RWDEBUG("No &session-state:FreeRADIUS-EAP-TEAP-Identity-Type was found.");
		RWDEBUG("No 'identity_types' was set in the configuration.  TEAP will likely not work.");

	} else {
		teap_tunnel_t *t;

		fr_assert(ssn->opaque == NULL);

		ssn->opaque = teap_alloc(ssn, inst);
		t = (teap_tunnel_t *) ssn->opaque;

		/*
		 *	We automatically add &session-state:FreeRADIUS-EAP-TEAP-Identity-Type
		 *	to control the flow.
		 */
		t->auto_chain = true;

		vp = fr_pair_make(request->state_ctx, &request->state, "FreeRADIUS-EAP-TEAP-Identity-Type", NULL, T_OP_SET);
		if (vp) {
			vp->vp_short = inst->identity_type[0];
			RDEBUG("Setting &session-state:FreeRADIUS-EAP-TEAP-Identity-Type = %s",
			       (vp->vp_short == 1) ? "User" : "Machine");

			t->auths[vp->vp_short].required = true;
		}

		if (inst->identity_type[1]) {
			vp = fr_pair_make(request->state_ctx, &request->state, "FreeRADIUS-EAP-TEAP-Identity-Type", NULL, T_OP_ADD);
			if (vp) {
				vp->vp_short = inst->identity_type[1];
				RDEBUG("Followed by &session-state:FreeRADIUS-EAP-TEAP-Identity-Type += %s",
				       (vp->vp_short == 1) ? "User" : "Machine");

				t->auths[vp->vp_short].required = true;
			}
		}
	}

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_request(handler->eap_ds, ssn, true);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG3("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
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
	rlm_eap_teap_t *inst = (rlm_eap_teap_t *) arg;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	teap_tunnel_t *t = (teap_tunnel_t *) tls_session->opaque;
	REQUEST *request = handler->request;

	RDEBUG2("Authenticate");

	/*
	 *	Process TLS layer until done.
	 */
	status = eaptls_process(handler);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG3("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
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
		}
		goto phase2;

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

phase2:
	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Proceeding to decode tunneled attributes");

	/*
	 *	We may need TEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) {
		tls_session->opaque = teap_alloc(tls_session, inst);
		t = (teap_tunnel_t *) tls_session->opaque;
	}

	if (t->received_version < 0) {
		t->received_version = handler->eap_ds->response->type.data[0] & 0x07;

		/*
		 *	We only support TEAPv1.
		 */
		if (t->received_version != EAP_TEAP_VERSION) {
			RDEBUG("Invalid TEAP version received.  Expected 1, got %u", t->received_version);
			goto fail;
		}
	}

	/*
	 *	Process the TEAP portion of the request.
	 */
	rcode = eap_teap_process(handler, tls_session);
	switch (rcode) {
	case PW_CODE_ACCESS_REJECT:
	fail:
		eaptls_fail(handler, 0);
		ret = 0;
		goto done;

		/*
		 *	Access-Challenge, continue tunneled conversation.
		 */
	case PW_CODE_ACCESS_CHALLENGE:
		eaptls_request(handler->eap_ds, tls_session, false);
		ret = 1;
		goto done;

		/*
		 *	Success: Automatically return MPPE keys.
		 */
	case PW_CODE_ACCESS_ACCEPT:
		goto do_keys;

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
extern rlm_eap_module_t rlm_eap_teap;
rlm_eap_module_t rlm_eap_teap = {
	.name		= "eap_teap",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
