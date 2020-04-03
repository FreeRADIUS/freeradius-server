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

#define LOG_PREFIX "rlm_eap_tls - "

#ifdef HAVE_OPENSSL_RAND_H
#  include <openssl/rand.h>
#endif
#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#include <freeradius-devel/unlang/base.h>

#include "rlm_eap_tls.h"

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

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, void *thread, REQUEST *request);

static rlm_rcode_t eap_tls_success_with_prf(REQUEST *request, eap_session_t *eap_session)
{
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t		*tls_session = eap_tls_session->tls_session;

	/*
	 *	Set the PRF label based on the TLS version negotiated
	 *	in the handshake.
	 */
	switch (SSL_SESSION_get_protocol_version(SSL_get_session(tls_session->ssl))) {
	case SSL2_VERSION:			/* Should never happen */
	case SSL3_VERSION:			/* Should never happen */
		rad_assert(0);
		return RLM_MODULE_INVALID;

	case TLS1_VERSION:
	case TLS1_1_VERSION:
	case TLS1_2_VERSION:
#endif
	{
		static char const keying_prf_label[] = "client EAP encryption";

		if (eap_tls_success(request, eap_session,
				    keying_prf_label, sizeof(keying_prf_label) - 1,
				    NULL, 0) < 0) return RLM_MODULE_FAIL;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
		break;

	case TLS1_3_VERSION:
	default:
	{
		static char const keying_prf_label[] = "EXPORTER_EAP_TLS_Key_Material";
		static char const sessid_prf_label[] = "EXPORTER_EAP_TLS_Method-Id";

		if (eap_tls_success(request, eap_session,
				    keying_prf_label, sizeof(keying_prf_label) - 1,
				    sessid_prf_label, sizeof(sessid_prf_label) - 1) < 0) return RLM_MODULE_FAIL;
	}
		break;
	}
#endif
	return RLM_MODULE_OK;
}

static unlang_action_t eap_tls_virtual_server_result(REQUEST *request, rlm_rcode_t *presult,
						     UNUSED int *priority, void *uctx)
{
	eap_session_t	*eap_session = talloc_get_type_abort(uctx, eap_session_t);

	switch (*presult) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		*presult = eap_tls_success_with_prf(request, eap_session);
		break;

	default:
		REDEBUG2("Certificate rejected by the virtual server");
		eap_tls_fail(request, eap_session);
		*presult = RLM_MODULE_REJECT;
		break;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static rlm_rcode_t eap_tls_virtual_server(rlm_eap_tls_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	CONF_SECTION	*server_cs;
	CONF_SECTION	*section;
	VALUE_PAIR	*vp;

	/* set the virtual server to use */
	vp = fr_pair_find_by_da(request->control, attr_virtual_server, TAG_ANY);
	if (vp) {
		server_cs = virtual_server_find(vp->vp_strvalue);
		if (!server_cs) {
			REDEBUG2("Virtual server \"%pV\" not found", &vp->data);
		error:
			eap_tls_fail(request, eap_session);
			return RLM_MODULE_INVALID;
		}
	} else {
		server_cs = virtual_server_find(inst->virtual_server);
		rad_assert(server_cs);
	}

	section = cf_section_find(server_cs, "recv", "Access-Request");
	if (!section) {
		REDEBUG2("Failed finding 'recv Access-Request { ... }' section of virtual server %s",
			 cf_section_name2(server_cs));
		goto error;
	}

	if (!unlang_section(section)) {
		REDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
			cf_section_name1(server_cs), cf_section_name2(server_cs));
		goto error;
	}

	RDEBUG2("Validating certificate");

	/*
	 *	Catch the interpreter on the way back up the stack
	 */
	unlang_interpret_push_function(request, NULL, eap_tls_virtual_server_result, eap_session);

	/*
	 *	Push unlang instructions for the virtual server section
	 */
	unlang_interpret_push_section(request, section, RLM_MODULE_NOOP, UNLANG_SUB_FRAME);

	return RLM_MODULE_YIELD;
}

static rlm_rcode_t mod_process(void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_tls_status_t	status;

	rlm_eap_tls_t		*inst = talloc_get_type_abort(instance, rlm_eap_tls_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session = talloc_get_type_abort(eap_session->opaque, eap_tls_session_t);
	fr_tls_session_t		*tls_session = eap_tls_session->tls_session;

	status = eap_tls_process(request, eap_session);
	if ((status == EAP_TLS_INVALID) || (status == EAP_TLS_FAIL)) {
		REDEBUG("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eap-tls process] = %s", fr_table_str_by_value(eap_tls_status_table, status, "<INVALID>"));
	}

	switch (status) {
	/*
	 *	EAP-TLS handshake was successful, return an
	 *	EAP-TLS-Success packet here.
	 *
	 *	If a virtual server was configured, check that
	 *	it accepts the certificates, too.
	 */
	case EAP_TLS_ESTABLISHED:
		if (inst->virtual_server) return eap_tls_virtual_server(inst, request, eap_session);
		return eap_tls_success_with_prf(request, eap_session);


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
		REDEBUG("Received unexpected tunneled data after successful handshake");
		eap_tls_fail(request, eap_session);

		return RLM_MODULE_INVALID;

	/*
	 *	Anything else: fail.
	 *
	 *	Also, remove the session from the cache so that
	 *	the client can't re-use it.
	 */
	default:
		fr_tls_cache_deny(tls_session);

		return RLM_MODULE_REJECT;
	}
}

/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static rlm_rcode_t mod_session_init(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_eap_tls_t		*inst = talloc_get_type_abort(instance, rlm_eap_tls_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_tls_session_t	*eap_tls_session;

	VALUE_PAIR		*vp;
	bool			client_cert;

	eap_session->tls = true;

	/*
	 *	EAP-TLS-Require-Client-Cert attribute will override
	 *	the require_client_cert configuration option.
	 */
	vp = fr_pair_find_by_da(request->control, attr_eap_tls_require_client_cert, TAG_ANY);
	if (vp) {
		client_cert = vp->vp_uint32 ? true : false;
	} else {
		client_cert = inst->req_client_cert;
	}

	/*
	 *	EAP-TLS always requires a client certificate.
	 */
	eap_session->opaque = eap_tls_session = eap_tls_session_init(request, eap_session, inst->tls_conf, client_cert);
	if (!eap_tls_session) return RLM_MODULE_FAIL;

	eap_tls_session->include_length = inst->include_length;

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	if (eap_tls_start(request, eap_session) < 0) {
		talloc_free(eap_tls_session);
		return RLM_MODULE_FAIL;
	}

	eap_session->process = mod_process;

	return RLM_MODULE_HANDLED;
}

/*
 *	Attach the EAP-TLS module.
 */
static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_tls_t *inst = talloc_get_type_abort(instance, rlm_eap_tls_t);

	inst->tls_conf = eap_tls_conf_parse(cs, "tls");
	if (!inst->tls_conf) {
		ERROR("Failed initializing SSL context");
		return -1;
	}

	if (inst->virtual_server && !virtual_server_find(inst->virtual_server)) {
		cf_log_err_by_child(cs, "virtual_server", "Unknown virtual server '%s'", inst->virtual_server);
		return -1;
	}

	return 0;
}

#undef EAP_SECTION_DEFINE
#define EAP_SECTION_DEFINE(_field, _verb, _name) \
	{ \
		.name = _verb, \
		.name2 = _name, \
		.component = MOD_AUTHORIZE, \
		.offset = offsetof(eap_tls_actions_t, _field), \
	}

static virtual_server_compile_t compile_list[] = {
	EAP_SECTION_DEFINE(recv_access_request, "recv", "Access-Request"),

	COMPILE_TERMINATOR
};


/** Compile virtual server sections
 *
 */
static int mod_section_compile(eap_tls_actions_t *actions, CONF_SECTION *server_cs)
{
	int found;
	vp_tmpl_rules_t parse_rules;

	if (!fr_cond_assert(server_cs)) return -1;

	memset(&parse_rules, 0, sizeof(parse_rules));
	parse_rules.dict_def = dict_freeradius;

	found = virtual_server_compile_sections(server_cs, compile_list, &parse_rules, actions);
	if (found < 0) return -1;

	/*
	 *	Warn if we couldn't find any actions.
	 */
	if (!found) {
		cf_log_warn(server_cs, "No \"eap-tls\" actions found in virtual server \"%s\"",
			    cf_section_name2(server_cs));
	}

	return 0;
}

/** Compile any virtual servers with the "eap-tls" namespace
 *
 */
static int mod_namespace_load(CONF_SECTION *server_cs)
{
	return mod_section_compile(NULL, server_cs);
}

static int mod_load(void)
{
	if (virtual_namespace_register("eap-tls", "eap-tls", NULL, mod_namespace_load) < 0) return -1;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_tls;
rlm_eap_submodule_t rlm_eap_tls = {
	.name		= "eap_tls",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_TLS },
	.inst_size	= sizeof(rlm_eap_tls_t),
	.config		= submodule_config,
	.instantiate	= mod_instantiate,	/* Create new submodule instance */

	.onload		= mod_load,
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
