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
 * @file rlm_eap.c
 * @brief Implements the EAP framework.
 *
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_eap (%s) - "
#define LOG_PREFIX_ARGS dl_module_instance_name_by_data(inst)

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include "rlm_eap.h"

extern module_t rlm_eap;

/** Resume context for calling a submodule
 *
 */
typedef struct {
	char const	*caller;		//!< Original caller.
	rlm_eap_t	*inst;			//!< Instance of the rlm_eap module.
	eap_session_t	*eap_session;		//!< The eap_session we're continuing.
	rlm_rcode_t	rcode;			//!< The result of the submodule.
} eap_auth_rctx_t;

static int submodule_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int eap_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			  CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("default_eap_type", FR_TYPE_VOID, rlm_eap_t, default_method),
			 .dflt = "md5", .func = eap_type_parse },

	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, rlm_eap_t, submodule_cs),
			 .func = submodule_parse },

	{ FR_CONF_DEPRECATED("timer_expire", FR_TYPE_UINT32, rlm_eap_t, timer_limit), .dflt = "60" },
	{ FR_CONF_OFFSET("ignore_unknown_eap_types", FR_TYPE_BOOL, rlm_eap_t, ignore_unknown_types), .dflt = "no" },
	{ FR_CONF_OFFSET("cisco_accounting_username_bug", FR_TYPE_BOOL, rlm_eap_t,
			 cisco_accounting_username_bug), .dflt = "no" },
	{ FR_CONF_DEPRECATED("max_sessions", FR_TYPE_UINT32, rlm_eap_t, max_sessions), .dflt = "2048" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_dict[];
fr_dict_autoload_t rlm_eap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_eap_type;
static fr_dict_attr_t const *attr_eap_identity;

static fr_dict_attr_t const *attr_cisco_avpair;
static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_cisco_avpair, .name = "Vendor-Specific.Cisco.AvPair", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);
static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

/** Wrapper around dl_instance which loads submodules based on type = foo pairs
 *
 * @param[in] ctx	to allocate data in (instance of rlm_eap_t).
 * @param[out] out	Where to write child conf section to.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int submodule_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	char		*our_name = NULL;
	char		*p;
	CONF_SECTION	*eap_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*submodule_cs;
	eap_type_t	method;

	/*
	 *	Search with underscores smashed to hyphens
	 *	as that's what's used in the dictionary.
	 */
	p = our_name = talloc_strdup(NULL, name);
	while (*p) {
		if (*p == '_') *p = '-';
		p++;
	}

	method = eap_name2type(our_name);
	if (method == FR_EAP_METHOD_INVALID) {
		talloc_free(our_name);
		cf_log_err(ci, "Unknown EAP type %s", name);
		return -1;
	}

#if !defined(HAVE_OPENSSL_SSL_H) || !defined(HAVE_LIBSSL)
	/*
	 *	This allows the default configuration to be
	 *	shipped with EAP-TLS, etc. enabled.  If the
	 *	system doesn't have OpenSSL, they will be
	 *	ignored.
	 *
	 *	If the system does have OpenSSL, then this
	 *	code will not be used.  The administrator will
	 *	then have to delete the tls,
	 *	etc. configurations from eap.conf in order to
	 *	have EAP without the TLS types.
	 */
	switch (method) {
	case FR_EAP_METHOD_TLS:
	case FR_EAP_METHOD_TTLS:
	case FR_EAP_METHOD_PEAP:
	case FR_EAP_METHOD_PWD:
	case FR_EAP_METHOD_AKA_PRIME:
	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_SIM:
	{
		rlm_eap_t *inst = ((dl_module_inst_t *)cf_data_value(cf_data_find(eap_cs,
								     dl_module_inst_t, "rlm_eap")))->data;

		WARN("Ignoring EAP method %s because we don't have OpenSSL support", name);

		talloc_free(our_name);
	}
		return 0;

	default:
		break;
	}
#endif

	/*
	 *	A bit hacky, we should really figure out a better way
	 *	of handling missing sections.
	 */
	submodule_cs = cf_section_find(eap_cs, name, NULL);
	if (!submodule_cs) {
		submodule_cs = cf_section_alloc(eap_cs, eap_cs, name, NULL);
		cf_filename_set(submodule_cs, cf_filename(ci));
		cf_lineno_set(submodule_cs, cf_lineno(ci));
	}

	*(void **)out = submodule_cs;

	talloc_free(our_name);

	return 0;
}

/** Convert EAP type strings to eap_type_t values
 *
 * @param[in] ctx	unused.
 * @param[out] out	Where to write the #eap_type_t value we found.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the EAP method.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int eap_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			  CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*default_method_name = cf_pair_value(cf_item_to_pair(ci));
	eap_type_t	method;

	/*
	 *	Ensure that the default EAP type is loaded.
	 */
	method = eap_name2type(default_method_name);
	if (method == FR_EAP_METHOD_INVALID) {
		cf_log_err(ci, "Unknown EAP type %s", default_method_name);
		return -1;
	}

	*(eap_type_t *)out = method;

	return 0;
}

/** Process NAK data from EAP peer
 *
 */
static eap_type_t eap_process_nak(module_ctx_t const *mctx, request_t *request,
				  eap_type_t type,
				  eap_type_data_t *nak)
{
	rlm_eap_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_t);
	unsigned int i;
	fr_pair_t *vp;
	eap_type_t method = FR_EAP_METHOD_INVALID;

	/*
	 *	The NAK data is the preferred EAP type(s) of
	 *	the client.
	 *
	 *	RFC 3748 says to list one or more proposed
	 *	alternative types, one per octet, or to use
	 *	0 for no alternative.
	 */
	if (!nak->data) {
		REDEBUG("Peer sent empty (invalid) NAK. Can't select method to continue with");

		return FR_EAP_METHOD_INVALID;
	}

	/*
	 *	Pick one type out of the one they asked for,
	 *	as they may have asked for many.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_type);
	for (i = 0; i < nak->length; i++) {
		/*
		 *	Type 0 is valid, and means there are no
		 *	common choices.
		 */
		if (nak->data[i] == 0) {
			REDEBUG("Peer NAK'd indicating it is not willing to continue");

			return FR_EAP_METHOD_INVALID;
		}

		/*
		 *	It is invalid to request identity,
		 *	notification & nak in nak.
		 */
		if (nak->data[i] < FR_EAP_METHOD_MD5) {
			REDEBUG("Peer NAK'd asking for bad type %s (%d)", eap_type2name(nak->data[i]), nak->data[i]);

			return FR_EAP_METHOD_INVALID;
		}

		if ((nak->data[i] >= FR_EAP_METHOD_MAX) ||
		    !inst->methods[nak->data[i]].submodule) {
			RDEBUG2("Peer NAK'd asking for unsupported EAP type %s (%d), skipping...",
				eap_type2name(nak->data[i]),
				nak->data[i]);

			continue;
		}

		/*
		 *	Prevent a firestorm if the client is confused.
		 */
		if (type == nak->data[i]) {
			char const *type_str = eap_type2name(nak->data[i]);

			RDEBUG2("Peer NAK'd our request for %s (%d) with a request for %s (%d), skipping...",
				type_str, nak->data[i], type_str, nak->data[i]);

			RWARN("!!! We requested to use EAP type %s (%i)", type_str, nak->data[i]);
			RWARN("!!! The supplicant rejected that, and requested to use the same EAP type.");
			RWARN("!!!     i.e. the supplicant said 'I don't like %s, please use %s instead.",
			      type_str, type_str);
			RWARN("!!! The supplicant software is broken and does not work properly.");
			RWARN("!!! Please upgrade it to software that works.");

			continue;
		}

		/*
		 *	Enforce per-user configuration of EAP
		 *	types.
		 */
		if (vp && (vp->vp_uint32 != nak->data[i])) {
			RDEBUG2("Peer wants %s (%d), while we require %s (%d), skipping",
				eap_type2name(nak->data[i]), nak->data[i],
				eap_type2name(vp->vp_uint32), vp->vp_uint32);

			continue;
		}

		RDEBUG2("Found mutually acceptable type %s (%d)", eap_type2name(nak->data[i]), nak->data[i]);

		method = nak->data[i];

		break;
	}

	if (method == FR_EAP_METHOD_INVALID) REDEBUG("No mutually acceptable types found");

	return method;
}

/** Cancel a call to a submodule
 *
 * @param[in] mctx	module calling ctx.
 * @param[in] request	The current request.
 * @param[in] rctx	the eap_session_t
 * @param[in] action	to perform.
 */
static void mod_authenticate_cancel(UNUSED module_ctx_t const *mctx, request_t *request, void *rctx,
				    fr_state_signal_t action)
{
	eap_session_t	*eap_session;

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Request cancelled - Destroying EAP-Session");

	eap_session = talloc_get_type_abort(rctx, eap_session_t);

	(void)fr_cond_assert(request_detach(eap_session->subrequest, true) == 0);
	TALLOC_FREE(eap_session->subrequest);

	/*
	 *	This is the only safe thing to do.
	 *	We have no idea what state the submodule
	 *	left its opaque data in.
	 */
	eap_session_destroy(&eap_session);
}

/** Process the result of calling a submodule
 *
 * @param[out] p_result		Result of calling the module, one of:
 *				- RLM_MODULE_INVALID	if the request or EAP session state is invalid.
 *				- RLM_MODULE_OK		if this round succeeded.
 *				- RLM_MODULE_HANDLED	if we're done with this round.
 *				- RLM_MODULE_REJECT	if the user should be rejected.
 * @param[in] request	The current request.
 * @param[in] mctx	module calling ctx.
 * @param[in] eap_session the EAP session
 * @param[in] result	the input result from the submodule
 */
static unlang_action_t mod_authenticate_result(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
					       request_t *request, eap_session_t *eap_session, rlm_rcode_t result)
{
	rlm_rcode_t	rcode;

	/*
	 *	Cleanup the subrequest
	 */
	(void)fr_cond_assert(request_detach(eap_session->subrequest, true) == 0);
	TALLOC_FREE(eap_session->subrequest);

	/*
	 *	The submodule failed.  Die.
	 */
	switch (result) {
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
		eap_fail(eap_session);
		eap_session_destroy(&eap_session);

		rcode = RLM_MODULE_INVALID;
		goto finish;

	/*
	 *	Inconsistent result from submodule...
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
		break;

	/*
	 *	Definitely shouldn't get this.
	 */
	case RLM_MODULE_YIELD:
		fr_assert(0);
		break;

	default:
		break;
	}

	/*
	 *	We are done, wrap the EAP-request in RADIUS to send
	 *	with all other required radius attributes
	 */
	rcode = eap_compose(eap_session);

	/*
	 *	Add to the list only if it is EAP-Request, OR if
	 *	it's LEAP, and a response.
	 */
	if (((eap_session->this_round->request->code == FR_EAP_CODE_REQUEST) &&
	    (eap_session->this_round->request->type.num >= FR_EAP_METHOD_MD5)) ||

		/*
		 *	LEAP is a little different.  At Stage 4,
		 *	it sends an EAP-Success message, but we still
		 *	need to keep the State attribute & session
		 *	data structure around for the AP Challenge.
		 *
		 *	At stage 6, LEAP sends an EAP-Response, which
		 *	isn't put into the list.
		 */
	    ((eap_session->this_round->response->code == FR_EAP_CODE_RESPONSE) &&
	     (eap_session->this_round->response->type.num == FR_EAP_METHOD_LEAP) &&
	     (eap_session->this_round->request->code == FR_EAP_CODE_SUCCESS) &&
	     (eap_session->this_round->request->type.num == 0))) {
		talloc_free(eap_session->prev_round);
		eap_session->prev_round = eap_session->this_round;
		eap_session->this_round = NULL;
	} else {
		RDEBUG2("Cleaning up EAP session");
		eap_session_destroy(&eap_session);
	}

	/*
	 *	Freeze the eap_session so we can continue
	 *	the authentication session later.
	 */
	eap_session_freeze(&eap_session);

finish:
	RETURN_MODULE_RCODE(rcode);
}

/** Call mod_authenticate_result asynchronously from the unlang interpreter
 *
 * @param[out] p_result	The result of the operation.
 * @param[in] mctx	module calling ctx.
 * @param[in] request	the current request.
 * @param[in] rctx	the eap_session_t.
 * @return The result of this round of authentication.
 */
static unlang_action_t mod_authenticate_result_async(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						     request_t *request, void *rctx)
{
	eap_session_t	*eap_session = talloc_get_type_abort(rctx, eap_session_t);

	return mod_authenticate_result(p_result, mctx, request, eap_session, eap_session->submodule_rcode);
}

/** Select the correct callback based on a response
 *
 * Based on the EAP response from the supplicant, and setup a call on the
 * unlang stack to the appropriate submodule.
 *
 * Default to the configured EAP-Type for all Unsupported EAP-Types.
 *
 * @param[out] p_result		the result of the operation.
 * @param[in] mctx		module calling ctx.
 * @param[in] eap_session	State data that persists over multiple rounds of EAP.
 * @return
 *	- RLM_MODULE_INVALID	destroy the EAP session as its invalid.
 *	- RLM_MODULE_YIELD	Yield control back to the interpreter so it can
 *				call the submodule.
 */
static unlang_action_t eap_method_select(rlm_rcode_t *p_result, module_ctx_t const *mctx, eap_session_t *eap_session)
{
	rlm_eap_t const			*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_t);
	eap_type_data_t			*type = &eap_session->this_round->response->type;
	request_t				*request = eap_session->request;

	rlm_eap_method_t const		*method;

	eap_type_t			next = inst->default_method;
	fr_pair_t			*vp;

	/*
	 *	Session must have been thawed...
	 */
	fr_assert(eap_session->request);

	/*
	 *	Don't trust anyone.
	 */
	if ((type->num == 0) || (type->num >= FR_EAP_METHOD_MAX)) {
		REDEBUG("Peer sent EAP type number %d, which is outside known range", type->num);

	is_invalid:
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Multiple levels of TLS nesting are invalid.  But if
	 *	the parent has a home_server defined, then this
	 *	request is being processed through a virtual
	 *	server... so that's OK.
	 *
	 *	i.e. we're inside an EAP tunnel, which means we have a
	 *	parent.  If the outer session exists, and doesn't have
	 *	a home server, then it's multiple layers of tunneling.
	 */
	if (eap_session->request->parent &&
	    eap_session->request->parent->parent) {
		RERROR("Multiple levels of TLS nesting are invalid");
		goto is_invalid;
	}

	RDEBUG2("Peer sent packet with EAP method %s (%d)", eap_type2name(type->num), type->num);

	/*
	 *	Figure out what to do.
	 */
	switch (type->num) {
	case FR_EAP_METHOD_IDENTITY:
		/*
		 *	Allow per-user configuration of EAP types.
		 */
		vp = fr_pair_find_by_da(&eap_session->request->control_pairs, attr_eap_type);
		if (vp) {
			RDEBUG2("Using method from &control.EAP-Type");
			next = vp->vp_uint32;
		}

		/*
		 *	Ensure it's valid.
		 */
		if ((next < FR_EAP_METHOD_MD5) || (next >= FR_EAP_METHOD_MAX) || (!inst->methods[next].submodule)) {
			REDEBUG2("Tried to start unsupported EAP type %s (%d)",
				 eap_type2name(next), next);
			goto is_invalid;
		}

	do_init:
		/*
		 *	If any of these fail, we messed badly somewhere
		 */
		fr_assert(next >= FR_EAP_METHOD_MD5);
		fr_assert(next < FR_EAP_METHOD_MAX);
		fr_assert(inst->methods[next].submodule);

		eap_session->process = inst->methods[next].submodule->session_init;
		eap_session->type = next;
		break;

	case FR_EAP_METHOD_NAK:
		/*
		 *	Delete old data, if necessary.  If we called a method
		 *	before, and it initialized itself, we need to free
		 *	the memory it alloced.
		 */
		TALLOC_FREE(eap_session->opaque);
		next = eap_process_nak(mctx, eap_session->request, eap_session->type, type);
		if (!next) RETURN_MODULE_REJECT;

		/*
		 *	Initialise the state machine for the next submodule
		 */
		goto do_init;

	/*
	 *	Only allow modules that are enabled to be called,
	 *	treating any other requests as invalid.
	 *
	 *	This may seem a bit harsh, but remember the server
	 *	dictates which type of EAP method should be started,
	 *	so this is the supplicant ignoring the normal EAP method
	 *	negotiation mechanism, by not NAKing and just trying
	 *	to start a new EAP method.
	 */
	default:
		if (!inst->methods[type->num].submodule) {
			REDEBUG2("Client asked for unsupported EAP type %s (%d)", eap_type2name(type->num), type->num);
			goto is_invalid;
		}
		eap_session->type = type->num;
		break;
	}

	method = &inst->methods[eap_session->type];

	RDEBUG2("Calling submodule %s", method->submodule->name);

	/*
	 *	Allocate a new subrequest
	 */
	MEM(eap_session->subrequest = unlang_module_subrequest_alloc(request,
								     method->submodule->namespace ?
								     *(method->submodule->namespace) :
								     request->dict));

	if (method->submodule->clone_parent_lists) {
		if (fr_pair_list_copy(eap_session->subrequest,
				      &eap_session->subrequest->control_pairs, &request->control_pairs) < 0) {
		list_copy_fail:
			RERROR("Failed copying parent's attribute list");
		fail:
			TALLOC_FREE(eap_session->subrequest);
			RETURN_MODULE_FAIL;
		}

		if (fr_pair_list_copy(eap_session->subrequest->packet,
				      &eap_session->subrequest->request_pairs,
				      &request->request_pairs) < 0) goto list_copy_fail;
	}

	/*
	 *	Push the submodule into the child's stack
	 */
	if (unlang_module_push(NULL,	/* rcode should bubble up and be returned by yield_to_subrequest */
			       eap_session->subrequest, method->submodule_inst, eap_session->process, true) < 0) {
		goto fail;
	}

	if (eap_session->identity) {
		fr_pair_t	*identity;

		request = eap_session->subrequest;	/* Set request for pair_add_request macro */

		MEM(pair_add_request(&identity, attr_eap_identity) >= 0);
		fr_pair_value_bstrdup_buffer(identity, eap_session->identity, true);
	}

	/*
	 *	Add the EAP-Type we're running to the subrequest
	 *	This is useful for when policies are shared between
	 *      virtual server sections for multiple EAP types.
	 */
	{
		fr_pair_t	*type_vp;

		MEM(pair_add_request(&type_vp, attr_eap_type) >= 0);
		type_vp->vp_uint32 = eap_session->type;
	}

	/*
	 *	Yield to the subrequest, and start executing it
	 */
	return unlang_module_yield_to_subrequest(&eap_session->submodule_rcode, eap_session->subrequest,
						 mod_authenticate_result_async, mod_authenticate_cancel,
						 &(unlang_subrequest_session_t){ .enable = true, .unique_ptr = eap_session },
						 eap_session);
}

static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_t);
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;
	unlang_action_t		ua;

	if (!fr_pair_find_by_da(&request->request_pairs, attr_eap_message)) {
		REDEBUG("You set 'Auth-Type = EAP' for a request that does not contain an EAP-Message attribute!");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Reconstruct the EAP packet from the EAP-Message
	 *	attribute.  The relevant decoder should have already
	 *	concatenated the fragments into a single buffer.
	 */
	eap_packet = eap_packet_from_vp(request, request->request_pairs);
	if (!eap_packet) {
		RPERROR("Malformed EAP Message");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Allocate a new eap_session, or if this request
	 *	is part of an ongoing authentication session,
	 *	retrieve the existing eap_session from the request
	 *	data.
	 */
	eap_session = eap_session_continue(inst, &eap_packet, request);
	if (!eap_session) RETURN_MODULE_INVALID;	/* Don't emit error here, it will mask the real issue */

	/*
	 *	Call an EAP submodule to process the request,
	 *	or with simple types like Identity and NAK,
	 *	process it ourselves.
	 */
	if ((ua = eap_method_select(p_result, mctx, eap_session)) != UNLANG_ACTION_CALCULATE_RESULT) return ua;
	switch (*p_result) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		eap_session_freeze(&eap_session);
		break;

	/*
	 *	RFC 3748 Section 2
	 *	The conversation continues until the authenticator cannot
	 *	authenticate the peer (unacceptable Responses to one or more
	 *	Requests), in which case the authenticator implementation MUST
	 *	transmit an EAP Failure (Code 4).
	 */
	default:
		eap_fail(eap_session);
		eap_session_destroy(&eap_session);
		break;
	}

	return ua;
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existence & get their configured values.
 * It Handles EAP-START Messages, User-Name initialization.
 */
static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_t);
	int			status;

#ifdef WITH_PROXY
	/*
	 *	We don't do authorization again, once we've seen the
	 *	proxy reply (or the proxied packet)
	 */
	if (request->proxy != NULL)
		RETURN_MODULE_NOOP;
#endif

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup EAP authentication",
		     inst->name, inst->name);
		RETURN_MODULE_NOOP;
	}

	/*
	 *	For EAP_START, send Access-Challenge with EAP Identity
	 *	request.  even when we have to proxy this request
	 *
	 *	RFC 2869, Section 2.3.1 notes that the "domain" of the
	 *	user, (i.e. where to proxy it) comes from the EAP-Identity,
	 *	so we CANNOT proxy the user, until we know its identity.
	 *
	 *	We therefore send an EAP Identity request.
	 */
	status = eap_start(request, inst->methods, inst->ignore_unknown_types);
	switch (status) {
	case RLM_MODULE_NOOP:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_HANDLED:
		return status;

	default:
		break;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	if (status == RLM_MODULE_OK) RETURN_MODULE_OK;

	RETURN_MODULE_UPDATED;
}

#if 0
/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static unlang_action_t mod_post_proxy(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_t const		*inst = talloc_get_type_abort_const(instance->mctx, rlm_eap_t);
	size_t			i;
	size_t			len;
	ssize_t			ret;
	char			*p;
	fr_pair_t		*vp;
	eap_session_t		*eap_session;
	fr_cursor_t		cursor;

	/*
	 *	If there was a eap_session associated with this request,
	 *	then it's a tunneled request which was proxied...
	 */
	if (request_data_get(request, inst, REQUEST_DATA_EAP_SESSION_PROXIED)) {
		rlm_rcode_t		rcode;
		eap_tunnel_data_t	*data;
		fr_pair_t		*username;

		eap_session = eap_session_thaw(request);
		fr_assert(eap_session);

		/*
		 *	Grab the tunnel callbacks from the request.
		 */
		data = (eap_tunnel_data_t *) request_data_get(request,
							      request->proxy,
							      REQUEST_DATA_EAP_TUNNEL_CALLBACK);
		if (!data) {
			RERROR("Failed to retrieve callback for tunneled session!");
			eap_session_destroy(&eap_session);
			RETURN_MODULE_FAIL;
		}

		/*
		 *	Do the callback...
		 */
		RDEBUG2("Doing post-proxy callback");
		rcode = data->callback(eap_session, data->tls_session);
		talloc_free(data);
		switch (rcode) {
		default:
			RDEBUG2("Failed in post-proxy callback");
			eap_fail(eap_session);
			eap_session_destroy(&eap_session);
			return rcode;

		case RLM_MODULE_OK:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_HANDLED:
			break;
		}

		/*
		 *	We are done, wrap the EAP-request in RADIUS to send
		 *	with all other required radius attributes
		 */
		eap_compose(eap_session);

		/*
		 *	Add to the list only if it is EAP-Request, OR if
		 *	it's LEAP, and a response.
		 */
		if ((eap_session->this_round->request->code == FR_EAP_CODE_REQUEST) &&
		    (eap_session->this_round->request->type.num >= FR_EAP_METHOD_MD5)) {
			talloc_free(eap_session->prev_round);
			eap_session->prev_round = eap_session->this_round;
			eap_session->this_round = NULL;
		} else {	/* couldn't have been LEAP, there's no tunnel */
			RDEBUG2("Freeing eap_session");
			eap_session_destroy(&eap_session);
		}

		username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);

		/*
		 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
		 *	says that we MUST include a User-Name attribute in the
		 *	Access-Accept.
		 */
		if ((request->reply->code == FR_CODE_ACCESS_ACCEPT) && username) {
			MEM(pair_update_reply(&vp, attr_user_name) >= 0);
			fr_pair_value_copy(vp, username);
		}

		eap_session_freeze(&eap_session);

		RETURN_MODULE_OK;
	} else {
		RDEBUG2("No pre-existing eap_session found");
	}

	/*
	 *	This is allowed.
	 */
	RETURN_MODULE_NOOP;
}
#endif

static unlang_action_t mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_eap_t);
	fr_pair_t		*vp;
	eap_session_t		*eap_session;
	fr_pair_t		*username;

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	if ((request->reply->code == FR_CODE_ACCESS_ACCEPT) && username) {
		/*
		 *	Doesn't exist, add it in.
		 */
		vp = fr_pair_find_by_da(&request->reply_pairs, attr_user_name);
		if (!vp) {
			vp = fr_pair_copy(request->reply, username);
			fr_pair_add(&request->reply_pairs, vp);
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.
		 */
		if (inst->cisco_accounting_username_bug) {
			char *new;

			MEM(new = talloc_zero_array(vp, char, vp->vp_length + 1 + 1));	/* \0 + \0 */
			memcpy(new, vp->vp_strvalue, vp->vp_length);
			fr_pair_value_bstrdup_buffer_shallow(vp, new, vp->vp_tainted);	/* Also frees existing buffer */
		}
	}

	/*
	 *	Only synthesize a failure message if something
	 *	previously rejected the request.
	 */
	if (request->reply->code != FR_CODE_ACCESS_REJECT) RETURN_MODULE_NOOP;

	if (!fr_pair_find_by_da(&request->request_pairs, attr_eap_message)) {
		RDEBUG3("Request didn't contain an EAP-Message, not inserting EAP-Failure");
		RETURN_MODULE_NOOP;
	}

	if (fr_pair_find_by_da(&request->reply_pairs, attr_eap_message)) {
		RDEBUG3("Reply already contained an EAP-Message, not inserting EAP-Failure");
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Retrieve pre-existing eap_session from request
	 *	data.  This will have been added to the request
	 *	data by the state API.
	 */
	eap_session = eap_session_thaw(request);
	if (!eap_session) {
		RDEBUG3("Failed to get eap_session, probably already removed, not inserting EAP-Failure");
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Already set to failure, assume something else
	 *	added EAP-Message with a failure code, do nothing.
	 */
	if (eap_session->this_round->request->code == FR_EAP_CODE_FAILURE) RETURN_MODULE_NOOP;

	/*
	 *	Was *NOT* an EAP-Failure, so we now need to turn it into one.
	 */
	REDEBUG("Request rejected after last call to module \"%s\", transforming response into EAP-Failure",
		inst->name);
	eap_fail(eap_session);				/* Compose an EAP failure */
	eap_session_destroy(&eap_session);		/* Free the EAP session, and dissociate it from the request */

	/*
	 *	Make sure there's a message authenticator attribute in the response
	 *	RADIUS protocol code will calculate the correct value later...
	 */
	MEM(pair_update_reply(&vp, attr_message_authenticator) >= 0);
	MEM(fr_pair_value_mem_alloc(vp, NULL, RADIUS_AUTH_VECTOR_LENGTH, false) == 0);

	RETURN_MODULE_UPDATED;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	rlm_eap_t	*inst = talloc_get_type_abort(instance, rlm_eap_t);
	size_t		i;

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, inst->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  EAP authentication will likely not work",
		     inst->name);
	}

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) inst->rand_pool.randrsl[i] = fr_rand();
	fr_rand_init(&inst->rand_pool, 1);
	inst->rand_pool.randcnt = 0;

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	rlm_eap_t	*inst = talloc_get_type_abort(instance, rlm_eap_t);
	size_t		i, j, loaded, count = 0;

	inst->name = cf_section_name2(cs);
	if (!inst->name) inst->name = cf_section_name1(cs);

	/*
	 *	Load and bootstrap the submodules now
	 *	We have to do that here instead of in a parse function
	 *	Because the submodule might want to look at its parent
	 *	and we haven't completed our own bootstrap phase yet.
	 */
	loaded = talloc_array_length(inst->submodule_cs);
	for (i = 0; i < loaded; i++) {
		eap_type_t			method;
		CONF_SECTION			*submodule_cs = inst->submodule_cs[i];
		rlm_eap_submodule_t const	*submodule;
		module_instance_t		*submodule_inst;

		if (!submodule_cs) continue;	/* Skipped as we don't have SSL support */

		submodule_inst = module_bootstrap(module_by_data(inst), submodule_cs);
		if (!submodule_inst) return -1;
		submodule = (rlm_eap_submodule_t const *)submodule_inst->dl_inst->module->common;

		/*
		 *	Add the methods the submodule provides
		 */
		for (j = 0; j < MAX_PROVIDED_METHODS; j++) {
			if (!submodule->provides[j]) break;

			method = submodule->provides[j];
			/*
			 *	Check for duplicates
			 */
			if (inst->methods[method].submodule) {
				CONF_SECTION *conf = inst->methods[method].submodule_inst->dl_inst->conf;

				cf_log_err(submodule_cs, "Duplicate EAP-Type %s.  Conflicting entry %s[%u]",
					   eap_type2name(method),
					   cf_filename(conf), cf_lineno(conf));

				return -1;
			}

			inst->methods[method].submodule_inst = submodule_inst;
			inst->methods[method].submodule = submodule;
		}

		count++;
	}

	if (count == 0) {
		cf_log_err(cs, "No EAP method configured, module cannot do anything");
		return -1;
	}

	return 0;
}

static int mod_load(void)
{
	rlm_eap_t	instance = { .name = "global" };
	rlm_eap_t	*inst = &instance;

	if (eap_base_init() < 0) {
		PERROR("Failed initialising EAP base library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	eap_base_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
module_t rlm_eap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "eap",
	.inst_size	= sizeof(rlm_eap_t),
	.config		= module_config,
	.onload		= mod_load,
	.unload		= mod_unload,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
