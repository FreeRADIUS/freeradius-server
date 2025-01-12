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

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include "rlm_eap.h"

extern module_rlm_t rlm_eap;

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
			   CONF_ITEM *ci, UNUSED conf_parser_t const *rule);
static int eap_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			  CONF_ITEM *ci, UNUSED conf_parser_t const *rule);

static fr_table_num_sorted_t const require_identity_realm_table[] = {
	{ L("nai"),	REQUIRE_REALM_NAI	},
	{ L("no"),	REQUIRE_REALM_NO	},
	{ L("yes"),	REQUIRE_REALM_YES 	}
};
static size_t require_identity_realm_table_len = NUM_ELEMENTS(require_identity_realm_table);

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("require_identity_realm", rlm_eap_t, require_realm),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){ .table = require_identity_realm_table, .len = &require_identity_realm_table_len },
			 .dflt = "nai" },

	{ FR_CONF_OFFSET_IS_SET("default_eap_type", FR_TYPE_VOID, 0, rlm_eap_t, default_method), .func = eap_type_parse },

	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_MULTI | CONF_FLAG_NOT_EMPTY, rlm_eap_t, type_submodules), .func = submodule_parse },

	{ FR_CONF_OFFSET("ignore_unknown_eap_types", rlm_eap_t, ignore_unknown_types), .dflt = "no" },

	{ FR_CONF_DEPRECATED("timer_expire", rlm_eap_t, timer_limit), .dflt = "60" },
	{ FR_CONF_DEPRECATED("cisco_accounting_username_bug", rlm_eap_t,
			     cisco_accounting_username_bug), .dflt = "no" },
	{ FR_CONF_DEPRECATED("max_sessions", rlm_eap_t, max_sessions), .dflt = "2048" },
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
static fr_dict_attr_t const *attr_stripped_user_domain;

static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;


extern fr_dict_attr_autoload_t rlm_eap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_domain, .name = "Stripped-User-Domain", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);
static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

/** Loads submodules based on type = foo pairs
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
static int submodule_parse(TALLOC_CTX *ctx, void *out, void *parent,
			   CONF_ITEM *ci, conf_parser_t const *rule)
{	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	char		*our_name = NULL;
	char		*p;
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
	talloc_free(our_name);

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
		CONF_SECTION	*eap_cs = cf_item_to_section(cf_parent(ci));

		module_inst_ctx_t *mctx = MODULE_INST_CTX(
			((module_instance_t *)cf_data_value(cf_data_find(eap_cs,
									module_instance_t, "rlm_eap"))));
		WARN("Ignoring EAP method %s because we don't have OpenSSL support", name);
	}
		return 0;

	default:
		break;
	}
#endif
 	return module_rlm_submodule_parse(ctx, out, parent, ci, rule);
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
			  CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
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
				  eap_type_t last_type,
				  eap_type_data_t *nak)
{
	rlm_eap_t const *inst = talloc_get_type_abort_const(mctx->mi->data, rlm_eap_t);
	unsigned int i, s_i = 0;
	fr_pair_t *vp = NULL;
	eap_type_t method = FR_EAP_METHOD_INVALID;
	eap_type_t sanitised[nak->length];

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
	 *	Do a loop over the contents of the NAK, only moving entries
	 *	which are valid to the sanitised array.
	 */
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
		 *
		 *	FIXME: Really we should keep a list of
		 *	methods we've already sent back.
		 */
		if (last_type == nak->data[i]) {
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

		sanitised[s_i++] = nak->data[i];
	}

	if (s_i == 0) {
		REDEBUG("Peer presented no valid EAP types in its NAK response");
		return FR_EAP_METHOD_INVALID;
	}

	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_eap_type);
	if (vp) {
		/*
		 *	Loop over allowed methods and the contents
		 *	of the NAK, attempting to find something
		 *	we can continue with.
		 */
		do {
			/*
			 *	Provide a way of the admin potentially
			 *	disabling EAP negotiation.
			 */
			if (vp->vp_uint32 == FR_EAP_METHOD_INVALID) continue;

			for (i = 0; i < s_i; i++) {
				/*
				 *	Enforce per-user configuration of EAP
				 *	types.
				 */
				if (vp->vp_uint32 != sanitised[i]) continue;
				RDEBUG2("Found mutually acceptable type %s (%d)", eap_type2name(sanitised[i]), sanitised[i]);
				method = sanitised[i];
				break;
			}

			if (method != FR_EAP_METHOD_INVALID) break;	/* Found one1 */
		} while ((vp = fr_pair_find_by_da(&request->control_pairs, vp, attr_eap_type)));
	/*
	 *	If there's no control pairs, respond with
	 *	the first valid method in the NAK.
	 */
	} else {
		method = sanitised[0];
	}

	/*
	 *	Couldn't find something to continue with,
	 *	emit a very verbose message.
	 */
	if (method == FR_EAP_METHOD_INVALID) {
		fr_sbuff_t *proposed = NULL, *allowed = NULL;

		FR_SBUFF_TALLOC_THREAD_LOCAL(&proposed, 256, 1024);
		FR_SBUFF_TALLOC_THREAD_LOCAL(&allowed, 256, 1024);

		for (i = 0; i < s_i; i++) {
			(void) fr_sbuff_in_sprintf(proposed, "%s (%d), ", eap_type2name(sanitised[i]), sanitised[i]);
		}
		fr_sbuff_advance(proposed, -2);
		fr_sbuff_terminate(proposed);

		vp = NULL;
		while ((vp = fr_pair_find_by_da(&request->control_pairs, vp, attr_eap_type))) {
			(void) fr_sbuff_in_sprintf(allowed, "%s (%d), ", eap_type2name(vp->vp_uint32), vp->vp_uint32);
		}
		fr_sbuff_advance(allowed, -2);	/* Negative advance past start should be disallowed */
		fr_sbuff_terminate(allowed);

		REDEBUG("No mutually acceptable EAP types found.  Supplicant proposed: %s.  We allow: %s",
		        fr_sbuff_start(proposed), fr_sbuff_start(allowed));
	}

	return method;
}

/** Cancel a call to a submodule
 *
 * @param[in] mctx	module calling ctx.
 * @param[in] request	The current request.
 * @param[in] action	to perform.
 */
static void mod_authenticate_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	eap_session_t	*eap_session;

	RDEBUG2("Request cancelled - Destroying EAP-Session");

	eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);

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
 * @return The result of this round of authentication.
 */
static unlang_action_t mod_authenticate_result_async(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						     request_t *request)
{
	eap_session_t	*eap_session = talloc_get_type_abort(mctx->rctx, eap_session_t);

	return mod_authenticate_result(p_result, mctx, request, eap_session, eap_session->submodule_rcode);
}

/** Basic tests to determine if an identity is a valid NAI
 *
 * In this version we mostly just care about realm.
 *
 * @param[in] identity	to check.
 * @return
 *	- The length of the string on success.
 *	- <= 0 a negative offset specifying where the format error occurred.
 */
static ssize_t eap_identity_is_nai_with_realm(char const *identity)
{
	char const *p = identity;
	char const *end = identity + (talloc_array_length(identity) - 1);
	char const *realm;

	/*
	 *	Get the last '@'
	 */
	p = realm = memrchr(identity, '@', end - p);
	if (!p) {
		fr_strerror_printf("Identity is not valid.  Missing realm separator '@'");
		return identity - end;
	}

	p = memchr(p, '.', end - p);
	if (!p) {
		fr_strerror_printf("Identity is not valid.  Realm is missing label separator '.'");
		return identity - end;
	}

	if ((realm - 1) == p) {
		fr_strerror_printf("Identity is not valid.  "
				   "Realm is missing label between realm separator '@' and label separator '.'");
		return identity - realm;
	}
	if ((p + 1) == end) {
		fr_strerror_printf("Identity is not valid.  "
				   "Realm is missing label between label separator '.' and the end of the "
				   "identity string");
		return identity - end;
	}

	return end - identity;
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
 *	- UNLANG_ACTION_CALCULATE_RESULT	+ *p_result = RLM_MODULE_INVALID.
 *						Invalid request.
 *	- UNLANG_ACTION_PUSHED_CHILD		Yield control back to the interpreter so it can
 *						call the submodule.
 */
static unlang_action_t eap_method_select(rlm_rcode_t *p_result, module_ctx_t const *mctx, eap_session_t *eap_session)
{
	rlm_eap_t const			*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_eap_t);
	eap_type_data_t			*type = &eap_session->this_round->response->type;
	request_t			*request = eap_session->request;

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
	if (type->num == FR_EAP_METHOD_TLS && eap_session->request->parent &&
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
		{
			ssize_t slen;

			/*
			 *	Check if we allow this identity format
			 */
			switch (inst->require_realm) {
			case REQUIRE_REALM_NAI:
				slen = eap_identity_is_nai_with_realm(eap_session->identity);
				if (slen <= 0) {
					char *tmp_id;
				bad_id:
					/*
					 *	Produce an escaped version and run that
					 *	through the format check function to get
					 *	the correct offset *sigh*...
					 */
					MEM(tmp_id = fr_asprint(NULL,
								eap_session->identity,
								talloc_array_length(eap_session->identity) - 1,
								'"'));
					slen = eap_identity_is_nai_with_realm(tmp_id);

					REMARKER(tmp_id, slen, "%s", fr_strerror());

					talloc_free(tmp_id);
					goto is_invalid;
				}
				break;

			case REQUIRE_REALM_YES:
				slen = eap_identity_is_nai_with_realm(eap_session->identity);
				if (slen <= 0) {
					fr_pair_t *stripped_user_domain;

					/*
					 *	If it's not an NAI with a realm, check
					 *	to see if the user has set Stripped-User-domain.
					 */
					stripped_user_domain = fr_pair_find_by_da_idx(&eap_session->request->request_pairs,
										  attr_stripped_user_domain, 0);
					if (!stripped_user_domain) goto bad_id;
				}
				break;

			case REQUIRE_REALM_NO:
				break;
			}
		}
		/*
		 *	Allow per-user configuration of EAP types.
		 */
		vp = fr_pair_find_by_da(&eap_session->request->control_pairs, NULL, attr_eap_type);
		if (vp) {
			RDEBUG2("Using method from &control.EAP-Type");
			next = vp->vp_uint32;
		/*
		 *	We have an array of the submodules which
		 *	have a type_identity callback.  Call
		 *	each of these in turn to see if any of
		 *	them recognise the identity.
		 */
		} else if (inst->type_identity_submodule) {
			size_t i;

			for (i = 0; i < inst->type_identity_submodule_len; i++) {
				rlm_eap_submodule_t const *submodule =
					(rlm_eap_submodule_t const *)inst->type_identity_submodule[i]->exported;
				eap_type_t ret;

				ret = submodule->type_identity(inst->type_identity_submodule[i]->data,
							       eap_session->identity,
							       talloc_array_length(eap_session->identity) - 1);
				if (ret != FR_EAP_METHOD_INVALID) {
					next = ret;
					break;
				}
			}
		}
	do_init:
		/*
		 *	Ensure it's valid.
		 */
		if ((next < FR_EAP_METHOD_MD5) || (next >= FR_EAP_METHOD_MAX) || (!inst->methods[next].submodule)) {
			REDEBUG2("Peer tried to start unsupported EAP type %s (%d)",
				 eap_type2name(next), next);
			goto is_invalid;
		}

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
		fr_state_discard_child(eap_session->request, eap_session, 0);
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
			REDEBUG2("Peer asked for unsupported EAP type %s (%d)", eap_type2name(type->num), type->num);
			goto is_invalid;
		}
		/*
		 *	Perr started the EAP method without
		 *	sending an Identity-Response.
		 *
		 *	There's nothing that says it *HAS* to send an
		 *	identity response before starting a method,
		 *	so just jump to the initialisation function
		 *	of the method and continue.
		 */
		if (eap_session->rounds == 0) {
			RDEBUG2("Peer started EAP type %s (%d) without sending an Identity", eap_type2name(type->num), type->num);
			vp = fr_pair_find_by_da(&eap_session->request->control_pairs, NULL, attr_eap_type);
			if (vp) {
				RDEBUG2("Using method from &control.EAP-Type");
				next = vp->vp_uint32;
			}
			goto do_init;
		}

		/*
		 *	FIXME - We should only update the type
		 *	on completion of the final round.
		 */
		eap_session->type = type->num;
		break;
	}

	method = &inst->methods[eap_session->type];

	RDEBUG2("Calling submodule %s", method->submodule->common.name);

	/*
	 *	Allocate a new subrequest
	 */
	MEM(eap_session->subrequest = unlang_subrequest_alloc(request,
							      method->submodule->namespace ?
							      *(method->submodule->namespace) :
							      request->dict));

	if (method->submodule->clone_parent_lists) {
		if (fr_pair_list_copy(eap_session->subrequest->control_ctx,
				      &eap_session->subrequest->control_pairs, &request->control_pairs) < 0) {
		list_copy_fail:
			RERROR("Failed copying parent's attribute list");
		fail:
			TALLOC_FREE(eap_session->subrequest);
			RETURN_MODULE_FAIL;
		}

		if (fr_pair_list_copy(eap_session->subrequest->request_ctx,
				      &eap_session->subrequest->request_pairs,
				      &request->request_pairs) < 0) goto list_copy_fail;
	}

	/*
	 *	Push a resumption frame for the parent
	 *	This will get executed when the child is
	 *	done (after the subrequest frame in the
	 *	parent gets popped).
	 */
	(void)unlang_module_yield(request, mod_authenticate_result_async, mod_authenticate_cancel, ~FR_SIGNAL_CANCEL, eap_session);

	/*
	 *	This sets up a subrequest frame in the parent
	 *	and a resumption frame in the child.
	 *
	 *	This must be done before pushing frames onto
	 *	the child's stack.
	 */
	if (unlang_subrequest_child_push(&eap_session->submodule_rcode, eap_session->subrequest,
					 &(unlang_subrequest_session_t){ .enable = true, .unique_ptr = eap_session },
					 false, UNLANG_SUB_FRAME) < 0) {
	child_fail:
		unlang_interpet_frame_discard(request);	/* Ensure the yield frame doesn't stick around */
		goto fail;
	}

	/*
	 *	Push the EAP submodule into the child's stack
	 */
	if (unlang_module_push(NULL,	/* rcode should bubble up and be set in eap_session->submodule_rcode */
			       eap_session->subrequest, method->submodule_inst, eap_session->process,
			       UNLANG_SUB_FRAME) < 0) {
		goto child_fail;
	}

	if (eap_session->identity) {
		fr_pair_t	*identity;

		request = eap_session->subrequest;	/* Set request for pair_append_request macro */

		MEM(pair_append_request(&identity, attr_eap_identity) >= 0);
		fr_pair_value_bstrdup_buffer(identity, eap_session->identity, true);
	}

	/*
	 *	Add the EAP-Type we're running to the subrequest
	 *	This is useful for when policies are shared between
	 *      virtual server sections for multiple EAP types.
	 */
	{
		fr_pair_t	*type_vp;

		MEM(pair_append_request(&type_vp, attr_eap_type) >= 0);
		type_vp->vp_uint32 = eap_session->type;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_eap_t);
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;
	unlang_action_t		ua;

	if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_eap_message)) {
		REDEBUG("You set 'Auth-Type = EAP' for a request that does not contain an EAP-Message attribute!");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Reconstruct the EAP packet from the EAP-Message
	 *	attribute.  The relevant decoder should have already
	 *	concatenated the fragments into a single buffer.
	 */
	eap_packet = eap_packet_from_vp(request, &request->request_pairs);
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
	rlm_eap_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_eap_t);
	int			status;

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup EAP authentication",
		     mctx->mi->name, mctx->mi->name);
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

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	if (status == RLM_MODULE_OK) RETURN_MODULE_OK;

	RETURN_MODULE_UPDATED;
}

static unlang_action_t mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t		*vp;
	eap_session_t		*eap_session;
	fr_pair_t		*username;

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if ((request->reply->code == FR_RADIUS_CODE_ACCESS_ACCEPT) && username) {
		/*
		 *	Doesn't exist, add it in.
		 */
		vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_user_name);
		if (!vp) {
			vp = fr_pair_copy(request->reply_ctx, username);
			fr_pair_append(&request->reply_pairs, vp);
		}
	}

	/*
	 *	Only synthesize a failure message if something
	 *	previously rejected the request.
	 */
	if (request->reply->code != FR_RADIUS_CODE_ACCESS_REJECT) RETURN_MODULE_NOOP;

	if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_eap_message)) {
		RDEBUG3("Request didn't contain an EAP-Message, not inserting EAP-Failure");
		RETURN_MODULE_NOOP;
	}

	if (fr_pair_find_by_da(&request->reply_pairs, NULL, attr_eap_message)) {
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
	 *	If this reject is before eap has been called in authenticate
	 *	the eap_round will not have been populated.
	 */
	if (!eap_session->this_round) {
		eap_packet_raw_t	*eap_packet = eap_packet_from_vp(request, &request->request_pairs);
		eap_session->this_round  = eap_round_build(eap_session, &eap_packet);
	}

	/*
	 *	This should never happen, but we may be here
	 *	because there was an unexpected error in the
	 *	EAP module.
	 */
	if (!fr_cond_assert(eap_session->this_round) || !fr_cond_assert(eap_session->this_round->request)) {
		eap_session_destroy(&eap_session);		/* Free the EAP session, and dissociate it from the request */
		RETURN_MODULE_FAIL;
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
		mctx->mi->name);
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

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_eap_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_t);
	size_t		i;
	size_t		j, loaded, count = 0;

	loaded = talloc_array_length(inst->type_submodules);

	/*
	 *	Pre-allocate the method identity to be the number
	 *	of modules we're going to load.
	 *
	 *	We'll shrink it later.
	 */
	if (!inst->default_method_is_set) {
		MEM(inst->type_identity_submodule = talloc_array(inst, module_instance_t const *, loaded));
	}

	for (i = 0; i < loaded; i++) {
		module_instance_t 		*submodule_inst = inst->type_submodules[i];
		rlm_eap_submodule_t const	*submodule;

		if (!submodule_inst) continue;	/* Skipped as we don't have SSL support */

		submodule = (rlm_eap_submodule_t const *)submodule_inst->module->exported;

		/*
		 *	Add the methods the submodule provides
		 */
		for (j = 0; j < MAX_PROVIDED_METHODS; j++) {
			eap_type_t	method;

			if (!submodule->provides[j]) break;

			method = submodule->provides[j];

			/*
			 *	If the user didn't specify a default method
			 *	take the first method provided by the first
			 *	submodule as the default.
			 */
			if (!inst->default_method_is_set && (i == 0)) inst->default_method = method;

			/*
			 *	Check for duplicates
			 */
			if (inst->methods[method].submodule) {
				CONF_SECTION *conf = inst->methods[method].submodule_inst->conf;

				cf_log_err(submodule_inst->conf,
					   "Duplicate EAP-Type %s.  Conflicting entry %s[%u]",
					   eap_type2name(method),
					   cf_filename(conf), cf_lineno(conf));

				return -1;
			}

			inst->methods[method].submodule_inst = submodule_inst;
			inst->methods[method].submodule = submodule;
		}

		/*
		 *	This module provides a method identity
		 *	callback.  We need to call each of these
		 *	in turn if default_eap_type isn't set,
		 *	to figure out the default eap type.
		 */
		if (!inst->default_method_is_set && submodule->type_identity) {
			inst->type_identity_submodule[inst->type_identity_submodule_len++] = submodule_inst;
		}
		count++;
	}

	/*
	 *	Check if the default method specified is actually
	 *	allowed by the config.
	 */
	if (inst->default_method_is_set && !inst->methods[inst->default_method].submodule) {
		cf_log_err_by_child(mctx->mi->conf, "default_eap_type", "EAP-Type \"%s\" is not enabled",
				    eap_type2name(inst->default_method));
		return -1;
	}

	if (count == 0) {
		cf_log_err(mctx->mi->conf, "No EAP method(s) configured, module cannot do anything");
		return -1;
	}

	/*
	 *	Shrink the method identity array so it's the
	 *	correct length.
	 */
	if (!inst->default_method_is_set) {
		if (inst->type_identity_submodule_len > 0) {
			MEM(inst->type_identity_submodule = talloc_realloc(inst, inst->type_identity_submodule,
									   module_instance_t const *,
									   inst->type_identity_submodule_len));
		} else {
			TALLOC_FREE(inst->type_identity_submodule);
		}
	}

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->mi->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  EAP authentication will likely not work",
		     mctx->mi->name);
	}

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) inst->rand_pool.randrsl[i] = fr_rand();
	fr_isaac_init(&inst->rand_pool, 1);
	inst->rand_pool.randcnt = 0;

	return 0;
}

static int mod_load(void)
{
	if (eap_base_init() < 0) {
		fr_perror("Failed initialising EAP base library");
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
module_rlm_t rlm_eap = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap",
		.inst_size	= sizeof(rlm_eap_t),
		.config		= module_config,
		.onload		= mod_load,
		.unload		= mod_unload,
		.instantiate	= mod_instantiate,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate },
			{ .section = SECTION_NAME("recv", "Access-Request"), .method = mod_authorize },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY), .method = mod_post_auth },
			MODULE_BINDING_TERMINATOR
		}
	}
};
