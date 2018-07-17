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
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_eap (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/dl.h>
#include "rlm_eap.h"

extern rad_module_t rlm_eap;

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

	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, rlm_eap_t, submodule_instances),
			 .func = submodule_parse },

	{ FR_CONF_DEPRECATED("timer_expire", FR_TYPE_UINT32, rlm_eap_t, timer_limit), .dflt = "60" },
	{ FR_CONF_OFFSET("ignore_unknown_eap_types", FR_TYPE_BOOL, rlm_eap_t, ignore_unknown_types), .dflt = "no" },
	{ FR_CONF_OFFSET("cisco_accounting_username_bug", FR_TYPE_BOOL, rlm_eap_t,
			 cisco_accounting_username_bug), .dflt = "no" },
	{ FR_CONF_DEPRECATED("max_sessions", FR_TYPE_UINT32, rlm_eap_t, max_sessions), .dflt = "2048" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_eap_dict[];
fr_dict_autoload_t rlm_eap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_post_auth_type;
fr_dict_attr_t const *attr_eap_type;

static fr_dict_attr_t const *attr_cisco_avpair;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_message_authenticator;
fr_dict_attr_t const *attr_state;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_eap_type, .name = "EAP-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_post_auth_type, .name = "Post-Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_cisco_avpair, .name = "Cisco-AvPair", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

static rlm_rcode_t mod_post_proxy(void *instance, UNUSED void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authorize(void *instance, UNUSED void *thread, REQUEST *request) CC_HINT(nonnull);

/** Wrapper around dl_instance which loads submodules based on type = foo pairs
 *
 * @param[in] ctx	to allocate data in (instance of rlm_eap_t).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int submodule_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const			*name = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION			*eap_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION			*submodule_cs;
	eap_type_t			method;
	dl_instance_t			*parent_inst;
	dl_instance_t			*dl_inst;
	rlm_eap_submodule_t const	*submodule;
	rlm_eap_t			*inst;
	int				ret;
	uint8_t				i;

	method = eap_name2type(name);
	if (method == FR_EAP_INVALID) {
		cf_log_err(ci, "Unknown EAP type %s", name);
		return -1;
	}

	/*
	 *	Helpfully stored for us by dl_instance()
	 */
	parent_inst = cf_data_value(cf_data_find(eap_cs, dl_instance_t, "rlm_eap"));
	rad_assert(parent_inst);
	inst = talloc_get_type_abort(parent_inst->data, rlm_eap_t);

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
	case FR_EAP_TLS:
	case FR_EAP_TTLS:
	case FR_EAP_PEAP:
	case FR_EAP_PWD:
	case FR_EAP_AKA:
	case FR_EAP_SIM:
		WARN("Ignoring EAP method %s because we don't have OpenSSL support", name);
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

	ret = dl_instance(ctx, &dl_inst, submodule_cs, parent_inst, name, DL_TYPE_SUBMODULE);
	if (ret < 0) return -1;


	submodule = (rlm_eap_submodule_t const *)dl_inst->module->common;

	/*
	 *	Add the methods the submodule provides
	 */
	for (i = 0; i < MAX_PROVIDED_METHODS; i++) {
		if (!submodule->provides[i]) break;

		method = submodule->provides[i];
		/*
		 *	Check for duplicates
		 */
		if (inst->methods[method].submodule) {
			CONF_SECTION *conf = inst->methods[method].submodule_inst->conf;

			cf_log_err(ci, "Duplicate EAP-Type %s.  Conflicting entry %s[%u]", name,
				   cf_filename(conf), cf_lineno(conf));
			talloc_free(dl_inst);
			return -1;
		}

		inst->methods[method].submodule_inst = dl_inst;
		inst->methods[method].submodule = submodule;
	}

	rad_assert(i > 0);	/* Yes this is a fatal error */

	*(void **)out = dl_inst;

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
	if (method == FR_EAP_INVALID) {
		cf_log_err(ci, "Unknown EAP type %s", default_method_name);
		return -1;
	}

	*(eap_type_t *)out = method;

	return 0;
}

/** Process NAK data from EAP peer
 *
 */
static eap_type_t eap_process_nak(rlm_eap_t *inst, REQUEST *request,
				  eap_type_t type,
				  eap_type_data_t *nak)
{
	unsigned int i;
	VALUE_PAIR *vp;
	eap_type_t method = FR_EAP_INVALID;

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

		return FR_EAP_INVALID;
	}

	/*
	 *	Pick one type out of the one they asked for,
	 *	as they may have asked for many.
	 */
	vp = fr_pair_find_by_da(request->control, attr_eap_type, TAG_ANY);
	for (i = 0; i < nak->length; i++) {
		/*
		 *	Type 0 is valid, and means there are no
		 *	common choices.
		 */
		if (nak->data[i] == 0) {
			RDEBUG("Peer NAK'd indicating it is not willing to continue ");

			return FR_EAP_INVALID;
		}

		/*
		 *	It is invalid to request identity,
		 *	notification & nak in nak.
		 */
		if (nak->data[i] < FR_EAP_MD5) {
			REDEBUG("Peer NAK'd asking for bad type %s (%d)", eap_type2name(nak->data[i]), nak->data[i]);

			return FR_EAP_INVALID;
		}

		if ((nak->data[i] >= FR_EAP_MAX_TYPES) ||
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

		RDEBUG("Found mutually acceptable type %s (%d)", eap_type2name(nak->data[i]), nak->data[i]);

		method = nak->data[i];

		break;
	}

	if (method == FR_EAP_INVALID) REDEBUG("No mutually acceptable types found");

	return method;
}

/** Process the result of calling a submodule
 *
 * @param[in] request	The current request.
 * @param[in] instance	of the rlm_eap module.
 * @param[in] thread	UNUSED.
 * @param[in] eap_session the EAP session
 * @param[in] result	the input result from the submodule
 * @return
 *	- RLM_MODULE_INVALID	if the request or EAP session state is invalid.
 *	- RLM_MODULE_OK		if this round succeeded.
 *	- RLM_MODULE_HANDLED	if we're done with this round.
 *	- RLM_MODULE_REJECT	if the user should be rejected.
 */
static rlm_rcode_t mod_authenticate_result(REQUEST *request, void *instance, UNUSED void *thread,
					   eap_session_t *eap_session, rlm_rcode_t result)
{
	rlm_eap_t		*inst = talloc_get_type_abort(instance, rlm_eap_t);
	rlm_eap_method_t	*method = &inst->methods[eap_session->type];
	rlm_rcode_t		rcode;

	RDEBUG2("Submodule %s returned", method->submodule->name);

	/*
	 *	The submodule failed.  Die.
	 */
	if (result == RLM_MODULE_INVALID) {
		eap_fail(eap_session);
		eap_session_destroy(&eap_session);

		rcode = RLM_MODULE_INVALID;
		goto finish;
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
	    (eap_session->this_round->request->type.num >= FR_EAP_MD5)) ||

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
	     (eap_session->this_round->response->type.num == FR_EAP_LEAP) &&
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
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	if ((request->reply->code == FR_CODE_ACCESS_ACCEPT) && request->username) {
		VALUE_PAIR *vp;

		/*
		 *	Doesn't exist, add it in.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_user_name, TAG_ANY);
		if (!vp) {
			vp = fr_pair_copy(request->reply, request->username);
			fr_pair_add(&request->reply->vps, vp);
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.
		 */
		if (inst->cisco_accounting_username_bug) {
			char *new;

			new = talloc_zero_array(vp, char, vp->vp_length + 1 + 1);	/* \0 + \0 */
			memcpy(new, vp->vp_strvalue, vp->vp_length);
			fr_pair_value_strsteal(vp, new);        /* Also frees existing buffer */
		}
	}

	/*
	 *	Freeze the eap_session so we can continue
	 *	the authentication session later.
	 */
	eap_session_freeze(&eap_session);

finish:
	return rcode;
}

/** Call mod_authenticate_result asynchronously from the unlang interpreter
 *
 * @param[in] request	The current request.
 * @param[in] instance	of rlm_eap.
 * @param[in] thread	UNUSED.
 * @param[in] uctx	the eap_session_t.
 * @return The result of this round of authentication.
 */
static rlm_rcode_t mod_authenticate_result_async(REQUEST *request, void *instance, void *thread, void *uctx)
{
	eap_session_t	*eap_session = talloc_get_type_abort(uctx, eap_session_t);
	rlm_rcode_t	result = unlang_stack_result(request);

	return mod_authenticate_result(request, instance, thread, eap_session, result);
}

/** Select the correct callback based on a response
 *
 * Based on the EAP response from the supplicant, and setup a call on the
 * unlang stack to the appropriate submodule.
 *
 * Default to the configured EAP-Type for all Unsupported EAP-Types.
 *
 * @param[in] inst		Configuration data for this instance of rlm_eap.
 * @param[in] thread		UNUSED.
 * @param[in] eap_session	State data that persists over multiple rounds of EAP.
 * @return
 *	- RLM_MODULE_INVALID	destroy the EAP session as its invalid.
 *	- RLM_MODULE_YIELD	Yield control back to the interpreter so it can
 *				call the submodule.
 */
static rlm_rcode_t eap_method_select(rlm_eap_t *inst, void *thread, eap_session_t *eap_session)
{
	eap_type_data_t			*type = &eap_session->this_round->response->type;
	REQUEST				*request = eap_session->request;

	rlm_eap_method_t const		*method;

	eap_type_t			next = inst->default_method;
	VALUE_PAIR			*vp;

	rlm_rcode_t			rcode;

	/*
	 *	Session must have been thawed...
	 */
	rad_assert(eap_session->request);

	/*
	 *	Don't trust anyone.
	 */
	if ((type->num == 0) || (type->num >= FR_EAP_MAX_TYPES)) {
		REDEBUG("Peer sent EAP type number %d, which is outside known range", type->num);

		return RLM_MODULE_INVALID;
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
	    eap_session->request->parent->parent &&
	    !eap_session->request->parent->parent->home_server) {
		RERROR("Multiple levels of TLS nesting are invalid");

		return RLM_MODULE_INVALID;
	}

	RDEBUG2("Peer sent packet with EAP method %s (%d)", eap_type2name(type->num), type->num);

	/*
	 *	Figure out what to do.
	 */
	switch (type->num) {
	case FR_EAP_IDENTITY:
		/*
		 *	Allow per-user configuration of EAP types.
		 */
		vp = fr_pair_find_by_da(eap_session->request->control, attr_eap_type, TAG_ANY);
		if (vp) {
			RDEBUG2("Setting method from &control:EAP-Type");
			next = vp->vp_uint32;
		}

		/*
		 *	Ensure it's valid.
		 */
		if ((next < FR_EAP_MD5) || (next >= FR_EAP_MAX_TYPES) || (!inst->methods[next].submodule)) {
			REDEBUG2("Tried to start unsupported EAP type %s (%d)",
				 eap_type2name(next), next);
			return RLM_MODULE_INVALID;
		}

	do_initiate:
		/*
		 *	If any of these fail, we messed badly somewhere
		 */
		rad_assert(next >= FR_EAP_MD5);
		rad_assert(next < FR_EAP_MAX_TYPES);
		rad_assert(inst->methods[next].submodule);

		eap_session->process = inst->methods[next].submodule->session_init;
		eap_session->type = next;
		goto module_call;

	case FR_EAP_NAK:
		/*
		 *	Delete old data, if necessary.  If we called a method
		 *	before, and it initialized itself, we need to free
		 *	the memory it alloced.
		 */
		TALLOC_FREE(eap_session->opaque);
		next = eap_process_nak(inst, eap_session->request, eap_session->type, type);

		/*
		 *	We probably want to return 'fail' here...
		 */
		if (!next) return RLM_MODULE_INVALID;
		goto do_initiate;

	/*
	 *	Key off of the configured sub-modules.
	 */
	default:
		break;
	}

	/*
	 *	We haven't configured it, it doesn't exit.
	 */
	if (!inst->methods[type->num].submodule) {
		REDEBUG2("Client asked for unsupported EAP type %s (%d)", eap_type2name(type->num), type->num);

		return RLM_MODULE_INVALID;
	}

	eap_session->type = type->num;

module_call:
	method = &inst->methods[eap_session->type];

	unlang_module_yield(request, mod_authenticate_result_async, NULL, eap_session);

	/*
	 *	mod_authenticate_result will be called after
	 *	eap_call_submodule finishes.
	 */
	RDEBUG2("Calling submodule %s", method->submodule->name);
//	caller = request->module;
//	request->module = method->submodule->name;
	rcode = eap_session->process(method->submodule_inst->data, eap_session);
//	request->module = caller;

	/*
	 *	If the submodule yielded, then setup a resumption
	 *	frame for when it finishes.
	 */
	if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

	/*
	 *	If the submodule didn't yield call the result
	 *	function directly using the C stack.
	 */
	return mod_authenticate_result(request, inst, thread, eap_session, rcode);
}

static rlm_rcode_t mod_authenticate(void *instance, void *thread, REQUEST *request)
{
	rlm_eap_t		*inst = talloc_get_type_abort(instance, rlm_eap_t);
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;

	if (!fr_pair_find_by_da(request->packet->vps, attr_eap_message, TAG_ANY)) {
		REDEBUG("You set 'Auth-Type = EAP' for a request that does not contain an EAP-Message attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Reconstruct the EAP packet from the EAP-Message
	 *	attribute.  The relevant decoder should have already
	 *	concatenated the fragments into a single buffer.
	 */
	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RPERROR("Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Allocate a new eap_session, or if this request
	 *	is part of an ongoing authentication session,
	 *	retrieve the existing eap_session from the request
	 *	data.
	 */
	eap_session = eap_session_continue(&eap_packet, inst, request);
	if (!eap_session) return RLM_MODULE_INVALID;	/* Don't emit error here, it will mask the real issue */

	/*
	 *	Call an EAP submodule to process the request,
	 *	or with simple types like Identity and NAK,
	 *	process it ourselves.
	 */
	return eap_method_select(inst, thread, eap_session);
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existence & get their configured values.
 * It Handles EAP-START Messages, User-Name initialization.
 */
static rlm_rcode_t mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_eap_t const		*inst = instance;
	int			status;

#ifdef WITH_PROXY
	/*
	 *	We don't do authorization again, once we've seen the
	 *	proxy reply (or the proxied packet)
	 */
	if (request->proxy != NULL)
		return RLM_MODULE_NOOP;
#endif

	/*
	 *	For EAP_START, send Access-Challenge with EAP Identity
	 *	request.  even when we have to proxy this request
	 *
	 *	RFC 2869, Section 2.3.1 notes that the "domain" of the
	 *	user, (i.e. where to proxy him) comes from the EAP-Identity,
	 *	so we CANNOT proxy the user, until we know his identity.
	 *
	 *	We therefore send an EAP Identity request.
	 */
	status = eap_start(inst, request);
	switch (status) {
	case RLM_MODULE_NOOP:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_HANDLED:
		return status;

	default:
		break;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) return RLM_MODULE_NOOP;

	if (status == RLM_MODULE_OK) return RLM_MODULE_OK;

	return RLM_MODULE_UPDATED;
}

#ifdef WITH_PROXY
/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static rlm_rcode_t mod_post_proxy(void *instance, UNUSED void *thread, REQUEST *request)
{
	size_t		i;
	size_t		len;
	ssize_t		ret;
	char		*p;
	VALUE_PAIR	*vp;
	eap_session_t	*eap_session;
	fr_cursor_t	cursor;
	rlm_eap_t const	*inst = instance;

	/*
	 *	If there was a eap_session associated with this request,
	 *	then it's a tunneled request which was proxied...
	 */
	if (request_data_get(request, inst, REQUEST_DATA_EAP_SESSION_PROXIED)) {
		rlm_rcode_t		rcode;
		eap_tunnel_data_t	*data;

		eap_session = eap_session_thaw(request);
		rad_assert(eap_session);

		/*
		 *	Grab the tunnel callbacks from the request.
		 */
		data = (eap_tunnel_data_t *) request_data_get(request,
							      request->proxy,
							      REQUEST_DATA_EAP_TUNNEL_CALLBACK);
		if (!data) {
			RERROR("Failed to retrieve callback for tunneled session!");
			eap_session_destroy(&eap_session);
			return RLM_MODULE_FAIL;
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
		    (eap_session->this_round->request->type.num >= FR_EAP_MD5)) {
			talloc_free(eap_session->prev_round);
			eap_session->prev_round = eap_session->this_round;
			eap_session->this_round = NULL;
		} else {	/* couldn't have been LEAP, there's no tunnel */
			RDEBUG2("Freeing eap_session");
			eap_session_destroy(&eap_session);
		}

		/*
		 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
		 *	says that we MUST include a User-Name attribute in the
		 *	Access-Accept.
		 */
		if ((request->reply->code == FR_CODE_ACCESS_ACCEPT) && request->username) {
			MEM(pair_update_reply(&vp, attr_user_name) >= 0);
			fr_pair_value_bstrncpy(vp, request->username->vp_strvalue, request->username->vp_length);
		}

		eap_session_freeze(&eap_session);

		return RLM_MODULE_OK;
	} else {
		RDEBUG2("No pre-existing eap_session found");
	}

	/*
	 *	This is allowed.
	 */
	if (!request->proxy->reply) return RLM_MODULE_NOOP;

	/*
	 *	Hmm... there's got to be a better way to
	 *	discover codes for vendor attributes.
	 *
	 *	This is vendor Cisco (9), Cisco-AVPair
	 *	attribute (1)
	 */
	for (vp = fr_cursor_iter_by_da_init(&cursor, &request->proxy->reply->vps, attr_cisco_avpair);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	If it's "leap:session-key", then stop.
		 *
		 *	The format is VERY specific!
		 */
		if (strncasecmp(vp->vp_strvalue, "leap:session-key=", 17) == 0) break;
	}

	/*
	 *	Got to the end without finding "leap:session-key="
	 */
	if (!vp) return RLM_MODULE_NOOP;

	/*
	 *	The format is very specific.
	 *
	 *	- 17 bytes are "leap:session-key="
	 *	- 32 are the hex encoded session key.
	 *	- 2 bytes are the salt.
	 */
	if (vp->vp_length != (17 + 34)) {
		RDEBUG2("&Cisco-AVPair with leap:session-key has incorrect length. Got %zu, expected %d",
		       vp->vp_length, 17 + 34);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Decrypt the session key, using the proxy data.
	 *
	 *	Note that the session key is *binary*, and therefore
	 *	may contain embedded zeros.  So we have to use memdup.
	 *	However, Cisco-AVPair is a "string", so the rest of the
	 *	code assumes that it's terminated by a trailing '\0'.
	 *
	 *	So... be sure to (a) use memdup, and (b) include the last
	 *	zero byte.
	 */
	i = 34;
	p = talloc_memdup(vp, vp->vp_strvalue, vp->vp_length + 1);
	talloc_set_type(p, uint8_t);
	ret = fr_radius_decode_tunnel_password((uint8_t *)p + 17, &i, request->proxy->home_server->secret,
					       request->proxy->packet->vector, false);
	if (ret < 0) {
		REDEBUG("Decoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}
	len = i;
	if (len != 16) {
		REDEBUG("Decoded key length is incorrect, must be 16 bytes");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Encrypt the session key again, using the request data.
	 */
	ret = fr_radius_encode_tunnel_password(p + 17, &len, request->client->secret, request->packet->vector);
	if (ret < 0) {
		REDEBUG("Encoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	fr_pair_value_strsteal(vp, p);

	return RLM_MODULE_UPDATED;
}
#endif

static rlm_rcode_t mod_post_auth(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_eap_t const		*inst = instance;
	VALUE_PAIR		*vp;
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;

	/*
	 *	Only build a failure message if something previously rejected the request
	 */
	vp = fr_pair_find_by_da(request->control, attr_post_auth_type, TAG_ANY);
	if (!vp || (vp->vp_uint32 != FR_POST_AUTH_TYPE_REJECT)) return RLM_MODULE_NOOP;

	if (!fr_pair_find_by_da(request->packet->vps, attr_eap_message, TAG_ANY)) {
		RDEBUG3("Request didn't contain an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_da(request->reply->vps, attr_eap_message, TAG_ANY)) {
		RDEBUG3("Reply already contained an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Reconstruct the EAP packet from EAP-Message fragments
	 *	in the request.
	 */
	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RPERROR("Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Retrieve pre-existing eap_session from request
	 *	data.  This will have been added to the request
	 *	data by the state API.
	 */
	eap_session = eap_session_continue(&eap_packet, inst, request);
	if (!eap_session) {
		RDEBUG2("Failed to get eap_session, probably already removed, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	REDEBUG("Request was previously rejected, inserting EAP-Failure");
	eap_fail(eap_session);				/* Compose an EAP failure */
	eap_session_destroy(&eap_session);		/* Free the EAP session, and dissociate it from the request */

	/*
	 *	Make sure there's a message authenticator attribute in the response
	 *	RADIUS protocol code will calculate the correct value later...
	 */
	MEM(pair_update_reply(&vp, attr_message_authenticator) >= 0);
	fr_pair_value_memsteal(vp, talloc_zero_array(vp, uint8_t, AUTH_VECTOR_LEN));

	return RLM_MODULE_UPDATED;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	rlm_eap_t	*inst = talloc_get_type_abort(instance, rlm_eap_t);

	size_t		i, loaded;

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) inst->rand_pool.randrsl[i] = fr_rand();
	fr_randinit(&inst->rand_pool, 1);
	inst->rand_pool.randcnt = 0;

	loaded = talloc_array_length(inst->submodule_instances);
	for (i = 0; i < loaded; i++) {
		rlm_eap_submodule_t const	*method;
		dl_instance_t			*dl_inst = inst->submodule_instances[i];

		if (!dl_inst) continue;	/* Skipped as we don't have SSL support */

		method = (rlm_eap_submodule_t const *)dl_inst->module->common;
		if ((method->instantiate) &&
		    ((method->instantiate)(dl_inst->data, dl_inst->conf) < 0)) {
			return -1;
		}

#ifndef NDEBUG
		if (dl_inst->data) module_instance_read_only(dl_inst->data, dl_inst->name);
#endif
	}

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	rlm_eap_t	*inst = talloc_get_type_abort(instance, rlm_eap_t);
	size_t		i, loaded, count = 0;

	inst->name = cf_section_name2(cs);
	if (!inst->name) inst->name = "eap";

	loaded = talloc_array_length(inst->submodule_instances);

	for (i = 0; i < loaded; i++) {
		rlm_eap_submodule_t const	*method;
		dl_instance_t			*dl_inst = inst->submodule_instances[i];

		if (!dl_inst) continue;	/* Skipped as we don't have SSL support */

		method = (rlm_eap_submodule_t const *)dl_inst->module->common;
		if ((method->bootstrap) &&
		    ((method->bootstrap)(dl_inst->data, dl_inst->conf) < 0)) return -1;

		count++;
	}

	if (fr_dict_enum_add_alias_next(attr_auth_type, inst->name) < 0) {
		PERROR("Failed adding %s alias", inst->name);
		return -1;
	}
	inst->auth_type = fr_dict_enum_by_alias(attr_auth_type, inst->name, -1);
	rad_assert(inst->name);

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
rad_module_t rlm_eap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "eap",
	.inst_size	= sizeof(rlm_eap_t),
	.config		= module_config,
	.load		= mod_load,
	.unload		= mod_unload,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_PROXY
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
