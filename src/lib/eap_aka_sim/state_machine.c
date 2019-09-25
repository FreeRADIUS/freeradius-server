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
 * @file src/lib/eap_aka_sim/state_machine.c
 * @brief Implement a common state machine for EAP-SIM, EAP-AKA, EAP-AKA'.
 *
 * @author Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS \<info@networkradius.com\>
 */
RCSID("$Id$")
#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/unlang/module.h>

#include "base.h"
#include "state_machine.h"
#include "attrs.h"

#ifndef EAP_TLS_MPPE_KEY_LEN
#  define EAP_TLS_MPPE_KEY_LEN     32
#endif

/** A state transition function
 *
 * This is passed to sub-state machines that perform other actions, before
 * fully transitioning to a new state.
 *
 * Examples of these are the sub-state machines that deal with clearing
 * pseudonyms and reauthentication data.
 */
typedef rlm_rcode_t(*aka_sim_state_enter_t)(eap_aka_sim_common_conf_t *inst,
					    REQUEST *request, eap_session_t *eap_session);

static rlm_rcode_t common_eap_failure(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_failure_notification(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_eap_success(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_success_notification(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t common_reauthentication(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t aka_challenge(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t sim_challenge(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t aka_identity(void *instance, void *thread, REQUEST *request);
static rlm_rcode_t sim_start(void *instance, void *thread, REQUEST *request);

static rlm_rcode_t common_failure_notification_enter(eap_aka_sim_common_conf_t *inst,
						     REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t aka_challenge_enter(eap_aka_sim_common_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t sim_challenge_enter(eap_aka_sim_common_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t common_challenge_enter(eap_aka_sim_common_conf_t *inst,
					  REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t aka_identity_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t sim_start_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request, eap_session_t *eap_session);
static rlm_rcode_t common_identity_enter(eap_aka_sim_common_conf_t *inst,
				         REQUEST *request, eap_session_t *eap_session);

static module_state_func_table_t const aka_sim_stable_table[] = {
	{ "FAILURE-NOTIFICATION",	common_failure_notification	},
	{ "EAP-FAILURE",		common_eap_failure		},
	{ "SUCCESS-NOTIFICATION",	common_success_notification 	},
	{ "EAP-SUCCESS",		common_eap_success		},
	{ "REAUTHENTICATION",		common_reauthentication		},
	{ "AKA-CHALLENGE",		aka_challenge			},
	{ "SIM-CHALLENGE",		sim_challenge			},
	{ "IDENTITY",			aka_identity			},
	{ "SIM-START",			sim_start			},
	{ "EAP-IDENTITY",		aka_sim_state_machine_start	},

	{ NULL }
};

/** Cancel a call to a submodule
 *
 * @param[in] instance	UNUSED.
 * @param[in] thread	UNUSED.
 * @param[in] request	The current request.
 * @param[in] rctx	the eap_session_t
 * @param[in] action	to perform.
 */
static void mod_signal(UNUSED void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx,
		       fr_state_signal_t action)
{
	eap_session_t	*eap_session = eap_session_get(request->parent);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Request cancelled - Destroying session");

	TALLOC_FREE(eap_session->opaque);
}

/** Warn the user that the rcode they provided is being ignored in this section
 *
 */
static inline void section_rcode_ignored(REQUEST *request)
{
	switch (request->rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		RWDEBUG("Ignoring rcode (%s)",
			fr_table_str_by_value(mod_rcode_table, request->rcode, "<invalid>"));
		break;

	default:
		break;
	}
}

/** Trigger a state transition to FAILURE-NOTIFICATION if the section returned a failure code
 *
 */
#define section_rcode_process(_inst, _request, _eap_session, _eap_aka_sim_session) \
{ \
	if (after_authentication(_eap_aka_sim_session)) { \
		switch ((_request)->rcode) { \
		case RLM_MODULE_REJECT:	 \
		case RLM_MODULE_DISALLOW: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_TEMPORARILY_DENIED; \
			return common_failure_notification_enter(_inst, _request, _eap_session); \
		case RLM_MODULE_NOTFOUND: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_NOT_SUBSCRIBED; \
			return common_failure_notification_enter(_inst, _request, _eap_session); \
		case RLM_MODULE_INVALID: \
		case RLM_MODULE_FAIL: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_GENERAL_FAILURE_AFTER_AUTHENTICATION;\
			return common_failure_notification_enter(_inst, _request, _eap_session); \
		default: \
			break; \
		} \
	} else { \
		switch ((_request)->rcode) { \
		case RLM_MODULE_USER_SECTION_REJECT: \
			REDEBUG("Section rcode (%s) indicates we should reject the user", \
		        	fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>")); \
			return common_failure_notification_enter(_inst, _request, _eap_session); \
		default: \
			break; \
		} \
	} \
}

/** Sync up what identity we're requesting with attributes in the reply
 *
 */
static bool identity_req_set_by_user(REQUEST *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	VALUE_PAIR 	*vp;
	fr_cursor_t	cursor;
	bool		set_by_user = false;

	/*
	 *	Check if the user included any of the
	 *      ID req attributes.  If they did, use
	 *	them to inform what we do next, and
	 *	then delete them so they don't screw
	 *	up any of the other code.
	 */
	for (vp = fr_cursor_init(&cursor, &request->reply->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da == attr_eap_aka_sim_permanent_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
		found:
			set_by_user = true;
			RDEBUG2("Previous section added &reply:%pP, will request additional identity", vp);
			fr_cursor_free_item(&cursor);
		}
		else if (vp->da == attr_eap_aka_sim_fullauth_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			goto found;
		}
		else if (vp->da == attr_eap_aka_sim_any_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_ANY_ID_REQ;
			goto found;
		}
	}

	return set_by_user;
}

/** Based on the hint byte in the identity, add &Identity-Type and &Method-Hint attributes
 *
 */
static void identity_hint_pairs_add(fr_aka_sim_id_type_t *type_p, fr_aka_sim_method_hint_t *method_p,
				    REQUEST *request, char const *identity)
{
	fr_aka_sim_id_type_t		type;
	fr_aka_sim_method_hint_t	method;

	/*
	 *	Process the identity that we received.
	 */
	if (fr_aka_sim_id_type(&type, &method,
			   identity, talloc_array_length(identity) - 1) < 0) {
		RPWDEBUG2("Failed parsing identity, continuing anyway");
	}

	/*
	 *	Map the output from the generic ID parser
	 *	function to specific EAP-AKA internal
	 *	attributes in the subrequest.
	 */
	if (type != AKA_SIM_ID_TYPE_UNKNOWN) {
		VALUE_PAIR *vp = NULL;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_identity_type) >= 0);
		switch (type) {
		case AKA_SIM_ID_TYPE_PERMANENT:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_PERMANENT;
			break;

		case AKA_SIM_ID_TYPE_PSEUDONYM:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_PSEUDONYM;
			break;

		case AKA_SIM_ID_TYPE_FASTAUTH:
			vp->vp_uint32 = FR_IDENTITY_TYPE_VALUE_FASTAUTH;
			break;

		default:
			rad_assert(0);
		}
	}

	/*
	 *	Map the output from the generic ID parser
	 *	function to specific EAP-AKA internal
	 *	attributes in the subrequest.
	 */
	if (method != AKA_SIM_METHOD_HINT_UNKNOWN) {
		VALUE_PAIR *vp = NULL;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_method_hint) >= 0);
		switch (method) {
		case AKA_SIM_METHOD_HINT_AKA_PRIME:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_AKA_PRIME;
			break;

		case AKA_SIM_METHOD_HINT_AKA:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_AKA;
			break;

		case AKA_SIM_METHOD_HINT_SIM:
			vp->vp_uint32 = FR_METHOD_HINT_VALUE_SIM;
			break;

		default:
			rad_assert(0);
		}
	}

	if (type_p) *type_p = type;
	if (method_p) *method_p = method;
}

/** Print out the error the client returned
 *
 */
static inline void client_error_debug(REQUEST *request, VALUE_PAIR *from_peer)
{
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_client_error_code, TAG_ANY);
	if (!vp) {
		REDEBUG("Peer has not supplied a AT_ERROR_CODE");
	} else {
		REDEBUG("Peer rejected request with error: %i (%pV)", vp->vp_uint16, &vp->data);
	}
}

/** Add an Identity Request attribute to the reply
 *
 * Verify the progression of identity requests is valid.
 *
 * @param[in] request			The current request.
 * @param[in] eap_aka_sim_session	The current eap_aka_sim_session.
 * @return
 *	- 0 on success.
 *	- -1 on failure (progression of identities was not valid).
 */
static int identity_req_pairs_add(REQUEST *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	VALUE_PAIR *vp;

	switch (eap_aka_sim_session->id_req) {
	case AKA_SIM_ANY_ID_REQ:
		if (eap_aka_sim_session->last_id_req != AKA_SIM_NO_ID_REQ) {
		id_out_of_order:
			REDEBUG("Cannot send %s, already sent %s",
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->last_id_req, "<INVALID>"));
			return -1;
		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_any_id_req) >= 0);
		vp->vp_bool = true;
		break;

	case AKA_SIM_FULLAUTH_ID_REQ:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:		/* Not sent anything before */
		case AKA_SIM_ANY_ID_REQ:	/* Last request was for any ID, but the re-auth ID was bad */
			break;

		default:
			goto id_out_of_order;
		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_fullauth_id_req) >= 0);
		vp->vp_bool = true;
		break;

	case AKA_SIM_PERMANENT_ID_REQ:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:		/* Not sent anything before */
		case AKA_SIM_ANY_ID_REQ:	/* Last request was for any ID, but the re-auth ID was bad */
		case AKA_SIM_FULLAUTH_ID_REQ:	/* ...didn't understand the pseudonym either */
			break;

		default:
			goto id_out_of_order;
		}
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_permanent_id_req) >= 0);
		vp->vp_bool = true;
		break;

	default:
		rad_assert(0);
	}

	return 0;
}

/** Copy the incoming identity to the permanent identity attribute
 *
 * If the incoming ID really looks like a permanent ID, and we were
 * told it was a permanent ID, then (optionally) trim the first byte
 * to form the real permanent ID.
 *
 * Otherwise copy the entire incoming Identity to the
 * &session-state:Permanent-Identity attribute.
 *
 * @param[in] request		The current request.
 * @param[in] in		current identity.
 * @param[in] eap_type		The current eap_type.
 * @param[in] strip_hint	Whether to strip the hint byte off the permanent identity
 */
static int identity_to_permanent_identity(REQUEST *request, VALUE_PAIR *in, eap_type_t eap_type, bool strip_hint)
{
	fr_aka_sim_id_type_t		our_type;
	fr_aka_sim_method_hint_t	our_method, expected_method;
	VALUE_PAIR			*vp;

	if (in->vp_length == 0) {
		RDEBUG2("Not processing zero length identity");
		return -1;
	}

	/*
	 *	Not requested to strip hint, don't do anything
	 *	fancy, just copy Identity -> Permanent-Identity.
	 */
	if (!strip_hint) {
		MEM(fr_pair_update_by_da(request->state_ctx, &vp,
					 &request->state, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrncpy(vp, in->vp_strvalue, in->vp_length);
		return 0;
	}

	switch (eap_type) {
	case FR_EAP_METHOD_SIM:
		expected_method = AKA_SIM_METHOD_HINT_SIM;
		break;

	case FR_EAP_METHOD_AKA:
		expected_method = AKA_SIM_METHOD_HINT_AKA;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		expected_method = AKA_SIM_METHOD_HINT_AKA_PRIME;
		break;

	default:
		return -1;
	}

	/*
	 *	First, lets see if this looks like an identity
	 *	we can process.
	 *
	 *	For now we allow all permanent identities no
	 *	matter what EAP method.
	 *
	 *	This is because we could be starting a different
	 *	EAP method to the one the identity hinted,
	 *	but we still want to strip the first byte.
	 */
	if ((fr_aka_sim_id_type(&our_type, &our_method, in->vp_strvalue, in->vp_length) < 0) ||
	    (our_type != AKA_SIM_ID_TYPE_PERMANENT)) {
		MEM(fr_pair_update_by_da(request->state_ctx, &vp,
					 &request->state, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrncpy(vp, in->vp_strvalue, in->vp_length);

		RDEBUG2("%s has incorrect hint byte, expected '%c', got '%c'.  "
			"'hint' byte not stripped",
			attr_eap_aka_sim_permanent_identity->name,
			fr_aka_sim_hint_byte(AKA_SIM_ID_TYPE_PERMANENT, expected_method),
			fr_aka_sim_hint_byte(our_type, our_method));
		RINDENT();
		RDEBUG2("&session-state:%pP", vp);
		REXDENT();
	} else {
		/*
		 *	To get here the identity must be >= 1 and must have
		 *      had the expected hint byte.
		 *
		 *	Strip off the hint byte, and then add the permanent
		 *	identity to the output list.
		 */
		MEM(fr_pair_update_by_da(request->state_ctx, &vp,
					 &request->state, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrncpy(vp, in->vp_strvalue + 1, in->vp_length - 1);

		RDEBUG2("Stripping 'hint' byte from %s", attr_eap_aka_sim_permanent_identity->name);
		RINDENT();
		RDEBUG2("&session-state:%pP", vp);
		REXDENT();
	}

	return 0;
}

/** Set the crypto identity from a received identity
 *
 */
static void identity_to_crypto_identity(REQUEST *request, eap_aka_sim_session_t *eap_aka_sim_session,
					uint8_t const *identity, size_t len)
{
	RDEBUG3("Setting cryptographic identity to \"%pV\"", fr_box_strvalue_len((char const *)identity, len));

	talloc_free(eap_aka_sim_session->keys.identity);
	eap_aka_sim_session->keys.identity_len = len;
	MEM(eap_aka_sim_session->keys.identity = talloc_memdup(eap_aka_sim_session, identity, len));
}

/** Determine if we're after authentication
 *
 */
static inline bool after_authentication(eap_aka_sim_session_t *eap_aka_sim_session)
{
	return eap_aka_sim_session->challenge_success || eap_aka_sim_session->reauthentication_success;
}

/** Resume after 'store session { ... }'
 *
 */
static rlm_rcode_t session_store_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	switch (request->rcode) {
	/*
	 *	Store failed.  Don't send fastauth id
	 */
	case RLM_MODULE_USER_SECTION_REJECT:
		pair_delete_reply(attr_eap_aka_sim_next_reauth_id);
		break;

	default:
		break;
	}

	pair_delete_request(attr_eap_aka_sim_next_reauth_id);

	return state_enter(instance, request, eap_session_get(request->parent));
}

/** Resume after 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t pseudonym_store_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;
	VALUE_PAIR		*vp;
	VALUE_PAIR		*new;

	switch (request->rcode) {
	/*
	 *	Store failed.  Don't send pseudonym
	 */
	case RLM_MODULE_USER_SECTION_REJECT:
		pair_delete_reply(attr_eap_aka_sim_next_pseudonym);
		break;

	default:
		break;
	}

	request->rcode = RLM_MODULE_NOOP;	/* Needed because we may call resume functions directly */

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_next_reauth_id, TAG_ANY);
	if (vp) {
		/*
		 *	Generate a random fastauth string
		 */
		if (vp->vp_length == 0) {
			char *identity;

			if (!inst->ephemeral_id_length) {
				RWDEBUG("Found empty Next-Reauth-Id, and told not to generate one.  "
					"Skipping store session { ... } section");

				goto done;
			}

			MEM(identity = talloc_array(vp, char, inst->ephemeral_id_length + 2));
			switch (eap_aka_sim_session->type) {
			case FR_EAP_METHOD_SIM:
				identity[0] = (char)ID_TAG_SIM_FASTAUTH;
				break;

			case FR_EAP_METHOD_AKA:
			 	identity[0] = (char)ID_TAG_AKA_FASTAUTH;
				break;

			case FR_EAP_METHOD_AKA_PRIME:
				identity[0] = (char)ID_TAG_AKA_PRIME_FASTAUTH;
				break;

			default:
				break;
			}
			fr_rand_str((uint8_t *)identity + 1, inst->ephemeral_id_length, 'a');
			identity[talloc_array_length(identity) - 1] = '\0';

			fr_value_box_strdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_session_id);
		fr_pair_value_memcpy(new, (uint8_t const *)vp->vp_strvalue, vp->vp_length, vp->vp_tainted);

		MEM(eap_aka_sim_session->fastauth_sent = talloc_bstrndup(eap_aka_sim_session,
									 vp->vp_strvalue, vp->vp_length));

		switch (eap_aka_sim_session->type) {
		/*
		 *	AKA and SIM use the original MK for session resumption.
		 */
		case FR_EAP_METHOD_SIM:
		case FR_EAP_METHOD_AKA:
			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.mk,
					     sizeof(eap_aka_sim_session->keys.mk), false);
			break;
		/*
		 *	AKA' KDF 1 generates an additional key k_re
		 *	which is used for reauthentication instead
		 *	of the MK.
		 */
		case FR_EAP_METHOD_AKA_PRIME:
			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.k_re,
					     sizeof(eap_aka_sim_session->keys.k_re), false);
			break;

		default:
			rad_assert(0);
			break;
		}

		/*
		 *	If the counter already exists in session
		 *	state increment by 1, otherwise, add the
		 *	attribute and set to zero.
		 */
		vp = fr_pair_find_by_da(request->state, attr_eap_aka_sim_counter, TAG_ANY);
		if (vp) {
			vp->vp_uint16++;
		/*
		 *	Will get incremented by 1 in
		 *	reauthentication_send, so when
		 *	used, it'll be 1 (as per the standard).
		 */
		} else {
			MEM(pair_add_session_state(&vp, attr_eap_aka_sim_counter) >= 0);
			vp->vp_uint16 = 0;
		}

		return unlang_module_yield_to_section(request,
						      inst->actions.store_session,
						      RLM_MODULE_NOOP,
						      session_store_resume,
						      mod_signal,
						      rctx);
	}

done:
	return state_enter(inst, request, eap_session_get(request->parent));
}

/** Implements a set of states for storing pseudonym and fastauth identities
 *
 * At the end of challenge or reauthentication rounds, the user may have specified
 * a pseudonym and fastauth identity to return to the supplicant.
 *
 * Call the appropriate sections to persist those values.
 *
 * @param[in] inst		of rlm_eap_aka.
 * @param[in] request		the current request.
 * @param[in] state_enter	state entry function for the
 *				state to transition to *after* the current
 *				state.
 * @return RLM_MODULE_HANDLED.
 */
static rlm_rcode_t session_and_pseudonym_store(eap_aka_sim_common_conf_t *inst,
					       REQUEST *request, eap_session_t *eap_session,
					       aka_sim_state_enter_t state_enter)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	VALUE_PAIR		*vp;
	VALUE_PAIR		*new;

	request->rcode = RLM_MODULE_NOOP;	/* Needed because we may call resume functions directly */

	vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_next_pseudonym, TAG_ANY);
	if (vp) {
		/*
		 *	Generate a random pseudonym string
		 */
		if (vp->vp_length == 0) {
			char *identity;

			if (!inst->ephemeral_id_length) {
				RWDEBUG("Found empty Pseudonym-Id, and told not to generate one.  "
					"Skipping store pseudonym { ... } section");

				return pseudonym_store_resume(inst,
							      module_thread_by_data(inst),
							      request, (void *)state_enter);
			}

			MEM(identity = talloc_array(vp, char, inst->ephemeral_id_length + 2));
			fr_rand_str((uint8_t *)identity + 1, inst->ephemeral_id_length, 'a');
			switch (eap_aka_sim_session->type) {
			case FR_EAP_METHOD_SIM:
				identity[0] = (char)ID_TAG_SIM_PSEUDONYM;
				break;

			case FR_EAP_METHOD_AKA:
			 	identity[0] = (char)ID_TAG_AKA_PSEUDONYM;
				break;

			case FR_EAP_METHOD_AKA_PRIME:
				identity[0] = (char)ID_TAG_AKA_PRIME_PSEUDONYM;
				break;

			default:
				break;
			}
			identity[talloc_array_length(identity) - 1] = '\0';
			fr_value_box_strdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_eap_aka_sim_next_pseudonym);
		fr_pair_value_copy(new, vp);

		MEM(eap_aka_sim_session->pseudonym_sent = talloc_bstrndup(eap_aka_sim_session,
									  vp->vp_strvalue, vp->vp_length));

		return unlang_module_yield_to_section(request,
						      inst->actions.store_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_store_resume,
						      mod_signal,
						      (void *)state_enter);
	}

	return pseudonym_store_resume(inst, module_thread_by_data(inst), request, (void *)state_enter);
}

/** Resume after 'clear session { ... }'
 *
 */
static rlm_rcode_t session_clear_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	pair_delete_request(attr_session_id);

	return state_enter(instance, request, eap_session_get(request->parent));
}

/** Resume after 'clear pseudonym { ... }'
 *
 */
static rlm_rcode_t pseudonym_clear_resume(void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	/*
	 *	Clear session
	 */
	if (eap_aka_sim_session->fastauth_sent) {
		VALUE_PAIR *vp;

		pair_delete_request(attr_session_id);

		MEM(pair_update_request(&vp, attr_session_id) >= 0);
		fr_value_box_memcpy(vp, &vp->data, NULL,
				    (uint8_t *)eap_aka_sim_session->fastauth_sent,
				    talloc_array_length(eap_aka_sim_session->fastauth_sent) - 1, true);
		TALLOC_FREE(eap_aka_sim_session->fastauth_sent);

		return unlang_module_yield_to_section(request,
						      inst->actions.clear_session,
						      RLM_MODULE_NOOP,
						      session_clear_resume,
						      mod_signal,
						      rctx);
	}

	return state_enter(inst, request, eap_session_get(request->parent));
}

/** Implements a set of states for clearing out pseudonym and fastauth identities
 *
 * If either a Challenge round or Reauthentication round fail, we need to clear
 * any identities that were provided during those rounds, as the supplicant
 * will have discarded them.
 *
 * @param[in] inst		of rlm_eap_aka.
 * @param[in] request		the current request.
 * @param[in] state_enter	state entry function for the
 *				state to transition to *after* the current
 *				state.
 * @return RLM_MODULE_HANDLED.
 */
static rlm_rcode_t session_and_pseudonym_clear(eap_aka_sim_common_conf_t *inst,
					       REQUEST *request, eap_session_t *eap_session,
					       aka_sim_state_enter_t state_enter)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	/*
	 *	Clear out pseudonyms
	 */
	if (eap_aka_sim_session->pseudonym_sent) {
		VALUE_PAIR *vp;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_next_pseudonym) >= 0);
		fr_value_box_strdup_buffer(vp, &vp->data, NULL, eap_aka_sim_session->pseudonym_sent, true);
		TALLOC_FREE(eap_aka_sim_session->pseudonym_sent);

		return unlang_module_yield_to_section(request,
						      inst->actions.clear_pseudonym,
						      RLM_MODULE_NOOP,
						      session_clear_resume,
						      mod_signal,
						      (void *)state_enter);
	}

	return pseudonym_clear_resume(inst, module_thread_by_data(inst), request, (void *)state_enter);
}

/** Encode EAP-SIM/AKA['] attributes
 *
 */
static int common_encode(REQUEST *request, eap_session_t *eap_session, uint16_t subtype,
			 uint8_t const *hmac_extra, size_t hmac_extra_len)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	fr_cursor_t		cursor;
	fr_cursor_t		to_encode;
	VALUE_PAIR		*head = NULL, *vp, *subtype_vp;
	ssize_t			ret;
	fr_aka_sim_encode_ctx_t	encoder_ctx = {
					.root = fr_dict_root(dict_eap_aka_sim),
					.keys = &eap_aka_sim_session->keys,

					.iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					.iv_included = false,

					.hmac_md = eap_aka_sim_session->mac_md,
					.eap_packet = eap_session->this_round->request,
					.hmac_extra = hmac_extra,
					.hmac_extra_len = hmac_extra_len
				};

	/*
	 *	Set the subtype to identity request
	 */
	MEM(pair_update_reply(&subtype_vp, attr_eap_aka_sim_subtype) >= 0);
	subtype_vp->vp_uint16 = subtype;

	/*
	 *	State what kind of request we're sending
	 */
	if (RDEBUG_ENABLED2) {
		switch (subtype) {
		case FR_SUBTYPE_VALUE_SIM_START:
		case FR_SUBTYPE_VALUE_AKA_IDENTITY:
			RDEBUG2("Sending EAP-Request/%pV (%s)", &subtype_vp->data,
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
			break;

		default:
			RDEBUG2("Sending EAP-Request/%pV", &subtype_vp->data);
			break;
		}
	}

	fr_cursor_init(&cursor, &request->reply->vps);
	fr_cursor_init(&to_encode, &head);

	/*
	 *	We have to be *SUPER* careful here not to reorder
	 *	attributes, because for EAP-SIM the RAND values
	 *	must be inserted into the packet in exactly the
	 *	same order as they appear in fr_sim_keys_t
	 *	otherwise the KDF will produce a different
	 *	result.
	 */
	while ((vp = fr_cursor_current(&cursor))) {
		if (!fr_dict_parent_common(encoder_ctx.root, vp->da, true)) {
			fr_cursor_next(&cursor);
			continue;
		}
		vp = fr_cursor_remove(&cursor);

		/*
		 *	Silently discard encrypted attributes until
		 *	the peer should have k_encr.  These can be
		 *	added by policy, and seem to cause
		 *	wpa_supplicant to fail if sent before the challenge.
		 */
		if (!eap_aka_sim_session->allow_encrypted &&
		    fr_dict_parent_common(attr_eap_aka_sim_encr_data, vp->da, true)) {
			RWDEBUG("Silently discarding &reply:%s: Encrypted attributes not allowed in this round",
				vp->da->name);
			talloc_free(vp);
			continue;
		}

		fr_cursor_prepend(&to_encode, vp);
	}


	RDEBUG2("Encoding attributes");
	log_request_pair_list(L_DBG_LVL_2, request, head, NULL);

	eap_session->this_round->request->type.num = eap_aka_sim_session->type;
	eap_session->this_round->request->id = eap_aka_sim_session->id++ & 0xff;
	eap_session->this_round->set_request_id = true;

	ret = fr_aka_sim_encode(request, head, &encoder_ctx);
	fr_cursor_head(&to_encode);
	fr_cursor_free_list(&to_encode);

	if (ret < 0) {
		RPEDEBUG("Failed encoding attributes");
		return -1;
	}
	return 0;
}

/** Send a EAP-Failure message to the supplicant
 *
 */
static rlm_rcode_t common_eap_failure_send(REQUEST *request, eap_session_t *eap_session)
{
	RDEBUG2("Sending EAP-Failure");

	eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
	eap_session->finished = true;

	return RLM_MODULE_REJECT;
}

/** Send a EAP-Request/(AKA|SIM)-Notification (Failure) message to the supplicant
 *
 */
static rlm_rcode_t common_failure_notification_send(eap_aka_sim_common_conf_t *inst,
						    REQUEST *request, eap_session_t *eap_session)
{
	VALUE_PAIR		*vp, *notification_vp;
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	/*
	 *	Allow the user to specify specific failure notification
	 *	types.  We assume the user knows what they're doing and
	 *	only toggle success and phase bits.
	 *
	 *	This allows custom notification schemes to be implemented.
	 *
	 *	If this is prior to authentication, valid values are:
	 *	- FR_NOTIFICATION_VALUE_GENERAL_FAILURE
	 *
	 *	If this is after authentication, valid values are:
	 *	- FR_NOTIFICATION_VALUE_GENERAL_FAILURE_AFTER_AUTHENTICATION
	 *	- FR_NOTIFICATION_VALUE_TEMPORARILY_DENIED - User has been
	 *	  temporarily denied access to the requested service.
	 *	- FR_NOTIFICATION_VALUE_NOT_SUBSCRIBED
	 *	  User has not subscribed to the requested service.
	 */
	notification_vp = fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_notification, TAG_ANY);

	/*
	 *	Change the failure notification depending where
	 *	we are in the eap_aka_state machine.
	 */
	if (after_authentication(eap_aka_sim_session)) {
		if (!notification_vp) {
			pair_add_reply(&notification_vp, attr_eap_aka_sim_notification);
			notification_vp->vp_uint16 = eap_aka_sim_session->failure_type; /* Default will be zero */
		}

		notification_vp->vp_uint16 &= ~0x4000;	/* Unset phase bit */

		/*
		 *	Include the counter attribute if we're failing
		 *	after a reauthentication success.
		 *
		 *	RFC 4187 Section #9.10
		 *
		 *	If EAP-Request/AKA-Notification is used on
		 *	a fast re-authentication exchange, and if
		 *	the P bit in AT_NOTIFICATION is set to zero,
		 *	then AT_COUNTER is used for replay protection.
		 *	In this case, the AT_ENCR_DATA and AT_IV
		 *	attributes MUST be included, and the
		 *	encapsulated plaintext attributes MUST include
		 *	the AT_COUNTER attribute.  The counter value
		 *	included in AT_COUNTER MUST be the same
   		 *	as in the EAP-Request/AKA-Reauthentication
   		 *	packet on the same fast re-authentication
   		 *	exchange.
		 *
		 *	If the counter is used it should never be zero,
		 *	as it's incremented on first reauthentication
		 *	request.
		 */
		if (eap_aka_sim_session->reauthentication_success) {
			MEM(pair_update_reply(&notification_vp, attr_eap_aka_sim_counter) >= 0);
			notification_vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;
		}

		/*
		 *	If we're after the challenge phase
		 *	then we need to include a MAC to
		 *	protect notifications.
		 */
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
		fr_pair_value_memcpy(vp, NULL, 0, false);
	} else {
		/*
		 *	Only valid code is general failure
		 */
		if (!notification_vp) {
			pair_add_reply(&notification_vp, attr_eap_aka_sim_notification);
			notification_vp->vp_uint16 = FR_NOTIFICATION_VALUE_GENERAL_FAILURE;
		/*
		 *	User supplied failure code
		 */
		} else {
			notification_vp->vp_uint16 |= 0x4000;	/* Set phase bit */
		}
	}
	notification_vp->vp_uint16 &= ~0x8000;		/* In both cases success bit should be low */

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Encode the packet
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION, NULL, 0) < 0) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	return RLM_MODULE_HANDLED;
}

/** Add MPPE keys to the request being sent to the supplicant
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * attributes derived from the MSK.
 */
static rlm_rcode_t common_eap_success_send(REQUEST *request, eap_session_t *eap_session)
{
	uint8_t			*p;
	eap_aka_sim_session_t	*eap_aka_sim_session;

	RDEBUG2("Sending EAP-Success");

	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	RDEBUG2("Adding attributes for MSK");
	p = eap_aka_sim_session->keys.msk;
	eap_add_reply(request->parent, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(request->parent, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	return RLM_MODULE_OK;
}

/** Send a EAP-Request/(AKA|SIM)-Notification (Success) message to the supplicant
 *
 */
static rlm_rcode_t common_success_notification_send(eap_aka_sim_common_conf_t *inst,
						    REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	if (!fr_cond_assert(after_authentication(eap_aka_sim_session))) return RLM_MODULE_FAIL;

	/*
	 *	If we're in this state success bit is
	 *	high phase bit is low.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_notification) >= 0);
	vp->vp_uint16 = FR_NOTIFICATION_VALUE_SUCCESS;

	/*
	 *	RFC 4187 section #9.10
	 *
	 *	If EAP-Request/AKA-Notification is used on
	 *	a fast re-authentication exchange, and if
	 *	the P bit in AT_NOTIFICATION is set to zero,
	 *	then AT_COUNTER is used for replay protection.
	 *	In this case, the AT_ENCR_DATA and AT_IV
	 *	attributes MUST be included, and the
	 *	encapsulated plaintext attributes MUST include
	 *	the AT_COUNTER attribute.  The counter value
	 *	included in AT_COUNTER MUST be the same
	 *	as in the EAP-Request/AKA-Reauthentication
	 *	packet on the same fast re-authentication
	 *	exchange.
	 *
	 *	If the counter is used it should never be zero,
	 *	as it's incremented on first reauthentication
	 *	request.
	 */
	if (eap_aka_sim_session->keys.reauth.counter > 0) {
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_counter) >= 0);
		vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;
	}

	/*
	 *	Need to include an AT_MAC attribute so that
	 *	it will get calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	Encode the packet
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION, NULL, 0) < 0) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	return RLM_MODULE_HANDLED;
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t common_reauthentication_request_send(eap_aka_sim_common_conf_t *inst,
							REQUEST *request, eap_session_t *eap_session)
{
	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_AKA_SIM_REAUTHENTICATION, NULL, 0) < 0) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	return RLM_MODULE_HANDLED;
}

/** Send a EAP-Request/(AKA|SIM)-Reauthenticate message to the supplicant
 *
 */
static rlm_rcode_t common_reauthentication_request_compose(eap_aka_sim_common_conf_t *inst, REQUEST *request,
							   eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	VALUE_PAIR		*to_peer = request->reply->vps, *vp;

	VALUE_PAIR		*kdf_id;

	/*
	 *	Allow override of KDF Identity
	 *
	 *	Because certain handset manufacturers don't
	 *	implement RFC 4187 correctly and use the
	 *	wrong identity as input the the PRF/KDF.
	 *
	 *	Not seen any doing this for re-authentication
	 *	but you never know...
	 */
	kdf_id = fr_pair_find_by_da(request->control, attr_eap_aka_sim_kdf_identity, TAG_ANY);
	if (kdf_id) {
		identity_to_crypto_identity(request, eap_aka_sim_session,
					    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Generating new session keys");

	switch (eap_aka_sim_session->type) {
	/*
	 *	The GSM and UMTS KDF_0 mutate their keys using
	 *	and identical algorithm.
	 */
	case FR_EAP_METHOD_SIM:
	case FR_EAP_METHOD_AKA:
		if (fr_aka_sim_vector_gsm_umts_kdf_0_reauth_from_attrs(request, request->state,
								       &eap_aka_sim_session->keys) != 0) {
		request_new_id:
			switch (eap_aka_sim_session->last_id_req) {
			/*
			 *	Got here processing EAP-Identity-Response
			 *	If this is the *true* reauth ID, then
			 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
			 */
			case AKA_SIM_NO_ID_REQ:
			case AKA_SIM_ANY_ID_REQ:
				RDEBUG2("Composing EAP-Request/Reauthentication failed.  Clearing reply attributes and "
					"requesting additional Identity");
				fr_pair_list_free(&request->reply->vps);
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				return common_identity_enter(inst, request, eap_session);

			case AKA_SIM_FULLAUTH_ID_REQ:
			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Last requested fullauth or permanent ID, "
					"but received, or were told we received (by policy), "
					"a fastauth ID.  Cannot continue");
			failure:
				return common_failure_notification_enter(inst, request, eap_session);
			}
		}
		if (fr_aka_sim_crypto_kdf_0_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		switch (eap_aka_sim_session->kdf) {
		case FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME:
			if (fr_aka_sim_vector_umts_kdf_1_reauth_from_attrs(request, request->state,
									   &eap_aka_sim_session->keys) != 0) {
				goto request_new_id;
			}
			if (fr_aka_sim_crypto_umts_kdf_1_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
			break;

		default:
			rad_assert(0);
			break;
		}
		break;

	default:
		rad_assert(0);
		break;
	}

	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	/*
	 *	Add AT_IV, AT_COUNTER, AT_NONCE_S, and AT_MAC to to reply
	 *      The user may have added AT_NEXT_REAUTH_ID, in which case
	 *	we'll have sent that too.
	 */
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_result_ind, TAG_ANY);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	RFC 5448 says AT_BIDDING is only sent in the challenge
	 *	not in reauthentication, so don't add that here.
	 */

	 /*
	  *	Add AT_NONCE_S
	  */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_nonce_s) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.reauth.nonce_s,
			     sizeof(eap_aka_sim_session->keys.reauth.nonce_s), false);

	/*
	 *	Add AT_COUNTER
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_counter) >= 0);
	vp->vp_uint16 = eap_aka_sim_session->keys.reauth.counter;

	/*
	 *	need to include an empty AT_MAC attribute so that
	 *	the mac will get calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	If there's no checkcode_md we're not doing
	 *	checkcodes.
	 */
	if (eap_aka_sim_session->checkcode_md) {
		/*
		 *	If we have checkcode data, send that to the peer
		 *	in AT_CHECKCODE for validation.
		 */
		if (eap_aka_sim_session->checkcode_state) {
			ssize_t	slen;

			slen = fr_aka_sim_crypto_finalise_checkcode(eap_aka_sim_session->checkcode,
								    &eap_aka_sim_session->checkcode_state);
			if (slen < 0) {
				RPEDEBUG("Failed calculating checkcode");
				goto failure;
			}
			eap_aka_sim_session->checkcode_len = slen;

			MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->checkcode, slen, false);
		/*
		 *	If we don't have checkcode data, then we exchanged
		 *	no identity packets, so checkcode is zero.
		 */
		} else {
			MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
			fr_pair_value_memcpy(vp, NULL, 0, false);
			eap_aka_sim_session->checkcode_len = 0;
		}
	}

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(inst, request, eap_session, common_reauthentication_request_send);
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t aka_challenge_request_send(eap_aka_sim_common_conf_t *inst,
					      REQUEST *request, eap_session_t *eap_session)
{
	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_AKA_CHALLENGE, NULL, 0) < 0) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	return RLM_MODULE_HANDLED;
}

/** Send a EAP-Request/AKA-Challenge message to the supplicant
 *
 */
static rlm_rcode_t aka_challenge_request_compose(eap_aka_sim_common_conf_t *inst,
						 REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*to_peer = request->reply->vps, *vp;
	fr_aka_sim_vector_src_t	src = AKA_SIM_VECTOR_SRC_AUTO;

	VALUE_PAIR		*kdf_id;

	/*
	 *	Allow override of KDF Identity
	 *
	 *	Because certain handset manufacturers don't
	 *	implement RFC 4187 correctly and use the
	 *	wrong identity as input the the PRF/KDF.
	 */
	kdf_id = fr_pair_find_by_da(request->control, attr_eap_aka_sim_kdf_identity, TAG_ANY);
	if (kdf_id) {
		identity_to_crypto_identity(request, eap_aka_sim_session,
					    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Acquiring UMTS vector(s)");

	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA_PRIME) {
		/*
		 *	Copy the network name the user specified for
		 *	key derivation purposes.
		 */
		vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_kdf_input, TAG_ANY);
		if (vp) {
			talloc_free(eap_aka_sim_session->keys.network);
			eap_aka_sim_session->keys.network = talloc_memdup(eap_aka_sim_session,
									  (uint8_t const *)vp->vp_strvalue,
									  vp->vp_length);
			eap_aka_sim_session->keys.network_len = vp->vp_length;
		} else {
			REDEBUG("No network name available, can't set AT_KDF_INPUT");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);
		}

		/*
		 *	We don't allow the user to specify
		 *	the KDF currently.
		 */
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_kdf) >= 0);
		vp->vp_uint16 = eap_aka_sim_session->kdf;
	}

	/*
	 *	Get vectors from attribute or generate
	 *	them using COMP128-* or Milenage.
	 */
	if (fr_aka_sim_vector_umts_from_attrs(request, request->control, &eap_aka_sim_session->keys, &src) != 0) {
	    	REDEBUG("Failed retrieving UMTS vectors");
		goto failure;
	}

	/*
	 *	Don't leave the AMF hanging around
	 */
	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA_PRIME) pair_delete_control(attr_sim_amf);

	/*
	 *	All set, calculate keys!
	 */
	switch (eap_aka_sim_session->type) {
	default:
	case FR_EAP_METHOD_SIM:
		rad_assert(0);	/* EAP-SIM has its own Challenge state */
		break;

	case FR_EAP_METHOD_AKA:
		fr_aka_sim_crypto_umts_kdf_0(&eap_aka_sim_session->keys);
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		switch (eap_aka_sim_session->kdf) {
		case FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME:
			fr_aka_sim_crypto_umts_kdf_1(&eap_aka_sim_session->keys);
			break;

		default:
			rad_assert(0);
			break;
		}
	}
	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_result_ind, TAG_ANY);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	See if we're indicating we want EAP-AKA'
	 *	If so include AT_BIDDING with the correct
	 *	value.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_bidding, TAG_ANY);
	if (vp) {
		eap_aka_sim_session->send_at_bidding_prefer_prime =
			(vp->vp_uint16 == FR_BIDDING_VALUE_PREFER_AKA_PRIME);
	}

	/*
	 *	These attributes are only allowed with
	 *	EAP-AKA', protect users from themselves.
	 */
	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA) {
		pair_delete_reply(attr_eap_aka_sim_kdf_input);
		pair_delete_reply(attr_eap_aka_sim_kdf);
	}

	/*
	 *	Okay, we got the challenge! Put it into an attribute.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.umts.vector.rand, AKA_SIM_VECTOR_UMTS_RAND_SIZE, false);

	/*
	 *	Send the AUTN value to the client, so it can authenticate
	 *	whoever has knowledge of the Ki.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_autn) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.umts.vector.autn, AKA_SIM_VECTOR_UMTS_AUTN_SIZE, false);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	If we have checkcode data, send that to the peer
	 *	in AT_CHECKCODE for validation.
	 */
	if (eap_aka_sim_session->checkcode_state) {
		ssize_t	slen;

		slen = fr_aka_sim_crypto_finalise_checkcode(eap_aka_sim_session->checkcode,
							    &eap_aka_sim_session->checkcode_state);
		if (slen < 0) {
			RPEDEBUG("Failed calculating checkcode");
			goto failure;
		}
		eap_aka_sim_session->checkcode_len = slen;

		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, eap_aka_sim_session->checkcode, slen, false);
	/*
	 *	If we don't have checkcode data, then we exchanged
	 *	no identity packets, so AT_CHECKCODE is zero.
	 */
	} else {
		MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
		fr_pair_value_memcpy(vp, NULL, 0, false);
		eap_aka_sim_session->checkcode_len = 0;
	}

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(inst, request, eap_session, aka_challenge_request_send);
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static rlm_rcode_t sim_challenge_request_send(eap_aka_sim_common_conf_t *inst,
					      REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_SIM_CHALLENGE,
			  eap_aka_sim_session->keys.gsm.nonce_mt, sizeof(eap_aka_sim_session->keys.gsm.nonce_mt)) < 0) {
		return common_failure_notification_enter(inst, request, eap_session);
	}

	return RLM_MODULE_HANDLED;
}

/** Send a EAP-Request/SIM-Challenge message to the supplicant
 *
 */
static rlm_rcode_t sim_challenge_request_compose(eap_aka_sim_common_conf_t *inst,
						 REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	VALUE_PAIR		*to_peer = request->reply->vps, *vp;
	fr_aka_sim_vector_src_t	src = AKA_SIM_VECTOR_SRC_AUTO;

	VALUE_PAIR		*kdf_id;

	/*
	 *	Allow override of KDF Identity
	 *
	 *	Because certain handset manufacturers don't
	 *	implement RFC 4187 correctly and use the
	 *	wrong identity as input the the PRF/KDF.
	 */
	kdf_id = fr_pair_find_by_da(request->control, attr_eap_aka_sim_kdf_identity, TAG_ANY);
	if (kdf_id) {
		identity_to_crypto_identity(request, eap_aka_sim_session,
					    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Acquiring GSM vector(s)");
	if ((fr_aka_sim_vector_gsm_from_attrs(request, request->control, 0,
					      &eap_aka_sim_session->keys, &src) != 0) ||
	    (fr_aka_sim_vector_gsm_from_attrs(request, request->control, 1,
	    				      &eap_aka_sim_session->keys, &src) != 0) ||
	    (fr_aka_sim_vector_gsm_from_attrs(request, request->control, 2,
	    				      &eap_aka_sim_session->keys, &src) != 0)) {
	    	REDEBUG("Failed retrieving SIM vectors");
		return RLM_MODULE_FAIL;
	}

	fr_aka_sim_crypto_gsm_kdf_0(&eap_aka_sim_session->keys);

	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(to_peer, attr_eap_aka_sim_result_ind, TAG_ANY);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	Okay, we got the challenges! Put them into attributes.
	 */
	MEM(pair_add_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.gsm.vector[0].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	MEM(pair_add_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.gsm.vector[1].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	MEM(pair_add_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.gsm.vector[2].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memcpy(vp, NULL, 0, false);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(inst, request, eap_session, sim_challenge_request_send);
}

/** Send a EAP-Request/AKA-Identity message to the supplicant
 *
 * There are three types of user identities that can be implemented
 * - Permanent identities such as 0123456789098765@myoperator.com
 *   Permanent identities can be identified by the leading zero followed by
 *   by 15 digits (the IMSI number).
 * - Ephemeral identities (pseudonyms).  These are identities assigned for
 *   identity privacy so the user can't be tracked.  These can identities
 *   can either be generated as per the 3GPP 'Security aspects of non-3GPP accesses'
 *   document section 14, where a set of up to 16 encryption keys are used
 *   to reversibly encrypt the IMSI. Alternatively the pseudonym can be completely
 *   randomised and stored in a datastore.
 * - A fast resumption ID which resolves to data used for fast resumption.
 *
 * In order to perform full authentication the original IMSI is required for
 * forwarding to the HLR. In the case where we can't match/decrypt the pseudonym,
 * or can't perform fast resumption, we need to request the full identity from
 * the supplicant.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	to continue.
 * @return
 *	- RLM_MODULE_HANDLED on success.
 *	- anything else on failure.
 */
static rlm_rcode_t aka_identity_request_send(eap_aka_sim_common_conf_t *inst,
					     REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Update eap_aka_sim_session->id_req in case the the
	 *	user set attributes in `send Identity-Request { ... }`
	 *	Also removes all existing id_req attributes
	 *	from the reply.
	 */
	identity_req_set_by_user(request, eap_aka_sim_session);

	/*
	 *	Select the right type of identity request attribute
	 *
	 *      Implement checks on identity request order described
	 *	by RFC4187 section #4.1.5.
	 *
	 *	The internal state machine should always handle this
	 *	correctly, but the user may have other ideas...
	 */
	if (identity_req_pairs_add(request, eap_aka_sim_session) < 0) {
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	eap_aka_sim_session->last_id_req = eap_aka_sim_session->id_req;	/* Record what we last requested */

	/*
	 *	Encode the packet
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_AKA_IDENTITY, NULL, 0) < 0) goto failure;

	/*
	 *	Digest the packet contents, updating our checkcode.
	 */
	if (eap_aka_sim_session->checkcode_md) {
		if (!eap_aka_sim_session->checkcode_state &&
		    fr_aka_sim_crypto_init_checkcode(eap_aka_sim_session, &eap_aka_sim_session->checkcode_state,
						     eap_aka_sim_session->checkcode_md) < 0) {
			RPEDEBUG("Failed initialising checkcode");
			goto failure;
		}
		if (fr_aka_sim_crypto_update_checkcode(eap_aka_sim_session->checkcode_state,
						       eap_session->this_round->request) < 0) {
			RPEDEBUG("Failed updating checkcode");
			goto failure;
		}
	}

	return RLM_MODULE_HANDLED;
}

/** Send a EAP-Request/SIM-Start message to the supplicant
 *
 * There are three types of user identities that can be implemented
 * - Permanent identities such as 0123456789098765@myoperator.com
 *   Permanent identities can be identified by the leading zero followed by
 *   by 15 digits (the IMSI number).
 * - Ephemeral identities (pseudonyms).  These are identities assigned for
 *   identity privacy so the user can't be tracked.  These can identities
 *   can either be generated as per the 3GPP 'Security aspects of non-3GPP accesses'
 *   document section 14, where a set of up to 16 encryption keys are used
 *   to reversibly encrypt the IMSI. Alternatively the pseudonym can be completely
 *   randomised and stored in a datastore.
 * - A fast resumption ID which resolves to data used for fast resumption.
 *
 * In order to perform full authentication the original IMSI is required for
 * forwarding to the HLR. In the case where we can't match/decrypt the pseudonym,
 * or can't perform fast resumption, we need to request the full identity from
 * the supplicant.
 *
 * @param[in] request		The current subrequest.
 * @param[in] eap_session	to continue.
 * @return
 *	- RLM_MODULE_HANDLED on success.
 *	- anything else on failure.
 */
static rlm_rcode_t sim_start_request_send(eap_aka_sim_common_conf_t *inst,
					  REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	VALUE_PAIR		*vp;
	fr_cursor_t		cursor;
	uint8_t			*p, *end;

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	p = eap_aka_sim_session->keys.gsm.version_list;
	end = p + sizeof(eap_aka_sim_session->keys.gsm.version_list);
	eap_aka_sim_session->keys.gsm.version_list_len = 0;

	/*
	 *	If the user provided no versions, then
	 *      just add the default (1).
	 */
	if (!(fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_version_list, TAG_ANY))) {
		MEM(pair_add_reply(&vp, attr_eap_aka_sim_version_list) >= 0);
		vp->vp_uint16 = EAP_SIM_VERSION;
	}

	/*
	 *	Iterate over the the versions adding them
	 *      to the version list we use for keying.
	 */
	for (vp = fr_cursor_init(&cursor, &request->reply->vps); vp; vp = fr_cursor_next(&cursor)) {
		if (vp->da != attr_eap_aka_sim_version_list) continue;

		if ((end - p) < 2) break;

		/*
		 *	Store as big endian
		 */
		*p++ = (vp->vp_uint16 & 0xff00) >> 8;
		*p++ = (vp->vp_uint16 & 0x00ff);
		eap_aka_sim_session->keys.gsm.version_list_len += sizeof(uint16_t);
	}

	/*
	 *	Update eap_aka_sim_session->id_req in case the the
	 *	user set attributes in `send Identity-Request { ... }`
	 *	Also removes all existing id_req attributes
	 *	from the reply.
	 */
	identity_req_set_by_user(request, eap_aka_sim_session);

	/*
	 *	Select the right type of identity request attribute
	 *
	 *      Implement checks on identity request order described
	 *	by RFC4186 section #4.2.5.
	 *
	 *	The internal state machine should always handle this
	 *	correctly, but the user may have other ideas...
	 */
	if (identity_req_pairs_add(request, eap_aka_sim_session) < 0) {
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	eap_aka_sim_session->last_id_req = eap_aka_sim_session->id_req;	/* Record what we last requested */

	/*
	 *	Encode the packet
	 */
	if (common_encode(request, eap_session, FR_SUBTYPE_VALUE_SIM_START, NULL, 0) < 0) goto failure;

	return RLM_MODULE_HANDLED;
}

/** Print debugging information, and write new state to eap_session->process
 *
 */
static inline void state_transition(REQUEST *request, eap_session_t *eap_session,
					    module_method_t new_state)
{
	module_method_t		old_state = eap_session->process;

	if (new_state != old_state) {
		RDEBUG2("Changed state %s -> %s",
			module_state_method_to_str(aka_sim_stable_table, old_state, "<unknown>"),
			module_state_method_to_str(aka_sim_stable_table, new_state, "<unknown>"));
	} else {
		RDEBUG2("Reentering state %s",
			module_state_method_to_str(aka_sim_stable_table, old_state, "<unknown>"));
	}

	eap_session->process = new_state;
}

/** Resume after 'send EAP-Failure { ... }'
 *
 */
static rlm_rcode_t common_eap_failure_enter_resume(UNUSED void *instance, UNUSED void *thread,
						   REQUEST *request, UNUSED void *rctx)
{
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	return common_eap_failure_send(request, eap_session);
}

/** Enter EAP-FAILURE state
 *
 */
static rlm_rcode_t common_eap_failure_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t *eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst,
						   request, eap_session, common_eap_failure_enter); /* come back when we're done */
	}

	state_transition(request, eap_session, common_eap_failure);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_eap_failure,
					      RLM_MODULE_NOOP,
					      common_eap_failure_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Failure-Notification { ... }'
 *
 * Ignores return code from send Failure-Notification { ... } section.
 */
static rlm_rcode_t common_failure_notification_enter_resume(void *instance, UNUSED void *thread,
							    REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t	*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply->vps);

	/*
	 *	If there's an issue composing the failure
	 *      message just send an EAP-Failure instead.
	 */
	return common_failure_notification_send(inst, request, eap_session);
}

/** Enter the FAILURE-NOTIFICATION state
 *
 */
static rlm_rcode_t common_failure_notification_enter(eap_aka_sim_common_conf_t *inst,
						     REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst, request, eap_session,
						   common_failure_notification_enter); /* come back when we're done */
	}

	/*
	 *	We've already sent a failure notification
	 *	Now we just fail as it means something
	 *	went wrong processing the ACK or we got
	 *	garbage from the supplicant.
	 */
	if (eap_session->process == common_failure_notification) {
		return common_eap_failure_enter(inst, request, eap_session);
	}

	/*
	 *	Otherwise just transition as normal...
	 */
	state_transition(request, eap_session, common_failure_notification);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_failure_notification,
					      RLM_MODULE_NOOP,
					      common_failure_notification_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send EAP-Success { ... }'
 *
 */
static rlm_rcode_t common_eap_success_enter_resume(void *instance, UNUSED void *thread,
						  REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);

	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	/*
	 *	If this is true we're entering this state
	 *	after sending a AKA-Success-Notification
	 *
	 *	Is seems like a really bad idea to allow the
	 *	user to send a protected success to the
	 *	supplicant and then force a failure using
	 *	the send EAP-Success { ... } section.
	 */
	if (eap_aka_sim_session->send_result_ind) {
		switch (request->rcode) {
		case RLM_MODULE_USER_SECTION_REJECT:
			RWDEBUG("Ignoring rcode (%s) from send EAP-Success { ... } "
				"as we already sent a Success-Notification",
				fr_table_str_by_value(mod_rcode_table, request->rcode, "<invalid>"));
			RWDEBUG("If you need to force a failure, return an error code from "
				"send Success-Notification { ... }");
			break;

		default:
			break;
		}

	/*
	 *	But... if we're not working with protected
	 *	success indication, this is the only
	 *	opportunity the user has to force a failure at
	 *	the end of authentication.
	 */
	} else {
		section_rcode_process(inst, request, eap_session, eap_aka_sim_session);
	}

	return common_eap_success_send(request, eap_session);
}

/** Enter EAP-SUCCESS state
 *
 */
static rlm_rcode_t common_eap_success_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request,
					    eap_session_t *eap_session)
{
	state_transition(request, eap_session, common_eap_success);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_eap_success,
					      RLM_MODULE_NOOP,
					      common_eap_success_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Success-Notification { ... }'
 *
 */
static rlm_rcode_t common_success_notification_enter_resume(void *instance, UNUSED void *thread,
							       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return common_success_notification_send(inst, request, eap_session);
}

/** Enter the SUCCESS-NOTIFICATION state
 *
 */
static rlm_rcode_t common_success_notification_enter(eap_aka_sim_common_conf_t *inst,
							REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, common_success_notification);

	return unlang_module_yield_to_section(request,
					      inst->actions.send_success_notification,
					      RLM_MODULE_NOOP,
					      common_success_notification_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Reauthentication-Request { ... }'
 *
 */
static rlm_rcode_t common_reauthentication_send_resume(void *instance, UNUSED void *thread,
				 		       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	switch (request->rcode) {
	/*
	 *	Failed getting the values we need for resumption
	 *	Request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		/*
		 *	Got here processing EAP-Identity-Response
		 *	If this is the *true* reauth ID, then
		 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
		 */
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
			RDEBUG2("Previous section returned (%s), clearing reply attributes and "
				"requesting additional identity",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"));
			fr_pair_list_free(&request->reply->vps);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;

			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested Full-Auth-Id or Permanent-Identity, "
				"but received a Fast-Auth-Id.  Cannot continue");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);

		}

	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		goto failure;

	/*
	 *	Everything looks ok, send the EAP-Request/reauthentication message
	 *	After storing any new pseudonyms or session information.
	 */
	case RLM_MODULE_NOOP:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		return common_reauthentication_request_compose(inst, request, eap_session);
	}
}

/** Resume after 'load session { ... }'
 *
 */
static rlm_rcode_t session_load_resume(void *instance, UNUSED void *thread,
				       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	pair_delete_request(attr_session_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_session) goto reauthenticate;

	switch (request->rcode) {
	/*
	 *	Failed getting the values we need for resumption
	 *	Request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		/*
		 *	Got here processing EAP-Identity-Response
		 *	If this is the *true* reauth ID, then
		 *	there's no point in setting AKA_SIM_ANY_ID_REQ.
		 */
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
			RDEBUG2("Previous section returned (%s), clearing reply attributes and "
				"requesting additional identity",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"));
			fr_pair_list_free(&request->reply->vps);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested Full-Auth-Id or Permanent-Identity, "
				"but received a Fast-Auth-Id.  Cannot continue");
			return common_failure_notification_enter(inst, request, eap_session);

		}

	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		return common_failure_notification_enter(inst, request, eap_session);

	/*
	 *	Everything OK
	 */
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	reauthenticate:
		return unlang_module_yield_to_section(request,
						      inst->actions.send_reauthentication_request,
						      RLM_MODULE_NOOP,
						      common_reauthentication_send_resume,
						      mod_signal,
						      NULL);
	}
}

/** Resume after 'load pseudonym { ... }'
 *
 */
static rlm_rcode_t pseudonym_load_resume(void *instance, UNUSED void *thread,
					 REQUEST *request, void *rctx)
{
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	aka_sim_state_enter_t	state_enter = (aka_sim_state_enter_t)rctx;

	pair_delete_request(attr_eap_aka_sim_next_reauth_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_pseudonym) {
	next_state:
		return state_enter(inst, request, eap_session);
	}

	switch (request->rcode) {
	/*
	 *	Failed resolving the pseudonym
	 *	request a different identity.
	 */
	default:
		switch (eap_aka_sim_session->last_id_req) {
		case AKA_SIM_NO_ID_REQ:
		case AKA_SIM_ANY_ID_REQ:
		case AKA_SIM_FULLAUTH_ID_REQ:
			RDEBUG2("Previous section returned (%s), clearing reply attributes and "
				"requesting additional identity",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"));
			fr_pair_list_free(&request->reply->vps);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return common_identity_enter(inst, request, eap_session);

		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested a Permanent-Identity, but received a Pseudonym.  Cannot continue");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);
		}
	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
		goto failure;

	/*
	 *	Everything OK
	 */
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		goto next_state;
	}
}

/** Enter the REAUTHENTICATION state
 *
 */
static rlm_rcode_t common_reauthentication_enter(eap_aka_sim_common_conf_t *inst,
						 REQUEST *request, eap_session_t *eap_session)
{
	VALUE_PAIR		*vp = NULL;
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	state_transition(request, eap_session, common_reauthentication);

	/*
	 *	Add the current identity as session_id
	 *      to make it easier to load/store things from
	 *	the cache module.
	 */
	MEM(pair_update_request(&vp, attr_session_id) >= 0);
	fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.identity, eap_aka_sim_session->keys.identity_len, true);

	return unlang_module_yield_to_section(request,
					      inst->actions.load_session,
					      RLM_MODULE_NOOP,
					      session_load_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Challenge-Request { ... }'
 *
 */
static rlm_rcode_t aka_challenge_enter_resume(void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return aka_challenge_request_compose(inst, request, eap_session);
}

/** Enter the AKA-CHALLENGE state
 *
 */
static rlm_rcode_t aka_challenge_enter(eap_aka_sim_common_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);
	VALUE_PAIR		*vp;

	/*
	 *	If we've sent either of these identities it
	 *	means we've come here form a Reauthentication-Request
	 *	that failed.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst, request, eap_session, aka_challenge_enter);	/* come back when we're done */
	}

	state_transition(request, eap_session, aka_challenge);

	/*
	 *	Set some default attributes, giving the user a
	 *	chance to modify them.
	 */
	switch (eap_session->type) {
	case FR_EAP_METHOD_AKA_PRIME:
	{
		uint8_t		amf_buff[2] = { 0x80, 0x00 };	/* Set the AMF separation bit high */

		/*
		 *	Toggle the AMF high bit to indicate we're doing AKA'
		 */
		MEM(pair_update_control(&vp, attr_sim_amf) >= 0);
		fr_pair_value_memcpy(vp, amf_buff, sizeof(amf_buff), false);

	        /*
	 	 *	Use the default network name we have configured
	 	 *	and send it to the peer.
	 	 */
		if (inst->network_name &&
		    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_kdf_input, TAG_ANY)) {
			MEM(pair_add_reply(&vp, attr_eap_aka_sim_kdf_input) >= 0);
			fr_pair_value_bstrncpy(vp, inst->network_name, talloc_array_length(inst->network_name) - 1);
		}
	}
		break;

	default:
		/*
		 *	Use the default bidding value we have configured
		 */
		if (eap_aka_sim_session->send_at_bidding_prefer_prime &&
		    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_bidding, TAG_ANY)) {
			MEM(pair_add_reply(&vp, attr_eap_aka_sim_bidding) >= 0);
			vp->vp_uint16 = FR_BIDDING_VALUE_PREFER_AKA_PRIME;
		}
		break;

	}

	/*
	 *	Set the defaults for protected result indicator
	 */
	if (eap_aka_sim_session->send_result_ind &&
	    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_result_ind, TAG_ANY)) {
	    	MEM(pair_add_reply(&vp, attr_eap_aka_sim_result_ind) >= 0);
		vp->vp_bool = true;
	}

	return unlang_module_yield_to_section(request,
					      inst->actions.send_challenge_request,
					      RLM_MODULE_NOOP,
					      aka_challenge_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Challenge-Request { ... }'
 *
 */
static rlm_rcode_t sim_challenge_enter_resume(void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return sim_challenge_request_compose(inst, request, eap_session);
}

/** Enter the SIM-CHALLENGE state
 *
 */
static rlm_rcode_t sim_challenge_enter(eap_aka_sim_common_conf_t *inst,
				       REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);
	VALUE_PAIR			*vp;

	/*
	 *	If we've sent either of these identities it
	 *	means we've come here form a Reauthentication-Request
	 *	that failed.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(inst, request, eap_session, sim_challenge_enter);	/* come back when we're done */
	}

	state_transition(request, eap_session, sim_challenge);

	/*
	 *	Set the defaults for protected result indicator
	 */
	if (eap_aka_sim_session->send_result_ind &&
	    !fr_pair_find_by_da(request->reply->vps, attr_eap_aka_sim_result_ind, TAG_ANY)) {
	    	MEM(pair_add_reply(&vp, attr_eap_aka_sim_result_ind) >= 0);
		vp->vp_bool = true;
	}

	return unlang_module_yield_to_section(request,
					      inst->actions.send_challenge_request,
					      RLM_MODULE_NOOP,
					      sim_challenge_enter_resume,
					      mod_signal,
					      NULL);
}

/** Enter the SIM-CHALLENGE or AKA-CHALLENGE state
 *
 * Called by functions which are common to both the EAP-SIM and EAP-AKA state machines
 * to enter the correct challenge state.
 */
static rlm_rcode_t common_challenge_enter(eap_aka_sim_common_conf_t *inst,
				          REQUEST *request, eap_session_t *eap_session)
{
	switch (eap_session->type) {
	case FR_EAP_METHOD_SIM:
		return sim_challenge_enter(inst, request, eap_session);

	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_AKA_PRIME:
		return aka_challenge_enter(inst, request, eap_session);

	default:
		rad_assert(0);
	}
}

/** Resume after 'send Identity-Request { ... }'
 *
 */
static rlm_rcode_t aka_identity_enter_resume(void *instance, UNUSED void *thread,
						   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return aka_identity_request_send(inst, request, eap_session);
}

/** Enter the AKA-IDENTITY state
 *
 */
static rlm_rcode_t aka_identity_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, aka_identity);

	/*
	 *	If we have an send_aka_identity_request section
	 *	then run that, otherwise just run the normal
	 *	identity request section.
	 */
	return unlang_module_yield_to_section(request,
					      inst->actions.aka.send_aka_identity_request ?
							inst->actions.aka.send_aka_identity_request:
							inst->actions.send_identity_request,
					      RLM_MODULE_NOOP,
					      aka_identity_enter_resume,
					      mod_signal,
					      NULL);
}

/** Resume after 'send Start { ... }'
 *
 */
static rlm_rcode_t sim_start_enter_resume(void *instance, UNUSED void *thread,
					  REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return sim_start_request_send(inst, request, eap_session);
}

/** Enter the SIM-START state
 *
 */
static rlm_rcode_t sim_start_enter(eap_aka_sim_common_conf_t *inst, REQUEST *request, eap_session_t *eap_session)
{
	state_transition(request, eap_session, sim_start);

	return unlang_module_yield_to_section(request,
					      inst->actions.sim.send_sim_start_request ?
					      		inst->actions.sim.send_sim_start_request:
					      		inst->actions.send_identity_request,
					      RLM_MODULE_NOOP,
					      sim_start_enter_resume,
					      mod_signal,
					      NULL);
}

/** Enter the SIM-START or AKA-IDENTITY state
 *
 * Called by functions which are common to both the EAP-SIM and EAP-AKA state machines
 * to enter the correct Identity-Request state.
 */
static rlm_rcode_t common_identity_enter(eap_aka_sim_common_conf_t *inst,
				         REQUEST *request, eap_session_t *eap_session)
{
	switch (eap_session->type) {
	case FR_EAP_METHOD_SIM:
		return sim_start_enter(inst, request, eap_session);

	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_AKA_PRIME:
		return aka_identity_enter(inst, request, eap_session);

	default:
		rad_assert(0);
	}
}

/** Process a EAP-Response/(AKA|SIM)-Reauthentication message - The response to our EAP-Request/(AKA|SIM)-Reauthentication message
 *
 */
static rlm_rcode_t common_reauthentication_response_process(eap_aka_sim_common_conf_t *inst, REQUEST *request,
							    eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	uint8_t			calc_mac[AKA_SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*mac, *checkcode;
	VALUE_PAIR		*from_peer = request->packet->vps;

	mac = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	if (mac->vp_length != AKA_SIM_MAC_DIGEST_SIZE) {
		REDEBUG("MAC has incorrect length, expected %u bytes got %zu bytes",
			AKA_SIM_MAC_DIGEST_SIZE, mac->vp_length);
		goto failure;
	}

	slen = fr_aka_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					     eap_aka_sim_session->mac_md,
					     eap_aka_sim_session->keys.k_aut, eap_aka_sim_session->keys.k_aut_len,
					     eap_aka_sim_session->keys.reauth.nonce_s,
					     sizeof(eap_aka_sim_session->keys.reauth.nonce_s));
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		goto failure;
	} else if (slen == 0) {
		REDEBUG("Zero length AT_MAC attribute");
		goto failure;
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("Received MAC matches calculated MAC");
	} else {
		REDEBUG("Received MAC does not match calculated MAC");
		RHEXDUMP_INLINE2(mac->vp_octets, AKA_SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE2(calc_mac, AKA_SIM_MAC_DIGEST_SIZE, "Expected");
		goto failure;
	}

	/*
	 *	If the peer doesn't include a checkcode then that
	 *	means they don't support it, and we can't validate
	 *	their view of the identity packets.
	 */
	checkcode = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_checkcode, TAG_ANY);
	if (checkcode) {
		if (checkcode->vp_length != eap_aka_sim_session->checkcode_len) {
			REDEBUG("Received checkcode's length (%zu) does not match calculated checkcode's length (%zu)",
				checkcode->vp_length, eap_aka_sim_session->checkcode_len);
			goto failure;
		}

		if (memcmp(checkcode->vp_octets, eap_aka_sim_session->checkcode,
			   eap_aka_sim_session->checkcode_len) == 0) {
			RDEBUG2("Received checkcode matches calculated checkcode");
		} else {
			REDEBUG("Received checkcode does not match calculated checkcode");
			RHEXDUMP_INLINE2(checkcode->vp_octets, checkcode->vp_length, "Received");
			RHEXDUMP_INLINE2(eap_aka_sim_session->checkcode,
					 eap_aka_sim_session->checkcode_len, "Expected");
			goto failure;
		}
	/*
	 *	Only print something if we calculated a checkcode
	 */
	} else if (eap_aka_sim_session->checkcode_len > 0){
		RDEBUG2("Peer didn't include AT_CHECKCODE, skipping checkcode validation");
	}

	/*
	 *	Check to see if the supplicant sent
	 *	AT_COUNTER_TOO_SMALL, if they did then we
	 *	clear out reauth information and enter the
	 *	challenge state.
	 */
	if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_counter_too_small, TAG_ANY)) {
		RWDEBUG("Peer sent AT_COUNTER_TOO_SMALL (indicating our AT_COUNTER value (%u) wasn't fresh)",
			eap_aka_sim_session->keys.reauth.counter);

		fr_aka_sim_vector_umts_reauth_clear(&eap_aka_sim_session->keys);
		eap_aka_sim_session->allow_encrypted = false;

	 	return aka_challenge_enter(inst, request, eap_session);
	}

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 *
	 *	RFC 4187 Section #6.2. Result Indications
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return common_success_notification_enter(inst, request, eap_session);
		}
	} else if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	eap_aka_sim_session->reauthentication_success = true;

	return common_eap_success_enter(inst, request, eap_session);
}

/** Process a EAP-Response/AKA-Challenge message - The response to our EAP-Request/AKA-Challenge message
 *
 * Verify that MAC, and RES match what we expect.
 */
static rlm_rcode_t aka_challenge_response_process(eap_aka_sim_common_conf_t *inst,
						  REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	uint8_t			calc_mac[AKA_SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*vp = NULL, *mac, *checkcode;
	VALUE_PAIR		*from_peer = request->packet->vps;

	mac = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	if (mac->vp_length != AKA_SIM_MAC_DIGEST_SIZE) {
		REDEBUG("MAC has incorrect length, expected %u bytes got %zu bytes",
			AKA_SIM_MAC_DIGEST_SIZE, mac->vp_length);
		goto failure;
	}

	slen = fr_aka_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					     eap_aka_sim_session->mac_md,
					     eap_aka_sim_session->keys.k_aut, eap_aka_sim_session->keys.k_aut_len,
					     NULL, 0);
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		goto failure;
	} else if (slen == 0) {
		REDEBUG("Zero length AT_MAC attribute");
		goto failure;
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("Received MAC matches calculated MAC");
	} else {
		REDEBUG("Received MAC does not match calculated MAC");
		RHEXDUMP_INLINE2(mac->vp_octets, AKA_SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE2(calc_mac, AKA_SIM_MAC_DIGEST_SIZE, "Expected");
		goto failure;
	}

	/*
	 *	If the peer doesn't include a checkcode then that
	 *	means they don't support it, and we can't validate
	 *	their view of the identity packets.
	 */
	if (eap_aka_sim_session->checkcode_md) {
		checkcode = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_checkcode, TAG_ANY);
		if (checkcode) {
			if (checkcode->vp_length != eap_aka_sim_session->checkcode_len) {
				REDEBUG("Received checkcode's length (%zu) does not match "
					"calculated checkcode's length (%zu)",
					checkcode->vp_length, eap_aka_sim_session->checkcode_len);
				goto failure;
			}

			if (memcmp(checkcode->vp_octets,
				   eap_aka_sim_session->checkcode, eap_aka_sim_session->checkcode_len) == 0) {
				RDEBUG2("Received checkcode matches calculated checkcode");
			} else {
				REDEBUG("Received checkcode does not match calculated checkcode");
				RHEXDUMP_INLINE2(checkcode->vp_octets, checkcode->vp_length, "Received");
				RHEXDUMP_INLINE2(eap_aka_sim_session->checkcode,
						eap_aka_sim_session->checkcode_len, "Expected");
				goto failure;
			}
		/*
		 *	Only print something if we calculated a checkcode
		 */
		} else if (eap_aka_sim_session->checkcode_len > 0){
			RDEBUG2("Peer didn't include AT_CHECKCODE, skipping checkcode validation");
		}
	}

	vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_res, TAG_ANY);
	if (!vp) {
		REDEBUG("AT_RES missing from challenge response");
		goto failure;
	}

	if (vp->vp_length != eap_aka_sim_session->keys.umts.vector.xres_len) {
		REDEBUG("Received RES' length (%zu) does not match calculated XRES' length (%zu)",
			vp->vp_length, eap_aka_sim_session->keys.umts.vector.xres_len);
		goto failure;
	}

  	if (memcmp(vp->vp_octets, eap_aka_sim_session->keys.umts.vector.xres, vp->vp_length)) {
    		REDEBUG("Received RES does not match calculated XRES");
		RHEXDUMP_INLINE2(vp->vp_octets, vp->vp_length, "RES  :");
		RHEXDUMP_INLINE2(eap_aka_sim_session->keys.umts.vector.xres,
				eap_aka_sim_session->keys.umts.vector.xres_len, "XRES :");
		goto failure;
	}

	RDEBUG2("Received RES matches calculated XRES");

	eap_aka_sim_session->challenge_success = true;

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 *
	 *	RFC 4187 Section #6.2. Result Indications
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return common_success_notification_enter(inst, request, eap_session);
		}
	} else if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	return common_eap_success_enter(inst, request, eap_session);
}

/** Process a EAP-Response/SIM-Challenge message - The response to our EAP-Request/SIM-Challenge message
 *
 * Verify that MAC, and RES match what we expect.
 */
static rlm_rcode_t sim_challenge_response_process(eap_aka_sim_common_conf_t *inst,
						  REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	uint8_t			sres_cat[AKA_SIM_VECTOR_GSM_SRES_SIZE * 3];
	uint8_t			*p = sres_cat;

	uint8_t			calc_mac[AKA_SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*mac;
	VALUE_PAIR		*from_peer = request->packet->vps;

	memcpy(p, eap_aka_sim_session->keys.gsm.vector[0].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[1].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[2].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);

	mac = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	if (mac->vp_length != AKA_SIM_MAC_DIGEST_SIZE) {
		REDEBUG("MAC has incorrect length, expected %u bytes got %zu bytes",
			AKA_SIM_MAC_DIGEST_SIZE, mac->vp_length);
		goto failure;
	}

	slen = fr_aka_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					     eap_aka_sim_session->mac_md,
					     eap_aka_sim_session->keys.k_aut, eap_aka_sim_session->keys.k_aut_len,
					     sres_cat, sizeof(sres_cat));
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		goto failure;
	} else if (slen == 0) {
		REDEBUG("Zero length AT_MAC attribute");
		goto failure;
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("Received MAC matches calculated MAC");
	} else {
		REDEBUG("Received MAC does not match calculated MAC");
		RHEXDUMP_INLINE2(mac->vp_octets, AKA_SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE2(calc_mac, AKA_SIM_MAC_DIGEST_SIZE, "Expected");
		goto failure;
	}

	eap_aka_sim_session->challenge_success = true;

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return common_success_notification_enter(inst, request, eap_session);
		}
	} else if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_result_ind, TAG_ANY)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	return common_eap_success_enter(inst, request, eap_session);
}

/** Process a EAP-Response/AKA-Identity message i.e. an EAP-AKA Identity-Response
 *
 * - If the message does not contain AT_IDENTITY, then enter the FAILURE-NOTIFICATION state.
 * - If the user requested another identity, re-enter the AKA-Identity sate.
 * - ...or continue based on the value of &Identity-Type which was added by #aka_identity,
 *   and possibly modified by the user.
 *   - Fastauth - Enter the REAUTHENTICATION state.
 *   - Pseudonym - Call 'load pseudonym { ... }'
 *   - Permanent - Enter the CHALLENGE state.
 */
static rlm_rcode_t aka_identity_response_process(eap_aka_sim_common_conf_t *inst,
						 REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	bool			user_set_id_req;
	VALUE_PAIR		*identity_type;
	VALUE_PAIR		*from_peer = request->packet->vps;
	/*
	 *	Digest the identity response
	 */
	if (eap_aka_sim_session->checkcode_md) {
		if (fr_aka_sim_crypto_update_checkcode(eap_aka_sim_session->checkcode_state,
						       eap_session->this_round->response) < 0) {
			RPEDEBUG("Failed updating checkcode");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);
		}
	}

	/*
	 *	See if the user wants us to request another
	 *	identity.
	 *
	 *	If they set one themselves don't override
	 *	what they set.
	 */
	user_set_id_req = identity_req_set_by_user(request, eap_aka_sim_session);
	if ((request->rcode == RLM_MODULE_NOTFOUND) || user_set_id_req) {
		if (!user_set_id_req) {
			switch (eap_aka_sim_session->last_id_req) {
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				break;

			case AKA_SIM_FULLAUTH_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
				break;

			case AKA_SIM_NO_ID_REQ:	/* Should not happen */
				rad_assert(0);
				/* FALL-THROUGH */

			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Peer sent no usable identities");
				goto failure;

			}
			RDEBUG2("Previous section returned (%s), requesting next most permissive identity (%s)",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		}
		return aka_identity_enter(inst, request, eap_session);
	}

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do fullauth.
	 */
	identity_type = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity_type, TAG_ANY);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return common_reauthentication_enter(inst, request, eap_session);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		return unlang_module_yield_to_section(request,
						      inst->actions.load_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_load_resume,
						      mod_signal,
						      (void *)aka_challenge_enter);
	default:
		break;
	}

	return aka_challenge_enter(inst, request, eap_session);
}

/** Helper function to check for the presence and length of AT_SELECTED_VERSION and copy its value into the keys structure
 *
 * Also checks the version matches one of the ones we advertised in our version list,
 * which is a bit redundant seeing as there's only one version of EAP-SIM.
 */
static int sim_start_selected_version_check(REQUEST *request, VALUE_PAIR *from_peer,
					    eap_aka_sim_session_t *eap_aka_sim_session)
{
	VALUE_PAIR		*selected_version_vp;

	/*
	 *	Check that we got an AT_SELECTED_VERSION
	 */
	selected_version_vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_selected_version, TAG_ANY);
	if (!selected_version_vp) {
		REDEBUG("EAP-Response/SIM/Start does not contain AT_SELECTED_VERSION");
		return -1;
	}

	/*
	 *	See if the selected version was in our list
	 */
	{
		uint8_t selected_version[2];
		uint8_t *p, *end;
		bool found = false;

		p = eap_aka_sim_session->keys.gsm.version_list;
		end = p + eap_aka_sim_session->keys.gsm.version_list_len;

		selected_version[0] = (selected_version_vp->vp_uint16 & 0xff00) >> 8;
		selected_version[1] = (selected_version_vp->vp_uint16 & 0x00ff);

		while (p < end) {
			if ((p[0] == selected_version[0]) && (p[1] == selected_version[1])) {
				found = true;
				/*
				 *	Update our keying material
				 */
				eap_aka_sim_session->keys.gsm.version_select[0] = selected_version[0];
				eap_aka_sim_session->keys.gsm.version_select[1] = selected_version[1];
				break;
			}
		}

		if (!found) {
			REDEBUG("AT_SELECTED_VERSION (%u) does not match a value in our version list",
				selected_version_vp->vp_uint16);
			return -1;
		}
	}

	return 0;
}

/** Helper function to check for the presence and length of AT_NONCE_MT and copy its value into the keys structure
 *
 * Does not actually perform cryptographic validation of AT_NONCE_MT, this is done later.
 */
static int sim_start_nonce_mt_check(REQUEST *request, VALUE_PAIR *from_peer,
				    eap_aka_sim_session_t *eap_aka_sim_session)
{
	VALUE_PAIR	*nonce_mt_vp;

	/*
	 *	Copy nonce_mt to the keying material
	 */
	nonce_mt_vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_nonce_mt, TAG_ANY);
	if (!nonce_mt_vp) {
		REDEBUG("EAP-Response/SIM/Start does not contain AT_NONCE_MT");
		return -1;
	}

	if (nonce_mt_vp->vp_length != sizeof(eap_aka_sim_session->keys.gsm.nonce_mt)) {
		REDEBUG("AT_NONCE_MT must be exactly %zu bytes, not %zu bytes",
			sizeof(eap_aka_sim_session->keys.gsm.nonce_mt), nonce_mt_vp->vp_length);
		return -1;
	}
	memcpy(eap_aka_sim_session->keys.gsm.nonce_mt, nonce_mt_vp->vp_octets,
	       sizeof(eap_aka_sim_session->keys.gsm.nonce_mt));

	return 0;
}

/** Process a EAP-Response/SIM-Start message i.e. an EAP-SIM Identity-Response
 *
 * - If the message does not contain AT_IDENTITY, then enter the FAILURE-NOTIFICATION state.
 * - If the user requested another identity, re-enter the SIM-START sate.
 * - ...or continue based on the value of &Identity-Type which was added by #sim_start,
 *   and possibly modified by the user.
 *   - Fastauth
 *     - If AT_NONCE_MT or AT_SELECTED_VERSION are present, enter the FAILURE-NOTIFICATION state.
 *     - ...or enter the REAUTHENTICATION state.
 *   - Pseudonym - Verify selected version and AT_NONCE_MT, then call 'load pseudonym { ... }'
 *   - Permanent - Verify selected version and AT_NONCE_MT, then enter the CHALLENGE state.
 */
static rlm_rcode_t sim_start_response_process(eap_aka_sim_common_conf_t *inst,
					      REQUEST *request, eap_session_t *eap_session)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);
	bool			user_set_id_req;
	VALUE_PAIR		*identity_type;

	VALUE_PAIR		*from_peer = request->packet->vps;

	/*
	 *	See if the user wants us to request another
	 *	identity.
	 *
	 *	If they set one themselves don't override
	 *	what they set.
	 */
	user_set_id_req = identity_req_set_by_user(request, eap_aka_sim_session);
	if ((request->rcode == RLM_MODULE_NOTFOUND) || user_set_id_req) {
		if (!user_set_id_req) {
			switch (eap_aka_sim_session->last_id_req) {
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				break;

			case AKA_SIM_FULLAUTH_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
				break;

			case AKA_SIM_NO_ID_REQ:	/* Should not happen */
				rad_assert(0);
				/* FALL-THROUGH */

			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Peer sent no usable identities");
			failure:
				return common_failure_notification_enter(inst, request, eap_session);
			}
			RDEBUG2("Previous section returned (%s), requesting next most permissive identity (%s)",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		}
		return sim_start_enter(inst, request, eap_session);
	}

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do fullauth.
	 */
	identity_type = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity_type, TAG_ANY);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		/*
		 *  RFC 4186 Section #9.2
		 *
		 *  The AT_NONCE_MT attribute MUST NOT be included if the AT_IDENTITY
		 *  with a fast re-authentication identity is present for fast
		 *  re-authentication
		 */
		if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_nonce_mt, TAG_ANY)) {
			REDEBUG("AT_NONCE_MT is not allowed in EAP-Response/SIM-Reauthentication messages");
			return common_failure_notification_enter(inst, request, eap_session);
		}

		/*
		 *  RFC 4186 Section #9.2
		 *
		 *  The AT_SELECTED_VERSION attribute MUST NOT be included if the
		 *  AT_IDENTITY attribute with a fast re-authentication identity is
		 *  present for fast re-authentication.
		 */
		if (fr_pair_find_by_da(from_peer, attr_eap_aka_sim_selected_version, TAG_ANY)) {
			REDEBUG("AT_SELECTED_VERSION is not allowed in EAP-Response/SIM-Reauthentication messages");
			return common_failure_notification_enter(inst, request, eap_session);
		}

		return common_reauthentication_enter(inst, request, eap_session);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		if (sim_start_selected_version_check(request, from_peer, eap_aka_sim_session) < 0) goto failure;
		if (sim_start_nonce_mt_check(request, from_peer, eap_aka_sim_session) < 0) goto failure;

		return unlang_module_yield_to_section(request,
						      inst->actions.load_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_load_resume,
						      mod_signal,
						      (void *)sim_challenge_enter);

	/*
	 *	If it's a permanent ID, copy it over to
	 *	the session state list for use in the
	 *      store pseudonym/store session sections
	 *	later.
	 */
	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
		if (sim_start_selected_version_check(request, from_peer, eap_aka_sim_session) < 0) goto failure;
		if (sim_start_nonce_mt_check(request, from_peer, eap_aka_sim_session) < 0) goto failure;

		/* FALL-THROUGH */
	default:
		break;
	}

	return sim_challenge_enter(inst, request, eap_session);
}

/** Resume after 'recv Failure-Notification-Ack { ... }'
 *
 * - Enter the EAP-FAILURE state.
 */
static rlm_rcode_t common_failure_notification_recv_resume(void *instance, UNUSED void *thread,
							   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return common_eap_failure_enter(inst, request, eap_session);
}

/** Resume after 'recv Success-Notification-Ack { ... }'
 *
 * - Enter the EAP-SUCCESS state.
 */
static rlm_rcode_t common_success_notification_ack_recv_resume(void *instance, UNUSED void *thread,
							       REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	RFC 4187 says we ignore the contents of the
	 *	next packet after we send our success notification
	 *	and always send a success.
	 */
	return common_eap_success_enter(inst, request, eap_session);
}

/** Resume after 'recv Challenge-Response { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the AKA-Challenge message.
 */
static rlm_rcode_t aka_challenge_response_recv_resume(void *instance, UNUSED void *thread,
						      REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return aka_challenge_response_process(inst, request, eap_session);
}

/** Resume after 'recv Challenge-Response { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the SIM-Challenge message.
 */
static rlm_rcode_t sim_challenge_response_recv_resume(void *instance, UNUSED void *thread,
						      REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return sim_challenge_response_process(inst, request, eap_session);
}

/** Resume after 'recv Identity-Response { ... }' or 'recv AKA-Identity { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the AKA-Identity message, mainly the AT_IDENTITY value.
 */
static rlm_rcode_t aka_identity_response_recv_resume(void *instance, UNUSED void *thread,
						     REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return aka_identity_response_process(inst, request, eap_session);
}

/** Resume after 'recv Identity-Response { ... }' or 'recv SIM-Start { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the SIM-Start message, mainly the AT_IDENTITY value.
 */
static rlm_rcode_t sim_start_response_recv_resume(void *instance, UNUSED void *thread,
						  REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     	     eap_aka_sim_session_t);

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return sim_start_response_process(inst, request, eap_session);
}

/** Resume after 'recv Authentication-Reject { ... }'
 *
 * - Enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t aka_authentication_reject_recv_resume(void *instance, UNUSED void *thread,
							 REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return common_eap_failure_enter(inst, request, eap_session);
}

/** Resume after 'recv Synchronization-Failure { ... }'
 *
 * - If 'recv Synchronization-Failure { ... }' returned a failure
 *   rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or if no 'recv Syncronization-Failure { ... }' section was
 *   defined, then enter the FAILURE-NOTIFICATION state.
 * - ...or if the user didn't provide a new SQN value in &control:SQN
 *   then enter the FAILURE-NOTIFICATION state.
 * - ...or enter the AKA-CHALLENGE state.
 */
static rlm_rcode_t aka_synchronization_failure_recv_resume(void *instance, UNUSED void *thread,
							   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);
	VALUE_PAIR			*vp;

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	/*
	 *	If there's no section to handle this, then no resynchronisation
	 *	can't have occurred and we just send a reject.
	 *
	 *	Similarly, if we've already received one synchronisation failure
	 *	then it's highly likely whatever user configured action was
	 *	configured was unsuccessful, and we should just give up.
	 */
	if (!inst->actions.aka.recv_syncronization_failure || eap_aka_sim_session->prev_recv_sync_failure) {
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	We couldn't generate an SQN and the user didn't provide one,
	 *	so we need to fail.
	 */
	vp = fr_pair_find_by_da(request->control, attr_sim_sqn, TAG_ANY);
	if (!vp) {
		REDEBUG("No &control:SQN value provided after resynchronisation, cannot continue");
		goto failure;
	}

	/*
	 *	RFC 4187 Section #6.3.1
	 *
	 *	"if the peer detects that the
   	 *	sequence number in AUTN is not correct, the peer responds with
	 *	EAP-Response/AKA-Synchronization-Failure (Section 9.6), and the
	 *	server proceeds with a new EAP-Request/AKA-Challenge."
	 */
	return aka_challenge_enter(inst, request, eap_session);
}

/** Resume after 'recv Client-Error { ... }'
 *
 * - Enter the EAP-FAILURE state.
 */
static rlm_rcode_t common_client_error_recv_resume(void *instance, UNUSED void *thread,
						   REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);

	section_rcode_ignored(request);

	return common_eap_failure_enter(inst, request, eap_session);
}

/** Resume after 'recv Reauthentication-Response { ... }'
 *
 * - If 'recv Reauthentication-Response { ... }' returned a failure
 *   rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call the EAP-Request/Reauthentication-Response function to act on the
 *   contents of the response.
 */
static rlm_rcode_t common_reauthentication_response_recv_resume(void *instance, UNUSED void *thread,
								REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t				*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t			*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
											     eap_aka_sim_session_t);
	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	return common_reauthentication_response_process(inst, request, eap_session);
}

/** Decode the peer's response
 *
 * This is called by the state_* functions to decode the peer's response.
 */
static rlm_rcode_t common_decode(VALUE_PAIR **subtype_vp, VALUE_PAIR **vps,
				 eap_aka_sim_common_conf_t *inst, REQUEST *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	fr_aka_sim_decode_ctx_t	ctx = {
					.keys = &eap_aka_sim_session->keys,
				};
	VALUE_PAIR		*aka_vps;
	fr_cursor_t		cursor;

	int			ret;

	fr_cursor_init(&cursor, &request->packet->vps);
	fr_cursor_tail(&cursor);

	ret = fr_aka_sim_decode(request,
				&cursor,
				dict_eap_aka_sim,
				eap_session->this_round->response->type.data,
				eap_session->this_round->response->type.length,
				&ctx);
	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case where
	 *	we cannot decode an EAP-AKA packet.
	 */
	if (ret < 0) {
		RPEDEBUG2("Failed decoding attributes");
	failure:
		return common_failure_notification_enter(inst, request, eap_session);
	}
	/* vps is the data from the client */
	aka_vps = fr_cursor_next(&cursor);
	if (aka_vps && RDEBUG_ENABLED2) {
		RDEBUG2("Decoded attributes");
		log_request_pair_list(L_DBG_LVL_2, request, aka_vps, NULL);
	}

	*subtype_vp = fr_pair_find_by_da(aka_vps, attr_eap_aka_sim_subtype, TAG_ANY);
	if (!*subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto failure;
	}
	*vps = aka_vps;

	RDEBUG2("Received EAP-Response/%pV", &(*subtype_vp)->data);

	return RLM_MODULE_OK;
}

/** FAILURE state - State machine exit point after sending EAP-Failure
 *
 * Should never actually be called. Is just a placeholder function to represent the FAILURE
 * termination state.  Could equally be a NULL pointer, but then on a logic error
 * we'd get a SEGV instead of a more friendly assert/failure rcode.
 */
static rlm_rcode_t common_eap_failure(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	rad_assert(0);	/* Should never actually be called */
	return RLM_MODULE_FAIL;
}

/** FAILURE-NOTIFICATION state - Continue the state machine after receiving a response to our EAP-Request/(AKA|SIM)-Notification
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/SIM-Client-Error - Call 'recv Failure-Notification-Ack { ... }'
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t common_failure_notification(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t			rcode;
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);

	VALUE_PAIR			*subtype_vp = NULL;
	VALUE_PAIR			*vps;

	rcode = common_decode(&subtype_vp, &vps, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION:
		RDEBUG2("Failure-Notification ACKed, sending EAP-Failure");
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_failure_notification_ack,
						      RLM_MODULE_NOOP,
						      common_failure_notification_recv_resume,
						      mod_signal,
						      NULL);

	default:
		RWDEBUG("Failure-Notification not ACKed correctly, sending EAP-Failure anyway");
		return common_eap_failure_enter(inst, request, eap_session);
	}
}

/** SUCCESS state - State machine exit point after sending EAP-Success
 *
 * Should never actually be called. Is just a placeholder function to represent the FAILURE
 * termination state.  Could equally be a NULL pointer, but then on a logic error
 * we'd get a SEGV instead of a more friendly assert/failure rcode.
 */
static rlm_rcode_t common_eap_success(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	rad_assert(0);
	return RLM_MODULE_FAIL;
}

/** SUCCESS-NOTIFICATION state - Continue the state machine after receiving a response to our EAP-Request/(AKA|SIM)-Notification
 *
 * - Call 'recv Success-Notification-Ack { ... }'
 */
static rlm_rcode_t common_success_notification(void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);

	return unlang_module_yield_to_section(request,
					      inst->actions.recv_success_notification_ack,
					      RLM_MODULE_NOOP,
					      common_success_notification_ack_recv_resume,
					      mod_signal,
					      NULL);
}


/** REAUTHENTICATION state - Continue the state machine after receiving a response to our EAP-Request/SIM-Start
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/(SIM|AKA)-Reauthentication - call 'recv Reauthentication-Response { ... }'
 *   - EAP-Response/(SIM|AKA)-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/(SIM|AKA)-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t common_reauthentication(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t			rcode;
	eap_aka_sim_common_conf_t 	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);

	VALUE_PAIR			*subtype_vp = NULL;
	VALUE_PAIR			*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	/*
	 *	These aren't allowed in Reauthentication responses as they don't apply:
	 *
	 *	EAP_AKA_AUTHENTICATION_REJECT	- We didn't provide an AUTN value
	 *	EAP_AKA_SYNCHRONIZATION_FAILURE	- We didn't use new vectors.
	 */
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_SIM_REAUTHENTICATION:
		/*
		 *	AT_COUNTER_TOO_SMALL is handled
		 *      in common_reauthentication_response_process.
		 */
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_reauthentication_response,
						      RLM_MODULE_NOOP,
						      common_reauthentication_response_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request, from_peer);

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      common_client_error_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
		eap_aka_sim_session->allow_encrypted = false;
		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** AKA-CHALLENGE state - Continue the state machine after receiving a response to our EAP-Request/SIM-Challenge
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/AKA-Challenge - call 'recv Challenge-Response { ... }'.
 *   - EAP-Response/AKA-Authentication-Reject - call 'recv Authentication-Reject { ... }'  and after that
 *     send a EAP-Request/SIM-Notification indicating a General Failure.
 *   - EAP-Response/AKA-Syncronization-Failure - call 'recv Syncronization-Failure { ... }'.
 *   - EAP-Response/AKA-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/AKA-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t aka_challenge(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_common_conf_t		*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque, eap_aka_sim_session_t);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*vp;
	VALUE_PAIR		*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_CHALLENGE:
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_challenge_response,
						      RLM_MODULE_NOOP,
						      aka_challenge_response_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_AUTHENTICATION_REJECT:
		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.aka.recv_authentication_reject,
						      RLM_MODULE_NOOP,
						      aka_authentication_reject_recv_resume,
						      mod_signal,
						      NULL);

	case FR_SUBTYPE_VALUE_AKA_SYNCHRONIZATION_FAILURE:
	{
		uint64_t	new_sqn;

		eap_aka_sim_session->allow_encrypted = false;

		vp = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_auts, TAG_ANY);
		if (!vp) {
			REDEBUG("EAP-Response/AKA-Synchronisation-Failure missing AT_AUTS");
		failure:
			return common_failure_notification_enter(inst, request, eap_session);
		}

		switch (fr_aka_sim_umts_resync_from_attrs(&new_sqn,
							  request, vp, &eap_aka_sim_session->keys)) {
		/*
		 *	Add everything back that we'll need in the
		 *	next challenge round.
		 */
		case 0:
			MEM(pair_add_control(&vp, attr_sim_sqn) >= 0);
			vp->vp_uint64 = new_sqn;

			MEM(pair_add_control(&vp, attr_sim_ki) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.auc.ki,
					     sizeof(eap_aka_sim_session->keys.auc.ki), false);

			MEM(pair_add_control(&vp, attr_sim_opc) >= 0);
			fr_pair_value_memcpy(vp, eap_aka_sim_session->keys.auc.opc,
					     sizeof(eap_aka_sim_session->keys.auc.opc), false);
			break;

		case 1:	/* Don't have Ki or OPc so something else will need to deal with this */
			break;

		default:
		case -1:
			goto failure;
		}

		return unlang_module_yield_to_section(request,
						      inst->actions.aka.recv_syncronization_failure,
						      RLM_MODULE_NOOP,
						      aka_synchronization_failure_recv_resume,
						      mod_signal,
						      NULL);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request, from_peer);

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      common_client_error_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
		eap_aka_sim_session->allow_encrypted = false;
		goto failure;
	}
}

/** SIM-CHALLENGE state - Continue the state machine after receiving a response to our EAP-Request/SIM-Challenge
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/SIM-Challenge - call 'recv Challenge-Response { ... }'.
 *   - EAP-Response/SIM-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/SIM-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t sim_challenge(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t		rcode;
	eap_aka_sim_common_conf_t *inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_session_t);

	VALUE_PAIR		*subtype_vp = NULL;
	VALUE_PAIR		*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_SIM_CHALLENGE:
		return unlang_module_yield_to_section(request,
						      inst->actions.recv_challenge_response,
						      RLM_MODULE_NOOP,
						      sim_challenge_response_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request, from_peer);

		eap_aka_sim_session->allow_encrypted = false;

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      common_client_error_recv_resume,
						      mod_signal,
						      NULL);

	/*
	 *	RFC 4186 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);

		eap_aka_sim_session->allow_encrypted = false;

		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** AKA-IDENTITY state - Continue the state machine after receiving a response to our EAP-Request/AKA-Identity
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/AKA-Identity - call either 'recv Identity-Response { ... }' or if
 *     provided 'recv AKA-Identity-Response { ... }'. The idea here is that the
 *     EAP-Identity-Response is really the first round in identity negotiation and
 *     there's no real value distinguishing between the first round and subsequent
 *     rounds, but if users do want to run different logic, then give them a way of
 *     doing that.
 *   - EAP-Response/AKA-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/SIM-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t aka_identity(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t			rcode;
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);
	VALUE_PAIR			*subtype_vp = NULL;
	VALUE_PAIR			*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif

	switch (subtype_vp->vp_uint16) {
	/*
	 *	This is the subtype we expect
	 */
	case FR_SUBTYPE_VALUE_AKA_IDENTITY:
	{
		VALUE_PAIR		*id;
		fr_aka_sim_id_type_t	type;

		id = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity, TAG_ANY);
		if (!id) {
			/*
			 *  9.2.  EAP-Response/Identity
			 *
			 *  The peer sends EAP-Response/Identity in response to a valid
			 *  EAP-Request/Identity from the server.
			 *  The peer MUST include the AT_IDENTITY attribute.  The usage of
			 *  AT_IDENTITY is defined in Section 4.1.
			 */
			REDEBUG("EAP-Response/Identity does not contain AT_IDENTITY");
			return common_failure_notification_enter(inst, request, eap_session);
		}

		/*
		 *	Add ID hint attributes to the request to help
		 *	the user make policy decisions.
		 */
		identity_hint_pairs_add(&type, NULL, request, id->vp_strvalue);
		if (type == AKA_SIM_ID_TYPE_PERMANENT) {
			identity_to_permanent_identity(request, id,
						       eap_aka_sim_session->type,
						       inst->strip_permanent_identity_hint);
		}

		/*
		 *	Update cryptographic identity
		 */
		identity_to_crypto_identity(request, eap_aka_sim_session,
					    (uint8_t const *)id->vp_strvalue, id->vp_length);

		return unlang_module_yield_to_section(request,
						      inst->actions.aka.recv_aka_identity_response?
						      		inst->actions.aka.recv_aka_identity_response:
						      		inst->actions.recv_identity_response,
						      RLM_MODULE_NOOP,
						      aka_identity_response_recv_resume,
						      mod_signal,
						      NULL);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 *
	 *	This can happen in the case of a conservative
	 *	peer, where it refuses to provide the permanent
	 *	identity.
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request, from_peer);

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      common_client_error_recv_resume,
						      mod_signal,
						      NULL);

	default:
		/*
		 *	RFC 4187 says we *MUST* notify, not just
		 *	send an EAP-Failure in this case.
		 */
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
		return common_failure_notification_enter(inst, request, eap_session);
	}
}

/** SIM-START state - Continue the state machine after receiving a response to our EAP-Request/SIM-Start
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/SIM-Start - call either 'recv Identity-Response { ... }' or if
 *     provided 'recv SIM-Start-Response { ... }'. The idea here is that the
 *     EAP-Identity-Response is really the first round in identity negotiation and
 *     there's no real value distinguishing between the first round and subsequent
 *     rounds, but if users do want to run different logic, then give them a way of
 *     doing that.
 *   - EAP-Response/SIM-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/SIM-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
static rlm_rcode_t sim_start(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t			rcode;
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);

	VALUE_PAIR			*subtype_vp = NULL;
	VALUE_PAIR			*from_peer;

	rcode = common_decode(&subtype_vp, &from_peer, inst, request);
	if (rcode != RLM_MODULE_OK) return rcode;

#ifdef __clang_analyzer__
	rad_assert(subtype_vp);
#endif

	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_SIM_START:
	{
		VALUE_PAIR		*id;
		fr_aka_sim_id_type_t	type;

		id = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity, TAG_ANY);
		if (!id) {
			/*
			 *  RFC 4186 Section #9.2
			 *
			 *  The peer sends EAP-Response/SIM/Start in response to a valid
			 *  EAP-Request/SIM/Start from the server.
			 *  The peer MUST include the AT_IDENTITY attribute.  The usage of
			 *  AT_IDENTITY is defined in Section 4.1.
			 */
			REDEBUG("EAP-Response/SIM/Start does not contain AT_IDENTITY");
			return common_failure_notification_enter(inst, request, eap_session);
		}

		/*
		 *	Add ID hint attributes to the request to help
		 *	the user make policy decisions.
		 */
		identity_hint_pairs_add(&type, NULL, request, id->vp_strvalue);
		if (type == AKA_SIM_ID_TYPE_PERMANENT) {
			identity_to_permanent_identity(request, id,
						       eap_aka_sim_session->type,
						       inst->strip_permanent_identity_hint);
		}

		/*
		 *	Update cryptographic identity
		 */
		identity_to_crypto_identity(request, eap_aka_sim_session,
					    (uint8_t const *)id->vp_strvalue, id->vp_length);

		return unlang_module_yield_to_section(request,
						      inst->actions.sim.recv_sim_start_response?
						      		inst->actions.sim.recv_sim_start_response:
						      		inst->actions.recv_identity_response,
						      RLM_MODULE_NOOP,
						      sim_start_response_recv_resume,
						      mod_signal,
						      NULL);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 *
	 *	This can happen in the case of a conservative
	 *	peer, where it refuses to provide the permanent
	 *	identity.
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request, from_peer);

		return unlang_module_yield_to_section(request,
						      inst->actions.recv_client_error,
						      RLM_MODULE_NOOP,
						      common_client_error_recv_resume,
						      mod_signal,
						      NULL);

	default:
		/*
		 *	RFC 4187 says we *MUST* notify, not just
		 *	send an EAP-Failure in this case.
		 */
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
		return common_failure_notification_enter(inst, request, eap_session);
	}
}


/** Resume after 'recv Identity-Response { ... }'
 *
 * - Perform the majority of eap_aka_sim_session_t initialisation.
 * - If 'recv Identity-Response { ... }' returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or continue based on the identity hint byte in the AT_IDENTITY value or EAP-Identity-Response value:
 *   - If identity is a pseudonym, call load pseudonym { ... }.
 *   - If identity is a fastauth identity, enter the REAUTHENTICATE state.
 *   - If identity is a permanent identity, enter the CHALLENGE state.
 */
static rlm_rcode_t common_eap_identity_resume(void *instance, UNUSED void *thread, REQUEST *request, UNUSED void *rctx)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(eap_session->opaque,
										     eap_aka_sim_session_t);
	VALUE_PAIR			*eap_type, *method, *identity_type;
	fr_aka_sim_method_hint_t	running, hinted;
	VALUE_PAIR			*from_peer = request->packet->vps;

	section_rcode_process(inst, request, eap_session, eap_aka_sim_session);

	/*
	 *	Ignore attempts to change the EAP-Type
	 *	This must be done before we enter
	 *	the submodule.
	 */
	eap_type = fr_pair_find_by_da(request->control, attr_eap_type, TAG_ANY);
	if (eap_type) RWDEBUG("Ignoring &control:EAP-Type, this must be set *before* the EAP module is called");

	method = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_method_hint, TAG_ANY);

	/*
	 *	Set default configuration, we may allow these
	 *	to be toggled by attributes later.
	 */
	eap_aka_sim_session->send_result_ind = inst->protected_success;
	eap_aka_sim_session->id_req = AKA_SIM_NO_ID_REQ;	/* Set the default */

	/*
	 *	Unless AKA-Prime is explicitly disabled,
	 *	use it... It has stronger keying, and
	 *	binds authentication to the network.
	 */
	switch (eap_session->type) {
	case FR_EAP_METHOD_SIM:
		RDEBUG2("New EAP-SIM session");

		running = AKA_SIM_METHOD_HINT_SIM;

		eap_aka_sim_session->type = FR_EAP_METHOD_SIM;
		eap_aka_sim_session->mac_md = EVP_sha1();	/* no checkcode support, so no checkcode_md */

		/*
		 *	RFC 5448 makes no mention of being
		 *	able to use this with EAP-SIM, so it's
		 *	permanently disabled for that EAP method.
		 */
		eap_aka_sim_session->send_at_bidding_prefer_prime = false;
		break;

	case FR_EAP_METHOD_AKA:
		RDEBUG2("New EAP-AKA session");

		running = AKA_SIM_METHOD_HINT_AKA;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA;
		eap_aka_sim_session->checkcode_md = eap_aka_sim_session->mac_md = EVP_sha1();
		eap_aka_sim_session->send_at_bidding_prefer_prime = inst->send_at_bidding_prefer_prime;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		RDEBUG2("New EAP-AKA' session");

		running = AKA_SIM_METHOD_HINT_AKA_PRIME;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA_PRIME;
		eap_aka_sim_session->kdf = FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME;
		eap_aka_sim_session->checkcode_md = eap_aka_sim_session->mac_md = EVP_sha256();
		break;

	default:
		rad_assert(0);
	}

	/*
	 *	Warn the user if the selected identity
	 *	does not match what's hinted.
	 */
	if (method) {
		switch (method->vp_uint32) {
		case FR_METHOD_HINT_VALUE_AKA_PRIME:
			hinted = AKA_SIM_METHOD_HINT_AKA_PRIME;
			break;

		case FR_METHOD_HINT_VALUE_AKA:
			hinted = AKA_SIM_METHOD_HINT_AKA;
			break;

		case FR_METHOD_HINT_VALUE_SIM:
			hinted = AKA_SIM_METHOD_HINT_SIM;
			break;

		default:
			hinted = running;
			break;
		}

		if (hinted != running) {
			RWDEBUG("EAP-Identity hints that EAP-%s should be started, but we're attempting EAP-%s",
				fr_table_str_by_value(fr_aka_sim_id_method_table, hinted, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_method_table, running, "<INVALID>"));
		}
	}

	/*
	 *	We always start by requesting any ID
	 *	initially as we can always negotiate down.
	 */
	if (!identity_req_set_by_user(request, eap_aka_sim_session)) {
		if (request->rcode == RLM_MODULE_NOTFOUND) {
			eap_aka_sim_session->id_req = AKA_SIM_ANY_ID_REQ;
			RDEBUG2("Previous section returned (%s), requesting additional identity (%s)",
				fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		} else if (inst->request_identity != AKA_SIM_NO_ID_REQ) {
			eap_aka_sim_session->id_req = inst->request_identity;
			RDEBUG2("Requesting additional identity (%s)",
				fr_table_str_by_value(fr_aka_sim_id_request_table, eap_aka_sim_session->id_req, "<INVALID>"));
		}
	}

	/*
	 *	User may want us to always request an identity
	 *	initially.  The RFCs says this is also the
	 *	better way to operate, as the supplicant
	 *	can 'decorate' the identity in the identity
	 *	response.
	 */
	if (eap_aka_sim_session->id_req != AKA_SIM_NO_ID_REQ) return common_identity_enter(inst, request, eap_session);

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do a fullauth.
	 */
	identity_type = fr_pair_find_by_da(from_peer, attr_eap_aka_sim_identity_type, TAG_ANY);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return common_reauthentication_enter(inst, request, eap_session);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		return unlang_module_yield_to_section(request,
						      inst->actions.load_pseudonym,
						      RLM_MODULE_NOOP,
						      pseudonym_load_resume,
						      mod_signal,
						      (void *)common_challenge_enter);

	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
		/* FALL-THROUGH */

	default:
		break;
	}

	return common_challenge_enter(inst, request, eap_session);
}

/** Zero out the eap_aka_sim_session when we free it to clear knowledge of secret keys
 *
 * @param[in] eap_aka_sim_session	to free.
 * @return 0
 */
static int _eap_aka_sim_session_free(eap_aka_sim_session_t *eap_aka_sim_session)
{
	memset(eap_aka_sim_session, 0, sizeof(*eap_aka_sim_session));
	return 0;
}

/** Enter the EAP-IDENTITY state - State machine entry point
 *
 * - Process the incoming EAP-Identity-Response
 * - Start EAP-SIM/EAP-AKA/EAP-AKA' state machine optionally calling 'recv Identity-Response { ... }'
 */
rlm_rcode_t aka_sim_state_machine_start(void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_aka_sim_common_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_common_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_session_t		*eap_aka_sim_session;
	VALUE_PAIR			*vp;
	fr_aka_sim_id_type_t		type;


	MEM(eap_aka_sim_session = talloc_zero(eap_session, eap_aka_sim_session_t));
	talloc_set_destructor(eap_aka_sim_session, _eap_aka_sim_session_free);

	eap_session->opaque = eap_aka_sim_session;

	/*
	 *	This value doesn't have be strong, but it is
	 *	good if it is different now and then.
	 */
	eap_aka_sim_session->id = (fr_rand() & 0xff);

	/*
	 *	Verify we received an EAP-Response/Identity
	 *	message before the supplicant started sending
	 *	EAP-SIM/AKA/AKA' packets.
	 */
	if (!eap_session->identity) {
		REDEBUG("All SIM or AKA exchanges must begin with a EAP-Response/Identity message");
		return common_failure_notification_enter(inst, request, eap_session);
	}

	/*
	 *	Add ID hint attributes to the request to help
	 *	the user make policy decisions.
	 */

	/*
	 *	Copy the EAP-Identity into and Identity
	 *	attribute to make policies easier.
	 */
	MEM(pair_add_request(&vp, attr_eap_aka_sim_identity) >= 0);
	fr_pair_value_bstrncpy(vp, eap_session->identity, talloc_array_length(eap_session->identity) - 1);

	/*
	 *	Add ID hint attributes to the request to help
	 *	the user make policy decisions.
	 */
	identity_hint_pairs_add(&type, NULL, request, eap_session->identity);
	if (type == AKA_SIM_ID_TYPE_PERMANENT) {
		identity_to_permanent_identity(request, vp, eap_session->type,
					       inst->strip_permanent_identity_hint);
	}

	identity_to_crypto_identity(request, eap_aka_sim_session,
				    (uint8_t const *)eap_session->identity,
				    talloc_array_length(eap_session->identity) - 1);

	/*
	 *	Running the same section as Identity-Response
	 *	makes policies significantly easier.
	 */
	return unlang_module_yield_to_section(request,
					      inst->actions.recv_identity_response,
					      RLM_MODULE_NOOP,
					      common_eap_identity_resume,
					      mod_signal,
					      NULL);
}
