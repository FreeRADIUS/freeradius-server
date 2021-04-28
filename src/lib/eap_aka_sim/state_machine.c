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
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS (legal@networkradius.com)
 */
RCSID("$Id$")
#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/util/table.h>

#include "base.h"
#include "state_machine.h"
#include "attrs.h"

#ifndef EAP_TLS_MPPE_KEY_LEN
#  define EAP_TLS_MPPE_KEY_LEN     32
#endif

#define STATE(_x) static inline unlang_action_t state_ ## _x(rlm_rcode_t *p_result, \
							     module_ctx_t const *mctx, \
							     request_t *request,\
							     eap_aka_sim_session_t *eap_aka_sim_session)
#define STATE_GUARD(_x)	static unlang_action_t guard_ ## _x(rlm_rcode_t *p_result, \
							    module_ctx_t const *mctx, \
							    request_t *request, \
							    eap_aka_sim_session_t *eap_aka_sim_session)

#define RESUME(_x) static inline unlang_action_t resume_ ## _x(rlm_rcode_t *p_result, \
							       module_ctx_t const *mctx, \
							       request_t *request, \
							       void *rctx)

#define STATE_TRANSITION(_x) guard_ ## _x(p_result, mctx, request, eap_aka_sim_session);

#define CALL_SECTION(_x)	unlang_module_yield_to_section(p_result, \
					      		       request, \
							       inst->actions._x, \
							       RLM_MODULE_NOOP, \
							       resume_ ## _x, \
							       mod_signal, \
							       eap_aka_sim_session)

/*
 *	Declare all state and guard functions to
 *	avoid ordering issues.
 */
STATE(eap_failure);
STATE_GUARD(eap_failure);
STATE(common_failure_notification);
STATE_GUARD(common_failure_notification);
STATE(eap_success);
STATE_GUARD(eap_success);
STATE(common_success_notification);
STATE_GUARD(common_success_notification);
STATE(common_reauthentication);
STATE_GUARD(common_reauthentication);
STATE(aka_challenge);
STATE_GUARD(aka_challenge);
STATE(sim_challenge);
STATE_GUARD(sim_challenge);
STATE_GUARD(common_challenge);
STATE(aka_identity);
STATE_GUARD(aka_identity);
STATE(sim_start);
STATE_GUARD(sim_start);
STATE_GUARD(common_identity);
STATE(init);

static fr_table_ptr_ordered_t const aka_sim_state_table[] = {
	{ L("INIT"),			NULL						},

	{ L("EAP-IDENTITY"),		(void *)state_init				},
	{ L("SIM-START"),		(void *)state_sim_start				},
	{ L("AKA-IDENTITY"),		(void *)state_aka_identity			},

	{ L("SIM-CHALLENGE"),		(void *)state_sim_challenge			},
	{ L("AKA-CHALLENGE"),		(void *)state_aka_challenge			},

	{ L("SUCCESS-NOTIFICATION"),	(void *)state_common_success_notification 	},
	{ L("FAILURE-NOTIFICATION"),	(void *)state_common_failure_notification	},

	{ L("REAUTHENTICATION"),	(void *)state_common_reauthentication		},

	{ L("EAP-SUCCESS"),		(void *)state_eap_success			},
	{ L("EAP-FAILURE"),		(void *)state_eap_failure			}
};
static size_t aka_sim_state_table_len = NUM_ELEMENTS(aka_sim_state_table);

/** Cancel a call to a submodule
 *
 * @param[in] mctx	UNUSED.
 * @param[in] request	The current request.
 * @param[in] rctx	the eap_session_t
 * @param[in] action	to perform.
 */
static void mod_signal(UNUSED module_ctx_t const *mctx, request_t *request, void *rctx,
		       fr_state_signal_t action)
{
	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Request cancelled - Destroying session");

	/*
	 *	Remove data from the request to
	 *	avoid double free.
	 */
	if (!fr_cond_assert(request_data_get(request, (void *)eap_aka_sim_state_machine_process, 0) == rctx)) return;

	TALLOC_FREE(rctx);
}

/** Warn the user that the rcode they provided is being ignored in this section
 *
 */
#define SECTION_RCODE_IGNORED \
do { \
	switch (unlang_interpret_stack_result(request)) { \
	case RLM_MODULE_USER_SECTION_REJECT: \
		RWDEBUG("Ignoring rcode (%s)", \
			fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<invalid>")); \
		break; \
	default: \
		break; \
	} \
} while(0)

/** Trigger a state transition to FAILURE-NOTIFICATION if the section returned a failure code
 *
 */
#define SECTION_RCODE_PROCESS \
do { \
	if (after_authentication(eap_aka_sim_session)) { \
		switch (unlang_interpret_stack_result(request)) { \
		case RLM_MODULE_REJECT:	 \
		case RLM_MODULE_DISALLOW: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_TEMPORARILY_DENIED; \
			return STATE_TRANSITION(common_failure_notification); \
		case RLM_MODULE_NOTFOUND: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_NOT_SUBSCRIBED; \
			return STATE_TRANSITION(common_failure_notification); \
		case RLM_MODULE_INVALID: \
		case RLM_MODULE_FAIL: \
			eap_aka_sim_session->failure_type = FR_NOTIFICATION_VALUE_GENERAL_FAILURE_AFTER_AUTHENTICATION;\
			return STATE_TRANSITION(common_failure_notification); \
		default: \
			break; \
		} \
	} else { \
		switch (unlang_interpret_stack_result(request)) { \
		case RLM_MODULE_USER_SECTION_REJECT: \
			REDEBUG("Section rcode (%s) indicates we should reject the user", \
		        	fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>")); \
			return STATE_TRANSITION(common_failure_notification); \
		default: \
			break; \
		} \
	} \
} while(0)

/** Print debugging information, and write new state to eap_aka_sim_session->state
 *
 */
static inline CC_HINT(always_inline) void state_set(request_t *request,
						    eap_aka_sim_session_t *eap_aka_sim_session,
						    eap_aka_sim_state_t new_state)
{
	eap_aka_sim_state_t	old_state = eap_aka_sim_session->state;

	if (new_state != old_state) {
		RDEBUG2("Changed state %s -> %s",
			fr_table_str_by_value(aka_sim_state_table, (void *)old_state, "<unknown>"),
			fr_table_str_by_value(aka_sim_state_table, (void *)new_state, "<unknown>"));
	} else {
		RDEBUG2("Reentering state %s",
			fr_table_str_by_value(aka_sim_state_table, (void *)old_state, "<unknown>"));
	}

	eap_aka_sim_session->state = new_state;
}
#define STATE_SET(_new_state) state_set(request, eap_aka_sim_session, state_ ## _new_state)

/** Determine if we're after authentication
 *
 */
static inline CC_HINT(always_inline) bool after_authentication(eap_aka_sim_session_t *eap_aka_sim_session)
{
	return eap_aka_sim_session->challenge_success || eap_aka_sim_session->reauthentication_success;
}

/** Print out the error the client returned
 *
 */
static inline CC_HINT(always_inline) void client_error_debug(request_t *request)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_client_error_code, 0);
	if (!vp) {
		REDEBUG("Peer has not supplied a AT_ERROR_CODE");
	} else {
		REDEBUG("Peer rejected request with error: %i (%pV)", vp->vp_uint16, &vp->data);
	}
}

/** Sync up what identity we're requesting with attributes in the reply
 *
 */
static bool identity_req_set_by_user(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	fr_pair_t 	*vp, *prev;
	bool		set_by_user = false;

	/*
	 *	Check if the user included any of the
	 *      ID req attributes.  If they did, use
	 *	them to inform what we do next, and
	 *	then delete them so they don't screw
	 *	up any of the other code.
	 */
	for (vp = fr_pair_list_head(&request->reply_pairs);
	     vp;
	     vp = fr_pair_list_next(&request->reply_pairs, vp)) {
		if (vp->da == attr_eap_aka_sim_permanent_id_req) {
			eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
		found:
			set_by_user = true;
			RDEBUG2("Previous section added &reply.%pP, will request additional identity", vp);
			prev = fr_pair_delete(&request->reply_pairs, vp);
			vp = prev;
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
				    request_t *request, char const *identity)
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
		fr_pair_t *vp = NULL;

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
			fr_assert(0);
		}
	}

	/*
	 *	Map the output from the generic ID parser
	 *	function to specific EAP-AKA internal
	 *	attributes in the subrequest.
	 */
	if (method != AKA_SIM_METHOD_HINT_UNKNOWN) {
		fr_pair_t *vp = NULL;

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
			fr_assert(0);
		}
	}

	if (type_p) *type_p = type;
	if (method_p) *method_p = method;
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
static int identity_req_pairs_add(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	fr_pair_t *vp;

	switch (eap_aka_sim_session->id_req) {
	case AKA_SIM_ANY_ID_REQ:
		if (eap_aka_sim_session->last_id_req != AKA_SIM_NO_ID_REQ) {
		id_out_of_order:
			REDEBUG("Cannot send %s, already sent %s",
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->id_req, "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->last_id_req, "<INVALID>"));
			return -1;
		}
		MEM(pair_append_reply(&vp, attr_eap_aka_sim_any_id_req) >= 0);
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
		MEM(pair_append_reply(&vp, attr_eap_aka_sim_fullauth_id_req) >= 0);
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
		MEM(pair_append_reply(&vp, attr_eap_aka_sim_permanent_id_req) >= 0);
		vp->vp_bool = true;
		break;

	default:
		fr_assert(0);
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
 * &session-state.Permanent-Identity attribute.
 *
 * @param[in] request		The current request.
 * @param[in] in		current identity.
 * @param[in] eap_type		The current eap_type.
 * @param[in] strip_hint	Whether to strip the hint byte off the permanent identity
 */
static int identity_to_permanent_identity(request_t *request, fr_pair_t *in, eap_type_t eap_type, bool strip_hint)
{
	fr_aka_sim_id_type_t		our_type;
	fr_aka_sim_method_hint_t	our_method, expected_method;
	fr_pair_t			*vp;

	if (in->vp_length == 0) {
		RDEBUG2("Not processing zero length identity");
		return -1;
	}

	/*
	 *	Not requested to strip hint, don't do anything
	 *	fancy, just copy Identity -> Permanent-Identity.
	 */
	if (!strip_hint) {
		MEM(fr_pair_update_by_da(request->session_state_ctx, &vp,
					 &request->session_state_pairs, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrndup(vp, in->vp_strvalue, in->vp_length, true);
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
		MEM(fr_pair_update_by_da(request->session_state_ctx, &vp,
					 &request->session_state_pairs, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrndup(vp, in->vp_strvalue, in->vp_length, true);

		RDEBUG2("%s has incorrect hint byte, expected '%c', got '%c'.  "
			"'hint' byte not stripped",
			attr_eap_aka_sim_permanent_identity->name,
			fr_aka_sim_hint_byte(AKA_SIM_ID_TYPE_PERMANENT, expected_method),
			fr_aka_sim_hint_byte(our_type, our_method));
		RINDENT();
		RDEBUG2("&session-state.%pP", vp);
		REXDENT();
	} else {
		/*
		 *	To get here the identity must be >= 1 and must have
		 *      had the expected hint byte.
		 *
		 *	Strip off the hint byte, and then add the permanent
		 *	identity to the output list.
		 */
		MEM(fr_pair_update_by_da(request->session_state_ctx, &vp,
					 &request->session_state_pairs, attr_eap_aka_sim_permanent_identity) >= 0);
		fr_pair_value_bstrndup(vp, in->vp_strvalue + 1, in->vp_length - 1, true);

		RDEBUG2("Stripping 'hint' byte from %s", attr_eap_aka_sim_permanent_identity->name);
		RINDENT();
		RDEBUG2("&session-state.%pP", vp);
		REXDENT();
	}

	return 0;
}

/** Check &control.checkcode matches &reply.checkcode
 *
 * @param[in] request	The current request.
 * @return
 *	- 1 if the check was skipped.
 *	- 0 if the check was successful.
 *	- -1 if the check failed.
 */
static int checkcode_validate(request_t *request)
{
	fr_pair_t		*peer_checkcode, *our_checkcode;
	/*
	 *	Checkcode validation
	 *
	 *	The actual cryptographic calculations are
	 *	done by the calling module, we just check
	 *      the result.
	 */
	our_checkcode = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_checkcode, 0);
	if (our_checkcode) {
		/*
		 *	If the peer doesn't include a checkcode then that
		 *	means they don't support it, and we can't validate
		 *	their view of the identity packets.
		 */
		peer_checkcode = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_checkcode, 0);
		if (peer_checkcode) {
			if (fr_pair_cmp(peer_checkcode, our_checkcode) == 0) {
				RDEBUG2("Received AT_CHECKCODE matches calculated AT_CHECKCODE");
				return 0;
			} else {
				REDEBUG("Received AT_CHECKCODE does not match calculated AT_CHECKCODE");
				RHEXDUMP_INLINE2(peer_checkcode->vp_octets, peer_checkcode->vp_length, "Received");
				RHEXDUMP_INLINE2(our_checkcode->vp_octets, our_checkcode->vp_length, "Expected");
				return -1;
			}
		/*
		 *	Only print something if we calculated a checkcode
		 */
		} else {
			RDEBUG2("Peer didn't include AT_CHECKCODE, skipping checkcode validation");
		}
	}
	return 1;
}

/** Check &control.mac matches &reply.mac
 *
 * @param[in] request	The current request.
 * @return
 *	- 0 if the check was successful.
 *	- -1 if the check failed.
 */
static int mac_validate(request_t *request)
{
	fr_pair_t		*peer_mac, *our_mac;
	/*
	 *	mac validation
	 *
	 *	The actual cryptographic calculations are
	 *	done by the calling module, we just check
	 *      the result.
	 */
	our_mac = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_mac, 0);
	if (!our_mac) {
		REDEBUG("Missing &control.%s", attr_eap_aka_sim_mac->name);
		return -1;

	}

	/*
	 *	If the peer doesn't include a mac then that
	 *	means they don't support it, and we can't validate
	 *	their view of the identity packets.
	 */
	peer_mac = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_mac, 0);
	if (!peer_mac) {
		REDEBUG("Peer didn't include AT_MAC");
		return -1;
	}

	if (fr_pair_cmp(peer_mac, our_mac) != 0) {
		REDEBUG("Received AT_MAC does not match calculated AT_MAC");
		RHEXDUMP_INLINE2(peer_mac->vp_octets, peer_mac->vp_length, "Received");
		RHEXDUMP_INLINE2(our_mac->vp_octets, our_mac->vp_length, "Expected");
		return -1;
	}

	RDEBUG2("Received AT_MAC matches calculated AT_MAC");
	return 0;
}

/** Set the crypto identity from a received identity
 *
 */
static void crypto_identity_set(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session,
				uint8_t const *identity, size_t len)
{
	RDEBUG3("Setting cryptographic identity to \"%pV\"", fr_box_strvalue_len((char const *)identity, len));

	talloc_free(eap_aka_sim_session->keys.identity);
	eap_aka_sim_session->keys.identity_len = len;
	MEM(eap_aka_sim_session->keys.identity = talloc_memdup(eap_aka_sim_session, identity, len));

}

/** Resume after 'store session { ... }'
 *
 */
RESUME(store_session)
{
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	switch (unlang_interpret_stack_result(request)) {
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

	return eap_aka_sim_session->next(p_result, mctx, request, eap_aka_sim_session);
}

/** Resume after 'store pseudonym { ... }'
 *
 * Stores session data if required.
 */
RESUME(store_pseudonym)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t			*vp;
	fr_pair_t			*new;

	switch (unlang_interpret_stack_result(request)) {
	/*
	 *	Store failed.  Don't send pseudonym
	 */
	case RLM_MODULE_USER_SECTION_REJECT:
		pair_delete_reply(attr_eap_aka_sim_next_pseudonym);
		break;

	default:
		break;
	}

	unlang_interpret_stack_result_set(request, RLM_MODULE_NOOP); /* Needed because we may call resume functions directly */

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	/*
	 *	Generate fast-reauth data if we
	 *	find a next_reauth_id pair in the
	 *	reply list.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_next_reauth_id, 0);
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

			fr_value_box_bstrdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_session_id);
		fr_pair_value_memdup(new, (uint8_t const *)vp->vp_strvalue, vp->vp_length, vp->vp_tainted);

		MEM(eap_aka_sim_session->fastauth_sent = talloc_bstrndup(eap_aka_sim_session,
									 vp->vp_strvalue, vp->vp_length));

		switch (eap_aka_sim_session->type) {
		/*
		 *	AKA and SIM use the original MK for session resumption.
		 */
		case FR_EAP_METHOD_SIM:
		case FR_EAP_METHOD_AKA:
			fr_assert(eap_aka_sim_session->keys.mk_len >= AKA_SIM_MK_SIZE);

			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memdup(vp,
					     eap_aka_sim_session->keys.mk, eap_aka_sim_session->keys.mk_len,
					     false);
			break;
		/*
		 *	AKA' KDF 1 generates an additional key k_re
		 *	which is used for reauthentication instead
		 *	of the MK.
		 */
		case FR_EAP_METHOD_AKA_PRIME:
			fr_assert(eap_aka_sim_session->keys.mk_len >= AKA_PRIME_MK_REAUTH_SIZE);

			MEM(pair_update_session_state(&vp, attr_session_data) >= 0);
			fr_pair_value_memdup(vp,
					     eap_aka_sim_session->keys.mk, AKA_PRIME_MK_REAUTH_SIZE,
					     false);	/* truncates */
			break;

		default:
			fr_assert(0);
			break;
		}

		/*
		 *	If the counter already exists in session
		 *	state increment by 1, otherwise, add the
		 *	attribute and set to zero.
		 */
		vp = fr_pair_find_by_da(&request->session_state_pairs, attr_eap_aka_sim_counter, 0);
		if (vp) {
			vp->vp_uint16++;
		/*
		 *	Will get incremented by 1 in
		 *	reauthentication_send, so when
		 *	used, it'll be 1 (as per the standard).
		 */
		} else {
			MEM(pair_append_session_state(&vp, attr_eap_aka_sim_counter) >= 0);
			vp->vp_uint16 = 0;
		}

		return CALL_SECTION(store_session);
	}

	/*
	 *	We didn't store any fast-reauth data
	 */
done:
	return eap_aka_sim_session->next(p_result, mctx, request, eap_aka_sim_session);
}

/** Implements a set of states for storing pseudonym and fastauth identities
 *
 * At the end of challenge or reauthentication rounds, the user may have specified
 * a pseudonym and fastauth identity to return to the supplicant.
 *
 * Call the appropriate sections to persist those values.
 *
 * @param[out] p_result			Result of calling the module.
 * @param[in] mctx			Module calling ctx.
 * @param[in] request			the current request.
 * @param[in] eap_aka_sim_session	the EAP session
 * @param[in] next			function to call after storing sessions and pseudonyms.
 */
static unlang_action_t session_and_pseudonym_store(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						   request_t *request,
						   eap_aka_sim_session_t *eap_aka_sim_session,
						   eap_aka_sim_next_t next)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*vp;
	fr_pair_t			*new;

	if (!fr_cond_assert(next)) return STATE_TRANSITION(common_failure_notification);

	eap_aka_sim_session->next = next;

	unlang_interpret_stack_result_set(request, RLM_MODULE_NOOP); /* Needed because we may call resume functions directly */

	vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_next_pseudonym, 0);
	if (vp) {
		/*
		 *	Generate a random pseudonym string
		 */
		if (vp->vp_length == 0) {
			char *identity;

			if (!inst->ephemeral_id_length) {
				RWDEBUG("Found empty Pseudonym-Id, and told not to generate one.  "
					"Skipping store pseudonym { ... } section");

				return resume_store_pseudonym(p_result, mctx, request, eap_aka_sim_session);
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
			fr_value_box_bstrdup_buffer_shallow(NULL, &vp->data, NULL, identity, false);
		}
		pair_update_request(&new, attr_eap_aka_sim_next_pseudonym);
		fr_pair_value_copy(new, vp);

		MEM(eap_aka_sim_session->pseudonym_sent = talloc_bstrndup(eap_aka_sim_session,
									  vp->vp_strvalue, vp->vp_length));
		return CALL_SECTION(store_pseudonym);
	}

	return resume_store_pseudonym(p_result, mctx, request, eap_aka_sim_session);
}

/** Resume after 'clear session { ... }'
 *
 */
RESUME(clear_session)
{
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	pair_delete_request(attr_session_id);

	return eap_aka_sim_session->next(p_result, mctx, request, eap_aka_sim_session);
}

/** Resume after 'clear pseudonym { ... }'
 *
 */
RESUME(clear_pseudonym)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	pair_delete_request(attr_eap_aka_sim_next_pseudonym);

	/*
	 *	Clear session (if one was stored)
	 */
	if (eap_aka_sim_session->fastauth_sent) {
		fr_pair_t *vp;

		pair_delete_request(attr_session_id);

		MEM(pair_update_request(&vp, attr_session_id) >= 0);
		fr_value_box_memdup(vp, &vp->data, NULL,
				    (uint8_t *)eap_aka_sim_session->fastauth_sent,
				    talloc_array_length(eap_aka_sim_session->fastauth_sent) - 1, true);
		TALLOC_FREE(eap_aka_sim_session->fastauth_sent);

		return CALL_SECTION(clear_session);
	}

	return eap_aka_sim_session->next(p_result, mctx, request, eap_aka_sim_session);
}

/** Implements a set of states for clearing out pseudonym and fastauth identities
 *
 * If either a Challenge round or Reauthentication round fail, we need to clear
 * any identities that were provided during those rounds, as the supplicant
 * will have discarded them.
 *
 * @param[out] p_result			Result of calling the module.
 * @param[in] mctx			module calling ctx.
 * @param[in] request			the current request.
 * @param[in] eap_aka_sim_session	the current EAP session
 * @param[in] next			function to call after clearing sessions and pseudonyms.
 */
static unlang_action_t session_and_pseudonym_clear(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						   request_t *request,
						   eap_aka_sim_session_t *eap_aka_sim_session,
						   eap_aka_sim_next_t next)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	if (!fr_cond_assert(next)) return STATE_TRANSITION(common_failure_notification);

	eap_aka_sim_session->next = next;

	unlang_interpret_stack_result_set(request, RLM_MODULE_NOOP); /* Needed because we may call resume functions directly */

	/*
	 *	Clear out pseudonyms (if we sent one)
	 */
	if (eap_aka_sim_session->pseudonym_sent) {
		fr_pair_t *vp;

		MEM(pair_update_request(&vp, attr_eap_aka_sim_next_pseudonym) >= 0);
		fr_value_box_bstrdup_buffer(vp, &vp->data, NULL, eap_aka_sim_session->pseudonym_sent, true);
		TALLOC_FREE(eap_aka_sim_session->pseudonym_sent);

		return CALL_SECTION(clear_pseudonym);
	}

	return resume_clear_pseudonym(p_result, mctx, request, eap_aka_sim_session);
}

/** Export EAP-SIM/AKA['] attributes
 *
 * Makes any internal data available as attributes in the response.
 * This allows test frameworks and the encoder to access any data they need without
 * needing to look at the eap_aka_session_t.
 */
static void common_reply(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session, uint16_t subtype)
{
	fr_pair_t		*vp = NULL, *subtype_vp;

	/*
	 *	Set the subtype to identity request
	 */
	MEM(pair_update_reply(&subtype_vp, attr_eap_aka_sim_subtype) >= 0);
	subtype_vp->vp_uint16 = subtype;

	if (!eap_aka_sim_session->allow_encrypted) {
		while ((vp = fr_pair_list_next(&request->reply_pairs, vp))) {
			if (fr_dict_attr_common_parent(attr_eap_aka_sim_encr_data, vp->da, true)) {
				RWDEBUG("Silently discarding &reply.%pP: Encrypted attributes not "
					"allowed in this round", vp);
				vp = fr_pair_delete(&request->reply_pairs, vp);
				continue;
			}
		}
	}
}

static void CC_HINT(nonnull(1,2))
common_crypto_export(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session,
		     uint8_t const *hmac_extra_request, size_t hmac_extra_request_len,
		     uint8_t const *hmac_extra_response, size_t hmac_extra_response_len)
{
	fr_pair_t *vp;

	/*
	 *	Export keying material necessary for
	 *	the encoder to encrypt and sign
	 *	packets.
	 */
	if (hmac_extra_request && hmac_extra_request_len) {
		MEM(pair_update_control(&vp, attr_eap_aka_sim_hmac_extra_request) >= 0);
		MEM(fr_pair_value_memdup(vp, hmac_extra_request, hmac_extra_request_len, true) == 0);
	}

	if (hmac_extra_response && hmac_extra_response_len) {
		MEM(pair_update_control(&vp, attr_eap_aka_sim_hmac_extra_response) >= 0);
		MEM(fr_pair_value_memdup(vp, hmac_extra_response, hmac_extra_response_len, true) == 0);
	}

	MEM(pair_update_control(&vp, attr_eap_aka_sim_k_aut) >= 0);
	MEM(fr_pair_value_memdup(vp,
				 eap_aka_sim_session->keys.k_aut,
				 eap_aka_sim_session->keys.k_aut_len,
				 true) == 0);

	MEM(pair_update_control(&vp, attr_eap_aka_sim_k_encr) >= 0);
	MEM(fr_pair_value_memdup(vp,
				 eap_aka_sim_session->keys.k_encr,
				 sizeof(eap_aka_sim_session->keys.k_encr),
				 true) == 0);
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static unlang_action_t common_reauthentication_request_send(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
							    request_t *request,
							    eap_aka_sim_session_t *eap_aka_sim_session)
{
	/*
	 *	Return reply attributes - AT_IV is handled automatically by the encoder
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_AKA_SIM_REAUTHENTICATION);

	/*
	 *	9.5.  EAP-Request/SIM/Re-authentication
	 *
	 *   	AT_MAC MUST be included.  No message-specific data is included in the
   	 *	MAC calculation.  See Section 10.14.
    	 *
    	 *	9.6.  EAP-Response/SIM/Re-authentication
    	 *
   	 *	The AT_MAC attribute MUST be included.  For
	 *	EAP-Response/SIM/Re-authentication, the MAC code is calculated over
	 *	the following data: EAP packet| NONCE_S
	 *
	 *	9.7.  EAP-Request/AKA-Reauthentication
	 *
	 *	The AT_MAC attribute MUST be included.  No message-specific data is
  	 *	included in the MAC calculation, see Section 10.15.
  	 *
  	 *	9.8.  EAP-Response/AKA-Reauthentication
	 *
   	 *	The AT_MAC attribute MUST be included.  For
   	 *	EAP-Response/AKA-Reauthentication, the MAC code is calculated over
   	 *	the following data:  EAP packet| NONCE_S.
	 */
	common_crypto_export(request, eap_aka_sim_session,
			     NULL, 0,
			     eap_aka_sim_session->keys.reauth.nonce_s,
			     sizeof(eap_aka_sim_session->keys.reauth.nonce_s));

	RETURN_MODULE_HANDLED;
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static unlang_action_t aka_challenge_request_send(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
						  request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_AKA_CHALLENGE);

	/*
	 *	9.3.  EAP-Request/AKA-Challenge
	 *
	 *	AT_MAC MUST be included.  In EAP-Request/AKA-Challenge, there is no
	 *	message-specific data covered by the MAC, see Section 10.15.
  	 *
  	 *	9.4.  EAP-Response/AKA-Challenge
	 *
	 *	The AT_MAC attribute MUST be included.  In
	 *	EAP-Response/AKA-Challenge, there is no message-specific data covered
	 *	by the MAC, see Section 10.15.
	 */
	common_crypto_export(request, eap_aka_sim_session, NULL, 0, NULL, 0);

	RETURN_MODULE_HANDLED;
}

/** Called after 'store session { ... }' and 'store pseudonym { ... }'
 *
 */
static unlang_action_t sim_challenge_request_send(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
						  request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	uint8_t			sres_cat[AKA_SIM_VECTOR_GSM_SRES_SIZE * 3];
	uint8_t			*p = sres_cat;

	/*
	 *	Encode the packet - AT_IV is handled automatically
	 *	by the encoder.
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_SIM_CHALLENGE);

	memcpy(p, eap_aka_sim_session->keys.gsm.vector[0].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[1].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[2].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);

	/*
	 *	9.3.  EAP-Request/SIM/Challenge
	 *
	 *	The AT_MAC attribute MUST be included.  For
	 *	EAP-Request/SIM/Challenge, the MAC code is calculated over the
	 *	following data: EAP packet| NONCE_MT
	 *
	 *	9.4.  EAP-Response/SIM/Challenge
	 *
	 *      The AT_MAC attribute MUST be included.  For EAP-
	 *	Response/SIM/Challenge, the MAC code is calculated over the following
	 *	data: EAP packet| n*SRES
	 */
	common_crypto_export(request, eap_aka_sim_session,
			     eap_aka_sim_session->keys.gsm.nonce_mt, sizeof(eap_aka_sim_session->keys.gsm.nonce_mt),
			     sres_cat, sizeof(sres_cat));

	RETURN_MODULE_HANDLED;
}

/** Helper function to check for the presence and length of AT_SELECTED_VERSION and copy its value into the keys structure
 *
 * Also checks the version matches one of the ones we advertised in our version list,
 * which is a bit redundant seeing as there's only one version of EAP-SIM.
 */
static int sim_start_selected_version_check(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	fr_pair_t		*selected_version_vp;

	/*
	 *	Check that we got an AT_SELECTED_VERSION
	 */
	selected_version_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_selected_version, 0);
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
static int sim_start_nonce_mt_check(request_t *request, eap_aka_sim_session_t *eap_aka_sim_session)
{
	fr_pair_t	*nonce_mt_vp;

	/*
	 *	Copy nonce_mt to the keying material
	 */
	nonce_mt_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_nonce_mt, 0);
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

/** FAILURE state - State machine exit point after sending EAP-Failure
 *
 * Should never actually be called. Is just a placeholder function to represent the FAILURE
 * termination state.  Could equally be a NULL pointer, but then on a logic error
 * we'd get a SEGV instead of a more friendly assert/failure rcode.
 */
STATE(eap_failure)
{
	if (!fr_cond_assert(request && mctx && eap_aka_sim_session)) RETURN_MODULE_FAIL;	/* unused args */

	fr_assert(0);	/* Should never actually be called */

	RETURN_MODULE_FAIL;
}

/** Resume after 'send EAP-Failure { ... }'
 *
 */
RESUME(send_eap_failure)
{
	if (!fr_cond_assert(mctx && rctx)) RETURN_MODULE_FAIL;	/* unused args */

	SECTION_RCODE_IGNORED;

	RDEBUG2("Sending EAP-Failure");

	RETURN_MODULE_REJECT;
}

/** Enter EAP-FAILURE state
 *
 */
STATE_GUARD(eap_failure)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply_pairs);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(p_result, mctx,
						   request, eap_aka_sim_session, guard_eap_failure);
						   /* come back when we're done */
	}

	STATE_SET(eap_failure);

	return CALL_SECTION(send_eap_failure);
}

/** Resume after 'recv Failure-Notification-Ack { ... }'
 *
 * - Enter the EAP-FAILURE state.
 */
RESUME(recv_common_failure_notification_ack)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_IGNORED;

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return STATE_TRANSITION(eap_failure);
}

/** FAILURE-NOTIFICATION state - Continue the state machine after receiving a response to our EAP-Request/(AKA|SIM)-Notification
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/SIM-Client-Error - Call 'recv Failure-Notification-Ack { ... }'
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
STATE(common_failure_notification)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*subtype_vp = NULL;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) goto fail;

	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION:
		RDEBUG2("Failure-Notification ACKed, sending EAP-Failure");
		return CALL_SECTION(recv_common_failure_notification_ack);

	default:
	fail:
		RWDEBUG("Failure-Notification not ACKed correctly, sending EAP-Failure anyway");
		return STATE_TRANSITION(eap_failure)
	}
}

/** Resume after 'send Failure-Notification { ... }'
 *
 * Ignores return code from send Failure-Notification { ... } section.
 */
RESUME(send_common_failure_notification)
{
	fr_pair_t		*vp, *notification_vp;
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx,
									     eap_aka_sim_session_t);

	if (!fr_cond_assert(mctx)) RETURN_MODULE_FAIL;	/* quiet unused warning */

	SECTION_RCODE_IGNORED;

	/*
	 *	Free anything we were going to send out...
	 */
	fr_pair_list_free(&request->reply_pairs);

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
	notification_vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_notification, 0);

	/*
	 *	Change the failure notification depending where
	 *	we are in the eap_aka_state machine.
	 */
	if (after_authentication(eap_aka_sim_session)) {
		if (!notification_vp) {
			MEM(pair_append_reply(&notification_vp, attr_eap_aka_sim_notification) >= 0);
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
		fr_pair_value_memdup(vp, NULL, 0, false);
	} else {
		/*
		 *	Only valid code is general failure
		 */
		if (!notification_vp) {
			MEM(pair_append_reply(&notification_vp, attr_eap_aka_sim_notification) >= 0);
			notification_vp->vp_uint16 = FR_NOTIFICATION_VALUE_GENERAL_FAILURE;
		/*
		 *	User supplied failure code
		 */
		} else {
			notification_vp->vp_uint16 |= 0x4000;	/* Set phase bit */
		}
	}
	notification_vp->vp_uint16 &= ~0x8000;		/* In both cases success bit should be low */

	/*
	 *	Send a response
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION);

	RETURN_MODULE_HANDLED;
}

/** Enter the FAILURE-NOTIFICATION state
 *
 */
STATE_GUARD(common_failure_notification)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	/*
	 *	If we're failing, then any identities
	 *	we sent are now invalid.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(p_result, mctx, request, eap_aka_sim_session,
						   guard_common_failure_notification); /* come back when we're done */
	}

	/*
	 *	We've already sent a failure notification
	 *	Now we just fail as it means something
	 *	went wrong processing the ACK or we got
	 *	garbage from the supplicant.
	 */
	if (eap_aka_sim_session->state == state_common_failure_notification) {
		return STATE_TRANSITION(eap_failure);
	}

	/*
	 *	Otherwise just transition as normal...
	 */
	STATE_SET(common_failure_notification);

	return CALL_SECTION(send_common_failure_notification);
}

/** SUCCESS state - State machine exit point after sending EAP-Success
 *
 * Should never actually be called. Is just a placeholder function to represent the SUCCESS
 * termination state.  Could equally be a NULL pointer, but then on a logic error
 * we'd get a SEGV instead of a more friendly assert/failure rcode.
 */
STATE(eap_success)
{
	if (!fr_cond_assert(request && mctx && eap_aka_sim_session)) RETURN_MODULE_FAIL;	/* unused args */

	fr_assert(0);	/* Should never actually be called */

	RETURN_MODULE_FAIL;
}

/** Resume after 'send EAP-Success { ... }'
 *
 * Add MPPE keys to the request being sent to the supplicant
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * attributes derived from the MSK.
 */
RESUME(send_eap_success)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	uint8_t			*p;

	RDEBUG2("Sending EAP-Success");

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
		switch (unlang_interpret_stack_result(request)) {
		case RLM_MODULE_USER_SECTION_REJECT:
			RWDEBUG("Ignoring rcode (%s) from send EAP-Success { ... } "
				"as we already sent a Success-Notification",
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<invalid>"));
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
		SECTION_RCODE_PROCESS;
	}

	RDEBUG2("Adding attributes for MSK");
	p = eap_aka_sim_session->keys.msk;
	eap_add_reply(request->parent, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(request->parent, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	RETURN_MODULE_OK;
}

/** Enter EAP-SUCCESS state
 *
 */
STATE_GUARD(eap_success)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	STATE_SET(eap_success);

	return CALL_SECTION(send_eap_success);
}

/** Resume after 'recv Success-Notification-Ack { ... }'
 *
 * - Enter the EAP-SUCCESS state.
 */
RESUME(recv_common_success_notification_ack)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_IGNORED;

	/*
	 *	RFC 4187 says we ignore the contents of the
	 *	next packet after we send our success notification
	 *	and always send a success.
	 */
	return STATE_TRANSITION(eap_success);
}

/** SUCCESS-NOTIFICATION state - Continue the state machine after receiving a response to our EAP-Request/(AKA|SIM)-Notification
 *
 * - Call 'recv Success-Notification-Ack { ... }'
 */
STATE(common_success_notification)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	/*
	 *  	Because the server uses the AT_NOTIFICATION code "Success" (32768) to
	 *	indicate that the EAP exchange has completed successfully, the EAP
	 *	exchange cannot fail when the server processes the EAP-AKA response
	 *	to this notification.  Hence, the server MUST ignore the contents of
	 *	the EAP-AKA response it receives to the EAP-Request/AKA-Notification
	 *	with this code.  Regardless of the contents of the EAP-AKA response,
	 *	the server MUST send EAP-Success as the next packet.
   	 */
	return CALL_SECTION(recv_common_success_notification_ack);
}

/** Resume after 'send Success-Notification { ... }'
 *
 */
RESUME(send_common_success_notification)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t		*vp;

	SECTION_RCODE_PROCESS;

	if (!fr_cond_assert(after_authentication(eap_aka_sim_session))) RETURN_MODULE_FAIL;

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
	fr_pair_value_memdup(vp, NULL, 0, false);

	/*
	 *	Return reply attributes
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_AKA_SIM_NOTIFICATION);

	RETURN_MODULE_HANDLED;
}

/** Enter the SUCCESS-NOTIFICATION state
 *
 */
STATE_GUARD(common_success_notification)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	STATE_SET(common_success_notification);

	return CALL_SECTION(send_common_success_notification);
}

/** Resume after 'recv Client-Error { ... }'
 *
 * - Enter the EAP-FAILURE state.
 */
RESUME(recv_common_client_error)
{
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_IGNORED;

	return STATE_TRANSITION(eap_failure);
}

/** Resume after 'recv Reauthentication-Response { ... }'
 *
 * - If 'recv Reauthentication-Response { ... }' returned a failure
 *   rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call the EAP-Request/Reauthentication-Response function to act on the
 *   contents of the response.
 */
RESUME(recv_common_reauthentication_response)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_PROCESS;

	/*
	 *	Validate mac
	 */
	if (mac_validate(request) < 0) {
	failure:
		return STATE_TRANSITION(common_failure_notification);
	}

	/*
	 *	Validate the checkcode
	 */
	if (checkcode_validate(request) < 0) goto failure;

	/*
	 *	Check to see if the supplicant sent
	 *	AT_COUNTER_TOO_SMALL, if they did then we
	 *	clear out reauth information and enter the
	 *	challenge state.
	 */
	if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_counter_too_small, 0)) {
		RWDEBUG("Peer sent AT_COUNTER_TOO_SMALL (indicating our AT_COUNTER value (%u) wasn't fresh)",
			eap_aka_sim_session->keys.reauth.counter);

		fr_aka_sim_vector_umts_reauth_clear(&eap_aka_sim_session->keys);
		eap_aka_sim_session->allow_encrypted = false;

	 	return STATE_TRANSITION(aka_challenge);
	}

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 *
	 *	RFC 4187 Section #6.2. Result Indications
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return STATE_TRANSITION(common_success_notification);
		}
	} else if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	eap_aka_sim_session->reauthentication_success = true;

	return STATE_TRANSITION(eap_success);
}

/** REAUTHENTICATION state - Continue the state machine after receiving a response to our EAP-Request/SIM-Start
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/(SIM|AKA)-Reauthentication - call 'recv Reauthentication-Response { ... }'
 *   - EAP-Response/(SIM|AKA)-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/(SIM|AKA)-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
STATE(common_reauthentication)
{
	eap_aka_sim_process_conf_t 	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*subtype_vp = NULL;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto fail;
	}

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
		return CALL_SECTION(recv_common_reauthentication_response);

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request);

		eap_aka_sim_session->allow_encrypted = false;

		return CALL_SECTION(recv_common_client_error);
	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
	fail:
		eap_aka_sim_session->allow_encrypted = false;

		return STATE_TRANSITION(common_failure_notification);
	}
}


/** Send a EAP-Request/(AKA|SIM)-Reauthenticate message to the supplicant
 *
 */
static unlang_action_t common_reauthentication_request_compose(rlm_rcode_t *p_result,
							       module_ctx_t const *mctx,
							       request_t *request,
							       eap_aka_sim_session_t *eap_aka_sim_session)
{
	fr_pair_t		*vp;
	fr_pair_t		*kdf_id;

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
	kdf_id = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity, 0);
	if (kdf_id) {
		crypto_identity_set(request, eap_aka_sim_session,
				    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Generating new session keys");

	switch (eap_aka_sim_session->type) {
	/*
	 *	The GSM and UMTS KDF_0 mutate their keys using
	 *	and identical algorithm.
	 */
	case FR_EAP_METHOD_SIM:
	case FR_EAP_METHOD_AKA:
		if (fr_aka_sim_vector_gsm_umts_kdf_0_reauth_from_attrs(request, &request->session_state_pairs,
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
				fr_pair_list_free(&request->reply_pairs);
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				return STATE_TRANSITION(common_identity);

			case AKA_SIM_FULLAUTH_ID_REQ:
			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Last requested fullauth or permanent ID, "
					"but received, or were told we received (by policy), "
					"a fastauth ID.  Cannot continue");
				return STATE_TRANSITION(common_failure_notification);
			}
		}
		if (fr_aka_sim_crypto_kdf_0_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		switch (eap_aka_sim_session->kdf) {
		case FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME:
			if (fr_aka_sim_vector_umts_kdf_1_reauth_from_attrs(request, &request->session_state_pairs,
									   &eap_aka_sim_session->keys) != 0) {
				goto request_new_id;
			}
			if (fr_aka_sim_crypto_umts_kdf_1_reauth(&eap_aka_sim_session->keys) < 0) goto request_new_id;
			break;

		default:
			fr_assert(0);
			break;
		}
		break;

	default:
		fr_assert(0);
		break;
	}

	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_result_ind, 0);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	RFC 5448 says AT_BIDDING is only sent in the challenge
	 *	not in reauthentication, so don't add that here.
	 */

	 /*
	  *	Add AT_NONCE_S
	  */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_nonce_s) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.reauth.nonce_s,
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
	fr_pair_value_memdup(vp, NULL, 0, false);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(p_result, mctx, request, eap_aka_sim_session,
					   common_reauthentication_request_send);
}

/** Resume after 'send Reauthentication-Request { ... }'
 *
 */
RESUME(send_common_reauthentication_request)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	switch (unlang_interpret_stack_result(request)) {
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
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"));
			fr_pair_list_free(&request->reply_pairs);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;

			return STATE_TRANSITION(common_identity);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
		default:
			break;
		}
		REDEBUG("Last requested Full-Auth-Id or Permanent-Identity, "
			"but received a Fast-Auth-Id.  Cannot continue");
	failure:
		return STATE_TRANSITION(common_failure_notification);

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
		return common_reauthentication_request_compose(p_result, mctx, request, eap_aka_sim_session);
	}
}

/** Resume after 'load pseudonym { ... }'
 *
 */
RESUME(load_pseudonym)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	pair_delete_request(attr_eap_aka_sim_next_reauth_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_pseudonym) {
	next_state:
		return eap_aka_sim_session->next(p_result, mctx, request, eap_aka_sim_session);
	}

	switch (unlang_interpret_stack_result(request)) {
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
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"));
			fr_pair_list_free(&request->reply_pairs);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return STATE_TRANSITION(common_identity);

		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested a Permanent-Identity, but received a Pseudonym.  Cannot continue");
		failure:
			return STATE_TRANSITION(common_failure_notification);
		}
		break;

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

	goto failure;
}

/** Resume after 'load session { ... }'
 *
 */
RESUME(load_session)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	pair_delete_request(attr_session_id);

	/*
	 *	Control attributes required could have been specified
	 *      in another section.
	 */
	if (!inst->actions.load_session) goto reauthenticate;

	switch (unlang_interpret_stack_result(request)) {
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
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"));
			fr_pair_list_free(&request->reply_pairs);
			eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
			return STATE_TRANSITION(common_identity);

		case AKA_SIM_FULLAUTH_ID_REQ:
		case AKA_SIM_PERMANENT_ID_REQ:
			REDEBUG("Last requested Full-Auth-Id or Permanent-Identity, "
				"but received a Fast-Auth-Id.  Cannot continue");
			return STATE_TRANSITION(common_failure_notification);
		}
		break;

	/*
	 *	Policy rejected the user
	 */
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
	reject:
		return STATE_TRANSITION(common_failure_notification);

	/*
	 *	Everything OK
	 */
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	reauthenticate:
		return CALL_SECTION(send_common_reauthentication_request);
	}

	goto reject;
}

/** Enter the REAUTHENTICATION state
 *
 */
STATE_GUARD(common_reauthentication)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t		*vp = NULL;

	STATE_SET(common_reauthentication);

	/*
	 *	Add the current identity as session_id
	 *      to make it easier to load/store things from
	 *	the cache module.
	 */
	MEM(pair_update_request(&vp, attr_session_id) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.identity, eap_aka_sim_session->keys.identity_len, true);

	return CALL_SECTION(load_session);
}

/** Resume after 'recv Synchronization-Failure { ... }'
 *
 * - If 'recv Synchronization-Failure { ... }' returned a failure
 *   rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or if no 'recv Syncronization-Failure { ... }' section was
 *   defined, then enter the FAILURE-NOTIFICATION state.
 * - ...or if the user didn't provide a new SQN value in &control.SQN
 *   then enter the FAILURE-NOTIFICATION state.
 * - ...or enter the AKA-CHALLENGE state.
 */
RESUME(recv_aka_syncronization_failure)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t			*vp;

	SECTION_RCODE_PROCESS;

	/*
	 *	If there's no section to handle this, then no resynchronisation
	 *	can't have occurred and we just send a reject.
	 *
	 *	Similarly, if we've already received one synchronisation failure
	 *	then it's highly likely whatever user configured action was
	 *	configured was unsuccessful, and we should just give up.
	 */
	if (!inst->actions.recv_aka_syncronization_failure || eap_aka_sim_session->prev_recv_sync_failure) {
	failure:
		return STATE_TRANSITION(common_failure_notification);
	}

	/*
	 *	We couldn't generate an SQN and the user didn't provide one,
	 *	so we need to fail.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_sim_sqn, 0);
	if (!vp) {
		REDEBUG("No &control.SQN value provided after resynchronisation, cannot continue");
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
	return STATE_TRANSITION(aka_challenge);
}

/** Resume after 'recv Authentication-Reject { ... }'
 *
 * - Enter the FAILURE-NOTIFICATION state.
 */
RESUME(recv_aka_authentication_reject)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_IGNORED;

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	return STATE_TRANSITION(eap_failure);
}

/** Resume after 'recv Challenge-Response { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the AKA-Challenge message.
 *
 * Verify that MAC, and RES match what we expect.
 */
RESUME(recv_aka_challenge_response)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t		*vp = NULL;

	SECTION_RCODE_PROCESS;

	/*
	 *	Validate mac
	 */
	if (mac_validate(request) < 0) {
	failure:
		return STATE_TRANSITION(common_failure_notification);
	}

	/*
	 *	Validate the checkcode
	 */
	if (checkcode_validate(request) < 0) goto failure;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_res, 0);
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
		if (!fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return STATE_TRANSITION(common_success_notification);
		}
	} else if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	return STATE_TRANSITION(eap_success);
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
STATE(aka_challenge)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*subtype_vp = NULL;
	fr_pair_t			*vp;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto fail;
	}

	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_CHALLENGE:
		return CALL_SECTION(recv_aka_challenge_response);

	/*
	 *	Case 2 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_AUTHENTICATION_REJECT:
		eap_aka_sim_session->allow_encrypted = false;
		return CALL_SECTION(recv_aka_authentication_reject);

	case FR_SUBTYPE_VALUE_AKA_SYNCHRONIZATION_FAILURE:
	{
		uint64_t	new_sqn;

		eap_aka_sim_session->allow_encrypted = false;

		vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_auts, 0);
		if (!vp) {
			REDEBUG("EAP-Response/AKA-Synchronisation-Failure missing AT_AUTS");
		failure:
			return STATE_TRANSITION(common_failure_notification);
		}

		switch (fr_aka_sim_umts_resync_from_attrs(&new_sqn,
							  request, vp, &eap_aka_sim_session->keys)) {
		/*
		 *	Add everything back that we'll need in the
		 *	next challenge round.
		 */
		case 0:
			MEM(pair_append_control(&vp, attr_sim_sqn) >= 0);
			vp->vp_uint64 = new_sqn;

			MEM(pair_append_control(&vp, attr_sim_ki) >= 0);
			fr_pair_value_memdup(vp, eap_aka_sim_session->keys.auc.ki,
					     sizeof(eap_aka_sim_session->keys.auc.ki), false);

			MEM(pair_append_control(&vp, attr_sim_opc) >= 0);
			fr_pair_value_memdup(vp, eap_aka_sim_session->keys.auc.opc,
					     sizeof(eap_aka_sim_session->keys.auc.opc), false);
			break;

		case 1:	/* Don't have Ki or OPc so something else will need to deal with this */
			break;

		default:
		case -1:
			goto failure;
		}

		return CALL_SECTION(recv_aka_syncronization_failure);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request);

		eap_aka_sim_session->allow_encrypted = false;

		return CALL_SECTION(recv_common_client_error);

	/*
	 *	RFC 4187 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
	fail:
		eap_aka_sim_session->allow_encrypted = false;
		goto failure;
	}
}

/** Resume after 'send Challenge-Request { ... }'
 *
 */
RESUME(send_aka_challenge_request)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t		*vp;
	fr_aka_sim_vector_src_t	src = AKA_SIM_VECTOR_SRC_AUTO;

	fr_pair_t		*kdf_id;

	SECTION_RCODE_PROCESS;

	/*
	 *	Allow override of KDF Identity
	 *
	 *	Because certain handset manufacturers don't
	 *	implement RFC 4187 correctly and use the
	 *	wrong identity as input the the PRF/KDF.
	 */
	kdf_id = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity, 0);
	if (kdf_id) {
		crypto_identity_set(request, eap_aka_sim_session,
				    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Acquiring UMTS vector(s)");

	if (eap_aka_sim_session->type == FR_EAP_METHOD_AKA_PRIME) {
		/*
		 *	Copy the network name the user specified for
		 *	key derivation purposes.
		 */
		vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_kdf_input, 0);
		if (vp) {
			talloc_free(eap_aka_sim_session->keys.network);
			eap_aka_sim_session->keys.network = talloc_memdup(eap_aka_sim_session,
									  (uint8_t const *)vp->vp_strvalue,
									  vp->vp_length);
			eap_aka_sim_session->keys.network_len = vp->vp_length;
		} else {
			REDEBUG("No network name available, can't set AT_KDF_INPUT");
		failure:
			return STATE_TRANSITION(common_failure_notification);
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
	if (fr_aka_sim_vector_umts_from_attrs(request, &request->control_pairs,
					      &eap_aka_sim_session->keys, &src) != 0) {
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
		fr_assert(0);	/* EAP-SIM has its own Challenge state */
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
			fr_assert(0);
			break;
		}
	}
	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_result_ind, 0);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

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
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.umts.vector.rand, AKA_SIM_VECTOR_UMTS_RAND_SIZE, false);

	/*
	 *	Send the AUTN value to the client, so it can authenticate
	 *	whoever has knowledge of the Ki.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_autn) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.umts.vector.autn, AKA_SIM_VECTOR_UMTS_AUTN_SIZE, false);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memdup(vp, NULL, 0, false);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(p_result, mctx, request, eap_aka_sim_session, aka_challenge_request_send);
}

/** Enter the AKA-CHALLENGE state
 *
 */
STATE_GUARD(aka_challenge)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*vp;

	/*
	 *	If we've sent either of these identities it
	 *	means we've come here form a Reauthentication-Request
	 *	that failed.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(p_result, mctx, request,
						   eap_aka_sim_session, guard_aka_challenge);
						   /* come back when we're done */
	}

	STATE_SET(aka_challenge);

	/*
	 *	Set some default attributes, giving the user a
	 *	chance to modify them.
	 */
	switch (eap_aka_sim_session->type) {
	case FR_EAP_METHOD_AKA_PRIME:
	{
		uint8_t		amf_buff[2] = { 0x80, 0x00 };	/* Set the AMF separation bit high */

		/*
		 *	Toggle the AMF high bit to indicate we're doing AKA'
		 */
		MEM(pair_update_control(&vp, attr_sim_amf) >= 0);
		fr_pair_value_memdup(vp, amf_buff, sizeof(amf_buff), false);

	        /*
	 	 *	Use the default network name we have configured
	 	 *	and send it to the peer.
	 	 */
		if (inst->network_name &&
		    !fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_kdf_input, 0)) {
			MEM(pair_append_reply(&vp, attr_eap_aka_sim_kdf_input) >= 0);
			fr_pair_value_bstrdup_buffer(vp, inst->network_name, false);
		}
	}
		break;

	default:
		break;

	}

	/*
	 *	Set the defaults for protected result indicator
	 */
	if (eap_aka_sim_session->send_result_ind &&
	    !fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_result_ind, 0)) {
	    	MEM(pair_append_reply(&vp, attr_eap_aka_sim_result_ind) >= 0);
		vp->vp_bool = true;
	}

	return CALL_SECTION(send_aka_challenge_request);
}

/** Resume after 'recv Challenge-Response { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the SIM-Challenge message.
 *
 * Verify that MAC, and RES match what we expect.
 */
RESUME(recv_sim_challenge_response)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	uint8_t			sres_cat[AKA_SIM_VECTOR_GSM_SRES_SIZE * 3];
	uint8_t			*p = sres_cat;

	SECTION_RCODE_PROCESS;

	memcpy(p, eap_aka_sim_session->keys.gsm.vector[0].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[1].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	p += AKA_SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_aka_sim_session->keys.gsm.vector[2].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE);

	/*
	 *	Validate mac
	 */
	if (mac_validate(request) < 0) return STATE_TRANSITION(common_failure_notification);

	eap_aka_sim_session->challenge_success = true;

	/*
	 *	If the peer wants a Success notification, and
	 *	we included AT_RESULT_IND then send a success
	 *      notification, otherwise send a normal EAP-Success.
	 */
	if (eap_aka_sim_session->send_result_ind) {
		if (!fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
			RDEBUG("We wanted to use protected result indications, but peer does not");
			eap_aka_sim_session->send_result_ind = false;
		} else {
			return STATE_TRANSITION(common_success_notification);
		}
	} else if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_result_ind, 0)) {
		RDEBUG("Peer wanted to use protected result indications, but we do not");
	}

	return STATE_TRANSITION(eap_success);
}

/** SIM-CHALLENGE state - Continue the state machine after receiving a response to our EAP-Request/SIM-Challenge
 *
 * - Continue based on received AT_SUBTYPE value:
 *   - EAP-Response/SIM-Challenge - call 'recv Challenge-Response { ... }'.
 *   - EAP-Response/SIM-Client-Error - call 'recv Client-Error { ... }' and after that
 *     send a EAP-Request/SIM-Notification indicating a General Failure.
 *   - Anything else, enter the FAILURE-NOTIFICATION state.
 */
STATE(sim_challenge)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t		  *subtype_vp = NULL;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto fail;
	}

	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_SIM_CHALLENGE:
		return CALL_SECTION(recv_sim_challenge_response);

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request);

		eap_aka_sim_session->allow_encrypted = false;

		return CALL_SECTION(recv_common_client_error);

	/*
	 *	RFC 4186 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case.
	 */
	default:
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
	fail:
		eap_aka_sim_session->allow_encrypted = false;

		return STATE_TRANSITION(common_failure_notification);
	}
}

/** Resume after 'send Challenge-Request { ... }'
 *
 */
RESUME(send_sim_challenge_request)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	fr_pair_t		*vp;
	fr_aka_sim_vector_src_t	src = AKA_SIM_VECTOR_SRC_AUTO;

	fr_pair_t		*kdf_id;

	SECTION_RCODE_PROCESS;

	/*
	 *	Allow override of KDF Identity
	 *
	 *	Because certain handset manufacturers don't
	 *	implement RFC 4187 correctly and use the
	 *	wrong identity as input the the PRF/KDF.
	 */
	kdf_id = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity, 0);
	if (kdf_id) {
		crypto_identity_set(request, eap_aka_sim_session,
				    (uint8_t const *)kdf_id->vp_strvalue, kdf_id->vp_length);
		fr_pair_delete_by_da(&request->control_pairs, attr_eap_aka_sim_kdf_identity);
	}

	RDEBUG2("Acquiring GSM vector(s)");
	if ((fr_aka_sim_vector_gsm_from_attrs(request, &request->control_pairs, 0,
					      &eap_aka_sim_session->keys, &src) != 0) ||
	    (fr_aka_sim_vector_gsm_from_attrs(request, &request->control_pairs, 1,
	    				      &eap_aka_sim_session->keys, &src) != 0) ||
	    (fr_aka_sim_vector_gsm_from_attrs(request, &request->control_pairs, 2,
	    				      &eap_aka_sim_session->keys, &src) != 0)) {
	    	REDEBUG("Failed retrieving SIM vectors");
		RETURN_MODULE_FAIL;
	}

	fr_aka_sim_crypto_gsm_kdf_0(&eap_aka_sim_session->keys);

	if (RDEBUG_ENABLED3) fr_aka_sim_crypto_keys_log(request, &eap_aka_sim_session->keys);

	/*
	 *	Indicate we'd like to use protected success messages
	 *	with AT_RESULT_IND
	 *
	 *	Use our default, but allow user override too.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_result_ind, 0);
	if (vp) eap_aka_sim_session->send_result_ind = vp->vp_bool;

	/*
	 *	Okay, we got the challenges! Put them into attributes.
	 */
	MEM(pair_append_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.gsm.vector[0].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	MEM(pair_append_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.gsm.vector[1].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	MEM(pair_append_reply(&vp, attr_eap_aka_sim_rand) >= 0);
	fr_pair_value_memdup(vp, eap_aka_sim_session->keys.gsm.vector[2].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE, false);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	MEM(pair_update_reply(&vp, attr_eap_aka_sim_mac) >= 0);
	fr_pair_value_memdup(vp, NULL, 0, false);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_aka_sim_session->allow_encrypted = true;

	return session_and_pseudonym_store(p_result, mctx,request, eap_aka_sim_session, sim_challenge_request_send);
}

/** Enter the SIM-CHALLENGE state
 *
 */
STATE_GUARD(sim_challenge)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*vp;

	/*
	 *	If we've sent either of these identities it
	 *	means we've come here form a Reauthentication-Request
	 *	that failed.
	 */
	if (eap_aka_sim_session->pseudonym_sent || eap_aka_sim_session->fastauth_sent) {
		return session_and_pseudonym_clear(p_result, mctx, request,
						   eap_aka_sim_session, guard_sim_challenge);
						   /* come back when we're done */
	}

	STATE_SET(sim_challenge);

	/*
	 *	Set the defaults for protected result indicator
	 */
	if (eap_aka_sim_session->send_result_ind &&
	    !fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_result_ind, 0)) {
	    	MEM(pair_append_reply(&vp, attr_eap_aka_sim_result_ind) >= 0);
		vp->vp_bool = true;
	}

	return CALL_SECTION(send_sim_challenge_request);
}

/** Enter the SIM-CHALLENGE or AKA-CHALLENGE state
 *
 * Called by functions which are common to both the EAP-SIM and EAP-AKA state machines
 * to enter the correct challenge state.
 */
STATE_GUARD(common_challenge)
{
	switch (eap_aka_sim_session->type) {
	case FR_EAP_METHOD_SIM:
		return STATE_TRANSITION(sim_challenge);

	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_AKA_PRIME:
		return STATE_TRANSITION(aka_challenge);

	default:
		break;
	}

	fr_assert(0);
	RETURN_MODULE_FAIL;
}

/** Resume after 'recv Identity-Response { ... }' or 'recv AKA-Identity { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the AKA-Identity message, mainly the AT_IDENTITY value.
 * - If the message does not contain AT_IDENTITY, then enter the FAILURE-NOTIFICATION state.
 * - If the user requested another identity, re-enter the AKA-Identity sate.
 * - ...or continue based on the value of &Identity-Type which was added by #aka_identity,
 *   and possibly modified by the user.
 *   - Fastauth - Enter the REAUTHENTICATION state.
 *   - Pseudonym - Call 'load pseudonym { ... }'
 *   - Permanent - Enter the CHALLENGE state.
 */
RESUME(recv_aka_identity_response)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	bool				user_set_id_req;
	fr_pair_t			*identity_type;

	SECTION_RCODE_PROCESS;

	/*
	 *	See if the user wants us to request another
	 *	identity.
	 *
	 *	If they set one themselves don't override
	 *	what they set.
	 */
	user_set_id_req = identity_req_set_by_user(request, eap_aka_sim_session);
	if ((unlang_interpret_stack_result(request) == RLM_MODULE_NOTFOUND) || user_set_id_req) {
		if (!user_set_id_req) {
			switch (eap_aka_sim_session->last_id_req) {
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				break;

			case AKA_SIM_FULLAUTH_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
				break;

			case AKA_SIM_NO_ID_REQ:	/* Should not happen */
				fr_assert(0);
				FALL_THROUGH;

			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Peer sent no usable identities");
				return STATE_TRANSITION(common_failure_notification);

			}
			RDEBUG2("Previous section returned (%s), requesting next most permissive identity (%s)",
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->id_req, "<INVALID>"));
		}
		return STATE_TRANSITION(aka_identity);
	}

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do fullauth.
	 */
	identity_type = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_identity_type, 0);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return STATE_TRANSITION(common_reauthentication);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		eap_aka_sim_session->next = guard_aka_challenge;
		return CALL_SECTION(load_pseudonym);

	default:
		break;
	}

	return STATE_TRANSITION(aka_challenge);
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
STATE(aka_identity)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*subtype_vp = NULL;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto fail;
	}

	switch (subtype_vp->vp_uint16) {
	/*
	 *	This is the subtype we expect
	 */
	case FR_SUBTYPE_VALUE_AKA_IDENTITY:
	{
		fr_pair_t		*id;
		fr_aka_sim_id_type_t	type;

		id = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_identity, 0);
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
			return STATE_TRANSITION(common_failure_notification);
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
		crypto_identity_set(request, eap_aka_sim_session,
				    (uint8_t const *)id->vp_strvalue, id->vp_length);

		return unlang_module_yield_to_section(p_result,
						      request,
						      inst->actions.recv_aka_identity_response ?
						      		inst->actions.recv_aka_identity_response:
						      		inst->actions.recv_common_identity_response,
						      RLM_MODULE_NOOP,
						      resume_recv_aka_identity_response,
						      mod_signal,
						      eap_aka_sim_session);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 *
	 *	This can happen in the case of a conservative
	 *	peer, where it refuses to provide the permanent
	 *	identity.
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request);

		return CALL_SECTION(recv_common_client_error);

	default:
		/*
		 *	RFC 4187 says we *MUST* notify, not just
		 *	send an EAP-Failure in this case.
		 */
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
	fail:
		return STATE_TRANSITION(common_failure_notification);
	}
}

/** Resume after 'send Identity-Request { ... }'
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
 */
RESUME(send_aka_identity_request)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);

	SECTION_RCODE_PROCESS;

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
		return STATE_TRANSITION(common_failure_notification);
	}
	eap_aka_sim_session->last_id_req = eap_aka_sim_session->id_req;	/* Record what we last requested */

	/*
	 *	Encode the packet
	 */
	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_AKA_IDENTITY);

	RETURN_MODULE_HANDLED;
}

/** Enter the AKA-IDENTITY state
 *
 */
STATE_GUARD(aka_identity)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	STATE_SET(aka_identity);

	/*
	 *	If we have an send_aka_identity_request section
	 *	then run that, otherwise just run the normal
	 *	identity request section.
	 */
	return unlang_module_yield_to_section(p_result,
					      request,
					      inst->actions.send_aka_identity_request ?
							inst->actions.send_aka_identity_request:
							inst->actions.send_common_identity_request,
					      RLM_MODULE_NOOP,
					      resume_send_aka_identity_request,
					      mod_signal,
					      eap_aka_sim_session);
}

/** Resume after 'recv Identity-Response { ... }' or 'recv SIM-Start { ... }'
 *
 * - If the previous section returned a failure rcode, enter the FAILURE-NOTIFICATION state.
 * - ...or call a function to process the contents of the SIM-Start message, mainly the AT_IDENTITY value.
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
RESUME(recv_sim_start_response)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	bool			  	user_set_id_req;
	fr_pair_t		  	*identity_type;

	SECTION_RCODE_PROCESS;

	/*
	 *	See if the user wants us to request another
	 *	identity.
	 *
	 *	If they set one themselves don't override
	 *	what they set.
	 */
	user_set_id_req = identity_req_set_by_user(request, eap_aka_sim_session);
	if ((unlang_interpret_stack_result(request) == RLM_MODULE_NOTFOUND) || user_set_id_req) {
		if (!user_set_id_req) {
			switch (eap_aka_sim_session->last_id_req) {
			case AKA_SIM_ANY_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_FULLAUTH_ID_REQ;
				break;

			case AKA_SIM_FULLAUTH_ID_REQ:
				eap_aka_sim_session->id_req = AKA_SIM_PERMANENT_ID_REQ;
				break;

			case AKA_SIM_NO_ID_REQ:	/* Should not happen */
				fr_assert(0);
				FALL_THROUGH;

			case AKA_SIM_PERMANENT_ID_REQ:
				REDEBUG("Peer sent no usable identities");
			failure:
				return STATE_TRANSITION(common_failure_notification);
			}
			RDEBUG2("Previous section returned (%s), requesting next most permissive identity (%s)",
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->id_req, "<INVALID>"));
		}
		return STATE_TRANSITION(sim_start);
	}

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do fullauth.
	 */
	identity_type = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_identity_type, 0);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		/*
		 *  RFC 4186 Section #9.2
		 *
		 *  The AT_NONCE_MT attribute MUST NOT be included if the AT_IDENTITY
		 *  with a fast re-authentication identity is present for fast
		 *  re-authentication
		 */
		if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_nonce_mt, 0)) {
			REDEBUG("AT_NONCE_MT is not allowed in EAP-Response/SIM-Reauthentication messages");
			return STATE_TRANSITION(common_failure_notification);
		}

		/*
		 *  RFC 4186 Section #9.2
		 *
		 *  The AT_SELECTED_VERSION attribute MUST NOT be included if the
		 *  AT_IDENTITY attribute with a fast re-authentication identity is
		 *  present for fast re-authentication.
		 */
		if (fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_selected_version, 0)) {
			REDEBUG("AT_SELECTED_VERSION is not allowed in EAP-Response/SIM-Reauthentication messages");
			return STATE_TRANSITION(common_failure_notification);
		}

		return STATE_TRANSITION(common_reauthentication);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		if (sim_start_selected_version_check(request, eap_aka_sim_session) < 0) goto failure;
		if (sim_start_nonce_mt_check(request, eap_aka_sim_session) < 0) goto failure;

		eap_aka_sim_session->next = guard_sim_challenge;
		return CALL_SECTION(load_pseudonym);

	/*
	 *	If it's a permanent ID, copy it over to
	 *	the session state list for use in the
	 *      store pseudonym/store session sections
	 *	later.
	 */
	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
		if (sim_start_selected_version_check(request, eap_aka_sim_session) < 0) goto failure;
		if (sim_start_nonce_mt_check(request, eap_aka_sim_session) < 0) goto failure;

		FALL_THROUGH;
	default:
		break;
	}

	return STATE_TRANSITION(sim_challenge);
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
STATE(sim_start)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*subtype_vp = NULL;

	subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype, 0);
	if (!subtype_vp) {
		REDEBUG("Missing AT_SUBTYPE");
		goto fail;
	}
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_SIM_START:
	{
		fr_pair_t		*id;
		fr_aka_sim_id_type_t	type;

		id = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_identity, 0);
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
			return STATE_TRANSITION(common_failure_notification);
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
		crypto_identity_set(request, eap_aka_sim_session,
				    (uint8_t const *)id->vp_strvalue, id->vp_length);

		return unlang_module_yield_to_section(p_result,
						      request,
						      inst->actions.recv_sim_start_response?
						      		inst->actions.recv_sim_start_response:
						      		inst->actions.recv_common_identity_response,
						      RLM_MODULE_NOOP,
						      resume_recv_sim_start_response,
						      mod_signal,
						      eap_aka_sim_session);
	}

	/*
	 *	Case 1 where we're allowed to send an EAP-Failure
	 *
	 *	This can happen in the case of a conservative
	 *	peer, where it refuses to provide the permanent
	 *	identity.
	 */
	case FR_SUBTYPE_VALUE_AKA_SIM_CLIENT_ERROR:
		client_error_debug(request);

		return CALL_SECTION(recv_common_client_error);

	default:
		/*
		 *	RFC 4187 says we *MUST* notify, not just
		 *	send an EAP-Failure in this case.
		 */
		REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
	fail:
		return STATE_TRANSITION(common_failure_notification);
	}
}

/** Resume after 'send Start { ... }'
 *
 * Send a EAP-Request/SIM-Start message to the supplicant
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
 */
RESUME(send_sim_start)
{
	eap_aka_sim_session_t	*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t		*vp;
	uint8_t			*p, *end;

	SECTION_RCODE_PROCESS;

	p = eap_aka_sim_session->keys.gsm.version_list;
	end = p + sizeof(eap_aka_sim_session->keys.gsm.version_list);
	eap_aka_sim_session->keys.gsm.version_list_len = 0;

	/*
	 *	If the user provided no versions, then
	 *      just add the default (1).
	 */
	if (!(fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_version_list, 0))) {
		MEM(pair_append_reply(&vp, attr_eap_aka_sim_version_list) >= 0);
		vp->vp_uint16 = EAP_SIM_VERSION;
	}

	/*
	 *	Iterate over the the versions adding them
	 *      to the version list we use for keying.
	 */
	for (vp = fr_pair_list_head(&request->reply_pairs);
	     vp;
	     vp = fr_pair_list_next(&request->reply_pairs, vp)) {
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
		return STATE_TRANSITION(common_failure_notification);
	}
	eap_aka_sim_session->last_id_req = eap_aka_sim_session->id_req;	/* Record what we last requested */

	common_reply(request, eap_aka_sim_session, FR_SUBTYPE_VALUE_SIM_START);

	RETURN_MODULE_HANDLED;
}

/** Enter the SIM-START state
 *
 */
STATE_GUARD(sim_start)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);

	STATE_SET(sim_start);

	return unlang_module_yield_to_section(p_result,
					      request,
					      inst->actions.send_sim_start_request ?
					      		inst->actions.send_sim_start_request:
					      		inst->actions.send_common_identity_request,
					      RLM_MODULE_NOOP,
					      resume_send_sim_start,
					      mod_signal,
					      eap_aka_sim_session);
}

/** Enter the SIM-START or AKA-IDENTITY state
 *
 * Called by functions which are common to both the EAP-SIM and EAP-AKA state machines
 * to enter the correct Identity-Request state.
 */
STATE_GUARD(common_identity)
{
	switch (eap_aka_sim_session->type) {
	case FR_EAP_METHOD_SIM:
		return STATE_TRANSITION(sim_start);

	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_AKA_PRIME:
		return STATE_TRANSITION(aka_identity);

	default:
		break;
	}

	fr_assert(0);
	RETURN_MODULE_FAIL;
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
RESUME(recv_common_identity_response)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t		*eap_aka_sim_session = talloc_get_type_abort(rctx, eap_aka_sim_session_t);
	fr_pair_t			*eap_type, *method, *identity_type;
	fr_aka_sim_method_hint_t	running, hinted;

	SECTION_RCODE_PROCESS;

	/*
	 *	Ignore attempts to change the EAP-Type
	 *	This must be done before we enter
	 *	the submodule.
	 */
	eap_type = fr_pair_find_by_da(&request->control_pairs, attr_eap_type, 0);
	if (eap_type) RWDEBUG("Ignoring &control.EAP-Type, this must be set *before* the EAP module is called");

	method = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_method_hint, 0);

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
	switch (eap_aka_sim_session->type) {
	case FR_EAP_METHOD_SIM:
		RDEBUG2("New EAP-SIM session");

		running = AKA_SIM_METHOD_HINT_SIM;

		eap_aka_sim_session->type = FR_EAP_METHOD_SIM;
		eap_aka_sim_session->mac_md = EVP_sha1();
		break;

	case FR_EAP_METHOD_AKA:
		RDEBUG2("New EAP-AKA session");

		running = AKA_SIM_METHOD_HINT_AKA;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA;
		eap_aka_sim_session->mac_md = EVP_sha1();
		break;

	case FR_EAP_METHOD_AKA_PRIME:
		RDEBUG2("New EAP-AKA' session");

		running = AKA_SIM_METHOD_HINT_AKA_PRIME;

		eap_aka_sim_session->type = FR_EAP_METHOD_AKA_PRIME;
		eap_aka_sim_session->kdf = FR_KDF_VALUE_PRIME_WITH_CK_PRIME_IK_PRIME;
		eap_aka_sim_session->mac_md = EVP_sha256();
		break;

	default:
		fr_assert(0);
		RETURN_MODULE_FAIL;
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
		if (unlang_interpret_stack_result(request) == RLM_MODULE_NOTFOUND) {
			eap_aka_sim_session->id_req = AKA_SIM_ANY_ID_REQ;
			RDEBUG2("Previous section returned (%s), requesting additional identity (%s)",
				fr_table_str_by_value(rcode_table, unlang_interpret_stack_result(request), "<INVALID>"),
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->id_req, "<INVALID>"));
		} else if (inst->request_identity != AKA_SIM_NO_ID_REQ) {
			eap_aka_sim_session->id_req = inst->request_identity;
			RDEBUG2("Requesting additional identity (%s)",
				fr_table_str_by_value(fr_aka_sim_id_request_table,
						      eap_aka_sim_session->id_req, "<INVALID>"));
		}
	}

	/*
	 *	User may want us to always request an identity
	 *	initially.  The RFCs says this is also the
	 *	better way to operate, as the supplicant
	 *	can 'decorate' the identity in the identity
	 *	response.
	 */
	if (eap_aka_sim_session->id_req != AKA_SIM_NO_ID_REQ) return STATE_TRANSITION(common_identity);

	/*
	 *	If the identity looks like a fast re-auth id
	 *	run fast re-auth, otherwise do a fullauth.
	 */
	identity_type = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_identity_type, 0);
	if (identity_type) switch (identity_type->vp_uint32) {
	case FR_IDENTITY_TYPE_VALUE_FASTAUTH:
		return STATE_TRANSITION(common_reauthentication);

	/*
	 *	It's a pseudonym, which now needs resolving.
	 *	The resume function here calls aka_challenge_enter
	 *	if pseudonym resolution went ok.
	 */
	case FR_IDENTITY_TYPE_VALUE_PSEUDONYM:
		eap_aka_sim_session->next = guard_common_challenge;
		return CALL_SECTION(load_pseudonym);

	case FR_IDENTITY_TYPE_VALUE_PERMANENT:
	default:
		break;
	}

	return STATE_TRANSITION(common_challenge);
}

/** Enter the EAP-IDENTITY state
 *
 * - Process the incoming EAP-Identity-Response
 * - Start EAP-SIM/EAP-AKA/EAP-AKA' state machine optionally calling 'recv Identity-Response { ... }'
 */
STATE(init)
{
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	fr_pair_t			*vp;
	fr_aka_sim_id_type_t		type;

	/*
	 *	Verify we received an EAP-Response/Identity
	 *	message before the supplicant started sending
	 *	EAP-SIM/AKA/AKA' packets.
	 */
	if (!eap_session->identity) {
		REDEBUG("All SIM or AKA exchanges must begin with a EAP-Response/Identity message");
		return STATE_TRANSITION(common_failure_notification);
	}

	/*
	 *	Copy the EAP-Identity into our Identity
	 *	attribute to make policies easier.
	 */
	MEM(pair_append_request(&vp, attr_eap_aka_sim_identity) >= 0);
	fr_pair_value_bstrdup_buffer(vp, eap_session->identity, true);

	/*
	 *	Add ID hint attributes to the request to help
	 *	the user make policy decisions.
	 */
	identity_hint_pairs_add(&type, NULL, request, eap_session->identity);
	if (type == AKA_SIM_ID_TYPE_PERMANENT) {
		identity_to_permanent_identity(request, vp, eap_session->type,
					       inst->strip_permanent_identity_hint);
	}

	/*
	 *	Set the initial crypto identity from
	 *	the EAP-Identity-Response
	 */
	crypto_identity_set(request, eap_aka_sim_session,
			    (uint8_t const *)eap_session->identity,
			    talloc_array_length(eap_session->identity) - 1);

	return CALL_SECTION(recv_common_identity_response);
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

/** Resumes the state machine when receiving a new response packet
 *
 */
unlang_action_t eap_aka_sim_state_machine_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_aka_sim_process_conf_t *inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_process_conf_t);
	eap_aka_sim_session_t *eap_aka_sim_session = request_data_reference(request,
									    (void *)eap_aka_sim_state_machine_process,
									    0);
	/*
	 *	A new EAP-SIM/AKA/AKA' session!
	 */
	if (!eap_aka_sim_session) {
		/*
		 *	Must be allocated in the NULL ctx as this will
		 *	need to persist over multiple rounds of EAP.
		 */
		MEM(eap_aka_sim_session = talloc_zero(NULL, eap_aka_sim_session_t));
		talloc_set_destructor(eap_aka_sim_session, _eap_aka_sim_session_free);

		/*
		 *	Add new session data to the request
		 *	We only ever need to do this once as it's restored
		 *	during the next round of EAP automatically.
		 *
		 *	It will also be freed automatically if the request
		 *	is freed and persistable data hasn't been moved
		 *	into the parent.
		 */
		if (unlikely(request_data_add(request, (void *)eap_aka_sim_state_machine_process, 0,
					      eap_aka_sim_session, true, true, true) < 0)) {
			RPEDEBUG("Failed creating new EAP-SIM/AKA/AKA' session");
			RETURN_MODULE_FAIL;
		}
		eap_aka_sim_session->type = inst->type;

		return state_init(p_result, mctx, request, eap_aka_sim_session);
	}

	if (!fr_cond_assert(eap_aka_sim_session->state)) RETURN_MODULE_FAIL;

	return eap_aka_sim_session->state(p_result, mctx, request, eap_aka_sim_session);
}
