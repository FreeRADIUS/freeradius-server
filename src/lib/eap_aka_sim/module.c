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
 * @file src/lib/eap_aka_sim/module.c
 * @brief Common encode/decode functions for EAP subtype modules
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/util/rand.h>

#include "attrs.h"
#include "base.h"
#include "module.h"

/** Encode EAP session data from attributes
 *
 */
static unlang_action_t mod_encode(rlm_rcode_t *p_result, module_ctx_t const *mctx,
				  request_t *request, UNUSED void *rctx)
{
	eap_aka_sim_module_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_module_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_mod_session_t	*mod_session = talloc_get_type_abort(eap_session->opaque,
										eap_aka_sim_mod_session_t);
	fr_pair_t			*subtype_vp;

	static eap_code_t		rcode_to_eap_code[RLM_MODULE_NUMCODES] = {
						[RLM_MODULE_REJECT]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_FAIL]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_OK]		= FR_EAP_CODE_SUCCESS,
						[RLM_MODULE_HANDLED]	= FR_EAP_CODE_REQUEST,
						[RLM_MODULE_INVALID]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_DISALLOW]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_NOTFOUND]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_NOOP]	= FR_EAP_CODE_FAILURE,
						[RLM_MODULE_UPDATED]	= FR_EAP_CODE_FAILURE
					};
	eap_code_t			code;
	rlm_rcode_t			rcode = unlang_interpret_stack_result(request);
	fr_aka_sim_ctx_t		encode_ctx;
	uint8_t	const			*request_hmac_extra = NULL;
	size_t				request_hmac_extra_len = 0;
	fr_pair_t			*vp;
	int				ret;

	/*
	 *	If there's no subtype vp, we look at the rcode
	 *	from the virtual server to determine what kind
	 *	of EAP response to send.
	 */
	subtype_vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_subtype);
	if (!subtype_vp) {
		eap_session->this_round->request->code = (rcode == RLM_MODULE_OK) ?
								FR_EAP_CODE_SUCCESS : FR_EAP_CODE_FAILURE;
		/*
		 *	RFC 3748 requires the request and response
		 *	IDs to be identical for EAP-SUCCESS and
		 *	EAP-FAILURE.
		 *
		 *	The EAP common code will do the right thing
		 *	here if we just tell it we haven't se the
		 *	request ID.
		 */
		eap_session->this_round->set_request_id = false;
		eap_session->finished = true;
		TALLOC_FREE(eap_session->opaque);

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	If there is a subtype vp, verify the return
	 *	code allows us send EAP-SIM/AKA/AKA' data back.
	 */
	code = rcode_to_eap_code[rcode];
	if (code != FR_EAP_CODE_REQUEST) {
		eap_session->this_round->request->code = code;
		eap_session->this_round->set_request_id = false;
		eap_session->finished = true;
		TALLOC_FREE(eap_session->opaque);

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	It's not an EAP-Success or an EAP-Failure
	 *	it's a real EAP-SIM/AKA/AKA' response.
	 */
	eap_session->this_round->request->type.num = inst->type;
	eap_session->this_round->request->code = code;
	eap_session->this_round->set_request_id = true;

	/*
	 *	RFC 3748 says this ID need only be different to
	 *	the previous ID.
	 *
	 *	We need to set the type, code, id here as the
	 *	HMAC operates on the complete packet we're
	 *	returning including the EAP headers, so the packet
	 *	fields must be filled in before we call encode.
	 */
	eap_session->this_round->request->id = mod_session->id++;

	/*
	 *	Perform different actions depending on the type
	 *	of request we're sending.
	 */
	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_IDENTITY:
	case FR_SUBTYPE_VALUE_SIM_START:
		if (RDEBUG_ENABLED2) break;

		/*
		 *	Figure out if the state machine is
		 *	requesting an ID.
		 */
		if ((vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_any_id_req)) ||
		    (vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_fullauth_id_req)) ||
		    (vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_permanent_id_req))) {
			RDEBUG2("Sending EAP-Request/%pV (%s)", &subtype_vp->data, vp->da->name);
		} else {
			RDEBUG2("Sending EAP-Request/%pV", &subtype_vp->data);
		}
		break;

	/*
	 *	Deal with sending bidding VP
	 *
	 *	This can either come from policy or be set by the default
	 *	virtual server.
	 *
	 *	We send AT_BIDDING in our EAP-Request/AKA-Challenge message
	 *	to tell the supplicant that if it has AKA' available/enabled
	 *	it should have used that.
	 */
	case FR_SUBTYPE_VALUE_AKA_CHALLENGE:
		vp = fr_pair_find_by_da(&request->reply_pairs, attr_eap_aka_sim_bidding);

		/*
		 *	Explicit NO
		 */
		if (inst->aka.send_at_bidding_prefer_prime_is_set &&
		    !inst->aka.send_at_bidding_prefer_prime) {
			if (vp) pair_delete_reply(attr_eap_aka_sim_bidding);
		/*
		 *	Implicit or explicit YES
		 */
		} else if (inst->aka.send_at_bidding_prefer_prime) {
			MEM(pair_append_reply(&vp, attr_eap_aka_sim_bidding) >= 0);
			vp->vp_uint16 = FR_BIDDING_VALUE_PREFER_AKA_PRIME;
		}
		FALL_THROUGH;

	case FR_SUBTYPE_VALUE_SIM_CHALLENGE:
	case FR_SUBTYPE_VALUE_AKA_SIM_REAUTHENTICATION:
		/*
		 *	Include our copy of the checkcode if we've been
		 *      calculating it.
		 */
		if (mod_session->checkcode_state) {
			uint8_t *checkcode;

			MEM(pair_update_reply(&vp, attr_eap_aka_sim_checkcode) >= 0);
			if (fr_aka_sim_crypto_finalise_checkcode(vp, &checkcode, mod_session->checkcode_state) < 0) {
				RPWDEBUG("Failed calculating checkcode");
				pair_delete_reply(vp);
			}
			fr_pair_value_memdup_buffer_shallow(vp, checkcode, false);	/* Buffer already in the correct ctx */
		}

		/*
		 *	Extra data to append to the packet when signing.
		 */
		vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_hmac_extra_request);
		if (vp) {
			request_hmac_extra = vp->vp_octets;
			request_hmac_extra_len = vp->vp_length;
		}

		/*
		 *	Extra data to append to the response packet when
		 *	validating the signature.
		 */
		vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_hmac_extra_response);
		if (vp) {
			fr_assert(!mod_session->response_hmac_extra);
			MEM(mod_session->response_hmac_extra = talloc_memdup(mod_session,
										vp->vp_octets, vp->vp_length));
			mod_session->response_hmac_extra_len = vp->vp_length;
		}
		/*
		 *	Key we use for encrypting and decrypting attributes.
		 */
		vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_k_encr);
		if (vp) {
			fr_assert(!mod_session->ctx.k_encr);
			MEM(mod_session->ctx.k_encr = talloc_memdup(mod_session, vp->vp_octets, vp->vp_length));
		}

		/*
		 *	Key we use for signing and validating mac values.
		 */
		vp = fr_pair_find_by_da(&request->control_pairs, attr_eap_aka_sim_k_aut);
		if (vp) {
			fr_assert(!mod_session->ctx.k_aut);
			MEM(mod_session->ctx.k_aut = talloc_memdup(mod_session, vp->vp_octets, vp->vp_length));
			mod_session->ctx.k_aut_len = vp->vp_length;
		}

		fr_assert(mod_session->ctx.k_encr && mod_session->ctx.k_aut);
		FALL_THROUGH;

	default:
		RDEBUG2("Sending EAP-Request/%pV", &subtype_vp->data);
		break;
	}

	encode_ctx = mod_session->ctx;
	encode_ctx.eap_packet = eap_session->this_round->request;
	encode_ctx.hmac_extra = request_hmac_extra;
	encode_ctx.hmac_extra_len = request_hmac_extra_len;

	RDEBUG2("Encoding attributes");
	log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->reply_pairs, NULL);
	ret = fr_aka_sim_encode(request, &request->reply_pairs, &encode_ctx);
	if (ret <= 0) RETURN_MODULE_FAIL;

	switch (subtype_vp->vp_uint16) {
	case FR_SUBTYPE_VALUE_AKA_IDENTITY:
		/*
		 *	Ingest the identity message into the checkcode
		 */
		if (mod_session->ctx.checkcode_md) {
			RDEBUG2("Updating checkcode");
			if (!mod_session->checkcode_state &&
			    (fr_aka_sim_crypto_init_checkcode(mod_session, &mod_session->checkcode_state,
							      mod_session->ctx.checkcode_md) < 0)) {
				RPWDEBUG("Failed initialising checkcode");
				break;
			}

			if (fr_aka_sim_crypto_update_checkcode(mod_session->checkcode_state,
							       eap_session->this_round->request) < 0) {
				RPWDEBUG("Failed updating checkcode");
			}
		}
		break;

	default:
		break;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;	/* rcode is already correct */
}

/** Decode EAP session data into attribute
 *
 */
unlang_action_t eap_aka_sim_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_aka_sim_module_conf_t	*inst = talloc_get_type_abort(mctx->instance, eap_aka_sim_module_conf_t);
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_mod_session_t	*mod_session = talloc_get_type_abort(eap_session->opaque,
									     eap_aka_sim_mod_session_t);
	fr_pair_t			*subtype_vp;
	fr_dcursor_t			cursor;
	int				ret;
	fr_aka_sim_ctx_t		decode_ctx;

	switch (eap_session->this_round->response->type.num) {
	default:
		REDEBUG2("Unsupported EAP type (%u)", eap_session->this_round->response->type.num);
		RETURN_MODULE_REJECT;

	case FR_EAP_METHOD_IDENTITY:
	case FR_EAP_METHOD_NAK:	/* Peer NAK'd our original suggestion */
		break;

	/*
	 *	Only decode data for EAP-SIM/AKA/AKA' responses
	 */
	case FR_EAP_METHOD_SIM:
	case FR_EAP_METHOD_AKA:
	case FR_EAP_METHOD_AKA_PRIME:
		fr_dcursor_init(&cursor, &request->request_pairs);

		decode_ctx = mod_session->ctx;
		decode_ctx.hmac_extra = mod_session->response_hmac_extra;
		decode_ctx.hmac_extra_len = mod_session->response_hmac_extra_len;
		decode_ctx.eap_packet = eap_session->this_round->response;

		ret = fr_aka_sim_decode(request,
					&cursor,
					dict_eap_aka_sim,
					eap_session->this_round->response->type.data,
					eap_session->this_round->response->type.length,
					&decode_ctx);

		/*
		 *	Only good for one response packet
		 */
		TALLOC_FREE(mod_session->response_hmac_extra);
		mod_session->response_hmac_extra_len = 0;

		/*
		 *	RFC 4187 says we *MUST* notify, not just send
		 *	an EAP-Failure in this case where we cannot
		 *	decode an EAP-AKA packet.
		 *
		 *	We instead call the state machine and allow it
		 *	to fail when it can't find the necessary
		 *	attributes.
		 */
		if (ret < 0) {
			RPEDEBUG2("Failed decoding attributes");
			goto done;
		}

		if (!fr_pair_list_empty(&request->request_pairs) && RDEBUG_ENABLED2) {
			RDEBUG2("Decoded attributes");
			log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->request_pairs, NULL);
		}

		subtype_vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_aka_sim_subtype);
		if (!subtype_vp) {
			REDEBUG2("Missing Sub-Type");	/* Let the state machine enter the right state */
			break;
		}

		RDEBUG2("Received EAP-Response/%pV", &(subtype_vp)->data);

		switch (subtype_vp->vp_uint16) {
		/*
		 *	Ingest the identity message into the checkcode
		 */
		case FR_SUBTYPE_VALUE_AKA_IDENTITY:
			if (mod_session->checkcode_state) {
				RDEBUG2("Updating checkcode");
				if (fr_aka_sim_crypto_update_checkcode(mod_session->checkcode_state,
								       eap_session->this_round->response) < 0) {
					RPWDEBUG("Failed updating checkcode");
				}
			}
			break;

		case FR_SUBTYPE_VALUE_AKA_SIM_REAUTHENTICATION:
		case FR_SUBTYPE_VALUE_AKA_CHALLENGE:
			/*
			 *	Include our copy of the checkcode if we've been
			 *      calculating it.  This is put in the control list
			 *	so the state machine can check they're identical.
			 *
			 *	This lets us simulate checkcode failures easily
			 *	when testing the state machine.
			 */
			if (mod_session->checkcode_state) {
				uint8_t		*checkcode;
				fr_pair_t	*vp;

				MEM(pair_append_control(&vp, attr_eap_aka_sim_checkcode) >= 0);
				if (fr_aka_sim_crypto_finalise_checkcode(vp, &checkcode, mod_session->checkcode_state) < 0) {
					RPWDEBUG("Failed calculating checkcode");
					pair_delete_control(vp);
				}
				fr_pair_value_memdup_buffer_shallow(vp, checkcode, false);	/* Buffer already in the correct ctx */

			}
			FALL_THROUGH;

		case FR_SUBTYPE_VALUE_SIM_CHALLENGE:
		{
			fr_pair_t	*vp;
			ssize_t		slen;
			uint8_t		*buff;

			MEM(pair_append_control(&vp, attr_eap_aka_sim_mac) >= 0);
			fr_pair_value_mem_alloc(vp, &buff, AKA_SIM_MAC_DIGEST_SIZE, false);

			slen = fr_aka_sim_crypto_sign_packet(buff, eap_session->this_round->response, true,
							     mod_session->ctx.hmac_md,
							     mod_session->ctx.k_aut,
							     mod_session->ctx.k_aut_len,
							     mod_session->response_hmac_extra,
							     mod_session->response_hmac_extra_len);
			if (slen <= 0) {
				RPEDEBUG("AT_MAC calculation failed");
				pair_delete_control(vp);
				RETURN_MODULE_FAIL;
			}
		}
			break;

		default:
			break;
		}
		break;
	}

done:
	/*
	 *	Setup our encode function as the resumption
	 *	frame when the state machine finishes with
	 *	this round.
	 */
	(void)unlang_module_yield(request, mod_encode, NULL, NULL);

	if (virtual_server_push(request, inst->virtual_server, UNLANG_SUB_FRAME) < 0) {
		unlang_interpet_frame_discard(request);
		RETURN_MODULE_FAIL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}
