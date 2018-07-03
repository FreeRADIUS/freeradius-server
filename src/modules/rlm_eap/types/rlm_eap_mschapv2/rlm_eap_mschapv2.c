/*
 * rlm_eap_mschapv2.c    Handles that are called from eap
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
 * @copyright 2003,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include <freeradius-devel/unlang.h>
#include "eap_mschapv2.h"

#include <freeradius-devel/rad_assert.h>

static int auth_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

typedef struct {
	bool			with_ntdomain_hack;
	bool			send_error;
	char const		*identity;
	fr_dict_enum_t		*auth_type;
} rlm_eap_mschapv2_t;

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("with_ntdomain_hack", FR_TYPE_BOOL, rlm_eap_mschapv2_t, with_ntdomain_hack), .dflt = "no" },

	{ FR_CONF_OFFSET("auth_type", FR_TYPE_VOID, rlm_eap_mschapv2_t, auth_type), .func = auth_type_parse, .dflt = "mschap" },
	{ FR_CONF_OFFSET("send_error", FR_TYPE_BOOL, rlm_eap_mschapv2_t, send_error), .dflt = "no" },
	{ FR_CONF_OFFSET("identity", FR_TYPE_STRING, rlm_eap_mschapv2_t, identity) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_eap_mschapv2_dict[];
fr_dict_autoload_t rlm_eap_mschapv2_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_ms_chap_peer_challenge;
static fr_dict_attr_t const *attr_ms_chap_user_name;

static fr_dict_attr_t const *attr_ms_chap_challenge;
static fr_dict_attr_t const *attr_ms_chap_error;
static fr_dict_attr_t const *attr_ms_chap_nt_enc_pw;
static fr_dict_attr_t const *attr_ms_chap2_cpw;
static fr_dict_attr_t const *attr_ms_chap2_response;
static fr_dict_attr_t const *attr_ms_chap2_success;
static fr_dict_attr_t const *attr_ms_mppe_encryption_policy;
static fr_dict_attr_t const *attr_ms_mppe_encryption_type;
static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_eap_mschapv2_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_mschapv2_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_peer_challenge, .name = "MS-CHAP-Peer-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_user_name, .name = "MS-CHAP-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_ms_chap_challenge, .name = "MS-CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_error, .name = "MS-CHAP-Error", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_ms_chap_nt_enc_pw, .name = "MS-CHAP-NT-Enc-PW", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_cpw, .name = "MS-CHAP2-CPW", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_response, .name = "MS-CHAP2-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_success, .name = "MS-CHAP2-Success", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_encryption_policy, .name = "MS-MPPE-Encryption-Policy", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_encryption_type, .name = "MS-MPPE-Encryption-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "MS-MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "MS-MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static void fix_mppe_keys(eap_session_t *eap_session, mschapv2_opaque_t *data)
{
	fr_pair_list_copy_by_da(data, &data->mppe_keys, eap_session->request->reply->vps,
				attr_ms_mppe_encryption_policy);
	fr_pair_list_copy_by_da(data, &data->mppe_keys, eap_session->request->reply->vps,
				attr_ms_mppe_encryption_type);
	fr_pair_list_copy_by_da(data, &data->mppe_keys, eap_session->request->reply->vps, attr_ms_mppe_recv_key);
	fr_pair_list_copy_by_da(data, &data->mppe_keys, eap_session->request->reply->vps, attr_ms_mppe_send_key);
}

/** Translate a string auth_type into an enumeration value
 *
 * @param[in] ctx	to allocate data.
 * @param[out] out	Where to write the auth_type we created or resolved.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the auth_type.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int auth_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*auth_type = cf_pair_value(cf_item_to_pair(ci));

	if (fr_dict_enum_add_alias_next(attr_auth_type, auth_type) < 0) {
		cf_log_err(ci, "Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	*((fr_dict_enum_t **)out) = fr_dict_enum_by_alias(attr_auth_type, auth_type, -1);

	return 0;
}

/*
 *	Compose the response.
 */
static int eapmschapv2_compose(rlm_eap_mschapv2_t const *inst, eap_session_t *eap_session,
			       VALUE_PAIR *reply) CC_HINT(nonnull);
static int eapmschapv2_compose(rlm_eap_mschapv2_t const *inst, eap_session_t *eap_session,
			       VALUE_PAIR *reply)
{
	uint8_t			*ptr;
	int16_t			length;
	mschapv2_header_t	*hdr;
	eap_round_t		*eap_round = eap_session->this_round;
	REQUEST			*request = eap_session->request;

	eap_round->request->code = FR_EAP_CODE_REQUEST;
	eap_round->request->type.num = FR_EAP_MSCHAPV2;

	/*
	 *	Always called with vendor Microsoft
	 */
	if (reply->da == attr_ms_chap_challenge) {
		/*
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Code      |   Identifier  |            Length             |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |   MS-Length   |  Value-Size   |  Challenge...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                             Challenge...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                             Server Name...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		length = MSCHAPV2_HEADER_LEN + MSCHAPV2_CHALLENGE_LEN + (talloc_array_length(inst->identity) - 1);
		eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, length);

		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (!eap_round->request->type.data) return -1;
		eap_round->request->type.length = length;

		ptr = eap_round->request->type.data;
		hdr = (mschapv2_header_t *) ptr;

		hdr->opcode = FR_EAP_MSCHAPV2_CHALLENGE;
		hdr->mschapv2_id = eap_round->response->id + 1;
		length = htons(length);
		memcpy(hdr->ms_length, &length, sizeof(uint16_t));
		hdr->value_size = MSCHAPV2_CHALLENGE_LEN;

		ptr += MSCHAPV2_HEADER_LEN;

		/*
		 *	Copy the Challenge, success, or error over.
		 */
		memcpy(ptr, reply->vp_octets, reply->vp_length);
		memcpy((ptr + reply->vp_length), inst->identity, (talloc_array_length(inst->identity) - 1));
	} else if (reply->da == attr_ms_chap2_success) {
		/*
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Code      |   Identifier  |            Length             |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |   MS-Length   |                    Message...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		RDEBUG2("MSCHAP Success");
		length = 46;
		eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, length);
		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (!eap_round->request->type.data) return -1;
		memset(eap_round->request->type.data, 0, length);
		eap_round->request->type.length = length;

		eap_round->request->type.data[0] = FR_EAP_MSCHAPV2_SUCCESS;
		eap_round->request->type.data[1] = eap_round->response->id;
		length = htons(length);
		memcpy((eap_round->request->type.data + 2), &length, sizeof(uint16_t));
		memcpy((eap_round->request->type.data + 4), reply->vp_strvalue + 1, 42);
	} else if (reply->da == attr_ms_chap_error) {
		REDEBUG("MSCHAP Failure");
		length = 4 + reply->vp_length - 1;
		eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, length);

		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (!eap_round->request->type.data) return 0;
		memset(eap_round->request->type.data, 0, length);
		eap_round->request->type.length = length;

		eap_round->request->type.data[0] = FR_EAP_MSCHAPV2_FAILURE;
		eap_round->request->type.data[1] = eap_round->response->id;
		length = htons(length);
		memcpy((eap_round->request->type.data + 2), &length, sizeof(uint16_t));
		/*
		 *	Copy the entire failure message.
		 */
		memcpy((eap_round->request->type.data + 4), reply->vp_strvalue + 1, reply->vp_length - 1);
	} else {
		RERROR("Internal sanity check failed");
		return -1;
	}

	return 0;
}


static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session);

#ifdef WITH_PROXY
/*
 *	Do post-proxy processing,
 *	0 = fail
 *	1 = OK.
 *
 *	Called from rlm_eap.c, eap_postproxy().
 */
static int CC_HINT(nonnull) mschap_postproxy(eap_session_t *eap_session, UNUSED void *tunnel_data)
{
	VALUE_PAIR *response = NULL;
	mschapv2_opaque_t *data;
	REQUEST *request = eap_session->request;

	data = talloc_get_type_abort(eap_session->opaque, mschapv2_opaque_t);
	rad_assert(request != NULL);

	RDEBUG2("Passing reply from proxy back into the tunnel %d", request->reply->code);

	/*
	 *	There is only a limited number of possibilities.
	 */
	switch (request->reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
		RDEBUG2("Proxied authentication succeeded");

		/*
		 *	Move the attribute, so it doesn't go into
		 *	the reply.
		 */
		fr_pair_list_copy_by_da(data, &response, request->reply->vps, attr_ms_chap2_success);
		break;

	default:
	case FR_CODE_ACCESS_REJECT:
		REDEBUG("Proxied authentication was rejected");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	No response, die.
	 */
	if (!response) {
		REDEBUG("Proxied reply contained no MS-CHAP2-Success or MS-CHAP-Error");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Done doing EAP proxy stuff.
	 */
	request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
	if (!fr_cond_assert(eap_session->inst)) return 0;
	eapmschapv2_compose(eap_session->inst, eap_session, response);
	data->code = FR_EAP_MSCHAPV2_SUCCESS;

	/*
	 *	Delete MPPE keys & encryption policy
	 *
	 *	FIXME: Use intelligent names...
	 */
	fix_mppe_keys(eap_session, data);

	/*
	 *	Save any other attributes for re-use in the final
	 *	access-accept e.g. vlan, etc. This lets the PEAP
	 *	use_tunneled_reply code work
	 */
	MEM(fr_pair_list_copy(data, &data->reply, request->reply->vps) >= 0);

	/*
	 *	And we need to challenge the user, not ack/reject them,
	 *	so we re-write the ACK to a challenge.  Yuck.
	 */
	request->reply->code = FR_CODE_ACCESS_CHALLENGE;
	fr_pair_list_free(&response);

	return RLM_MODULE_HANDLED;
}
#endif


static rlm_rcode_t mschap_finalize(REQUEST *request, rlm_eap_mschapv2_t *inst,
				   eap_session_t *eap_session, rlm_rcode_t rcode)
{
	mschapv2_opaque_t	*data = talloc_get_type_abort(eap_session->opaque, mschapv2_opaque_t);
	eap_round_t		*eap_round = eap_session->this_round;
	VALUE_PAIR		*response = NULL;

	/*
	 *	Delete MPPE keys & encryption policy.  We don't
	 *	want these here.
	 */
	fix_mppe_keys(eap_session, data);

	/*
	 *	Take the response from the mschap module, and
	 *	return success or failure, depending on the result.
	 */
	if (rcode == RLM_MODULE_OK) {
		if (fr_pair_list_copy_by_da(data, &response, request->reply->vps, attr_ms_chap2_success) < 0) {
			RPERROR("Failed copying %s", attr_ms_chap2_success->name);
			return RLM_MODULE_FAIL;
		}

		data->code = FR_EAP_MSCHAPV2_SUCCESS;
	} else if (inst->send_error) {
		if (fr_pair_list_copy_by_da(data, &response, request->reply->vps, attr_ms_chap_error) < 0) {
			RPERROR("Failed copying %s", attr_ms_chap_error->name);
			return RLM_MODULE_FAIL;
		}
		if (response) {
			int n, err, retry;
			char buf[34];

			VP_VERIFY(response);

			RDEBUG2("MSCHAP-Error: %s", response->vp_strvalue);

			/*
			 *	Parse the new challenge out of the
			 *	MS-CHAP-Error, so that if the client
			 *	issues a re-try, we will know which
			 *	challenge value that they used.
			 */
			n = sscanf(response->vp_strvalue, "%*cE=%d R=%d C=%32s", &err, &retry, &buf[0]);
			if (n == 3) {
				RDEBUG2("Found new challenge from MS-CHAP-Error: err=%d retry=%d challenge=%s",
					err, retry, buf);
				fr_hex2bin(data->auth_challenge, 16, buf, strlen(buf));
			} else {
				RDEBUG2("Could not parse new challenge from MS-CHAP-Error: %d", n);
			}
		}
		data->code = FR_EAP_MSCHAPV2_FAILURE;
	} else {
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		return RLM_MODULE_REJECT;
	}

	/*
	 *	No response, die.
	 */
	if (!response) {
		REDEBUG("No %s or %s attributes were found", attr_ms_chap2_success->name, attr_ms_chap_error->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Compose the response (whatever it is),
	 *	and return it to the over-lying EAP module.
	 */
	eapmschapv2_compose(eap_session->inst, eap_session, response);
	fr_pair_list_free(&response);

	return RLM_MODULE_OK;
}


/*
 *	Keep processing the Auth-Type until it doesn't return YIELD.
 */
static rlm_rcode_t mod_process_auth_type(void *instance, eap_session_t *eap_session)
{
	rlm_rcode_t	rcode;
	rlm_eap_mschapv2_t	*inst = instance;
	REQUEST		*request = eap_session->request;

	rcode = unlang_interpret_continue(request);

	if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_REJECT;

	if (rcode == RLM_MODULE_YIELD) return rcode;

	return mschap_finalize(request, inst, eap_session, rcode);}

/*
 *	Authenticate a previously sent challenge.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session)
{
	rlm_rcode_t		rcode;
	int			ccode;
	uint8_t			*p;
	size_t			length;
	char			*q;
	mschapv2_opaque_t	*data = talloc_get_type_abort(eap_session->opaque, mschapv2_opaque_t);
	eap_round_t		*eap_round = eap_session->this_round;
	VALUE_PAIR		*auth_challenge, *response, *name;
	rlm_eap_mschapv2_t	*inst = (rlm_eap_mschapv2_t *)instance;
	REQUEST			*request = eap_session->request;
	CONF_SECTION		*unlang;

	if (!fr_cond_assert(eap_session->inst)) return 0;

	/*
	 *	Sanity check the response.
	 */
	if (eap_round->response->length < 6) {
		REDEBUG("Response too short, expected at least 6 bytes, got %zu bytes",
			eap_round->response->length);
		return RLM_MODULE_INVALID;
	}

	ccode = eap_round->response->type.data[0];

	switch (data->code) {
	case FR_EAP_MSCHAPV2_FAILURE:
		if (ccode == FR_EAP_MSCHAPV2_RESPONSE) {
			RDEBUG2("Authentication re-try from client after we sent a failure");
			break;
		}

		/*
		 * if we sent error 648 (password expired) to the client
		 * we might get an MSCHAP-CPW packet here; turn it into a
		 * regular MS-CHAP2-CPW packet and pass it to rlm_mschap
		 * (or proxy it, I guess)
		 */
		if (ccode == FR_EAP_MSCHAPV2_CHGPASSWD) {
			VALUE_PAIR *cpw;
			int mschap_id = eap_round->response->type.data[1];
			int copied = 0 ,seq = 1;

			RDEBUG2("Password change packet received");

			MEM(pair_update_request(&auth_challenge, attr_ms_chap_challenge) >= 0);
			fr_pair_value_memcpy(auth_challenge, data->auth_challenge, MSCHAPV2_CHALLENGE_LEN);

			MEM(pair_update_request(&cpw, attr_ms_chap2_cpw) >= 0);
			p = talloc_array(cpw, uint8_t, 68);
			p[0] = 7;
			p[1] = mschap_id;
			memcpy(p + 2, eap_round->response->type.data + 520, 66);
			fr_pair_value_memsteal(cpw, p);

			/*
			 * break the encoded password into VPs (3 of them)
			 */
			while (copied < 516) {
				VALUE_PAIR *nt_enc;

				int to_copy = 516 - copied;
				if (to_copy > 243) to_copy = 243;

				MEM(pair_add_request(&nt_enc, attr_ms_chap_nt_enc_pw) >= 0);
				p = talloc_array(nt_enc, uint8_t, 4 + to_copy);
				p[0] = 6;
				p[1] = mschap_id;
				p[2] = 0;
				p[3] = seq++;
				memcpy(p + 4, eap_round->response->type.data + 4 + copied, to_copy);
				fr_pair_value_memsteal(nt_enc, p);

				copied += to_copy;
			}

			RDEBUG2("Built change password packet");
			log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);

			/*
			 * jump to "authentication"
			 */
			goto packet_ready;
		}

		/*
		 * we sent a failure and are expecting a failure back
		 */
		if (ccode != FR_EAP_MSCHAPV2_FAILURE) {
			REDEBUG("Sent FAILURE expecting FAILURE but got %d", ccode);
			return RLM_MODULE_INVALID;
		}

failure:
		request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		return RLM_MODULE_REJECT;

	case FR_EAP_MSCHAPV2_SUCCESS:
		/*
		 * we sent a success to the client; some clients send a
		 * success back as-per the RFC, some send an ACK. Permit
		 * both, I guess...
		 */

		switch (ccode) {
		case FR_EAP_MSCHAPV2_SUCCESS:
			eap_round->request->code = FR_EAP_CODE_SUCCESS;

			MEM(fr_pair_list_copy(request->reply, &request->reply->vps, data->mppe_keys) >= 0);
			/* FALL-THROUGH */

		case FR_EAP_MSCHAPV2_ACK:
#ifdef WITH_PROXY
			/*
			 *	It's a success.  Don't proxy it.
			 */
			request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
#endif
			MEM(fr_pair_list_copy(request->reply, &request->reply->vps, data->reply) >= 0);
			return RLM_MODULE_OK;
		}
		REDEBUG("Sent SUCCESS expecting SUCCESS (or ACK) but got %d", ccode);
		return RLM_MODULE_INVALID;

	case FR_EAP_MSCHAPV2_CHALLENGE:
		if (ccode == FR_EAP_MSCHAPV2_FAILURE) goto failure;

		/*
		 * we sent a challenge, expecting a response
		 */
		if (ccode != FR_EAP_MSCHAPV2_RESPONSE) {
			REDEBUG("Sent CHALLENGE expecting RESPONSE but got %d", ccode);
			return RLM_MODULE_INVALID;
		}
		/* authentication happens below */
		break;

	default:
		/* should never happen */
		REDEBUG("Unknown state %d", data->code);
		return RLM_MODULE_FAIL;
	}


	/*
	 *	Ensure that we have at least enough data
	 *	to do the following checks.
	 *
	 *	EAP header (4), EAP type, MS-CHAP opcode,
	 *	MS-CHAP ident, MS-CHAP data length (2),
	 *	MS-CHAP value length.
	 */
	if (eap_round->response->length < (4 + 1 + 1 + 1 + 2 + 1)) {
		REDEBUG("Response is too short");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The 'value_size' is the size of the response,
	 *	which is supposed to be the response (48
	 *	bytes) plus 1 byte of flags at the end.
	 *
	 *	NOTE: When using Cisco NEAT with EAP-MSCHAPv2, the
	 *	      switch supplicant will send MSCHAPv2 data (EAP type = 26)
	 *	      but will always set a value_size of 16 and NULL out the
	 *	      peer challenge.
	 *
	 */
	if ((eap_round->response->type.data[4] != 49) &&
	    (eap_round->response->type.data[4] != 16)) {
		REDEBUG("Response is of incorrect length %d", eap_round->response->type.data[4]);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The MS-Length field is 5 + value_size + length
	 *	of name, which is put after the response.
	 */
	length = (eap_round->response->type.data[2] << 8) | eap_round->response->type.data[3];
	if ((length < (5 + 49)) || (length > (256 + 5 + 49))) {
		REDEBUG("Response contains contradictory length %zu %d", length, 5 + 49);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We now know that the user has sent us a response
	 *	to the challenge.  Let's try to authenticate it.
	 *
	 *	We do this by taking the challenge from 'data',
	 *	the response from the EAP packet, and creating VALUE_PAIR's
	 *	to pass to the 'mschap' module.  This is a little wonky,
	 *	but it works.
	 */
	MEM(pair_update_request(&auth_challenge, attr_ms_chap_challenge) >= 0);
	fr_pair_value_memcpy(auth_challenge, data->auth_challenge, MSCHAPV2_CHALLENGE_LEN);

	MEM(pair_update_request(&response, attr_ms_chap2_response) >= 0);
	p = talloc_array(response, uint8_t, MSCHAPV2_RESPONSE_LEN);
	p[0] = eap_round->response->type.data[1];
	p[1] = eap_round->response->type.data[5 + MSCHAPV2_RESPONSE_LEN];
	memcpy(p + 2, &eap_round->response->type.data[5], MSCHAPV2_RESPONSE_LEN - 2);

	/*
	 *	If we're forcing a peer challenge, use it instead of
	 *	the challenge sent by the client.
	 */
	if (data->has_peer_challenge) memcpy(p + 2, data->peer_challenge, MSCHAPV2_CHALLENGE_LEN);
	fr_pair_value_memsteal(response, p);

	/*
	 *	MS-Length - MS-Value - 5.
	 */
	MEM(pair_update_request(&name, attr_ms_chap_user_name) >= 0);
	name->vp_tainted = true;
	name->vp_length = length - 49 - 5;
	name->vp_strvalue = q = talloc_array(name, char, name->vp_length + 1);
	memcpy(q, &eap_round->response->type.data[4 + MSCHAPV2_RESPONSE_LEN], name->vp_length);
	q[name->vp_length] = '\0';

packet_ready:

#ifdef WITH_PROXY
	/*
	 *	If this options is set, then we do NOT authenticate the
	 *	user here.  Instead, now that we've added the MS-CHAP
	 *	attributes to the request, we STOP, and let the outer
	 *	tunnel code handle it.
	 *
	 *	This means that the outer tunnel code will DELETE the
	 *	EAP attributes, and proxy the MS-CHAP attributes to a
	 *	home server.
	 */
	if (request->options & RAD_REQUEST_OPTION_PROXY_EAP) {
		int			ret;
		char			*username = NULL;
		eap_tunnel_data_t	*tunnel;

		RDEBUG2("Cancelling authentication and letting it be proxied");

		/*
		 *	Set up the callbacks for the tunnel
		 */
		tunnel = talloc_zero(request, eap_tunnel_data_t);

		tunnel->tls_session = instance;
		tunnel->callback = mschap_postproxy;

		/*
		 *	Associate the callback with the request.
		 */
		ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_TUNNEL_CALLBACK,
				       tunnel, false, false, false);
		fr_cond_assert(ret == 0);

		/*
		 *	The State attribute is NOT supposed to
		 *	go into the proxied packet, it will confuse
		 *	other RADIUS servers, and they will discard
		 *	the request.
		 *
		 *	The PEAP module will take care of adding
		 *	the State attribute back, before passing
		 *	the eap_session & request back into the tunnel.
		 */
		pair_delete_request(attr_state);

		/*
		 *	Fix the User-Name when proxying, to strip off
		 *	the NT Domain, if we're told to, and a User-Name
		 *	exists, and there's a \\, meaning an NT-Domain
		 *	in the user name, THEN discard the user name.
		 */
		if (inst->with_ntdomain_hack &&
		    ((auth_challenge = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY)) != NULL) &&
		    ((username = memchr(auth_challenge->vp_octets, '\\', auth_challenge->vp_length)) != NULL)) {
			/*
			 *	Wipe out the NT domain.
			 *
			 *	FIXME: Put it into MS-CHAP-Domain?
			 */
			username++; /* skip the \\ */
			fr_pair_value_strcpy(auth_challenge, username);
		}

		/*
		 *	Remember that in the post-proxy stage, we've got
		 *	to do the work below, AFTER the call to MS-CHAP
		 *	authentication...
		 */
		return RLM_MODULE_OK;
	}
#endif

	/*
	 *	This is a wild & crazy hack.
	 */
	unlang = cf_section_find(request->server_cs, "authenticate", inst->auth_type->alias);
	if (!unlang) {
		rcode = process_authenticate(inst->auth_type->value->vb_uint32, request);
	} else {
		unlang_push_section(request, unlang, RLM_MODULE_FAIL, UNLANG_TOP_FRAME);
		rcode = unlang_interpret_continue(request);

		/*
		 *	If it's yielding, set up the process function
		 *	to continue after resume.
		 */
		if (rcode == RLM_MODULE_YIELD) {
			eap_session->process = mod_process_auth_type;
			return rcode;
		}
	}

	return mschap_finalize(request, inst, eap_session, rcode);
}

/*
 *	Initiate the EAP-MSCHAPV2 session by sending a challenge to the peer.
 */
static rlm_rcode_t mod_session_init(void *instance, eap_session_t *eap_session)
{
	int			i;
	VALUE_PAIR		*auth_challenge;
	VALUE_PAIR		*peer_challenge;
	mschapv2_opaque_t	*data;
	REQUEST			*request = eap_session->request;
	uint8_t 		*p;
	bool			created_auth_challenge;

	if (!fr_cond_assert(instance)) return RLM_MODULE_FAIL;

	auth_challenge = fr_pair_find_by_da(request->control, attr_ms_chap_challenge, TAG_ANY);
	if (auth_challenge && (auth_challenge->vp_length != MSCHAPV2_CHALLENGE_LEN)) {
		RWDEBUG("&control:MS-CHAP-Challenge is incorrect length.  Ignoring it");
		auth_challenge = NULL;
	}

	peer_challenge = fr_pair_find_by_da(request->control, attr_ms_chap_peer_challenge, TAG_ANY);
	if (peer_challenge && (peer_challenge->vp_length != MSCHAPV2_CHALLENGE_LEN)) {
		RWDEBUG("&control:MS-CHAP-Peer-Challenge is incorrect length.  Ignoring it");
		peer_challenge = NULL;
	}

	if (auth_challenge) {
		created_auth_challenge = false;

		peer_challenge = fr_pair_find_by_da(request->control, attr_ms_chap_peer_challenge, TAG_ANY);
		if (peer_challenge && (peer_challenge->vp_length != MSCHAPV2_CHALLENGE_LEN)) {
			RWDEBUG("&control:MS-CHAP-Peer-Challenge is incorrect length.  Ignoring it");
			peer_challenge = NULL;
		}

	} else {
		created_auth_challenge = true;
		peer_challenge = NULL;

		/*
		 *	Get a random challenge.
		 */
		MEM(auth_challenge = fr_pair_afrom_da(eap_session, attr_ms_chap_challenge));
		p = talloc_array(auth_challenge, uint8_t, MSCHAPV2_CHALLENGE_LEN);
		for (i = 0; i < MSCHAPV2_CHALLENGE_LEN; i++) p[i] = fr_rand();
		fr_pair_value_memsteal(auth_challenge, p);
	}
	RDEBUG2("Issuing Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	data = talloc_zero(eap_session, mschapv2_opaque_t);
	rad_assert(data != NULL);

	/*
	 *	We're at the stage where we're challenging the user.
	 */
	data->code = FR_EAP_MSCHAPV2_CHALLENGE;
	memcpy(data->auth_challenge, auth_challenge->vp_octets, MSCHAPV2_CHALLENGE_LEN);
	data->mppe_keys = NULL;
	data->reply = NULL;

	if (peer_challenge) {
		data->has_peer_challenge = true;
		memcpy(data->peer_challenge, peer_challenge->vp_octets, MSCHAPV2_CHALLENGE_LEN);
	}

	eap_session->opaque = data;

	/*
	 *	Compose the EAP-MSCHAPV2 packet out of the data structure,
	 *	and free it.
	 */
	eapmschapv2_compose(instance, eap_session, auth_challenge);
	if (created_auth_challenge) TALLOC_FREE(auth_challenge);

#ifdef WITH_PROXY
	/*
	 *	The EAP session doesn't have enough information to
	 *	proxy the "inside EAP" protocol.  Disable EAP proxying.
	 */
	eap_session->request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
#endif

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'eap_session->this_round', which will be given back
	 *	to us...
	 */
	eap_session->process = mod_process;

	return RLM_MODULE_HANDLED;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	rlm_eap_mschapv2_t *inst = talloc_get_type_abort(instance, rlm_eap_mschapv2_t);

	if (inst->identity && (strlen(inst->identity) > 255)) {
		cf_log_err(cs, "identity is too long");
		return -1;
	}

	if (!inst->identity) inst->identity = talloc_typed_asprintf(inst, "freeradius-%s", RADIUSD_VERSION_STRING);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_mschapv2;
rlm_eap_submodule_t rlm_eap_mschapv2 = {
	.name		= "eap_mschapv2",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_MSCHAPV2 },
	.inst_size	= sizeof(rlm_eap_mschapv2_t),
	.config		= submodule_config,
	.instantiate	= mod_instantiate,	/* Create new submodule instance */

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
