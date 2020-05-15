/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file eap_fast.c
 * @brief Contains the interfaces that are called from the main handler
 *
 * @author Alexander Clouter (alex@digriz.org.uk)

 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "eap_fast.h"
#include "eap_fast_crypto.h"
#include <freeradius-devel/util/sha1.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#define RANDFILL(x) do { fr_assert(sizeof(x) % sizeof(uint32_t) == 0); for (size_t i = 0; i < sizeof(x); i += sizeof(uint32_t)) *((uint32_t *)&x[i]) = fr_rand(); } while(0)

/**
 * RFC 4851 section 5.1 - EAP-FAST Authentication Phase 1: Key Derivations
 */
static void eap_fast_init_keys(REQUEST *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint8_t *buf;
	uint8_t *scratch;
	size_t ksize;

	RDEBUG2("Deriving EAP-FAST keys");

	fr_assert(t->s_imck == NULL);

	ksize = fr_tls_utils_keyblock_size_get(request, tls_session->ssl);
	fr_assert(ksize > 0);
	buf = talloc_array(request, uint8_t, ksize + sizeof(*t->keyblock));
	scratch = talloc_array(request, uint8_t, ksize + sizeof(*t->keyblock));

	t->keyblock = talloc(t, eap_fast_keyblock_t);

	eap_fast_tls_gen_challenge(tls_session->ssl, buf, scratch, ksize + sizeof(*t->keyblock), "key expansion");
	memcpy(t->keyblock, &buf[ksize], sizeof(*t->keyblock));
	memset(buf, 0, ksize + sizeof(*t->keyblock));

	t->s_imck = talloc_array(t, uint8_t, EAP_FAST_SIMCK_LEN);
	memcpy(t->s_imck, t->keyblock, EAP_FAST_SKS_LEN);	/* S-IMCK[0] = session_key_seed */

	t->cmk = talloc_array(t, uint8_t, EAP_FAST_CMK_LEN);	/* note that CMK[0] is not defined */
	t->imck_count = 0;

	talloc_free(buf);
	talloc_free(scratch);
}

/**
 * RFC 4851 section 5.2 - Intermediate Compound Key Derivations
 */
static void eap_fast_update_icmk(REQUEST *request, fr_tls_session_t *tls_session, uint8_t *msk)
{
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint8_t imck[EAP_FAST_SIMCK_LEN + EAP_FAST_CMK_LEN];

	RDEBUG2("Updating ICMK");

	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Inner Methods Compound Keys", msk, 32, imck, sizeof(imck));	//-V512

	memcpy(t->s_imck, imck, EAP_FAST_SIMCK_LEN);
	RHEXDUMP3(t->s_imck, EAP_FAST_SIMCK_LEN, "S-IMCK[j]");

	memcpy(t->cmk, &imck[EAP_FAST_SIMCK_LEN], EAP_FAST_CMK_LEN);
	RHEXDUMP3(t->cmk, EAP_FAST_CMK_LEN, "CMK[j]");

	t->imck_count++;

	/*
         * Calculate MSK/EMSK at the same time as they are coupled to ICMK
         *
         * RFC 4851 section 5.4 - EAP Master Session Key Generation
         */
	t->msk = talloc_array(t, uint8_t, EAP_FAST_KEY_LEN);
	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Session Key Generating Function", NULL, 0, t->msk, EAP_FAST_KEY_LEN);
	RHEXDUMP3(t->msk, EAP_FAST_KEY_LEN, "MSK");

	t->emsk = talloc_array(t, uint8_t, EAP_EMSK_LEN);
	T_PRF(t->s_imck, EAP_FAST_SIMCK_LEN, "Extended Session Key Generating Function", NULL, 0, t->emsk, EAP_EMSK_LEN);
	RHEXDUMP3(t->emsk, EAP_EMSK_LEN, "EMSK");
}

void eap_fast_tlv_append(fr_tls_session_t *tls_session, fr_dict_attr_t const *tlv, bool mandatory, int length, void const *data)
{
	uint16_t hdr[2];

	hdr[0] = (mandatory) ? htons(tlv->attr | EAP_FAST_TLV_MANDATORY) : htons(tlv->attr);
	hdr[1] = htons(length);

	tls_session->record_from_buff(&tls_session->clean_in, &hdr, 4);
	tls_session->record_from_buff(&tls_session->clean_in, data, length);
}

static void eap_fast_send_error(fr_tls_session_t *tls_session, int error)
{
	uint32_t value;
	value = htonl(error);

	eap_fast_tlv_append(tls_session, attr_eap_fast_error, true, sizeof(value), &value);
}

static void eap_fast_append_result(fr_tls_session_t *tls_session, FR_CODE code)
{
	eap_fast_tunnel_t	*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint16_t		state;
	fr_dict_attr_t const	*da;


	da = (t->result_final) ? attr_eap_fast_result : attr_eap_fast_intermediate_result;
	state = htons((code == FR_CODE_ACCESS_REJECT) ? EAP_FAST_TLV_RESULT_FAILURE : EAP_FAST_TLV_RESULT_SUCCESS);

	eap_fast_tlv_append(tls_session, da, true, sizeof(state), &state);
}

static void eap_fast_send_identity_request(REQUEST *request, fr_tls_session_t *tls_session, eap_session_t *eap_session)
{
	eap_packet_raw_t eap_packet;

	RDEBUG2("Sending EAP-Identity");

	eap_packet.code = FR_EAP_CODE_REQUEST;
	eap_packet.id = eap_session->this_round->response->id + 1;
	eap_packet.length[0] = 0;
	eap_packet.length[1] = EAP_HEADER_LEN + 1;
	eap_packet.data[0] = FR_EAP_METHOD_IDENTITY;

	eap_fast_tlv_append(tls_session, attr_eap_fast_eap_payload, true, sizeof(eap_packet), &eap_packet);
}

static void eap_fast_send_pac_tunnel(REQUEST *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t			*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	eap_fast_pac_t				pac;
	eap_fast_attr_pac_opaque_plaintext_t	opaque_plaintext;
	int					alen, dlen;

	memset(&pac, 0, sizeof(pac));
	memset(&opaque_plaintext, 0, sizeof(opaque_plaintext));

	RDEBUG2("Sending Tunnel PAC");

	pac.key.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_key->attr);
	pac.key.hdr.length = htons(sizeof(pac.key.data));
	fr_assert(sizeof(pac.key.data) % sizeof(uint32_t) == 0);
	RANDFILL(pac.key.data);

	pac.info.lifetime.hdr.type = htons(attr_eap_fast_pac_info_pac_lifetime->attr);
	pac.info.lifetime.hdr.length = htons(sizeof(pac.info.lifetime.data));
	pac.info.lifetime.data = htonl(time(NULL) + t->pac_lifetime);

	pac.info.a_id.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_a_id->attr);
	pac.info.a_id.hdr.length = htons(sizeof(pac.info.a_id.data));
	memcpy(pac.info.a_id.data, t->a_id, sizeof(pac.info.a_id.data));

	pac.info.a_id_info.hdr.type = htons(attr_eap_fast_pac_a_id->attr);
	pac.info.a_id_info.hdr.length = htons(sizeof(pac.info.a_id_info.data));

#define MIN(a,b) (((a)>(b)) ? (b) : (a))
	alen = MIN(talloc_array_length(t->authority_identity) - 1, sizeof(pac.info.a_id_info.data));
	memcpy(pac.info.a_id_info.data, t->authority_identity, alen);

	pac.info.type.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_info_pac_type->attr);
	pac.info.type.hdr.length = htons(sizeof(pac.info.type.data));
	pac.info.type.data = htons(PAC_TYPE_TUNNEL);

	pac.info.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_info_tlv->attr);
	pac.info.hdr.length = htons(sizeof(pac.info.lifetime)
				+ sizeof(pac.info.a_id)
				+ sizeof(pac.info.a_id_info)
				+ sizeof(pac.info.type));

	memcpy(&opaque_plaintext.type, &pac.info.type, sizeof(opaque_plaintext.type));
	memcpy(&opaque_plaintext.lifetime, &pac.info.lifetime, sizeof(opaque_plaintext.lifetime));
	memcpy(&opaque_plaintext.key, &pac.key, sizeof(opaque_plaintext.key));

	RHEXDUMP3((uint8_t const *)&opaque_plaintext, sizeof(opaque_plaintext), "PAC-Opaque plaintext data section");

	fr_assert(PAC_A_ID_LENGTH <= EVP_GCM_TLS_TAG_LEN);
	memcpy(pac.opaque.aad, t->a_id, PAC_A_ID_LENGTH);
	fr_assert(RAND_bytes(pac.opaque.iv, sizeof(pac.opaque.iv)) != 0);
	dlen = eap_fast_encrypt((unsigned const char *)&opaque_plaintext, sizeof(opaque_plaintext),
				    t->a_id, PAC_A_ID_LENGTH, t->pac_opaque_key, pac.opaque.iv,
				    pac.opaque.data, pac.opaque.tag);

	pac.opaque.hdr.type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_pac_opaque_tlv->attr);
	pac.opaque.hdr.length = htons(sizeof(pac.opaque) - sizeof(pac.opaque.hdr) - sizeof(pac.opaque.data) + dlen);
	RHEXDUMP3((uint8_t const *)&pac.opaque, sizeof(pac.opaque) - sizeof(pac.opaque.data) + dlen, "PAC-Opaque");

	eap_fast_tlv_append(tls_session, attr_eap_fast_pac_tlv, true, sizeof(pac) - sizeof(pac.opaque.data) + dlen, &pac);
}

static void eap_fast_append_crypto_binding(REQUEST *request, fr_tls_session_t *tls_session)
{
	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	eap_tlv_crypto_binding_tlv_t	binding = {0};
	int const			len = sizeof(binding) - (&binding.reserved - (uint8_t *)&binding);

	RDEBUG2("Sending Cryptobinding");

	binding.tlv_type = htons(EAP_FAST_TLV_MANDATORY | attr_eap_fast_crypto_binding->attr);
	binding.length = htons(len);
	binding.version = EAP_FAST_VERSION;
	binding.received_version = EAP_FAST_VERSION;	/* FIXME use the clients value */
	binding.subtype = EAP_FAST_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST;

	fr_assert(sizeof(binding.nonce) % sizeof(uint32_t) == 0);
	RANDFILL(binding.nonce);
	binding.nonce[sizeof(binding.nonce) - 1] &= ~0x01; /* RFC 4851 section 4.2.8 */
	RHEXDUMP3(binding.nonce, sizeof(binding.nonce), "NONCE");

	RHEXDUMP3((uint8_t const *) &binding, sizeof(binding), "Crypto-Binding TLV for Compound MAC calculation");

	fr_hmac_sha1(binding.compound_mac, (uint8_t *)&binding, sizeof(binding), t->cmk, EAP_FAST_CMK_LEN);
	RHEXDUMP3(binding.compound_mac, sizeof(binding.compound_mac), "Compound MAC");

	eap_fast_tlv_append(tls_session, attr_eap_fast_crypto_binding, true, len, &binding.reserved);
}

#define EAP_FAST_TLV_MAX 11

static int eap_fast_verify(REQUEST *request, fr_tls_session_t *tls_session, uint8_t const *data, unsigned int data_len)
{
	uint16_t attr;
	uint16_t length;
	unsigned int remaining = data_len;
	int	total = 0;
	int	num[EAP_FAST_TLV_MAX] = {0};
	eap_fast_tunnel_t *t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	uint32_t present = 0;

	fr_assert(sizeof(present) * 8 > EAP_FAST_TLV_MAX);

	while (remaining > 0) {
		if (remaining < 4) {
			RDEBUG2("EAP-FAST TLV is too small (%u) to contain a EAP-FAST TLV header", remaining);
			return 0;
		}

		memcpy(&attr, data, sizeof(attr));
		attr = ntohs(attr) & EAP_FAST_TLV_TYPE;

		if ((attr == attr_eap_fast_result->attr) ||
		    (attr == attr_eap_fast_nak->attr) ||
		    (attr == attr_eap_fast_error->attr) ||
		    (attr == attr_eap_fast_vendor_specific->attr) ||
		    (attr == attr_eap_fast_eap_payload->attr) ||
		    (attr == attr_eap_fast_intermediate_result->attr) ||
		    (attr == attr_eap_fast_pac_tlv->attr) ||
		    (attr == attr_eap_fast_crypto_binding->attr)) {
			num[attr]++;
			present |= 1 << attr;

			if (num[attr_eap_fast_eap_payload->attr] > 1) {
				REDEBUG("Too many EAP-Payload TLVs");
unexpected:
				for (int i = 0; i < EAP_FAST_TLV_MAX; i++) {
					if (present & (1 << i)) RDEBUG2(" - attribute %d is present", i);
				}
				eap_fast_send_error(tls_session, EAP_FAST_ERR_UNEXPECTED_TLV);
				return 0;
			}

			if (num[attr_eap_fast_intermediate_result->attr] > 1) {
				REDEBUG("Too many Intermediate-Result TLVs");
				goto unexpected;
			}
		} else {
			if ((data[0] & 0x80) != 0) {
				REDEBUG("Unknown mandatory TLV %02x", attr);
				goto unexpected;
			}

			num[0]++;
		}

		total++;

		memcpy(&length, data + 2, sizeof(length));
		length = ntohs(length);

		data += 4;
		remaining -= 4;

		if (length > remaining) {
			RDEBUG2("EAP-FAST TLV %u is longer than room remaining in the packet (%u > %u).", attr,
				length, remaining);
			return 0;
		}

		/*
		 * If the rest of the TLVs are larger than
		 * this attribute, continue.
		 *
		 * Otherwise, if the attribute over-flows the end
		 * of the TLCs, die.
		 */
		if (remaining < length) {
			RDEBUG2("EAP-FAST TLV overflows packet!");
			return 0;
		}

		/*
		 * If there's an error, we bail out of the
		 * authentication process before allocating
		 * memory.
		 */
		if ((attr == attr_eap_fast_intermediate_result->attr) || (attr == attr_eap_fast_result->attr)) {
			uint16_t status;

			if (length < 2) {
				REDEBUG("EAP-FAST TLV %u is too short.  Expected 2, got %d", attr, length);
				return 0;
			}

			memcpy(&status, data, 2);
			status = ntohs(status);

			if (status == EAP_FAST_TLV_RESULT_FAILURE) {
				REDEBUG("EAP-FAST TLV %u indicates failure.  Rejecting request", attr);
				return 0;
			}

			if (status != EAP_FAST_TLV_RESULT_SUCCESS) {
				REDEBUG("EAP-FAST TLV %u contains unknown value.  Rejecting request", attr);
				goto unexpected;
			}
		}

		/*
		 * remaining > length, continue.
		 */
		remaining -= length;
		data += length;
	}

	/*
	 * Check if the peer mixed & matched TLVs.
	 */
	if ((num[attr_eap_fast_nak->attr] > 0) && (num[attr_eap_fast_nak->attr] != total)) {
		REDEBUG("NAK TLV sent with non-NAK TLVs.  Rejecting request");
		goto unexpected;
	}

	if (num[attr_eap_fast_intermediate_result->attr] > 0) {
		REDEBUG("NAK TLV sent with non-NAK TLVs.  Rejecting request");
		goto unexpected;
	}

	/*
	 * Check mandatory or not mandatory TLVs.
	 */
	switch (t->stage) {
	case EAP_FAST_TLS_SESSION_HANDSHAKE:
		if (present) {
			REDEBUG("Unexpected TLVs in TLS Session Handshake stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_AUTHENTICATION:
		if (present != (uint32_t)(1 << attr_eap_fast_eap_payload->attr)) {
			REDEBUG("Unexpected TLVs in authentication stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_CRYPTOBIND_CHECK:
	{
		uint32_t bits = (t->result_final)
				? 1 << attr_eap_fast_result->attr
				: 1 << attr_eap_fast_intermediate_result->attr;
		if (present & ~(bits | (1 << attr_eap_fast_crypto_binding->attr) | (1 << attr_eap_fast_pac_tlv->attr))) {
			REDEBUG("Unexpected TLVs in cryptobind checking stage");
			goto unexpected;
		}
		break;
	}
	case EAP_FAST_PROVISIONING:
		if (present & ~((1 << attr_eap_fast_pac_tlv->attr) | (1 << attr_eap_fast_result->attr))) {
			REDEBUG("Unexpected TLVs in provisioning stage");
			goto unexpected;
		}
		break;
	case EAP_FAST_COMPLETE:
		if (present) {
			REDEBUG("Unexpected TLVs in complete stage");
			goto unexpected;
		}
		break;
	default:
		REDEBUG("Unexpected stage %d", t->stage);
		return 0;
	}

	/*
	 * We got this far.  It looks OK.
	 */
	return 1;
}

/**
 *
 * FIXME do something with mandatory
 */
ssize_t eap_fast_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
			     uint8_t const *data, size_t data_len,
			     void *decoder_ctx)
{
	fr_dict_attr_t const	*da;
	uint8_t	const		*p = data, *end = p + data_len;

	/*
	 *	Decode the TLVs
	 */
	while (p < end) {
		ssize_t		ret;
		uint16_t	attr;
		uint16_t	len;
		VALUE_PAIR	*vp;

		attr = fr_net_to_uint16(p) & EAP_FAST_TLV_TYPE;
		p += 2;
		len = fr_net_to_uint16(p);
		p += 2;

		da = fr_dict_attr_child_by_num(parent, attr);
		if (!da) {
			MEM(vp = fr_pair_afrom_child_num(ctx, parent, attr));

		} else if (da->type == FR_TYPE_TLV) {
			p += (size_t) eap_fast_decode_pair(ctx, cursor, parent, p, len, decoder_ctx);
			continue;

		} else {
			MEM(vp = fr_pair_afrom_da(ctx, da));
		}

		ret = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da, p, len, true);
		if (ret != len) {
			fr_pair_to_unknown(vp);
			fr_pair_value_memcpy(vp, p, len, true);
		}
		fr_cursor_append(cursor, vp);
		p += len;
	}

	return p - data;
}


/*
 * Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(UNUSED eap_session_t *eap_session,
						  fr_tls_session_t *tls_session,
						  REQUEST *request, RADIUS_PACKET *reply)
{
	rlm_rcode_t			rcode = RLM_MODULE_REJECT;
	VALUE_PAIR			*vp;
	fr_cursor_t			cursor;

	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 * If the response packet was Access-Accept, then
	 * we're OK.  If not, die horribly.
	 *
	 * FIXME: EAP-Messages can only start with 'identity',
	 * NOT 'eap start', so we should check for that....
	 */
	switch (reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
		RDEBUG2("Got tunneled Access-Accept");

		rcode = RLM_MODULE_OK;

		/*
		 * Copy what we need into the TTLS tunnel and leave
		 * the rest to be cleaned up.
		 */
		for (vp = fr_cursor_init(&cursor, &reply->vps); vp; vp = fr_cursor_next(&cursor)) {
			if (fr_dict_vendor_num_by_da(vp->da) != VENDORPEC_MICROSOFT) continue;

			/* FIXME must be a better way to capture/re-derive this later for ISK */
			switch (vp->da->attr) {
			case FR_MSCHAP_MPPE_SEND_KEY:
				if (vp->vp_length != RADIUS_CHAP_CHALLENGE_LENGTH) {
				wrong_length:
					REDEBUG("Found %s with incorrect length.  Expected %u, got %zu",
						vp->da->name, RADIUS_CHAP_CHALLENGE_LENGTH, vp->vp_length);
					rcode = RLM_MODULE_INVALID;
					break;
				}

				memcpy(t->isk.mppe_send, vp->vp_octets, RADIUS_CHAP_CHALLENGE_LENGTH);
				break;

			case FR_MSCHAP_MPPE_RECV_KEY:
				if (vp->vp_length != RADIUS_CHAP_CHALLENGE_LENGTH) goto wrong_length;
				memcpy(t->isk.mppe_recv, vp->vp_octets, RADIUS_CHAP_CHALLENGE_LENGTH);
				break;

			case FR_MSCHAP2_SUCCESS:
				RDEBUG2("Got %s, tunneling it to the client in a challenge", vp->da->name);
				rcode = RLM_MODULE_HANDLED;
				t->authenticated = true;
				break;

			default:
				break;
			}
		}
		RHEXDUMP3((uint8_t *)&t->isk, 2 * RADIUS_CHAP_CHALLENGE_LENGTH, "ISK[j]"); /* FIXME (part of above) */
		break;

	case FR_CODE_ACCESS_REJECT:
		REDEBUG("Got tunneled Access-Reject");
		rcode = RLM_MODULE_REJECT;
		break;

	case FR_CODE_ACCESS_CHALLENGE:
		RDEBUG2("Got tunneled Access-Challenge");

		/*
		 *	Copy the EAP-Message back to the tunnel.
		 */
		(void) fr_cursor_init(&cursor, &reply->vps);

		for (vp = fr_cursor_iter_by_da_init(&cursor, &reply->vps, attr_eap_message);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			eap_fast_tlv_append(tls_session, attr_eap_fast_eap_payload, true, vp->vp_length, vp->vp_octets);
		}

		rcode = RLM_MODULE_HANDLED;
		break;

	default:
		REDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		rcode = RLM_MODULE_INVALID;
		break;
	}

	return rcode;
}

static FR_CODE eap_fast_eap_payload(REQUEST *request, eap_session_t *eap_session,
				    fr_tls_session_t *tls_session, VALUE_PAIR *tlv_eap_payload)
{
	FR_CODE			code = FR_CODE_ACCESS_REJECT;
	rlm_rcode_t		rcode;
	VALUE_PAIR		*vp;
	eap_fast_tunnel_t	*t;
	REQUEST			*fake;

	RDEBUG2("Processing received EAP Payload");

	/*
	 *	Allocate a fake REQUEST structure.
	 */
	fake = request_alloc_fake(request, NULL);
	fr_assert(!fake->packet->vps);

	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 *	Add the tunneled attributes to the fake request.
	 */

	MEM(fake->packet->vps = vp = fr_pair_afrom_da(fake->packet, attr_eap_message));
	fr_pair_value_memcpy(fake->packet->vps, tlv_eap_payload->vp_octets, tlv_eap_payload->vp_length, false);

	RDEBUG2("Got tunneled request");
	log_request_pair_list(L_DBG_LVL_1, fake, fake->packet->vps, NULL);

	/*
	 *	Tell the request that it's a fake one.
	 */
	MEM(fr_pair_add_by_da(fake->packet, &vp, &fake->packet->vps, attr_freeradius_proxied_to) >= 0);
	fr_pair_value_from_str(vp, "127.0.0.1", sizeof("127.0.0.1"), '\0', false);

	/*
	 *	If there's no User-Name in the stored data, look for
	 *	an EAP-Identity, and pull it out of there.
	 */
	if (!t->username) {
		fr_assert(vp->da == attr_eap_message); /* cached from above */

		if ((vp->vp_length >= EAP_HEADER_LEN + 2) &&
		    (vp->vp_strvalue[0] == FR_EAP_CODE_RESPONSE) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN] == FR_EAP_METHOD_IDENTITY) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN + 1] != 0)) {
			/*
			 *	Create and remember a User-Name
			 */
			MEM(t->username = fr_pair_afrom_da(t, attr_user_name));
			t->username->vp_tainted = true;
			fr_pair_value_bstrncpy(t->username, vp->vp_octets + 5, vp->vp_length - 5);

			RDEBUG2("Got tunneled identity of %pV", &t->username->data);
		} else {
			/*
			 * Don't reject the request outright,
			 * as it's permitted to do EAP without
			 * user-name.
			 */
			RWDEBUG2("No EAP-Identity found to start EAP conversation");
		}
	} /* else there WAS a t->username */

	if (t->username) {
		vp = fr_pair_copy(fake->packet, t->username);
		fr_pair_add(&fake->packet->vps, vp);
	}

	if (t->stage == EAP_FAST_AUTHENTICATION) {	/* FIXME do this only for MSCHAPv2 */
		VALUE_PAIR *tvp;

		MEM(tvp = fr_pair_afrom_da(fake, attr_eap_type));
		tvp->vp_uint32 = t->default_provisioning_method;
		fr_pair_add(&fake->control, tvp);

		/*
		 * RFC 5422 section 3.2.3 - Authenticating Using EAP-FAST-MSCHAPv2
		 */
		if (t->mode == EAP_FAST_PROVISIONING_ANON) {
			MEM(tvp = fr_pair_afrom_da(fake, attr_ms_chap_challenge));
			fr_pair_value_memcpy(tvp, t->keyblock->server_challenge, RADIUS_CHAP_CHALLENGE_LENGTH, false);
			fr_pair_add(&fake->control, tvp);
			RHEXDUMP3(t->keyblock->server_challenge, RADIUS_CHAP_CHALLENGE_LENGTH, "MSCHAPv2 auth_challenge");

			MEM(tvp = fr_pair_afrom_da(fake, attr_ms_chap_peer_challenge));
			fr_pair_value_memcpy(tvp, t->keyblock->client_challenge, RADIUS_CHAP_CHALLENGE_LENGTH, false);
			fr_pair_add(&fake->control, tvp);
			RHEXDUMP3(t->keyblock->client_challenge, RADIUS_CHAP_CHALLENGE_LENGTH, "MSCHAPv2 peer_challenge");
		}
	}

	/*
	 * Call authentication recursively, which will
	 * do PAP, CHAP, MS-CHAP, etc.
	 */
	eap_virtual_server(request, eap_session, t->virtual_server);

	/*
	 * Decide what to do with the reply.
	 */
	switch (fake->reply->code) {
	case 0:			/* No reply code, must be proxied... */
#ifdef WITH_PROXY
		vp = fr_pair_find_by_da(fake->control, attr_proxy_to_realm, TAG_ANY);
		if (vp) {
			int			ret;
			eap_tunnel_data_t	*tunnel;

			RDEBUG2("Tunneled authentication will be proxied to %pV", &vp->data);

			/*
			 *	Tell the original request that it's going to be proxied.
			 */
			fr_pair_list_copy_by_da(request, &request->control, fake->control, attr_proxy_to_realm);

			/*
			 *	Seed the proxy packet with the tunneled request.
			 */
			fr_assert(!request->proxy);

			/*
			 *	FIXME: Actually proxy stuff
			 */
			request->proxy = request_alloc_fake(request, NULL);

			request->proxy->packet = talloc_steal(request->proxy, fake->packet);
			memset(&request->proxy->packet->src_ipaddr, 0,
			       sizeof(request->proxy->packet->src_ipaddr));
			memset(&request->proxy->packet->src_ipaddr, 0,
			       sizeof(request->proxy->packet->src_ipaddr));
			request->proxy->packet->src_port = 0;
			request->proxy->packet->dst_port = 0;
			fake->packet = NULL;
			fr_radius_packet_free(&fake->reply);
			fake->reply = NULL;

			/*
			 *	Set up the callbacks for the tunnel
			 */
			tunnel = talloc_zero(request, eap_tunnel_data_t);
			tunnel->tls_session = tls_session;

			/*
			 *	Associate the callback with the request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_TUNNEL_CALLBACK,
					       tunnel, false, false, false);
			fr_cond_assert(ret == 0);

			/*
			 *	rlm_eap.c has taken care of associating the eap_session
			 *	with the fake request.
			 *
			 *	So we associate the fake request with this request.
			 */
			ret = request_data_add(request, request->proxy, REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK,
					       fake, true, false, false);
			fr_cond_assert(ret == 0);

			fake = NULL;

			/*
			 *	Didn't authenticate the packet, but we're proxying it.
			 */
			code = FR_CODE_STATUS_CLIENT;

		} else
#endif	/* WITH_PROXY */
		  {
			  REDEBUG("No tunneled reply was found, and the request was not proxied: rejecting the user");
			  code = FR_CODE_ACCESS_REJECT;
		  }
		break;

	default:
		/*
		 *	Returns RLM_MODULE_FOO, and we want to return FR_FOO
		 */
		rcode = process_reply(eap_session, tls_session, request, fake->reply);
		switch (rcode) {
		case RLM_MODULE_REJECT:
			code = FR_CODE_ACCESS_REJECT;
			break;

		case RLM_MODULE_HANDLED:
			code = FR_CODE_ACCESS_CHALLENGE;
			break;

		case RLM_MODULE_OK:
			code = FR_CODE_ACCESS_ACCEPT;
			break;

		default:
			code = FR_CODE_ACCESS_REJECT;
			break;
		}
		break;
	}

	talloc_free(fake);

	return code;
}

static FR_CODE eap_fast_crypto_binding(REQUEST *request, UNUSED eap_session_t *eap_session,
				       fr_tls_session_t *tls_session, eap_tlv_crypto_binding_tlv_t *binding)
{
	uint8_t			cmac[sizeof(binding->compound_mac)];
	eap_fast_tunnel_t	*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	memcpy(cmac, binding->compound_mac, sizeof(cmac));
	memset(binding->compound_mac, 0, sizeof(binding->compound_mac));

	RHEXDUMP3((uint8_t const *) binding, sizeof(*binding), "Crypto-Binding TLV for Compound MAC calculation");
	RHEXDUMP3(cmac, sizeof(cmac), "Received Compound MAC");

	fr_hmac_sha1(binding->compound_mac, (uint8_t *)binding, sizeof(*binding), t->cmk, EAP_FAST_CMK_LEN);
	if (memcmp(binding->compound_mac, cmac, sizeof(cmac))) {
		RDEBUG2("Crypto-Binding TLV mis-match");
		RHEXDUMP3((uint8_t const *) binding->compound_mac,
                sizeof(binding->compound_mac), "Calculated Compound MAC");
		return FR_CODE_ACCESS_REJECT;
	}

	return FR_CODE_ACCESS_ACCEPT;
}

static FR_CODE eap_fast_process_tlvs(REQUEST *request, eap_session_t *eap_session,
				     fr_tls_session_t *tls_session, VALUE_PAIR *fast_vps)
{
	eap_fast_tunnel_t		*t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);
	VALUE_PAIR			*vp;
	fr_cursor_t			cursor;
	eap_tlv_crypto_binding_tlv_t	my_binding, *binding = NULL;

	memset(&my_binding, 0, sizeof(my_binding));

	for (vp = fr_cursor_init(&cursor, &fast_vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		FR_CODE code = FR_CODE_ACCESS_REJECT;
		char *value;

		if (vp->da->parent == attr_eap_fast_tlv) {
			if (vp->da == attr_eap_fast_eap_payload) {
				code = eap_fast_eap_payload(request, eap_session, tls_session, vp);
				if (code == FR_CODE_ACCESS_ACCEPT) t->stage = EAP_FAST_CRYPTOBIND_CHECK;
			} else if ((vp->da == attr_eap_fast_result) ||
				   (vp->da == attr_eap_fast_intermediate_result)) {
				code = FR_CODE_ACCESS_ACCEPT;
				t->stage = EAP_FAST_PROVISIONING;
			} else {
				value = fr_pair_asprint(request->packet, vp, '"');
				RDEBUG2("ignoring unknown %s", value);
				talloc_free(value);
				continue;
			}
		} else if (vp->da->parent == attr_eap_fast_crypto_binding) {
			binding = &my_binding;

			/*
			 *	fr_radius_encode_pair() does not work for structures
			 */
			switch (vp->da->attr) {
			case 1:	/* FR_EAP_FAST_CRYPTO_BINDING_RESERVED */
				binding->reserved = vp->vp_uint8;
				break;
			case 2:	/* FR_EAP_FAST_CRYPTO_BINDING_VERSION */
				binding->version = vp->vp_uint8;
				break;
			case 3:	/* FR_EAP_FAST_CRYPTO_BINDING_RECV_VERSION */
				binding->received_version = vp->vp_uint8;
				break;
			case 4:	/* FR_EAP_FAST_CRYPTO_BINDING_SUB_TYPE */
				binding->subtype = vp->vp_uint8;
				break;
			case 5:	/* FR_EAP_FAST_CRYPTO_BINDING_NONCE */
				if (vp->vp_length >= sizeof(binding->nonce)) {
					memcpy(binding->nonce, vp->vp_octets, vp->vp_length);
				}
				break;
			case 6:	/* FR_EAP_FAST_CRYPTO_BINDING_COMPOUND_MAC */
				if (vp->vp_length >= sizeof(binding->compound_mac)) {
					memcpy(binding->compound_mac, vp->vp_octets, sizeof(binding->compound_mac));
				}
				break;
			}
			continue;
		} else if (vp->da->parent == attr_eap_fast_pac_tlv) {
			if (vp->da == attr_eap_fast_pac_acknowledge) {
				if (vp->vp_uint32 == EAP_FAST_TLV_RESULT_SUCCESS) {
					code = FR_CODE_ACCESS_ACCEPT;
					t->pac.expires = UINT32_MAX;
					t->pac.expired = false;
					t->stage = EAP_FAST_COMPLETE;
				}
			} else if (vp->da == attr_eap_fast_pac_info_pac_type) {
				if (vp->vp_uint32 != PAC_TYPE_TUNNEL) {
					RDEBUG2("only able to serve Tunnel PAC's, ignoring request");
					continue;
				}
				t->pac.send = true;
				continue;
			} else {
				value = fr_pair_asprint(request->packet, vp, '"');
				RDEBUG2("ignoring unknown EAP-FAST-PAC-TLV %s", value);
				talloc_free(value);
				continue;
			}
		} else {
			value = fr_pair_asprint(request->packet, vp, '"');
			RDEBUG2("ignoring non-EAP-FAST TLV %s", value);
			talloc_free(value);
			continue;
		}

		if (code == FR_CODE_ACCESS_REJECT) return FR_CODE_ACCESS_REJECT;
	}

	if (binding) {
		FR_CODE code = eap_fast_crypto_binding(request, eap_session, tls_session, binding);
		if (code == FR_CODE_ACCESS_ACCEPT) {
			t->stage = EAP_FAST_PROVISIONING;
		}
		return code;
	}

	return FR_CODE_ACCESS_ACCEPT;
}


/*
 * Process the inner tunnel data
 */
FR_CODE eap_fast_process(REQUEST *request, eap_session_t *eap_session, fr_tls_session_t *tls_session)
{
	FR_CODE			code;
	VALUE_PAIR		*fast_vps = NULL;
	fr_cursor_t		cursor;
	uint8_t const		*data;
	size_t			data_len;
	eap_fast_tunnel_t	*t;

	/*
	 * Just look at the buffer directly, without doing
	 * record_to_buff.
	 */
	data_len = tls_session->clean_out.used;
	tls_session->clean_out.used = 0;
	data = tls_session->clean_out.data;

	t = talloc_get_type_abort(tls_session->opaque, eap_fast_tunnel_t);

	/*
	 * See if the tunneled data is well formed.
	 */
	if (!eap_fast_verify(request, tls_session, data, data_len)) return FR_CODE_ACCESS_REJECT;

	if (t->stage == EAP_FAST_TLS_SESSION_HANDSHAKE) {
		fr_assert(t->mode == EAP_FAST_UNKNOWN);

		char buf[256];
		if (strstr(SSL_CIPHER_description(SSL_get_current_cipher(tls_session->ssl),
						  buf, sizeof(buf)), "Au=None")) {
			/* FIXME enforce MSCHAPv2 - RFC 5422 section 3.2.2 */
			RDEBUG2("Using anonymous provisioning");
			t->mode = EAP_FAST_PROVISIONING_ANON;
			t->pac.send = true;
		} else {
			if (SSL_session_reused(tls_session->ssl)) {
				RDEBUG2("Session Resumed from PAC");
				t->mode = EAP_FAST_NORMAL_AUTH;
			} else {
				RDEBUG2("Using authenticated provisioning");
				t->mode = EAP_FAST_PROVISIONING_AUTH;
			}

			if (!t->pac.expires || t->pac.expired || t->pac.expires - time(NULL) < t->pac_lifetime * 0.6) {
				t->pac.send = true;
			}
		}

		eap_fast_init_keys(request, tls_session);

		eap_fast_send_identity_request(request, tls_session, eap_session);

		t->stage = EAP_FAST_AUTHENTICATION;
		return FR_CODE_ACCESS_CHALLENGE;
	}

	fr_cursor_init(&cursor, &fast_vps);
	if (eap_fast_decode_pair(request, &cursor, attr_eap_fast_tlv,
				 data, data_len, NULL) < 0) return FR_CODE_ACCESS_REJECT;

	RDEBUG2("Got Tunneled FAST TLVs");
	log_request_pair_list(L_DBG_LVL_1, request, fast_vps, NULL);
	code = eap_fast_process_tlvs(request, eap_session, tls_session, fast_vps);
	fr_pair_list_free(&fast_vps);

	if (code == FR_CODE_ACCESS_REJECT) return FR_CODE_ACCESS_REJECT;

	switch (t->stage) {
	case EAP_FAST_AUTHENTICATION:
		code = FR_CODE_ACCESS_CHALLENGE;
		break;

	case EAP_FAST_CRYPTOBIND_CHECK:
	{
		if (t->mode != EAP_FAST_PROVISIONING_ANON && !t->pac.send)
			t->result_final = true;

		eap_fast_append_result(tls_session, code);

		eap_fast_update_icmk(request, tls_session, (uint8_t *)&t->isk);
		eap_fast_append_crypto_binding(request, tls_session);

		code = FR_CODE_ACCESS_CHALLENGE;
		break;
	}
	case EAP_FAST_PROVISIONING:
		t->result_final = true;

		eap_fast_append_result(tls_session, code);

		if (t->pac.send) {
			RDEBUG2("Peer requires new PAC");
			eap_fast_send_pac_tunnel(request, tls_session);
			code = FR_CODE_ACCESS_CHALLENGE;
			break;
		}

		t->stage = EAP_FAST_COMPLETE;
		FALL_THROUGH;

	case EAP_FAST_COMPLETE:
		/*
		 * RFC 5422 section 3.5 - Network Access after EAP-FAST Provisioning
		 */
		if (t->pac.type && t->pac.expired) {
			REDEBUG("Rejecting expired PAC.");
			code = FR_CODE_ACCESS_REJECT;
			break;
		}

		if (t->mode == EAP_FAST_PROVISIONING_ANON) {
			REDEBUG("Rejecting unauthenticated provisioning");
			code = FR_CODE_ACCESS_REJECT;
			break;
		}

		/*
		 * eap_crypto_mppe_keys() is unsuitable for EAP-FAST as Cisco decided
		 * it would be a great idea to flip the recv/send keys around
		 */
		#define EAPTLS_MPPE_KEY_LEN 32
		eap_add_reply(request, attr_ms_mppe_recv_key, t->msk, EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, attr_ms_mppe_send_key, &t->msk[EAPTLS_MPPE_KEY_LEN], EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, attr_eap_msk, t->msk, EAP_FAST_KEY_LEN);
		eap_add_reply(request, attr_eap_emsk, t->emsk, EAP_EMSK_LEN);

		break;

	default:
		RERROR("Internal sanity check failed in EAP-FAST at %d", t->stage);
		code = FR_CODE_ACCESS_REJECT;
	}

	return code;
}
