/*
 * eap_teap.c  contains the interfaces that are called from the main handler
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

#include "eap_teap.h"
#include "eap_teap_crypto.h"
#include <freeradius-devel/sha1.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#define PW_EAP_TEAP_TLV_IDENTITY (PW_FREERADIUS_EAP_TEAP_TLV | (EAP_TEAP_TLV_IDENTITY << 8))
#define PW_EAP_TEAP_TLV_PAC (PW_FREERADIUS_EAP_TEAP_TLV | (EAP_TEAP_TLV_PAC << 8))

#define EAPTLS_MPPE_KEY_LEN 32

#define RDEBUGHEX(_label, _data, _length) \
do {\
	char __buf[8192];\
	for (size_t i = 0; (i < (size_t) _length) && (3*i < sizeof(__buf)); i++) {\
		sprintf(&__buf[3*i], " %02x", (uint8_t)(_data)[i]);\
	}\
	RDEBUG("%s - hexdump(len=%zu):%s", _label, (size_t)_length, __buf);\
} while (0)

#define RANDFILL(x) do { rad_assert(sizeof(x) % sizeof(uint32_t) == 0); for (size_t i = 0; i < sizeof(x); i += sizeof(uint32_t)) *((uint32_t *)&x[i]) = fr_rand(); } while(0)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define MIN(a,b) (((a)>(b)) ? (b) : (a))

struct crypto_binding_buffer {
	uint16_t			tlv_type;
	uint16_t			length;
	eap_tlv_crypto_binding_tlv_t	binding;
	uint8_t				eap_type;
	uint8_t				outer_tlvs[1];
} CC_HINT(__packed__);
#define CRYPTO_BINDING_BUFFER_INIT(_cbb) \
do {\
	_cbb->tlv_type = htons(EAP_TEAP_TLV_MANDATORY | EAP_TEAP_TLV_CRYPTO_BINDING);\
	_cbb->length = htons(sizeof(struct eap_tlv_crypto_binding_tlv_t));\
	_cbb->eap_type = PW_EAP_TEAP;\
} while (0)

static struct teap_imck_t imck_zeros = { };

/**
 * RFC 7170 EAP-TEAP Authentication Phase 1: Key Derivations
 */
static void eap_teap_init_keys(REQUEST *request, tls_session_t *tls_session)
{
	teap_tunnel_t *t = tls_session->opaque;

	const EVP_MD *md = SSL_CIPHER_get_handshake_digest(SSL_get_current_cipher(tls_session->ssl));
	const int md_type = EVP_MD_type(md);

	RDEBUG("Using MAC %s (%d)", OBJ_nid2sn(md_type), md_type);

	RDEBUG2("Deriving EAP-TEAP keys");

	rad_assert(t->received_version > -1);
	rad_assert(t->imckc == 0);

	/* S-IMCK[0] = session_key_seed (RFC7170, Section 5.1) */
	eaptls_gen_keys_only(request, tls_session->ssl, "EXPORTER: teap session key seed", NULL, 0, t->imck_msk.simck, sizeof(t->imck_msk.simck));
	memcpy(t->imck_emsk.simck, t->imck_msk.simck, sizeof(t->imck_msk.simck));
	RDEBUGHEX("S-IMCK[0]", t->imck_msk.simck, sizeof(t->imck_msk.simck));
}

/**
 * RFC 7170 EAP-TEAP Intermediate Compound Key Derivations - Section 5.2
 */
/**
 * RFC 7170 - Intermediate Compound Key Derivations
 */
static void eap_teap_derive_imck(REQUEST *request, tls_session_t *tls_session,
				 uint8_t *msk, size_t msklen,
				 uint8_t *emsk, size_t emsklen)
{
	teap_tunnel_t *t = tls_session->opaque;

	t->imckc++;
	RDEBUG2("Updating ICMK (j = %d)", t->imckc);

	uint8_t imsk_msk[EAP_TEAP_IMSK_LEN] = {0};
	uint8_t imsk_emsk[EAP_TEAP_IMSK_LEN + 32];	// +32 for EMSK overflow
	struct teap_imck_t imck_msk, imck_emsk;

	uint8_t imck_label[27] = "Inner Methods Compound Keys";	// width trims trailing \0
	struct iovec imck_seed[2] = {
		{ (void *)imck_label, sizeof(imck_label) },
		{ NULL, EAP_TEAP_IMSK_LEN }
	};

	if (msklen) {
		memcpy(imsk_msk, msk, MIN(msklen, EAP_TEAP_IMSK_LEN));
		RDEBUGHEX("IMSK from MSK", imsk_msk, EAP_TEAP_IMSK_LEN);
	} else {
		RDEBUGHEX("IMSK Zero", imsk_msk, EAP_TEAP_IMSK_LEN);
	}
	imck_seed[1].iov_base = imsk_msk;
	TLS_PRF(tls_session->ssl,
		t->imck_msk.simck, sizeof(t->imck_msk.simck),
		imck_seed, ARRAY_SIZE(imck_seed),
		(uint8_t *)&imck_msk, sizeof(imck_msk));

	/* IMCK[j] 60 octets => S-IMCK[j] first 40 octets, CMK[j] last 20 octets */
	RDEBUGHEX("MSK S-IMCK[j]", imck_msk.simck, sizeof(imck_msk.simck));
	RDEBUGHEX("MSK CMK[j]", imck_msk.cmk, sizeof(imck_msk.cmk));

	if (emsklen) {
		uint8_t emsk_label[20] = "TEAPbindkey@ietf.org";
		uint8_t null[1] = {0};
		uint8_t length[2] = {0,64};	/* length of 64 bytes in two bytes in network order */
		struct iovec emsk_seed[] = {
			{ (void *)emsk_label, sizeof(emsk_label) },
			{ (void *)null, sizeof(null) },
			{ (void *)length, sizeof(length) }
		};

		TLS_PRF(tls_session->ssl,
			emsk, emsklen,
			emsk_seed, ARRAY_SIZE(emsk_seed),
			imsk_emsk, sizeof(imsk_emsk));

		RDEBUGHEX("IMSK from EMSK", imsk_emsk, EAP_TEAP_IMSK_LEN);

		imck_seed[1].iov_base = imsk_emsk;
		TLS_PRF(tls_session->ssl,
			t->imck_emsk.simck, sizeof(t->imck_emsk.simck),
			imck_seed, ARRAY_SIZE(imck_seed),
			(uint8_t *)&imck_emsk, sizeof(imck_emsk));

		/* IMCK[j] 60 octets => S-IMCK[j] first 40 octets, CMK[j] last 20 octets */
		RDEBUGHEX("EMSK S-IMCK[j]", imck_emsk.simck, sizeof(imck_emsk.simck));
		RDEBUGHEX("EMSK CMK[j]", imck_emsk.cmk, sizeof(imck_emsk.cmk));
	}

	memcpy(&t->imck_msk, &imck_msk, sizeof(imck_msk));
	if (emsklen) memcpy(&t->imck_emsk, &imck_emsk, sizeof(imck_emsk));
}

static void eap_teap_tlv_append(tls_session_t *tls_session, int tlv, bool mandatory, int length, const void *data)
{
	uint16_t hdr[2];

	hdr[0] = htons(tlv | (mandatory ? EAP_TEAP_TLV_MANDATORY : 0));
	hdr[1] = htons(length);

	tls_session->record_plus(&tls_session->clean_in, &hdr, 4);
	tls_session->record_plus(&tls_session->clean_in, data, length);
}

static void eap_teap_send_error(tls_session_t *tls_session, int error)
{
	uint32_t value;
	value = htonl(error);

	eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_ERROR, true, sizeof(value), &value);
}

static void eap_teap_append_identity(tls_session_t *tls_session, int value) {
	uint16_t identity;
	identity = htons(value);

	eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_IDENTITY, false, sizeof(identity), &identity);
}

static void eap_teap_append_result(tls_session_t *tls_session, PW_CODE code)
{
	teap_tunnel_t *t = (teap_tunnel_t *) tls_session->opaque;

	int type = (t->result_final)
			? EAP_TEAP_TLV_RESULT
			: EAP_TEAP_TLV_INTERMED_RESULT;

	uint16_t state = (code == PW_CODE_ACCESS_REJECT)
			? EAP_TEAP_TLV_RESULT_FAILURE
			: EAP_TEAP_TLV_RESULT_SUCCESS;
	state = htons(state);

	eap_teap_tlv_append(tls_session, type, true, sizeof(state), &state);
}

static void eap_teap_append_eap_identity_request(REQUEST *request, tls_session_t *tls_session, eap_handler_t *eap_session)
{
	eap_packet_raw_t eap_packet;

	RDEBUG("Sending EAP-Identity");

	eap_packet.code = PW_EAP_REQUEST;
	eap_packet.id = eap_session->eap_ds->response->id + 1;
	eap_packet.length[0] = 0;
	eap_packet.length[1] = EAP_HEADER_LEN + 1;
	eap_packet.data[0] = PW_EAP_IDENTITY;

	eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_EAP_PAYLOAD, true, sizeof(eap_packet), &eap_packet);
}

#if 0
static void eap_teap_send_pac_tunnel(REQUEST *request, tls_session_t *tls_session)
{
	teap_tunnel_t			*t = tls_session->opaque;
	eap_teap_pac_t				pac;
	eap_teap_attr_pac_opaque_plaintext_t	opaque_plaintext;
	int					alen, dlen;

	memset(&pac, 0, sizeof(pac));
	memset(&opaque_plaintext, 0, sizeof(opaque_plaintext));

	RDEBUG("Sending Tunnel PAC");

	pac.key.hdr.type = htons(EAP_TEAP_TLV_MANDATORY | PAC_INFO_PAC_KEY);
	pac.key.hdr.length = htons(sizeof(pac.key.data));
	rad_assert(sizeof(pac.key.data) % sizeof(uint32_t) == 0);
	RANDFILL(pac.key.data);

	pac.info.lifetime.hdr.type = htons(PAC_INFO_PAC_LIFETIME);
	pac.info.lifetime.hdr.length = htons(sizeof(pac.info.lifetime.data));
	pac.info.lifetime.data = htonl(time(NULL) + t->pac_lifetime);

	pac.info.a_id.hdr.type = htons(EAP_TEAP_TLV_MANDATORY | PAC_INFO_A_ID);
	pac.info.a_id.hdr.length = htons(sizeof(pac.info.a_id.data));
	memcpy(pac.info.a_id.data, t->a_id, sizeof(pac.info.a_id.data));

	pac.info.a_id_info.hdr.type = htons(PAC_INFO_A_ID_INFO);
	pac.info.a_id_info.hdr.length = htons(sizeof(pac.info.a_id_info.data));
	#define MIN(a,b) (((a)>(b)) ? (b) : (a))
	alen = MIN(talloc_array_length(t->authority_identity) - 1, sizeof(pac.info.a_id_info.data));
	memcpy(pac.info.a_id_info.data, t->authority_identity, alen);

	pac.info.type.hdr.type = htons(EAP_TEAP_TLV_MANDATORY | PAC_INFO_PAC_TYPE);
	pac.info.type.hdr.length = htons(sizeof(pac.info.type.data));
	pac.info.type.data = htons(PAC_TYPE_TUNNEL);

	pac.info.hdr.type = htons(EAP_TEAP_TLV_MANDATORY | PAC_INFO_PAC_INFO);
	pac.info.hdr.length = htons(sizeof(pac.info.lifetime)
				+ sizeof(pac.info.a_id)
				+ sizeof(pac.info.a_id_info)
				+ sizeof(pac.info.type));

	memcpy(&opaque_plaintext.type, &pac.info.type, sizeof(opaque_plaintext.type));
	memcpy(&opaque_plaintext.lifetime, &pac.info.lifetime, sizeof(opaque_plaintext.lifetime));
	memcpy(&opaque_plaintext.key, &pac.key, sizeof(opaque_plaintext.key));


	rad_assert(PAC_A_ID_LENGTH <= EVP_GCM_TLS_TAG_LEN);
	memcpy(pac.opaque.aad, t->a_id, PAC_A_ID_LENGTH);
	rad_assert(RAND_bytes(pac.opaque.iv, sizeof(pac.opaque.iv)) != 0);
	dlen = eap_teap_encrypt((unsigned const char *)&opaque_plaintext, sizeof(opaque_plaintext),
				t->a_id, PAC_A_ID_LENGTH, t->pac_opaque_key, pac.opaque.iv,
				pac.opaque.data, pac.opaque.tag);
	if (dlen < 0) return;

	pac.opaque.hdr.type = htons(EAP_TEAP_TLV_MANDATORY | PAC_INFO_PAC_OPAQUE);
	pac.opaque.hdr.length = htons(sizeof(pac.opaque) - sizeof(pac.opaque.hdr) - sizeof(pac.opaque.data) + dlen);

	eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_MANDATORY | EAP_TEAP_TLV_PAC, true,
			    sizeof(pac) - sizeof(pac.opaque.data) + dlen, &pac);
}
#endif

/*
 * RFC7170 and the consequences of EID5768, EID5770 and EID5775 makes the path forward unclear,
 * so just do what hostapd does...which the IETF probably agree with anyway:
 * https://mailarchive.ietf.org/arch/msg/emu/mXzpSGEn86Zx_fa4f1uULYMhMoM/
 */
static void eap_teap_append_crypto_binding(REQUEST *request, tls_session_t *tls_session,
					   uint8_t *msk, size_t msklen,
					   uint8_t *emsk, size_t emsklen)
{
	teap_tunnel_t			*t = tls_session->opaque;
	uint8_t				mac_msk[EVP_MAX_MD_SIZE], mac_emsk[EVP_MAX_MD_SIZE];
	unsigned int			maclen = EVP_MAX_MD_SIZE;
	uint8_t				*buf;
	unsigned int			olen;
	struct crypto_binding_buffer	*cbb;

	RDEBUG("Sending Cryptobinding");

	eap_teap_derive_imck(request, tls_session, msk, msklen, emsk, emsklen);

	t->imck_emsk_available = emsklen > 0;

	olen = tls_session->outer_tlvs_octets ? talloc_array_length(tls_session->outer_tlvs_octets) : 0;

	buf = talloc_zero_array(request, uint8_t, sizeof(struct crypto_binding_buffer) - 1/*outer_tlvs*/ + olen);
	rad_assert(buf != NULL);

	cbb = (struct crypto_binding_buffer *)buf;

	CRYPTO_BINDING_BUFFER_INIT(cbb);
	cbb->binding.version = EAP_TEAP_VERSION;
	cbb->binding.received_version = t->received_version;

	cbb->binding.subtype = ((emsklen ? EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_BOTH : EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_MSK) << 4) | EAP_TEAP_TLV_CRYPTO_BINDING_SUBTYPE_REQUEST;

	rad_assert(sizeof(cbb->binding.nonce) % sizeof(uint32_t) == 0);
	RANDFILL(cbb->binding.nonce);
	cbb->binding.nonce[sizeof(cbb->binding.nonce) - 1] &= ~0x01; /* RFC 7170, Section 4.2.13 */

	if (olen) memcpy(cbb->outer_tlvs, tls_session->outer_tlvs_octets, olen);

	RDEBUGHEX("BUFFER for Compound MAC calculation", buf, talloc_array_length(buf));

	const EVP_MD *md = SSL_CIPHER_get_handshake_digest(SSL_get_current_cipher(tls_session->ssl));
	HMAC(md, &t->imck_msk.cmk, EAP_TEAP_CMK_LEN, buf, talloc_array_length(buf), mac_msk, &maclen);
	if (t->imck_emsk_available) {
		HMAC(md, &t->imck_emsk.cmk, EAP_TEAP_CMK_LEN, buf, talloc_array_length(buf), mac_emsk, &maclen);
	}
	memcpy(cbb->binding.msk_compound_mac, &mac_msk, sizeof(cbb->binding.msk_compound_mac));
	if (t->imck_emsk_available) {
		memcpy(cbb->binding.emsk_compound_mac, &mac_emsk, sizeof(cbb->binding.emsk_compound_mac));
	}

	eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_CRYPTO_BINDING, true, sizeof(cbb->binding), (uint8_t *)&cbb->binding);
}

static int eap_teap_verify(REQUEST *request, tls_session_t *tls_session, uint8_t const *data, unsigned int data_len)
{
	uint16_t attr;
	uint16_t length;
	unsigned int remaining = data_len;
	int	total = 0;
	int	num[EAP_TEAP_TLV_MAX] = {0};
	teap_tunnel_t *t = (teap_tunnel_t *) tls_session->opaque;
	uint32_t present = 0;
	uint32_t error = 0;
	uint16_t status = 0;

	rad_assert(sizeof(present) * 8 > EAP_TEAP_TLV_MAX);

	while (remaining > 0) {
		if (remaining < 4) {
			RDEBUG2("EAP-TEAP TLV is too small (%u) to contain a EAP-TEAP TLV header", remaining);
			return 0;
		}

		memcpy(&attr, data, sizeof(attr));
		attr = ntohs(attr) & EAP_TEAP_TLV_TYPE;

		switch (attr) {
		case EAP_TEAP_TLV_RESULT:
		case EAP_TEAP_TLV_NAK:
		case EAP_TEAP_TLV_ERROR:
		case EAP_TEAP_TLV_VENDOR_SPECIFIC:
		case EAP_TEAP_TLV_EAP_PAYLOAD:
		case EAP_TEAP_TLV_INTERMED_RESULT:
		case EAP_TEAP_TLV_PAC:
		case EAP_TEAP_TLV_CRYPTO_BINDING:
			num[attr]++;
			present |= 1 << attr;

			if (num[EAP_TEAP_TLV_EAP_PAYLOAD] > 1) {
				RDEBUG("Too many EAP-Payload TLVs");
unexpected:
				for (int i = 0; i < EAP_TEAP_TLV_MAX; i++)
					if (present & (1 << i))
						RDEBUG(" - attribute %d is present", i);
				eap_teap_send_error(tls_session, EAP_TEAP_ERR_UNEXPECTED_TLV);
				return 0;
			}

			if (num[EAP_TEAP_TLV_INTERMED_RESULT] > 1) {
				RDEBUG("Too many Intermediate-Result TLVs");
				goto unexpected;
			}
			break;
		default:
			if ((data[0] & 0x80) != 0) {
				RDEBUG("Unknown mandatory TLV %02x", attr);
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
			RDEBUG2("EAP-TEAP TLV %u is longer than room remaining in the packet (%u > %u).", attr,
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
			RDEBUG2("EAP-TEAP TLV overflows packet!");
			return 0;
		}

		if (attr == EAP_TEAP_TLV_ERROR) {
			if (length != 4) goto fail_length;
			error = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
		}

		/*
		 * If there's an error, we bail out of the
		 * authentication process before allocating
		 * memory.
		 */
		if ((attr == EAP_TEAP_TLV_INTERMED_RESULT) || (attr == EAP_TEAP_TLV_RESULT)) {
			if (length < 2) {
			fail_length:
				RDEBUG("EAP-TEAP TLV %u is too short.  Expected 2, got %d.", attr, length);
				return 0;
			}

			status = (data[0] << 8) | data[1];
			if (status == 0) goto unknown_value;
		}

		/*
		 * remaining > length, continue.
		 */
		remaining -= length;
		data += length;
	}

	/*
	 *	Check status if we have it.
	 */
	if (status) {
		if (status == EAP_TEAP_TLV_RESULT_FAILURE) {
			if (!error) {
				RDEBUG("EAP-TEAP TLV Status indicates failure with error %u.  Rejecting request.", error);
			} else {
				RDEBUG("EAP-TEAP TLV Status indicates failure.  Rejecting request.");
			}
			return 0;
		}

		if (status != EAP_TEAP_TLV_RESULT_SUCCESS) {
		unknown_value:
			RDEBUG("EAP-TEAP TLV Status contains unknown value %u.  Rejecting request.", status);
			goto unexpected;
		}
	}

	/*
	 * Check if the peer mixed & matched TLVs.
	 */
	if ((num[EAP_TEAP_TLV_NAK] > 0) && (num[EAP_TEAP_TLV_NAK] != total)) {
		RDEBUG("NAK TLV sent with non-NAK TLVs.  Rejecting request.");
		goto unexpected;
	}

	/*
	 * RFC7170 EID5844 says we can have Intermediate-Result and Result TLVs all in one
	 */

	/*
	 * Check mandatory or not mandatory TLVs.
	 */
	switch (t->stage) {
	case TLS_SESSION_HANDSHAKE:
		if (present) {
			RDEBUG("Unexpected TLVs in TLS Session Handshake stage");
			goto unexpected;
		}
		break;
	case AUTHENTICATION:
		if (present & ~((1 << EAP_TEAP_TLV_EAP_PAYLOAD) | (1 << EAP_TEAP_TLV_CRYPTO_BINDING) | (1 << EAP_TEAP_TLV_INTERMED_RESULT) | (1 << EAP_TEAP_TLV_RESULT))) {
			RDEBUG("Unexpected TLVs in authentication stage");
			goto unexpected;
		}
		break;
	case PROVISIONING:
		if (present & ~((1 << EAP_TEAP_TLV_PAC) | (1 << EAP_TEAP_TLV_RESULT))) {
			RDEBUG("Unexpected TLVs in provisioning stage");
			goto unexpected;
		}
		break;
	case COMPLETE:
		if (present) {
			RDEBUG("Unexpected TLVs in complete stage");
			goto unexpected;
		}
		break;
	default:
		RDEBUG("Unexpected stage %d", t->stage);
		return 0;
	}

	/*
	 * We got this far.  It looks OK.
	 */
	return 1;
}

static ssize_t eap_teap_decode_vp(TALLOC_CTX *request, DICT_ATTR const *parent,
				  uint8_t const *data, size_t const attr_len, VALUE_PAIR **out)
{
	int8_t			tag = TAG_NONE;
	VALUE_PAIR		*vp;
	uint8_t const		*p = data;

	/*
	 *	FIXME: Attrlen can be larger than 253 for extended attrs!
	 */
	if (!parent || !out ) {
		RERROR("eap_teap_decode_vp: Invalid arguments");
		return -1;
	}

	/*
	 *	Silently ignore zero-length attributes.
	 */
	if (attr_len == 0) return 0;

	/*
	 *	And now that we've verified the basic type
	 *	information, decode the actual p.
	 */
	vp = fr_pair_afrom_da(request, parent);
	if (!vp) return -1;

	vp->vp_length = attr_len;
	vp->tag = tag;

	switch (parent->type) {
	case PW_TYPE_STRING:
		fr_pair_value_bstrncpy(vp, p, attr_len);
		break;

	case PW_TYPE_OCTETS:
		fr_pair_value_memcpy(vp, p, attr_len);
		break;

	case PW_TYPE_ABINARY:
		if (vp->vp_length > sizeof(vp->vp_filter)) {
			vp->vp_length = sizeof(vp->vp_filter);
		}
		memcpy(vp->vp_filter, p, vp->vp_length);
		break;

	case PW_TYPE_BYTE:
		vp->vp_byte = p[0];
		break;

	case PW_TYPE_SHORT:
		vp->vp_short = (p[0] << 8) | p[1];
		break;

	case PW_TYPE_INTEGER:
	case PW_TYPE_SIGNED:	/* overloaded with vp_integer */
		memcpy(&vp->vp_integer, p, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		break;

	case PW_TYPE_INTEGER64:
		memcpy(&vp->vp_integer64, p, 8);
		vp->vp_integer64 = ntohll(vp->vp_integer64);
		break;

	case PW_TYPE_DATE:
		memcpy(&vp->vp_date, p, 4);
		vp->vp_date = ntohl(vp->vp_date);
		break;

	case PW_TYPE_ETHERNET:
		memcpy(vp->vp_ether, p, 6);
		break;

	case PW_TYPE_IPV4_ADDR:
		memcpy(&vp->vp_ipaddr, p, 4);
		break;

	case PW_TYPE_IFID:
		memcpy(vp->vp_ifid, p, 8);
		break;

	case PW_TYPE_IPV6_ADDR:
		memcpy(&vp->vp_ipv6addr, p, 16);
		break;

	case PW_TYPE_IPV6_PREFIX:
		/*
		 *	FIXME: double-check that
		 *	(vp->vp_octets[1] >> 3) matches vp->vp_length + 2
		 */
		memcpy(vp->vp_ipv6prefix, p, vp->vp_length);
		if (vp->vp_length < 18) {
			memset(((uint8_t *)vp->vp_ipv6prefix) + vp->vp_length, 0,
			       18 - vp->vp_length);
		}
		break;

	case PW_TYPE_IPV4_PREFIX:
		/* FIXME: do the same double-check as for IPv6Prefix */
		memcpy(vp->vp_ipv4prefix, p, vp->vp_length);

		/*
		 *	/32 means "keep all bits".  Otherwise, mask
		 *	them out.
		 */
		if ((p[1] & 0x3f) > 32) {
			uint32_t addr, mask;

			memcpy(&addr, vp->vp_octets + 2, sizeof(addr));
			mask = 1;
			mask <<= (32 - (p[1] & 0x3f));
			mask--;
			mask = ~mask;
			mask = htonl(mask);
			addr &= mask;
			memcpy(vp->vp_ipv4prefix + 2, &addr, sizeof(addr));
		}
		break;

	default:
		RERROR("eap_teap_decode_vp: type %d Internal sanity check  %d ", parent->type, __LINE__);
		fr_pair_list_free(&vp);
		return -1;
	}
	vp->type = VT_DATA;
	*out = vp;
	return attr_len;
}


VALUE_PAIR *eap_teap_teap2vp(REQUEST *request, SSL *ssl, uint8_t const *data, size_t data_len,
                             DICT_ATTR const *teap_da, vp_cursor_t *out)
{
	uint16_t	attr;
	uint16_t	length;
	size_t		data_left = data_len;
	VALUE_PAIR	*first = NULL;
	VALUE_PAIR	*vp = NULL;
	DICT_ATTR const *da;

	if (!teap_da)
		teap_da = dict_attrbyvalue(PW_FREERADIUS_EAP_TEAP_TLV, VENDORPEC_FREERADIUS);
	rad_assert(teap_da != NULL);

	if (!out) {
		out = talloc(request, vp_cursor_t);
		rad_assert(out != NULL);
		fr_cursor_init(out, &first);
	}

	/*
	 * Decode the TLVs
	 */
	while (data_left > 0) {
		ssize_t decoded;

		/* FIXME do something with mandatory */

		memcpy(&attr, data, sizeof(attr));
		attr = ntohs(attr) & EAP_TEAP_TLV_TYPE;

		memcpy(&length, data + 2, sizeof(length));
		length = ntohs(length);

		data += 4;
		data_left -= 4;

		/*
		 * Look up the TLV.
		 *
		 * For now, if it doesn't exist, ignore it.
		 */
		da = dict_attrbyparent(teap_da, attr, teap_da->vendor);
		if (!da) {
			RDEBUG("eap_teap_teap2vp: no sub attribute found %s attr: %u vendor: %u",
					teap_da->name, attr, teap_da->vendor);
			goto next_attr;
		}
		if (da->type == PW_TYPE_TLV) {
			eap_teap_teap2vp(request, ssl, data, length, da, out);
			goto next_attr;
		}
		decoded = eap_teap_decode_vp(request, da, data, length, &vp);
		if (decoded < 0) {
			RERROR("Failed decoding %s: %s", da->name, fr_strerror());
			goto next_attr;
		}

		fr_cursor_merge(out, vp);

	next_attr:
		while (fr_cursor_next(out)) {
			/* nothing */
		}

		data += length;
		data_left -= length;
	}

	/*
	 * We got this far.  It looks OK.
	 */
	return first;
}


static void eapteap_copy_request_to_tunnel(REQUEST *request, REQUEST *fake) {
	VALUE_PAIR *copy, *vp;
	vp_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		 vp;
		 vp = fr_cursor_next(&cursor)) {
		/*
		 * The attribute is a server-side thingy,
		 * don't copy it.
		 */
		if ((vp->da->attr > 255) && (((vp->da->attr >> 16) & 0xffff) == 0)) {
			continue;
		}

		/*
		 * The outside attribute is already in the
		 * tunnel, don't copy it.
		 *
		 * This works for BOTH attributes which
		 * are originally in the tunneled request,
		 * AND attributes which are copied there
		 * from below.
		 */
		if (fr_pair_find_by_da(fake->packet->vps, vp->da, TAG_ANY)) continue;

		/*
		 *	Some attributes are handled specially.
		 */
		if (!vp->da->vendor) switch (vp->da->attr) {
			/*
			 * NEVER copy Message-Authenticator,
			 * EAP-Message, or State.  They're
			 * only for outside of the tunnel.
			 */
		case PW_USER_NAME:
		case PW_USER_PASSWORD:
		case PW_CHAP_PASSWORD:
		case PW_CHAP_CHALLENGE:
		case PW_PROXY_STATE:
		case PW_MESSAGE_AUTHENTICATOR:
		case PW_EAP_MESSAGE:
		case PW_STATE:
			continue;

			/*
			 * By default, copy it over.
			 */
		default:
			break;
		}

		/*
		 * Don't copy from the head, we've already
		 * checked it.
		 */
		copy = fr_pair_list_copy_by_num(fake->packet, vp, vp->da->attr, vp->da->vendor, TAG_ANY);
		fr_pair_add(&fake->packet->vps, copy);
	}
}

/*
 * Use a reply packet to determine what to do.
 */
static rlm_rcode_t CC_HINT(nonnull) process_reply(eap_handler_t *eap_session,
						  tls_session_t *tls_session,
						  REQUEST *request, RADIUS_PACKET *reply)
{
	rlm_rcode_t			rcode = RLM_MODULE_REJECT;
	VALUE_PAIR			*vp;
	vp_cursor_t			cursor;
	uint8_t				msk[2 * CHAP_VALUE_LENGTH] = {0}, emsk[2 * EAPTLS_MPPE_KEY_LEN] = {0};
	size_t				msklen = 0, emsklen = 0;

	teap_tunnel_t	*t = tls_session->opaque;

	rad_assert(eap_session->request == request);

	/*
	 * If the response packet was Access-Accept, then
	 * we're OK.  If not, die horribly.
	 *
	 * FIXME: EAP-Messages can only start with 'identity',
	 * NOT 'eap start', so we should check for that....
	 */
	switch (reply->code) {
	case PW_CODE_ACCESS_ACCEPT:
		RDEBUG("Got tunneled Access-Accept");

		for (vp = fr_cursor_init(&cursor, &reply->vps); vp; vp = fr_cursor_next(&cursor)) {
			if (vp->da->attr == PW_EAP_EMSK) {
				// FIXME check if we should be generating an emsk from MPPE keys below
				emsklen = MIN(vp->vp_length, sizeof(emsk));
				memcpy(emsk, vp->vp_octets, emsklen);
				break;
			}

			if (vp->da->vendor != VENDORPEC_MICROSOFT) continue;

			/* like for EAP-FAST, the keying material is used reversed */
			switch (vp->da->attr) {
			case PW_MSCHAP_MPPE_SEND_KEY:
				if (vp->vp_length == EAPTLS_MPPE_KEY_LEN) {
					/* do not set emsklen here so not to blat EAP-EMSK */
					// emsklen = sizeof(emsk);
					memcpy(emsk, vp->vp_octets, EAPTLS_MPPE_KEY_LEN);
				} else if (vp->vp_length == CHAP_VALUE_LENGTH) {
					msklen = sizeof(msk);
					memcpy(msk, vp->vp_octets, CHAP_VALUE_LENGTH);
				} else {
				wrong_length:
					REDEBUG("Found %s with incorrect length.  Expected %u or %u, got %zu",
						vp->da->name, CHAP_VALUE_LENGTH, EAPTLS_MPPE_KEY_LEN, vp->vp_length);
					return RLM_MODULE_INVALID;
				}

				RDEBUGHEX("MSCHAP_MPPE_SEND_KEY [low MSK]", vp->vp_octets, vp->length);
				break;

			case PW_MSCHAP_MPPE_RECV_KEY:
				/* only do this if there is no EAP-EMSK */
				if (vp->vp_length == EAPTLS_MPPE_KEY_LEN && emsklen == 0) {
					msklen = sizeof(msk);
					memcpy(msk, vp->vp_octets, EAPTLS_MPPE_KEY_LEN);
					emsklen = sizeof(emsk);
					memcpy(&emsk[EAPTLS_MPPE_KEY_LEN], vp->vp_octets, EAPTLS_MPPE_KEY_LEN);
				} else if (vp->vp_length == CHAP_VALUE_LENGTH) {
					msklen = sizeof(msk);
					memcpy(&msk[CHAP_VALUE_LENGTH], vp->vp_octets, CHAP_VALUE_LENGTH);
				} else {
					goto wrong_length;
				}

				RDEBUGHEX("MSCHAP_MPPE_RECV_KEY [high MSK]", vp->vp_octets, vp->vp_length);
				break;

			case PW_MSCHAP2_SUCCESS:
				RDEBUG("Got %s, tunneling it to the client in a challenge", vp->da->name);
				if (t->use_tunneled_reply) {
					t->authenticated = true;
					/*
					 *	Clean up the tunneled reply.
					 */
					fr_pair_delete_by_num(&reply->vps, PW_PROXY_STATE, 0, TAG_ANY);
					fr_pair_delete_by_num(&reply->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
					fr_pair_delete_by_num(&reply->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY);

					/*
					 *	Delete MPPE keys & encryption policy.  We don't
					 *	want these here.
					 */
					fr_pair_delete_by_num(&reply->vps, 7, VENDORPEC_MICROSOFT, TAG_ANY);
					fr_pair_delete_by_num(&reply->vps, 8, VENDORPEC_MICROSOFT, TAG_ANY);
					fr_pair_delete_by_num(&reply->vps, 16, VENDORPEC_MICROSOFT, TAG_ANY);
					fr_pair_delete_by_num(&reply->vps, 17, VENDORPEC_MICROSOFT, TAG_ANY);

					fr_pair_list_free(&t->accept_vps); /* for proxying MS-CHAP2 */
					fr_pair_list_mcopy_by_num(t, &t->accept_vps, &reply->vps, 0, 0, TAG_ANY);
					rad_assert(!reply->vps);
				}
				break;

			default:
				break;
			}
		}

		if (t->use_tunneled_reply) {
			/*
			 *	Clean up the tunneled reply.
			 */
			fr_pair_delete_by_num(&reply->vps, PW_EAP_EMSK, 0, TAG_ANY);
			fr_pair_delete_by_num(&reply->vps, PW_EAP_SESSION_ID, 0, TAG_ANY);
		}

		eap_teap_append_result(tls_session, reply->code);
		eap_teap_append_crypto_binding(request, tls_session, msk, msklen, emsk, emsklen);

		vp = fr_pair_find_by_num(request->state, PW_EAP_TEAP_TLV_IDENTITY, VENDORPEC_FREERADIUS, TAG_ANY);
		if (vp) {
			RDEBUG("&session-state:FreeRADIUS-EAP-TEAP-TLV-Identity-Type set so continuing EAP sequence/chaining");

			/* RFC3748, Section 2.1 - does not explictly tell us to but we need to eat the EAP-Success */
			fr_pair_delete_by_num(&reply->vps, PW_EAP_MESSAGE, 0, TAG_ANY);

			/* new identity */
			talloc_free(t->username);
			t->username = NULL;

			/* RFC7170, Appendix C.6 */
			eap_teap_append_identity(tls_session, vp->vp_short);
			eap_teap_append_eap_identity_request(request, tls_session, eap_session);

			goto challenge;
		}

		t->result_final = true;
		eap_teap_append_result(tls_session, reply->code);

		tls_session->authentication_success = true;
		rcode = RLM_MODULE_OK;

		break;

	case PW_CODE_ACCESS_REJECT:
		RDEBUG("Got tunneled Access-Reject");

		eap_teap_append_result(tls_session, reply->code);
		rcode = RLM_MODULE_REJECT;
		break;

	/*
	 * Handle Access-Challenge, but only if we
	 * send tunneled reply data.  This is because
	 * an Access-Challenge means that we MUST tunnel
	 * a Reply-Message to the client.
	 */
	case PW_CODE_ACCESS_CHALLENGE:
		RDEBUG("Got tunneled Access-Challenge");
challenge:
		/*
		 *	Keep the State attribute, if necessary.
		 *
		 *	Get rid of the old State, too.
		 */
		fr_pair_list_free(&t->state);
		fr_pair_list_mcopy_by_num(t, &t->state, &reply->vps, PW_STATE, 0, TAG_ANY);

		/*
		 *	Copy the EAP-Message back to the tunnel.
		 */
		(void) fr_cursor_init(&cursor, &reply->vps);

		while ((vp = fr_cursor_next_by_num(&cursor, PW_EAP_MESSAGE, 0, TAG_ANY)) != NULL) {
			eap_teap_tlv_append(tls_session, EAP_TEAP_TLV_EAP_PAYLOAD, true, vp->vp_length, vp->vp_octets);
		}

		/*
		 * When chaining, we 'goto challenge' and can use that to now signal back
		 * to unlang that a method has completed and we can now move to the next
		 */
		rcode = reply->code == PW_CODE_ACCESS_CHALLENGE ? RLM_MODULE_HANDLED : RLM_MODULE_OK;
		break;

	default:
		RDEBUG("Unknown RADIUS packet type %d: rejecting tunneled user", reply->code);
		rcode = RLM_MODULE_INVALID;
		break;
	}


	return rcode;
}

static PW_CODE eap_teap_eap_payload(REQUEST *request, eap_handler_t *eap_session,
				    tls_session_t *tls_session,
				    VALUE_PAIR *vp_eap, VALUE_PAIR *vp_type)
{
	PW_CODE			code = PW_CODE_ACCESS_REJECT;
	rlm_rcode_t		rcode;
	VALUE_PAIR		*vp;
	teap_tunnel_t	*t;
	REQUEST			*fake;

	RDEBUG("Processing received EAP Payload");

	/*
	 * Allocate a fake REQUEST structure.
	 */
	fake = request_alloc_fake(request);
	rad_assert(!fake->packet->vps);

	t = (teap_tunnel_t *) tls_session->opaque;

	/*
	 * Add the tunneled attributes to the fake request.
	 */

	fake->packet->vps = fr_pair_afrom_num(fake->packet, PW_EAP_MESSAGE, 0);
	fr_pair_value_memcpy(fake->packet->vps, vp_eap->vp_octets, vp_eap->vp_length);

	if (vp_type) fr_pair_add(&fake->packet->vps, fr_pair_copy(fake->packet, vp_type));

	RDEBUG("Got tunneled request");
	rdebug_pair_list(L_DBG_LVL_1, request, fake->packet->vps, NULL);

	/*
	 * Tell the request that it's a fake one.
	 */
	fr_pair_make(fake->packet, &fake->packet->vps, "Freeradius-Proxied-To", "127.0.0.1", T_OP_EQ);

	/*
	 * No User-Name in the stored data, look for
	 * an EAP-Identity, and pull it out of there.
	 */
	if (!t->username) {
		vp = fr_pair_find_by_num(fake->packet->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
		if (vp &&
		    (vp->vp_length >= EAP_HEADER_LEN + 2) &&
		    (vp->vp_strvalue[0] == PW_EAP_RESPONSE) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN] == PW_EAP_IDENTITY) &&
		    (vp->vp_strvalue[EAP_HEADER_LEN + 1] != 0)) {
			/*
			 * Create & remember a User-Name
			 */
			t->username = fr_pair_make(t, NULL, "User-Name", NULL, T_OP_EQ);
			rad_assert(t->username != NULL);

			fr_pair_value_bstrncpy(t->username, vp->vp_octets + 5, vp->vp_length - 5);

			RDEBUG("Got tunneled identity of %s", t->username->vp_strvalue);
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
		vp = fr_pair_list_copy(fake->packet, t->username);
		fr_pair_add(&fake->packet->vps, vp);
		fake->username = vp;
	}

	/*
	 *	Add the State attribute, too, if it exists.
	 */
	if (t->state) {
		vp = fr_pair_list_copy(fake->packet, t->state);
		if (vp) fr_pair_add(&fake->packet->vps, vp);
	}

	if (t->stage == AUTHENTICATION) {
		VALUE_PAIR *tvp;

		RDEBUG2("AUTHENTICATION");

		if (t->default_method) {
			/*
			 *	RFC 7170 - Authenticating Using EAP-TEAP-MSCHAPv2
			 */
			if (t->default_method == PW_EAP_MSCHAPV2 && t->mode == EAP_TEAP_PROVISIONING_ANON) {
				tvp = fr_pair_afrom_num(fake, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT);
				//fr_pair_value_memcpy(tvp, t->keyblock->server_challenge, CHAP_VALUE_LENGTH);
				fr_pair_add(&fake->config, tvp);

				tvp = fr_pair_afrom_num(fake, PW_MS_CHAP_PEER_CHALLENGE, 0);
				//fr_pair_value_memcpy(tvp, t->keyblock->client_challenge, CHAP_VALUE_LENGTH);
				fr_pair_add(&fake->config, tvp);
			}
		}
	}

	if (t->copy_request_to_tunnel) {
		eapteap_copy_request_to_tunnel(request, fake);
	}

	if ((vp = fr_pair_find_by_num(request->config, PW_VIRTUAL_SERVER, 0, TAG_ANY)) != NULL) {
		fake->server = vp->vp_strvalue;

	} else if (t->virtual_server) {
		fake->server = t->virtual_server;

	} /* else fake->server == request->server */

	/*
	 * Call authentication recursively, which will
	 * do PAP, CHAP, MS-CHAP, etc.
	 */
	rad_virtual_server(fake);

	/*
	 * Decide what to do with the reply.
	 */
	switch (fake->reply->code) {
	case 0:
		RDEBUG("No tunneled reply was found, rejecting the user.");
		code = PW_CODE_ACCESS_REJECT;
		break;

	default:
		/*
		 * Returns RLM_MODULE_FOO, and we want to return PW_FOO
		 */
		rcode = process_reply(eap_session, tls_session, request, fake->reply);
		switch (rcode) {
		case RLM_MODULE_REJECT:
			code = PW_CODE_ACCESS_REJECT;
			break;

		case RLM_MODULE_HANDLED:
			code = PW_CODE_ACCESS_CHALLENGE;
			break;

		case RLM_MODULE_OK:
			code = PW_CODE_ACCESS_ACCEPT;
			break;

		default:
			code = PW_CODE_ACCESS_REJECT;
			break;
		}
		break;
	}

	talloc_free(fake);

	return code;
}

static PW_CODE eap_teap_crypto_binding(REQUEST *request, UNUSED eap_handler_t *eap_session,
				       tls_session_t *tls_session, eap_tlv_crypto_binding_tlv_t const *binding)
{
	teap_tunnel_t			*t = tls_session->opaque;
	uint8_t				*buf;
	unsigned int			olen;
	struct crypto_binding_buffer	*cbb;
	uint8_t				mac[EVP_MAX_MD_SIZE];
	unsigned int			maclen = sizeof(mac);
	unsigned int			flags;
	struct teap_imck_t	 	*imck = NULL;

	olen = tls_session->outer_tlvs_octets ? talloc_array_length(tls_session->outer_tlvs_octets) : 0;
	/* FIXME: include client outer TLVs */

	buf = talloc_zero_array(request, uint8_t, sizeof(struct crypto_binding_buffer) - 1/*outer_tlvs*/ + olen);
	rad_assert(buf != NULL);

	cbb = (struct crypto_binding_buffer *)buf;

	if (binding->version != t->received_version || binding->received_version != EAP_TEAP_VERSION) {
		RDEBUG2("Crypto-Binding TLV version mis-match (possible downgrade attack!)");
		return PW_CODE_ACCESS_REJECT;
	}
	if ((binding->subtype & 0xf) != EAP_TEAP_TLV_CRYPTO_BINDING_SUBTYPE_RESPONSE) {
		RDEBUG2("Crypto-Binding TLV unexpected non-response");
		return PW_CODE_ACCESS_REJECT;
	}
	flags = binding->subtype >> 4;

	CRYPTO_BINDING_BUFFER_INIT(cbb);
	memcpy(&cbb->binding, binding, sizeof(cbb->binding) - sizeof(cbb->binding.emsk_compound_mac) - sizeof(cbb->binding.msk_compound_mac));
	if (olen) memcpy(cbb->outer_tlvs, tls_session->outer_tlvs_octets, olen);

	RDEBUGHEX("BUFFER for Compound MAC calculation", buf, talloc_array_length(buf));

	/*
	 * we carry forward the S-IMCK[j] based on what we verified for session key generation
	 *
	 * https://mailarchive.ietf.org/arch/msg/emu/mXzpSGEn86Zx_fa4f1uULYMhMoM/
	 * https://github.com/emu-wg/teap-errata/pull/13
	 */
	const EVP_MD *md = SSL_CIPHER_get_handshake_digest(SSL_get_current_cipher(tls_session->ssl));
	if (flags != EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_EMSK) {
		HMAC(md, &t->imck_msk.cmk, sizeof(t->imck_msk.cmk), buf, talloc_array_length(buf), mac, &maclen);
		if (memcmp(binding->msk_compound_mac, mac, sizeof(binding->msk_compound_mac))) {
			RDEBUG2("Crypto-Binding TLV (MSK) mis-match");
			return PW_CODE_ACCESS_REJECT;
		}
		imck = &t->imck_msk;
	}
	if (flags != EAP_TEAP_TLV_CRYPTO_BINDING_FLAGS_CMAC_MSK && t->imck_emsk_available) {
		HMAC(md, &t->imck_emsk.cmk, sizeof(t->imck_emsk.cmk), buf, talloc_array_length(buf), mac, &maclen);
		if (memcmp(binding->emsk_compound_mac, mac, sizeof(binding->emsk_compound_mac))) {
			RDEBUG2("Crypto-Binding TLV (EMSK) mis-match");
			return PW_CODE_ACCESS_REJECT;
		}
		imck = &t->imck_emsk;
	}

	if (!imck) imck = &imck_zeros;

	/* IMCK[j] 60 octets => S-IMCK[j] first 40 octets, CMK[j] last 20 octets */
	RDEBUGHEX("S-IMCK[j]", imck->simck, sizeof(imck->simck));

	uint8_t mk_msk_label[31] = "Session Key Generating Function";

	struct iovec mk_msk_seed[1] = {
		{ (void *)mk_msk_label, sizeof(mk_msk_label) }
	};
	TLS_PRF(tls_session->ssl,
		imck->simck, sizeof(imck->simck),
		mk_msk_seed, ARRAY_SIZE(mk_msk_seed),
		(uint8_t *)&t->msk, sizeof(t->msk));
	RDEBUGHEX("Derived key (MSK)", t->msk, sizeof(t->msk));

	uint8_t mk_emsk_label[40] = "Extended Session Key Generating Function";
	struct iovec mk_emsk_seed[1] = {
		{ (void *)mk_emsk_label, sizeof(mk_emsk_label) }
	};
	TLS_PRF(tls_session->ssl,
		imck->simck, sizeof(imck->simck),
		mk_emsk_seed, ARRAY_SIZE(mk_emsk_seed),
		(uint8_t *)&t->emsk, sizeof(t->emsk));
	RDEBUGHEX("Derived key (EMSK)", t->emsk, sizeof(t->emsk));

	return PW_CODE_ACCESS_ACCEPT;
}


static PW_CODE eap_teap_process_tlvs(REQUEST *request, eap_handler_t *eap_session,
				     tls_session_t *tls_session, VALUE_PAIR *teap_vps)
{
	teap_tunnel_t			*t = (teap_tunnel_t *) tls_session->opaque;
	VALUE_PAIR			*vp, *vp_eap = NULL, *vp_type = NULL;
	vp_cursor_t			cursor;
	PW_CODE code			= PW_CODE_ACCESS_ACCEPT;
	bool gotintermedresult = false, gotresult = false, gotcryptobinding = false;

	for (vp = fr_cursor_init(&cursor, &teap_vps); vp; vp = fr_cursor_next(&cursor)) {
		char *value;
		DICT_ATTR const *parent_da = NULL;
		parent_da = dict_parent(vp->da->attr, vp->da->vendor);
		if (parent_da == NULL || vp->da->vendor != VENDORPEC_FREERADIUS ||
			((vp->da->attr & 0xff) != PW_FREERADIUS_EAP_TEAP_TLV)) {
			value = vp_aprints(request->packet, vp, '"');
			RDEBUG2("ignoring non-EAP-TEAP TLV %s", value);
			talloc_free(value);
			continue;
		}

		switch (parent_da->attr) {
		case PW_FREERADIUS_EAP_TEAP_TLV:
			switch (vp->da->attr >> 8) {
			case EAP_TEAP_TLV_IDENTITY:
				vp_type = vp;
				break;
			case EAP_TEAP_TLV_EAP_PAYLOAD:
				vp_eap = vp;
				break;
			case EAP_TEAP_TLV_RESULT:
				gotresult = true;
				if (vp->vp_short != EAP_TEAP_TLV_RESULT_SUCCESS) code = PW_CODE_ACCESS_REJECT;
				break;
			case EAP_TEAP_TLV_INTERMED_RESULT:
				gotintermedresult = true;
				if (vp->vp_short != EAP_TEAP_TLV_RESULT_SUCCESS) code = PW_CODE_ACCESS_REJECT;
				break;
			case EAP_TEAP_TLV_CRYPTO_BINDING:
				gotcryptobinding = true;
				if (vp->vp_length >= sizeof(eap_tlv_crypto_binding_tlv_t))
					code = eap_teap_crypto_binding(request, eap_session, tls_session,
								       (eap_tlv_crypto_binding_tlv_t const *)vp->vp_octets);
				break;
			default:
				value = vp_aprints_value(request->packet, vp, '"');
				RDEBUG2("ignoring unknown %s", value);
				talloc_free(value);
			}
			break;
		case PW_EAP_TEAP_TLV_PAC:
			switch ( ( vp->da->attr >> 16 )) {
			case PAC_INFO_PAC_ACK:
				if (vp->vp_integer == EAP_TEAP_TLV_RESULT_SUCCESS) {
					t->pac.expires = UINT32_MAX;
					t->pac.expired = false;
				}
				break;
			case PAC_INFO_PAC_TYPE:
				if (vp->vp_integer != PAC_TYPE_TUNNEL) {
					RDEBUG("only able to serve Tunnel PAC's, ignoring request");
					break;
				}
				t->pac.send = true;
				break;
			default:
				value = vp_aprints(request->packet, vp, '"');
				RDEBUG2("ignoring unknown EAP-TEAP-PAC-TLV %s", value);
				talloc_free(value);
			}
			break;
		default:
			value = vp_aprints(request->packet, vp, '"');
			RDEBUG2("ignoring EAP-TEAP TLV %s", value);
			talloc_free(value);
		}

		if (code == PW_CODE_ACCESS_REJECT)
			return PW_CODE_ACCESS_REJECT;
	}

	if (t->stage == AUTHENTICATION) {
		if (gotcryptobinding && gotintermedresult) t->stage = PROVISIONING;
		/* rollback if we have an EAP sequence (chaining) */
		vp = fr_pair_find_by_num(request->state, PW_EAP_TEAP_TLV_IDENTITY, VENDORPEC_FREERADIUS, TAG_ANY);
		if (t->stage == PROVISIONING && !gotresult && vp) t->stage = AUTHENTICATION;
	}
	if (t->stage == PROVISIONING) {
		if (gotcryptobinding && gotresult) t->stage = COMPLETE;
	}

	if (vp_eap)
		code = eap_teap_eap_payload(request, eap_session, tls_session, vp_eap, vp_type);

	return code;
}


static void print_tunneled_data(uint8_t const *data, size_t data_len)
{
	size_t i;

	DEBUG2("  TEAP tunnel data total %zu", data_len);

	if ((rad_debug_lvl > 2) && fr_log_fp) {
		for (i = 0; i < data_len; i++) {
		  if ((i & 0x0f) == 0) fprintf(fr_log_fp, "  TEAP tunnel data in %02x: ", (int) i);

			fprintf(fr_log_fp, "%02x ", data[i]);

			if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
		}
		if ((data_len & 0x0f) != 0) fprintf(fr_log_fp, "\n");
	}
}


/*
 * Process the inner tunnel data
 */
PW_CODE eap_teap_process(eap_handler_t *eap_session, tls_session_t *tls_session)
{
	PW_CODE			code;
	VALUE_PAIR		*teap_vps, *vp;
	uint8_t			const *data;
	size_t			data_len;
	teap_tunnel_t		*t;
	REQUEST			*request = eap_session->request;

	/*
	 * Just look at the buffer directly, without doing
	 * record_to_buff.
	 */
	data_len = tls_session->clean_out.used;
	tls_session->clean_out.used = 0;
	data = tls_session->clean_out.data;

	t = (teap_tunnel_t *) tls_session->opaque;

	if (rad_debug_lvl > 2) print_tunneled_data(data, data_len);

	/*
	 * See if the tunneled data is well formed.
	 */
	if (!eap_teap_verify(request, tls_session, data, data_len)) return PW_CODE_ACCESS_REJECT;

	if (t->stage == TLS_SESSION_HANDSHAKE) {
		rad_assert(t->mode == EAP_TEAP_UNKNOWN);

		char buf[256];
		if (strstr(SSL_CIPHER_description(SSL_get_current_cipher(tls_session->ssl),
						  buf, sizeof(buf)), "Au=None")) {
			/* FIXME enforce MSCHAPv2 - RFC 7170 */
			RDEBUG2("Using anonymous provisioning");
			t->mode = EAP_TEAP_PROVISIONING_ANON;
			t->pac.send = true;
		} else {
			if (SSL_session_reused(tls_session->ssl)) {
				RDEBUG("Session Resumed from PAC");
				t->mode = EAP_TEAP_NORMAL_AUTH;
			} else {
				RDEBUG2("Using authenticated provisioning");
				t->mode = EAP_TEAP_PROVISIONING_AUTH;
			}

			/*
			 *	Send a new pac at ~0.6 times the lifetime.
			 */
			if (!t->pac.expires || t->pac.expired || t->pac.expires < (time(NULL) + (t->pac_lifetime >> 1) + (t->pac_lifetime >> 3))) {
				t->pac.send = true;
			}
		}

		eap_teap_init_keys(request, tls_session);

		/* RFC7170, Appendix C.6 */
		vp = fr_pair_find_by_num(request->state, PW_EAP_TEAP_TLV_IDENTITY, VENDORPEC_FREERADIUS, TAG_ANY);
		if (vp) eap_teap_append_identity(tls_session, vp->vp_short);

		eap_teap_append_eap_identity_request(request, tls_session, eap_session);

		t->stage = AUTHENTICATION;

		tls_handshake_send(request, tls_session);

		return PW_CODE_ACCESS_CHALLENGE;
	}

	teap_vps = eap_teap_teap2vp(request, tls_session->ssl, data, data_len, NULL, NULL);

	RDEBUG("Got Tunneled TEAP TLVs");
	rdebug_pair_list(L_DBG_LVL_1, request, teap_vps, NULL);

	code = eap_teap_process_tlvs(request, eap_session, tls_session, teap_vps);

	fr_pair_list_free(&teap_vps);

	if (code == PW_CODE_ACCESS_REJECT) return PW_CODE_ACCESS_REJECT;

	switch (t->stage) {
	case AUTHENTICATION:
		code = PW_CODE_ACCESS_CHALLENGE;
		break;

	case PROVISIONING:
		if (!t->result_final) {
			t->result_final = true;
			eap_teap_append_result(tls_session, code);
		}

#if 0
		if (t->pac.send) {
			RDEBUG("Peer requires new PAC");
			eap_teap_send_pac_tunnel(request, tls_session);
			code = PW_CODE_ACCESS_CHALLENGE;
			break;
		}
#endif

		/* FALL-THROUGH */

	case COMPLETE:
#if 0
		/*
		 * RFC 7170 - Network Access after EAP-TEAP Provisioning
		 */
		if (t->pac.type && t->pac.expired) {
			REDEBUG("Rejecting expired PAC.");
			code = PW_CODE_ACCESS_REJECT;
			break;
		}

		if (t->mode == EAP_TEAP_PROVISIONING_ANON) {
			REDEBUG("Rejecting unauthenticated provisioning");
			code = PW_CODE_ACCESS_REJECT;
			break;
		}
#endif
		/*
		 * TEAP wants to use it's own MSK, so boo to eap_tls_gen_mppe_keys()
		 */
		eap_add_reply(request, "MS-MPPE-Recv-Key", t->msk, EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, "MS-MPPE-Send-Key", &t->msk[EAPTLS_MPPE_KEY_LEN], EAPTLS_MPPE_KEY_LEN);
		eap_add_reply(request, "EAP-MSK", t->msk, sizeof(t->msk));
		eap_add_reply(request, "EAP-EMSK", t->emsk, sizeof(t->emsk));

		break;

	default:
		RERROR("Internal sanity check failed in EAP-TEAP at %d", t->stage);
		code = PW_CODE_ACCESS_REJECT;
	}

	tls_handshake_send(request, tls_session);

	return code;
}
