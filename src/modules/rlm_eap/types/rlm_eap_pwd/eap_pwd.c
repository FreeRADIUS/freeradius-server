/*
 * Copyright (c) Dan Harkins, 2012
 *
 *  Copyright holder grants permission for redistribution and use in source
 *  and binary forms, with or without modification, provided that the
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *	notice, this list of conditions, and the following disclaimer
 *	in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *	notice, this list of conditions, and the following disclaimer
 *	in the documentation and/or other materials provided with the
 *	distribution.
 *
 *  "DISCLAIMER OF LIABILITY
 *
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_pwd.h"

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/* The random function H(x) = HMAC-SHA256(0^32, x) */
static void H_Init(HMAC_CTX *ctx)
{
	uint8_t allzero[SHA256_DIGEST_LENGTH];

	memset(allzero, 0, SHA256_DIGEST_LENGTH);

	HMAC_Init_ex(ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);
}

static void H_Update(HMAC_CTX *ctx, uint8_t const *data, int len)
{
	HMAC_Update(ctx, data, len);
}

static void H_Final(HMAC_CTX *ctx, uint8_t *digest)
{
	unsigned int mdlen = SHA256_DIGEST_LENGTH;

	HMAC_Final(ctx, digest, &mdlen);
}

/* a counter-based KDF based on NIST SP800-108 */
static int eap_pwd_kdf(uint8_t *key, int keylen, char const *label, int labellen, uint8_t *result, int resultbitlen)
{
	HMAC_CTX *hctx = NULL;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint16_t i, ctr, L;
	int resultbytelen, len = 0;
	unsigned int mdlen = SHA256_DIGEST_LENGTH;
	uint8_t mask = 0xff;

	hctx = HMAC_CTX_new();
	if (hctx == NULL) {
		DEBUG("failed allocating HMAC context");
		return -1;
	}
	resultbytelen = (resultbitlen + 7)/8;
	ctr = 0;
	L = htons(resultbitlen);
	while (len < resultbytelen) {
		ctr++; i = htons(ctr);
		HMAC_Init_ex(hctx, key, keylen, EVP_sha256(), NULL);
		if (ctr > 1) {
			HMAC_Update(hctx, digest, mdlen);
		}
		HMAC_Update(hctx, (uint8_t *) &i, sizeof(uint16_t));
		HMAC_Update(hctx, (uint8_t const *)label, labellen);
		HMAC_Update(hctx, (uint8_t *) &L, sizeof(uint16_t));
		HMAC_Final(hctx, digest, &mdlen);
		if ((len + (int) mdlen) > resultbytelen) {
			memcpy(result + len, digest, resultbytelen - len);
		} else {
			memcpy(result + len, digest, mdlen);
		}
		len += mdlen;
	}
	HMAC_CTX_free(hctx);

	/* since we're expanding to a bit length, mask off the excess */
	if (resultbitlen % 8) {
		mask <<= (8 - (resultbitlen % 8));
		result[resultbytelen - 1] &= mask;
	}

	return 0;
}

int compute_password_element (pwd_session_t *session, uint16_t grp_num,
			      char const *password, int password_len,
			      char const *id_server, int id_server_len,
			      char const *id_peer, int id_peer_len,
			      uint32_t *token)
{
	BIGNUM *x_candidate = NULL, *rnd = NULL, *cofactor = NULL;
	HMAC_CTX *ctx = NULL;
	uint8_t pwe_digest[SHA256_DIGEST_LENGTH], *prfbuf = NULL, ctr;
	int nid, is_odd, primebitlen, primebytelen, ret = 0;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
		DEBUG("failed allocating HMAC context");
		goto fail;
	}

	switch (grp_num) { /* from IANA registry for IKE D-H groups */
	case 19:
		nid = NID_X9_62_prime256v1;
		break;

	case 20:
		nid = NID_secp384r1;
		break;

	case 21:
		nid = NID_secp521r1;
		break;

	case 25:
		nid = NID_X9_62_prime192v1;
		break;

	case 26:
		nid = NID_secp224r1;
		break;

	default:
		DEBUG("unknown group %d", grp_num);
		goto fail;
	}

	session->pwe = NULL;
	session->order = NULL;
	session->prime = NULL;

	if ((session->group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
		DEBUG("unable to create EC_GROUP");
		goto fail;
	}

	if (((rnd = BN_new()) == NULL) ||
	    ((cofactor = BN_new()) == NULL) ||
	    ((session->pwe = EC_POINT_new(session->group)) == NULL) ||
	    ((session->order = BN_new()) == NULL) ||
	    ((session->prime = BN_new()) == NULL) ||
	    ((x_candidate = BN_new()) == NULL)) {
		DEBUG("unable to create bignums");
		goto fail;
	}

	if (!EC_GROUP_get_curve_GFp(session->group, session->prime, NULL, NULL, NULL)) {
		DEBUG("unable to get prime for GFp curve");
		goto fail;
	}

	if (!EC_GROUP_get_order(session->group, session->order, NULL)) {
		DEBUG("unable to get order for curve");
		goto fail;
	}

	if (!EC_GROUP_get_cofactor(session->group, cofactor, NULL)) {
		DEBUG("unable to get cofactor for curve");
		goto fail;
	}

	primebitlen = BN_num_bits(session->prime);
	primebytelen = BN_num_bytes(session->prime);
	if ((prfbuf = talloc_zero_array(session, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for prf buffer");
		goto fail;
	}
	ctr = 0;
	while (1) {
		if (ctr > 10) {
			DEBUG("unable to find random point on curve for group %d, something's fishy", grp_num);
			goto fail;
		}
		ctr++;

		/*
		 * compute counter-mode password value and stretch to prime
		 *    pwd-seed = H(token | peer-id | server-id | password |
		 *		   counter)
		 */
		H_Init(ctx);
		H_Update(ctx, (uint8_t *)token, sizeof(*token));
		H_Update(ctx, (uint8_t const *)id_peer, id_peer_len);
		H_Update(ctx, (uint8_t const *)id_server, id_server_len);
		H_Update(ctx, (uint8_t const *)password, password_len);
		H_Update(ctx, (uint8_t *)&ctr, sizeof(ctr));
		H_Final(ctx, pwe_digest);

		BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
		if (eap_pwd_kdf(pwe_digest, SHA256_DIGEST_LENGTH, "EAP-pwd Hunting And Pecking",
			        strlen("EAP-pwd Hunting And Pecking"), prfbuf, primebitlen) != 0) {
			DEBUG("key derivation function failed");
			goto fail;
		}

		BN_bin2bn(prfbuf, primebytelen, x_candidate);
		/*
		 * eap_pwd_kdf() returns a string of bits 0..primebitlen but
		 * BN_bin2bn will treat that string of bits as a big endian
		 * number. If the primebitlen is not an even multiple of 8
		 * then excessive bits-- those _after_ primebitlen-- so now
		 * we have to shift right the amount we masked off.
		 */
		if (primebitlen % 8) BN_rshift(x_candidate, x_candidate, (8 - (primebitlen % 8)));
		if (BN_ucmp(x_candidate, session->prime) >= 0) continue;

		/*
		 * need to unambiguously identify the solution, if there is
		 * one...
		 */
		is_odd = BN_is_odd(rnd) ? 1 : 0;

		/*
		 * solve the quadratic equation, if it's not solvable then we
		 * don't have a point
		 */
		if (!EC_POINT_set_compressed_coordinates_GFp(session->group, session->pwe, x_candidate, is_odd, NULL)) {
			continue;
		}

		/*
		 * If there's a solution to the equation then the point must be
		 * on the curve so why check again explicitly? OpenSSL code
		 * says this is required by X9.62. We're not X9.62 but it can't
		 * hurt just to be sure.
		 */
		if (!EC_POINT_is_on_curve(session->group, session->pwe, NULL)) {
			DEBUG("EAP-pwd: point is not on curve");
			continue;
		}

		if (BN_cmp(cofactor, BN_value_one())) {
			/* make sure the point is not in a small sub-group */
			if (!EC_POINT_mul(session->group, session->pwe, NULL, session->pwe,
				cofactor, NULL)) {
				DEBUG("EAP-pwd: cannot multiply generator by order");
				continue;
			}

			if (EC_POINT_is_at_infinity(session->group, session->pwe)) {
				DEBUG("EAP-pwd: point is at infinity");
				continue;
			}
		}
		/* if we got here then we have a new generator. */
		break;
	}

	session->group_num = grp_num;
	if (0) {
		fail:		/* DON'T free session, it's in handler->opaque */
		ret = -1;
	}

	/* cleanliness and order.... */
	BN_clear_free(cofactor);
	BN_clear_free(x_candidate);
	BN_clear_free(rnd);
	talloc_free(prfbuf);
	HMAC_CTX_free(ctx);

	return ret;
}

int compute_scalar_element (pwd_session_t *session, BN_CTX *bnctx) {
	BIGNUM *mask = NULL;
	int ret = -1;

	if (((session->private_value = BN_new()) == NULL) ||
	    ((session->my_element = EC_POINT_new(session->group)) == NULL) ||
	    ((session->my_scalar = BN_new()) == NULL) ||
	    ((mask = BN_new()) == NULL)) {
		DEBUG2("server scalar allocation failed");
		goto fail;
	}

	if (BN_rand_range(session->private_value, session->order) != 1) {
		DEBUG2("Unable to get randomness for private_value");
		goto fail;
	}
	if (BN_rand_range(mask, session->order) != 1) {
		DEBUG2("Unable to get randomness for mask");
		goto fail;
	}
	BN_add(session->my_scalar, session->private_value, mask);
	BN_mod(session->my_scalar, session->my_scalar, session->order, bnctx);

	if (!EC_POINT_mul(session->group, session->my_element, NULL, session->pwe, mask, bnctx)) {
		DEBUG2("server element allocation failed");
		goto fail;
	}

	if (!EC_POINT_invert(session->group, session->my_element, bnctx)) {
		DEBUG2("server element inversion failed");
		goto fail;
	}

	ret = 0;

fail:
	BN_clear_free(mask);

	return ret;
}

int process_peer_commit (pwd_session_t *session, uint8_t *in, size_t in_len, BN_CTX *bnctx)
{
	uint8_t *ptr;
	size_t data_len;
	BIGNUM *x = NULL, *y = NULL, *cofactor = NULL;
	EC_POINT *K = NULL, *point = NULL;
	int res = 1;

	if (((session->peer_scalar = BN_new()) == NULL) ||
	    ((session->k = BN_new()) == NULL) ||
	    ((cofactor = BN_new()) == NULL) ||
	    ((x = BN_new()) == NULL) ||
	    ((y = BN_new()) == NULL) ||
	    ((point = EC_POINT_new(session->group)) == NULL) ||
	    ((K = EC_POINT_new(session->group)) == NULL) ||
	    ((session->peer_element = EC_POINT_new(session->group)) == NULL)) {
		DEBUG2("pwd: failed to allocate room to process peer's commit");
		goto finish;
	}

	if (!EC_GROUP_get_cofactor(session->group, cofactor, NULL)) {
		DEBUG2("pwd: unable to get group co-factor");
		goto finish;
	}

	/* element, x then y, followed by scalar */
	ptr = (uint8_t *)in;
	data_len = BN_num_bytes(session->prime);

	/*
	 *	Did the peer send enough data?
	 */
	if (in_len < (2 * data_len + BN_num_bytes(session->order))) {
		DEBUG("pwd: Invalid commit packet");
		goto finish;
	}

	BN_bin2bn(ptr, data_len, x);
	ptr += data_len;
	BN_bin2bn(ptr, data_len, y);
	ptr += data_len;

	data_len = BN_num_bytes(session->order);
	BN_bin2bn(ptr, data_len, session->peer_scalar);

	if (!EC_POINT_set_affine_coordinates_GFp(session->group, session->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	/* check to ensure peer's element is not in a small sub-group */
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(session->group, point, NULL, session->peer_element, cofactor, NULL)) {
			DEBUG2("pwd: unable to multiply element by co-factor");
			goto finish;
		}

		if (EC_POINT_is_at_infinity(session->group, point)) {
			DEBUG2("pwd: peer's element is in small sub-group");
			goto finish;
		}
	}

	/* compute the shared key, k */
	if ((!EC_POINT_mul(session->group, K, NULL, session->pwe, session->peer_scalar, bnctx)) ||
	    (!EC_POINT_add(session->group, K, K, session->peer_element, bnctx)) ||
	    (!EC_POINT_mul(session->group, K, NULL, K, session->private_value, bnctx))) {
		DEBUG2("pwd: unable to compute shared key, k");
		goto finish;
	}

	/* ensure that the shared key isn't in a small sub-group */
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(session->group, K, NULL, K, cofactor, NULL)) {
			DEBUG2("pwd: unable to multiply k by co-factor");
			goto finish;
		}
	}

	/*
	 * This check is strictly speaking just for the case above where
	 * co-factor > 1 but it was suggested that even though this is probably
	 * never going to happen it is a simple and safe check "just to be
	 * sure" so let's be safe.
	 */
	if (EC_POINT_is_at_infinity(session->group, K)) {
		DEBUG2("pwd: k is point-at-infinity!");
		goto finish;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(session->group, K, session->k, NULL, bnctx)) {
		DEBUG2("pwd: unable to get shared secret from K");
		goto finish;
	}
	res = 0;

finish:
	EC_POINT_clear_free(K);
	EC_POINT_clear_free(point);
	BN_clear_free(cofactor);
	BN_clear_free(x);
	BN_clear_free(y);

	return res;
}

int compute_server_confirm (pwd_session_t *session, uint8_t *out, BN_CTX *bnctx)
{
	BIGNUM *x = NULL, *y = NULL;
	HMAC_CTX *ctx = NULL;
	uint8_t *cruft = NULL;
	int offset, req = -1;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
		DEBUG2("pwd: unable to allocate HMAC context!");
		goto finish;
	}

	/*
	 * Each component of the cruft will be at most as big as the prime
	 */
	if (((cruft = talloc_zero_array(session, uint8_t, BN_num_bytes(session->prime))) == NULL) ||
	    ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
		DEBUG2("pwd: unable to allocate space to compute confirm!");
		goto finish;
	}

	/*
	 * commit is H(k | server_element | server_scalar | peer_element |
	 *	       peer_scalar | ciphersuite)
	 */
	H_Init(ctx);

	/*
	 * Zero the memory each time because this is mod prime math and some
	 * value may start with a few zeros and the previous one did not.
	 *
	 * First is k
	 */
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * next is server element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and server scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	BN_bn2bin(session->my_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));

	/*
	 * next is peer element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and peer scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	BN_bn2bin(session->peer_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));

	/*
	 * finally, ciphersuite
	 */
	H_Update(ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));

	H_Final(ctx, out);

	req = 0;
finish:
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);
	HMAC_CTX_free(ctx);

	return req;
}

int compute_peer_confirm (pwd_session_t *session, uint8_t *out, BN_CTX *bnctx)
{
	BIGNUM *x = NULL, *y = NULL;
	HMAC_CTX *ctx = NULL;
	uint8_t *cruft = NULL;
	int offset, req = -1;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
		DEBUG2("pwd: unable to allocate HMAC context!");
		goto finish;
	}

	/*
	 * Each component of the cruft will be at most as big as the prime
	 */
	if (((cruft = talloc_zero_array(session, uint8_t, BN_num_bytes(session->prime))) == NULL) ||
	    ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
		DEBUG2("pwd: unable to allocate space to compute confirm!");
		goto finish;
	}

	/*
	 * commit is H(k | server_element | server_scalar | peer_element |
	 *	       peer_scalar | ciphersuite)
	 */
	H_Init(ctx);

	/*
	 * Zero the memory each time because this is mod prime math and some
	 * value may start with a few zeros and the previous one did not.
	 *
	 * First is k
	 */
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	* then peer element: x, y
	*/
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and peer scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	BN_bn2bin(session->peer_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));

	/*
	 * then server element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and server scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	BN_bn2bin(session->my_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));

	/*
	 * finally, ciphersuite
	 */
	H_Update(ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));

	H_Final(ctx, out);

	req = 0;
finish:
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);
	HMAC_CTX_free(ctx);

	return req;
}

int compute_keys (pwd_session_t *session, uint8_t *peer_confirm, uint8_t *msk, uint8_t *emsk)
{
	HMAC_CTX *ctx = NULL;
	uint8_t mk[SHA256_DIGEST_LENGTH], *cruft = NULL;
	uint8_t session_id[SHA256_DIGEST_LENGTH + 1];
	uint8_t msk_emsk[128];		/* 64 each */
	int offset, ret = -1;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
		DEBUG2("pwd: unable to allocate HMAC context!");
		goto finish;
	}

	if ((cruft = talloc_array(session, uint8_t, BN_num_bytes(session->prime))) == NULL) {
		DEBUG2("pwd: unable to allocate space to compute keys");
		goto finish;
	}

	/*
	 * first compute the session-id = TypeCode | H(ciphersuite | scal_p |
	 *	scal_s)
	 */
	session_id[0] = PW_EAP_PWD;
	H_Init(ctx);
	H_Update(ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	memset(cruft, 0, BN_num_bytes(session->prime));
	BN_bn2bin(session->peer_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	memset(cruft, 0, BN_num_bytes(session->prime));
	BN_bn2bin(session->my_scalar, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->order));
	H_Final(ctx, (uint8_t *)&session_id[1]);

	/* then compute MK = H(k | commit-peer | commit-server) */
	H_Init(ctx);

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	H_Update(ctx, cruft, BN_num_bytes(session->prime));

	H_Update(ctx, peer_confirm, SHA256_DIGEST_LENGTH);

	H_Update(ctx, session->my_confirm, SHA256_DIGEST_LENGTH);

	H_Final(ctx, mk);

	/* stretch the mk with the session-id to get MSK | EMSK */
	if (eap_pwd_kdf(mk, SHA256_DIGEST_LENGTH, (char const *)session_id,
		        SHA256_DIGEST_LENGTH + 1, msk_emsk,
			/* it's bits, ((64 + 64) * 8) */
			1024) != 0) {
		DEBUG("key derivation function failed");
		goto finish;
	}

	memcpy(msk, msk_emsk, 64);
	memcpy(emsk, msk_emsk + 64, 64);

	ret = 0;
finish:
	talloc_free(cruft);
	HMAC_CTX_free(ctx);
	return ret;
}




