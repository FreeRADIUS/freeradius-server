/**
 *  copyright holder grants permission for redistribution and use in source
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
 *
 * @copyright (c) Dan Harkins, 2012
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_pwd.h"
#include "const_time.h"

static uint8_t allzero[SHA256_DIGEST_LENGTH] = { 0x00 };

/* The random function H(x) = HMAC-SHA256(0^32, x) */
static void pwd_hmac_final(HMAC_CTX *hmac_ctx, uint8_t *digest)
{
	unsigned int mdlen = SHA256_DIGEST_LENGTH;
	HMAC_Final(hmac_ctx, digest, &mdlen);
//	HMAC_CTX_reset(hmac_ctx);
}

/* a counter-based KDF based on NIST SP800-108 */
static void eap_pwd_kdf(uint8_t *key, int keylen, char const *label,
			int label_len, uint8_t *result, int result_bit_len)
{
	HMAC_CTX	*hmac_ctx;
	uint8_t		digest[SHA256_DIGEST_LENGTH];
	uint16_t	i, ctr, L;
	int		result_byte_len, len = 0;
	unsigned int	mdlen = SHA256_DIGEST_LENGTH;
	uint8_t		mask = 0xff;

	MEM(hmac_ctx = HMAC_CTX_new());
	result_byte_len = (result_bit_len + 7) / 8;

	ctr = 0;
	L = htons(result_bit_len);
	while (len < result_byte_len) {
		ctr++; i = htons(ctr);

		HMAC_Init_ex(hmac_ctx, key, keylen, EVP_sha256(), NULL);
		if (ctr > 1) HMAC_Update(hmac_ctx, digest, mdlen);
		HMAC_Update(hmac_ctx, (uint8_t *) &i, sizeof(uint16_t));
		HMAC_Update(hmac_ctx, (uint8_t const *)label, label_len);
		HMAC_Update(hmac_ctx, (uint8_t *) &L, sizeof(uint16_t));
		HMAC_Final(hmac_ctx, digest, &mdlen);
		if ((len + (int) mdlen) > result_byte_len) {
			memcpy(result + len, digest, result_byte_len - len);
		} else {
			memcpy(result + len, digest, mdlen);
		}
		len += mdlen;
//		HMAC_CTX_reset(hmac_ctx);
	}

	/* since we're expanding to a bit length, mask off the excess */
	if (result_bit_len % 8) {
		mask <<= (8 - (result_bit_len % 8));
		result[result_byte_len - 1] &= mask;
	}

	HMAC_CTX_free(hmac_ctx);
}

static BIGNUM *consttime_BN (void)
{
	BIGNUM *bn;

	bn = BN_new();
	if (bn) BN_set_flags(bn, BN_FLG_CONSTTIME);
	return bn;
}

/*
 * compute the legendre symbol in constant time
 */
static int legendre(BIGNUM *a, BIGNUM *p, BN_CTX *bnctx)
{
	int		symbol;
	unsigned int	mask;
	BIGNUM		*res, *pm1over2;

	pm1over2 = consttime_BN();
	res = consttime_BN();

	if (!BN_sub(pm1over2, p, BN_value_one()) ||
	    !BN_rshift1(pm1over2, pm1over2) ||
	    !BN_mod_exp_mont_consttime(res, a, pm1over2, p, bnctx, NULL)) {
		BN_free(pm1over2);
		BN_free(res);
		return -2;
	}

	symbol = -1;
	mask = const_time_eq(BN_is_word(res, 1), 1);
	symbol = const_time_select_int(mask, 1, symbol);
	mask = const_time_eq(BN_is_zero(res), 1);
	symbol = const_time_select_int(mask, -1, symbol);

	BN_free(pm1over2);
	BN_free(res);

	return symbol;
}

static void do_equation(EC_GROUP *group, BIGNUM *y2, BIGNUM *x, BN_CTX *bnctx)
{
	BIGNUM *p, *a, *b, *tmp1, *pm1;

	tmp1 = BN_new();
	pm1 = BN_new();
	p = BN_new();
	a = BN_new();
	b = BN_new();
	EC_GROUP_get_curve_GFp(group, p, a, b, bnctx);

	BN_sub(pm1, p, BN_value_one());

	/*
	 * y2 = x^3 + ax + b
	 */
	BN_mod_sqr(tmp1, x, p, bnctx);
	BN_mod_mul(y2, tmp1, x, p, bnctx);
	BN_mod_mul(tmp1, a, x, p, bnctx);
	BN_mod_add_quick(y2, y2, tmp1, p);
	BN_mod_add_quick(y2, y2, b, p);

	BN_free(tmp1);
	BN_free(pm1);
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return;
}

static int is_quadratic_residue(BIGNUM *val, BIGNUM *p, BIGNUM *qr, BIGNUM *qnr, BN_CTX *bnctx)
{
	int offset, check, ret = 0;
	BIGNUM *r = NULL, *pm1 = NULL, *res = NULL, *qr_or_qnr = NULL;
	unsigned int mask;
	unsigned char *qr_bin = NULL, *qnr_bin = NULL, *qr_or_qnr_bin = NULL;

	if (((r = consttime_BN()) == NULL) ||
	    ((res = consttime_BN()) == NULL) ||
	    ((qr_or_qnr = consttime_BN()) == NULL) ||
	    ((pm1 = consttime_BN()) == NULL)) {
		ret = -2;
		goto fail;
	}

	if (((qr_bin = (unsigned char *)malloc(BN_num_bytes(p))) == NULL) ||
	    ((qnr_bin = (unsigned char *)malloc(BN_num_bytes(p))) == NULL) ||
	    ((qr_or_qnr_bin = (unsigned char *)malloc(BN_num_bytes(p))) == NULL)) {
		ret = -2;
		goto fail;
	}

	/*
	 * we select binary in constant time so make them binary
	 */
	memset(qr_bin, 0, BN_num_bytes(p));
	memset(qnr_bin, 0, BN_num_bytes(p));
	memset(qr_or_qnr_bin, 0, BN_num_bytes(p));

	offset = BN_num_bytes(p) - BN_num_bytes(qr);
	BN_bn2bin(qr, qr_bin + offset);

	offset = BN_num_bytes(p) - BN_num_bytes(qnr);
	BN_bn2bin(qnr, qnr_bin + offset);

	/*
	 * r = (random() mod p-1) + 1
	 */
	BN_sub(pm1, p, BN_value_one());
	BN_rand_range(r, pm1);
	BN_add(r, r, BN_value_one());

	BN_copy(res, val);

	/*
	 * res = val * r * r which ensures res != val but has same quadratic residocity
	 */
	BN_mod_mul(res, res, r, p, bnctx);
	BN_mod_mul(res, res, r, p, bnctx);

	/*
	 * if r is even (mask is -1) then multiply by qnr and our check is qnr
	 * otherwise multiply by qr and our check is qr
	 */
	mask = const_time_is_zero(BN_is_odd(r));
	const_time_select_bin(mask, qnr_bin, qr_bin, BN_num_bytes(p), qr_or_qnr_bin);
	BN_bin2bn(qr_or_qnr_bin, BN_num_bytes(p), qr_or_qnr);
	BN_mod_mul(res, res, qr_or_qnr, p, bnctx);
	check = const_time_select_int(mask, -1, 1);

	if ((ret = legendre(res, p, bnctx)) == -2) {
		ret = -1;	/* just say no it's not */
		goto fail;
	}
	mask = const_time_eq(ret, check);
	ret = const_time_select_int(mask, 1, 0);

fail:
	if (qr_bin != NULL) free(qr_bin);
	if (qnr_bin != NULL) free(qnr_bin);
	if (qr_or_qnr_bin != NULL) free(qr_or_qnr_bin);
	BN_free(r);
	BN_free(res);
	BN_free(qr_or_qnr);
	BN_free(pm1);

	return ret;
}

int compute_password_element (REQUEST *request, pwd_session_t *session, uint16_t grp_num,
			      char const *password, int password_len,
			      char const *id_server, int id_server_len,
			      char const *id_peer, int id_peer_len,
			      uint32_t *token)
{
	BIGNUM *x_candidate = NULL, *rnd = NULL, *y_sqrd = NULL, *qr = NULL, *qnr = NULL;
	HMAC_CTX *ctx = NULL;
	uint8_t pwe_digest[SHA256_DIGEST_LENGTH], *prfbuf = NULL, *xbuf = NULL, *pm1buf = NULL, ctr;
	int nid, is_odd, primebitlen, primebytelen, ret = 0, found = 0, mask;
	int save, i, rbits, qr_or_qnr, save_is_odd = 0, cmp;
	unsigned int skip;

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

	if (((rnd = consttime_BN()) == NULL) ||
	    ((session->pwe = EC_POINT_new(session->group)) == NULL) ||
	    ((session->order = consttime_BN()) == NULL) ||
	    ((session->prime = consttime_BN()) == NULL) ||
	    ((qr = consttime_BN()) == NULL) ||
	    ((qnr = consttime_BN()) == NULL) ||
	    ((x_candidate = consttime_BN()) == NULL) ||
	    ((y_sqrd = consttime_BN()) == NULL)) {
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

	primebitlen = BN_num_bits(session->prime);
	primebytelen = BN_num_bytes(session->prime);
	if ((prfbuf = talloc_zero_array(session, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for prf buffer");
		goto fail;
	}
	if ((xbuf = talloc_zero_array(request, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for x buffer");
		goto fail;
	}
	if ((pm1buf = talloc_zero_array(request, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for pm1 buffer");
		goto fail;
	}

	/*
	* derive random quadradic residue and quadratic non-residue
	*/
	do {
		BN_rand_range(qr, session->prime);
	} while (legendre(qr, session->prime, session->bnctx) != 1);

	do {
		BN_rand_range(qnr, session->prime);
	} while (legendre(qnr, session->prime, session->bnctx) != -1);

	if (!BN_sub(rnd, session->prime, BN_value_one())) {
		goto fail;
	}
	BN_bn2bin(rnd, pm1buf);

	save_is_odd = 0;
	found = 0;
	memset(xbuf, 0, primebytelen);
	ctr = 0;
	while (ctr < 40) {
		ctr++;

		/*
		 * compute counter-mode password value and stretch to prime
		 *	pwd-seed = H(token | peer-id | server-id | password |
		 *		     counter)
		 */
		HMAC_Init_ex(ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(),NULL);
		HMAC_Update(ctx, (uint8_t *)token, sizeof(*token));
		HMAC_Update(ctx, (uint8_t const *)id_peer, id_peer_len);
		HMAC_Update(ctx, (uint8_t const *)id_server, id_server_len);
		HMAC_Update(ctx, (uint8_t const *)password, password_len);
		HMAC_Update(ctx, (uint8_t *)&ctr, sizeof(ctr));
		pwd_hmac_final(ctx, pwe_digest);

		BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
		eap_pwd_kdf(pwe_digest, SHA256_DIGEST_LENGTH, "EAP-pwd Hunting And Pecking",
			    strlen("EAP-pwd Hunting And Pecking"), prfbuf, primebitlen);

		/*
		 * eap_pwd_kdf() returns a string of bits 0..primebitlen but
		 * BN_bin2bn will treat that string of bits as a big endian
		 * number. If the primebitlen is not an even multiple of 8
		 * then excessive bits-- those _after_ primebitlen-- so now
		 * we have to shift right the amount we masked off.
		 */
		if (primebitlen % 8) {
			rbits = 8 - (primebitlen % 8);
			for (i = primebytelen - 1; i > 0; i--) {
				prfbuf[i] = (prfbuf[i - 1] << (8 - rbits)) | (prfbuf[i] >> rbits);
			}
			prfbuf[0] >>= rbits;
		}
		BN_bin2bn(prfbuf, primebytelen, x_candidate);

		/*
		* it would've been better if the spec reduced the candidate
		* modulo the prime but it didn't. So if the candidate >= prime
		* we need to skip it but still run through the operations below
		*/
		cmp = const_time_memcmp(pm1buf, prfbuf, primebytelen);
		skip = const_time_fill_msb((unsigned int)cmp);

		/*
		* need to unambiguously identify the solution, if there is
		* one..
		*/
		is_odd = BN_is_odd(rnd) ? 1 : 0;

		/*
		* check whether x^3 + a*x + b is a quadratic residue
		*
		* save the first quadratic residue we find in the loop but do
		* it in constant time.
		*/
		do_equation(session->group, y_sqrd, x_candidate, session->bnctx);
		qr_or_qnr = is_quadratic_residue(y_sqrd, session->prime, qr, qnr, session->bnctx);

		/*
		* if the candidate >= prime then we want to skip it
		*/
		qr_or_qnr = const_time_select(skip, 0, qr_or_qnr);

		/*
		* if we haven't found PWE yet (found = 0) then mask will be true,
		* if we have found PWE then mask will be false
		*/
		mask = const_time_select(found, 0, -1);

		/*
		* save will be 1 if we want to save this value-- i.e. we haven't
		* found PWE yet and this is a quadratic residue-- and 0 otherwise
		*/
		save = const_time_select(mask, qr_or_qnr, 0);

		/*
		* mask will be true (-1) if we want to save this and false (0)
		* otherwise
		*/
		mask = const_time_eq(save, 1);

		const_time_select_bin(mask, prfbuf, xbuf, primebytelen, xbuf);
		save_is_odd = const_time_select(mask, is_odd, save_is_odd);
		found = const_time_select(mask, -1, found);
	}

	/*
	* now we can savely construct PWE
	*/
	BN_bin2bn(xbuf, primebytelen, x_candidate);
	if (!EC_POINT_set_compressed_coordinates_GFp(session->group, session->pwe,
						     x_candidate, save_is_odd, NULL)) {
		goto fail;
	}

	session->group_num = grp_num;
	if (0) {
		fail:		/* DON'T free session, it's in handler->opaque */
		ret = -1;
	}

	/* cleanliness and order.... */
	BN_clear_free(x_candidate);
	BN_clear_free(y_sqrd);
	BN_clear_free(qr);
	BN_clear_free(qnr);
	BN_clear_free(rnd);

	if (prfbuf) talloc_free(prfbuf);
	if (xbuf) talloc_free(xbuf);
	if (pm1buf) talloc_free(pm1buf);

	HMAC_CTX_free(ctx);

	return ret;
}

int compute_scalar_element(REQUEST *request, pwd_session_t *session, BN_CTX *bn_ctx)
{
	BIGNUM *mask = NULL;
	int ret = -1;

	MEM(session->private_value = BN_new());
	MEM(session->my_element = EC_POINT_new(session->group));
	MEM(session->my_scalar = BN_new());

	MEM(mask = BN_new());

	if (BN_rand_range(session->private_value, session->order) != 1) {
		REDEBUG("Unable to get randomness for private_value");
		goto error;
	}
	if (BN_rand_range(mask, session->order) != 1) {
		REDEBUG("Unable to get randomness for mask");
		goto error;
	}
	BN_add(session->my_scalar, session->private_value, mask);
	BN_mod(session->my_scalar, session->my_scalar, session->order, bn_ctx);

	if (!EC_POINT_mul(session->group, session->my_element, NULL, session->pwe, mask, bn_ctx)) {
		REDEBUG("Server element allocation failed");
		goto error;
	}

	if (!EC_POINT_invert(session->group, session->my_element, bn_ctx)) {
		REDEBUG("Server element inversion failed");
		goto error;
	}

	ret = 0;

error:
	BN_clear_free(mask);

	return ret;
}

int process_peer_commit(REQUEST *request, pwd_session_t *session, uint8_t *in, size_t in_len, BN_CTX *bn_ctx)
{
	uint8_t		*ptr;
	size_t		data_len;
	BIGNUM		*x = NULL, *y = NULL, *cofactor = NULL;
	EC_POINT	*K = NULL, *point = NULL;
	int		ret = 1;

	MEM(session->peer_scalar = BN_new());
	MEM(session->k = BN_new());
	MEM(session->peer_element = EC_POINT_new(session->group));
	MEM(point = EC_POINT_new(session->group));
	MEM(K = EC_POINT_new(session->group));

	MEM(cofactor = BN_new());
	MEM(x = BN_new());
	MEM(y = BN_new());

	if (!EC_GROUP_get_cofactor(session->group, cofactor, NULL)) {
		REDEBUG("Unable to get group co-factor");
		goto finish;
	}

	/* element, x then y, followed by scalar */
	ptr = (uint8_t *)in;
	data_len = BN_num_bytes(session->prime);

	/*
	 *	Did the peer send enough data?
	 */
	if (in_len < (2 * data_len + BN_num_bytes(session->order))) {
		REDEBUG("Invalid commit packet");
		goto finish;
	}

	BN_bin2bn(ptr, data_len, x);
	ptr += data_len;
	BN_bin2bn(ptr, data_len, y);
	ptr += data_len;

	data_len = BN_num_bytes(session->order);
	BN_bin2bn(ptr, data_len, session->peer_scalar);

	/* validate received scalar */
	if (BN_is_zero(session->peer_scalar) ||
	    BN_is_one(session->peer_scalar) ||
	    BN_cmp(session->peer_scalar, session->order) >= 0) {
		REDEBUG("Peer's scalar is not within the allowed range");
		goto finish;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(session->group, session->peer_element, x, y, bn_ctx)) {
		REDEBUG("Unable to get coordinates of peer's element");
		goto finish;
	}

	/* validate received element */
	if (!EC_POINT_is_on_curve(session->group, session->peer_element, bn_ctx) ||
	    EC_POINT_is_at_infinity(session->group, session->peer_element)) {
		REDEBUG("Peer's element is not a point on the elliptic curve");
		goto finish;
	}

	/* check to ensure peer's element is not in a small sub-group */
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(session->group, point, NULL, session->peer_element, cofactor, NULL)) {
			REDEBUG("Unable to multiply element by co-factor");
			goto finish;
		}

		if (EC_POINT_is_at_infinity(session->group, point)) {
			REDEBUG("Peer's element is in small sub-group");
			goto finish;
		}
	}

	/* detect reflection attacks */
	if (BN_cmp(session->peer_scalar, session->my_scalar) == 0 ||
	    EC_POINT_cmp(session->group, session->peer_element, session->my_element, bn_ctx) == 0) {
		REDEBUG("Reflection attack detected");
		goto finish;
	}

	/* compute the shared key, k */
	if ((!EC_POINT_mul(session->group, K, NULL, session->pwe, session->peer_scalar, bn_ctx)) ||
	    (!EC_POINT_add(session->group, K, K, session->peer_element, bn_ctx)) ||
	    (!EC_POINT_mul(session->group, K, NULL, K, session->private_value, bn_ctx))) {
		REDEBUG("Unable to compute shared key, k");
		goto finish;
	}

	/* ensure that the shared key isn't in a small sub-group */
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(session->group, K, NULL, K, cofactor, NULL)) {
			REDEBUG("Unable to multiply k by co-factor");
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
		REDEBUG("K is point-at-infinity");
		goto finish;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(session->group, K, session->k, NULL, bn_ctx)) {
		REDEBUG("Unable to get shared secret from K");
		goto finish;
	}
	ret = 0;

finish:
	EC_POINT_clear_free(K);
	EC_POINT_clear_free(point);
	BN_clear_free(cofactor);
	BN_clear_free(x);
	BN_clear_free(y);

	return ret;
}

int compute_server_confirm(REQUEST *request, pwd_session_t *session, uint8_t *out, BN_CTX *bn_ctx)
{
	BIGNUM		*x = NULL, *y = NULL;
	HMAC_CTX	*hmac_ctx = NULL;
	uint8_t		*cruft = NULL;
	int		offset, req = -1;

	/*
	 * Each component of the cruft will be at most as big as the prime
	 */
	MEM(cruft = talloc_zero_array(session, uint8_t, BN_num_bytes(session->prime)));
	MEM(x = BN_new());
	MEM(y = BN_new());

	/*
	 * commit is H(k | server_element | server_scalar | peer_element |
	 *	       peer_scalar | ciphersuite)
	 */
	MEM(hmac_ctx = HMAC_CTX_new());
	HMAC_Init_ex(hmac_ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);

	/*
	 * Zero the memory each time because this is mod prime math and some
	 * value may start with a few zeros and the previous one did not.
	 *
	 * First is k
	 */
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * next is server element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y, bn_ctx)) {
		REDEBUG("Unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and server scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	BN_bn2bin(session->my_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));

	/*
	 * next is peer element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->peer_element, x, y, bn_ctx)) {
		REDEBUG("Unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and peer scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	BN_bn2bin(session->peer_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));

	/*
	 * finally, ciphersuite
	 */
	HMAC_Update(hmac_ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));

	pwd_hmac_final(hmac_ctx, out);

	req = 0;

finish:
	HMAC_CTX_free(hmac_ctx);
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);

	return req;
}

int compute_peer_confirm(REQUEST *request, pwd_session_t *session, uint8_t *out, BN_CTX *bn_ctx)
{
	BIGNUM		*x = NULL, *y = NULL;
	HMAC_CTX	*hmac_ctx = NULL;
	uint8_t		*cruft = NULL;
	int		offset, req = -1;

	/*
	 * Each component of the cruft will be at most as big as the prime
	 */
	MEM(cruft = talloc_zero_array(session, uint8_t, BN_num_bytes(session->prime)));
	MEM(x = BN_new());
	MEM(y = BN_new());

	/*
	 * commit is H(k | server_element | server_scalar | peer_element |
	 *	       peer_scalar | ciphersuite)
	 */
	MEM(hmac_ctx = HMAC_CTX_new());
	HMAC_Init_ex(hmac_ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);

	/*
	 * Zero the memory each time because this is mod prime math and some
	 * value may start with a few zeros and the previous one did not.
	 *
	 * First is k
	 */
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	* then peer element: x, y
	*/
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->peer_element, x, y, bn_ctx)) {
		REDEBUG("Unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and peer scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	BN_bn2bin(session->peer_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));

	/*
	 * then server element: x, y
	 */
	if (!EC_POINT_get_affine_coordinates_GFp(session->group, session->my_element, x, y, bn_ctx)) {
		REDEBUG("Unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	/*
	 * and server scalar
	 */
	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	BN_bn2bin(session->my_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));

	/*
	 * finally, ciphersuite
	 */
	HMAC_Update(hmac_ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));

	pwd_hmac_final(hmac_ctx, out);

	req = 0;
finish:
	HMAC_CTX_free(hmac_ctx);
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);

	return req;
}

int compute_keys(UNUSED REQUEST *request, pwd_session_t *session, uint8_t *peer_confirm, uint8_t *msk, uint8_t *emsk)
{
	HMAC_CTX	*hmac_ctx;
	uint8_t		mk[SHA256_DIGEST_LENGTH], *cruft;
	uint8_t		session_id[SHA256_DIGEST_LENGTH + 1];
	uint8_t		msk_emsk[128];		/* 64 each */
	int	 	offset;

	MEM(cruft = talloc_array(session, uint8_t, BN_num_bytes(session->prime)));
	MEM(hmac_ctx = HMAC_CTX_new());

	/*
	 * first compute the session-id = TypeCode | H(ciphersuite | scal_p |
	 *	scal_s)
	 */
	session_id[0] = PW_EAP_PWD;
	HMAC_Init_ex(hmac_ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);
	HMAC_Update(hmac_ctx, (uint8_t *)&session->ciphersuite, sizeof(session->ciphersuite));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->peer_scalar);
	memset(cruft, 0, BN_num_bytes(session->prime));
	BN_bn2bin(session->peer_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));
	offset = BN_num_bytes(session->order) - BN_num_bytes(session->my_scalar);
	memset(cruft, 0, BN_num_bytes(session->prime));
	BN_bn2bin(session->my_scalar, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->order));
	pwd_hmac_final(hmac_ctx, (uint8_t *)&session_id[1]);

	/* then compute MK = H(k | commit-peer | commit-server) */
	HMAC_Init_ex(hmac_ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);

	memset(cruft, 0, BN_num_bytes(session->prime));
	offset = BN_num_bytes(session->prime) - BN_num_bytes(session->k);
	BN_bn2bin(session->k, cruft + offset);
	HMAC_Update(hmac_ctx, cruft, BN_num_bytes(session->prime));

	HMAC_Update(hmac_ctx, peer_confirm, SHA256_DIGEST_LENGTH);

	HMAC_Update(hmac_ctx, session->my_confirm, SHA256_DIGEST_LENGTH);

	pwd_hmac_final(hmac_ctx, mk);

	/* stretch the mk with the session-id to get MSK | EMSK */
	eap_pwd_kdf(mk, SHA256_DIGEST_LENGTH, (char const *)session_id,
		    SHA256_DIGEST_LENGTH + 1, msk_emsk, 1024);  /* it's bits, ((64 + 64) * 8) */

	memcpy(msk, msk_emsk, 64);
	memcpy(emsk, msk_emsk + 64, 64);

	HMAC_CTX_free(hmac_ctx);
	talloc_free(cruft);
	return 0;
}
