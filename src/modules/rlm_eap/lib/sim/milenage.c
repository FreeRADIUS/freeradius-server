/**
 * @file rlm_eap/lib/sim/milenage.c
 * @brief 3GPP AKA - Milenage algorithm (3GPP TS 35.205, .206, .207, .208)
 *
 * This file implements an example authentication algorithm defined for 3GPP
 * AKA. This can be used to implement a simple HLR/AuC into hlr_auc_gw to allow
 * EAP-AKA to be tested properly with real USIM cards.
 *
 * This implementations assumes that the r1..r5 and c1..c5 constants defined in
 * TS 35.206 are used, i.e., r1=64, r2=0, r3=32, r4=64, r5=96, c1=00..00,
 * c2=00..01, c3=00..02, c4=00..04, c5=00..08. The block cipher is assumed to
 * be AES (Rijndael).
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * @copyright 2017 The FreeRADIUS server project
 * @Copyright 2006-2007 <j@w1.fi>
 */
#include <stddef.h>
#include <string.h>

#include <freeradius-devel/tls_log.h>
#include <freeradius-devel/proto.h>
#include <openssl/evp.h>
#include "milenage.h"

static inline int aes_128_encrypt_block(EVP_CIPHER_CTX *evp_ctx,
					uint8_t const key[16], uint8_t const in[16], uint8_t out[16])
{
	size_t len;

	if (unlikely(EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)) {
		tls_strerror_printf(true, "Failed initialising AES-128-ECB context");
		return -1;
	}

	/*
	 *	By default OpenSSL will try and pad out a 16 byte
	 *	plaintext to 32 bytes so that it's detectable that
	 *	there was padding.
	 *
	 *	In this case we know the length of the plaintext
	 *	we're trying to recover, so we explicitly tell
	 *	OpenSSL not to pad here, and not to expected padding
	 *	when decrypting.
	 */
	EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
	if (unlikely(EVP_EncryptUpdate(evp_ctx, out, (int *)&len, in, 16) != 1) ||
	    unlikely(EVP_EncryptFinal_ex(evp_ctx, out + len, (int *)&len) != 1)) {
		tls_strerror_printf(true, "Failed encrypting data");
		return -1;
	}

	return 0;
}

/** milenage_f1 - Milenage f1 and f1* algorithms
 *
 * @param[in] opc	128-bit value derived from OP and K.
 * @param[in] k		128-bit subscriber key.
 * @param[in] rand	128-bit random challenge.
 * @param[in] sqn	48-bit sequence number.
 * @param[in] amf	16-bit authentication management field.
 * @param[out] mac_a	Buffer for MAC-A = 64-bit network authentication code, or NULL
 * @param[out] mac_s	Buffer for MAC-S = 64-bit resync authentication code, or NULL
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int milenage_f1(uint8_t mac_a[8], uint8_t mac_s[8],
		       uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16],
		       uint8_t const sqn[6], uint8_t const amf[2])
{
	uint8_t	tmp1[16], tmp2[16], tmp3[16];
	int	i;
	EVP_CIPHER_CTX	*evp_ctx;

	/* tmp1 = TEMP = E_K(RAND XOR OP_C) */
	for (i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf(true, "Failed allocating EVP context");
		return -1;
	}

 	if (aes_128_encrypt_block(evp_ctx, k, tmp1, tmp1) < 0) {
 	error:
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
 	}

	/* tmp2 = IN1 = SQN || AMF || SQN || AMF */
	memcpy(tmp2, sqn, 6);
	memcpy(tmp2 + 6, amf, 2);
	memcpy(tmp2 + 8, tmp2, 8);

	/* OUT1 = E_K(TEMP XOR rot(IN1 XOR OP_C, r1) XOR c1) XOR OP_C */

	/*
	 *  rotate (tmp2 XOR OP_C) by r1 (= 0x40 = 8 bytes)
	 */
	for (i = 0; i < 16; i++) tmp3[(i + 8) % 16] = tmp2[i] ^ opc[i];

	/*
	 *  XOR with TEMP = E_K(RAND XOR OP_C)
	 */
	for (i = 0; i < 16; i++) tmp3[i] ^= tmp1[i];
	/* XOR with c1 (= ..00, i.e., NOP) */

	/*
	 *	f1 || f1* = E_K(tmp3) XOR OP_c
	 */
 	if (aes_128_encrypt_block(evp_ctx, NULL, tmp3, tmp1) < 0) goto error; /* Reuses existing key */

	for (i = 0; i < 16; i++) tmp1[i] ^= opc[i];

	if (mac_a) memcpy(mac_a, tmp1, 8);	/* f1 */
	if (mac_s) memcpy(mac_s, tmp1 + 8, 8);	/* f1* */

	EVP_CIPHER_CTX_free(evp_ctx);

	return 0;
}

/** milenage_f2345 - Milenage f2, f3, f4, f5, f5* algorithms
 *
 * @param[out] res	Buffer for RES = 64-bit signed response (f2), or NULL
 * @param[out] ck	Buffer for CK = 128-bit confidentiality key (f3), or NULL
 * @param[out] ik	Buffer for IK = 128-bit integrity key (f4), or NULL
 * @param[out] ak	Buffer for AK = 48-bit anonymity key (f5), or NULL
 * @param[out] akstar	Buffer for AK = 48-bit anonymity key (f5*), or NULL
 * @param[in] opc	128-bit value derived from OP and K.
 * @param[in] k		128-bit subscriber key
 * @param[in] rand	128-bit random challenge
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int milenage_f2345(uint8_t res[8], uint8_t ck[16], uint8_t ik[16], uint8_t ak[6], uint8_t akstar[6],
			  uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16])
{
	uint8_t		tmp1[16], tmp2[16], tmp3[16];
	int		i;
	EVP_CIPHER_CTX		*evp_ctx;

	/* tmp2 = TEMP = E_K(RAND XOR OP_C) */
	for (i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf(true, "Failed allocating EVP context");
		return -1;
	}

	if (aes_128_encrypt_block(evp_ctx, k, tmp1, tmp2) < 0) {
	error:
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
	}

	/* OUT2 = E_K(rot(TEMP XOR OP_C, r2) XOR c2) XOR OP_C */
	/* OUT3 = E_K(rot(TEMP XOR OP_C, r3) XOR c3) XOR OP_C */
	/* OUT4 = E_K(rot(TEMP XOR OP_C, r4) XOR c4) XOR OP_C */
	/* OUT5 = E_K(rot(TEMP XOR OP_C, r5) XOR c5) XOR OP_C */

	/* f2 and f5 */
	/* rotate by r2 (= 0, i.e., NOP) */
	for (i = 0; i < 16; i++) tmp1[i] = tmp2[i] ^ opc[i];
	tmp1[15] ^= 1; /* XOR c2 (= ..01) */
	/* f5 || f2 = E_K(tmp1) XOR OP_c */

	if (aes_128_encrypt_block(evp_ctx, NULL, tmp1, tmp3) < 0) goto error;

	for (i = 0; i < 16; i++) tmp3[i] ^= opc[i];
	if (res) memcpy(res, tmp3 + 8, 8); /* f2 */
	if (ak) memcpy(ak, tmp3, 6); /* f5 */

	/* f3 */
	if (ck) {
		/* rotate by r3 = 0x20 = 4 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 12) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 2; /* XOR c3 (= ..02) */

		if (aes_128_encrypt_block(evp_ctx, NULL, tmp1, ck) < 0) goto error;

		for (i = 0; i < 16; i++) ck[i] ^= opc[i];
	}

	/* f4 */
	if (ik) {
		/* rotate by r4 = 0x40 = 8 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 8) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 4; /* XOR c4 (= ..04) */

		if (aes_128_encrypt_block(evp_ctx, NULL, tmp1, ik) < 0) goto error;

		for (i = 0; i < 16; i++) ik[i] ^= opc[i];
	}

	/* f5* */
	if (akstar) {
		/* rotate by r5 = 0x60 = 12 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 4) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 8; /* XOR c5 (= ..08) */

		if (aes_128_encrypt_block(evp_ctx, k, tmp1, tmp1) < 0) goto error;

		for (i = 0; i < 6; i++) akstar[i] = tmp1[i] ^ opc[i];
	}
	EVP_CIPHER_CTX_free(evp_ctx);

	return 0;
}

/** milenage_generate - Generate AKA AUTN, IK, CK, RES
 *
 * @param[out] autn	Buffer for AUTN = 128-bit authentication token.
 * @param[out] ik	Buffer for IK = 128-bit integrity key (f4), or NULL.
 * @param[out] ck	Buffer for CK = 128-bit confidentiality key (f3), or NULL.
 * @param[out] res	Buffer for RES = 64-bit signed response (f2), or NULL.
 * @param[in] res_len	Max length for res; set to used length or 0 on failure.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] amf	16-bit authentication management field.
 * @param[in] k		128-bit subscriber key.
 * @param[in] sqn	48-bit sequence number.
 * @param[in] rand	128-bit random challenge.
 */
int milenage_umts_generate(uint8_t autn[16], uint8_t ik[16], uint8_t ck[16], uint8_t *res, size_t *res_len,
			   uint8_t const opc[16], uint8_t const amf[2], uint8_t const k[16],
			   uint8_t const sqn[6], uint8_t const rand[16])
{
	int	i;
	uint8_t	mac_a[8], ak[6];

	*res_len = 0;

	if (*res_len < 8) return - 1;
	if ((milenage_f1(mac_a, NULL, opc, k, rand, sqn, amf) < 0) ||
	    (milenage_f2345(res, ck, ik, ak, NULL, opc, k, rand) < 0)) return -1;
	*res_len = 8;

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (i = 0; i < 6; i++) autn[i] = sqn[i] ^ ak[i];
	memcpy(autn + 6, amf, 2);
	memcpy(autn + 8, mac_a, 8);

	return 0;
}

/** milenage_auts - Milenage AUTS validation
 *
 * @param[out] sqn	Buffer for SQN = 48-bit sequence number.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] k		128-bit subscriber key.
 * @param[in] rand	128-bit random challenge.
 * @param[in] auts	112-bit authentication token from client.
 * @return
 *	- 0 on success with sqn filled.
 *	- -1 on failure.
 */
int milenage_auts(uint8_t sqn[6],
		  uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16], uint8_t const auts[14])
{
	uint8_t amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
	uint8_t ak[6], mac_s[8];
	int i;

	if (milenage_f2345(NULL, NULL, NULL, NULL, ak, opc, k, rand)) return -1;
	for (i = 0; i < 6; i++) sqn[i] = auts[i] ^ ak[i];

	if (milenage_f1(NULL, mac_s, opc, k, rand, sqn, amf) || CRYPTO_memcmp(mac_s, auts + 6, 8) != 0) return -1;
	return 0;
}

/** gsm_milenage - Generate GSM-Milenage (3GPP TS 55.205) authentication triplet
 *
 * @param[out] sres	Buffer for SRES = 32-bit SRES.
 * @param[out] kc	64-bit Kc.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] k		128-bit subscriber key.
 * @param[in] rand	128-bit random challenge.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int milenage_gsm_generate(uint8_t sres[4], uint8_t kc[8],
			  uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16])
{
	uint8_t res[8], ck[16], ik[16];
	int i;

	if (milenage_f2345(res, ck, ik, NULL, NULL, opc, k, rand)) return -1;

	for (i = 0; i < 8; i++) kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];

#ifdef GSM_MILENAGE_ALT_SRES
	memcpy(sres, res, 4);
#else /* GSM_MILENAGE_ALT_SRES */
	for (i = 0; i < 4; i++) sres[i] = res[i] ^ res[i + 4];
#endif /* GSM_MILENAGE_ALT_SRES */

	return 0;
}

/** milenage check
 *
 * @param[out] ik	Buffer for IK = 128-bit integrity key (f4), or NULL.
 * @param[out] ck	Buffer for CK = 128-bit confidentiality key (f3), or NULL.
 * @param[out] res	Buffer for RES = 64-bit signed response (f2), or NULL.
 * @param[in] res_len	Variable that will be set to RES length.
 * @param[in] auts	112-bit buffer for AUTS.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] k		128-bit subscriber key.
 * @param[in] sqn	48-bit sequence number.
 * @param[in] rand	128-bit random challenge.
 * @param[in] autn	128-bit authentication token.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 *	- -2 on synchronization failure
 */
int milenage_check(uint8_t ik[16], uint8_t ck[16], uint8_t *res, size_t *res_len, uint8_t *auts,
		   uint8_t const opc[16], uint8_t const k[16], uint8_t const sqn[6],
		   uint8_t const rand[16], uint8_t const autn[16])
{
	int i;
	uint8_t mac_a[8], ak[6], rx_sqn[6];
	const uint8_t *amf;

	FR_PROTO_HEX_DUMP("AUTN", autn, 16);
	FR_PROTO_HEX_DUMP("RAND", rand, 16);

	if (milenage_f2345(res, ck, ik, ak, NULL, opc, k, rand))
		return -1;

	*res_len = 8;
	FR_PROTO_HEX_DUMP("RES", res, *res_len);
	FR_PROTO_HEX_DUMP("CK", ck, 16);
	FR_PROTO_HEX_DUMP("IK", ik, 16);
	FR_PROTO_HEX_DUMP("AK", ak, 6);

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (i = 0; i < 6; i++)
		rx_sqn[i] = autn[i] ^ ak[i];
	FR_PROTO_HEX_DUMP("SQN", rx_sqn, 6);

	if (memcmp(rx_sqn, sqn, 6) <= 0) {
		uint8_t auts_amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */

		if (milenage_f2345(NULL, NULL, NULL, NULL, ak, opc, k, rand)) return -1;

		FR_PROTO_HEX_DUMP("AK*", ak, 6);
		for (i = 0; i < 6; i++) auts[i] = sqn[i] ^ ak[i];

		if (milenage_f1(NULL, auts + 6, opc, k, rand, sqn, auts_amf) < 0) return -1;
		FR_PROTO_HEX_DUMP("AUTS", auts, 14);
		return -2;
	}

	amf = autn + 6;
	FR_PROTO_HEX_DUMP("AMF", amf, 2);
	if (milenage_f1(mac_a, NULL, opc, k, rand, rx_sqn, amf) < 0) return -1;

	FR_PROTO_HEX_DUMP("MAC_A", mac_a, 8);

	if (CRYPTO_memcmp(mac_a, autn + 8, 8) != 0) {
		fr_strerror_printf("MAC mismatch");
		FR_PROTO_HEX_DUMP("Received MAC_A", autn + 8, 8);
		return -1;
	}

	return 0;
}
