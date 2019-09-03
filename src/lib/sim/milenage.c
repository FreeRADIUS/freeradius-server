/**
 * @file src/lib/aka-sim/milenage.c
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
 * @copyright 2006-2007 (j@w1.fi)
 */
#include <stddef.h>
#include <string.h>

#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/util/proto.h>
#include <openssl/evp.h>
#include "common.h"
#include "milenage.h"

#define MILENAGE_MAC_A_SIZE	8
#define MILENAGE_MAC_S_SIZE	8

static inline int aes_128_encrypt_block(EVP_CIPHER_CTX *evp_ctx,
					uint8_t const key[16], uint8_t const in[16], uint8_t out[16])
{
	size_t len;

	if (unlikely(EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)) {
		tls_strerror_printf("Failed initialising AES-128-ECB context");
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
		tls_strerror_printf("Failed encrypting data");
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
static int milenage_f1(uint8_t mac_a[MILENAGE_MAC_A_SIZE],
		       uint8_t mac_s[MILENAGE_MAC_S_SIZE],
		       uint8_t const opc[MILENAGE_OPC_SIZE],
		       uint8_t const k[MILENAGE_KI_SIZE],
		       uint8_t const rand[MILENAGE_RAND_SIZE],
		       uint8_t const sqn[MILENAGE_SQN_SIZE],
		       uint8_t const amf[MILENAGE_AMF_SIZE])
{
	uint8_t		tmp1[16], tmp2[16], tmp3[16];
	int		i;
	EVP_CIPHER_CTX	*evp_ctx;

	/* tmp1 = TEMP = E_K(RAND XOR OP_C) */
	for (i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("Failed allocating EVP context");
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
 	if (aes_128_encrypt_block(evp_ctx, k, tmp3, tmp1) < 0) goto error; /* Reuses existing key */

	for (i = 0; i < 16; i++) tmp1[i] ^= opc[i];

	if (mac_a) memcpy(mac_a, tmp1, 8);	/* f1 */
	if (mac_s) memcpy(mac_s, tmp1 + 8, 8);	/* f1* */

	EVP_CIPHER_CTX_free(evp_ctx);

	return 0;
}

/** milenage_f2345 - Milenage f2, f3, f4, f5, f5* algorithms
 *
 * @param[out] res		Buffer for RES = 64-bit signed response (f2), or NULL
 * @param[out] ck		Buffer for CK = 128-bit confidentiality key (f3), or NULL
 * @param[out] ik		Buffer for IK = 128-bit integrity key (f4), or NULL
 * @param[out] ak		Buffer for AK = 48-bit anonymity key (f5), or NULL
 * @param[out] ak_resync	Buffer for AK = 48-bit anonymity key (f5*), or NULL
 * @param[in] opc		128-bit value derived from OP and K.
 * @param[in] k			128-bit subscriber key
 * @param[in] rand		128-bit random challenge
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int milenage_f2345(uint8_t res[MILENAGE_RES_SIZE],
			  uint8_t ik[MILENAGE_IK_SIZE],
			  uint8_t ck[MILENAGE_CK_SIZE],
			  uint8_t ak[MILENAGE_AK_SIZE],
			  uint8_t ak_resync[MILENAGE_AK_SIZE],
			  uint8_t const opc[MILENAGE_OPC_SIZE],
			  uint8_t const k[MILENAGE_KI_SIZE],
			  uint8_t const rand[MILENAGE_RAND_SIZE])
{
	uint8_t			tmp1[16], tmp2[16], tmp3[16];
	int			i;
	EVP_CIPHER_CTX		*evp_ctx;

	/* tmp2 = TEMP = E_K(RAND XOR OP_C) */
	for (i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("Failed allocating EVP context");
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

	if (aes_128_encrypt_block(evp_ctx, k, tmp1, tmp3) < 0) goto error;

	for (i = 0; i < 16; i++) tmp3[i] ^= opc[i];
	if (res) memcpy(res, tmp3 + 8, 8); /* f2 */
	if (ak) memcpy(ak, tmp3, 6); /* f5 */

	/* f3 */
	if (ck) {
		/* rotate by r3 = 0x20 = 4 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 12) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 2; /* XOR c3 (= ..02) */

		if (aes_128_encrypt_block(evp_ctx, k, tmp1, ck) < 0) goto error;

		for (i = 0; i < 16; i++) ck[i] ^= opc[i];
	}

	/* f4 */
	if (ik) {
		/* rotate by r4 = 0x40 = 8 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 8) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 4; /* XOR c4 (= ..04) */

		if (aes_128_encrypt_block(evp_ctx, k, tmp1, ik) < 0) goto error;

		for (i = 0; i < 16; i++) ik[i] ^= opc[i];
	}

	/* f5* */
	if (ak_resync) {
		/* rotate by r5 = 0x60 = 12 bytes */
		for (i = 0; i < 16; i++) tmp1[(i + 4) % 16] = tmp2[i] ^ opc[i];
		tmp1[15] ^= 8; /* XOR c5 (= ..08) */

		if (aes_128_encrypt_block(evp_ctx, k, tmp1, tmp1) < 0) goto error;

		for (i = 0; i < 6; i++) ak_resync[i] = tmp1[i] ^ opc[i];
	}
	EVP_CIPHER_CTX_free(evp_ctx);

	return 0;
}

/** Derive OPc from OP and Ki
 *
 * @param[out] opc	The derived Operator Code used as an input to other Milenage
 *			functions.
 * @param[in] op	Operator Code.
 * @param[in] ki	Subscriber key.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int milenage_opc_generate(uint8_t opc[MILENAGE_OPC_SIZE],
			  uint8_t const op[MILENAGE_OP_SIZE],
			  uint8_t const ki[MILENAGE_KI_SIZE])
{
	int		ret;
	uint8_t		tmp[MILENAGE_OPC_SIZE];
	EVP_CIPHER_CTX	*evp_ctx;
	size_t		i;

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("Failed allocating EVP context");
		return -1;
	}
 	ret = aes_128_encrypt_block(evp_ctx, ki, op, tmp);
 	EVP_CIPHER_CTX_free(evp_ctx);
	if (ret < 0) return ret;

 	for (i = 0; i < sizeof(tmp); i++) opc[i] = op[i] ^ tmp[i];

 	return 0;
}

/** Generate AKA AUTN, IK, CK, RES
 *
 * @param[out] autn	Buffer for AUTN = 128-bit authentication token.
 * @param[out] ik	Buffer for IK = 128-bit integrity key (f4), or NULL.
 * @param[out] ck	Buffer for CK = 128-bit confidentiality key (f3), or NULL.
 * @param[out] ak	Buffer for AK = 48-bit anonymity key (f5), or NULL
 * @param[out] res	Buffer for RES = 64-bit signed response (f2), or NULL.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] amf	16-bit authentication management field.
 * @param[in] ki	128-bit subscriber key.
 * @param[in] sqn	48-bit sequence number (host byte order).
 * @param[in] rand	128-bit random challenge.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int milenage_umts_generate(uint8_t autn[MILENAGE_AUTN_SIZE],
			   uint8_t ik[MILENAGE_IK_SIZE],
			   uint8_t ck[MILENAGE_CK_SIZE],
			   uint8_t ak[MILENAGE_AK_SIZE],
			   uint8_t res[MILENAGE_RES_SIZE],
			   uint8_t const opc[MILENAGE_OPC_SIZE],
			   uint8_t const amf[MILENAGE_AMF_SIZE],
			   uint8_t const ki[MILENAGE_KI_SIZE],
			   uint64_t sqn,
			   uint8_t const rand[MILENAGE_RAND_SIZE])
{
	uint8_t		mac_a[8], ak_buff[MILENAGE_AK_SIZE];
	uint8_t		sqn_buff[MILENAGE_SQN_SIZE];
	uint8_t		*p = autn;
	size_t		i;

	if ((milenage_f1(mac_a, NULL, opc, ki, rand,
			 uint48_to_buff(sqn_buff, sqn), amf) < 0) ||
	    (milenage_f2345(res, ik, ck, ak_buff, NULL, opc, ki, rand) < 0)) return -1;

	/*
	 *	AUTN = (SQN ^ AK) || AMF || MAC_A
	 */
	for (i = 0; i < sizeof(sqn_buff); i++) *p++ = sqn_buff[i] ^ ak_buff[i];
	memcpy(p, amf, MILENAGE_AMF_SIZE);
	p += MILENAGE_AMF_SIZE;
	memcpy(p, mac_a, sizeof(mac_a));

	/*
	 *	Output the anonymity key if required
	 */
	if (ak) memcpy(ak, ak_buff, sizeof(ak_buff));

	return 0;
}

/** Milenage AUTS validation
 *
 * @param[out] sqn	SQN = 48-bit sequence number (host byte order).
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] ki	128-bit subscriber key.
 * @param[in] rand	128-bit random challenge.
 * @param[in] auts	112-bit authentication token from client.
 * @return
 *	- 0 on success with sqn filled.
 *	- -1 on failure.
 */
int milenage_auts(uint64_t *sqn,
		  uint8_t const opc[MILENAGE_OPC_SIZE],
		  uint8_t const ki[MILENAGE_KI_SIZE],
		  uint8_t const rand[MILENAGE_RAND_SIZE],
		  uint8_t const auts[MILENAGE_AUTS_SIZE])
{
	uint8_t		amf[MILENAGE_AMF_SIZE] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
	uint8_t		ak[MILENAGE_AK_SIZE], mac_s[MILENAGE_MAC_S_SIZE];
	uint8_t		sqn_buff[MILENAGE_SQN_SIZE];
	size_t		i;

	if (milenage_f2345(NULL, NULL, NULL, NULL, ak, opc, ki, rand)) return -1;
	for (i = 0; i < sizeof(sqn_buff); i++) sqn_buff[i] = auts[i] ^ ak[i];

	if (milenage_f1(NULL, mac_s, opc, ki, rand, sqn_buff, amf) || CRYPTO_memcmp(mac_s, auts + 6, 8) != 0) return -1;

	*sqn = uint48_from_buff(sqn_buff);

	return 0;
}

/** Generate GSM-Milenage (3GPP TS 55.205) authentication triplet from a quintuplet
 *
 * @param[out] sres	Buffer for SRES = 32-bit SRES.
 * @param[out] kc	64-bit Kc.
 * @param[in] ik	128-bit integrity.
 * @param[in] ck	Confidentiality key.
 * @param[in] res	64-bit signed response.
 */
void milenage_gsm_from_umts(uint8_t sres[MILENAGE_SRES_SIZE],
			    uint8_t kc[MILENAGE_KC_SIZE],
			    uint8_t const ik[MILENAGE_IK_SIZE],
			    uint8_t const ck[MILENAGE_CK_SIZE],
			    uint8_t const res[MILENAGE_RES_SIZE])
{
	int i;

	for (i = 0; i < 8; i++) kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];

#ifdef GSM_MILENAGE_ALT_SRES
	memcpy(sres, res, 4);
#else	/* GSM_MILENAGE_ALT_SRES */
	for (i = 0; i < 4; i++) sres[i] = res[i] ^ res[i + 4];
#endif	/* GSM_MILENAGE_ALT_SRES */
}

/** Generate GSM-Milenage (3GPP TS 55.205) authentication triplet
 *
 * @param[out] sres	Buffer for SRES = 32-bit SRES.
 * @param[out] kc	64-bit Kc.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] ki	128-bit subscriber key.
 * @param[in] rand	128-bit random challenge.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int milenage_gsm_generate(uint8_t sres[MILENAGE_SRES_SIZE],
			  uint8_t kc[MILENAGE_KC_SIZE],
			  uint8_t const opc[MILENAGE_OPC_SIZE],
			  uint8_t const ki[MILENAGE_KI_SIZE],
			  uint8_t const rand[MILENAGE_RAND_SIZE])
{
	uint8_t		res[MILENAGE_RES_SIZE], ck[MILENAGE_CK_SIZE], ik[MILENAGE_IK_SIZE];

	if (milenage_f2345(res, ik, ck, NULL, NULL, opc, ki, rand)) return -1;

	milenage_gsm_from_umts(sres, kc, ik, ck, res);

	return 0;
}

/** Milenage check
 *
 * @param[out] ik	Buffer for IK = 128-bit integrity key (f4), or NULL.
 * @param[out] ck	Buffer for CK = 128-bit confidentiality key (f3), or NULL.
 * @param[out] res	Buffer for RES = 64-bit signed response (f2), or NULL.
 * @param[in] auts	112-bit buffer for AUTS.
 * @param[in] opc	128-bit operator variant algorithm configuration field (encr.).
 * @param[in] ki	128-bit subscriber key.
 * @param[in] sqn	48-bit sequence number.
 * @param[in] rand	128-bit random challenge.
 * @param[in] autn	128-bit authentication token.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 *	- -2 on synchronization failure
 */
int milenage_check(uint8_t ik[MILENAGE_IK_SIZE],
		   uint8_t ck[MILENAGE_CK_SIZE],
		   uint8_t res[MILENAGE_RES_SIZE],
		   uint8_t auts[MILENAGE_AUTS_SIZE],
		   uint8_t const opc[MILENAGE_OPC_SIZE],
		   uint8_t const ki[MILENAGE_KI_SIZE],
		   uint64_t sqn,
		   uint8_t const rand[MILENAGE_RAND_SIZE],
		   uint8_t const autn[MILENAGE_AUTN_SIZE])
{

	uint8_t mac_a[MILENAGE_MAC_A_SIZE], ak[MILENAGE_AK_SIZE], rx_sqn[MILENAGE_SQN_SIZE];
	uint8_t sqn_buff[MILENAGE_SQN_SIZE];
	const uint8_t *amf;
	size_t i;

	uint48_to_buff(sqn_buff, sqn);

	FR_PROTO_HEX_DUMP(autn, MILENAGE_AUTN_SIZE, "AUTN");
	FR_PROTO_HEX_DUMP(rand, MILENAGE_RAND_SIZE, "RAND");

	if (milenage_f2345(res, ck, ik, ak, NULL, opc, ki, rand)) return -1;

	FR_PROTO_HEX_DUMP(res, MILENAGE_RES_SIZE, "RES");
	FR_PROTO_HEX_DUMP(ck, MILENAGE_CK_SIZE, "CK");
	FR_PROTO_HEX_DUMP(ik, MILENAGE_IK_SIZE, "IK");
	FR_PROTO_HEX_DUMP(ak, MILENAGE_AK_SIZE, "AK");

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (i = 0; i < 6; i++) rx_sqn[i] = autn[i] ^ ak[i];
	FR_PROTO_HEX_DUMP(rx_sqn, MILENAGE_SQN_SIZE, "SQN");

	if (CRYPTO_memcmp(rx_sqn, sqn_buff, sizeof(rx_sqn)) <= 0) {
		uint8_t auts_amf[MILENAGE_AMF_SIZE] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */

		if (milenage_f2345(NULL, NULL, NULL, NULL, ak, opc, ki, rand)) return -1;

		FR_PROTO_HEX_DUMP(ak, sizeof(ak), "AK*");
		for (i = 0; i < 6; i++) auts[i] = sqn_buff[i] ^ ak[i];

		if (milenage_f1(NULL, auts + 6, opc, ki, rand, sqn_buff, auts_amf) < 0) return -1;
		FR_PROTO_HEX_DUMP(auts, 14, "AUTS");
		return -2;
	}

	amf = autn + 6;
	FR_PROTO_HEX_DUMP(amf, MILENAGE_AMF_SIZE, "AMF");
	if (milenage_f1(mac_a, NULL, opc, ki, rand, rx_sqn, amf) < 0) return -1;

	FR_PROTO_HEX_DUMP(mac_a, MILENAGE_MAC_A_SIZE, "MAC_A");

	if (CRYPTO_memcmp(mac_a, autn + 8, 8) != 0) {
		FR_PROTO_HEX_DUMP(autn + 8, 8, "Received MAC_A");
		fr_strerror_printf("MAC mismatch");
		return -1;
	}

	return 0;
}

#ifdef TESTING_MILENAGE
/*
 *  cc milenage.c -g3 -Wall -DHAVE_DLFCN_H -DTESTING_MILENAGE -DWITH_TLS -I../../../../ -I../../../ -I ../base/ -I /usr/local/opt/openssl/include/ -include ../include/build.h -L /usr/local/opt/openssl/lib/ -l ssl -l crypto -l talloc -L ../../../../../build/lib/local/.libs/ -lfreeradius-server -lfreeradius-tls -lfreeradius-util -o test_milenage && ./test_milenage
 */
#include <freeradius-devel/util/cutest.h>

void test_set_1(void)
{
	/*
	 *	Inputs
	 */
	uint8_t ki[]		= { 0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
				    0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc };
	uint8_t rand[]		= { 0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d,
				    0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35  };
	uint8_t sqn[]		= { 0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07 };
	uint8_t amf[]		= { 0xb9, 0xb9 };
	uint8_t op[]		= { 0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6,
				    0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18 };
	uint8_t opc[]		= { 0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
				    0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf };

	/*
	 *	Outputs
	 */
	uint8_t opc_out[MILENAGE_OPC_SIZE];
	uint8_t	mac_a_out[MILENAGE_MAC_A_SIZE];
	uint8_t	mac_s_out[MILENAGE_MAC_S_SIZE];
	uint8_t res_out[MILENAGE_RES_SIZE];
	uint8_t ck_out[MILENAGE_CK_SIZE];
	uint8_t ik_out[MILENAGE_IK_SIZE];
	uint8_t ak_out[MILENAGE_AK_SIZE];
	uint8_t ak_resync_out[MILENAGE_AK_SIZE];

	/* function 1 */
	uint8_t mac_a[]		= { 0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3 };
	/* function 1* */
	uint8_t mac_s[]		= { 0x01, 0xcf, 0xaf, 0x9e, 0xc4, 0xe8, 0x71, 0xe9 };
	/* function 2 */
	uint8_t res[]		= { 0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf };
	/* function 3 */
	uint8_t ck[]		= { 0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05,
				    0xbb, 0xf0, 0xd9, 0x87, 0xb2, 0x1b, 0xf8, 0xcb };
	/* function 4 */
	uint8_t ik[]		= { 0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04,
			    	    0x12, 0x76, 0x72, 0x71, 0x1c, 0x6d, 0x34, 0x41 };
	/* function 5 */
	uint8_t ak[]		= { 0xaa, 0x68, 0x9c, 0x64, 0x83, 0x70 };
	/* function 5* */
	uint8_t ak_resync[]	= { 0x45, 0x1e, 0x8b, 0xec, 0xa4, 0x3b };

	int ret = 0;

/*
	fr_debug_lvl = 4;
*/
	ret = milenage_opc_generate(opc_out, op, ki);
	TEST_CHECK(ret == 0);

	FR_PROTO_HEX_DUMP(opc_out, sizeof(opc_out), "opc");

	TEST_CHECK(memcmp(opc_out, opc, sizeof(opc_out)) == 0);

	if ((milenage_f1(mac_a_out, mac_s_out, opc, ki, rand, sqn, amf) < 0) ||
	    (milenage_f2345(res_out, ik_out, ck_out, ak_out, ak_resync_out, opc, ki, rand) < 0)) ret = -1;

	FR_PROTO_HEX_DUMP(mac_a, sizeof(mac_a_out), "mac_a");
	FR_PROTO_HEX_DUMP(mac_s, sizeof(mac_s_out), "mac_s");
	FR_PROTO_HEX_DUMP(ik_out, sizeof(ik_out), "ik");
	FR_PROTO_HEX_DUMP(ck_out, sizeof(ck_out), "ck");
	FR_PROTO_HEX_DUMP(res_out, sizeof(res_out), "res");
	FR_PROTO_HEX_DUMP(ak_out, sizeof(ak_out), "ak");
	FR_PROTO_HEX_DUMP(ak_resync_out, sizeof(ak_resync_out), "ak_resync");

	TEST_CHECK(ret == 0);
	TEST_CHECK(memcmp(mac_a_out, mac_a, sizeof(mac_a_out)) == 0);
	TEST_CHECK(memcmp(mac_s_out, mac_s, sizeof(mac_s_out)) == 0);
	TEST_CHECK(memcmp(res_out, res, sizeof(res_out)) == 0);
	TEST_CHECK(memcmp(ck_out, ck, sizeof(ck_out)) == 0);
	TEST_CHECK(memcmp(ik_out, ik, sizeof(ik_out)) == 0);
	TEST_CHECK(memcmp(ak_out, ak, sizeof(ak_out)) == 0);
	TEST_CHECK(memcmp(ak_resync, ak_resync, sizeof(ak_resync_out)) == 0);
}

void test_set_19(void)
{
	/*
	 *	Inputs
	 */
	uint8_t ki[]		= { 0x51, 0x22, 0x25, 0x02, 0x14, 0xc3, 0x3e, 0x72,
				    0x3a, 0x5d, 0xd5, 0x23, 0xfc, 0x14, 0x5f, 0xc0 };
	uint8_t rand[]		= { 0x81, 0xe9, 0x2b, 0x6c, 0x0e, 0xe0, 0xe1, 0x2e,
				    0xbc, 0xeb, 0xa8, 0xd9, 0x2a, 0x99, 0xdf, 0xa5 };
	uint8_t sqn[]		= { 0x16, 0xf3, 0xb3, 0xf7, 0x0f, 0xc2 };
	uint8_t amf[]		= { 0xc3, 0xab };
	uint8_t op[]		= { 0xc9, 0xe8, 0x76, 0x32, 0x86, 0xb5, 0xb9, 0xff,
				    0xbd, 0xf5, 0x6e, 0x12, 0x97, 0xd0, 0x88, 0x7b };
	uint8_t opc[]		= { 0x98, 0x1d, 0x46, 0x4c, 0x7c, 0x52, 0xeb, 0x6e,
				    0x50, 0x36, 0x23, 0x49, 0x84, 0xad, 0x0b, 0xcf };

	/*
	 *	Outputs
	 */
	uint8_t opc_out[MILENAGE_OPC_SIZE];
	uint8_t	mac_a_out[MILENAGE_MAC_A_SIZE];
	uint8_t	mac_s_out[MILENAGE_MAC_S_SIZE];
	uint8_t res_out[MILENAGE_RES_SIZE];
	uint8_t ck_out[MILENAGE_CK_SIZE];
	uint8_t ik_out[MILENAGE_IK_SIZE];
	uint8_t ak_out[MILENAGE_AK_SIZE];
	uint8_t ak_resync_out[MILENAGE_AK_SIZE];

	/* function 1 */
	uint8_t mac_a[]		= { 0x2a, 0x5c, 0x23, 0xd1, 0x5e, 0xe3, 0x51, 0xd5 };
	/* function 1* */
	uint8_t mac_s[]		= { 0x62, 0xda, 0xe3, 0x85, 0x3f, 0x3a, 0xf9, 0xd2 };
	/* function 2 */
	uint8_t res[]		= { 0x28, 0xd7, 0xb0, 0xf2, 0xa2, 0xec, 0x3d, 0xe5 };
	/* function 3 */
	uint8_t ck[]		= { 0x53, 0x49, 0xfb, 0xe0, 0x98, 0x64, 0x9f, 0x94,
				    0x8f, 0x5d, 0x2e, 0x97, 0x3a, 0x81, 0xc0, 0x0f };
	/* function 4 */
	uint8_t ik[]		= { 0x97, 0x44, 0x87, 0x1a, 0xd3, 0x2b, 0xf9, 0xbb,
				    0xd1, 0xdd, 0x5c, 0xe5, 0x4e, 0x3e, 0x2e, 0x5a };
	/* function 5 */
	uint8_t ak[]		= { 0xad, 0xa1, 0x5a, 0xeb, 0x7b, 0xb8 };
	/* function 5* */
	uint8_t ak_resync[]	= { 0xd4, 0x61, 0xbc, 0x15, 0x47, 0x5d };

	int ret = 0;

/*
	fr_debug_lvl = 4;
*/

	ret = milenage_opc_generate(opc_out, op, ki);
	TEST_CHECK(ret == 0);

	FR_PROTO_HEX_DUMP(opc_out, sizeof(opc_out), "opc");

	TEST_CHECK(memcmp(opc_out, opc, sizeof(opc_out)) == 0);

	if ((milenage_f1(mac_a_out, mac_s_out, opc, ki, rand, sqn, amf) < 0) ||
	    (milenage_f2345(res_out, ik_out, ck_out, ak_out, ak_resync_out, opc, ki, rand) < 0)) ret = -1;

	FR_PROTO_HEX_DUMP(mac_a, sizeof(mac_a_out), "mac_a");
	FR_PROTO_HEX_DUMP(mac_s, sizeof(mac_s_out), "mac_s");
	FR_PROTO_HEX_DUMP(ik_out, sizeof(ik_out), "ik");
	FR_PROTO_HEX_DUMP(ck_out, sizeof(ck_out), "ck");
	FR_PROTO_HEX_DUMP(res_out, sizeof(res_out), "res");
	FR_PROTO_HEX_DUMP(ak_out, sizeof(ak_out), "ak");
	FR_PROTO_HEX_DUMP(ak_resync_out, sizeof(ak_resync_out), "ak_resync");

	TEST_CHECK(ret == 0);
	TEST_CHECK(memcmp(mac_a_out, mac_a, sizeof(mac_a_out)) == 0);
	TEST_CHECK(memcmp(mac_s_out, mac_s, sizeof(mac_s_out)) == 0);
	TEST_CHECK(memcmp(res_out, res, sizeof(res_out)) == 0);
	TEST_CHECK(memcmp(ck_out, ck, sizeof(ck_out)) == 0);
	TEST_CHECK(memcmp(ik_out, ik, sizeof(ik_out)) == 0);
	TEST_CHECK(memcmp(ak_out, ak, sizeof(ak_out)) == 0);
	TEST_CHECK(memcmp(ak_resync, ak_resync, sizeof(ak_resync_out)) == 0);
}

TEST_LIST = {
	{ "test_set_1",		test_set_1 },
	{ "test_set_19",	test_set_19 },
	{ NULL }
};
#endif
