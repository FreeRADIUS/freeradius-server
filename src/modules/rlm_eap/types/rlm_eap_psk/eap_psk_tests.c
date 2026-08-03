/*
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
 */

/**
 * $Id$
 *
 * @file eap_psk_tests.c
 * @brief Known-answer tests for the EAP-PSK (RFC 4764) cryptographic primitives
 *
 * RFC 4764 publishes no test vectors, so verification is done in two layers:
 *
 *   1. The CMAC core is checked against the official AES-CMAC vectors from
 *      RFC 4493 Section 4.
 *
 *   2. The EAP-PSK derivations (AK/KDK, TEK/MSK/EMSK, MAC_P, MAC_S, and the
 *      EAX protected channel) are checked against known-answer values
 *      computed with hostap's INDEPENDENT implementation
 *      (src/eap_common/eap_psk_common.c, src/crypto/aes-omac1.c and
 *      aes-eax.c, hostap commit f541de4), for the fixed inputs documented
 *      below.
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/util/test/acutest.h>

#include "eap_psk.c"

/*
 *	Fixed inputs for the hostap cross-check vectors.  If any of these
 *	change, the expected values below must be regenerated.
 */
static uint8_t const test_psk[EAP_PSK_PSK_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static uint8_t const test_rand_s[EAP_PSK_RAND_LEN] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static uint8_t const test_rand_p[EAP_PSK_RAND_LEN] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static char const test_id_s[] = "FreeRADIUS";
static char const test_id_p[] = "bob@example.com";

/*
 *	Expected values, computed by hostap (see the file header).
 */
static uint8_t const expect_ak[EAP_PSK_AK_LEN] = {
	0x18, 0xb6, 0x2d, 0x2c, 0x84, 0xc5, 0xe4, 0x57,
	0x1a, 0xfc, 0x41, 0xa2, 0x9d, 0xb7, 0x1f, 0x4d
};
static uint8_t const expect_kdk[EAP_PSK_KDK_LEN] = {
	0x97, 0xb7, 0x04, 0x35, 0x00, 0x85, 0x02, 0x83,
	0x63, 0x92, 0x46, 0x12, 0x56, 0x5b, 0x9b, 0x0d
};
static uint8_t const expect_tek[EAP_PSK_TEK_LEN] = {
	0x96, 0xa0, 0x0b, 0x88, 0x8b, 0x1f, 0x6b, 0x2f,
	0x8e, 0x20, 0x1e, 0xe9, 0x6a, 0x22, 0x77, 0xf6
};
static uint8_t const expect_msk[EAP_PSK_MSK_LEN] = {
	0xe2, 0x82, 0xc7, 0xc3, 0x2f, 0x4a, 0x3b, 0x28,
	0xf1, 0x8d, 0x75, 0x86, 0x0f, 0xa2, 0x67, 0x1c,
	0x46, 0xd0, 0x71, 0xe2, 0xf7, 0xe5, 0x09, 0xce,
	0x2e, 0x98, 0xae, 0x9a, 0xe3, 0x34, 0x99, 0x77,
	0x05, 0xf9, 0x27, 0xd1, 0x84, 0xea, 0xd2, 0x71,
	0xf9, 0xbc, 0xb1, 0xb7, 0xa1, 0xf9, 0x22, 0x30,
	0xbf, 0x0d, 0xc9, 0x0d, 0x94, 0x61, 0x17, 0xaa,
	0xe0, 0xd7, 0x84, 0xb8, 0x35, 0x59, 0x57, 0xd5
};
static uint8_t const expect_emsk[EAP_PSK_EMSK_LEN] = {
	0xd2, 0x0b, 0x6b, 0x75, 0x56, 0x33, 0x92, 0x00,
	0xf0, 0x4e, 0x65, 0x30, 0xeb, 0x7d, 0x3c, 0x61,
	0xa7, 0x81, 0x0b, 0x5c, 0xa9, 0x3f, 0x4c, 0x0b,
	0xa8, 0x9e, 0xa5, 0xee, 0xdf, 0x63, 0x4a, 0x69,
	0x79, 0x29, 0x20, 0xa6, 0xca, 0xea, 0x9d, 0x8e,
	0x7b, 0x11, 0x2d, 0x63, 0x83, 0xdd, 0x85, 0x88,
	0xb6, 0x8b, 0x74, 0xf6, 0xe7, 0xc2, 0xf8, 0xd5,
	0x1a, 0xce, 0x97, 0x06, 0x71, 0x17, 0xac, 0x92
};
static uint8_t const expect_mac_p[EAP_PSK_MAC_LEN] = {
	0x97, 0xb0, 0xed, 0xe6, 0x89, 0xa3, 0xe4, 0x55,
	0x3d, 0x8b, 0x30, 0x22, 0x58, 0xd1, 0x95, 0x12
};
static uint8_t const expect_mac_s[EAP_PSK_MAC_LEN] = {
	0x25, 0xa1, 0xd6, 0x46, 0x87, 0x9e, 0xef, 0x18,
	0x7d, 0x1c, 0xc1, 0xff, 0x17, 0x7e, 0x26, 0x6d
};

/*
 *	Third/fourth message EAX header H (22 bytes), and the expected
 *	ciphertext/tag for the single protected byte 0x80 (R=DONE_SUCCESS).
 *	Message 3: Code=Request(1), Id=2, Length=59, Type=47, Flags=T2.
 *	Message 4: Code=Response(2), Id=2, Length=43, Type=47, Flags=T3.
 */
static uint8_t const expect_msg3_cipher = 0x8f;
static uint8_t const expect_msg3_tag[EAP_PSK_TAG_LEN] = {
	0x47, 0xd6, 0x44, 0x26, 0x5c, 0xae, 0x5a, 0x68,
	0x9a, 0x40, 0xa4, 0x7a, 0xc5, 0x4d, 0xdf, 0x80
};
static uint8_t const expect_msg4_cipher = 0xcc;
static uint8_t const expect_msg4_tag[EAP_PSK_TAG_LEN] = {
	0x7a, 0x7a, 0x71, 0x52, 0x7b, 0x1f, 0x04, 0x7a,
	0x77, 0xfb, 0xf0, 0xef, 0xa6, 0x73, 0xf7, 0x54
};

static void test_header(uint8_t header[EAP_PSK_HEADER_LEN], uint8_t code, uint16_t eap_len, uint8_t flags)
{
	header[0] = code;
	header[1] = 0x02;
	header[2] = (uint8_t) (eap_len >> 8);
	header[3] = (uint8_t) (eap_len & 0xff);
	header[4] = 0x2f;	/* EAP Type 47, EAP-PSK */
	header[5] = flags;
	memcpy(header + 6, test_rand_s, EAP_PSK_RAND_LEN);
}

/** AES-CMAC vectors from RFC 4493 Section 4
 *
 */
static void test_cmac_rfc4493(void)
{
	static uint8_t const key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	static uint8_t const msg[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	static uint8_t const expect_m0[16] = {
		0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
		0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
	};
	static uint8_t const expect_m16[16] = {
		0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
		0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
	};
	static uint8_t const expect_m40[16] = {
		0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
		0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
	};
	static uint8_t const expect_m64[16] = {
		0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
		0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
	};
	uint8_t mac[16];

	/* Example 1 - empty message */
	TEST_CHECK(eap_psk_cmac(mac, key, NULL, 0, NULL, 0, NULL, 0, NULL, 0) == 0);
	TEST_CHECK(memcmp(mac, expect_m0, sizeof(mac)) == 0);

	/* Example 2 - 16 bytes */
	TEST_CHECK(eap_psk_cmac(mac, key, msg, 16, NULL, 0, NULL, 0, NULL, 0) == 0);
	TEST_CHECK(memcmp(mac, expect_m16, sizeof(mac)) == 0);

	/* Example 3 - 40 bytes */
	TEST_CHECK(eap_psk_cmac(mac, key, msg, 40, NULL, 0, NULL, 0, NULL, 0) == 0);
	TEST_CHECK(memcmp(mac, expect_m40, sizeof(mac)) == 0);

	/* Example 3 again, split across segments - must match the one-shot value */
	TEST_CHECK(eap_psk_cmac(mac, key, msg, 16, msg + 16, 16, msg + 32, 8, NULL, 0) == 0);
	TEST_CHECK(memcmp(mac, expect_m40, sizeof(mac)) == 0);

	/* Example 4 - 64 bytes */
	TEST_CHECK(eap_psk_cmac(mac, key, msg, 64, NULL, 0, NULL, 0, NULL, 0) == 0);
	TEST_CHECK(memcmp(mac, expect_m64, sizeof(mac)) == 0);
}

/** AK/KDK derivation matches hostap's implementation
 *
 */
static void test_derive_ak_kdk(void)
{
	uint8_t ak[EAP_PSK_AK_LEN], kdk[EAP_PSK_KDK_LEN];

	TEST_CHECK(eap_psk_derive_ak_kdk(ak, kdk, test_psk) == 0);
	TEST_CHECK(memcmp(ak, expect_ak, sizeof(ak)) == 0);
	TEST_CHECK(memcmp(kdk, expect_kdk, sizeof(kdk)) == 0);
}

/** TEK/MSK/EMSK derivation matches hostap's implementation
 *
 */
static void test_derive_keys(void)
{
	uint8_t tek[EAP_PSK_TEK_LEN], msk[EAP_PSK_MSK_LEN], emsk[EAP_PSK_EMSK_LEN];

	TEST_CHECK(eap_psk_derive_keys(tek, msk, emsk, expect_kdk, test_rand_p) == 0);
	TEST_CHECK(memcmp(tek, expect_tek, sizeof(tek)) == 0);
	TEST_CHECK(memcmp(msk, expect_msk, sizeof(msk)) == 0);
	TEST_CHECK(memcmp(emsk, expect_emsk, sizeof(emsk)) == 0);
}

/** MAC_P and MAC_S match hostap's implementation
 *
 */
static void test_macs(void)
{
	uint8_t mac_p[EAP_PSK_MAC_LEN], mac_s[EAP_PSK_MAC_LEN];

	TEST_CHECK(eap_psk_mac_p(mac_p, expect_ak,
				 (uint8_t const *) test_id_p, strlen(test_id_p),
				 (uint8_t const *) test_id_s, strlen(test_id_s),
				 test_rand_s, test_rand_p) == 0);
	TEST_CHECK(memcmp(mac_p, expect_mac_p, sizeof(mac_p)) == 0);

	TEST_CHECK(eap_psk_mac_s(mac_s, expect_ak,
				 (uint8_t const *) test_id_s, strlen(test_id_s),
				 test_rand_p) == 0);
	TEST_CHECK(memcmp(mac_s, expect_mac_s, sizeof(mac_s)) == 0);
}

/** Protected channel encryption matches hostap, for both message directions
 *
 */
static void test_pchannel_encrypt(void)
{
	uint8_t header[EAP_PSK_HEADER_LEN];
	uint8_t plain = 0x80;	/* R = DONE_SUCCESS, E = 0 */
	uint8_t cipher;
	uint8_t tag[EAP_PSK_TAG_LEN];

	test_header(header, 0x01, 59, 0x80);
	TEST_CHECK(eap_psk_pchannel_encrypt(&cipher, tag, expect_tek, 0,
					    header, sizeof(header), &plain, 1) == 0);
	TEST_CHECK(cipher == expect_msg3_cipher);
	TEST_CHECK(memcmp(tag, expect_msg3_tag, sizeof(tag)) == 0);

	test_header(header, 0x02, 43, 0xc0);
	TEST_CHECK(eap_psk_pchannel_encrypt(&cipher, tag, expect_tek, 1,
					    header, sizeof(header), &plain, 1) == 0);
	TEST_CHECK(cipher == expect_msg4_cipher);
	TEST_CHECK(memcmp(tag, expect_msg4_tag, sizeof(tag)) == 0);
}

/** Protected channel decryption round-trips, and rejects tampering
 *
 */
static void test_pchannel_decrypt(void)
{
	uint8_t header[EAP_PSK_HEADER_LEN];
	uint8_t plain;
	uint8_t bad_tag[EAP_PSK_TAG_LEN];
	uint8_t bad_cipher;

	test_header(header, 0x02, 43, 0xc0);

	/* The hostap-computed message 4 ciphertext decrypts to R = DONE_SUCCESS */
	TEST_CHECK(eap_psk_pchannel_decrypt(&plain, expect_tek, 1,
					    header, sizeof(header),
					    &expect_msg4_cipher, 1, expect_msg4_tag) == 0);
	TEST_CHECK(plain == 0x80);

	/* A tampered tag must be rejected */
	memcpy(bad_tag, expect_msg4_tag, sizeof(bad_tag));
	bad_tag[0] ^= 0x01;
	TEST_CHECK(eap_psk_pchannel_decrypt(&plain, expect_tek, 1,
					    header, sizeof(header),
					    &expect_msg4_cipher, 1, bad_tag) < 0);

	/* A tampered ciphertext must be rejected */
	bad_cipher = expect_msg4_cipher ^ 0x01;
	TEST_CHECK(eap_psk_pchannel_decrypt(&plain, expect_tek, 1,
					    header, sizeof(header),
					    &bad_cipher, 1, expect_msg4_tag) < 0);

	/* The wrong nonce must be rejected */
	TEST_CHECK(eap_psk_pchannel_decrypt(&plain, expect_tek, 0,
					    header, sizeof(header),
					    &expect_msg4_cipher, 1, expect_msg4_tag) < 0);

	/* A tampered header must be rejected */
	header[1] ^= 0x01;
	TEST_CHECK(eap_psk_pchannel_decrypt(&plain, expect_tek, 1,
					    header, sizeof(header),
					    &expect_msg4_cipher, 1, expect_msg4_tag) < 0);
}

TEST_LIST = {
	{ "cmac_rfc4493",	test_cmac_rfc4493 },
	{ "derive_ak_kdk",	test_derive_ak_kdk },
	{ "derive_keys",	test_derive_keys },
	{ "macs",		test_macs },
	{ "pchannel_encrypt",	test_pchannel_encrypt },
	{ "pchannel_decrypt",	test_pchannel_decrypt },
	{ NULL, NULL }
};
