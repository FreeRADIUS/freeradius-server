/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for EAP packet validation
 *
 * @file src/tests/api/eap_tests.c
 *
 * Covers the TLS header length checks in eap_vp2packet().
 *
 * @copyright 2026 The FreeRADIUS server project
 */
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/conf.h>	/* RADIUS_DICTIONARY */

#include "eap_types.h"

#include "acutest_common_init.h"
#include "acutest_helpers.h"

#include <sys/wait.h>

/* Linker hacks */

#ifdef HAVE_PTHREAD_H
pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

static TALLOC_CTX	*autofree;

static void test_init(void) __attribute__((constructor));
static void test_init(void)
{
	char const *dict_dir = getenv("DICT_DIR");

DIAG_OFF(deprecated-declarations)
	autofree = talloc_autofree_context();
DIAG_ON(deprecated-declarations)
	if (!autofree) {
		fr_perror("eap_tests");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on.
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("eap_tests");
		exit(EXIT_FAILURE);
	}

	if (!dict_dir) dict_dir = "share";

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("eap_tests: failed loading dictionaries from \"%s\"", dict_dir);
		fprintf(stderr, "Set DICT_DIR to the directory holding \"dictionary\"\n");
		exit(EXIT_FAILURE);
	}
}

/** Run eap_vp2packet() on a single EAP-Message containing the given data
 *
 * @return true if the packet was accepted.
 */
static bool eap_packet_ok(uint8_t const *data, size_t data_len)
{
	VALUE_PAIR		*vps = NULL;
	VALUE_PAIR		*vp;
	eap_packet_raw_t	*eap_packet;
	bool			ok;

	vp = fr_pair_afrom_num(autofree, PW_EAP_MESSAGE, 0);
	TEST_ASSERT(vp != NULL);
	fr_pair_value_memcpy(vp, data, data_len);
	fr_pair_add(&vps, vp);

	eap_packet = eap_vp2packet(autofree, vps);
	ok = (eap_packet != NULL);
	if (!ok) TEST_MSG("eap_vp2packet: %s", fr_strerror());

	talloc_free(eap_packet);
	fr_pair_list_free(&vps);

	return ok;
}

/*
 *	EAP-Response, Id 1, Type EAP-TLS (13)
 *
 *	Flags 0x80 = 'L', Message Length follows the flags.
 */
static void test_tls_no_flags(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x05, 0x0d		/* no flags octet */
	};

	TEST_CASE("TLS flags octet is missing");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

static void test_tls_length_truncated(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x09, 0x0d, 0x80,
		0x00, 0x00, 0x00			/* 3 of 4 octets */
	};

	TEST_CASE("TLS Message Length field is truncated");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

static void test_tls_length_complete(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x0a, 0x0d, 0x80,
		0x00, 0x00, 0x00, 0x00			/* Message Length = 0 */
	};

	TEST_CASE("TLS Message Length field is complete, with no data");
	TEST_CHECK(eap_packet_ok(packet, sizeof(packet)));
}

/*
 *	EAP-Response, Id 1, Type TEAP (55)
 *
 *	Flags 0x10 = 'O', Outer TLV Length follows the flags.
 *	Flags 0x90 = 'L' + 'O', Outer TLV Length follows the Message Length.
 */
static void test_teap_outer_tlv_length_truncated(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x09, 0x37, 0x10,
		0x00, 0x00, 0x00			/* 3 of 4 octets */
	};

	TEST_CASE("Outer TLV Length field is truncated");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_outer_tlv_length_no_data(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x0a, 0x37, 0x10,
		0x00, 0x00, 0x00, 0x00			/* Outer TLV Length = 0 */
	};

	TEST_CASE("Outer TLV Length field is complete, with no data");
	TEST_CHECK(eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_outer_tlv_length_fits(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x0c, 0x37, 0x10,
		0x00, 0x00, 0x00, 0x02,			/* Outer TLV Length = 2 */
		0xaa, 0xbb
	};

	TEST_CASE("Outer TLV Length matches the remaining data");
	TEST_CHECK(eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_outer_tlv_length_too_long(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x0c, 0x37, 0x10,
		0x00, 0x00, 0x00, 0x03,			/* Outer TLV Length = 3 */
		0xaa, 0xbb
	};

	TEST_CASE("Outer TLV Length is one octet larger than the remaining data");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_outer_tlv_length_max(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x0c, 0x37, 0x10,
		0xff, 0xff, 0xff, 0xff,			/* Outer TLV Length = 0xffffffff */
		0xaa, 0xbb
	};

	TEST_CASE("Outer TLV Length is 0xffffffff");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_length_outer_tlv_length_fits(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x10, 0x37, 0x90,
		0x00, 0x00, 0x00, 0x00,			/* Message Length = 0 */
		0x00, 0x00, 0x00, 0x02,			/* Outer TLV Length = 2 */
		0xaa, 0xbb
	};

	TEST_CASE("With 'L', Outer TLV Length matches the remaining data");
	TEST_CHECK(eap_packet_ok(packet, sizeof(packet)));
}

static void test_teap_length_outer_tlv_length_too_long(void)
{
	uint8_t const packet[] = {
		0x02, 0x01, 0x00, 0x10, 0x37, 0x90,
		0x00, 0x00, 0x00, 0x00,			/* Message Length = 0 */
		0x00, 0x00, 0x00, 0x03,			/* Outer TLV Length = 3 */
		0xaa, 0xbb
	};

	TEST_CASE("With 'L', Outer TLV Length is one octet larger than the remaining data");
	TEST_CHECK(!eap_packet_ok(packet, sizeof(packet)));
}

TEST_LIST = {
	{ "tls_no_flags",				test_tls_no_flags },
	{ "tls_length_truncated",			test_tls_length_truncated },
	{ "tls_length_complete",			test_tls_length_complete },

	{ "teap_outer_tlv_length_truncated",		test_teap_outer_tlv_length_truncated },
	{ "teap_outer_tlv_length_no_data",		test_teap_outer_tlv_length_no_data },
	{ "teap_outer_tlv_length_fits",			test_teap_outer_tlv_length_fits },
	{ "teap_outer_tlv_length_too_long",		test_teap_outer_tlv_length_too_long },
	{ "teap_outer_tlv_length_max",			test_teap_outer_tlv_length_max },
	{ "teap_length_outer_tlv_length_fits",		test_teap_length_outer_tlv_length_fits },
	{ "teap_length_outer_tlv_length_too_long",	test_teap_length_outer_tlv_length_too_long },

	{ NULL }
};
