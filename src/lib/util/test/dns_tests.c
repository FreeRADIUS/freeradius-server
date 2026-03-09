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

/** Tests for DNS label encoding / decoding
 *
 * @file src/lib/util/test/dns_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

#include "acutest.h"
#include "acutest_helpers.h"
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/talloc.h>

#define DNS_HDR_LEN 12

/*
 *	Helper: set up an fr_dns_labels_t with tracking blocks.
 */
static fr_dns_block_t	test_blocks[256];
static uint8_t		test_marker[65536];

static void labels_init(fr_dns_labels_t *lb, uint8_t const *packet, size_t packet_len, bool use_mark)
{
	lb->max = 256;
	lb->blocks = test_blocks;
	lb->start = packet;
	lb->end = packet + packet_len;
	lb->num = 1;
	lb->blocks[0].start = DNS_HDR_LEN;
	lb->blocks[0].end = DNS_HDR_LEN;

	if (use_mark) {
		fr_assert(packet_len <= sizeof(test_marker));
		memset(test_marker, 0, packet_len);
		lb->mark = test_marker;
	} else {
		lb->mark = NULL;
	}
}

/*
 *	Helper: encode a string into DNS label format in a buffer.
 *	Returns total bytes written at 'where', or < 0 on error.
 */
static ssize_t encode_label(uint8_t *buf, size_t buf_len, uint8_t *where,
			    char const *str, bool compression, fr_dns_labels_t *lb)
{
	return fr_dns_label_from_value_box(NULL, buf, buf_len, where, compression, fr_box_strvalue(str), lb);
}

/*
 *  Encoding tests
 *
 */

static void test_encode_empty_string(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* empty string => single 0x00 byte */
	slen = encode_label(buf, sizeof(buf), buf, "", false, NULL);
	TEST_CHECK(slen == 1);
	TEST_CHECK(buf[0] == 0x00);
}

static void test_encode_root_dot(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* "." => single 0x00 byte */
	slen = encode_label(buf, sizeof(buf), buf, ".", false, NULL);
	TEST_CHECK(slen == 1);
	TEST_CHECK(buf[0] == 0x00);
}

static void test_encode_simple_label(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* "com" => 03 63 6f 6d 00 */
	slen = encode_label(buf, sizeof(buf), buf, "com", false, NULL);
	TEST_CHECK(slen == 5);
	TEST_MSG("Expected 5, got %zd", slen);
	TEST_CHECK(buf[0] == 3);
	TEST_CHECK(memcmp(buf + 1, "com", 3) == 0);
	TEST_CHECK(buf[4] == 0x00);
}

static void test_encode_multi_label(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* "www.example.com" => 03 www 07 example 03 com 00 */
	slen = encode_label(buf, sizeof(buf), buf, "www.example.com", false, NULL);
	TEST_CHECK(slen == 17);
	TEST_MSG("Expected 17, got %zd", slen);
	TEST_CHECK(buf[0] == 3);
	TEST_CHECK(memcmp(buf + 1, "www", 3) == 0);
	TEST_CHECK(buf[4] == 7);
	TEST_CHECK(memcmp(buf + 5, "example", 7) == 0);
	TEST_CHECK(buf[12] == 3);
	TEST_CHECK(memcmp(buf + 13, "com", 3) == 0);
	TEST_CHECK(buf[16] == 0x00);
}

static void test_encode_trailing_dot(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* "example.com." trailing dot should be stripped */
	slen = encode_label(buf, sizeof(buf), buf, "example.com.", false, NULL);
	TEST_CHECK(slen == 13);
	TEST_MSG("Expected 13, got %zd", slen);
	/* same as "example.com" */
	TEST_CHECK(buf[0] == 7);
	TEST_CHECK(buf[8] == 3);
	TEST_CHECK(buf[12] == 0x00);
}

static void test_encode_underscore_prefix(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* "_srv.example.com" - underscore allowed at label start */
	slen = encode_label(buf, sizeof(buf), buf, "_srv.example.com", false, NULL);
	TEST_CHECK(slen > 0);
	TEST_MSG("Expected >0, got %zd", slen);
	TEST_CHECK(buf[0] == 4); /* _srv is 4 chars */
	TEST_CHECK(buf[1] == '_');
}

/*
 *  Encoding error paths
 */
static void test_encode_null_inputs(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* NULL buf */
	slen = fr_dns_label_from_value_box(NULL, NULL, 100, (uint8_t[100]){0}, false, fr_box_strvalue("test"), NULL);
	TEST_CHECK(slen < 0);

	/* zero buf_len */
	slen = fr_dns_label_from_value_box(NULL, buf, 0, buf, false, fr_box_strvalue("test"), NULL);
	TEST_CHECK(slen < 0);

	/* NULL value */
	slen = fr_dns_label_from_value_box(NULL, buf, sizeof(buf), buf, false, NULL, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_non_string_type(void)
{
	ssize_t slen;
	fr_value_box_t vb;
	uint8_t buf[256] = {};

	fr_value_box_init_null(&vb);
	slen = fr_dns_label_from_value_box(NULL, buf, sizeof(buf), buf, false, &vb, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_invalid_chars(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	/* space is invalid */
	slen = encode_label(buf, sizeof(buf), buf, "hello world", false, NULL);
	TEST_CHECK(slen < 0);

	/* @ is invalid */
	slen = encode_label(buf, sizeof(buf), buf, "user@host", false, NULL);
	TEST_CHECK(slen < 0);

	/* tab is invalid */
	slen = encode_label(buf, sizeof(buf), buf, "a\tb", false, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_double_dot(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	slen = encode_label(buf, sizeof(buf), buf, "www..example.com", false, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_leading_dot(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	slen = encode_label(buf, sizeof(buf), buf, ".example.com", false, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_label_too_long(void)
{
	ssize_t slen;
	char label[65];
	uint8_t buf[256] = {};

	/* 64-char label exceeds the 63-byte limit */
	memset(label, 'a', 64);
	label[64] = '\0';
	slen = encode_label(buf, sizeof(buf), buf, label, false, NULL);
	TEST_CHECK(slen < 0);
}

static void test_encode_buffer_too_small(void)
{
	ssize_t slen;
	size_t need = 0;
	uint8_t buf[5] = {}; /* too small for "example.com" */

	slen = fr_dns_label_from_value_box(&need, buf, sizeof(buf), buf, false,
					   fr_box_strvalue("example.com"), NULL);
	TEST_CHECK(slen == 0); /* returns 0 when buffer too small */
	TEST_CHECK(need == 13);
	TEST_MSG("need=%zu, buf_len=%zu", need, sizeof(buf));
}

static void test_encode_where_outside_buf(void)
{
	ssize_t slen;
	uint8_t outside[16];
	uint8_t buf[256] = {};

	/* 'where' pointer is outside the buffer */
	slen = fr_dns_label_from_value_box(NULL, buf, sizeof(buf), outside, false, fr_box_strvalue("test"), NULL);
	TEST_CHECK(slen < 0);
}

/*
 *  Decode / uncompressed length tests
 */

static void test_decode_simple_label(void)
{
	uint8_t const *next;
	ssize_t slen;
	uint8_t pkt[DNS_HDR_LEN + 5];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3;
	pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm';
	pkt[16] = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 5, &next, NULL);
	TEST_CHECK(slen == 3);
	TEST_MSG("Expected 3, got %zd", slen);
	TEST_CHECK(next == pkt + 17);
}

static void test_decode_multi_label(void)
{	
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 17];	/* "www.example.com" */

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3;  memcpy(pkt + 13, "www", 3);
	pkt[16] = 7;  memcpy(pkt + 17, "example", 7);
	pkt[24] = 3;  memcpy(pkt + 25, "com", 3);
	pkt[28] = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 17, &next, NULL);
	TEST_CHECK(slen == 15);
	TEST_MSG("Expected 15, got %zd", slen);
	TEST_CHECK(next == pkt + 29);
}

static void test_decode_root_label(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 1];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 1, &next, NULL);
	TEST_CHECK(slen == 1);
	TEST_MSG("Expected 1, got %zd", slen);
}

static void test_decode_compressed_pointer(void)
{
	ssize_t slen;
	uint8_t const *next;
	fr_dns_labels_t lb;
	uint8_t pkt[DNS_HDR_LEN + 11];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;
	pkt[17] = 3; pkt[18] = 'f'; pkt[19] = 'o'; pkt[20] = 'o';
	pkt[21] = 0xc0; pkt[22] = 0x0c; /* pointer to offset 12 */

	labels_init(&lb, pkt, sizeof(pkt), true);
	test_marker[12] = 1;

	next = pkt + 17;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + 17, 6, &next, &lb);
	TEST_CHECK(slen == 7);
	TEST_MSG("Expected 7, got %zd", slen);
	TEST_CHECK(next == pkt + 23);
}

static void test_decode_forward_pointer_rejected(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 8];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 0xc0; pkt[13] = 17; /* forward pointer */
	pkt[14] = 3; pkt[15] = 'c'; pkt[16] = 'o'; pkt[17] = 'm'; pkt[18] = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 8, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Forward pointer should be rejected, got %zd", slen);
}

static void test_decode_self_pointer_rejected(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 2];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 0xc0; pkt[13] = 12;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 2, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Self-pointer should be rejected, got %zd", slen);
}

static void test_decode_pointer_to_pointer_rejected(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 9];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;
	pkt[17] = 0xc0; pkt[18] = 0x0c;
	pkt[19] = 0xc0; pkt[20] = 0x11; /* pointer to offset 17 (which is a pointer) */

	next = pkt + 19;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + 19, 2, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Pointer-to-pointer should be rejected, got %zd", slen);
}

static void test_decode_invalid_high_bits(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 2];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 0x80; pkt[13] = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 2, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("0x80 high bits should be rejected, got %zd", slen);
}

static void test_decode_label_overflow(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 4];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 10; /* 10 bytes, but only 3 available */
	pkt[13] = 'a'; pkt[14] = 'b'; pkt[15] = 'c';

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 4, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Overflow should be rejected, got %zd", slen);
}

static void test_decode_null_inputs(void)
{
	ssize_t slen;
	uint8_t const *next = NULL;

	slen = fr_dns_label_uncompressed_length(NULL, (uint8_t const *)"x", 1, &next, NULL);
	TEST_CHECK(slen == 0);

	slen = fr_dns_label_uncompressed_length((uint8_t const *)"x", NULL, 1, &next, NULL);
	TEST_CHECK(slen == 0);

	{
		uint8_t pkt[1] = {0};
		slen = fr_dns_label_uncompressed_length(pkt, pkt, 0, &next, NULL);
		TEST_CHECK(slen == 0);
	}

	{
		uint8_t pkt[13];
		memset(pkt, 0, sizeof(pkt));
		slen = fr_dns_label_uncompressed_length(pkt, pkt + 12, 1, NULL, NULL);
		TEST_CHECK(slen == 0);
	}
}

static void test_decode_label_invalid_chars(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 4];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'a'; pkt[14] = ' '; pkt[15] = 'b';

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, 4, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Invalid char in label should be rejected, got %zd", slen);
}

static void test_decode_total_length_exceeds_255(void)
{
	uint8_t const *next;
	ssize_t slen;
	int i;
	uint8_t pkt[DNS_HDR_LEN + 5*(1+52) + 1];
	uint8_t *p = pkt + DNS_HDR_LEN;

	memset(pkt, 0, DNS_HDR_LEN);

	for (i = 0; i < 5; i++) {
		*p++ = 52;
		memset(p, 'a', 52);
		p += 52;
	}
	*p++ = 0x00;

	next = pkt + DNS_HDR_LEN;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN, (size_t)(p - pkt - DNS_HDR_LEN), &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Total length > 255 should be rejected, got %zd", slen);
}

/*
 *  network_verify tests
 */

static void test_verify_simple(void)
{
	ssize_t slen;
	uint8_t pkt[DNS_HDR_LEN + 5];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;

	slen = fr_dns_labels_network_verify(pkt, pkt + DNS_HDR_LEN, 5, pkt + DNS_HDR_LEN, NULL);
	TEST_CHECK(slen > 0);
	TEST_MSG("Expected >0, got %zd", slen);
}

static void test_verify_empty(void)
{
	ssize_t slen;
	uint8_t pkt[DNS_HDR_LEN + 1];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 0x00;

	slen = fr_dns_labels_network_verify(pkt, pkt + DNS_HDR_LEN, 1, pkt + DNS_HDR_LEN, NULL);
	TEST_CHECK(slen > 0);
}

/* ----------------------------------------------------------------
 *  Round-trip tests: encode then decode
 * ---------------------------------------------------------------- */

static void test_roundtrip_simple(void)
{
	ssize_t enc_len, dec_len;
	TALLOC_CTX *ctx = talloc_init("test");
	fr_value_box_t vb_out;
	uint8_t buf[256] = {};

	enc_len = encode_label(buf, sizeof(buf), buf, "example.com", false, NULL);
	TEST_CHECK(enc_len > 0);
	TEST_MSG("encode returned %zd", enc_len);
	if (enc_len <= 0) return;

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, buf, enc_len, buf, false, NULL);
	TEST_CHECK(dec_len > 0);
	TEST_MSG("decode returned %zd", dec_len);

	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, "example.com") == 0);
	TEST_MSG("Expected 'example.com', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

static void test_roundtrip_trailing_dot(void)
{
	ssize_t enc_len, dec_len;
	TALLOC_CTX *ctx = talloc_init("test");
	fr_value_box_t vb_out;
	uint8_t buf[256] = {};

	enc_len = encode_label(buf, sizeof(buf), buf, "example.com.", false, NULL);
	TEST_CHECK(enc_len > 0);
	if (enc_len <= 0) return;

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, buf, enc_len, buf, false, NULL);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, "example.com") == 0);
	TEST_MSG("Expected 'example.com', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

static void test_roundtrip_root(void)
{
	ssize_t enc_len, dec_len;
	TALLOC_CTX *ctx = talloc_init("test");
	fr_value_box_t vb_out;
	uint8_t buf[256] = {};

	enc_len = encode_label(buf, sizeof(buf), buf, ".", false, NULL);
	TEST_CHECK(enc_len == 1);
	if (enc_len <= 0) return;

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, buf, enc_len, buf, false, NULL);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, ".") == 0);
	TEST_MSG("Expected '.', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

static void test_roundtrip_underscore(void)
{
	ssize_t enc_len, dec_len;
	TALLOC_CTX *ctx = talloc_init("test");
	fr_value_box_t vb_out;
	uint8_t buf[256] = {};

	enc_len = encode_label(buf, sizeof(buf), buf, "_tcp.example.com", false, NULL);
	TEST_CHECK(enc_len > 0);

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, buf, enc_len, buf, false, NULL);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, "_tcp.example.com") == 0);
	TEST_MSG("Expected '_tcp.example.com', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

static void test_roundtrip_case_preservation(void)
{
	ssize_t enc_len, dec_len;
	TALLOC_CTX *ctx = talloc_init("test");
	fr_value_box_t vb_out;
	uint8_t buf[256] = {};

	enc_len = encode_label(buf, sizeof(buf), buf, "WWW.Example.COM", false, NULL);
	TEST_CHECK(enc_len > 0);
	if (enc_len <= 0) return;

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, buf, enc_len, buf, false, NULL);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, "WWW.Example.COM") == 0);
	TEST_MSG("Expected 'WWW.Example.COM', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

/*
 *  Compression tests (encoding with compression)
 */

static void test_compress_two_names(void)
{
	ssize_t slen1, slen2;
	fr_dns_labels_t lb;
	uint8_t pkt[256] = {};

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, "example.com", true, &lb);
	TEST_CHECK(slen1 > 0);
	TEST_MSG("First encode: %zd", slen1);

	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, "foo.example.com", true, &lb);
	TEST_CHECK(slen2 > 0);
	TEST_MSG("Second encode: %zd", slen2);

	/*
	 *	Without compression: "foo.example.com" = 17 bytes
	 *	With compression: "foo" (4 bytes) + pointer (2 bytes) = 6 bytes
	 */
	TEST_CHECK(slen2 < 17);
	TEST_MSG("Compressed size %zd should be < 17", slen2);
}

/* ----------------------------------------------------------------
 *  Decode: fr_dns_label_to_value_box error paths
 * ---------------------------------------------------------------- */

static void test_decode_to_value_box_zero_len(void)
{
	fr_value_box_t vb;
	ssize_t slen;
	uint8_t pkt[1] = {};

	slen = fr_dns_label_to_value_box(NULL, &vb, pkt, 0, pkt, false, NULL);
	TEST_CHECK(slen < 0);
}

static void test_decode_to_value_box_label_outside_buf(void)
{
	fr_value_box_t vb;
	ssize_t slen;
	uint8_t other[16];
	uint8_t pkt[16] = {};

	slen = fr_dns_label_to_value_box(NULL, &vb, pkt, sizeof(pkt), other, false, NULL);
	TEST_CHECK(slen < 0);
}

/* ----------------------------------------------------------------
 *  Compression with label tracking (block-based)
 * ---------------------------------------------------------------- */

static void test_labels_block_tracking(void)
{
	ssize_t slen;
	fr_dns_labels_t lb;
	uint8_t pkt[256] = {};

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, "test.example.org", true, &lb);
	TEST_CHECK(slen > 0);
	TEST_MSG("encode returned %zd", slen);

	TEST_CHECK(lb.num >= 1);
	TEST_CHECK(lb.blocks[0].start == DNS_HDR_LEN);
}

static void test_pointer_valid_no_tracking(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 11];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;
	pkt[17] = 3; pkt[18] = 'f'; pkt[19] = 'o'; pkt[20] = 'o';
	pkt[21] = 0xc0; pkt[22] = 0x0c;

	next = pkt + 17;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + 17, 6, &next, NULL);
	TEST_CHECK(slen == 7);
	TEST_MSG("Expected 7, got %zd", slen);
}

static void test_pointer_invalid_with_mark_tracking(void)
{
	ssize_t slen;
	uint8_t const *next;
	fr_dns_labels_t lb;
	uint8_t pkt[DNS_HDR_LEN + 11];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;
	pkt[17] = 3; pkt[18] = 'f'; pkt[19] = 'o'; pkt[20] = 'o';
	pkt[21] = 0xc0; pkt[22] = 0x0c;

	labels_init(&lb, pkt, sizeof(pkt), true);
	/* Do NOT mark offset 12 */

	next = pkt + 17;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + 17, 6, &next, &lb);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Unmarked pointer target should be rejected, got %zd", slen);
}

static void test_pointer_to_zero_label_rejected(void)
{
	ssize_t slen;
	uint8_t const *next;
	uint8_t pkt[DNS_HDR_LEN + 8];

	memset(pkt, 0, DNS_HDR_LEN);
	pkt[12] = 3; pkt[13] = 'c'; pkt[14] = 'o'; pkt[15] = 'm'; pkt[16] = 0x00;
	pkt[17] = 0xc0; pkt[18] = 0x10; /* pointer to offset 16 (0x00 byte) */

	next = pkt + 17;
	slen = fr_dns_label_uncompressed_length(pkt, pkt + 17, 2, &next, NULL);
	TEST_CHECK(slen <= 0);
	TEST_MSG("Pointer to 0x00 should be rejected, got %zd", slen);
}

/*
 *  Encode: max label length (63 bytes exactly)
 */

static void test_encode_max_label_length(void)
{
	ssize_t slen;
	char label[64];
	uint8_t buf[256] = {};

	memset(label, 'a', 63);
	label[63] = '\0';
	slen = encode_label(buf, sizeof(buf), buf, label, false, NULL);
	TEST_CHECK(slen == 65); /* 1 (length) + 63 (data) + 1 (terminator) */
	TEST_MSG("Expected 65, got %zd", slen);
}

static void test_encode_hyphen_and_digits(void)
{
	ssize_t slen;
	uint8_t buf[256] = {};

	slen = encode_label(buf, sizeof(buf), buf, "my-host-01.example.com", false, NULL);
	TEST_CHECK(slen > 0);
	TEST_MSG("Expected >0, got %zd", slen);
}

/* ----------------------------------------------------------------
 *  Roundtrip with compression
 * ---------------------------------------------------------------- */

static void test_roundtrip_compressed(void)
{
	ssize_t slen1, slen2, dec_len;
	ssize_t uncomp_len;
	uint8_t const *next_label;
	fr_value_box_t vb_out;
	fr_dns_labels_t lb;
	TALLOC_CTX *ctx = talloc_init("test");
	uint8_t pkt[256] = {};

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, "example.com", true, &lb);
	TEST_CHECK(slen1 > 0);

	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, "foo.example.com", true, &lb);
	TEST_CHECK(slen2 > 0);

	next_label = pkt + DNS_HDR_LEN + slen1;
	uncomp_len = fr_dns_label_uncompressed_length(pkt, pkt + DNS_HDR_LEN,
						      slen1 + slen2, &next_label, &lb);
	TEST_CHECK(uncomp_len == 15);
	TEST_MSG("Expected 15, got %zd", uncomp_len);

	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, pkt + DNS_HDR_LEN, slen1 + slen2,
					    pkt + DNS_HDR_LEN + slen1, false, &lb);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, "foo.example.com") == 0);
	TEST_MSG("Expected 'foo.example.com', got '%s'", vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

/*
 *  Compression with 62 and 63 byte labels.
 *
 *  These test both <= 63 checks in dns_label_compress():
 *
 *  Path 1: recursive call when the NEXT label after the
 *  current one is still uncompressed.  Tested by encoding "foo.LONG"
 *  where LONG is 62 or 63 bytes - the recursive call to compress LONG
 *  has *next == 62/63.
 *
 *  Path 2: buffer scan where a candidate label is followed
 *  by an uncompressed label of length 62/63.  Tested by encoding
 *  "bar.LONG" first (uncompressed), then "foo.LONG" - during the
 *  scan for "foo", we find "bar" whose next label (*ptr) is 62/63.
 */
static void test_compress_62_byte_label(void)
{
	ssize_t slen1, slen2, dec_len;
	fr_dns_labels_t lb;
	fr_value_box_t vb_out;
	TALLOC_CTX *ctx = talloc_init("test");
	char const *name1 = "bar.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	char const *name2 = "foo.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	uint8_t pkt[512] = {};

	TEST_CHECK(strlen(name1) == 66);
	TEST_CHECK(strlen(name2) == 66);

	labels_init(&lb, pkt, sizeof(pkt), false);

	/* First name goes in uncompressed */
	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, name1, true, &lb);
	TEST_CHECK(slen1 > 0);
	TEST_MSG("First encode: %zd", slen1);

	/*
	 *  Second name should compress the 62-byte suffix.
	 *  Uncompressed would be 4 + 1 + 62 + 1 = 68 bytes.
	 *  Compressed should be "foo" (4 bytes) + pointer (2 bytes) = 6 bytes.
	 */
	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, name2, true, &lb);
	TEST_CHECK(slen2 > 0);
	TEST_CHECK(slen2 < 68);
	TEST_MSG("62-byte label compression: %zd (expected < 68)", slen2);

	/* Round-trip decode to verify correctness */
	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, pkt + DNS_HDR_LEN,
					    slen1 + slen2,
					    pkt + DNS_HDR_LEN + slen1,
					    false, &lb);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, name2) == 0);
	TEST_MSG("Expected '%s', got '%s'", name2, vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

static void test_compress_63_byte_label(void)
{
	ssize_t slen1, slen2, dec_len;
	fr_dns_labels_t lb;
	fr_value_box_t vb_out;
	TALLOC_CTX *ctx = talloc_init("test");
	char long63[64];
	uint8_t pkt[512] = {};

	/*
	 *	The encoder limits non-first labels to 62 bytes (off-by-one in the dot tracking), so we test
	 *	63-byte labels as thue first (and only) label.  Encode a standalone 63-byte label twice; the
	 *	second should compress to a 2-byte pointer.
	 */
	memset(long63, 'a', 63);
	long63[63] = '\0';

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, long63, true, &lb);
	TEST_CHECK(slen1 == 65); /* 1 (length) + 63 (data) + 1 (terminator) */
	TEST_MSG("First encode: %zd", slen1);

	/* Duplicate name should fully compress to a 2-byte pointer */
	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, long63, true, &lb);
	TEST_CHECK(slen2 > 0);
	TEST_CHECK(slen2 == 2);
	TEST_MSG("63-byte duplicate compression: %zd (expected 2)", slen2);

	/* Round-trip decode the compressed entry */
	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, pkt + DNS_HDR_LEN,
					    slen1 + slen2,
					    pkt + DNS_HDR_LEN + slen1,
					    false, &lb);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, long63) == 0);
	TEST_MSG("Expected '%s', got '%s'", long63, vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

/*
 *  The same tests, but with a three-label name so that the 62/63-byte
 *  label is a middle suffix.  This exercises the Path 2 more
 *  directly: when scanning the buffer, the candidate "bar" is
 *  followed by an uncompressed 62/63-byte label which IS the suffix
 *  pointer target.
 */
static void test_compress_middle_62_byte_label(void)
{
	ssize_t slen1, slen2;
	fr_dns_labels_t lb;
	char const *name1 = "bar.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";
	char const *name2 = "foo.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";
	uint8_t pkt[512] = {};

	TEST_CHECK(strlen(name1) == 70); /* "bar." + 62 + ".com"*/
	TEST_CHECK(strlen(name2) == 70);

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, name1, true, &lb);
	TEST_CHECK(slen1 > 0);
	TEST_MSG("First encode: %zd", slen1);

	/*
	 *	Compression produces "foo" + pointer to the "aaa...com" suffix.  When scanning for "foo" in
	 *	the buffer, the code finds "bar" whose next label is the 62-byte 'a' label (*ptr == 62).  The
	 *	<= 63 check at line 523 allows this to be recognized as the suffix target.
	 */
	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, name2, true, &lb);
	TEST_CHECK(slen2 > 0);
	TEST_CHECK(slen2 < slen1);
	TEST_MSG("Compressed size %zd should be < %zd", slen2, slen1);
}

static void test_compress_middle_63_byte_label(void)
{
	ssize_t slen1, slen2, dec_len;
	fr_dns_labels_t lb;
	fr_value_box_t vb_out;
	TALLOC_CTX *ctx = talloc_init("test");
	char const *name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";
	uint8_t pkt[512] = {};

	/*
	 *	Test compression of a multi-label name where the first label is 63 bytes.  Encode "<63
	 *	a's>.com" twice.
	 *
	 *	On the second encode, dns_label_compress recursively compresses "com" first, then scans the
	 *	buffer for the 63-byte label.  The buffer scan at checks *ptr <= 63 where ptr points to the
	 *	"com" label (3 bytes) after the 63-byte label in the first entry.  It then verifies ptr ==
	 *	suffix (both point to "com" in name1) and compares the 63-byte labels.
	 */
	TEST_CHECK(strlen(name) == 67);

	labels_init(&lb, pkt, sizeof(pkt), false);

	slen1 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN, name, true, &lb);
	TEST_CHECK(slen1 > 0);
	TEST_MSG("First encode: %zd", slen1);

	/* Duplicate should fully compress to a 2-byte pointer */
	slen2 = encode_label(pkt, sizeof(pkt), pkt + DNS_HDR_LEN + slen1, name, true, &lb);
	TEST_CHECK(slen2 > 0);
	TEST_CHECK(slen2 == 2);
	TEST_MSG("Compressed size %zd (expected 2)", slen2);

	/* Round-trip decode */
	dec_len = fr_dns_label_to_value_box(ctx, &vb_out, pkt + DNS_HDR_LEN,
					    slen1 + slen2,
					    pkt + DNS_HDR_LEN + slen1,
					    false, &lb);
	TEST_CHECK(dec_len > 0);
	TEST_CHECK(vb_out.type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(vb_out.vb_strvalue, name) == 0);
	TEST_MSG("Expected '%s', got '%s'", name, vb_out.vb_strvalue);

	fr_value_box_clear(&vb_out);
	talloc_free(ctx);
}

TEST_LIST = {
	/* Encoding */
	{ "encode_empty_string",		test_encode_empty_string },
	{ "encode_root_dot",			test_encode_root_dot },
	{ "encode_simple_label",		test_encode_simple_label },
	{ "encode_multi_label",			test_encode_multi_label },
	{ "encode_trailing_dot",		test_encode_trailing_dot },
	{ "encode_underscore_prefix",		test_encode_underscore_prefix },
	{ "encode_max_label_length",		test_encode_max_label_length },
	{ "encode_hyphen_and_digits",		test_encode_hyphen_and_digits },

	/* Encoding errors */
	{ "encode_null_inputs",			test_encode_null_inputs },
	{ "encode_non_string_type",		test_encode_non_string_type },
	{ "encode_invalid_chars",		test_encode_invalid_chars },
	{ "encode_double_dot",			test_encode_double_dot },
	{ "encode_leading_dot",			test_encode_leading_dot },
	{ "encode_label_too_long",		test_encode_label_too_long },
	{ "encode_buffer_too_small",		test_encode_buffer_too_small },
	{ "encode_where_outside_buf",		test_encode_where_outside_buf },

	/* Decoding / uncompressed length */
	{ "decode_simple_label",		test_decode_simple_label },
	{ "decode_multi_label",			test_decode_multi_label },
	{ "decode_root_label",			test_decode_root_label },
	{ "decode_compressed_pointer",		test_decode_compressed_pointer },
	{ "decode_null_inputs",			test_decode_null_inputs },
	{ "decode_label_invalid_chars",		test_decode_label_invalid_chars },
	{ "decode_total_length_exceeds_255",	test_decode_total_length_exceeds_255 },

	/* Decode error paths */
	{ "decode_forward_pointer_rejected",	test_decode_forward_pointer_rejected },
	{ "decode_self_pointer_rejected",	test_decode_self_pointer_rejected },
	{ "decode_pointer_to_pointer_rejected",	test_decode_pointer_to_pointer_rejected },
	{ "decode_invalid_high_bits",		test_decode_invalid_high_bits },
	{ "decode_label_overflow",		test_decode_label_overflow },
	{ "decode_pointer_to_zero_rejected",	test_pointer_to_zero_label_rejected },

	/* Network verify */
	{ "verify_simple",			test_verify_simple },
	{ "verify_empty",			test_verify_empty },

	/* Value box decode errors */
	{ "decode_vb_zero_len",			test_decode_to_value_box_zero_len },
	{ "decode_vb_label_outside_buf",	test_decode_to_value_box_label_outside_buf },

	/* Pointer tracking */
	{ "pointer_valid_no_tracking",		test_pointer_valid_no_tracking },
	{ "pointer_invalid_with_mark",		test_pointer_invalid_with_mark_tracking },

	/* Label block tracking */
	{ "labels_block_tracking",		test_labels_block_tracking },

	/* Round-trip */
	{ "roundtrip_simple",			test_roundtrip_simple },
	{ "roundtrip_trailing_dot",		test_roundtrip_trailing_dot },
	{ "roundtrip_root",			test_roundtrip_root },
	{ "roundtrip_underscore",		test_roundtrip_underscore },
	{ "roundtrip_case_preservation",	test_roundtrip_case_preservation },

	/* Compression */
	{ "compress_two_names",			test_compress_two_names },
	{ "roundtrip_compressed",		test_roundtrip_compressed },
	{ "compress_62_byte_label",		test_compress_62_byte_label },
	{ "compress_63_byte_label",		test_compress_63_byte_label },
	{ "compress_middle_62_byte_label",	test_compress_middle_62_byte_label },
	{ "compress_middle_63_byte_label",	test_compress_middle_63_byte_label },

	TEST_TERMINATOR
};
