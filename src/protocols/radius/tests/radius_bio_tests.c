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

/** Tests for the RADIUS bio verify callbacks
 *
 * The verify callbacks are fr_radius_bio_verify() for stream sockets, and
 * fr_radius_bio_verify_datagram() for datagram sockets.  The tests call
 * the callbacks directly, and the stream callback also through a memory bio.
 *
 * @file src/protocols/radius/tests/radius_bio_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/mem.h>
#include <freeradius-devel/bio/pipe.h>
#include <freeradius-devel/radius/bio.h>

#define MESSAGE_AUTHENTICATOR	80

#define MAX_PACKET_SIZE		4096

static int	cb_noop(fr_bio_t *bio)		{ (void) bio; return 0; }
static void	cb_noop_void(fr_bio_t *bio)	{ (void) bio; }

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_noop,
	.eof		= cb_noop_void,
};

/** Make a verify context which allows Access-Request and Access-Accept.
 */
static fr_radius_bio_verify_t test_ctx(void)
{
	return (fr_radius_bio_verify_t) {
		.max_attributes = 200,
		.max_packet_size = MAX_PACKET_SIZE,
		.allowed = {
			[FR_RADIUS_CODE_ACCESS_REQUEST] = true,
			[FR_RADIUS_CODE_ACCESS_ACCEPT] = true,
		},
	};
}

/** Build a packet with a header, and the given attributes.
 *
 * @param[out] out	where to write the packet.
 * @param[in] code	of the packet.
 * @param[in] attrs	to copy after the header, which may be NULL.
 * @param[in] attrs_len	length of the attributes.
 * @return the length of the packet.
 */
static size_t make_packet(uint8_t *out, uint8_t code, uint8_t const *attrs, size_t attrs_len)
{
	size_t len = RADIUS_HEADER_LENGTH + attrs_len;

	memset(out, 0, len);
	out[0] = code;
	out[1] = 1;
	out[2] = len >> 8;
	out[3] = len & 0xff;

	if (attrs_len) memcpy(out + RADIUS_HEADER_LENGTH, attrs, attrs_len);

	return len;
}

/** Make a packet whose attributes are a User-Name of "ab".
 */
static size_t make_valid(uint8_t *out, uint8_t code)
{
	static uint8_t const user_name[] = { 1, 4, 'a', 'b' };

	return make_packet(out, code, user_name, sizeof(user_name));
}

/** Call the stream verify callback on a buffer holding in_buffer bytes.
 */
static fr_bio_verify_action_t stream_verify(fr_radius_bio_verify_t *ctx, uint8_t const *buf, size_t in_buffer,
					    size_t *size_out)
{
	fr_bio_t	dummy = {};
	size_t		size = in_buffer;
	fr_bio_verify_action_t action;

	action = fr_radius_bio_verify(&dummy, ctx, NULL, buf, &size);
	if (size_out) *size_out = size;

	return action;
}

/** Call the datagram verify callback on a buffer holding in_buffer bytes.
 */
static fr_bio_verify_action_t datagram_verify(fr_radius_bio_verify_t *ctx, uint8_t const *buf, size_t in_buffer,
					      size_t *size_out)
{
	fr_bio_t	dummy = {};
	size_t		size = in_buffer;
	fr_bio_verify_action_t action;

	action = fr_radius_bio_verify_datagram(&dummy, ctx, NULL, buf, &size);
	if (size_out) *size_out = size;

	return action;
}

/*
 *	Stream sockets, calling the callback directly.
 */

/** A buffer which holds less than a header asks for the header.
 */
static void test_stream_short_buffer(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			size;
	size_t			in_buffer;

	(void) make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);

	/*
	 *	3 is less than the length field, 4 is the length field alone, and 19 is one byte short of a
	 *	header.  None of them is an error, as TCP can split a packet anywhere.
	 */
	for (in_buffer = 0; in_buffer < RADIUS_HEADER_LENGTH; in_buffer++) {
		TEST_CASE("less than a header");
		TEST_MSG("in_buffer = %zu", in_buffer);
		TEST_CHECK(stream_verify(&ctx, buf, in_buffer, &size) == FR_BIO_VERIFY_WANT_MORE);
		TEST_CHECK_LEN(size, RADIUS_HEADER_LENGTH);
	}
}

/** A complete packet is returned, and only that packet.
 */
static void test_stream_one_packet(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;

	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);

	TEST_CASE("exactly one packet");
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);

	TEST_CASE("one packet, and the start of another");
	(void) make_valid(buf + len, FR_RADIUS_CODE_ACCESS_ACCEPT);
	TEST_CHECK(stream_verify(&ctx, buf, len + 7, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);

	TEST_CASE("two packets");
	TEST_CHECK(stream_verify(&ctx, buf, len * 2, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);
}

/** A packet which is not all in the buffer asks for the rest of the packet.
 */
static void test_stream_partial_packet(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;

	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);

	TEST_CASE("the header, and no attributes");
	TEST_CHECK(stream_verify(&ctx, buf, RADIUS_HEADER_LENGTH, &size) == FR_BIO_VERIFY_WANT_MORE);
	TEST_CHECK_LEN(size, len);

	TEST_CASE("all but the last byte");
	TEST_CHECK(stream_verify(&ctx, buf, len - 1, &size) == FR_BIO_VERIFY_WANT_MORE);
	TEST_CHECK_LEN(size, len);
}

/** A packet with a code which the module does not know is skipped, and the packets after it are kept.
 */
static void test_stream_unknown_code(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;
	uint8_t			code;

	len = make_valid(buf, 0);
	(void) make_valid(buf + len, FR_RADIUS_CODE_ACCESS_ACCEPT);

	/*
	 *	Code 0 is invalid, FR_RADIUS_CODE_MAX is the first code which is too large, and 255 is the
	 *	largest value.
	 */
	for (code = 0; ; code = (code == 0) ? FR_RADIUS_CODE_MAX : 255) {
		TEST_CASE("unknown code, followed by a valid packet");
		TEST_MSG("code = %u", code);
		buf[0] = code;
		TEST_CHECK(stream_verify(&ctx, buf, len * 2, &size) == FR_BIO_VERIFY_DISCARD);
		TEST_CHECK_LEN(size, len);

		if (code == 255) break;
	}
}

/** A packet with a code which is known, but not allowed, is skipped.
 */
static void test_stream_not_allowed(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;

	len = make_valid(buf, FR_RADIUS_CODE_ACCOUNTING_RESPONSE);
	(void) make_valid(buf + len, FR_RADIUS_CODE_ACCESS_ACCEPT);

	TEST_CHECK(stream_verify(&ctx, buf, len * 2, &size) == FR_BIO_VERIFY_DISCARD);
	TEST_CHECK_LEN(size, len);
}

/** A packet with more attributes than the limit is skipped, and the packets after it are kept.
 */
static void test_stream_too_many_attributes(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	uint8_t const		attrs[] = { 1, 3, 'a', 1, 3, 'b', 1, 3, 'c' };
	size_t			len, size;

	ctx.max_attributes = 2;

	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, attrs, sizeof(attrs));
	(void) make_valid(buf + len, FR_RADIUS_CODE_ACCESS_ACCEPT);

	TEST_CASE("three attributes, limit of two");
	TEST_CHECK(stream_verify(&ctx, buf, len * 2, &size) == FR_BIO_VERIFY_DISCARD);
	TEST_CHECK_LEN(size, len);

	TEST_CASE("two attributes, limit of two");
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, attrs, 6);
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);
}

/** Errors which leave the stream without a known start of the next packet close the connection.
 */
static void test_stream_fatal(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;
	uint8_t const		*attrs;

	struct {
		char const	*name;
		uint8_t const	*attrs;
		size_t		len;
	} const			*p, bad[] = {
#define BAD(_name, ...) { _name, (uint8_t const[]) { __VA_ARGS__ }, sizeof((uint8_t const[]) { __VA_ARGS__ }) }
		BAD("attribute number zero", 0, 3, 'a'),
		BAD("attribute length of zero", 1, 0, 'a'),
		BAD("attribute length of one", 1, 1, 'a'),
		BAD("attribute runs past the packet", 1, 9, 'a'),
		BAD("a single byte after the attributes", 1, 3, 'a', 1),
		BAD("Message-Authenticator is too short", MESSAGE_AUTHENTICATOR, 10, 0, 0, 0, 0, 0, 0, 0, 0),
		BAD("two Message-Authenticators",
		    MESSAGE_AUTHENTICATOR, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		    MESSAGE_AUTHENTICATOR, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
#undef BAD
	};

	for (p = bad; p < (bad + NUM_ELEMENTS(bad)); p++) {
		len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, p->attrs, p->len);

		TEST_CASE(p->name);
		TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_ERROR_CLOSE);
	}

	TEST_CASE("length field is less than a header");
	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);
	buf[2] = 0;
	buf[3] = RADIUS_HEADER_LENGTH - 1;
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_ERROR_CLOSE);

	TEST_CASE("Message-Authenticator is required, and missing");
	ctx.require_message_authenticator = true;
	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_ACCEPT);
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_ERROR_CLOSE);

	TEST_CASE("Message-Authenticator is required, and present");
	attrs = (uint8_t const[]) { MESSAGE_AUTHENTICATOR, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_ACCEPT, attrs, 18);
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);
}

/** A packet which is larger than the module allows closes the connection, even when only the header has arrived.
 */
static void test_stream_too_large(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	uint8_t			attrs[200];
	size_t			len, size, i;

	ctx.max_packet_size = 64;

	for (i = 0; i < sizeof(attrs); i += 4) {
		attrs[i] = 1;
		attrs[i + 1] = 4;
		attrs[i + 2] = 'a';
		attrs[i + 3] = 'b';
	}

	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, attrs, sizeof(attrs));
	TEST_CHECK(len > ctx.max_packet_size);

	TEST_CASE("only the header of a large packet");
	TEST_CHECK(stream_verify(&ctx, buf, RADIUS_HEADER_LENGTH, &size) == FR_BIO_VERIFY_ERROR_CLOSE);

	TEST_CASE("all of a large packet");
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_ERROR_CLOSE);

	TEST_CASE("a packet of exactly the maximum");
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, attrs, ctx.max_packet_size - RADIUS_HEADER_LENGTH);
	TEST_CHECK_LEN(len, ctx.max_packet_size);
	TEST_CHECK(stream_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);
}

/*
 *	Datagram sockets, calling the callback directly.
 */

/** A datagram holds one packet, and trailing bytes are padding.
 */
static void test_datagram_one_packet(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	size_t			len, size;

	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);

	TEST_CASE("exactly one packet");
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);

	TEST_CASE("padding after the packet is not part of the packet");
	memset(buf + len, 0xff, 9);
	TEST_CHECK(datagram_verify(&ctx, buf, len + 9, &size) == FR_BIO_VERIFY_OK);
	TEST_CHECK_LEN(size, len);
}

/** A datagram which is not a good packet is discarded, and never closes the socket.
 */
static void test_datagram_discard(void)
{
	fr_radius_bio_verify_t	ctx = test_ctx();
	uint8_t			buf[MAX_PACKET_SIZE];
	uint8_t const		attrs[] = { 1, 3, 'a', 1, 3, 'b', 1, 3, 'c' };
	size_t			len, size;

	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);

	TEST_CASE("less than a header");
	TEST_CHECK(datagram_verify(&ctx, buf, RADIUS_HEADER_LENGTH - 1, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("the length field is larger than the datagram");
	TEST_CHECK(datagram_verify(&ctx, buf, len - 1, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("the length field is less than a header");
	buf[2] = 0;
	buf[3] = RADIUS_HEADER_LENGTH - 1;
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("unknown code");
	len = make_valid(buf, 0);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);
	len = make_valid(buf, FR_RADIUS_CODE_MAX);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("code which is not allowed");
	len = make_valid(buf, FR_RADIUS_CODE_ACCOUNTING_RESPONSE);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("bad attribute");
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, (uint8_t const[]) { 1, 9, 'a' }, 3);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("Message-Authenticator is too short");
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST,
			  (uint8_t const[]) { MESSAGE_AUTHENTICATOR, 3, 0 }, 3);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);

	TEST_CASE("Message-Authenticator is required, and missing");
	ctx.require_message_authenticator = true;
	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);
	ctx.require_message_authenticator = false;

	TEST_CASE("too many attributes");
	ctx.max_attributes = 2;
	len = make_packet(buf, FR_RADIUS_CODE_ACCESS_REQUEST, attrs, sizeof(attrs));
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);
	ctx.max_attributes = 200;

	TEST_CASE("larger than the maximum");
	ctx.max_packet_size = 20;
	len = make_valid(buf, FR_RADIUS_CODE_ACCESS_REQUEST);
	TEST_CHECK(datagram_verify(&ctx, buf, len, &size) == FR_BIO_VERIFY_DISCARD);
}

/*
 *	Stream sockets, through a memory bio.
 */

/** A memory bio in front of a pipe, which stands in for the network.
 */
static fr_bio_t *test_mem_alloc(TALLOC_CTX *ctx, fr_bio_t **source_p, fr_radius_bio_verify_t *vctx)
{
	fr_bio_t *mem, *source;

	source = fr_bio_pipe_alloc(ctx, &test_cb, 1024);
	if (!source) return NULL;

	mem = fr_bio_mem_alloc(ctx, 1024, 0, source);
	if (!mem) return NULL;

	if (fr_bio_mem_set_verify(mem, fr_radius_bio_verify, vctx, false) < 0) return NULL;

	*source_p = source;
	return mem;
}

/** Put bytes where the memory bio's reads will find them.
 */
static ssize_t test_source_write(fr_bio_t *source, uint8_t const *data, size_t size)
{
	return source->write(source, NULL, data, size);
}

/** A packet which the module does not accept does not take the packets after it.
 */
static void test_mem_unknown_code_keeps_next_packet(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_radius_bio_verify_t	vctx = test_ctx();
	fr_bio_t		*mem, *source;
	uint8_t			in[MAX_PACKET_SIZE], good[MAX_PACKET_SIZE], out[MAX_PACKET_SIZE];
	size_t			len;
	ssize_t			slen;

	mem = test_mem_alloc(ctx, &source, &vctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	len = make_valid(in, 200);
	(void) make_valid(in + len, FR_RADIUS_CODE_ACCESS_ACCEPT);
	(void) make_valid(good, FR_RADIUS_CODE_ACCESS_ACCEPT);
	TEST_CHECK_SLEN(test_source_write(source, in, len * 2), (ssize_t) (len * 2));

	TEST_CASE("the valid packet is returned");
	slen = fr_bio_read(mem, NULL, out, sizeof(out));
	TEST_CHECK_SLEN(slen, (ssize_t) len);
	if (slen == (ssize_t) len) TEST_CHECK(memcmp(out, good, len) == 0);

	TEST_CASE("nothing else is left");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), 0);

done:
	talloc_free(ctx);
}

/** A packet which arrives in pieces is returned when the packet is complete, and the connection stays open.
 */
static void test_mem_split_packet(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_radius_bio_verify_t	vctx = test_ctx();
	fr_bio_t		*mem, *source;
	uint8_t			in[MAX_PACKET_SIZE], out[MAX_PACKET_SIZE];
	size_t			len;

	mem = test_mem_alloc(ctx, &source, &vctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	len = make_valid(in, FR_RADIUS_CODE_ACCESS_ACCEPT);

	/*
	 *	The first piece is part of the header, and the second piece ends in the attributes.
	 */
	TEST_CHECK_SLEN(test_source_write(source, in, 10), 10);

	TEST_CASE("part of the header");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), 0);

	TEST_CHECK_SLEN(test_source_write(source, in + 10, len - 11), (ssize_t) (len - 11));

	TEST_CASE("all but the last byte");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), 0);

	TEST_CHECK_SLEN(test_source_write(source, in + len - 1, 1), 1);

	TEST_CASE("the whole packet");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), (ssize_t) len);
	TEST_CHECK(memcmp(out, in, len) == 0);

done:
	talloc_free(ctx);
}

/** Packets which arrive together are returned one at a time.
 */
static void test_mem_two_packets(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_radius_bio_verify_t	vctx = test_ctx();
	fr_bio_t		*mem, *source;
	uint8_t			in[MAX_PACKET_SIZE], out[MAX_PACKET_SIZE];
	size_t			len;

	mem = test_mem_alloc(ctx, &source, &vctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	len = make_valid(in, FR_RADIUS_CODE_ACCESS_ACCEPT);
	(void) make_valid(in + len, FR_RADIUS_CODE_ACCESS_REQUEST);
	TEST_CHECK_SLEN(test_source_write(source, in, len * 2), (ssize_t) (len * 2));

	TEST_CASE("first packet");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), (ssize_t) len);
	TEST_CHECK(memcmp(out, in, len) == 0);

	TEST_CASE("second packet");
	TEST_CHECK_SLEN(fr_bio_read(mem, NULL, out, sizeof(out)), (ssize_t) len);
	TEST_CHECK(memcmp(out, in + len, len) == 0);

done:
	talloc_free(ctx);
}

/** A packet which cannot be skipped fails the read.
 */
static void test_mem_fatal(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_radius_bio_verify_t	vctx = test_ctx();
	fr_bio_t		*mem, *source;
	uint8_t			in[MAX_PACKET_SIZE], out[MAX_PACKET_SIZE];
	size_t			len;

	mem = test_mem_alloc(ctx, &source, &vctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	len = make_packet(in, FR_RADIUS_CODE_ACCESS_REQUEST, (uint8_t const[]) { 1, 9, 'a' }, 3);
	TEST_CHECK_SLEN(test_source_write(source, in, len), (ssize_t) len);

	TEST_CASE("an attribute which runs past the packet");
	TEST_CHECK(fr_bio_read(mem, NULL, out, sizeof(out)) < 0);

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "stream_short_buffer",		test_stream_short_buffer },
	{ "stream_one_packet",			test_stream_one_packet },
	{ "stream_partial_packet",		test_stream_partial_packet },
	{ "stream_unknown_code",		test_stream_unknown_code },
	{ "stream_not_allowed",			test_stream_not_allowed },
	{ "stream_too_many_attributes",		test_stream_too_many_attributes },
	{ "stream_fatal",			test_stream_fatal },
	{ "stream_too_large",			test_stream_too_large },
	{ "datagram_one_packet",		test_datagram_one_packet },
	{ "datagram_discard",			test_datagram_discard },
	{ "mem_unknown_code_keeps_next_packet",	test_mem_unknown_code_keeps_next_packet },
	{ "mem_split_packet",			test_mem_split_packet },
	{ "mem_two_packets",			test_mem_two_packets },
	{ "mem_fatal",				test_mem_fatal },
	{ NULL, NULL }
};
