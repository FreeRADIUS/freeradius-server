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

/** Tests for the memory bio
 *
 * @file src/lib/bio/test/bio_mem_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/mem.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/pipe.h>

static int	cb_noop(fr_bio_t *bio)		{ (void) bio; return 0; }
static void	cb_noop_void(fr_bio_t *bio)	{ (void) bio; }

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_noop,
	.eof		= cb_noop_void,
};

/** Framing for the tests: the first byte of a packet is its total length.
 */
typedef struct {
	bool	fail;			//!< return ERROR_CLOSE for the next packet
} test_verify_ctx_t;

static fr_bio_verify_action_t test_verify(UNUSED fr_bio_t *bio, void *verify_ctx, UNUSED void *packet_ctx,
					  const void *buffer, size_t *size)
{
	test_verify_ctx_t	*tctx = verify_ctx;
	uint8_t const		*p = buffer;

	if (tctx->fail) return FR_BIO_VERIFY_ERROR_CLOSE;

	if (*size < 1) {
		*size = 1;
		return FR_BIO_VERIFY_WANT_MORE;
	}

	if (*size < (size_t) p[0]) {
		*size = p[0];
		return FR_BIO_VERIFY_WANT_MORE;
	}

	*size = p[0];
	return FR_BIO_VERIFY_OK;
}

/** Put bytes where the memory bio's reads will find them.
 *
 *  fr_bio_write() requires the head of a chain, and the source is the tail, so this calls the
 *  source's own write routine.
 */
static ssize_t test_source_write(fr_bio_t *source, char const *data, size_t size)
{
	return source->write(source, NULL, data, size);
}

/** A memory bio in front of a pipe, which stands in for the network.
 *
 *  Writing to the pipe puts bytes where the memory bio's reads will find them.
 */
static fr_bio_t *test_mem_alloc(TALLOC_CTX *ctx, fr_bio_t **source_p, test_verify_ctx_t *tctx)
{
	fr_bio_t *mem, *source;

	source = fr_bio_pipe_alloc(ctx, &test_cb, 1024);
	if (!source) return NULL;

	mem = fr_bio_mem_alloc(ctx, 1024, 0, source);
	if (!mem) return NULL;

	if (tctx && (fr_bio_mem_set_verify(mem, test_verify, tctx, false) < 0)) return NULL;

	if (source_p) *source_p = source;
	return mem;
}

/** A complete packet is returned, and only one packet at a time.
 */
static void test_verify_one_packet(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	test_verify_ctx_t	tctx = {};
	fr_bio_t		*mem, *source;
	uint8_t			buf[64];
	ssize_t			slen;

	mem = test_mem_alloc(ctx, &source, &tctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CHECK_RET((int) test_source_write(source, "\x05""abcd", 5), 5);

	TEST_CASE("one whole packet comes back");
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(buf, "\x05""abcd", 5) == 0);

	TEST_CASE("there is nothing else to read");
	TEST_CHECK_RET((int) fr_bio_read(mem, NULL, buf, sizeof(buf)), 0);

done:
	talloc_free(ctx);
}

/** A packet split across two reads is reassembled.
 */
static void test_verify_partial_packet(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	test_verify_ctx_t	tctx = {};
	fr_bio_t		*mem, *source;
	uint8_t			buf[64];
	ssize_t			slen;

	mem = test_mem_alloc(ctx, &source, &tctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CASE("half a packet is not a packet");
	TEST_CHECK_RET((int) test_source_write(source, "\x05""ab", 3), 3);
	TEST_CHECK_RET((int) fr_bio_read(mem, NULL, buf, sizeof(buf)), 0);

	TEST_CASE("the rest of it completes the packet");
	TEST_CHECK_RET((int) test_source_write(source, "cd", 2), 2);
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(buf, "\x05""abcd", 5) == 0);

done:
	talloc_free(ctx);
}

/** Pipelined packets: a buffer holding more than one packet must still return the first.
 *
 *  mem.md finding 1.  The second path used to compare the whole buffer against the caller's size,
 *  and return BUFFER_TOO_SMALL although a complete packet was sitting at the front.
 */
static void test_verify_pipelined(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	test_verify_ctx_t	tctx = {};
	fr_bio_t		*mem, *source;
	uint8_t			buf[5];
	ssize_t			slen;

	mem = test_mem_alloc(ctx, &source, &tctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CASE("two packets arrive in one go");
	TEST_CHECK_RET((int) test_source_write(source, "\x05""abcd" "\x05""efgh", 10), 10);

	TEST_CASE("a one-packet buffer gets the first packet, not an error");
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_MSG("returned %zd (%s)", slen, slen < 0 ? fr_bio_strerror(slen) : "no error");
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(buf, "\x05""abcd", 5) == 0);

	TEST_CASE("and the second packet on the next read");
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(buf, "\x05""efgh", 5) == 0);

done:
	talloc_free(ctx);
}

/** A caller buffer smaller than the packet is an error, and loses nothing.
 */
static void test_verify_buffer_too_small(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	test_verify_ctx_t	tctx = {};
	fr_bio_t		*mem, *source;
	uint8_t			small[3], big[64];
	ssize_t			slen;

	mem = test_mem_alloc(ctx, &source, &tctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CHECK_RET((int) test_source_write(source, "\x05""abcd", 5), 5);

	TEST_CASE("too small a buffer is reported as such");
	TEST_CHECK(fr_bio_read(mem, NULL, small, sizeof(small)) == fr_bio_error(BUFFER_TOO_SMALL));

	TEST_CASE("and the packet is still there for a bigger one");
	slen = fr_bio_read(mem, NULL, big, sizeof(big));
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(big, "\x05""abcd", 5) == 0);

done:
	talloc_free(ctx);
}

/** A verify function which says "close" shuts the chain down.
 */
static void test_verify_error_close(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	test_verify_ctx_t	tctx = {};
	fr_bio_t		*mem, *source;
	uint8_t			buf[64];

	mem = test_mem_alloc(ctx, &source, &tctx);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CHECK_RET((int) test_source_write(source, "\x05""abcd", 5), 5);
	tctx.fail = true;

	TEST_CASE("a verify failure is reported as one");
	TEST_CHECK(fr_bio_read(mem, NULL, buf, sizeof(buf)) == fr_bio_error(VERIFY));

	TEST_CASE("and the chain is shut down");
	TEST_CHECK(fr_bio_read(mem, NULL, buf, sizeof(buf)) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

/** Without a verify function the bio is a plain buffer, and hands back what it has.
 *
 *  mem.md finding 9.  A zero from the next bio means no more is coming, and the bytes already
 *  buffered still belong to the application.
 */
static void test_buffered_read_drains(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*mem, *source;
	uint8_t		buf[64];
	ssize_t		slen;

	mem = test_mem_alloc(ctx, &source, NULL);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CHECK_RET((int) test_source_write(source, "abcde", 5), 5);

	TEST_CASE("a small read buffers the rest");
	slen = fr_bio_read(mem, NULL, buf, 2);
	TEST_CHECK_RET((int) slen, 2);
	if (slen == 2) TEST_CHECK(memcmp(buf, "ab", 2) == 0);

	TEST_CASE("asking for more than is left still returns what is left");
	TEST_MSG("the source has nothing more, but three bytes are buffered");
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 3);
	if (slen == 3) TEST_CHECK(memcmp(buf, "cde", 3) == 0);

	TEST_CASE("and then there is nothing");
	TEST_CHECK_RET((int) fr_bio_read(mem, NULL, buf, sizeof(buf)), 0);

done:
	talloc_free(ctx);
}

/** A stub transport which fails recoverably or fatally, as each test chooses.
 *
 *  On a recoverable failure, the stub returns an error and changes nothing else.  On a fatal failure,
 *  the stub first shuts the chain down, as the fd bio does.  Only the failing bio decides whether a
 *  failure is recoverable or fatal.
 */
typedef struct {
	FR_BIO_COMMON;
	bool		data_sent;		//!< the first read has returned "abcde"
	bool		fatal;			//!< shut the chain down before failing
} stub_t;

static int	shutdown_count;

static int	cb_shutdown(fr_bio_t *bio)	{ (void) bio; shutdown_count++; return 0; }

static fr_bio_cb_funcs_t stub_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_noop,
	.eof		= cb_noop_void,
	.shutdown	= cb_shutdown,
};

/** Return "abcde" once, and fail every read after that.
 */
static ssize_t stub_read(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	stub_t *stub = (stub_t *) bio;

	if (stub->data_sent || (size < 5)) {
		if (stub->fatal) (void) fr_bio_shutdown(bio);

		fr_strerror_const("stub read failure");
		return fr_bio_error(GENERIC);
	}

	stub->data_sent = true;
	memcpy(buffer, "abcde", 5);
	return 5;
}

static ssize_t stub_write_fail(fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	stub_t *stub = (stub_t *) bio;

	if (stub->fatal) (void) fr_bio_shutdown(bio);

	fr_strerror_const("stub write failure");
	return fr_bio_error(GENERIC);
}

/** Accept one byte of each write, so the memory bio buffers the rest.
 */
static ssize_t stub_write_one(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	return 1;
}

/** Accept every write in full.
 */
static ssize_t stub_write_all(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, size_t size)
{
	return size;
}

static fr_bio_t *stub_alloc(TALLOC_CTX *ctx)
{
	stub_t *stub;

	shutdown_count = 0;

	stub = talloc_zero(ctx, stub_t);
	if (!stub) return NULL;

	stub->bio.read = stub_read;
	stub->bio.write = stub_write_fail;

	return &stub->bio;
}

/** The memory bio passes a recoverable write error up to the application, and keeps working.
 */
static void test_recoverable_write_passes_up(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*mem, *stub;

	stub = stub_alloc(ctx);
	TEST_CHECK(stub != NULL);
	if (!stub) goto done;

	mem = fr_bio_mem_alloc(ctx, 1024, 1024, stub);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	fr_bio_cb_set(mem, &stub_cb);

	TEST_CASE("the write gets the error from the stub");
	TEST_CHECK(fr_bio_write(mem, NULL, "x", 1) == fr_bio_error(GENERIC));

	TEST_CASE("the memory bio does not shut the chain down");
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("the next write reaches the stub again");
	stub->write = stub_write_all;
	TEST_CHECK_RET((int) fr_bio_write(mem, NULL, "x", 1), 1);

done:
	talloc_free(ctx);
}

/** The memory bio passes a recoverable flush error up to the application, and keeps the buffered data.
 */
static void test_recoverable_flush_passes_up(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*mem, *stub;

	stub = stub_alloc(ctx);
	TEST_CHECK(stub != NULL);
	if (!stub) goto done;

	mem = fr_bio_mem_alloc(ctx, 1024, 1024, stub);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	fr_bio_cb_set(mem, &stub_cb);

	TEST_CASE("a partial write leaves data in the write buffer");
	stub->write = stub_write_one;
	TEST_CHECK_RET((int) fr_bio_write(mem, NULL, "hello", 5), 5);

	TEST_CASE("the flush gets the error from the stub");
	stub->write = stub_write_fail;
	TEST_CHECK(fr_bio_write(mem, NULL, NULL, SIZE_MAX) == fr_bio_error(GENERIC));

	TEST_CASE("the memory bio does not shut the chain down");
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("a later flush sends the rest of the buffered data");
	stub->write = stub_write_all;
	TEST_CHECK_RET((int) fr_bio_write(mem, NULL, NULL, SIZE_MAX), 4);

done:
	talloc_free(ctx);
}

/** After a fatal read error in the next bio, the application still gets the buffered data.
 *
 *  The stub decides that the error is fatal, and calls fr_bio_shutdown().  The memory bio passes
 *  the error up, and fr_bio_mem_eof() keeps the buffered data for the application.
 */
static void test_fatal_read_drains(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*mem, *stub;
	uint8_t		buf[64];
	ssize_t		slen;

	stub = stub_alloc(ctx);
	TEST_CHECK(stub != NULL);
	if (!stub) goto done;

	mem = fr_bio_mem_alloc(ctx, 1024, 0, stub);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	fr_bio_cb_set(mem, &stub_cb);

	TEST_CASE("a small read buffers the rest");
	slen = fr_bio_read(mem, NULL, buf, 2);
	TEST_CHECK_RET((int) slen, 2);

	TEST_CASE("the next read fails in the stub, which shuts the chain down");
	((stub_t *) stub)->fatal = true;
	TEST_CHECK(fr_bio_read(mem, NULL, buf, sizeof(buf)) < 0);

	TEST_CASE("writes stop at once, but the teardown waits for the drain");
	TEST_CHECK(fr_bio_write(mem, NULL, "x", 1) == fr_bio_error(SHUTDOWN));
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("the application still gets the buffered data");
	slen = fr_bio_read(mem, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 3);
	if (slen == 3) TEST_CHECK(memcmp(buf, "cde", 3) == 0);

	TEST_CASE("an empty buffer completes the shutdown");
	TEST_CHECK_RET((int) fr_bio_read(mem, NULL, buf, sizeof(buf)), 0);
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("the chain reports SHUTDOWN once it is torn down");
	TEST_CHECK(fr_bio_read(mem, NULL, buf, sizeof(buf)) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

/** With the datagram verify reader, the memory bio passes a recoverable read error up to the application.
 */
static void test_recoverable_read_datagram(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_t		*mem, *stub;
	test_verify_ctx_t	tctx = { .fail = false };
	uint8_t			buf[64];

	stub = stub_alloc(ctx);
	TEST_CHECK(stub != NULL);
	if (!stub) goto done;

	((stub_t *) stub)->data_sent = true;

	mem = fr_bio_mem_alloc(ctx, 0, 0, stub);
	TEST_CHECK(mem != NULL);
	if (!mem) goto done;

	TEST_CHECK(fr_bio_mem_set_verify(mem, test_verify, &tctx, true) == 0);
	fr_bio_cb_set(mem, &stub_cb);

	TEST_CASE("the read gets the error from the stub");
	TEST_CHECK(fr_bio_read(mem, NULL, buf, sizeof(buf)) == fr_bio_error(GENERIC));

	TEST_CASE("the memory bio does not shut the chain down");
	TEST_CHECK_RET(shutdown_count, 0);

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "verify_one_packet",		test_verify_one_packet },
	{ "verify_partial_packet",	test_verify_partial_packet },
	{ "verify_pipelined",		test_verify_pipelined },
	{ "verify_buffer_too_small",	test_verify_buffer_too_small },
	{ "verify_error_close",		test_verify_error_close },
	{ "buffered_read_drains",	test_buffered_read_drains },
	{ "recoverable_write_passes_up",	test_recoverable_write_passes_up },
	{ "recoverable_flush_passes_up",	test_recoverable_flush_passes_up },
	{ "fatal_read_drains",			test_fatal_read_drains },
	{ "recoverable_read_datagram",		test_recoverable_read_datagram },
	TEST_TERMINATOR
};
