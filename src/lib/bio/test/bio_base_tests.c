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

/** Tests for chaining, EOF and shutdown
 *
 * @file src/lib/bio/test/bio_base_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/mem.h>
#include <freeradius-devel/bio/pipe.h>

static int	eof_count;
static int	shutdown_count;

static void	cb_eof(fr_bio_t *bio)		{ (void) bio; eof_count++; }
static int	cb_shutdown(fr_bio_t *bio)	{ (void) bio; shutdown_count++; return 0; }
static int	cb_noop(fr_bio_t *bio)		{ (void) bio; return 0; }

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_noop,
	.eof		= cb_eof,
	.shutdown	= cb_shutdown,
};

/** A pipe in front of a sink, which is the smallest chain we can build without a socket.
 *
 *  The pipe is the head, and is the bio which can hold data for the application.  The sink stands
 *  in for the transport.
 */
static fr_bio_t *test_chain_alloc(TALLOC_CTX *ctx, fr_bio_t **sink_p)
{
	fr_bio_t *head, *sink;

	eof_count = shutdown_count = 0;

	head = fr_bio_pipe_alloc(ctx, &test_cb, 1024);
	if (!head) return NULL;

	sink = fr_bio_mem_sink_alloc(ctx, 1024);
	if (!sink) return NULL;

	fr_bio_chain(head, sink);

	if (sink_p) *sink_p = sink;
	return head;
}

static void test_chain(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *sink;

	head = test_chain_alloc(ctx, &sink);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	TEST_CASE("the head of the chain is the first bio");
	TEST_CHECK(fr_bio_head(sink) == head);
	TEST_CHECK(fr_bio_head(head) == head);

	TEST_CASE("next and prev are each other's inverse");
	TEST_CHECK(fr_bio_next(head) == sink);
	TEST_CHECK(fr_bio_prev(sink) == head);
	TEST_CHECK(fr_bio_next(sink) == NULL);
	TEST_CHECK(fr_bio_prev(head) == NULL);

done:
	talloc_free(ctx);
}

/** With nothing buffered, a shutdown tears the chain down at once.
 */
static void test_shutdown_immediate(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *sink;
	uint8_t		buf[16];

	head = test_chain_alloc(ctx, &sink);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	TEST_CASE("shutdown of an empty chain completes");
	TEST_CHECK(fr_bio_shutdown(sink) == 0);
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("reads and writes report SHUTDOWN afterwards");
	TEST_CHECK(fr_bio_read(head, NULL, buf, sizeof(buf)) == fr_bio_error(SHUTDOWN));
	TEST_CHECK(fr_bio_write(head, NULL, "x", 1) == fr_bio_error(SHUTDOWN));

	TEST_CASE("a second shutdown is a no-op");
	TEST_CHECK(fr_bio_shutdown(sink) == 0);
	TEST_CHECK_RET(shutdown_count, 1);

done:
	talloc_free(ctx);
}

/** A bio which still holds data defers the teardown until the application has drained it.
 */
static void test_shutdown_drains_reads(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *sink;
	uint8_t		buf[32];
	ssize_t		slen;

	head = test_chain_alloc(ctx, &sink);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	TEST_CHECK(fr_bio_write(head, NULL, "hello world", 11) == 11);

	TEST_CASE("the teardown waits while a bio still holds data");
	TEST_CHECK(fr_bio_shutdown(sink) == 0);
	TEST_CHECK_RET(shutdown_count, 0);
	TEST_CHECK_RET(eof_count, 0);

	TEST_CASE("writes stop at once even though reads do not");
	TEST_CHECK(fr_bio_write(head, NULL, "x", 1) < 0);

	TEST_CASE("the application still gets the data which had arrived");
	slen = fr_bio_read(head, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 11);
	if (slen == 11) TEST_CHECK(memcmp(buf, "hello world", 11) == 0);

	TEST_CASE("draining the last byte completes the shutdown");
	TEST_CHECK_RET(eof_count, 1);
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("the chain reports SHUTDOWN once it is torn down");
	TEST_CHECK(fr_bio_read(head, NULL, buf, sizeof(buf)) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

/** fr_bio_shutdown_discard() does not wait, and throws the buffered data away.
 */
static void test_shutdown_discard(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *sink;
	uint8_t		buf[32];

	head = test_chain_alloc(ctx, &sink);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	TEST_CHECK(fr_bio_write(head, NULL, "hello world", 11) == 11);

	TEST_CASE("discard tears the chain down immediately");
	TEST_CHECK(fr_bio_shutdown_discard(sink) == 0);
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("the buffered data is not handed over");
	TEST_CHECK(fr_bio_read(head, NULL, buf, sizeof(buf)) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

/** A free completes a shutdown which is still waiting for a drain.
 */
static void test_shutdown_free_completes(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *sink;

	head = test_chain_alloc(ctx, &sink);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	TEST_CHECK(fr_bio_write(head, NULL, "hello world", 11) == 11);
	TEST_CHECK(fr_bio_shutdown(sink) == 0);

	TEST_CASE("the teardown has not run yet");
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("freeing the chain finishes it");
	TALLOC_FREE(head);
	TEST_CHECK_RET(shutdown_count, 1);

done:
	talloc_free(ctx);
}

static void test_strerror(void)
{
	TEST_CASE("every error code has a message");
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(NONE)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(GENERIC)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(IO_WOULD_BLOCK)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(IO)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(VERIFY)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(BUFFER_FULL)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(BUFFER_TOO_SMALL)), "<unknown>") != 0);
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(SHUTDOWN)), "<unknown>") != 0);

	TEST_CASE("OOM has a message too");
	TEST_MSG("summary.md records this as missing");
	TEST_CHECK(strcmp(fr_bio_strerror(fr_bio_error(OOM)), "<unknown>") != 0);
}

TEST_LIST = {
	{ "chain",			test_chain },
	{ "shutdown_immediate",		test_shutdown_immediate },
	{ "shutdown_drains_reads",	test_shutdown_drains_reads },
	{ "shutdown_discard",		test_shutdown_discard },
	{ "shutdown_free_completes",	test_shutdown_free_completes },
	{ "strerror",			test_strerror },
	TEST_TERMINATOR
};
