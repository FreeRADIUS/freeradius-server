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

/** Tests for the queue bio's shutdown and error handling
 *
 * @file src/lib/bio/test/bio_queue_tests.c
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
#include <freeradius-devel/bio/queue.h>

static int	cancel_count;
static int	shutdown_count;

static void	cb_eof(fr_bio_t *bio)		{ (void) bio; }
static int	cb_shutdown(fr_bio_t *bio)	{ (void) bio; shutdown_count++; return 0; }
static int	cb_noop(fr_bio_t *bio)		{ (void) bio; return 0; }

static void	queue_cancel(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	(void) bio; (void) packet_ctx; (void) buffer; (void) size;
	cancel_count++;
}

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_noop,
	.eof		= cb_eof,
	.shutdown	= cb_shutdown,
};

/*
 *	The pipe holds 1024 bytes, so the second write is partial, and the queue saves it.
 */
static uint8_t	fill[1000];
static uint8_t	overflow[100];

/** A stub transport which fails recoverably or fatally, as each test chooses.
 *
 *  On a recoverable failure, the stub returns an error and changes nothing else.  On a fatal failure,
 *  the stub first shuts the chain down, as the fd bio does.  Only the failing bio decides whether a
 *  failure is recoverable or fatal.
 */
typedef struct {
	FR_BIO_COMMON;
	bool		fatal;			//!< shut the chain down before failing
} stub_t;

static ssize_t stub_write_fail(fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	stub_t *stub = (stub_t *) bio;

	if (stub->fatal) (void) fr_bio_shutdown(bio);

	fr_strerror_const("stub write failure");
	return fr_bio_error(GENERIC);
}

/** A transport which accepts one byte of each write, so the queue bio saves the rest of the packet.
 */
static ssize_t stub_write_one(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	return 1;
}

/** A transport which accepts every write in full.
 */
static ssize_t stub_write_all(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, size_t size)
{
	return size;
}

static fr_bio_t *stub_alloc(TALLOC_CTX *ctx)
{
	stub_t *stub;

	stub = talloc_zero(ctx, stub_t);
	if (!stub) return NULL;

	stub->bio.read = fr_bio_null_read;
	stub->bio.write = stub_write_fail;

	return &stub->bio;
}

/** Leave one packet partly written in the queue.
 */
static bool queue_fill(fr_bio_t *head)
{
	if (fr_bio_write(head, NULL, fill, sizeof(fill)) != sizeof(fill)) return false;

	return (fr_bio_write(head, NULL, overflow, sizeof(overflow)) == sizeof(overflow));
}

/** The application installs its callbacks on a queue bio at the head of the chain.
 *
 *  The queue's own shutdown routine must survive that, and still cancel the saved packet.
 */
static void test_shutdown_keeps_app_callback(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*queue, *pipe;

	cancel_count = shutdown_count = 0;

	pipe = fr_bio_pipe_alloc(ctx, &test_cb, 1024);
	TEST_CHECK(pipe != NULL);
	if (!pipe) goto done;

	queue = fr_bio_queue_alloc(ctx, 4, NULL, NULL, queue_cancel, pipe);
	TEST_CHECK(queue != NULL);
	if (!queue) goto done;

	fr_bio_cb_set(queue, &test_cb);

	TEST_CHECK(queue_fill(queue));

	TEST_CASE("the transport dies");
	TEST_CHECK(fr_bio_shutdown(pipe) == 0);

	TEST_CASE("the saved packet is cancelled");
	TEST_CHECK_RET(cancel_count, 1);

	TEST_CASE("the application is told about the shutdown");
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("writes report SHUTDOWN");
	TEST_CHECK(fr_bio_write(queue, NULL, "x", 1) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

/** A queue bio in the middle of a chain is not the head, so only the private slot reaches it.
 */
static void test_shutdown_not_head(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*head, *queue, *pipe;

	cancel_count = shutdown_count = 0;

	pipe = fr_bio_pipe_alloc(ctx, &test_cb, 1024);
	TEST_CHECK(pipe != NULL);
	if (!pipe) goto done;

	queue = fr_bio_queue_alloc(ctx, 4, NULL, NULL, queue_cancel, pipe);
	TEST_CHECK(queue != NULL);
	if (!queue) goto done;

	/*
	 *	A memory bio with no buffers passes writes straight through.
	 */
	head = fr_bio_mem_alloc(ctx, 0, 0, queue);
	TEST_CHECK(head != NULL);
	if (!head) goto done;

	fr_bio_cb_set(head, &test_cb);

	TEST_CHECK(queue_fill(head));

	TEST_CASE("the transport dies");
	TEST_CHECK(fr_bio_shutdown(pipe) == 0);

	TEST_CASE("the saved packet is cancelled");
	TEST_CHECK_RET(cancel_count, 1);

	TEST_CASE("the application is told about the shutdown");
	TEST_CHECK_RET(shutdown_count, 1);

done:
	talloc_free(ctx);
}

/** Build a queue in front of a stub, with one packet saved after a partial write.
 */
static fr_bio_t *test_queue_saved_alloc(TALLOC_CTX *ctx, fr_bio_t **stub_p)
{
	fr_bio_t	*queue, *stub;

	cancel_count = shutdown_count = 0;

	stub = stub_alloc(ctx);
	if (!stub) return NULL;

	queue = fr_bio_queue_alloc(ctx, 4, NULL, NULL, queue_cancel, stub);
	if (!queue) return NULL;

	fr_bio_cb_set(queue, &test_cb);

	stub->write = stub_write_one;
	if (fr_bio_write(queue, NULL, overflow, sizeof(overflow)) != sizeof(overflow)) return NULL;

	*stub_p = stub;
	return queue;
}

/** The queue bio passes a recoverable write error up to the application, and keeps working.
 */
static void test_recoverable_write_passes_up(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*queue, *stub;

	cancel_count = shutdown_count = 0;

	stub = stub_alloc(ctx);
	TEST_CHECK(stub != NULL);
	if (!stub) goto done;

	queue = fr_bio_queue_alloc(ctx, 4, NULL, NULL, queue_cancel, stub);
	TEST_CHECK(queue != NULL);
	if (!queue) goto done;

	fr_bio_cb_set(queue, &test_cb);

	TEST_CASE("the write gets the error from the stub");
	TEST_CHECK(fr_bio_write(queue, NULL, "x", 1) == fr_bio_error(GENERIC));

	TEST_CASE("the queue bio does not shut the chain down");
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("the next write reaches the stub again");
	stub->write = stub_write_all;
	TEST_CHECK_RET((int) fr_bio_write(queue, NULL, "x", 1), 1);

done:
	talloc_free(ctx);
}

/** The queue bio passes a recoverable flush error up to the application, and keeps the saved packet.
 */
static void test_recoverable_flush_passes_up(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*queue, *stub = NULL;

	queue = test_queue_saved_alloc(ctx, &stub);
	TEST_CHECK(queue != NULL);
	if (!queue) goto done;

	TEST_CASE("the flush gets the error from the stub");
	stub->write = stub_write_fail;
	TEST_CHECK(fr_bio_write(queue, NULL, NULL, SIZE_MAX) == fr_bio_error(GENERIC));

	TEST_CASE("the saved packet is not cancelled, and the chain is not shut down");
	TEST_CHECK_RET(cancel_count, 0);
	TEST_CHECK_RET(shutdown_count, 0);

	TEST_CASE("a later flush sends the saved packet");
	stub->write = stub_write_all;
	TEST_CHECK(fr_bio_write(queue, NULL, NULL, SIZE_MAX) > 0);
	TEST_CHECK_RET(cancel_count, 0);

done:
	talloc_free(ctx);
}

/** When the next bio shuts the chain down on a fatal flush error, fr_bio_queue_shutdown() cancels the saved packet.
 */
static void test_fatal_flush_from_next(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*queue, *stub = NULL;

	queue = test_queue_saved_alloc(ctx, &stub);
	TEST_CHECK(queue != NULL);
	if (!queue) goto done;

	TEST_CASE("the flush gets the error from the stub");
	((stub_t *) stub)->fatal = true;
	stub->write = stub_write_fail;
	TEST_CHECK(fr_bio_write(queue, NULL, NULL, SIZE_MAX) == fr_bio_error(GENERIC));

	TEST_CASE("fr_bio_queue_shutdown() cancels the saved packet, and the application is told");
	TEST_CHECK_RET(cancel_count, 1);
	TEST_CHECK_RET(shutdown_count, 1);

	TEST_CASE("later writes report SHUTDOWN");
	TEST_CHECK(fr_bio_write(queue, NULL, "x", 1) == fr_bio_error(SHUTDOWN));

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "shutdown_keeps_app_callback",	test_shutdown_keeps_app_callback },
	{ "shutdown_not_head",			test_shutdown_not_head },
	{ "recoverable_write_passes_up",	test_recoverable_write_passes_up },
	{ "recoverable_flush_passes_up",	test_recoverable_flush_passes_up },
	{ "fatal_flush_from_next",		test_fatal_flush_from_next },
	TEST_TERMINATOR
};
