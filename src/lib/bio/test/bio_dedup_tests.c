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


/** Tests for the dedup bio expiring entries after a reply
 *
 * @file src/lib/bio/test/bio_dedup_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/bio/dedup.h>

static int			expired_count;
static fr_bio_dedup_entry_t	*saved_item;

static uint8_t			request[4] = { 1, 2, 3, 4 };
static uint8_t			reply[4] = { 5, 6, 7, 8 };
static int			packet_ctx;		//!< the tests pass only the address of packet_ctx

static bool dedup_receive(UNUSED fr_bio_t *bio, fr_bio_dedup_entry_t *dedup_ctx, UNUSED void *pctx)
{
	saved_item = dedup_ctx;
	return true;
}

static void dedup_release(UNUSED fr_bio_t *bio, UNUSED fr_bio_dedup_entry_t *dedup_ctx,
			  fr_bio_dedup_release_reason_t reason)
{
	if (reason == FR_BIO_DEDUP_EXPIRED) expired_count++;
}

static fr_bio_dedup_entry_t *dedup_get_item(UNUSED fr_bio_t *bio, UNUSED void *pctx)
{
	return saved_item;
}

/** The stub transport returns a copy of request on every read, and reports every write as complete.
 */
static ssize_t stub_read(UNUSED fr_bio_t *bio, UNUSED void *pctx, void *buffer, size_t size)
{
	if (size < sizeof(request)) return fr_bio_error(BUFFER_TOO_SMALL);

	memcpy(buffer, request, sizeof(request));
	return sizeof(request);
}

static size_t			stub_bytes;		//!< bytes of reply data which the stub transport has accepted

static ssize_t stub_write_all(UNUSED fr_bio_t *bio, UNUSED void *pctx, void const *buffer, size_t size)
{
	if (!buffer) return 0;		/* nothing to flush */

	stub_bytes += size;
	return size;
}

/** A stub transport write function which always returns IO_WOULD_BLOCK.
 */
static ssize_t stub_write_block(UNUSED fr_bio_t *bio, UNUSED void *pctx, UNUSED void const *buffer, UNUSED size_t size)
{
	return fr_bio_error(IO_WOULD_BLOCK);
}

/** A stub transport write function which accepts one byte of each write.
 */
static ssize_t stub_write_one(UNUSED fr_bio_t *bio, UNUSED void *pctx, void const *buffer, UNUSED size_t size)
{
	if (!buffer) return 0;

	stub_bytes++;
	return 1;
}

static fr_bio_t *stub_alloc(TALLOC_CTX *ctx)
{
	fr_bio_common_t *my;

	my = talloc_zero(ctx, fr_bio_common_t);
	if (!my) return NULL;

	my->bio.read = stub_read;
	my->bio.write = stub_write_all;

	return &my->bio;
}

/** Allocate a dedup bio with two entries and a one-second lifetime, in front of the stub transport.
 */
static fr_bio_t *test_dedup_alloc(TALLOC_CTX *ctx, fr_bio_dedup_config_t *cfg)
{
	fr_bio_t *stub;

	expired_count = 0;
	saved_item = NULL;
	stub_bytes = 0;

	cfg->el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!cfg->el) return NULL;

	cfg->lifetime = fr_time_delta_from_sec(1);

	stub = stub_alloc(ctx);
	if (!stub) return NULL;

	return fr_bio_dedup_alloc(ctx, 2, dedup_receive, dedup_release, dedup_get_item, cfg, stub);
}

/** Read one request through the dedup bio, and attach reply to the dedup entry of the request.
 */
static bool test_read_request(fr_bio_t *dedup, uint8_t *buffer, size_t size)
{
	saved_item = NULL;

	if (fr_bio_read(dedup, &packet_ctx, buffer, size) != sizeof(request)) return false;
	if (!saved_item) return false;

	saved_item->reply = reply;
	saved_item->reply_size = sizeof(reply);
	saved_item->reply_ctx = &packet_ctx;
	return true;
}

/** Run every timer which is due within the next five seconds.
 */
static void test_run_timers(fr_bio_dedup_config_t *cfg)
{
	fr_time_t when = fr_time_add(fr_time(), fr_time_delta_from_sec(5));

	(void) fr_timer_list_run(cfg->el->tl, &when);
}

/** The dedup entry for a reply sent with fr_bio_dedup_respond() expires once the lifetime is over.
 *
 *  Regression test for dedup.md finding 1.  fr_bio_dedup_respond() and fr_bio_dedup_write() did not
 *  arm the expiry timer, so no entry expired.
 */
static void test_respond_expires(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;

	TEST_CHECK(test_read_request(dedup, buffer, sizeof(buffer)));
	if (!saved_item) goto done;

	TEST_CASE("fr_bio_dedup_respond() writes the reply");
	TEST_CHECK_RET((int) fr_bio_dedup_respond(dedup, saved_item), (int) sizeof(reply));

	TEST_CASE("the dedup entry expires once the lifetime is over");
	test_run_timers(&cfg);
	TEST_CHECK_RET(expired_count, 1);

done:
	talloc_free(ctx);
}

/** The dedup entry for a reply sent with fr_bio_write() expires once the lifetime is over.
 */
static void test_write_expires(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;

	TEST_CHECK(test_read_request(dedup, buffer, sizeof(buffer)));
	if (!saved_item) goto done;

	TEST_CASE("fr_bio_write() writes the reply");
	TEST_CHECK_RET((int) fr_bio_write(dedup, &packet_ctx, reply, sizeof(reply)), (int) sizeof(reply));

	TEST_CASE("the dedup entry expires once the lifetime is over");
	test_run_timers(&cfg);
	TEST_CHECK_RET(expired_count, 1);

done:
	talloc_free(ctx);
}

/** The expiry timer returns each expired entry to the free list, so the dedup bio reads more
 *  requests than the dedup bio has entries.
 *
 *  The UDP bio of the RADIUS server has 256 entries.  Without the fix for dedup.md finding 1, the UDP
 *  bio returned fr_bio_error(OOM) for every request after 256 replies.
 */
static void test_entries_are_reused(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup;
	uint8_t			buffer[64];
	int			i;

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;

	TEST_CASE("a dedup bio with two entries finds a free entry for each of five requests");
	for (i = 0; i < 5; i++) {
		TEST_CHECK(test_read_request(dedup, buffer, sizeof(buffer)));
		TEST_MSG("request %d", i);
		if (!saved_item) break;

		TEST_CHECK_RET((int) fr_bio_dedup_respond(dedup, saved_item), (int) sizeof(reply));
		test_run_timers(&cfg);
	}
	TEST_CHECK_RET(expired_count, 5);

done:
	talloc_free(ctx);
}

/** Two entries with the same expiry time both expire.
 *
 *  See finding 1 in dedup.md.  The expiry tree compared only the expiry time, so the tree treated the
 *  second entry as a duplicate, and never inserted the second entry.
 */
static void test_equal_expiry(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup;
	fr_bio_dedup_entry_t	*first, *second;
	fr_time_t		expires;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;

	TEST_CHECK(test_read_request(dedup, buffer, sizeof(buffer)));
	first = saved_item;
	if (!first) goto done;
	TEST_CHECK_RET((int) fr_bio_dedup_respond(dedup, first), (int) sizeof(reply));

	TEST_CHECK(test_read_request(dedup, buffer, sizeof(buffer)));
	second = saved_item;
	if (!second) goto done;
	TEST_CHECK_RET((int) fr_bio_dedup_respond(dedup, second), (int) sizeof(reply));

	TEST_CASE("fr_bio_dedup_entry_extend() gives both entries the same expiry time");
	expires = fr_time_add(fr_time(), fr_time_delta_from_sec(2));
	TEST_CHECK(fr_bio_dedup_entry_extend(dedup, first, expires) == 0);
	TEST_CHECK(fr_bio_dedup_entry_extend(dedup, second, expires) == 0);

	TEST_CASE("both entries expire");
	test_run_timers(&cfg);
	TEST_CHECK_RET(expired_count, 2);

done:
	talloc_free(ctx);
}

/** Call the dedup bio's write_resume callback, as fr_bio_packet_write_resume() does.
 */
static int test_write_resume(fr_bio_t *dedup)
{
	fr_bio_common_t *my = (fr_bio_common_t *) dedup;

	if (!my->priv_cb.write_resume) return -1;

	return my->priv_cb.write_resume(dedup);
}

/** Read a request, and respond while the stub transport is blocked, so that the reply goes on the
 *  pending list.
 */
static bool test_pending_reply(fr_bio_t *dedup, fr_bio_t *stub, uint8_t *buffer, size_t size)
{
	if (!test_read_request(dedup, buffer, size)) return false;

	stub->write = stub_write_block;
	return (fr_bio_dedup_respond(dedup, saved_item) == sizeof(reply));
}

/** write_resume sends a pending reply, and the dedup entry then expires once the lifetime is over.
 */
static void test_resume_sends_pending(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup, *stub;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;
	stub = fr_bio_next(dedup);

	TEST_CASE("a reply written while the stub transport is blocked goes on the pending list");
	TEST_CHECK(test_pending_reply(dedup, stub, buffer, sizeof(buffer)));
	TEST_CHECK_RET((int) stub_bytes, 0);

	TEST_CASE("write_resume sends the pending reply");
	stub->write = stub_write_all;
	TEST_CHECK_RET(test_write_resume(dedup), 1);
	TEST_CHECK_RET((int) stub_bytes, (int) sizeof(reply));

	TEST_CASE("the dedup entry then expires once the lifetime is over");
	test_run_timers(&cfg);
	TEST_CHECK_RET(expired_count, 1);

done:
	talloc_free(ctx);
}

/** write_resume keeps the pending reply when the stub transport is still blocked.
 */
static void test_resume_still_blocked(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup, *stub;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;
	stub = fr_bio_next(dedup);

	TEST_CHECK(test_pending_reply(dedup, stub, buffer, sizeof(buffer)));

	TEST_CASE("write_resume reports that writes are still blocked");
	TEST_CHECK_RET(test_write_resume(dedup), 0);

	TEST_CASE("write_resume kept the pending reply, and the next write_resume call sends the pending reply");
	stub->write = stub_write_all;
	TEST_CHECK_RET(test_write_resume(dedup), 1);
	TEST_CHECK_RET((int) stub_bytes, (int) sizeof(reply));

done:
	talloc_free(ctx);
}

/** When the stub transport writes only part of a pending reply, the next resume writes the rest.
 */
static void test_resume_partial(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_dedup_config_t	cfg;
	fr_bio_t		*dedup, *stub;
	uint8_t			buffer[64];

	dedup = test_dedup_alloc(ctx, &cfg);
	TEST_CHECK(dedup != NULL);
	if (!dedup) goto done;
	stub = fr_bio_next(dedup);

	TEST_CHECK(test_pending_reply(dedup, stub, buffer, sizeof(buffer)));

	TEST_CASE("the stub transport accepts one byte, so write_resume reports that writes are still blocked");
	stub->write = stub_write_one;
	TEST_CHECK_RET(test_write_resume(dedup), 0);
	TEST_CHECK_RET((int) stub_bytes, 1);

	TEST_CASE("the next write_resume call sends the rest of the reply exactly once");
	stub->write = stub_write_all;
	TEST_CHECK_RET(test_write_resume(dedup), 1);
	TEST_CHECK_RET((int) stub_bytes, (int) sizeof(reply));

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "respond_expires",		test_respond_expires },
	{ "write_expires",		test_write_expires },
	{ "entries_are_reused",		test_entries_are_reused },
	{ "equal_expiry",		test_equal_expiry },
	{ "resume_sends_pending",	test_resume_sends_pending },
	{ "resume_still_blocked",	test_resume_still_blocked },
	{ "resume_partial",		test_resume_partial },
	TEST_TERMINATOR
};
