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

/** Tests for the retry bio running out of entries
 *
 * @file src/lib/bio/test/bio_retry_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/retry.h>

static int			blocked_count;
static int			resume_count;
static int			release_count;
static fr_bio_retry_entry_t	*saved_item;

static fr_bio_t			*resume_write_bio;	//!< when set, cb_write_resume() writes packet2 to this bio
static ssize_t			resume_write_rcode;

static uint8_t			packet1[4] = { 1, 2, 3, 4 };
static uint8_t			packet2[4] = { 5, 6, 7, 8 };

static int	cb_noop(fr_bio_t *bio)		{ (void) bio; return 0; }
static void	cb_noop_void(fr_bio_t *bio)	{ (void) bio; }
static int	cb_write_blocked(fr_bio_t *bio)	{ (void) bio; blocked_count++; return 1; }

static int cb_write_resume(fr_bio_t *bio)
{
	(void) bio;
	resume_count++;

	if (resume_write_bio) resume_write_rcode = fr_bio_write(resume_write_bio, NULL, packet2, sizeof(packet2));

	return 1;
}

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_write_resume,
	.read_blocked	= cb_noop,
	.write_blocked	= cb_write_blocked,
	.eof		= cb_noop_void,
};

static void retry_sent(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED const void *buffer, UNUSED size_t size,
		       fr_bio_retry_entry_t *retry_ctx)
{
	saved_item = retry_ctx;
}

static bool retry_response(UNUSED fr_bio_t *bio, UNUSED fr_bio_retry_entry_t **item_p, UNUSED void *packet_ctx,
			   UNUSED const void *buffer, UNUSED size_t size)
{
	return false;
}

static void retry_release(UNUSED fr_bio_t *bio, UNUSED fr_bio_retry_entry_t *retry_ctx,
			  UNUSED fr_bio_retry_release_reason_t reason)
{
	release_count++;
}

static size_t			stub_bytes;		//!< bytes of packet data which the stub has accepted

/** A transport which accepts every write in full, and never has anything to read.
 */
static ssize_t stub_write_all(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, void const *buffer, size_t size)
{
	if (!buffer) return 0;		/* nothing to flush */

	stub_bytes += size;
	return size;
}

/** A transport which accepts one byte of each write, so the retry bio saves the rest of the packet.
 */
static ssize_t stub_write_one(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, void const *buffer, UNUSED size_t size)
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

	my->bio.read = fr_bio_null_read;
	my->bio.write = stub_write_all;

	return &my->bio;
}

/** Allocate a retry bio with one entry, in front of a stub.
 *
 *  Only test_partial_retransmit() runs the timer list, so no timer fires in the other tests.
 */
static fr_bio_t *test_retry_alloc(TALLOC_CTX *ctx, fr_bio_retry_config_t *cfg)
{
	fr_bio_t	*retry, *stub;

	blocked_count = resume_count = release_count = 0;
	stub_bytes = 0;
	saved_item = NULL;
	resume_write_bio = NULL;
	resume_write_rcode = 0;

	cfg->el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!cfg->el) return NULL;

	cfg->retry_config = (fr_retry_config_t) {
		.irt = fr_time_delta_from_sec(2),
		.mrt = fr_time_delta_from_sec(16),
		.mrd = fr_time_delta_from_sec(30),
		.mrc = 5,
	};

	stub = stub_alloc(ctx);
	if (!stub) return NULL;

	retry = fr_bio_retry_alloc(ctx, 1, retry_sent, retry_response, NULL, retry_release, cfg, stub);
	if (!retry) return NULL;

	fr_bio_cb_set(retry, &test_cb);

	return retry;
}

/** Running out of entries blocks writes, and freeing an entry resumes writes.
 *
 *  See finding 1 in retry.md.  Only fr_bio_retry_write_resume() clears write_blocked, and
 *  fr_bio_retry_write_resume() runs only when the socket becomes writable.  If running out of
 *  entries set write_blocked, then the application would never resume writes.
 */
static void test_all_used_resumes(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_retry_config_t	cfg;
	fr_bio_t		*retry;

	retry = test_retry_alloc(ctx, &cfg);
	TEST_CHECK(retry != NULL);
	if (!retry) goto done;

	TEST_CASE("the first packet uses the only entry");
	TEST_CHECK_RET((int) fr_bio_write(retry, NULL, packet1, sizeof(packet1)), (int) sizeof(packet1));
	TEST_CHECK(saved_item != NULL);
	if (!saved_item) goto done;

	TEST_CASE("the second write returns IO_WOULD_BLOCK, and the retry bio calls the write_blocked callback");
	TEST_CHECK(fr_bio_write(retry, NULL, packet2, sizeof(packet2)) == fr_bio_error(IO_WOULD_BLOCK));
	TEST_CHECK_RET(blocked_count, 1);

	TEST_CASE("running out of entries does not set write_blocked");
	TEST_CHECK(!fr_bio_retry_info(retry)->write_blocked);

	TEST_CASE("cancelling the entry calls the release callback and the resume callback");
	TEST_CHECK_RET(fr_bio_retry_entry_cancel(retry, saved_item), 1);
	TEST_CHECK_RET(release_count, 1);
	TEST_CHECK_RET(resume_count, 1);

	TEST_CASE("the retry bio now accepts the second packet");
	TEST_CHECK_RET((int) fr_bio_write(retry, NULL, packet2, sizeof(packet2)), (int) sizeof(packet2));

done:
	talloc_free(ctx);
}

/** The application may write from inside the resume callback, so fr_bio_retry_release() must put
 *  the freed entry on the free list before calling the resume callback.
 */
static void test_resume_can_write(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_retry_config_t	cfg;
	fr_bio_t		*retry;

	retry = test_retry_alloc(ctx, &cfg);
	TEST_CHECK(retry != NULL);
	if (!retry) goto done;

	TEST_CHECK_RET((int) fr_bio_write(retry, NULL, packet1, sizeof(packet1)), (int) sizeof(packet1));
	TEST_CHECK(fr_bio_write(retry, NULL, packet2, sizeof(packet2)) == fr_bio_error(IO_WOULD_BLOCK));
	if (!saved_item) goto done;

	TEST_CASE("a write from inside the resume callback succeeds");
	resume_write_bio = retry;
	TEST_CHECK_RET(fr_bio_retry_entry_cancel(retry, saved_item), 1);
	TEST_CHECK_RET(resume_count, 1);
	TEST_CHECK_RET((int) resume_write_rcode, (int) sizeof(packet2));

	TEST_CASE("the retry bio did not call the write_blocked callback a second time");
	TEST_CHECK_RET(blocked_count, 1);

done:
	talloc_free(ctx);
}

/** The retry bio saves the rest of a partly written retransmission once, and a flush sends the rest once.
 *
 *  See finding 2 in retry.md.  Before the fix, fr_bio_retry_rewrite() saved the rest of the packet,
 *  and then fr_bio_retry_write_item() saved the rest of the packet again.
 */
static void test_partial_retransmit(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_retry_config_t	cfg;
	fr_bio_t		*retry, *stub;
	fr_time_t		when;

	retry = test_retry_alloc(ctx, &cfg);
	TEST_CHECK(retry != NULL);
	if (!retry) goto done;

	stub = fr_bio_next(retry);

	TEST_CASE("the stub accepts the first transmission in full");
	TEST_CHECK_RET((int) fr_bio_write(retry, NULL, packet1, sizeof(packet1)), (int) sizeof(packet1));
	TEST_CHECK_RET((int) stub_bytes, (int) sizeof(packet1));

	TEST_CASE("the retransmission timer fires, and the stub accepts one byte");
	TEST_MSG("the initial retransmission time (irt) is 2s, so running the timer list 3s ahead fires exactly one retransmission");
	stub->write = stub_write_one;
	when = fr_time_add(fr_time(), fr_time_delta_from_sec(3));
	(void) fr_timer_list_run(cfg.el->tl, &when);
	TEST_CHECK_RET((int) stub_bytes, (int) sizeof(packet1) + 1);

	TEST_CASE("the retry bio has saved the rest of the packet and has blocked writes");
	TEST_CHECK(fr_bio_retry_info(retry)->write_blocked);

	TEST_CASE("a flush sends the rest of the packet exactly once");
	stub->write = stub_write_all;
	(void) fr_bio_write(retry, NULL, NULL, SIZE_MAX);
	TEST_CHECK_RET((int) stub_bytes, (int) (2 * sizeof(packet1)));
	TEST_CHECK(!fr_bio_retry_info(retry)->write_blocked);

done:
	talloc_free(ctx);
}

/** When the retry bio cannot save the rest of a partly written packet, the retry bio releases the entry of the packet.
 *
 *  See 'A related defect: a failed save kept the entry' in retry.md.  Without the release, the entry
 *  stays on both timer lists after the sent() callback has passed the entry to the application.  The
 *  write returns OOM, so an application which then frees the packet leaves the retry bio holding a
 *  pointer to freed memory.
 */
static void test_partial_oom_releases(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_bio_retry_config_t	cfg;
	fr_bio_t		*retry, *stub;

	retry = test_retry_alloc(ctx, &cfg);
	TEST_CHECK(retry != NULL);
	if (!retry) goto done;

	stub = fr_bio_next(retry);

	TEST_CASE("a partial write returns OOM when the retry bio cannot allocate the buffer for the rest of the packet");
	TEST_MSG("a talloc memory limit on the retry bio makes the buffer allocation fail");
DIAG_OFF(deprecated-declarations)
	TEST_CHECK(talloc_set_memlimit(retry, talloc_total_size(retry)) == 0);
DIAG_ON(deprecated-declarations)
	stub->write = stub_write_one;
	TEST_CHECK(fr_bio_write(retry, NULL, packet1, sizeof(packet1)) == fr_bio_error(OOM));

	TEST_CASE("the retry bio releases the entry");
	TEST_CHECK_RET(release_count, 1);

	TEST_CASE("the only entry is free again, so the retry bio accepts the next packet");
DIAG_OFF(deprecated-declarations)
	TEST_CHECK(talloc_set_memlimit(retry, 0) == 0);
DIAG_ON(deprecated-declarations)
	stub->write = stub_write_all;
	TEST_CHECK_RET((int) fr_bio_write(retry, NULL, packet2, sizeof(packet2)), (int) sizeof(packet2));
	TEST_CHECK_RET(blocked_count, 0);

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "all_used_resumes",		test_all_used_resumes },
	{ "resume_can_write",		test_resume_can_write },
	{ "partial_retransmit",		test_partial_retransmit },
	{ "partial_oom_releases",	test_partial_oom_releases },
	TEST_TERMINATOR
};
