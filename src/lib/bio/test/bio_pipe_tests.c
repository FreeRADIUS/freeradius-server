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

/** Tests for the pipe bio
 *
 * @file src/lib/bio/test/bio_pipe_tests.c
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
static int	read_blocked_count;

static void	cb_eof(fr_bio_t *bio)			{ (void) bio; eof_count++; }
static int	cb_read_blocked(fr_bio_t *bio)		{ (void) bio; read_blocked_count++; return 0; }
static int	cb_noop(fr_bio_t *bio)			{ (void) bio; return 0; }

static fr_bio_cb_funcs_t test_cb = {
	.read_resume	= cb_noop,
	.write_resume	= cb_noop,
	.read_blocked	= cb_read_blocked,
	.write_blocked	= cb_noop,
	.eof		= cb_eof,
};

static fr_bio_t *test_pipe_alloc(TALLOC_CTX *ctx, size_t size)
{
	eof_count = read_blocked_count = 0;

	return fr_bio_pipe_alloc(ctx, &test_cb, size);
}

static void test_write_read(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*bio;
	uint8_t		buf[32];
	ssize_t		slen;

	bio = test_pipe_alloc(ctx, 1024);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	TEST_CASE("a write is accepted whole");
	TEST_CHECK_RET((int) fr_bio_write(bio, NULL, "hello", 5), 5);

	TEST_CASE("a read returns what was written");
	slen = fr_bio_read(bio, NULL, buf, sizeof(buf));
	TEST_CHECK_RET((int) slen, 5);
	if (slen == 5) TEST_CHECK(memcmp(buf, "hello", 5) == 0);

	TEST_CASE("an empty pipe reads nothing, and says so");
	TEST_CHECK_RET((int) fr_bio_read(bio, NULL, buf, sizeof(buf)), 0);
	TEST_CHECK_RET(read_blocked_count, 1);
	TEST_CHECK_RET(eof_count, 0);

done:
	talloc_free(ctx);
}

/** A write larger than the buffer is clamped rather than refused.
 */
static void test_write_clamped(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*bio;
	uint8_t		data[2048];

	bio = test_pipe_alloc(ctx, 1024);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	memset(data, 'a', sizeof(data));

	TEST_CASE("the write is clamped to the room available");
	TEST_CHECK_RET((int) fr_bio_write(bio, NULL, data, sizeof(data)), 1024);

	TEST_CASE("a full pipe accepts nothing more");
	TEST_CHECK_RET((int) fr_bio_write(bio, NULL, data, 1), 0);

done:
	talloc_free(ctx);
}

/** EOF is signalled even when the read which notices it returns no data.
 *
 *  The pipe used to call read_blocked() in that case, telling an application which read until it
 *  got nothing that it was blocked rather than finished.
 */
static void test_eof_on_empty_read(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*bio, *sink;
	uint8_t		buf[32];

	bio = test_pipe_alloc(ctx, 1024);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	sink = fr_bio_mem_sink_alloc(ctx, 1024);
	TEST_CHECK(sink != NULL);
	if (!sink) goto done;

	fr_bio_chain(bio, sink);

	TEST_CHECK_RET((int) fr_bio_write(bio, NULL, "hi", 2), 2);

	/*
	 *	The sink is at EOF.  The pipe still holds two bytes, so the walk stops there.
	 */
	TEST_CHECK(fr_bio_eof(sink) == bio);
	TEST_CHECK_RET(eof_count, 0);

	TEST_CASE("the buffered data is still delivered");
	TEST_CHECK_RET((int) fr_bio_read(bio, NULL, buf, sizeof(buf)), 2);

	TEST_CASE("EOF is signalled once the buffer empties");
	TEST_CHECK_RET(eof_count, 1);
	TEST_CHECK_RET(read_blocked_count, 0);

done:
	talloc_free(ctx);
}

/** An empty pipe must not stop the EOF walk.
 *
 *  fr_bio_eof() stops when a handler returns zero or less.  The pipe used to return zero for
 *  "nothing buffered", which stopped the walk and left a chain containing a pipe unable to finish.
 */
static void test_eof_walk_continues(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*bio, *sink;

	bio = test_pipe_alloc(ctx, 1024);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	sink = fr_bio_mem_sink_alloc(ctx, 1024);
	TEST_CHECK(sink != NULL);
	if (!sink) goto done;

	fr_bio_chain(bio, sink);

	TEST_CASE("an empty pipe lets the walk reach the head");
	TEST_CHECK(fr_bio_eof(sink) == NULL);
	TEST_CHECK_RET(eof_count, 1);

done:
	talloc_free(ctx);
}

/** A write after EOF reports an error rather than "try again later".
 */
static void test_write_after_eof(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	fr_bio_t	*bio, *sink;

	bio = test_pipe_alloc(ctx, 1024);
	TEST_CHECK(bio != NULL);
	if (!bio) goto done;

	sink = fr_bio_mem_sink_alloc(ctx, 1024);
	TEST_CHECK(sink != NULL);
	if (!sink) goto done;

	fr_bio_chain(bio, sink);

	TEST_CHECK(fr_bio_eof(sink) == NULL);

	TEST_CASE("a write after EOF is an error, not a zero");
	TEST_CHECK(fr_bio_write(bio, NULL, "x", 1) < 0);

done:
	talloc_free(ctx);
}

TEST_LIST = {
	{ "write_read",			test_write_read },
	{ "write_clamped",		test_write_clamped },
	{ "eof_on_empty_read",		test_eof_on_empty_read },
	{ "eof_walk_continues",		test_eof_walk_continues },
	{ "write_after_eof",		test_write_after_eof },
	TEST_TERMINATOR
};
