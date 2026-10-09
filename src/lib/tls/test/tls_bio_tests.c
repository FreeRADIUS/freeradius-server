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

/** Tests for the datagram boundaries which the TLS dbuff bio records
 *
 * The bio is the boundary between OpenSSL and the application.  OpenSSL calls
 * BIO_write() once per datagram, and a datagram transport has to send each of
 * those as its own datagram.  These tests write to the bio directly, so they
 * need no socket, no session, and no handshake.
 *
 * @file src/lib/tls/test/tls_bio_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/test/acutest_common_init.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#include <freeradius-devel/tls/bio.h>

/** Build the BIO_METHOD which fr_tls_bio_dbuff_alloc() clones
 *
 * The server calls this from fr_tls_init().  These tests do not start a
 * server, so they call it themselves.  acutest runs each test in its own
 * process, so the flag is per test rather than per run.
 */
static void tls_bio_test_init(void)
{
	static bool done = false;

	if (done) return;

	TEST_CHECK(fr_tls_bio_init() == 0);
	done = true;
}

/** Allocate a bio, without datagram boundaries
 */
static BIO *stream_bio_alloc(fr_tls_bio_dbuff_t **out)
{
	tls_bio_test_init();

	return fr_tls_bio_dbuff_alloc(out, NULL, NULL, 1024, 0, true);
}

/** Allocate a bio with datagram boundaries turned on
 */
static BIO *datagram_bio_alloc(fr_tls_bio_dbuff_t **out)
{
	BIO *bio;

	bio = stream_bio_alloc(out);
	TEST_CHECK(bio != NULL);
	if (!bio) return NULL;

	TEST_CHECK(fr_tls_bio_dbuff_datagram_init(*out) == 0);

	return bio;
}

/** Without datagram mode the bio reports no boundaries at all
 */
static void test_stream_has_no_boundaries(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;

	bio = stream_bio_alloc(&bd);
	TEST_CHECK(bio != NULL);
	if (!bio) return;

	TEST_CHECK(BIO_write(bio, "hello", 5) == 5);
	TEST_CHECK(BIO_write(bio, "world", 5) == 5);

	/*
	 *	The data is there, the boundaries are not.
	 */
	TEST_CHECK(fr_dbuff_remaining(fr_tls_bio_dbuff_out(bd)) == 10);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** One write is one datagram
 */
static void test_one_write_one_datagram(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	TEST_CHECK(BIO_write(bio, "hello", 5) == 5);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 5);

	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** Writes of different lengths come back in the order they were written
 *
 * This is the case the whole change exists for: OpenSSL writes a flight as
 * several datagrams of unequal length, and joining them back together would
 * produce one datagram larger than the MTU OpenSSL was given.
 */
static void test_flight_keeps_its_boundaries(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;
	static size_t const	len[] = { 71, 1103, 314, 308, 12 };
	uint8_t			buf[1200];
	size_t			i;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	memset(buf, 0xa5, sizeof(buf));

	for (i = 0; i < NUM_ELEMENTS(len); i++) {
		TEST_CHECK(BIO_write(bio, (char const *) buf, (int) len[i]) == (int) len[i]);
	}

	for (i = 0; i < NUM_ELEMENTS(len); i++) {
		TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), len[i]);
		fr_tls_bio_dbuff_datagram_sent(bd);
	}

	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** A flight which is fully drained is followed by another
 *
 * This is what actually happens on a connection: OpenSSL writes a flight,
 * the application sends all of it, and the next flight arrives later.  The
 * queue has to be reusable rather than fill up once.
 */
static void test_flight_after_flight(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;
	uint8_t			buf[64];
	size_t			i;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < 16; i++) {
		size_t	flight;

		/*
		 *	Two datagrams, drained to nothing, over and over.
		 *	The lengths change each time round so that a stale
		 *	entry does not read as a correct one.
		 */
		for (flight = 0; flight < 2; flight++) {
			size_t len = (i * 2) + flight + 1;

			TEST_CHECK(BIO_write(bio, (char const *) buf, (int) len) == (int) len);
		}

		for (flight = 0; flight < 2; flight++) {
			TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), (i * 2) + flight + 1);
			fr_tls_bio_dbuff_datagram_sent(bd);
		}

		TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);
	}

	talloc_free(bd);
}

/** Draining part of a flight leaves the rest in order
 */
static void test_partial_drain(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;
	uint8_t			buf[64];

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	memset(buf, 0, sizeof(buf));

	TEST_CHECK(BIO_write(bio, (char const *) buf, 10) == 10);
	TEST_CHECK(BIO_write(bio, (char const *) buf, 20) == 20);

	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 10);
	fr_tls_bio_dbuff_datagram_sent(bd);

	/*
	 *	A write which arrives while a datagram is still queued must
	 *	not disturb the one which is waiting.
	 */
	TEST_CHECK(BIO_write(bio, (char const *) buf, 30) == 30);

	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 20);
	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 30);
	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** Sending more datagrams than were written is harmless
 */
static void test_over_send(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	TEST_CHECK(BIO_write(bio, "x", 1) == 1);
	fr_tls_bio_dbuff_datagram_sent(bd);
	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** Vary the datagram length, so that a mis-ordered queue is visible
 *
 * A test which writes the same length every time cannot tell a correctly
 * ordered queue from a shuffled one.  The period is 7 and the test below
 * drains 3, so a queue which is off by 3 reads differently at every entry.
 * A period which divides the drain hides exactly the bug this is here to
 * find.
 */
static size_t cap_test_len(size_t i)
{
	return (i % 7) + 1;
}

/** The queue is capped, a write past the cap fails, and draining makes room
 *
 * Filling the queue and then draining part of it is what makes the entries
 * wrap, so this is also the test which covers moving them back down.
 */
static void test_queue_cap(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;
	size_t			i;
	uint8_t			buf[16]; /* post-drain writes are >8 bytes */

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < FR_TLS_MAX_DATAGRAMS; i++) {
		TEST_CHECK(BIO_write(bio, (char const *) buf, (int) cap_test_len(i)) == (int) cap_test_len(i));
	}

	/*
	 *	Nothing has been drained, so there is nowhere to put the
	 *	next boundary.
	 */
	TEST_CHECK(BIO_write(bio, (char const *) buf, 1) <= 0);

	/*
	 *	Draining three makes room for three more, and the three new
	 *	ones go behind the 253 which are still queued.
	 */
	for (i = 0; i < 3; i++) {
		TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), cap_test_len(i));
		fr_tls_bio_dbuff_datagram_sent(bd);
	}

	for (i = 0; i < 3; i++) {
		TEST_CHECK(BIO_write(bio, (char const *) buf, 7 + (int) i) == 7 + (int) i);
	}

	/*
	 *	What is left is entries 3..255 of the first run, in order,
	 *	and then the three which were written after the drain.
	 */
	for (i = 3; i < FR_TLS_MAX_DATAGRAMS; i++) {
		TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), cap_test_len(i));
		fr_tls_bio_dbuff_datagram_sent(bd);
	}

	for (i = 0; i < 3; i++) {
		TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 7 + i);
		fr_tls_bio_dbuff_datagram_sent(bd);
	}

	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** A datagram which does not fit records no boundary at all
 *
 * The buffer here cannot extend, so a write larger than the room left copies
 * part of the data.  Half a datagram is not a datagram, so the write has to
 * fail rather than queue a length with nothing behind it.
 */
static void test_partial_write_records_nothing(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;
	uint8_t			buf[128];

	tls_bio_test_init();

	/*
	 *	init == max, so the buffer is 64 octets and stays that way.
	 */
	bio = fr_tls_bio_dbuff_alloc(&bd, NULL, NULL, 64, 64, true);
	TEST_CHECK(bio != NULL);
	if (!bio) return;

	TEST_CHECK(fr_tls_bio_dbuff_datagram_init(bd) == 0);

	memset(buf, 0, sizeof(buf));

	TEST_CHECK(BIO_write(bio, (char const *) buf, 40) == 40);
	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 40);

	/*
	 *	Only 24 octets of room are left, so this cannot be buffered
	 *	whole.
	 */
	TEST_CHECK(BIO_write(bio, (char const *) buf, 100) <= 0);

	/*
	 *	The first datagram is still the one at the head, and the
	 *	write which failed left no second entry behind it.
	 */
	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 40);
	fr_tls_bio_dbuff_datagram_sent(bd);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** Clearing the buffer discards the boundaries with the data
 */
static void test_clear_discards_boundaries(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	TEST_CHECK(BIO_write(bio, "hello", 5) == 5);
	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 5);

	fr_tls_bio_dbuff_clear(bd);

	TEST_CHECK(fr_dbuff_remaining(fr_tls_bio_dbuff_out(bd)) == 0);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_len(bd) == 0);

	talloc_free(bd);
}

/** Enabling datagram mode twice is not an error
 */
static void test_enable_is_idempotent(void)
{
	fr_tls_bio_dbuff_t	*bd = NULL;
	BIO			*bio;

	bio = datagram_bio_alloc(&bd);
	if (!bio) return;

	TEST_CHECK(BIO_write(bio, "hello", 5) == 5);
	TEST_CHECK(fr_tls_bio_dbuff_datagram_init(bd) == 0);

	/*
	 *	The second call must not throw away what is already queued.
	 */
	TEST_CHECK_LEN(fr_tls_bio_dbuff_datagram_len(bd), 5);

	talloc_free(bd);
}

TEST_LIST = {
	{ "stream_has_no_boundaries",		test_stream_has_no_boundaries },
	{ "one_write_one_datagram",		test_one_write_one_datagram },
	{ "flight_keeps_its_boundaries",	test_flight_keeps_its_boundaries },
	{ "flight_after_flight",		test_flight_after_flight },
	{ "partial_drain",			test_partial_drain },
	{ "over_send",				test_over_send },
	{ "queue_cap",				test_queue_cap },
	{ "partial_write_records_nothing",	test_partial_write_records_nothing },
	{ "clear_discards_boundaries",		test_clear_discards_boundaries },
	{ "enable_is_idempotent",		test_enable_is_idempotent },
	TEST_TERMINATOR
};
