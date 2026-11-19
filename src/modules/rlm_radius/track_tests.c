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

/** Tests for the RADIUS/1.1 Token tracking in the rlm_radius tracking table
 *
 * @file src/modules/rlm_radius/track_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#include "track.c"

/*
 *	The tracking table stores the request pointer, and does not read the request.
 */
static char	dummy_request;
#define REQUEST	((request_t *) &dummy_request)

/*
 *	The first Token is random, so the tests set the counter to a known value.
 */
static radius_track_t *token_table(uint32_t epoch, uint32_t current)
{
	radius_track_t *tt = radius_track_alloc(NULL, true);

	TEST_ASSERT(tt != NULL);
	tt->epoch = epoch;
	tt->current = current;

	return tt;
}

/*
 *	In Token mode, radius_track_entry_find() reads the Token from the first four bytes of the vector,
 *	which is where the Token is in the RADIUS/1.1 header after the Code, ID, and Length.
 */
static radius_track_entry_t *token_find(radius_track_t *tt, uint32_t token)
{
	uint8_t vector[RADIUS_AUTH_VECTOR_LENGTH] = {};

	fr_nbo_from_uint32(vector, token);

	return radius_track_entry_find(tt, 0, vector);
}

static radius_track_entry_t *track_reserve(radius_track_t *tt, radius_track_entry_t **te_p)
{
	*te_p = NULL;

	if (radius_track_entry_reserve(te_p, NULL, tt, REQUEST, 1, NULL) < 0) return NULL;

	return *te_p;
}

/*
 *	The analyzer does not know that TEST_ASSERT() and the result of TEST_CHECK() mean that the
 *	pointer is not NULL, so the tests return explicitly when the reserve fails.
 */
#define RESERVE_OR_RETURN(_tt, _te) \
do { \
	if (!track_reserve(_tt, &(_te))) { \
		TEST_CHECK(!"track_reserve() failed"); \
		return; \
	} \
} while (0)

static void test_token_find(void)
{
	radius_track_t		*tt = token_table(0, 100);
	radius_track_entry_t	*a = NULL, *b = NULL, *c = NULL;

	TEST_CASE("Tokens come from the counter, and each Token finds its entry");
	RESERVE_OR_RETURN(tt, a);
	RESERVE_OR_RETURN(tt, b);
	RESERVE_OR_RETURN(tt, c);

	TEST_CHECK((a->token) == (100));
	TEST_CHECK((b->token) == (101));
	TEST_CHECK((c->token) == (102));
	TEST_CHECK((a->epoch) == (0));

	TEST_CHECK(token_find(tt, 100) == a);
	TEST_CHECK(token_find(tt, 101) == b);
	TEST_CHECK(token_find(tt, 102) == c);

	TEST_CASE("Tokens which were not issued are not found");
	TEST_CHECK(token_find(tt, 99) == NULL);
	TEST_CHECK(token_find(tt, 103) == NULL);
	TEST_CHECK(token_find(tt, 0) == NULL);
	TEST_CHECK(token_find(tt, UINT32_MAX) == NULL);

	radius_track_entry_release(&a);
	radius_track_entry_release(&b);
	radius_track_entry_release(&c);
	talloc_free(tt);
}

static void test_token_release(void)
{
	radius_track_t		*tt = token_table(0, 10);
	radius_track_entry_t	*e[4] = { NULL, NULL, NULL, NULL };
	int			i;

	for (i = 0; i < 4; i++) RESERVE_OR_RETURN(tt, e[i]);

	TEST_CASE("Releasing a middle entry removes only that entry");
	radius_track_entry_release(&e[1]);
	TEST_CHECK(token_find(tt, 11) == NULL);
	TEST_CHECK(token_find(tt, 10) == e[0]);
	TEST_CHECK(token_find(tt, 12) == e[2]);
	TEST_CHECK(token_find(tt, 13) == e[3]);

	TEST_CASE("Releasing the first entry issued, and then the last entry issued");
	radius_track_entry_release(&e[0]);
	radius_track_entry_release(&e[3]);
	TEST_CHECK(token_find(tt, 10) == NULL);
	TEST_CHECK(token_find(tt, 13) == NULL);
	TEST_CHECK(token_find(tt, 12) == e[2]);

	radius_track_entry_release(&e[2]);
	TEST_CHECK(token_find(tt, 12) == NULL);
	TEST_CHECK((tt->num_requests) == (0));

	talloc_free(tt);
}

static void test_token_reuse(void)
{
	radius_track_t		*tt = token_table(0, 7);
	radius_track_entry_t	*a = NULL, *b = NULL, *released;

	TEST_CASE("A released entry is not found");
	RESERVE_OR_RETURN(tt, a);
	TEST_CHECK(token_find(tt, 7) == a);

	released = a;
	radius_track_entry_release(&a);
	TEST_CHECK(token_find(tt, 7) == NULL);
	TEST_CHECK((fr_dlist_num_elements(&tt->free_list)) == (1));

	TEST_CASE("The next reserve continues the counter, and the new Token finds the entry");
	RESERVE_OR_RETURN(tt, b);
	TEST_CHECK((b->token) == (8));
	TEST_CHECK(token_find(tt, 8) == b);
	TEST_CHECK(token_find(tt, 7) == NULL);

	TEST_CASE("The released entry is reused, and the free list is empty while the entry is in use");
	TEST_CHECK(b == released);
	TEST_CHECK((fr_dlist_num_elements(&tt->free_list)) == (0));

	radius_track_entry_release(&b);
	talloc_free(tt);
}

static void test_token_epoch(void)
{
	radius_track_t		*tt = token_table(0, UINT32_MAX - 1);
	radius_track_entry_t	*a = NULL, *b = NULL, *c = NULL, *d = NULL;

	TEST_CASE("The epoch increases when the counter wraps to zero");
	RESERVE_OR_RETURN(tt, a);
	RESERVE_OR_RETURN(tt, b);
	RESERVE_OR_RETURN(tt, c);

	TEST_CHECK((a->token) == (UINT32_MAX - 1));
	TEST_CHECK((b->token) == (UINT32_MAX));
	TEST_CHECK((c->token) == (0));

	TEST_CHECK((a->epoch) == (0));
	TEST_CHECK((b->epoch) == (0));
	TEST_CHECK((c->epoch) == (1));
	TEST_CHECK((tt->epoch) == (1));

	TEST_CASE("Entries from the previous epoch are still found");
	TEST_CHECK(token_find(tt, UINT32_MAX - 1) == a);
	TEST_CHECK(token_find(tt, UINT32_MAX) == b);
	TEST_CHECK(token_find(tt, 0) == c);

	TEST_CASE("Tokens which were not issued are not found across the wrap");
	TEST_CHECK(token_find(tt, UINT32_MAX - 2) == NULL);
	TEST_CHECK(token_find(tt, 1) == NULL);

	TEST_CASE("Releasing the entries from the previous epoch");
	radius_track_entry_release(&a);
	radius_track_entry_release(&b);
	TEST_CHECK(token_find(tt, UINT32_MAX - 1) == NULL);
	TEST_CHECK(token_find(tt, UINT32_MAX) == NULL);
	TEST_CHECK(token_find(tt, 0) == c);

	TEST_CASE("The counter continues in the new epoch");
	RESERVE_OR_RETURN(tt, d);
	TEST_CHECK((d->token) == (1));
	TEST_CHECK((d->epoch) == (1));
	TEST_CHECK(token_find(tt, 1) == d);

	radius_track_entry_release(&c);
	radius_track_entry_release(&d);
	talloc_free(tt);
}

static void test_token_many(void)
{
	radius_track_t		*tt = token_table(0, 1000);
	radius_track_entry_t	*e[1024] = {};
	int			i;

	TEST_CASE("A table in Token mode is not limited to 256 outstanding entries");
	for (i = 0; i < 1024; i++) RESERVE_OR_RETURN(tt, e[i]);

	TEST_CHECK((tt->num_requests) == (1024));

	for (i = 0; i < 1024; i++) {
		TEST_CHECK(token_find(tt, 1000 + i) == e[i]);
	}

	TEST_CASE("Releasing in the order of issue, and then reserving again");
	for (i = 0; i < 1024; i++) radius_track_entry_release(&e[i]);
	TEST_CHECK((tt->num_requests) == (0));

	for (i = 0; i < 1024; i++) {
		RESERVE_OR_RETURN(tt, e[i]);
		TEST_CHECK(token_find(tt, e[i]->token) == e[i]);
	}

	for (i = 0; i < 1024; i++) radius_track_entry_release(&e[i]);

	talloc_free(tt);
}

static void test_binding(void)
{
	radius_track_t		*tt = token_table(0, 5);
	radius_track_entry_t	*a = NULL, *b = NULL;
	TALLOC_CTX		*ctx = talloc_new(NULL);

	TEST_CASE("An entry which is released, and then reserved without a ctx, has no binding");
	TEST_ASSERT(radius_track_entry_reserve(&a, ctx, tt, REQUEST, 1, NULL) == 0);
	TEST_CHECK(a->binding != NULL);
	radius_track_entry_release(&a);
	TEST_CHECK(a == NULL);

	RESERVE_OR_RETURN(tt, b);
	TEST_CHECK(b->binding == NULL);
	radius_track_entry_release(&b);

	talloc_free(ctx);
	talloc_free(tt);
}

static void test_update(void)
{
	radius_track_t		*tt;
	radius_track_entry_t	*a = NULL;
	uint8_t			vector[RADIUS_AUTH_VECTOR_LENGTH] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t			other[RADIUS_AUTH_VECTOR_LENGTH] = {};

	TEST_CASE("In ID mode, the vector is stored, and find matches on the ID and ignores the vector");
	tt = radius_track_alloc(NULL, false);
	RESERVE_OR_RETURN(tt, a);
	TEST_CHECK(radius_track_entry_update(a, vector) == 0);
	TEST_CHECK(memcmp(a->vector, vector, sizeof(vector)) == 0);

	TEST_CHECK(radius_track_entry_find(tt, a->id, vector) == a);
	TEST_CHECK(radius_track_entry_find(tt, a->id, other) == a);
	TEST_CHECK(radius_track_entry_find(tt, a->id + 1, vector) == NULL);

	radius_track_entry_release(&a);
	talloc_free(tt);

	TEST_CASE("In Token mode, the vector is not stored, and the Token and epoch are not changed");
	tt = token_table(3, 200);
	RESERVE_OR_RETURN(tt, a);
	TEST_CHECK(radius_track_entry_update(a, vector) == 0);
	TEST_CHECK((a->token) == (200));
	TEST_CHECK((a->epoch) == (3));
	TEST_CHECK(token_find(tt, 200) == a);

	radius_track_entry_release(&a);
	talloc_free(tt);
}

static void test_id_mode(void)
{
	radius_track_t		*tt = radius_track_alloc(NULL, false);
	radius_track_entry_t	*a = NULL;
	uint8_t			vector[RADIUS_AUTH_VECTOR_LENGTH] = {};

	TEST_CASE("A table which is not in Token mode finds entries by ID");

	RESERVE_OR_RETURN(tt, a);

	TEST_CHECK(a == &tt->id[a->id]);

	/*
	 *	In ID mode, the vector is ignored.  The vector is not NULL, because the analyzer forgets that the
	 *	table is in ID mode after the reserve, and follows the Token mode path of
	 *	radius_track_entry_find(), which reads the Token from the vector.
	 */
	TEST_CHECK(radius_track_entry_find(tt, a->id, vector) == a);

	radius_track_entry_release(&a);
	TEST_CHECK(radius_track_entry_find(tt, 0, vector) == NULL);

	talloc_free(tt);
}

TEST_LIST = {
	{ "token_find",			test_token_find },
	{ "token_release",		test_token_release },
	{ "token_reuse",		test_token_reuse },
	{ "token_epoch",		test_token_epoch },
	{ "token_many",			test_token_many },
	{ "binding",			test_binding },
	{ "update",			test_update },
	{ "id_mode",			test_id_mode },

	TEST_TERMINATOR
};
