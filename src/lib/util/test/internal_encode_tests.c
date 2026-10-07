/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for the internal encoder writing into a talloc dbuff that must grow
 *
 * @file src/lib/util/test/internal_encode_tests.c
 *
 * @copyright 2026 The FreeRADIUS server project
 */
static void test_init(void) __attribute__((constructor));
static void test_fini(void) __attribute__((destructor));

#include "acutest_common_init.h"

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/internal/internal.h>

static TALLOC_CTX	*autofree;
static fr_dict_t	*test_dict;
static fr_dict_t	*internal_dict;

/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("internal_encode_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;

	/*
	 *	The encoder checks every attribute against the root of the
	 *	internal dictionary.
	 */
	if (fr_dict_internal_afrom_file(&internal_dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) goto error;
}

/** Release the internal dictionary before the dictionary context is freed
 */
static void test_fini(void)
{
	fr_dict_free(&internal_dict, __FILE__);
}

/** Encode one pair into talloc dbuffs of every initial size up to the encoded length
 *
 * Each initial size puts the end of the buffer at a different point in the
 * encoding.  A talloc dbuff grows on demand, so every size must produce the
 * same bytes as the encoding into a fixed buffer.
 */
static void test_encode_talloc_extend(void)
{
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	fr_dcursor_t		cursor;
	uint8_t			ref[64] = { 0 };
	ssize_t			ref_len, slen;
	size_t			init;

	fr_pair_list_init(&list);
	TEST_ASSERT(fr_pair_append_by_da(autofree, &vp, &list, fr_dict_attr_test_string) == 0);
	TEST_ASSERT(fr_pair_value_strdup(vp, "bob", false) == 0);

	fr_pair_dcursor_init(&cursor, &list);
	ref_len = fr_internal_encode_pair(&FR_DBUFF_TMP(ref, sizeof(ref)), &cursor, NULL);
	TEST_ASSERT(ref_len > 0);

	for (init = 1; init <= (size_t)ref_len + 1; init++) {
		fr_dbuff_t		dbuff;
		fr_dbuff_uctx_talloc_t	tctx;

		TEST_CASE("Initial size");

		MEM(fr_dbuff_init_talloc(autofree, &dbuff, &tctx, init, 1024));

		fr_pair_dcursor_init(&cursor, &list);
		slen = fr_internal_encode_pair(&dbuff, &cursor, NULL);
		TEST_CHECK(slen == ref_len);
		TEST_MSG("init = %zu, expected %zd, got %zd", init, ref_len, slen);
		if (slen == ref_len) {
			TEST_CHECK(memcmp(fr_dbuff_start(&dbuff), ref, (size_t)ref_len) == 0);
		}

		fr_dbuff_free_talloc(&dbuff);
	}

	fr_pair_list_free(&list);
}

TEST_LIST = {
	{ "encode_talloc_extend",	test_encode_talloc_extend },

	TEST_TERMINATOR
};
