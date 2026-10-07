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

/** Tests for fr_pair_ctx_afrom_substr()
 *
 * @file src/lib/util/test/pair_tokenize_tests.c
 *
 * @copyright 2026 The FreeRADIUS server project
 */
static void test_init(void) __attribute__((constructor));

#include "acutest_common_init.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/util/pair.h>

static TALLOC_CTX	*autofree;
static fr_dict_t	*test_dict;

/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("pair_tokenize_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;
}

/** Start a parsing context at the root of the test dictionary
 */
static void pair_ctx_init(fr_pair_ctx_t *pair_ctx, fr_pair_list_t *list)
{
	fr_pair_list_init(list);
	pair_ctx->ctx = autofree;
	pair_ctx->list = list;
	fr_pair_ctx_reset(pair_ctx, test_dict);
}

static void test_leaf_quoted(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	char const	in[] = "Test-String-0 = \"hello world\"";
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN(in, sizeof(in) - 1));
	TEST_CHECK_SLEN(slen, (fr_slen_t)(sizeof(in) - 1));

	TEST_CHECK(fr_pair_list_num_elements(&list) == 1);
	vp = fr_pair_list_head(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_string);
	TEST_CHECK(vp->op == T_OP_EQ);
	TEST_CHECK_STRCMP(vp->vp_strvalue, "hello world");

	TEST_CASE("A leaf parsed from the root leaves the context at the root");
	TEST_CHECK(pair_ctx.parent == fr_dict_root(test_dict));

	fr_pair_list_free(&list);
}

static void test_leaf_bareword_stops_at_comma(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	char const	in[] = "Test-Uint32-0 == 42, Test-String-0 = bob";
	fr_sbuff_t	sbuff = FR_SBUFF_IN(in, sizeof(in) - 1);
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &sbuff);
	TEST_CHECK_SLEN(slen, 19);
	TEST_CHECK(fr_sbuff_is_char(&sbuff, ','));

	TEST_CASE("The caller consumes the comma");
	fr_sbuff_advance(&sbuff, 1);
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &sbuff);
	TEST_CHECK_SLEN(slen, 20);
	TEST_CHECK(fr_sbuff_remaining(&sbuff) == 0);

	TEST_CHECK(fr_pair_list_num_elements(&list) == 2);

	vp = fr_pair_list_head(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->op == T_OP_CMP_EQ);
	TEST_CHECK(vp->vp_uint32 == 42);

	vp = fr_pair_list_next(&list, vp);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_string);
	TEST_CHECK(vp->op == T_OP_EQ);
	TEST_CHECK_STRCMP(vp->vp_strvalue, "bob");

	fr_pair_list_free(&list);
}

/** The sbuff bounds the input, so skipping leading whitespace cannot run past the end of the input
 */
static void test_leaf_leading_whitespace(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	char const	in[] = "   Test-String-0 = bob";
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN(in, sizeof(in) - 1));
	TEST_CHECK_SLEN(slen, (fr_slen_t)(sizeof(in) - 1));

	vp = fr_pair_list_head(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK_STRCMP(vp->vp_strvalue, "bob");

	fr_pair_list_free(&list);
}

static void test_whitespace_only(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	char const	in[] = "  \t ";
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN(in, sizeof(in) - 1));
	TEST_CHECK_SLEN(slen, (fr_slen_t)(sizeof(in) - 1));
	TEST_CHECK(fr_pair_list_num_elements(&list) == 0);
}

static void test_context_structural(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	TEST_CASE("A bare structural attribute changes the context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-TLV-0"));
	TEST_CHECK_SLEN(slen, 10);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_tlv);

	TEST_CASE("After a leading '.', the leaf is a child of the current context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR(".String = 'child'"));
	TEST_CHECK_SLEN(slen, 17);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_tlv);

	vp = fr_pair_list_head(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv_string);
	TEST_CHECK_STRCMP(vp->vp_strvalue, "child");

	TEST_CASE("A structural attribute followed by a comma leaves the comma for the caller");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-Group-0,"));
	TEST_CHECK_SLEN(slen, 12);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_group);

	fr_pair_list_free(&list);
}

static void test_context_nested(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	fr_slen_t	slen;

	pair_ctx_init(&pair_ctx, &list);

	TEST_CASE("A dotted reference descends from the root");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-Nested-Top-TLV-0.Child-TLV"));
	TEST_CHECK_SLEN(slen, 31);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_nested_child_tlv);

	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR(".Leaf-Int32 = -7"));
	TEST_CHECK_SLEN(slen, 16);

	vp = fr_pair_list_head(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_nested_leaf_int32);
	TEST_CHECK(vp->vp_int32 == -7);

	TEST_CASE("'..' is the parent of the current context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR(".."));
	TEST_CHECK_SLEN(slen, 2);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_nested_top_tlv);

	TEST_CASE("After a leading '.', a structural attribute is a child of the current context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR(".Child-TLV"));
	TEST_CHECK_SLEN(slen, 10);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_nested_child_tlv);

	TEST_CASE("'..' followed by a leaf parses the leaf under the parent of the current context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-TLV-0"));
	TEST_CHECK_SLEN(slen, 10);
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("..Test-String-0 = up"));
	TEST_CHECK_SLEN(slen, 20);
	TEST_CHECK(pair_ctx.parent == fr_dict_root(test_dict));

	vp = fr_pair_list_tail(&list);
	TEST_ASSERT(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_string);
	TEST_CHECK_STRCMP(vp->vp_strvalue, "up");

	TEST_CASE("'..' followed by a reference descends from the parent of the current context");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-Nested-Top-TLV-0.Child-TLV"));
	TEST_CHECK_SLEN(slen, 31);
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("..Child-TLV"));
	TEST_CHECK_SLEN(slen, 11);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_nested_child_tlv);

	TEST_CASE("Each further '.' walks one level further up");
	slen = fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("...Test-TLV-0"));
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK(pair_ctx.parent == fr_dict_attr_test_tlv);

	fr_pair_list_free(&list);
}

/** Check that a parse fails at the expected offset with the expected message
 */
static void pair_ctx_check_error(fr_pair_ctx_t *pair_ctx, char const *in, fr_slen_t offset, char const *msg)
{
	fr_slen_t	slen;

	TEST_CASE(in);
	fr_strerror_clear();
	slen = fr_pair_ctx_afrom_substr(pair_ctx, &FR_SBUFF_IN(in, strlen(in)));
	TEST_CHECK_SLEN(slen, -(offset + 1));
	TEST_CHECK_STRCMP(fr_strerror(), msg);
}

static void test_errors(void)
{
	fr_pair_ctx_t	pair_ctx;
	fr_pair_list_t	list;

	pair_ctx_init(&pair_ctx, &list);

	pair_ctx_check_error(&pair_ctx, "Test-Nope = 1", 0,
			     "Attribute 'Test-Nope' not found in namespace 'test'");

	TEST_CASE("The error offset counts leading whitespace");
	pair_ctx_check_error(&pair_ctx, "  Test-Nope = 1", 2,
			     "Attribute 'Test-Nope' not found in namespace 'test'");

	pair_ctx_check_error(&pair_ctx, "Test-String-0 \"x\"", 14,
			     "Expected operator");

	pair_ctx_check_error(&pair_ctx, "Test-String-0 = `ls`", 16,
			     "Invalid string quotation");

	pair_ctx_check_error(&pair_ctx, "Test-String-0 = \"abc", 20,
			     "Unterminated string");

	pair_ctx_check_error(&pair_ctx, "Test-TLV-0 foo", 10,
			     "Unexpected text after attribute");

	pair_ctx_check_error(&pair_ctx, "Test-TLV-0.Nope", 11,
			     "Attribute 'Nope' not found in namespace 'Test-TLV-0'");

	TEST_CASE("A trailing '.' has no attribute to set the context from");
	fr_strerror_clear();
	TEST_CHECK(fr_pair_ctx_afrom_substr(&pair_ctx, &FR_SBUFF_IN_STR("Test-TLV-0.")) < 0);
	TEST_CHECK(fr_strerror()[0] != '\0');

	TEST_CASE("The dictionary root has no parent, so '..' at the root fails");
	fr_pair_ctx_reset(&pair_ctx, test_dict);
	pair_ctx_check_error(&pair_ctx, "..Test-String-0", 1,
			     "No parent above the dictionary root");

	TEST_CHECK(fr_pair_list_num_elements(&list) == 0);
}

TEST_LIST = {
	{ "leaf_quoted",			test_leaf_quoted },
	{ "leaf_bareword_stops_at_comma",	test_leaf_bareword_stops_at_comma },
	{ "leaf_leading_whitespace",		test_leaf_leading_whitespace },
	{ "whitespace_only",			test_whitespace_only },
	{ "context_structural",			test_context_structural },
	{ "context_nested",			test_context_nested },
	{ "errors",				test_errors },

	TEST_TERMINATOR
};
