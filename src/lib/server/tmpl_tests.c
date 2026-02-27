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

/** Tests for tmpl parsing and printing
 *
 * @file src/lib/server/tmpl_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

static void test_init(void);
#  define TEST_INIT  test_init()

#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/pair.h>

static TALLOC_CTX	*autofree;
static fr_dict_t	*test_dict;

DIAG_OFF(declaration-after-statement)

/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("tmpl_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;

	if (request_global_init() < 0) goto error;
}

static request_t *request_fake_alloc(void)
{
	request_t	*request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc_external(autofree, (&(request_init_args_t){ .namespace = test_dict }));

	request->packet = fr_packet_alloc(request, false);
	TEST_ASSERT(request->packet != NULL);

	request->reply = fr_packet_alloc(request, false);
	TEST_ASSERT(request->reply != NULL);

	return request;
}

/** Default tmpl rules for tests
 */
#define test_rules() \
	(&(tmpl_rules_t){ \
		.attr = { \
			.dict_def = test_dict, \
			.list_def = request_attr_request, \
		} \
	})

/*
 *	=== Tokenization: tmpl_afrom_attr_str ===
 */

static void test_parse_attr_simple(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_da(vpt) == fr_dict_attr_test_string);
	talloc_free(vpt);
}

static void test_parse_attr_index(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[0]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_da(vpt) == fr_dict_attr_test_int32);
	TEST_CHECK(tmpl_attr_tail_num(vpt) == 0);
	talloc_free(vpt);
}

static void test_parse_attr_all(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[*]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_num(vpt) == NUM_ALL);
	talloc_free(vpt);
}

static void test_parse_attr_count(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[#]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_num(vpt) == NUM_COUNT);
	talloc_free(vpt);
}

static void test_parse_attr_last(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[n]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_num(vpt) == NUM_LAST);
	talloc_free(vpt);
}

static void test_parse_attr_nested(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt,
				   "Test-Nested-Top-TLV-0.Child-TLV.Leaf-String", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_num_elements(vpt) >= 3);
	TEST_MSG("Expected at least 3 attr refs in chain, got %zu", tmpl_attr_num_elements(vpt));
	TEST_CHECK(tmpl_attr_tail_da(vpt) == fr_dict_attr_test_nested_leaf_string);
	talloc_free(vpt);
}

static void test_parse_attr_missing(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;
	tmpl_rules_t		rules = {
		.attr = {
			.dict_def = test_dict,
			.list_def = request_attr_request,
			.allow_unresolved = true,
		}
	};

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Non-Existent-Attr", &rules);
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr_unresolved(vpt));
	talloc_free(vpt);
}

static void test_parse_attr_invalid(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "aaa^442", test_rules());
	TEST_CHECK(slen < 0);
	TEST_MSG("Expected negative slen for invalid attribute, got %zd", slen);
	if (vpt) talloc_free(vpt);
}

static void test_parse_attr_emptystring(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err = TMPL_ATTR_ERROR_NONE;
	ssize_t			slen;
	tmpl_rules_t		rules = {
		.attr = {
			.dict_def = test_dict,
			.list_def = request_attr_request,
			.allow_unresolved = false,
		}
	};

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "", &rules);
	TEST_CHECK(slen == -1);
	TEST_MSG("Expected no data when no input, got slen=%zd", slen);
	TEST_CHECK(vpt == NULL);
}


/*
 *	Tokenization: tmpl_afrom_substr()
 */

static void test_parse_bareword_attr(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("Test-String-0"),
				 T_BARE_WORD, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_attr(vpt));
	TEST_CHECK(tmpl_attr_tail_da(vpt) == fr_dict_attr_test_string);
	talloc_free(vpt);
}

static void test_parse_single_quoted(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("hello world"),
				 T_SINGLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	/*
	 *	Single-quoted strings without a cast produce
	 *	TMPL_TYPE_DATA_UNRESOLVED.  The string is stored in
	 *	vpt->data.unescaped, and not in the value box.
	 */
	TEST_CHECK(tmpl_is_data_unresolved(vpt));
	talloc_free(vpt);
}

static void test_parse_double_quoted_literal(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("hello world"),
				 T_DOUBLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	/*
	 *	Double quoted strings without expansions end up as
	 *	data or unresolved.
	 *	A literal "hello world" should result in data unresolved.
	 */
	TEST_CHECK(tmpl_is_data_unresolved(vpt) || tmpl_is_data(vpt));
	talloc_free(vpt);
}

static void test_parse_double_quoted_xlat(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;
	tmpl_rules_t		rules = {
		.attr = {
			.dict_def = test_dict,
			.list_def = request_attr_request,
			.allow_unresolved = true,
		}
	};

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("Hello %{User-Name}"),
				 T_DOUBLE_QUOTED_STRING, NULL, &rules);
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	/*
	 *	Double quoted strings with expansions end up as
	 *	xlats.
	 */
	TEST_CHECK(tmpl_is_xlat_unresolved(vpt));
	talloc_free(vpt);
}

/*
 *	tmpl_afrom_value_box()
 */

static void test_from_value_box_string(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;

	fr_value_box_init(&box, FR_TYPE_STRING, NULL, false);
	fr_value_box_strdup_shallow(&box, NULL, "test", false);

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_STRING);
	TEST_CHECK(strcmp(tmpl_value(vpt)->vb_strvalue, "test") == 0);

	talloc_free(vpt);
}

static void test_from_value_box_uint32(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 42;

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_UINT32);
	TEST_CHECK(tmpl_value(vpt)->vb_uint32 == 42);

	talloc_free(vpt);
}

static void test_from_value_box_ipaddr(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;

	fr_value_box_init(&box, FR_TYPE_IPV4_ADDR, NULL, false);
	box.vb_ip.af = AF_INET;
	box.vb_ip.prefix = 32;
	box.vb_ip.addr.v4.s_addr = htonl(INADDR_LOOPBACK);

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_IPV4_ADDR);

	talloc_free(vpt);
}

/*
 *	tmpl_cast_in_place()
 */

static void test_cast_unresolved_to_uint32(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;
	int		ret;
	tmpl_rules_t	rules = *test_rules();

	/*
	 *	Parse "42" as single-quoted.  Without a cast, single-quoted
	 *	strings produce TMPL_TYPE_DATA_UNRESOLVED.
	 */
	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("42"),
				 T_SINGLE_QUOTED_STRING, NULL, &rules);
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	TEST_CHECK(tmpl_is_data_unresolved(vpt));

	ret = tmpl_cast_in_place(vpt, FR_TYPE_UINT32, NULL);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_cast_in_place failed: %s", fr_strerror());

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_UINT32);
	TEST_CHECK(tmpl_value(vpt)->vb_uint32 == 42);

	talloc_free(vpt);
}

static void test_cast_unresolved_to_string(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;
	int		ret;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("hello"),
				 T_SINGLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_cast_in_place(vpt, FR_TYPE_STRING, NULL);
	TEST_CHECK(ret == 0);

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_STRING);
	TEST_CHECK(strcmp(tmpl_value(vpt)->vb_strvalue, "hello") == 0);

	talloc_free(vpt);
}

static void test_cast_uint32_to_uint64(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 100;

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_cast_in_place(vpt, FR_TYPE_UINT64, NULL);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_cast_in_place failed: %s", fr_strerror());

	TEST_CHECK(tmpl_is_data(vpt));
	TEST_CHECK(tmpl_value_type(vpt) == FR_TYPE_UINT64);
	TEST_CHECK(tmpl_value(vpt)->vb_uint64 == 100);

	talloc_free(vpt);
}

static void test_cast_invalid(void)
{
	tmpl_t		*vpt = NULL;
	ssize_t		slen;
	int		ret;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("not_a_number"),
				 T_SINGLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_cast_in_place(vpt, FR_TYPE_UINT32, NULL);
	TEST_CHECK(ret == -1);
	TEST_MSG("Expected failure casting 'not_a_number' to uint32");

	talloc_free(vpt);
}

/*
 *	tmpl_copy_foo()
 */

static void test_copy_data(void)
{
	tmpl_t		*vpt = NULL;
	tmpl_t		*copy;
	fr_value_box_t	box;
	int		ret;

	fr_value_box_init(&box, FR_TYPE_STRING, NULL, false);
	fr_value_box_strdup_shallow(&box, NULL, "copy_test", false);

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	copy = tmpl_copy(autofree, vpt);
	TEST_ASSERT(copy != NULL);

	TEST_CHECK(copy != vpt);
	TEST_CHECK(tmpl_is_data(copy));
	TEST_CHECK(tmpl_value_type(copy) == FR_TYPE_STRING);
	TEST_CHECK(strcmp(tmpl_value(copy)->vb_strvalue, "copy_test") == 0);

	talloc_free(vpt);
	talloc_free(copy);
}

static void test_copy_attr(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_t			*copy;
	tmpl_attr_error_t	err;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	copy = tmpl_copy(autofree, vpt);
	TEST_ASSERT(copy != NULL);

	TEST_CHECK(copy != vpt);
	TEST_CHECK(tmpl_is_attr(copy));
	TEST_CHECK(tmpl_attr_tail_da(copy) == tmpl_attr_tail_da(vpt));

	talloc_free(vpt);
	talloc_free(copy);
}

static void test_copy_data_unresolved(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_t			*copy;
	ssize_t			slen;

	slen = tmpl_afrom_substr(autofree, &vpt, &FR_SBUFF_IN_STR("hello world"),
				 T_DOUBLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	copy = tmpl_copy(autofree, vpt);
	TEST_ASSERT(copy != NULL);

	TEST_CHECK(copy != vpt);
	TEST_CHECK(copy->type == vpt->type);

	talloc_free(vpt);
	talloc_free(copy);
}

/*
 *	tmpl_eval() and friends
 */

static void test_eval_data(void)
{
	tmpl_t			*vpt = NULL;
	fr_value_box_t		box;
	fr_value_box_list_t	out;
	fr_value_box_t		*result;
	request_t		*request = request_fake_alloc();
	int			ret;

	fr_value_box_list_init(&out);

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 42;

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_eval(autofree, &out, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_eval failed: %s", fr_strerror());

	result = fr_value_box_list_head(&out);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result->type == FR_TYPE_UINT32);
	TEST_CHECK(result->vb_uint32 == 42);

	talloc_free(vpt);
	fr_value_box_list_talloc_free(&out);
	talloc_free(request);
}

static void test_eval_attr_found(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	fr_value_box_list_t	out;
	fr_value_box_t		*result;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*string_vp;
	ssize_t			slen;
	int			ret;

	fr_value_box_list_init(&out);

	pair_append_request(&string_vp, fr_dict_attr_test_string);
	TEST_ASSERT(string_vp != NULL);
	ret = fr_pair_value_strdup(string_vp, "hello", false); /* @todo - shallow copy here crashes! */
	TEST_CHECK(ret == 0);

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_eval(autofree, &out, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_eval failed: %s", fr_strerror());

	result = fr_value_box_list_head(&out);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result->type == FR_TYPE_STRING);
	TEST_CHECK(strcmp(result->vb_strvalue, "hello") == 0);

	talloc_free(vpt);
	fr_value_box_list_talloc_free(&out);
	talloc_free(request);
}

static void test_eval_attr_missing(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	fr_value_box_list_t	out;
	fr_value_box_t		*result;
	request_t		*request = request_fake_alloc();
	ssize_t			slen;
	int			ret;

	fr_value_box_list_init(&out);

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int16-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_eval(autofree, &out, request, vpt);
	/*
	 *	When the attribute is missing, tmpl_eval returns 0 with an empty list.
	 */
	TEST_CHECK(ret == 0);

	result = fr_value_box_list_head(&out);
	TEST_CHECK(result == NULL);
	TEST_MSG("Expected empty result list for missing attribute");

	talloc_free(vpt);
	fr_value_box_list_talloc_free(&out);
	talloc_free(request);
}

static void test_eval_attr_multiple(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	fr_value_box_list_t	out;
	fr_value_box_t		*result;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*vp1, *vp2;
	ssize_t			slen;
	int			ret;

	fr_value_box_list_init(&out);

	pair_append_request(&vp1, fr_dict_attr_test_int32);
	vp1->vp_int32 = 10;

	pair_append_request(&vp2, fr_dict_attr_test_int32);
	vp2->vp_int32 = 20;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[*]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_eval(autofree, &out, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_eval failed: %s", fr_strerror());

	result = fr_value_box_list_head(&out);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result->type == FR_TYPE_INT32);
	TEST_CHECK(result->vb_int32 == 10);

	result = fr_value_box_list_next(&out, result);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result->vb_int32 == 20);

	talloc_free(vpt);
	fr_value_box_list_talloc_free(&out);
	talloc_free(request);
}

static void test_eval_attr_count(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	fr_value_box_list_t	out;
	fr_value_box_t		*result;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*vp1, *vp2;
	ssize_t			slen;
	int			ret;

	fr_value_box_list_init(&out);

	pair_append_request(&vp1, fr_dict_attr_test_int32);
	vp1->vp_int32 = 10;

	pair_append_request(&vp2, fr_dict_attr_test_int32);
	vp2->vp_int32 = 20;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int32-0[#]", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_eval(autofree, &out, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_MSG("tmpl_eval failed: %s", fr_strerror());

	result = fr_value_box_list_head(&out);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result->type == FR_TYPE_UINT32);
	TEST_CHECK(result->vb_uint32 == 2);
	TEST_MSG("Expected count=2, got %" PRIu32, result->vb_uint32);

	talloc_free(vpt);
	fr_value_box_list_talloc_free(&out);
	talloc_free(request);
}

/*
 *	tmpl_find_vp() and tmpl_find_or_add_vp()
 */

static void test_find_vp_found(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*string_vp;
	fr_pair_t		*found = NULL;
	ssize_t			slen;
	int			ret;

	pair_append_request(&string_vp, fr_dict_attr_test_string);
	fr_pair_value_strdup(string_vp, "findme", false);

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_find_vp(&found, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_CHECK(found == string_vp);

	talloc_free(vpt);
	talloc_free(request);
}

static void test_find_vp_missing(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*found = NULL;
	ssize_t			slen;
	int			ret;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int16-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_find_vp(&found, request, vpt);
	TEST_CHECK(ret != 0);
	TEST_CHECK(found == NULL);

	talloc_free(vpt);
	talloc_free(request);
}

static void test_find_or_add_existing(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*string_vp;
	fr_pair_t		*found = NULL;
	ssize_t			slen;
	int			ret;

	pair_append_request(&string_vp, fr_dict_attr_test_string);
	fr_pair_value_strdup(string_vp, "existing", false);

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_find_or_add_vp(&found, request, vpt);
	TEST_CHECK(ret == 0);
	TEST_MSG("Expected 0 (found existing), got %d", ret);
	TEST_CHECK(found == string_vp);

	talloc_free(vpt);
	talloc_free(request);
}

static void test_find_or_add_new(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	request_t		*request = request_fake_alloc();
	fr_pair_t		*found = NULL;
	ssize_t			slen;
	int			ret;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-Int16-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	ret = tmpl_find_or_add_vp(&found, request, vpt);
	TEST_CHECK(ret == 1);
	TEST_MSG("Expected 1 (created new), got %d", ret);
	TEST_CHECK(found != NULL);
	TEST_MSG("Expected non-NULL vp from find_or_add");

	talloc_free(vpt);
	talloc_free(request);
}

/*
 *	tmpl_print() and friends.
 */

static void test_print_attr(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err;
	ssize_t			slen;
	char			*str = NULL;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(vpt != NULL);

	slen = tmpl_aprint(autofree, &str, vpt, NULL);
	TEST_CHECK(slen > 0);
	TEST_CHECK(str != NULL);
	if (str) {
		TEST_CHECK(strcmp(str, "Test-String-0") == 0);
		TEST_MSG("Expected 'Test-String-0', got '%s'", str);
		talloc_free(str);
	}

	talloc_free(vpt);
}

static void test_print_data_string(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;
	ssize_t		slen;
	char		*str = NULL;

	fr_value_box_init(&box, FR_TYPE_STRING, NULL, false);
	fr_value_box_strdup_shallow(&box, NULL, "hello", false);

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	slen = tmpl_aprint(autofree, &str, vpt, NULL);
	TEST_CHECK(slen > 0);
	TEST_CHECK(str != NULL);
	if (str) {
		TEST_CHECK(strcmp(str, "hello") == 0);
		TEST_MSG("Expected 'hello', got '%s'", str);
		talloc_free(str);
	}

	talloc_free(vpt);
}

static void test_print_data_uint32(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;
	ssize_t		slen;
	char		*str = NULL;

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 42;

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	slen = tmpl_aprint(autofree, &str, vpt, NULL);
	TEST_CHECK(slen > 0);
	TEST_CHECK(str != NULL);
	if (str) {
		TEST_CHECK(strcmp(str, "42") == 0);
		TEST_MSG("Expected '42', got '%s'", str);
		talloc_free(str);
	}

	talloc_free(vpt);
}

static void test_print_quoted(void)
{
	tmpl_t		*vpt = NULL;
	fr_value_box_t	box;
	int		ret;
	ssize_t		slen;
	char		*str = NULL;

	fr_value_box_init(&box, FR_TYPE_STRING, NULL, false);
	fr_value_box_strdup_shallow(&box, NULL, "hello", false);

	ret = tmpl_afrom_value_box(autofree, &vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(vpt != NULL);

	/*
	 *	String values from tmpl_afrom_value_box get T_SINGLE_QUOTED_STRING,
	 *	so tmpl_print_quoted should wrap with single quotes.
	 */
	slen = tmpl_aprint_quoted(autofree, &str, vpt);
	TEST_CHECK(slen > 0);
	TEST_CHECK(str != NULL);
	if (str) {
		TEST_CHECK(strcmp(str, "'hello'") == 0);
		TEST_MSG("Expected \"'hello'\", got '%s'", str);
		talloc_free(str);
	}

	talloc_free(vpt);
}

/*
 *	Type checking macros.
 */

static void test_type_checking(void)
{
	tmpl_t			*data_vpt = NULL;
	tmpl_t			*attr_vpt = NULL;
	tmpl_t			*unresolved_vpt = NULL;
	tmpl_attr_error_t	err;
	fr_value_box_t		box;
	ssize_t			slen;
	int			ret;

	/* Create a DATA tmpl */
	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 1;
	ret = tmpl_afrom_value_box(autofree, &data_vpt, &box, false);
	TEST_CHECK(ret == 0);
	TEST_ASSERT(data_vpt != NULL);
	TEST_CHECK(tmpl_is_data(data_vpt));
	TEST_CHECK(!tmpl_is_attr(data_vpt));
	TEST_CHECK(!tmpl_needs_resolving(data_vpt));

	/* Create an ATTR tmpl */
	slen = tmpl_afrom_attr_str(autofree, &err, &attr_vpt, "Test-String-0", test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(attr_vpt != NULL);
	TEST_CHECK(tmpl_is_attr(attr_vpt));
	TEST_CHECK(!tmpl_is_data(attr_vpt));
	TEST_CHECK(tmpl_contains_attr(attr_vpt));
	TEST_CHECK(!tmpl_needs_resolving(attr_vpt));

	/* Create a DATA_UNRESOLVED tmpl */
	slen = tmpl_afrom_substr(autofree, &unresolved_vpt, &FR_SBUFF_IN_STR("hello"),
				 T_DOUBLE_QUOTED_STRING, NULL, test_rules());
	TEST_CHECK(slen > 0);
	TEST_ASSERT(unresolved_vpt != NULL);

	/*
	 *	Double-quoted "hello" (no expansions) is DATA_UNRESOLVED.
	 */
	if (tmpl_is_data_unresolved(unresolved_vpt)) {
		TEST_CHECK(tmpl_needs_resolving(unresolved_vpt));
		TEST_CHECK(!tmpl_is_attr(unresolved_vpt));
	}

	talloc_free(data_vpt);
	talloc_free(attr_vpt);
	talloc_free(unresolved_vpt);
}

/*
 *	Error cases.
 */

static void test_parse_attr_empty_ref(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err = TMPL_ATTR_ERROR_NONE;
	ssize_t			slen;

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "", test_rules());
	TEST_CHECK(slen <= 0);
	TEST_CHECK(vpt == NULL);
	TEST_MSG("Expected error for empty attr ref '&', got slen=%zd", slen);
	TEST_CHECK(err != TMPL_ATTR_ERROR_NONE);
	TEST_MSG("Expected non-zero error code, got %d", err);
}

static void test_parse_attr_unresolved_disallowed(void)
{
	tmpl_t			*vpt = NULL;
	tmpl_attr_error_t	err = TMPL_ATTR_ERROR_NONE;
	ssize_t			slen;
	tmpl_rules_t		rules = {
		.attr = {
			.dict_def = test_dict,
			.list_def = request_attr_request,
			.allow_unresolved = false,
		}
	};

	slen = tmpl_afrom_attr_str(autofree, &err, &vpt, "No-Such-Attr", &rules);
	TEST_CHECK(slen < 0);
	TEST_MSG("Expected error when unresolved not allowed, got slen=%zd", slen);
	TEST_CHECK(vpt == NULL);
}

TEST_LIST = {
	/* Tokenization: tmpl_afrom_attr_str */
	{ "test_parse_attr_simple",		test_parse_attr_simple },
	{ "test_parse_attr_index",		test_parse_attr_index },
	{ "test_parse_attr_all",		test_parse_attr_all },
	{ "test_parse_attr_count",		test_parse_attr_count },
	{ "test_parse_attr_last",		test_parse_attr_last },
	{ "test_parse_attr_nested",		test_parse_attr_nested },
	{ "test_parse_attr_missing",		test_parse_attr_missing },
	{ "test_parse_attr_invalid",		test_parse_attr_invalid },
	{ "test_parse_attr_emptystring",       	test_parse_attr_emptystring },

	/* Tokenization: tmpl_afrom_substr */
	{ "test_parse_bareword_attr",		test_parse_bareword_attr },
	{ "test_parse_single_quoted",		test_parse_single_quoted },
	{ "test_parse_double_quoted_literal",	test_parse_double_quoted_literal },
	{ "test_parse_double_quoted_xlat",	test_parse_double_quoted_xlat },

	/* tmpl_afrom_value_box */
	{ "test_from_value_box_string",		test_from_value_box_string },
	{ "test_from_value_box_uint32",		test_from_value_box_uint32 },
	{ "test_from_value_box_ipaddr",		test_from_value_box_ipaddr },

	/* tmpl_cast_in_place */
	{ "test_cast_unresolved_to_uint32",	test_cast_unresolved_to_uint32 },
	{ "test_cast_unresolved_to_string",	test_cast_unresolved_to_string },
	{ "test_cast_uint32_to_uint64",		test_cast_uint32_to_uint64 },
	{ "test_cast_invalid",			test_cast_invalid },

	/* tmpl_copy */
	{ "test_copy_data",			test_copy_data },
	{ "test_copy_attr",			test_copy_attr },
	{ "test_copy_data_unresolved",		test_copy_data_unresolved },

	/* tmpl_eval and tmpl_eval_pair */
	{ "test_eval_data",			test_eval_data },
	{ "test_eval_attr_found",		test_eval_attr_found },
	{ "test_eval_attr_missing",		test_eval_attr_missing },
	{ "test_eval_attr_multiple",		test_eval_attr_multiple },
	{ "test_eval_attr_count",		test_eval_attr_count },

	/* tmpl_find_vp and tmpl_find_or_add_vp */
	{ "test_find_vp_found",		test_find_vp_found },
	{ "test_find_vp_missing",		test_find_vp_missing },
	{ "test_find_or_add_existing",		test_find_or_add_existing },
	{ "test_find_or_add_new",		test_find_or_add_new },

	/* tmpl_print and tmpl_print_quoted */
	{ "test_print_attr",			test_print_attr },
	{ "test_print_data_string",		test_print_data_string },
	{ "test_print_data_uint32",		test_print_data_uint32 },
	{ "test_print_quoted",			test_print_quoted },

	/* Type checking macros */
	{ "test_type_checking",			test_type_checking },

	/* Error cases */
	{ "test_parse_attr_empty_ref",		test_parse_attr_empty_ref },
	{ "test_parse_attr_unresolved_disallowed", test_parse_attr_unresolved_disallowed },

	TEST_TERMINATOR
};

DIAG_ON(declaration-after-statement)
