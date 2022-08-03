#define USE_CONSTRUCTOR

#ifdef USE_CONSTRUCTOR
static void test_init(void) __attribute((constructor));
#else
static void test_init(void);
#define TEST_INIT test_init()
#endif

#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/pair.h>


static TALLOC_CTX       *autofree;
static fr_dict_t	*test_dict;


/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("tmpl_dcursor_tests");
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
	request = request_local_alloc_external(autofree, NULL);

	request->packet = fr_radius_packet_alloc(request, false);
	TEST_CHECK(request->packet != NULL);

	request->reply = fr_radius_packet_alloc(request, false);
	TEST_CHECK(request->reply != NULL);

	return request;
}

#define pair_defs(_x) \
	fr_pair_t	*int32_vp ## _x; \
	fr_pair_t	*string_vp ## _x; \
	fr_pair_t	*group_vp ## _x; \
	fr_pair_t	*child_vp ## _x; \
	fr_pair_t	*top_vp ## _x; \
	fr_pair_t	*mid_vp ## _x; \
	fr_pair_t	*leaf_string_vp ## _x; \
	fr_pair_t	*leaf_int32_vp ## _x

#define pair_populate(_x) \
	pair_append_request(&int32_vp ## _x, fr_dict_attr_test_int32); \
	pair_append_request(&string_vp ## _x, fr_dict_attr_test_string); \
	pair_append_request(&group_vp ## _x, fr_dict_attr_test_group); \
	fr_pair_append_by_da(group_vp ## _x, &child_vp ## _x, &group_vp ## _x->children, fr_dict_attr_test_int16); \
	pair_append_request(&top_vp ## _x, fr_dict_attr_test_nested_top_tlv); \
	fr_pair_append_by_da(top_vp ## _x, &mid_vp ## _x, &top_vp ## _x->children, fr_dict_attr_test_nested_child_tlv); \
	fr_pair_append_by_da(mid_vp ## _x, &leaf_string_vp ## _x, &mid_vp ## _x->children, fr_dict_attr_test_nested_leaf_string); \
	fr_pair_append_by_da(mid_vp ## _x, &leaf_int32_vp ## _x, &mid_vp ## _x->children, fr_dict_attr_test_nested_leaf_int32);

/*
 *	Top level attribute names in the test dictionary all have -0 on the end
 *	due to the ability to add multiple instances of each attribute for the
 *	pair list performance tests.
 *
 * 	So, when entering strings to build tmpls, ensure the top level attriubutes
 *	all end -0.
 *
 *	The same applies to immediate children of group attributes since they will
 *	be other top level attributes.
 */

/*
 *	Variables used in all tests
 */
#define common_vars \
	request_t		*request = request_fake_alloc(); \
	fr_dcursor_t		cursor; \
	tmpl_dcursor_ctx_t	cc; \
	int			err; \
	tmpl_t			*vpt; \
	char const		*ref; \
	fr_pair_t		*vp

/*
 *	Common code for every test
 */
#define tmpl_setup_and_cursor_init(_attr) \
	ref = _attr; \
	tmpl_afrom_attr_substr(autofree, NULL, &vpt, &FR_SBUFF_IN(ref, strlen(ref)), NULL, &(tmpl_rules_t){.attr = {.dict_def = test_dict}}); \
	vp = tmpl_dcursor_init(&err, NULL, &cc, &cursor, request, vpt);

/*
 *	How every test ends
 */
#define test_end \
	vp = fr_dcursor_next(&cursor); \
	TEST_CHECK(vp == NULL); \
	tmpl_dursor_clear(&cc); \
	TEST_CHECK_RET(talloc_free(request), 0)

/*
 *	One instance of attribute at the top level
 */
static void test_level_1_one(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Int32-0");
	TEST_CHECK(vp == int32_vp1);

	test_end;
}

/*
 *	One instance of attribute at the top level - search for second
 */
static void test_level_1_one_second(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Int32-0[1]");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	One instance of attribute at the top level - search for all
 */
static void test_level_1_one_all(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Int32-0[*]");
	TEST_CHECK(vp == int32_vp1);

	test_end;
}

/*
 *	One instance of attribute at the top level - search for non-existant
 */
static void test_level_1_one_missing(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Int16-0");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	One instance of attribute at the top level - search for last
 */
static void test_level_1_one_last(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Int32-0[n]");
	TEST_CHECK(vp == int32_vp1);

	test_end;
}

/*
 *	Two instances of attribute at the top level
 */
static void test_level_1_two(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0");
	TEST_CHECK(vp == int32_vp1);

	test_end;
}

/*
 *	Two instances of attribute at the top level - choose second
 */
static void test_level_1_two_second(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0[1]");
	TEST_CHECK(vp == int32_vp2);

	test_end;
}

/*
 *	Two instances of attribute at the top level - choose third - should be NULL
 */
static void test_level_1_two_third(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0[2]");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	Two instances of attribute at the top level - choose all
 */
static void test_level_1_two_all(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0[*]");

	TEST_CHECK(vp == int32_vp1);

	vp = fr_dcursor_next(&cursor);
	TEST_CHECK(vp == int32_vp2);

	test_end;
}

/*
 *	Two instances of attribute at the top level - choose last
 */
static void test_level_1_two_last(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0[n]");
	TEST_CHECK(vp == int32_vp2);

	test_end;
}

/*
 *	Two instances of attribute at the top level - use count suffix
 */
static void test_level_1_two_count(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Int32-0[#]");
	TEST_CHECK(vp == int32_vp1);

	vp = fr_dcursor_next(&cursor);
	TEST_CHECK(vp == int32_vp2);

	test_end;
}

/*
 *	One instance of a group attribute
 */
static void test_level_2_one(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Group-0.Test-Int16-0");
	TEST_CHECK(vp == child_vp1);

	test_end;
}

/*
 *	One instance of a group attribute - look for second child
 */
static void test_level_2_one_second(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Group-0.Test-Int16-0[1]");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	One instance of a group attribute - look for all
 */
static void test_level_2_one_all(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Group-0.Test-Int16-0[*]");
	TEST_CHECK(vp == child_vp1);

	test_end;
}

/*
 *	One instance of a group attribute - look for missing
 */
static void test_level_2_one_missing(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Group-0.Test-Int32-0");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	Two instances of a group attribute
 */
static void test_level_2_two(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Group-0.Test-Int16-0");
	TEST_CHECK(vp == child_vp1);

	test_end;
}

/*
 *	Two instances of a group attribute - look for child in second parent
 */
static void test_level_2_two_second(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Group-0[1].Test-Int16-0");
	TEST_CHECK(vp == child_vp2);

	test_end;
}

/*
 *	Two instances of a group attribute - children of all parents
 */
static void test_level_2_two_all(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Group-0[*].Test-Int16-0");
	TEST_CHECK(vp == child_vp1);

	vp = fr_dcursor_next(&cursor);
	TEST_CHECK(vp == child_vp2);

	test_end;
}

/*
 *	Two instances of a group attribute - children of last parent
 */
static void test_level_2_two_last(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Group-0[n].Test-Int16-0");
	TEST_CHECK(vp == child_vp2);

	test_end;
}

/*
 *	Two instances of a group attribute - missing children of all parents
 */
static void test_level_2_two_missing(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Group-0[*].Test-Int32-0");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	Single instance of three level TLV
 */
static void test_level_3_one(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-String");
	TEST_CHECK(vp == leaf_string_vp1);

	test_end;
}

/*
 *	Single instance of three level TLV - look for a second instance of level 2 TLV
 */
static void test_level_3_one_second(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[0].Child-TLV[1].Leaf-String");
	TEST_CHECK(vp == NULL);

	test_end;
}

/*
 *	Single instance of three level TLV - look for a second instance of level 2 TLV
 */
static void test_level_3_one_all(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[0].Child-TLV[*].Leaf-String");
	TEST_CHECK(vp == leaf_string_vp1);

	test_end;
}

static void test_level_3_two(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-Int32");
	TEST_CHECK(vp == leaf_int32_vp1);

	test_end;
}

static void test_level_3_two_all(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[*].Child-TLV[*].Leaf-Int32");
	TEST_CHECK(vp == leaf_int32_vp1);

	vp = fr_dcursor_next(&cursor);
	TEST_CHECK(vp == leaf_int32_vp2);

	test_end;
}

static void test_level_3_two_last(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init("&Test-Nested-Top-TLV-0[n].Child-TLV[n].Leaf-Int32[n]");
	TEST_CHECK(vp == leaf_int32_vp2);

	test_end;
}

TEST_LIST = {
	{ "test_level_1_one",		test_level_1_one },
	{ "test_level_1_one_second",	test_level_1_one_second },
	{ "test_level_1_one_all",	test_level_1_one_all },
	{ "test_level_1_one_missing",	test_level_1_one_missing },
	{ "test_level_1_one_last",	test_level_1_one_last },
	{ "test_level_1_two",		test_level_1_two },
	{ "test_level_1_two_second",	test_level_1_two_second },
	{ "test_level_1_two_third",	test_level_1_two_third },
	{ "test_level_1_two_all",	test_level_1_two_all },
	{ "test_level_1_two_last",	test_level_1_two_last },
	{ "test_level_1_two_count",	test_level_1_two_count },
	{ "test_level_2_one", 		test_level_2_one },
	{ "test_level_2_one_second",	test_level_2_one_second },
	{ "test_level_2_one_all",	test_level_2_one_all },
	{ "test_level_2_one_missing",	test_level_2_one_missing },
	{ "test_level_2_two",		test_level_2_two },
	{ "test_level_2_two_second",	test_level_2_two_second },
	{ "test_level_2_two_all",	test_level_2_two_all },
	{ "test_level_2_two_last",	test_level_2_two_last },
	{ "test_level_2_two_missing",	test_level_2_two_missing },
	{ "test_level_3_one",		test_level_3_one },
	{ "test_level_3_one_second",	test_level_3_one_second },
	{ "test_level_3_one_all",	test_level_3_one_all },
	{ "test_level_3_two",		test_level_3_two },
	{ "test_level_3_two_all",	test_level_3_two_all },
	{ "test_level_3_two_last",	test_level_3_two_last },

	{ NULL }
};
