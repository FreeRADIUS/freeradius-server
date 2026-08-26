static void test_init(void);
#  define TEST_INIT  test_init()

#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/pair.h>


static TALLOC_CTX       *autofree;
static fr_dict_t	*test_dict;

DIAG_OFF(declaration-after-statement)

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
	request = request_local_alloc_external(autofree, (&(request_init_args_t){ .namespace = test_dict }));

	request->packet = fr_packet_alloc(request, false);
	TEST_CHECK(request->packet != NULL);

	request->reply = fr_packet_alloc(request, false);
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

#define pair_defs_thin(_x) \
	fr_pair_t	*int32_vp ## _x; \
	fr_pair_t	*group_vp ## _x; \
	fr_pair_t	*top_vp ## _x; \
	fr_pair_t	*mid_vp ## _x; \
	fr_pair_t	*leaf_int32_vp ## _x

#define pair_populate(_x) do { \
	pair_append_request(&int32_vp ## _x, fr_dict_attr_test_int32); \
	pair_append_request(&string_vp ## _x, fr_dict_attr_test_string); \
	pair_append_request(&group_vp ## _x, fr_dict_attr_test_group); \
	fr_pair_append_by_da(group_vp ## _x, &child_vp ## _x, &group_vp ## _x->children, fr_dict_attr_test_int16); \
	pair_append_request(&top_vp ## _x, fr_dict_attr_test_nested_top_tlv); \
	fr_pair_append_by_da(top_vp ## _x, &mid_vp ## _x, &top_vp ## _x->children, fr_dict_attr_test_nested_child_tlv); \
	fr_pair_append_by_da(mid_vp ## _x, &leaf_string_vp ## _x, &mid_vp ## _x->children, fr_dict_attr_test_nested_leaf_string); \
	fr_pair_append_by_da(mid_vp ## _x, &leaf_int32_vp ## _x, &mid_vp ## _x->children, fr_dict_attr_test_nested_leaf_int32); \
     } while (0)

#define pair_populate_thin(_x) do { \
	pair_append_request(&int32_vp ## _x, fr_dict_attr_test_int32); \
	pair_append_request(&group_vp ## _x, fr_dict_attr_test_group); \
	pair_append_request(&top_vp ## _x, fr_dict_attr_test_nested_top_tlv); \
	fr_pair_append_by_da(top_vp ## _x, &mid_vp ## _x, &top_vp ## _x->children, fr_dict_attr_test_nested_child_tlv); \
	fr_pair_append_by_da(mid_vp ## _x, &leaf_int32_vp ## _x, &mid_vp ## _x->children, fr_dict_attr_test_nested_leaf_int32); \
      } while (0)

/*
 *	Top level attribute names in the test dictionary all have -0 on the end
 *	due to the ability to add multiple instances of each attribute for the
 *	pair list performance tests.
 *
 * 	So, when entering strings to build tmpls, ensure the top level attributes
 *	all end -0.
 *
 *	The same applies to immediate children of group attributes since they will
 *	be other top level attributes.
 */

typedef struct {
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	int			err;
	tmpl_t			*vpt;
	fr_pair_t		*vp;
} tmpl_dcursor_vars_t;

#define test_cursor() &vars.cursor
#define test_vp() vars.vp
#define test_vp_p() &vars.vp
#define test_vp_set(_vp) vars.vp = _vp

/*
 *	Variables used in all tests
 */
#define common_vars \
	tmpl_dcursor_vars_t vars; \
	request_t *request = request_fake_alloc()

/** Initialise a tmpl using the _attr_str string, and return the first pair
 *
 * @param[out] vp_out		where to write the returned pair
 * @param[in,out] vars		test variables
 * @param[in] request		the current request.
 * @param[in] ref		Attribute reference string.
 */
static inline CC_HINT(always_inline)
int _tmpl_setup_and_cursor_init(fr_pair_t **vp_out, tmpl_dcursor_vars_t *vars, request_t *request, char const *ref)
{
	tmpl_afrom_attr_substr(autofree, NULL, &vars->vpt, &FR_SBUFF_IN_STR(ref), NULL, &(tmpl_rules_t){
			.attr = {
				.dict_def = test_dict,
				.list_def = request_attr_request,
			}});
	TEST_CHECK(vars->vpt!= NULL);
	TEST_MSG("Failed creating tmpl from %s: %s", ref, fr_strerror());
	if (!vars->vpt) {
		*vp_out = NULL;
		return -1;
	}

	*vp_out = tmpl_dcursor_init(&vars->err, NULL, &vars->cc, &vars->cursor, request, vars->vpt);
	return 0;
}

#define tmpl_setup_and_cursor_init(_vp_out, _ref) \
	if (_tmpl_setup_and_cursor_init(_vp_out, &vars, request, _ref)) return

/** Initialise a tmpl using the _attr_str string, and return the first pair
 *
 * @param[out] vp_out		where to write the returned pair.
 * @param[in,out] vars		test variables
 * @param[in] request		the current request.
 * @param[in] ref		Attribute reference string.
 */
static inline CC_HINT(always_inline)
int _tmpl_setup_and_cursor_build_init(fr_pair_t **vp_out, tmpl_dcursor_vars_t *vars, request_t *request, char const *ref)
{
	tmpl_afrom_attr_substr(autofree, NULL, &vars->vpt, &FR_SBUFF_IN_STR(ref), NULL, &(tmpl_rules_t){
			.attr = {
				.dict_def = test_dict,
				.list_def = request_attr_request,
			}});
	TEST_CHECK(vars->vpt!= NULL);
	TEST_MSG("Failed creating tmpl from %s: %s", ref, fr_strerror());
	if (!vars->vpt) {
		*vp_out = NULL;
		return -1;
	}

	*vp_out = tmpl_dcursor_build_init(&vars->err, autofree, &vars->cc, &vars->cursor, request, vars->vpt, &tmpl_dcursor_pair_build, NULL);
	return 0;
}

#define tmpl_setup_and_cursor_build_init(_vp_out, _ref) \
	if (_tmpl_setup_and_cursor_build_init(_vp_out, &vars, request, _ref)) return

/*
 *	How every test ends
 */
#define test_end \
	debug_attr_list(&request->request_pairs, 0); \
	vars.vp = fr_dcursor_next(test_cursor()); \
	TEST_CHECK_PAIR(vars.vp, NULL); \
	TEST_MSG("Cursor should've been empty (i.e. returned NULL) at end of test"); \
	tmpl_dcursor_clear(&vars.cc); \
	TEST_CHECK_RET(talloc_free(vars.vpt), 0); \
	TEST_CHECK_RET(talloc_free(request), 0)

/*
 *	Call after "build" cursors
 *	Checks that no additional attributes are created
 */
#define build_test_end \
	debug_attr_list(&request->request_pairs, 0); \
	test_vp_set(fr_dcursor_next(test_cursor())); \
	TEST_CHECK_PAIR(test_vp(), NULL); \
	tmpl_dcursor_clear(&vars.cc)

static void debug_attr_list(fr_pair_list_t *list, int indent)
{
	fr_pair_t *vp = NULL;
	while ((vp = fr_pair_list_next(list, vp))) {
		switch (vp->vp_type) {
		case FR_TYPE_STRUCTURAL:
			TEST_MSG("%*s%s => {", indent, "", vp->da->name);
			debug_attr_list(&vp->vp_group, indent + 2);
			TEST_MSG("%*s}", indent, "");
			break;
		default:
			TEST_MSG("%*s%s", indent, "", vp->da->name);
		}
	}
}

/*
 *	One instance of attribute at the top level
 */
static void test_level_1_one(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), int32_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[1]");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[*]");
	TEST_CHECK_PAIR(test_vp(), int32_vp1);

	test_end;
}

/*
 *	One instance of attribute at the top level - search for non-existent
 */
static void test_level_1_one_missing(void)
{
	common_vars;
	pair_defs(1);

	pair_populate(1);
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[n]");
	TEST_CHECK_PAIR(test_vp(), int32_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), int32_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[1]");
	TEST_CHECK_PAIR(test_vp(), int32_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[2]");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[*]");

	TEST_CHECK_PAIR(test_vp(), int32_vp1);

	test_vp_set(fr_dcursor_next(test_cursor()));
	TEST_CHECK_PAIR(test_vp(), int32_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[n]");
	TEST_CHECK_PAIR(test_vp(), int32_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int32-0[#]");
	TEST_CHECK_PAIR(test_vp(), int32_vp1);

	test_vp_set(fr_dcursor_next(test_cursor()));
	TEST_CHECK_PAIR(test_vp(), int32_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), child_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int16-0[1]");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int16-0[*]");
	TEST_CHECK_PAIR(test_vp(), child_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), child_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0[1].Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), child_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0[*].Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), child_vp1);

	test_vp_set(fr_dcursor_next(test_cursor()));
	TEST_CHECK_PAIR(test_vp(), child_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0[n].Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), child_vp2);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0[*].Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), leaf_string_vp1);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[0].Child-TLV[1].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), NULL);

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
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[0].Child-TLV[*].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), leaf_string_vp1);

	test_end;
}

static void test_level_3_two(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-Int32");
	TEST_CHECK_PAIR(test_vp(), leaf_int32_vp1);

	test_end;
}

static void test_level_3_two_all(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[*].Child-TLV[*].Leaf-Int32");
	TEST_CHECK_PAIR(test_vp(), leaf_int32_vp1);

	test_vp_set(fr_dcursor_next(test_cursor()));
	TEST_CHECK_PAIR(test_vp(), leaf_int32_vp2);

	test_end;
}

static void test_level_3_two_last(void)
{
	common_vars;
	pair_defs(1);
	pair_defs(2);

	pair_populate(1);
	pair_populate(2);
	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[n].Child-TLV[n].Leaf-Int32[n]");
	TEST_CHECK_PAIR(test_vp(), leaf_int32_vp2);

	test_end;
}

static void test_level_1_build(void)
{
	common_vars;
	pair_defs(1);
	fr_pair_t	*inserted;

	pair_populate(1);
	tmpl_setup_and_cursor_build_init(&inserted, "Test-Int16-0");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_2_build_leaf(void)
{
	common_vars;
	pair_defs(1);
	fr_pair_t	*inserted;

	pair_populate(1);
	tmpl_setup_and_cursor_build_init(&inserted, "Test-Group-0.Test-Int32-0");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_2_build_intermediate(void)
{
	common_vars;
	fr_pair_t	*inserted;

	tmpl_setup_and_cursor_build_init(&inserted, "Test-Group-0.Test-Int16-0");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Int16-0");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_2_build_multi(void)
{
	common_vars;
	pair_defs_thin(1);
	pair_defs_thin(2);
	fr_pair_t	*inserted, *second;

	pair_populate_thin(1);
	pair_populate_thin(2);
	tmpl_setup_and_cursor_build_init(&inserted, "Test-Group-0[*].Test-Int32-0");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);

	second = fr_dcursor_next(test_cursor());
	TEST_CHECK_PAIR_NEQ(second, NULL);
	TEST_CHECK_PAIR_NEQ(second, inserted);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0[*].Test-Int32-0");
	TEST_CHECK_PAIR(test_vp(), inserted);
	test_vp_set(fr_dcursor_next(test_cursor()));
	TEST_CHECK_PAIR(test_vp(), second);

	test_end;
}

static void test_level_3_build_leaf(void)
{
	common_vars;
	pair_defs(1);
	fr_pair_t	*inserted;

	pair_populate(1);
	tmpl_setup_and_cursor_build_init(&inserted, "Test-Group-0.Test-Group-0.Test-String-0");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Group-0.Test-Group-0.Test-String-0");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_3_build_entire(void)
{
	common_vars;
	fr_pair_t	*inserted;

	tmpl_setup_and_cursor_build_init(&inserted, "Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[0].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_3_build_partial(void)
{
	common_vars;
	pair_defs(1);
	pair_defs_thin(2);
	fr_pair_t	*inserted;

	pair_populate(1);
	pair_populate_thin(2);
	tmpl_setup_and_cursor_build_init(&inserted, "Test-Nested-Top-TLV-0[1].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR_NEQ(inserted, NULL);
	TEST_CHECK_PAIR_NEQ(inserted, leaf_string_vp1);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[1].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), inserted);

	test_end;
}

static void test_level_3_build_invalid1(void)
{
	common_vars;
	fr_pair_t	*inserted;

	tmpl_setup_and_cursor_build_init(&inserted, "Test-Nested-Top-TLV-0[3].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[3].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), NULL);

	test_end;
}

static void test_level_3_build_invalid2(void)
{
	common_vars;
	fr_pair_t	*inserted;

	tmpl_setup_and_cursor_build_init(&inserted, "Test-Nested-Top-TLV-0[*].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(inserted, NULL);
	build_test_end;

	tmpl_setup_and_cursor_init(test_vp_p(), "Test-Nested-Top-TLV-0[*].Child-TLV[0].Leaf-String");
	TEST_CHECK_PAIR(test_vp(), NULL);

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

	{ "test_level_1_build",			test_level_1_build },
	{ "test_level_2_build_leaf",		test_level_2_build_leaf },
	{ "test_level_2_build_intermediate",	test_level_2_build_intermediate },
	{ "test_level_2_build_multi",		test_level_2_build_multi },
	{ "test_level_3_build_leaf",		test_level_3_build_leaf },
	{ "test_level_3_build_entire",		test_level_3_build_entire },
	{ "test_level_3_build_partial",		test_level_3_build_partial },
	{ "test_level_3_build_invalid1",	test_level_3_build_invalid1 },
	{ "test_level_3_build_invalid2",	test_level_3_build_invalid2 },

	TEST_TERMINATOR
};

DIAG_ON(declaration-after-statement)
