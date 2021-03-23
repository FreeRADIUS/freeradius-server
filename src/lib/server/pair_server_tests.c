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

/** Tests for a AVP manipulation and search API.
 *
 * @file src/lib/server/pair_server_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

/**
 *	The 'TEST_INIT' macro provided by 'acutest.h' allowing to register a function to be called
 *	before call the unit tests. Therefore, It calls the function ALL THE TIME causing an overhead.
 *	That is why we are initializing pair_tests_init() by "__attribute__((constructor));" reducing the
 *	test execution by 50% of the time.
 */
#define USE_CONSTRUCTOR

/*
 * It should be declared before include the "acutest.h"
 */
#ifdef USE_CONSTRUCTOR
static void pair_tests_init(void) __attribute__((constructor));
#else
static void pair_tests_init(void);
#	define TEST_INIT  pair_tests_init()
#endif

#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/request.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#	include <gperftools/profiler.h>
#endif

static char const       *dict_dir  = "share/dictionary";

/* Set by pair_tests_init()*/
static TALLOC_CTX       *autofree;
static fr_pair_list_t   sample_pairs;

typedef struct value {
	char const *key;
	fr_value_box_t val;
} fr_dict_adhoc_attr_value_t;

typedef struct {
	int attr;
	fr_dict_attr_t const **parent;
	fr_dict_attr_t const **da;
	char const *name;
	fr_type_t type;
	void *values;
} fr_dict_adhoc_attr_t;

#define FR_TEST_INTEGER         1
#define FR_TEST_STRING          2
#define FR_TEST_OCTETS          3
#define FR_TEST_VALUES          4
#define FR_TEST_TLV_ROOT        5
#define FR_TEST_TLV_STRING      1

static fr_dict_t *dict_test;

static fr_dict_attr_t const *attr_test_integer;
static fr_dict_attr_t const *attr_test_string;
static fr_dict_attr_t const *attr_test_octets;
static fr_dict_attr_t const *attr_test_values;
static fr_dict_attr_t const *attr_test_tlv_root;
static fr_dict_attr_t const *attr_test_tlv_string;

static fr_dict_adhoc_attr_value_t attr_test_values_entries[] = {
	{ .key = "Tapioca123", .val = { .type = FR_TYPE_UINT32, .vb_uint32 = 123 } },
	{ .key = "Tapioca321", .val = { .type = FR_TYPE_UINT32, .vb_uint32 = 321 } },
	{ .key = NULL, },
};

static fr_dict_adhoc_attr_t test_dict_attrs[] = {
	{ .attr = FR_TEST_INTEGER, .parent = NULL, .da = &attr_test_integer, .name = "Test-Integer", .type = FR_TYPE_UINT32, },
	{ .attr = FR_TEST_STRING, .parent = NULL, .da = &attr_test_string, .name = "Test-String", .type = FR_TYPE_STRING, },
	{ .attr = FR_TEST_OCTETS, .parent = NULL, .da = &attr_test_octets, .name = "Test-Octets", .type = FR_TYPE_OCTETS, },
	{ .attr = FR_TEST_VALUES, .parent = NULL, .da = &attr_test_values, .name = "Test-Values", .type = FR_TYPE_UINT32, .values = &attr_test_values_entries },
	{ .attr = FR_TEST_TLV_ROOT, .parent = NULL, .da = &attr_test_tlv_root, .name = "Test-TLV-Root", .type = FR_TYPE_TLV, },
	{ .attr = FR_TEST_TLV_STRING, .parent = &attr_test_tlv_root, .da = &attr_test_tlv_string, .name = "Test-TLV-String", .type = FR_TYPE_STRING, },
	{ .attr = -1, .parent = NULL, .da = NULL, .name = NULL, .type = FR_TYPE_NULL }
};

/*
 *	It will be called before of unit tests.
 */
static int load_attr_pairs(fr_pair_list_t *out)
{
	fr_dict_adhoc_attr_t *p;

	fr_pair_list_init(out);

	for (p = test_dict_attrs;
	     p->attr != -1;
	     p++) if (fr_pair_prepend_by_da(autofree, NULL, out, *p->da) < 0) return -1;

	return 0;
}

static int init_adhoc_attrs(fr_dict_adhoc_attr_t *dict_adhoc)
{
	fr_dict_adhoc_attr_t *ctx;
	fr_dict_attr_flags_t dict_flags = {
		.is_root = true
	};

	for (ctx = dict_adhoc;
	     ctx->attr != -1;
	     ctx++) {
		fr_dict_attr_t const *parent = ctx->parent ? *ctx->parent : fr_dict_root(dict_test);
		fr_dict_attr_t const *attr;

		if (fr_dict_attr_add(dict_test, parent, ctx->name, ctx->attr, ctx->type, &dict_flags) < 0) return -1;

		attr = fr_dict_attr_by_name(NULL, parent, ctx->name);
		if (!attr) return -1;

		/* Set the VALUES */
		if (ctx->values) {
			fr_dict_adhoc_attr_value_t *v;

			for (v = ctx->values;
			     v->key != NULL;
			     v++) fr_dict_enum_add_name(fr_dict_attr_unconst(attr), v->key, &v->val, false, false);
		}

		*ctx->da = attr;
	}

	return 0;
}

static void pair_tests_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("pair_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (!fr_dict_global_ctx_init(autofree, dict_dir)) goto error;

	/*
	 *	Initialise attributes that go in requests
	 */
	if (request_global_init() < 0) goto error;

	/*
	 *	Set the root name of the dictionary
	 */
	dict_test = fr_dict_alloc("test", 666);
	if (!dict_test) goto error;

	if (init_adhoc_attrs(test_dict_attrs) < 0) goto error;

	/* Initialize the "sample_pairs" list */
	fr_pair_list_init(&sample_pairs);
	if (load_attr_pairs(&sample_pairs) < 0) goto error;


}

static request_t *request_fake_alloc(void)
{
	request_t	*request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc(autofree, NULL);

	request->packet = fr_radius_packet_alloc(request, false);
	TEST_CHECK(request->packet != NULL);

	request->reply = fr_radius_packet_alloc(request, false);
	TEST_CHECK(request->reply != NULL);

	return request;
}

/*
 *	Tests functions
 */
static void test_pair_append_request(void)
{
	fr_pair_t      *local_vp;
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Add 'Test-Integer' in 'request_pairs' using pair_append_request()");
	TEST_CHECK(pair_append_request(&local_vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	TEST_CHECK((vp = fr_pair_list_head(&request->request_pairs)) != NULL);
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 12345");
	vp->vp_uint32 = 12345;
	TEST_CHECK(vp->vp_uint32 == 12345);
	TEST_MSG("Expected %s == 12345", attr_test_integer->name);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_append_reply(void)
{
	fr_pair_t      *local_vp;
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Add 'Test-Integer' in 'reply_pairs' using pair_append_reply()");
	TEST_CHECK(pair_append_reply(&local_vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	TEST_CHECK((vp = fr_pair_list_head(&request->reply_pairs)) != NULL);
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 12345");
	vp->vp_uint32 = 12345;

	TEST_CHECK(vp->vp_uint32 == 12345);
	TEST_MSG("Expected %s == 12345", attr_test_integer->name);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_append_control(void)
{
	fr_pair_t      *local_vp;
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Add 'Test-Integer' in 'control_pairs' using pair_append_control()");
	TEST_CHECK(pair_append_control(&local_vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	TEST_CHECK((vp = fr_pair_list_head(&request->control_pairs)) != NULL);
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 12345");
	vp->vp_uint32 = 12345;

	TEST_CHECK(vp->vp_uint32 == 12345);
	TEST_MSG("Expected %s == 12345", attr_test_integer->name);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_append_session_state(void)
{
	fr_pair_t      *local_vp;
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Add 'Test-Integer' in 'control_pairs' using pair_append_session_state()");
	TEST_CHECK(pair_append_session_state(&local_vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	TEST_CHECK((vp = fr_pair_list_head(&request->session_state_pairs)) != NULL);
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 12345");
	vp->vp_uint32 = 12345;

	TEST_CHECK(vp->vp_uint32 == 12345);
	TEST_MSG("Expected %s == 12345", attr_test_integer->name);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_update_request(void)
{
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Update 'Test-Integer' in 'request_pairs' using pair_update_request()");
	TEST_CHECK(pair_update_request(&vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 112233");
	vp->vp_uint32 = 112233;

	TEST_CASE("Expected attr_test_integer (vp->vp_uint32 == 112233)");
	TEST_CHECK((vp = fr_pair_find_by_da(&request->request_pairs, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_MSG("Checking if vp == 12345");
	/*
	 * Such 'vp != NULL' just to mute clang "warning: Dereference of null pointer"
	 */
	TEST_CHECK(vp && vp->vp_uint32 == 112233);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_update_reply(void)
{
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Update 'Test-Integer' in 'reply_pairs' using pair_update_request()");
	TEST_CHECK(pair_update_reply(&vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 3333");
	vp->vp_uint32 = 3333;

	TEST_CASE("Expected attr_test_integer (vp->vp_uint32 == 3333)");
	TEST_CHECK((vp = fr_pair_find_by_da(&request->reply_pairs, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp && vp->vp_uint32 == 3333);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_update_control(void)
{
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Update 'Test-Integer' in 'control_pairs' using pair_update_control()");
	TEST_CHECK(pair_update_control(&vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 44444");
	vp->vp_uint32 = 44444;

	TEST_CASE("Expected attr_test_integer (vp->vp_uint32 == 44444)");
	TEST_CHECK((vp = fr_pair_find_by_da(&request->control_pairs, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp && vp->vp_uint32 == 44444);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_update_session_state(void)
{
	fr_pair_t      *vp;
	request_t      *request = request_fake_alloc();

	TEST_CASE("Update 'Test-Integer' in 'state' using pair_update_session_state()");
	TEST_CHECK(pair_update_session_state(&vp, attr_test_integer) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_MSG("Set vp = 7890");
	vp->vp_uint32 = 7890;

	TEST_CASE("Expected attr_test_integer (vp->vp_uint32 == 7890)");
	TEST_CHECK((vp = fr_pair_find_by_da(&request->session_state_pairs, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp && vp->vp_uint32 == 7890);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_delete_request(void)
{
	request_t      *request = request_fake_alloc();

	TEST_CASE("Copy 'sample_pairs' into 'request->request_pairs'");
	TEST_CHECK(fr_pair_list_copy(autofree, &request->request_pairs, &sample_pairs) > 0);

	TEST_CASE("Delete 'Test-Integer' in 'request->request_pairs' using pair_delete_request()");
	TEST_CHECK(pair_delete_request(attr_test_integer) > 0);

	TEST_CASE("The 'Test-Integer' shouldn't exist in 'request->request_pairs'");
	TEST_CHECK(fr_pair_find_by_da(&request->request_pairs, attr_test_integer) == NULL);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_delete_reply(void)
{
	request_t      *request = request_fake_alloc();

	TEST_CASE("Copy 'sample_pairs' into 'request->reply_pairs'");
	TEST_CHECK(fr_pair_list_copy(autofree, &request->reply_pairs, &sample_pairs) > 0);

	TEST_CASE("Delete 'Test-Integer' in 'request->reply_pairs' using pair_delete_reply()");
	TEST_CHECK(pair_delete_reply(attr_test_integer) > 0);

	TEST_CASE("The 'Test-Integer' shouldn't exist in 'request->reply_pairs'");
	TEST_CHECK(fr_pair_find_by_da(&request->reply_pairs, attr_test_integer) == NULL);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_delete_control(void)
{
	request_t      *request = request_fake_alloc();

	TEST_CASE("Copy 'sample_pairs' into 'request->control_pairs'");
	TEST_CHECK(fr_pair_list_copy(autofree, &request->control_pairs, &sample_pairs) > 0);

	TEST_CASE("Delete 'Test-Integer' in 'request->control_pairs' using pair_delete_control()");
	TEST_CHECK(pair_delete_control(attr_test_integer) > 0);

	TEST_CASE("The 'Test-Integer' shouldn't exist in 'request->control_pairs'");
	TEST_CHECK(fr_pair_find_by_da(&request->control_pairs, attr_test_integer) == NULL);

	TEST_CHECK_RET(talloc_free(request), 0);
}

static void test_pair_delete_session_state(void)
{
	request_t      *request = request_fake_alloc();

	TEST_CASE("Copy 'sample_pairs' into 'request->state'");
	TEST_CHECK(fr_pair_list_copy(autofree, &request->session_state_pairs, &sample_pairs) > 0);

	TEST_CASE("Delete 'Test-Integer' in 'request->state' using pair_delete_session_state()");
	TEST_CHECK(pair_delete_session_state(attr_test_integer) > 0);

	TEST_CASE("The 'Test-Integer' shouldn't exist in 'request->state'");
	TEST_CHECK(fr_pair_find_by_da(&request->session_state_pairs, attr_test_integer) == NULL);

	TEST_CHECK_RET(talloc_free(request), 0);
}

TEST_LIST = {
	/*
	 *	Add pairs
	 */
	{ "pair_append_request",          test_pair_append_request },
	{ "pair_append_reply",            test_pair_append_reply },
	{ "pair_append_control",          test_pair_append_control },
	{ "pair_append_session_state",    test_pair_append_session_state },

	/*
	 *	Update pairs
	 */
	{ "pair_update_request",       test_pair_update_request },
	{ "pair_update_reply",         test_pair_update_reply },
	{ "pair_update_control",       test_pair_update_control },
	{ "pair_update_session_state", test_pair_update_session_state },

	/*
	 *	Delete pairs
	 */
	{ "pair_delete_request",       test_pair_delete_request },
	{ "pair_delete_reply",         test_pair_delete_reply },
	{ "pair_delete_control",       test_pair_delete_control },
	{ "pair_delete_session_state", test_pair_delete_session_state },

	{ NULL }
};
