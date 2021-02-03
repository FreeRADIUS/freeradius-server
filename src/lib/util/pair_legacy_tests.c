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
 * @file src/lib/util/pair_legacy_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
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

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/radius/radius.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#	include <gperftools/profiler.h>
#endif

static char const       *dict_dir  = "share/dictionary";

/* Set by pair_tests_init()*/
static TALLOC_CTX       *autofree;
static fr_pair_list_t   sample_pairs;
static char const       *sample_string = "We love Tapioca!";

/*
 *	Needed by fr_dict_*() API
 */
#include "dict_priv.h"

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
static fr_dict_t *dict_internal;

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
	{ .attr = -1, .parent = NULL, .da = NULL, .name = NULL, .type = FR_TYPE_INVALID }
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
	     p++) if (fr_pair_add_by_da(autofree, NULL, out, *p->da) < 0) return -1;

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
	printf("Setup %s\n", __func__);

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

	if (fr_dict_internal_afrom_file(&dict_internal, FR_DICTIONARY_INTERNAL_DIR) < 0) goto error;

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

/*
 *	Tests functions
 */
static void test_fr_pair_make(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	TALLOC_CTX     *ctx = talloc_null_ctx();

	fr_pair_list_init(&list);

	TEST_CASE("Creating 'vp' using fr_pair_make()");
	TEST_CHECK((vp = fr_pair_make(ctx, dict_test, &list, "Test-String", sample_string, T_DOUBLE_QUOTED_STRING)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == sample_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, sample_string) == 0);

	fr_pair_list_free(&list);
}

static void test_fr_pair_mark_xlat(void)
{
	fr_pair_t  *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&sample_pairs, attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Marking 'vp' using fr_pair_mark_xlat()");
	TEST_CHECK(fr_pair_mark_xlat(vp, "Hello %{Test-Integer}") == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->xlat == 'Hello %{Test-Integer}')");
	TEST_CHECK(vp && strcmp(vp->xlat, "Hello %{Test-Integer}") == 0);
	TEST_CHECK(vp && vp->type == VT_XLAT);

	talloc_free(vp);
}

static void test_fr_pair_list_afrom_str(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	char const     *buffer = "Test-Integer = 123, Test-String = \"Tapioca\"";

	fr_pair_list_init(&list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_str()");
	TEST_CHECK(fr_pair_list_afrom_str(autofree, dict_test, buffer, &list) == T_EOL);

	TEST_CASE("Looking for Test-Integer");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Checking if (Test-Integer == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Checking if (Test-String == 'Tapioca')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Tapioca") == 0);

	fr_pair_list_free(&list);
}

FILE *open_buffer_as_file(char const *buffer, size_t buffer_len);
FILE *open_buffer_as_file(char const *buffer, size_t buffer_len)
{
	FILE *fp;
	char *our_buffer;

	memcpy(&our_buffer, &buffer, sizeof(buffer));

	TEST_CHECK((fp = fmemopen(our_buffer, buffer_len, "r")) != NULL);

	fflush (fp);

	return fp;
}

static void test_fr_pair_list_afrom_file(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	char const     *buffer = "Test-Integer = 123\nTest-String = \"Tapioca\"\n";
	FILE           *fp = open_buffer_as_file(buffer, strlen(buffer));
	bool           pfiledone;

	fr_pair_list_init(&list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, dict_test, &list, fp, &pfiledone) == 0);

	TEST_CASE("Looking for Test-Integer");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Checking if (Test-Integer == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Checking if (Test-String == 'Tapioca')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Tapioca") == 0);

	fr_pair_list_free(&list);

	fclose(fp);
}

static void test_fr_pair_list_move(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t old_list, new_list;
	bool           pfiledone;
	char const     *fake_file = "Test-Integer = 123\nTest-String = \"Tapioca\"\n";
	FILE           *fp = open_buffer_as_file(fake_file, strlen(fake_file));

	fr_pair_list_init(&old_list);
	fr_pair_list_init(&new_list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, dict_test, &old_list, fp, &pfiledone) == 0);
	TEST_CHECK(pfiledone == true);

	TEST_CASE("Move pair from 'old_list' to 'old_list' using fr_pair_list_move()");
	fr_pair_list_move(&new_list, &old_list);

	TEST_CASE("Looking for Test-Integer");
	TEST_CHECK((vp = fr_pair_find_by_da(&new_list, attr_test_integer)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp != NULL);

	TEST_CASE("Checking if (Test-Integer == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String");
	TEST_CHECK((vp = fr_pair_find_by_da(&new_list, attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp != NULL);

	TEST_CASE("Checking if (Test-String == 'Tapioca')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Tapioca") == 0);

	fr_pair_list_free(&old_list);
	fr_pair_list_free(&new_list);

	fclose(fp);
}

TEST_LIST = {
	/*
	 *	Legacy calls
	 */
	{ "fr_pair_make",            test_fr_pair_make },
	{ "fr_pair_mark_xlat",       test_fr_pair_mark_xlat },
	{ "fr_pair_list_afrom_str",  test_fr_pair_list_afrom_str },
	{ "fr_pair_list_afrom_file", test_fr_pair_list_afrom_file },
	{ "fr_pair_list_move",       test_fr_pair_list_move },

	{ NULL }
};
