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

/** Performance tests for lists of fr_pair_t
 *
 * @file src/bin/pair_list_perf_test.c
 * @author Nick Porter <nick.porter@networkradius.com>
 *
 * @copyright 2021 Network RADIUS SARL <legal@networkradius.com>
 */

/**
 *	The 'TEST_INIT' macro provided by 'acutest.h' allows registering a function to be called
 *	before call the unit tests. Therefore, It calls the function ALL THE TIME causing an overhead.
 *	That is why we are initializing pair_list_perf_init() by "__attribute__((constructor));" reducing the
 *	test execution by 50% of the time.
 */
#define USE_CONSTRUCTOR

/*
 * It should be declared before including "acutest.h"
 */
#ifdef USE_CONSTRUCTOR
static void fr_pair_list_perf_init(void) __attribute__((constructor));
#else
static void fr_pair_list_perf_init(void);
#define TEST_INIT fr_pair_list_perf_init()
#endif

#include <freeradius-devel/util/acutest.h>

#ifdef WITH_VERIFY_PTR
#undef WITH_VERIFY_PTR
#endif

#include "pair.c"
#include <freeradius-devel/server/base.h>

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)


typedef struct {
        int attr;
        fr_dict_attr_t const **parent;
        fr_dict_attr_t const **da;
        char const *name;
        fr_type_t type;
        void *values;
} fr_dict_adhoc_attr_t;

/*
 *      Global variables
 */

static fr_dict_t        *dict;
static char const       *dict_dir  = "share/dictionary";
static TALLOC_CTX       *autofree;
static int              input_count = 0;
static char const       *test_attrs = "Tmp-String-0 = \"goodbye\",Tmp-String-1 = \"wibble\",Tmp-Integer-0 = 542,Tmp-Integer-1 = 456,Tmp-IP-Address-0 = 192.168.1.1,Tmp-IP-Address-1 = 10.0.0.1,Tmp-Ethernet-0 = 11:22:33:44:55:66,Tmp-Ethernet-1 = ff:ee:dd:cc:bb:aa,Tmp-Date-0 = 959985459,Tmp-Date-1 = \"Jan  1 2020 00:00:00 UTC\",Tmp-Integer64-0 = 156453412,Tmp-Integer64-1 = 46456155,Tmp-Signed-0 = -4573,Tmp-Signed-1 = 45645,Tmp-Float-0 = 45.48,Tmp-Float-0 = 58.64,IP-Pool.Name = \"main\",IP-Pool.Action = Allocate";
static fr_pair_t        **source_vps;

void fr_pair_list_perf_init(void)
{
        fr_pair_list_t  input_vps;
        fr_pair_t       *vp, *next;
        int             i;

        fr_pair_list_init(&input_vps);
        autofree = talloc_autofree_context();

	TEST_ASSERT(fr_dict_global_ctx_init(autofree, dict_dir) != NULL);

	TEST_ASSERT(fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) == 0);

        TEST_ASSERT(fr_pair_list_afrom_str(autofree, dict, test_attrs, strlen(test_attrs), &input_vps) != T_INVALID);

        fr_time_start();

        input_count = fr_pair_list_len(&input_vps);
        fr_pair_list_debug(&input_vps);

        /*
         *  Move vps to array so we can pick them randomly to populate the test list.
         */
        source_vps = talloc_zero_array(autofree, fr_pair_t *, input_count);
        for (vp = fr_pair_list_head(&input_vps), i = 0; vp; vp = next, i++) {
                next = fr_pair_list_next(&input_vps, vp);
                fr_pair_remove(&input_vps, vp);
                source_vps[i] = vp;
        }
}


static void do_test_fr_pair_append(uint len, uint reps)
{
        fr_pair_list_t  test_vps;
        uint             i, j;
        fr_pair_t       *new_vp;
        fr_time_t       start, end, used = 0;

        fr_pair_list_init(&test_vps);

        /*
         *  Insert pairs into the test list, choosing randomly from the source list
         */
        for (i = 0; i < reps; i++) {
                for (j = 0; j < len; j++) {
                        int index = rand() % input_count;
                        new_vp = fr_pair_copy(autofree, source_vps[index]);
                        start = fr_time();
                        fr_pair_append(&test_vps, new_vp);
                        end = fr_time();
                        used += (end - start);
                }
                TEST_CHECK(fr_pair_list_len(&test_vps) == len);
                fr_pair_list_free(&test_vps);
        }
        TEST_MSG_ALWAYS("repetitions=%d", reps);
        TEST_MSG_ALWAYS("list_length=%d", len);
        TEST_MSG_ALWAYS("used=%"PRId64, used);
        TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/((double)used / NSEC));
}

#define test_func(_func, _count) static void test_ ## _func ## _ ## _count(void)\
{\
        do_test_ ## _func(_count, 10000);\
}

#define test_funcs(_func) test_func(_func, 20)\
test_func(_func, 40)\
test_func(_func, 60)\
test_func(_func, 80)\
test_func(_func, 100)

test_funcs(fr_pair_append)

static void do_test_fr_pair_find_by_da(uint len, uint reps)
{
        fr_pair_list_t          test_vps;
        uint                    i, j;
        fr_pair_t               *new_vp;
        fr_time_t               start, end, used = 0;
        const fr_dict_attr_t    *da;

        fr_pair_list_init(&test_vps);

        /*
         *  Initialise the test list
         */
        for (i = 0; i < len; i++) {
                int index = rand() % input_count;
                new_vp = fr_pair_copy(autofree, source_vps[index]);
                fr_pair_append(&test_vps, new_vp);
        }

        /*
         * Find first instance of specific DA
         */
        for (i = 0; i < reps; i++) {
                for (j = 0; j < len; j++) {
                        int index = rand() % input_count;
                        da = source_vps[index]->da;
                        start = fr_time();
                        (void) fr_pair_find_by_da(&test_vps, da);
                        end = fr_time();
                        used += (end - start);
                }

        }
        fr_pair_list_free(&test_vps);
        TEST_MSG_ALWAYS("repetitions=%d", reps);
        TEST_MSG_ALWAYS("list_length=%d", len);
        TEST_MSG_ALWAYS("used=%"PRId64, used);
        TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/((double)used / NSEC));
}

test_funcs(fr_pair_find_by_da)

static void do_test_find_nth(uint len, uint reps)
{
        fr_pair_list_t          test_vps;
        uint                     i, j, k, nth_item;
        fr_pair_t               *new_vp;
        fr_time_t               start, end, used = 0;
        const fr_dict_attr_t    *da;

        fr_pair_list_init(&test_vps);

        /*
         *  Initialise the test list
         */
        for (i = 0; i < len; i++) {
                int index = rand() % input_count;
                new_vp = fr_pair_copy(autofree, source_vps[index]);
                fr_pair_append(&test_vps, new_vp);
        }

        /*
         * Find nth instance of specific DA
         */
        nth_item = (uint)(len / input_count);
        for (i = 0; i < reps; i++) {
                for (j = 0; j < len; j++) {
                        int index = rand() % input_count;
                        da = source_vps[index]->da;
                        start = fr_time();
                        k = 0;
                        for (new_vp = fr_pair_list_head(&test_vps); new_vp; new_vp = fr_pair_list_next(&test_vps, new_vp)) {
                                if (new_vp->da == da) {
                                        k++;
                                        if (k == nth_item) break;
                                }
                        }
                        end = fr_time();
                        used += (end - start);
                }
        }
        fr_pair_list_free(&test_vps);
        TEST_MSG_ALWAYS("repetitions=%d", reps);
        TEST_MSG_ALWAYS("list_length=%d", len);
        TEST_MSG_ALWAYS("used=%"PRId64, used);
        TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/((double)used / NSEC));
}

test_funcs(find_nth)

static void do_test_fr_pair_list_free(uint len, uint reps)
{
        fr_pair_list_t  test_vps;
        uint             i, j;
        fr_pair_t       *new_vp;
        fr_time_t       start, end, used = 0;

        fr_pair_list_init(&test_vps);

        for (i = 0; i < reps; i++) {
                for (j = 0; j < len; j++) {
                        int index = rand() % input_count;
                        new_vp = fr_pair_copy(autofree, source_vps[index]);
                        fr_pair_append(&test_vps, new_vp);
                }
                start = fr_time();
                fr_pair_list_free(&test_vps);
                end = fr_time();
                used += (end - start);
        }
        TEST_MSG_ALWAYS("repetitions=%d", reps);
        TEST_MSG_ALWAYS("list_length=%d", len);
        TEST_MSG_ALWAYS("used=%"PRId64, used);
        TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/((double)used / NSEC));
}

test_funcs(fr_pair_list_free)

#define tests(_func) { #_func "_20", test_ ## _func ## _20},\
        { #_func "_40", test_ ## _func ## _40},\
        { #_func "_60", test_ ## _func ## _60},\
        { #_func "_80", test_ ## _func ## _80},\
        { #_func "_100", test_ ## _func ## _100},\

TEST_LIST = {
        tests(fr_pair_append)
        tests(fr_pair_find_by_da)
        tests(find_nth)
        tests(fr_pair_list_free)

        { NULL }
};