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
static void pair_list_perf_init(void) __attribute__((constructor));
#else
static void pair_list_perf_init(void);
#define TEST_INIT pair_list_perf_init()
#endif

#include <freeradius-devel/util/acutest.h>

#ifdef WITH_VERIFY_PTR
#undef WITH_VERIFY_PTR
#endif

#include "pair.c"
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/server/base.h>

/*
 *      Global variables
 */

static fr_dict_t	*test_dict;
static TALLOC_CTX	*autofree;

static char const	*test_attrs_0 = \
	"Test-String = \"hello\","			/* 1 */
	"Test-Octets = 0x0102030405060708,"		/* 2 */
	"Test-IPv4-Addr = 192.168.1.1,"			/* 3 */
	"Test-IPv4-Prefix = 192.168/16,"		/* 4 */
	"Test-IPv6-Addr = fd12:3456:789a:1::1,"		/* 5 */
	"Test-IPv6-Prefix = fd12:3456:789a:1::/64,"	/* 6 */
	"Test-Ethernet = 11:22:33:44:55:66,"		/* 7 */
	"Test-Uint8 = 255,"				/* 8 */
	"Test-Uint16 = 65535,"				/* 9 */
	"Test-Uint32 = 4294967295,"			/* 10 */
	"Test-Uint64 = 18446744073709551615,"		/* 11 */
	"Test-Int8 = -120,"				/* 12 */
	"Test-Int16 = -4573,"				/* 13 */
	"Test-Int32 = 45645,"				/* 14 */
	"Test-Int64 = 85645,"				/* 15 */
	"Test-Float32 = 1.134,"				/* 16 */
	"Test-Float64 = 1.1345,"			/* 17 */
	"Test-Date += \"Jan  1 2020 00:00:00 UTC\","	/* 18 */
	"Test-TLV.String = \"nested\","			/* 19 */
	"Test-Struct.uint32 = 1234";			/* 20 */

static char const	*test_attrs_25 = \
	"Test-String += \"hello\","			/* 1 */
	"Test-String += \"goodbye\","			/* 2 */
	"Test-String += \"hola\","			/* 3 */
	"Test-String += \"hasta pronto\","		/* 4 */
	"Test-String += \"bonjour\","			/* 5 */
	"Test-Octets += 0x0102030405060708,"		/* 6 */
	"Test-IPv4-Addr = 192.168.1.1,"			/* 7 */
	"Test-IPv4-Prefix = 192.168/16,"		/* 8 */
	"Test-IPv6-Addr = fd12:3456:789a:1::1,"		/* 9 */
	"Test-IPv6-Prefix = fd12:3456:789a:1::/64,"	/* 10 */
	"Test-Ethernet = 11:22:33:44:55:66,"		/* 11 */
	"Test-Uint8 = 255,"				/* 12 */
	"Test-Uint16 = 65535,"				/* 13 */
	"Test-Uint32 = 4294967295,"			/* 14 */
	"Test-Uint64 = 18446744073709551615,"		/* 15 */
	"Test-Int64 = 85645,"				/* 16 */
	"Test-Float32 = 1.134,"				/* 17 */
	"Test-Date += \"Jan  1 2020 00:00:00 UTC\","	/* 18 */
	"Test-TLV.String = \"nested\","			/* 19 */
	"Test-Struct.uint32 = 1234";			/* 20 */

static char const	*test_attrs_50 = \
	"Test-String += \"hello\","			/* 1 */
	"Test-String += \"goodbye\","			/* 2 */
	"Test-String += \"hola\","			/* 3 */
	"Test-String += \"hasta pronto\","		/* 4 */
	"Test-String += \"bonjour\","			/* 5 */
	"Test-String += \"au revoir\","			/* 6 */
	"Test-String += \"halo\","			/* 7 */
	"Test-String += \"kwaheri\","			/* 8 */
	"Test-String += \"ciao\","			/* 9 */
	"Test-String += \"arrivederci\","		/* 10 */
	"Test-IPv4-Addr = 192.168.1.1,"			/* 11 */
	"Test-IPv4-Prefix = 192.168/16,"		/* 12 */
	"Test-IPv6-Addr = fd12:3456:789a:1::1,"		/* 13 */
	"Test-IPv6-Prefix = fd12:3456:789a:1::/64,"	/* 14 */
	"Test-Ethernet = 11:22:33:44:55:66,"		/* 15 */
	"Test-Uint8 = 255,"				/* 16 */
	"Test-Int64 = 85645,"				/* 17 */
	"Test-Date += \"Jan  1 2020 00:00:00 UTC\","	/* 18 */
	"Test-TLV.String = \"nested\","			/* 19 */
	"Test-Struct.uint32 = 1234";			/* 20 */

static char const	*test_attrs_75 = \
	"Test-String += \"hello\","			/* 1 */
	"Test-String += \"goodbye\","			/* 2 */
	"Test-String += \"hola\","			/* 3 */
	"Test-String += \"hasta pronto\","		/* 4 */
	"Test-String += \"bonjour\","			/* 5 */
	"Test-String += \"au revoir\","			/* 6 */
	"Test-String += \"halo\","			/* 7 */
	"Test-String += \"kwaheri\","			/* 8 */
	"Test-String += \"ciao\","			/* 9 */
	"Test-String += \"arrivederci\","		/* 10 */
	"Test-String += \"halo\","			/* 11 */
	"Test-String += \"selamat tinggal\","		/* 12 */
	"Test-String += \"你好\","			/* 13 */
	"Test-String += \"再见\","			/* 14 */
	"Test-String += \"Привет\","			/* 15 */
	"Test-Uint8 = 255,"				/* 16 */
	"Test-Int64 = 85645,"				/* 17 */
	"Test-Date += \"Jan  1 2020 00:00:00 UTC\","	/* 18 */
	"Test-TLV.String = \"nested\","			/* 19 */
	"Test-Struct.uint32 = 1234";			/* 20 */

static char const	*test_attrs_100 = \
	"Test-String += \"hello\","			/* 1 */
	"Test-String += \"goodbye\","			/* 2 */
	"Test-String += \"hola\","			/* 3 */
	"Test-String += \"hasta pronto\","		/* 4 */
	"Test-String += \"bonjour\","			/* 5 */
	"Test-String += \"au revoir\","			/* 6 */
	"Test-String += \"halo\","			/* 7 */
	"Test-String += \"kwaheri\","			/* 8 */
	"Test-String += \"ciao\","			/* 9 */
	"Test-String += \"arrivederci\","		/* 10 */
	"Test-String += \"halo\","			/* 11 */
	"Test-String += \"selamat tinggal\","		/* 12 */
	"Test-String += \"你好\","			/* 13 */
	"Test-String += \"再见\","			/* 14 */
	"Test-String += \"Привет\","			/* 15 */
	"Test-String += \"до свидания\","		/* 16 */
	"Test-String += \"вся слава советской россии\","/* 17 */
	"Test-String += \"у нас есть видео с мочой\","	/* 18 */
	"Test-String += \"Байден заплатит за\","	/* 19 */
	"Test-String += \"приставание к бурундукам\"";	/* 20 */

static fr_pair_t	**source_vps_0;		//!< List with zero duplicate attributes.
static fr_pair_t	**source_vps_25;	//!< List with 25% duplicate attributes.
static fr_pair_t	**source_vps_50;	//!< List with 50% duplicate attributes.
static fr_pair_t	**source_vps_75;	//!< List with 75% duplicate attributes.
static fr_pair_t	**source_vps_100;	//!< List with 100% duplicate attributes, i.e. all the same.

static void pair_list_init(TALLOC_CTX *ctx, fr_pair_t ***out, fr_dict_t const *dict, char const *pairs)
{
	fr_pair_list_t  list;
	fr_pair_t	*vp, *next;
	int		i;
	fr_token_t	ret;
	fr_pair_t	**vp_array;
	size_t		input_count;

	fr_pair_list_init(&list);
	ret = fr_pair_list_afrom_str(ctx, dict, pairs, strlen(pairs), &list);
	if (ret == T_INVALID) fr_perror("pair_list_perf_tests");
	TEST_ASSERT(ret != T_INVALID);

	input_count = fr_pair_list_len(&list);
	fr_pair_list_debug(&list);

	/*
	 *  Move vps to array so we can pick them randomly to populate the test list.
	 */
	vp_array = talloc_array(ctx, fr_pair_t *, input_count);
	for (vp = fr_pair_list_head(&list), i = 0; vp; vp = next, i++) {
		next = fr_pair_list_next(&list, vp);
		fr_pair_remove(&list, vp);
		vp_array[i] = vp;
	}

	*out = vp_array;
}

void pair_list_perf_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("pair_list_perf_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;

	pair_list_init(autofree, &source_vps_0, test_dict, test_attrs_0);
	pair_list_init(autofree, &source_vps_25, test_dict, test_attrs_25);
	pair_list_init(autofree, &source_vps_50, test_dict, test_attrs_50);
	pair_list_init(autofree, &source_vps_75, test_dict, test_attrs_75);
	pair_list_init(autofree, &source_vps_100, test_dict, test_attrs_100);
	fr_time_start();
}

static void do_test_fr_pair_append(unsigned int len, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t  test_vps;
	unsigned int	i, j;
	fr_pair_t	*new_vp;
	fr_time_t	start, end, used = 0;
	size_t		input_count = talloc_array_length(source_vps);

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

static void do_test_fr_pair_find_by_da(unsigned int len, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t		test_vps;
	unsigned int		i, j;
	fr_pair_t		*new_vp;
	fr_time_t		start, end, used = 0;
	fr_dict_attr_t const	*da;
	size_t			input_count = talloc_array_length(source_vps);

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
			(void) fr_pair_find_by_da(&test_vps, da, 0);
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

static void do_test_find_nth(unsigned int len, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t	  	test_vps;
	unsigned int		i, j, nth_item;
	fr_pair_t		*new_vp;
	fr_time_t		start, end, used = 0;
	fr_dict_attr_t const	*da;
	size_t			input_count = talloc_array_length(source_vps);

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
	nth_item = (unsigned int)(len / input_count);
	for (i = 0; i < reps; i++) {
		for (j = 0; j < len; j++) {
			int index = rand() % input_count;

			da = source_vps[index]->da;
			start = fr_time();
			(void) fr_pair_find_by_da(&test_vps, da, nth_item);
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

static void do_test_fr_pair_list_free(unsigned int len, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t  test_vps;
	unsigned int	i, j;
	fr_pair_t	*new_vp;
	fr_time_t	start, end, used = 0;
	size_t		input_count = talloc_array_length(source_vps);

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
	fr_pair_list_free(&test_vps);
	TEST_MSG_ALWAYS("repetitions=%d", reps);
	TEST_MSG_ALWAYS("list_length=%d", len);
	TEST_MSG_ALWAYS("used=%"PRId64, used);
	TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/((double)used / NSEC));
}

#define test_func(_func, _count, _source_vps) \
static void test_ ## _func ## _ ## _count(void)\
{\
	do_test_ ## _func(_count, 10000, _source_vps);\
}

#define test_funcs(_func) \
	test_func(_func, 20, source_vps_0) \
	test_func(_func, 40, source_vps_0) \
	test_func(_func, 60, source_vps_0) \
	test_func(_func, 80, source_vps_0) \
	test_func(_func, 100, source_vps_0)

test_funcs(fr_pair_append)
test_funcs(fr_pair_find_by_da)
test_funcs(find_nth)
test_funcs(fr_pair_list_free)

#define repetition_tests(_func) \
	{ #_func "_20", test_ ## _func ## _20},\
	{ #_func "_40", test_ ## _func ## _40},\
	{ #_func "_60", test_ ## _func ## _60},\
	{ #_func "_80", test_ ## _func ## _80},\
	{ #_func "_100", test_ ## _func ## _100},\

TEST_LIST = {
	repetition_tests(fr_pair_append)
	repetition_tests(fr_pair_find_by_da)
	repetition_tests(find_nth)
	repetition_tests(fr_pair_list_free)

	{ NULL }
};
