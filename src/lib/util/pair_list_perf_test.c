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
 * @file src/lib/util/pair_list_perf_test.c
 * @author Nick Porter <nick.porter@networkradius.com>
 *
 * @copyright 2021 Network RADIUS SAS <legal@networkradius.com>
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

#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/server/base.h>
/*
 *      Global variables
 */

static fr_dict_t	*test_dict;
static TALLOC_CTX	*autofree;

static char const	*test_attrs_0 = \
	"Test-String-# = \"hello\","				/* 1 */
	"Test-Octets-# = 0x0102030405060708,"			/* 2 */
	"Test-IPv4-Addr-# = 192.168.1.1,"			/* 3 */
	"Test-IPv4-Prefix-# = 192.168/16,"			/* 4 */
	"Test-IPv6-Addr-# = fd12:3456:789a:1::1,"		/* 5 */
	"Test-IPv6-Prefix-# = fd12:3456:789a:1::/64,"		/* 6 */
	"Test-Ethernet-# = 11:22:33:44:55:66,"			/* 7 */
	"Test-Uint8-# = 255,"					/* 8 */
	"Test-Uint16-# = 65535,"				/* 9 */
	"Test-Uint32-# = 4294967295,"				/* 10 */
	"Test-Uint64-# = 18446744073709551615,"			/* 11 */
	"Test-Int8-# = -120,"					/* 12 */
	"Test-Int16-# = -4573,"					/* 13 */
	"Test-Int32-# = 45645,"					/* 14 */
	"Test-Int64-# = 85645,"					/* 15 */
	"Test-Float32-# = 1.134,"				/* 16 */
	"Test-Float64-# = 1.1345,"				/* 17 */
	"Test-Date-# += \"Jan  1 2020 00:00:00 UTC\","		/* 18 */
	"Test-TLV-#.String = \"nested\","			/* 19 */
	"Test-Struct-#.uint32 = 1234";				/* 20 */

static char const	*test_attrs_25 = \
	"Test-String-# += \"hello\","				/* 1 */
	"Test-String-# += \"goodbye\","				/* 2 */
	"Test-String-# += \"hola\","				/* 3 */
	"Test-String-# += \"hasta pronto\","			/* 4 */
	"Test-String-# += \"bonjour\","				/* 5 */
	"Test-Octets-# += 0x0102030405060708,"			/* 6 */
	"Test-IPv4-Addr-# = 192.168.1.1,"			/* 7 */
	"Test-IPv4-Prefix-# = 192.168/16,"			/* 8 */
	"Test-IPv6-Addr-# = fd12:3456:789a:1::1,"		/* 9 */
	"Test-IPv6-Prefix-# = fd12:3456:789a:1::/64,"		/* 10 */
	"Test-Ethernet-# = 11:22:33:44:55:66,"			/* 11 */
	"Test-Uint8-# = 255,"					/* 12 */
	"Test-Uint16-# = 65535,"				/* 13 */
	"Test-Uint32-# = 4294967295,"				/* 14 */
	"Test-Uint64-# = 18446744073709551615,"			/* 15 */
	"Test-Int64-# = 85645,"					/* 16 */
	"Test-Float32-# = 1.134,"				/* 17 */
	"Test-Date-# += \"Jan  1 2020 00:00:00 UTC\","		/* 18 */
	"Test-TLV-#.String = \"nested\","			/* 19 */
	"Test-Struct-#.uint32 = 1234";				/* 20 */

static char const	*test_attrs_50 = \
	"Test-String-# += \"hello\","				/* 1 */
	"Test-String-# += \"goodbye\","				/* 2 */
	"Test-String-# += \"hola\","				/* 3 */
	"Test-String-# += \"hasta pronto\","			/* 4 */
	"Test-String-# += \"bonjour\","				/* 5 */
	"Test-String-# += \"au revoir\","			/* 6 */
	"Test-String-# += \"halo\","				/* 7 */
	"Test-String-# += \"kwaheri\","				/* 8 */
	"Test-String-# += \"ciao\","				/* 9 */
	"Test-String-# += \"arrivederci\","			/* 10 */
	"Test-IPv4-Addr-# = 192.168.1.1,"			/* 11 */
	"Test-IPv4-Prefix-# = 192.168/16,"			/* 12 */
	"Test-IPv6-Addr-# = fd12:3456:789a:1::1,"		/* 13 */
	"Test-IPv6-Prefix-# = fd12:3456:789a:1::/64,"		/* 14 */
	"Test-Ethernet-# = 11:22:33:44:55:66,"			/* 15 */
	"Test-Uint8-# = 255,"					/* 16 */
	"Test-Int64-# = 85645,"					/* 17 */
	"Test-Date-# += \"Jan  1 2020 00:00:00 UTC\","		/* 18 */
	"Test-TLV-#.String = \"nested\","			/* 19 */
	"Test-Struct-#.uint32 = 1234";				/* 20 */

static char const	*test_attrs_75 = \
	"Test-String-# += \"hello\","				/* 1 */
	"Test-String-# += \"goodbye\","				/* 2 */
	"Test-String-# += \"hola\","				/* 3 */
	"Test-String-# += \"hasta pronto\","			/* 4 */
	"Test-String-# += \"bonjour\","				/* 5 */
	"Test-String-# += \"au revoir\","			/* 6 */
	"Test-String-# += \"halo\","				/* 7 */
	"Test-String-# += \"kwaheri\","				/* 8 */
	"Test-String-# += \"ciao\","				/* 9 */
	"Test-String-# += \"arrivederci\","			/* 10 */
	"Test-String-# += \"halo\","				/* 11 */
	"Test-String-# += \"selamat tinggal\","			/* 12 */
	"Test-String-# += \"你好\","				/* 13 */
	"Test-String-# += \"再见\","				/* 14 */
	"Test-String-# += \"Привет\","				/* 15 */
	"Test-Uint8-# = 255,"					/* 16 */
	"Test-Int64-# = 85645,"					/* 17 */
	"Test-Date-# += \"Jan  1 2020 00:00:00 UTC\","		/* 18 */
	"Test-TLV-#.String = \"nested\","			/* 19 */
	"Test-Struct-#.uint32 = 1234";				/* 20 */

static char const	*test_attrs_100 = \
	"Test-String-# += \"hello\","				/* 1 */
	"Test-String-# += \"goodbye\","				/* 2 */
	"Test-String-# += \"hola\","				/* 3 */
	"Test-String-# += \"hasta pronto\","			/* 4 */
	"Test-String-# += \"bonjour\","				/* 5 */
	"Test-String-# += \"au revoir\","			/* 6 */
	"Test-String-# += \"halo\","				/* 7 */
	"Test-String-# += \"kwaheri\","				/* 8 */
	"Test-String-# += \"ciao\","				/* 9 */
	"Test-String-# += \"arrivederci\","			/* 10 */
	"Test-String-# += \"halo\","				/* 11 */
	"Test-String-# += \"selamat tinggal\","			/* 12 */
	"Test-String-# += \"你好\","				/* 13 */
	"Test-String-# += \"再见\","				/* 14 */
	"Test-String-# += \"Привет\","				/* 15 */
	"Test-String-# += \"до свидания\","			/* 16 */
	"Test-String-# += \"вся слава советской россии\","	/* 17 */
	"Test-String-# += \"у нас есть видео с мочой\","	/* 18 */
	"Test-String-# += \"Байден заплатит за\","		/* 19 */
	"Test-String-# += \"приставание к бурундукам\"";	/* 20 */

static fr_pair_t	**source_vps_0;		//!< List with zero duplicate attributes.
static fr_pair_t	**source_vps_25;	//!< List with 25% duplicate attributes.
static fr_pair_t	**source_vps_50;	//!< List with 50% duplicate attributes.
static fr_pair_t	**source_vps_75;	//!< List with 75% duplicate attributes.
static fr_pair_t	**source_vps_100;	//!< List with 100% duplicate attributes, i.e. all the same.

static void pair_list_init(TALLOC_CTX *ctx, fr_pair_t ***out, fr_dict_t const *dict, char const *pairs,
			   int const perc, int const reps)
{
	fr_pair_list_t  list, full_list, dups;
	char		*prep_pairs, *p;
	fr_pair_t	*vp, *next;
	int		i;
	size_t		j;
	ssize_t		slen;
	fr_pair_t	**vp_array;
	size_t		input_count;

	fr_pair_list_init(&list);
	fr_pair_list_init(&full_list);
	fr_pair_list_init(&dups);

	prep_pairs = talloc_array(NULL, char, strlen(pairs) + 1);

	/*
	 *  Build a list of pairs, repeating the source list 'reps' times
	 *  replacing the '#' in the source string with the number of this
	 *  repetition.
	 */
	for (i = 0; i < reps; i++) {
		fr_pair_parse_t root, relative;

		root = (fr_pair_parse_t) {
			.ctx = ctx,
			.da = fr_dict_root(dict),
			.list = &list,
			.dict = dict,
			.internal = fr_dict_internal(),
		};
		relative = (fr_pair_parse_t) { };

		strcpy(prep_pairs, pairs);
		p = prep_pairs;
		while ((p = strchr(p, '#'))) {
			*p = (char)(i + 48);
		}
		slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN_STR(prep_pairs));
		if (slen <= 0) fr_perror("pair_list_perf_tests");
		TEST_ASSERT(slen > 0);

		input_count = fr_pair_list_num_elements(&list);

		if ((i == 0) && (perc > 0) && (reps > 0)) {
			fr_pair_t	*new_vp;
			/*
			 *  Copy the required number of attributes from the first iteration
			 *  to use for duplicating attributes to required percentage.
			 *  Duplicates are at the beginning of the source list
			 */
			/* coverity[dereference] */
			vp = fr_pair_list_head(&list);
			for (j = 0; j < (size_t)(input_count * perc / 100); j++) {
				/* coverity[dereference] */
				new_vp = fr_pair_copy(ctx, vp);
				fr_pair_append(&dups, new_vp);
				/* coverity[dereference] */
				vp = fr_pair_list_next(&list, vp);
			}
		}

		if (i == 0) {
			/*
			 *  On the first iteration, just move the test pairs to the final list
			 */
			fr_pair_list_append(&full_list, &list);
		} else {
			/*
			 *  With subsequent iterations, replicate the duplicates from the first
			 *  iteration to maintain the percentage of attribute repeats
			 */
			vp = fr_pair_list_head(&dups);
			fr_pair_sublist_copy(ctx, &full_list, &dups, vp, 0);

			/*
			 *  Walk past equivalent pairs in new source list
			 */
			vp = fr_pair_list_head(&list);
			for (j = 0; j < fr_pair_list_num_elements(&dups); j++) vp = fr_pair_list_next(&list, vp);

			/*
			 *  Append copy remaining pairs from source list to destination
			 */
			fr_pair_sublist_copy(ctx, &full_list, &list, vp, 0);

			/*
			 *  We copied pairs rather than moving, free the source
			 */
			fr_pair_list_free(&list);
		}
	}

	talloc_free(prep_pairs);

	/*
	 *  Move vps to array so we can pick them randomly to populate the test list.
	 */
	vp_array = talloc_array(ctx, fr_pair_t *, fr_pair_list_num_elements(&full_list));
	for (vp = fr_pair_list_head(&full_list), i = 0; vp; vp = next, i++) {
		next = fr_pair_list_next(&full_list, vp);
		fr_pair_remove(&full_list, vp);
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

	if (fr_dict_test_attrs_init(test_dict, fr_dict_test_attrs, 100, 1) < 0) goto error;
	if (fr_dict_test_attrs_init(test_dict, fr_dict_test_attrs, 200, 2) < 0) goto error;
	if (fr_dict_test_attrs_init(test_dict, fr_dict_test_attrs, 300, 3) < 0) goto error;
	if (fr_dict_test_attrs_init(test_dict, fr_dict_test_attrs, 400, 4) < 0) goto error;

	pair_list_init(autofree, &source_vps_0, test_dict, test_attrs_0, 0, 5);
	pair_list_init(autofree, &source_vps_25, test_dict, test_attrs_25, 25, 5);
	pair_list_init(autofree, &source_vps_50, test_dict, test_attrs_50, 50, 5);
	pair_list_init(autofree, &source_vps_75, test_dict, test_attrs_75, 75, 5);
	pair_list_init(autofree, &source_vps_100, test_dict, test_attrs_100, 100, 5);

	fr_time_start();
}

static void do_test_fr_pair_append(unsigned int len, unsigned int perc, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t  test_vps;
	unsigned int	i, j;
	fr_pair_t	*new_vp;
	fr_time_t	start, end;
	fr_time_delta_t	used = fr_time_delta_wrap(0);
	size_t		input_count = talloc_array_length(source_vps);
	fr_fast_rand_t	rand_ctx;

	fr_pair_list_init(&test_vps);
	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	/*
	 *  Only use up to the number of pairs needed from the source to maintain ratio
	 *  of attribute repeats.
	 */
	if (input_count > len) input_count = len;

	/*
	 *  Insert pairs into the test list, choosing randomly from the source list
	 */
	for (i = 0; i < reps; i++) {
		for (j = 0; j < len; j++) {
			int idx = fr_fast_rand(&rand_ctx) % input_count;
			new_vp = fr_pair_copy(autofree, source_vps[idx]);
			start = fr_time();
			fr_pair_append(&test_vps, new_vp);
			end = fr_time();
			used = fr_time_delta_add(used, fr_time_sub(end, start));
		}
		TEST_CHECK(fr_pair_list_num_elements(&test_vps) == len);
		fr_pair_list_free(&test_vps);
	}
	TEST_MSG_ALWAYS("repetitions=%u", reps);
	TEST_MSG_ALWAYS("perc_rep=%u", perc);
	TEST_MSG_ALWAYS("list_length=%u", len);
	TEST_MSG_ALWAYS("used=%"PRId64, fr_time_delta_unwrap(used));
	TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/(fr_time_delta_unwrap(used) / (double)NSEC));
}

static void do_test_fr_pair_find_by_da_idx(unsigned int len, unsigned int perc, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t		test_vps;
	unsigned int		i, j;
	fr_pair_t		*new_vp;
	fr_time_t		start, end;
	fr_time_delta_t		used = fr_time_delta_wrap(0);
	fr_dict_attr_t const	*da;
	size_t			input_count = talloc_array_length(source_vps);
	fr_fast_rand_t		rand_ctx;

	fr_pair_list_init(&test_vps);
	if (input_count > len) input_count = len;
	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	/*
	 *  Initialise the test list
	 */
	for (i = 0; i < len; i++) {
		int idx = fr_fast_rand(&rand_ctx) % input_count;
		new_vp = fr_pair_copy(autofree, source_vps[idx]);
		fr_pair_append(&test_vps, new_vp);
	}

	/*
	 * Find first instance of specific DA
	 */
	for (i = 0; i < reps; i++) {
		for (j = 0; j < len; j++) {
			int idx = fr_fast_rand(&rand_ctx) % input_count;
			da = source_vps[idx]->da;
			start = fr_time();
			(void) fr_pair_find_by_da(&test_vps, NULL, da);
			end = fr_time();
			used = fr_time_delta_add(used, fr_time_sub(end, start));
		}
	}
	fr_pair_list_free(&test_vps);
	TEST_MSG_ALWAYS("repetitions=%u", reps);
	TEST_MSG_ALWAYS("perc_rep=%u", perc);
	TEST_MSG_ALWAYS("list_length=%u", len);
	TEST_MSG_ALWAYS("used=%"PRId64, fr_time_delta_unwrap(used));
	TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/(fr_time_delta_unwrap(used) / (double)NSEC));
}

static void do_test_find_nth(unsigned int len, unsigned int perc, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t	  	test_vps;
	unsigned int		i, j, nth_item;
	fr_pair_t		*new_vp;
	fr_time_t		start, end;
	fr_time_delta_t		used = fr_time_delta_wrap(0);
	fr_dict_attr_t const	*da;
	size_t			input_count = talloc_array_length(source_vps);
	fr_fast_rand_t		rand_ctx;

	fr_pair_list_init(&test_vps);
	if (input_count > len) input_count = len;
	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	/*
	 *  Initialise the test list
	 */
	for (i = 0; i < len; i++) {
		int idx = fr_fast_rand(&rand_ctx) % input_count;
		new_vp = fr_pair_copy(autofree, source_vps[idx]);
		fr_pair_append(&test_vps, new_vp);
	}

	/*
	 *  Find nth instance of specific DA.  nth is based on the percentage
	 *  of attributes which are repeats.
	 */
	nth_item = perc == 0 ? 1 : (unsigned int)(len * perc / 100);
	for (i = 0; i < reps; i++) {
		for (j = 0; j < len; j++) {
			int idx = fr_fast_rand(&rand_ctx) % input_count;

			da = source_vps[idx]->da;
			start = fr_time();
			(void) fr_pair_find_by_da_idx(&test_vps, da, nth_item);
			end = fr_time();
			used = fr_time_delta_add(used, fr_time_sub(end, start));
		}
	}
	fr_pair_list_free(&test_vps);
	TEST_MSG_ALWAYS("repetitions=%u", reps);
	TEST_MSG_ALWAYS("perc_rep=%u", perc);
	TEST_MSG_ALWAYS("list_length=%u", len);
	TEST_MSG_ALWAYS("used=%"PRId64, fr_time_delta_unwrap(used));
	TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/(fr_time_delta_unwrap(used) / (double)NSEC));
}

static void do_test_fr_pair_list_free(unsigned int len, unsigned int perc, unsigned int reps, fr_pair_t *source_vps[])
{
	fr_pair_list_t  test_vps;
	unsigned int	i, j;
	fr_pair_t	*new_vp;
	fr_time_t	start, end;
	fr_time_delta_t	used = fr_time_delta_wrap(0);
	size_t		input_count = talloc_array_length(source_vps);
	fr_fast_rand_t	rand_ctx;

	fr_pair_list_init(&test_vps);
	if (input_count > len) input_count = len;
	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	for (i = 0; i < reps; i++) {
		for (j = 0; j < len; j++) {
			int idx = fr_fast_rand(&rand_ctx) % input_count;
			new_vp = fr_pair_copy(autofree, source_vps[idx]);
			fr_pair_append(&test_vps, new_vp);
		}
		start = fr_time();
		fr_pair_list_free(&test_vps);
		end = fr_time();
		used = fr_time_delta_add(used, fr_time_sub(end, start));
	}
	fr_pair_list_free(&test_vps);
	TEST_MSG_ALWAYS("repetitions=%u", reps);
	TEST_MSG_ALWAYS("perc_rep=%u", perc);
	TEST_MSG_ALWAYS("list_length=%u", len);
	TEST_MSG_ALWAYS("used=%"PRId64, fr_time_delta_unwrap(used));
	TEST_MSG_ALWAYS("per_sec=%0.0lf", (reps * len)/(fr_time_delta_unwrap(used) / (double)NSEC));
}

#define test_func(_func, _count, _perc, _source_vps) \
static void test_ ## _func ## _ ## _count ## _ ## _perc(void)\
{\
	do_test_ ## _func(_count, _perc, 10000, _source_vps);\
}

#define test_funcs(_func, _perc) \
	test_func(_func, 20, _perc, source_vps_ ## _perc) \
	test_func(_func, 40, _perc, source_vps_ ## _perc) \
	test_func(_func, 60, _perc, source_vps_ ## _perc) \
	test_func(_func, 80, _perc, source_vps_ ## _perc) \
	test_func(_func, 100, _perc, source_vps_ ## _perc)

#define all_test_funcs(_func) \
	test_funcs(_func, 0) \
	test_funcs(_func, 25) \
	test_funcs(_func, 50) \
	test_funcs(_func, 75) \
	test_funcs(_func, 100)

all_test_funcs(fr_pair_append)
all_test_funcs(fr_pair_find_by_da_idx)
all_test_funcs(find_nth)
all_test_funcs(fr_pair_list_free)

#define repetition_tests(_func, _perc) \
	{ #_func "_20_" #_perc, test_ ## _func ## _20_ ## _perc},\
	{ #_func "_40_" #_perc, test_ ## _func ## _40_ ## _perc},\
	{ #_func "_60_" #_perc, test_ ## _func ## _60_ ## _perc},\
	{ #_func "_80_" #_perc, test_ ## _func ## _80_ ## _perc},\
	{ #_func "_100_" #_perc, test_ ## _func ## _100_ ## _perc},\

#define all_repetition_tests(_func) \
	repetition_tests(_func, 0) \
	repetition_tests(_func, 25) \
	repetition_tests(_func, 50) \
	repetition_tests(_func, 75) \
	repetition_tests(_func, 100)

TEST_LIST = {
	all_repetition_tests(fr_pair_append)
	all_repetition_tests(fr_pair_find_by_da_idx)
	all_repetition_tests(find_nth)
	all_repetition_tests(fr_pair_list_free)

	TEST_TERMINATOR
};
