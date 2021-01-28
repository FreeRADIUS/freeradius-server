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

/**
 * $Id$
 *
 * @file src/bin/pair_list_perf_test.c
 * @brief Test performance of lists of fr_pair_t
 *
 * @copyright 2021 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

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
#define FR_TEST_TLV_ROOT        4
#define FR_TEST_TLV_STRING      1

/*
 *      Global variables
 */

static fr_dict_t        *dict;
static char const       *dict_dir  = "share/dictionary";
static TALLOC_CTX       *autofree;

static void usage(int status);

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
        int                     ret = EXIT_SUCCESS;
        int                     c, i, j, k, nth_item = 1;
        int                     input_count = 0, insert_count = 1, find_count = 0, nth_count = 0, repeat_count = 1;
        const char              *input_file = NULL;
        FILE                    *fp;
        fr_pair_list_t          input_vps;
        fr_pair_list_t          test_vps;
        fr_pair_t               **source_vps;
        fr_pair_t               *vp, *next;
        static bool             filedone;
        clock_t                 begin_time, end_time;
        clock_t                 insert_time = 0, find_time = 0, nth_time = 0, free_time = 0;
        fr_pair_t               *new_vp;
        const fr_dict_attr_t    *da;

        fr_pair_list_init(&input_vps);
        fr_pair_list_init(&test_vps);
        autofree = talloc_autofree_context();

        fr_talloc_fault_setup();

        /*
         *      If the server was built with debugging enabled always install
         *      the basic fatal signal handlers.
         */
#ifndef NDEBUG
        if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
                fr_exit_now(EXIT_FAILURE);
        }
#else
        fr_disable_null_tracking_on_free(autofree);
#endif

        fr_debug_lvl = 0;

        default_log.dst = L_DST_STDOUT;
        default_log.fd = STDOUT_FILENO;
        default_log.print_level = true;

        /*  Process the options.  */
        while ((c = getopt(argc, argv, "f:hi:n:r:s:xX")) != -1) {
                switch(c) {
                        case 'f':
                                find_count = atoi(optarg);
                                break;

                        case 'h':
                                usage(EXIT_SUCCESS);
                                break;

                        case 'i':
                                insert_count = atoi(optarg);
                                break;

                        case 'n':
                                nth_count = atoi(optarg);
                                break;

                        case 'r':
                                repeat_count = atoi(optarg);
                                break;

                        case 's':
                                input_file = optarg;
                                break;

                        case 'X':
                                fr_debug_lvl += 2;
                                default_log.print_level = true;
                                break;

                        case 'x':
                                fr_debug_lvl++;
                                if (fr_debug_lvl > 2) default_log.print_level = true;
                                break;

                        default:
                                usage(EXIT_FAILURE);
                                break;
                }
        }

        if (fr_debug_lvl) dependency_version_print();

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (!fr_dict_global_ctx_init(autofree, dict_dir)) EXIT_WITH_FAILURE;

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");

		if (panic_action && (fr_fault_setup(autofree, panic_action, argv[0]) < 0)) {
			EXIT_WITH_FAILURE;
		}
	}

	if (!input_file || (strcmp(input_file, "-") == 0)) {
		fp = stdin;
	} else {
		fp = fopen(input_file, "r");
		if (!fp) {
			fprintf(stderr, "Failed reading %s: %s\n",
				input_file, fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}
	}

        /*
         *  Read pairs to use in test from input file
         */
        if (fr_pair_list_afrom_file(autofree, dict, &input_vps, fp, &filedone) < 0) {
                fr_perror("Failed reading test pairs from %s", input_file);
                EXIT_WITH_FAILURE;
        }

        input_count = fr_pair_list_len(&input_vps);
        INFO("Source pairs read - %d", input_count);
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

        for (i = 0; i < repeat_count; i++) {

                /*
                 *  Insert pairs into the test list, choosing randomly from the source list
                 */
                for (j = 0; j < insert_count; j++) {
                        int index = rand() % input_count;
                        new_vp = fr_pair_copy(autofree, source_vps[index]);
                        begin_time = clock();
                        fr_pair_add(&test_vps, new_vp);
                        end_time = clock();
                        insert_time += (end_time - begin_time);
                }

                /*
                 * Find first instance of specific DA
                 */
                for (j = 0; j < find_count; j++) {
                        int index = rand() % input_count;
                        da = source_vps[index]->da;
                        begin_time = clock();
                        new_vp = fr_pair_find_by_da(&test_vps, da);
                        end_time = clock();
                        find_time += (end_time - begin_time);
                }

                /*
                 *  Find nth instance of specific DA
                 *  Presuming each DA is only once in the source list each DA will be 
                 *  roughly insert_count / input_count times in the test list
                 */
                nth_item = (int)(insert_count / input_count);
                for (j = 0; j < nth_count; j++) {
                        int index = rand() % input_count;
                        da = source_vps[index]->da;
                        k = 0;
                        begin_time = clock();
                        LIST_VERIFY(&test_vps);
                        for (new_vp = fr_pair_list_head(&test_vps); new_vp; new_vp = fr_pair_list_next(&test_vps, new_vp)) {
                                if (new_vp->da == da) {
                                        k++;
                                        if (k == nth_item) break;
                                }
                        }
                        end_time = clock();
                        nth_time += (end_time - begin_time);
                }

                begin_time = clock();
                fr_pair_list_free(&test_vps);
                end_time = clock();
                free_time += (end_time - begin_time);

        }

        INFO("Operation        Repetitions     CPU Ticks");
        INFO("------------------------------------------");
        INFO("Add to list      %11d     %9ld", insert_count * repeat_count, insert_time);
        INFO("Find in list     %11d     %9ld", find_count * repeat_count, find_time);
        INFO("Find nth in list %11d     %9ld", nth_count * repeat_count, nth_time);
        INFO("Free list        %11d     %9ld", repeat_count, free_time);

cleanup:

        return ret;
}

/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: pair_list_perf_test [options]\n");
	fprintf(output, "Options:\n");
        fprintf(output, "  -f <count>         Number of \"find\" operations per test.\n");
        fprintf(output, "  -i <count>         Number of pairs to insert in test list.\n");
        fprintf(output, "  -n <count>         Number of \"find nth\" operations per test.\n");
        fprintf(output, "  -r <count>         Number of times to repeat the test.\n");
	fprintf(output, "  -s <file>          File to read test pairs from.\n");
	fprintf(output, "  -X                 Turn on full debugging.\n");
	fprintf(output, "  -x                 Turn on additional debugging. (-xx gives more debugging).\n");

	fr_exit_now(status);
}
