#include "acutest.h"
#include"acutest_helpers.h"
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/heap.h>

/*
 *	This counterintuitive #include gives these separately-compiled tests
 *	access to fr_lst_t internals that lst.h doesn't reveal
 *	to those who #include it.
 */
#include "../lst.c"

typedef struct {
	unsigned int	data;
	fr_lst_index_t	idx;
	bool		visited;	/* Only used by iterator test */
} lst_thing;

#if 0
static void	lst_validate(fr_lst_t *lst);
#endif

static bool fr_lst_contains(fr_lst_t *lst, void *data)
{
	unsigned int size = fr_lst_num_elements(lst);

	for (unsigned int i = 0; i < size; i++) if (item(lst, i + lst->idx) == data) return true;

	return false;
}

static int8_t lst_cmp(void const *one, void const *two)
{
	lst_thing const	*item1 = one, *item2 = two;

	return CMP(item1->data, item2->data);
}

static void populate_values(lst_thing values[], unsigned int len)
{
	unsigned int i;
	fr_fast_rand_t	rand_ctx;

	for (i = 0; i < len; i++) {
		values[i].data = i;
		values[i].idx = 0;
		values[i].visited = false;
	}

	/* shuffle values before insertion, so the heap has to work to give them back in order */
	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	for (i = 0; i < len; i++) {
		unsigned int	j = fr_fast_rand(&rand_ctx) % len;
		int	temp = values[i].data;

		values[i].data = values[j].data;
		values[j].data = temp;
	}
}

#define NVALUES	20
static void lst_test_basic(void)
{
	fr_lst_t	*lst;
	lst_thing	values[NVALUES];

	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, NVALUES);
	TEST_CHECK(lst != NULL);

	populate_values(values, NUM_ELEMENTS(values));

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++) {
		TEST_CHECK(fr_lst_insert(lst, &values[i]) >= 0);
		TEST_CHECK(fr_lst_entry_inserted(values[i].idx));
	}

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++) {
		lst_thing	*value = fr_lst_pop(lst);

		TEST_CHECK(value != NULL);
		TEST_CHECK(!fr_lst_entry_inserted(value->idx));
		TEST_CHECK(value->data == i);
		TEST_MSG("iteration %u, popped %u", i, value->data);
	}
	talloc_free(lst);
}

#define LST_TEST_SIZE (4096)

static void lst_test(int skip)
{
	fr_lst_t	*lst;
	int		i;
	lst_thing	*values;
	int		left;
	int		ret;

	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 0);
	TEST_CHECK(lst != NULL);

	values = calloc(LST_TEST_SIZE, sizeof(lst_thing));

	/*
	 *	Initialise random values
	 */
	populate_values(values, LST_TEST_SIZE);

	TEST_CASE("insertions");
	for (i = 0; i < LST_TEST_SIZE; i++) {
		FR_LST_VERIFY(lst);
		TEST_CHECK((ret = fr_lst_insert(lst, &values[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(fr_lst_contains(lst, &values[i]));
		TEST_MSG("element %i inserted but not in LST", i);
	}

	TEST_CASE("deletions");
	for (int entry = 0; entry < LST_TEST_SIZE; entry += skip) {
		FR_LST_VERIFY(lst);
		TEST_CHECK(values[entry].idx != 0);
		TEST_MSG("element %i removed out of order", entry);

		TEST_CHECK((ret = fr_lst_extract(lst, &values[entry])) >= 0);
		TEST_MSG("element %i removal failed, returned %i", entry, ret);

		TEST_CHECK(!fr_lst_contains(lst, &values[entry]));
		TEST_MSG("element %i removed but still in LST", entry);

		TEST_CHECK(values[entry].idx == 0);
		TEST_MSG("element %i removed out of order", entry);
	}

	left = fr_lst_num_elements(lst);
	for (i = 0; i < left; i++) {
		FR_LST_VERIFY(lst);
		TEST_CHECK(fr_lst_pop(lst) != NULL);
		TEST_MSG("expected %i elements remaining in the lst", left - i);
		TEST_MSG("failed extracting %i", i);
	}

	TEST_CHECK((ret = fr_lst_num_elements(lst)) == 0);
	TEST_MSG("%i elements remaining", ret);

	talloc_free(lst);
	free(values);
}

static void lst_test_skip_1(void)
{
	lst_test(1);
}

static void lst_test_skip_2(void)
{
	lst_test(2);
}

static void lst_test_skip_10(void)
{
	lst_test(10);
}


static void lst_stress_realloc(void)
{
	fr_lst_t	*lst;
	fr_heap_t	*hp;
	lst_thing	*lst_array, *hp_array;
	fr_fast_rand_t	rand_ctx;
	int		ret;
	lst_thing	*from_lst, *from_hp;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 0);
	TEST_CHECK(lst != NULL);
	hp = fr_heap_alloc(NULL, lst_cmp, lst_thing, idx, 0);

	lst_array = calloc(2 * INITIAL_CAPACITY, sizeof(lst_thing));
	hp_array = calloc(2 * INITIAL_CAPACITY, sizeof(lst_thing));

	/*
	 *	Initialise random values
	 */
	for (unsigned int i = 0; i < 2 * INITIAL_CAPACITY; i++) {
		lst_array[i].data = hp_array[i].data = fr_fast_rand(&rand_ctx) % 65537;
	}

	/* Add the first INITIAL_CAPACITY values to lst and to hp */
	TEST_CASE("partial fill");
	for (int i = 0; i < INITIAL_CAPACITY; i++) {
		TEST_CHECK((ret = fr_lst_insert(lst, &lst_array[i])) >= 0);
		TEST_MSG("lst insert failed, iteration %d; returned %i - %s", i, ret, fr_strerror());
		TEST_CHECK((ret = fr_heap_insert(&hp, &hp_array[i])) >= 0);
		TEST_MSG("heap insert failed, iteration %d; returned %i - %s", i, ret, fr_strerror());
	}

	/* Pop INITIAL_CAPACITY / 2 values from each (they should all be equal) */
	TEST_CASE("partial pop");
	for (unsigned int i = 0; i < INITIAL_CAPACITY / 2; i++) {
		TEST_CHECK((from_lst = fr_lst_pop(lst)) != NULL);
		TEST_CHECK((from_hp = fr_heap_pop(&hp)) != NULL);
		TEST_CHECK(lst_cmp(from_lst, from_hp) == 0);
	}

	/*
	 * Add the second INITIAL_CAPACITY values to lst and to hp.
	 * This should force lst to move entries to maintain adjacency,
	 * which is what we're testing here.
	 */
	TEST_CASE("force move with expansion");
	for (unsigned int i = INITIAL_CAPACITY; i < 2 * INITIAL_CAPACITY; i++) {
		TEST_CHECK((ret = fr_lst_insert(lst, &lst_array[i])) >= 0);
		TEST_MSG("lst insert failed, iteration %u; returned %i - %s", i, ret, fr_strerror());
		TEST_CHECK((ret = fr_heap_insert(&hp, &hp_array[i])) >= 0);
		TEST_MSG("heap insert failed, iteration %u; returned %i - %s", i, ret, fr_strerror());
	}

	/* pop the remaining 3 * INITIAL_CAPACITY / 2 values from each (they should all be equal) */
	TEST_CASE("complete pop");
	for (unsigned int i = 0; i < 3 * INITIAL_CAPACITY / 2; i++) {
		TEST_CHECK((from_lst = fr_lst_pop(lst)) != NULL);
		TEST_CHECK((from_hp = fr_heap_pop(&hp)) != NULL);
		TEST_CHECK(lst_cmp(from_lst, from_hp) == 0);
	}

	TEST_CHECK(fr_lst_num_elements(lst) == 0);
	TEST_CHECK(fr_heap_num_elements(hp) == 0);

	talloc_free(lst);
	talloc_free(hp);
	free(lst_array);
	free(hp_array);
}

#define BURN_IN_OPS	(10000000)

static void lst_burn_in(void)
{
	fr_lst_t	*lst = NULL;
	lst_thing	*array = NULL;
	fr_fast_rand_t	rand_ctx;
	int		insert_count = 0;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	array = calloc(BURN_IN_OPS, sizeof(lst_thing));
	for (unsigned int i = 0; i < BURN_IN_OPS; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	/* Make init small to exercise growing the pivot stack. */
	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 32);

	for (unsigned int i = 0; i < BURN_IN_OPS; i++) {
		lst_thing	*ret_thing = NULL;
		int		ret_insert = -1;

		if (fr_lst_num_elements(lst) == 0) {
		insert:
			TEST_CHECK((ret_insert = fr_lst_insert(lst, &array[insert_count])) >= 0);
			insert_count++;
		} else {
			switch (fr_fast_rand(&rand_ctx) % 3) {
			case 0: /* insert */
				goto insert;

			case 1: /* pop */
				ret_thing = fr_lst_pop(lst);
				TEST_CHECK(ret_thing != NULL);
				break;
			case 2: /* peek */
				ret_thing = fr_lst_peek(lst);
				TEST_CHECK(ret_thing != NULL);
				break;
			}
		}
	}

	talloc_free(lst);
	free(array);
}

#define LST_CYCLE_SIZE (1600000)

static void lst_cycle(void)
{
	fr_lst_t	*lst;
	int		i;
	lst_thing	*values;
	int		to_remove;
	int 		inserted, removed;
	int		ret;
	fr_time_t	start_insert, start_remove, start_swap, end;

	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 0);
	TEST_CHECK(lst != NULL);

	values = calloc(LST_CYCLE_SIZE, sizeof(lst_thing));

	/*
	 *	Initialise random values
	 */
	populate_values(values, LST_CYCLE_SIZE);

	start_insert = fr_time();
	TEST_CASE("insertions");
	for (i = 0; i < LST_CYCLE_SIZE; i++) {
		TEST_CHECK((ret = fr_lst_insert(lst, &values[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
	}
	TEST_CHECK(fr_lst_num_elements(lst) == LST_CYCLE_SIZE);

	TEST_CASE("pop");

	/*
	 *	Remove a random number of elements from the LST
	 */
	to_remove = fr_lst_num_elements(lst) / 2;
	start_remove = fr_time();
	for (i = 0; i < to_remove; i++) {
		TEST_CHECK(fr_lst_pop(lst) != NULL);
		TEST_MSG("failed extracting %i", i);
		TEST_MSG("expected %i elements remaining in the LST", to_remove - i);
	}

	/*
	 *	Now swap the inserted and removed set creating churn
	 */
	start_swap = fr_time();

	inserted = 0;
	removed = 0;

	for (i = 0; i < LST_CYCLE_SIZE; i++) {
		if (values[i].idx == 0) {
			TEST_CHECK((ret = fr_lst_insert(lst, &values[i])) >= 0);
			TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
			inserted++;
		} else {
			TEST_CHECK((ret = fr_lst_extract(lst, &values[i])) >= 0);
			TEST_MSG("element %i removal failed, returned %i", i, ret);
			removed++;
		}
	}

	TEST_CHECK(removed == (LST_CYCLE_SIZE - to_remove));
	TEST_MSG("expected %i", LST_CYCLE_SIZE - to_remove);
	TEST_MSG("got %i", removed);

	TEST_CHECK(inserted == to_remove);
	TEST_MSG("expected %i", to_remove);
	TEST_MSG("got %i", inserted);

	end = fr_time();

	TEST_MSG_ALWAYS("\ncycle size: %d\n", LST_CYCLE_SIZE);
	TEST_MSG_ALWAYS("insert: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(start_remove, start_insert)) / (double)NSEC);
	TEST_MSG_ALWAYS("extract: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(start_swap, start_remove)) / (double)NSEC);
	TEST_MSG_ALWAYS("swap: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(end, start_swap)) / (double)NSEC);

	talloc_free(lst);
	free(values);
}

static void lst_iter(void)
{
	fr_lst_t	*lst;
	fr_lst_iter_t	iter;
	lst_thing	values[NVALUES], *data;
	unsigned int	total;

	lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 0);
	TEST_CHECK(lst != NULL);

	populate_values(values, NUM_ELEMENTS(values));

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++) TEST_CHECK(fr_lst_insert(lst, &values[i]) == 0);

	data = fr_lst_iter_init(lst, &iter);

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++, data = fr_lst_iter_next(lst, &iter)) {
		TEST_CHECK(data != NULL);
		TEST_CHECK(!data->visited);
		TEST_CHECK(data->idx > 0);
		data->visited = true;
	}

	TEST_CHECK(data == NULL);

	total = 0;
	fr_lst_foreach(lst, lst_thing, item) {
		total += item->data;
	}}
	TEST_CHECK(total = 190);

	talloc_free(lst);
}

static CC_HINT(noinline) lst_thing *array_pop(lst_thing **array, unsigned int count)
{
	lst_thing *low = NULL;
	unsigned int idx = 0;

	for (unsigned int j = 0; j < count; j++) {
		if (!array[j]) continue;

		if (!low || (lst_cmp(array[j], low) < 0)) {
			idx = j;
			low = array[j];
		}
	}
	if (low) array[idx] = NULL;

	return low;
}

/** Benchmarks for LSTs vs heaps when used as queues
 *
 */
static void queue_cmp(unsigned int count)
{
	fr_lst_t	*lst;
	fr_heap_t	*hp;

	lst_thing	*values;

	unsigned int	i;

	values = talloc_array(NULL, lst_thing, count);

	/*
	 *	Check times for LST alloc, insert, pop
	 */
	{
		fr_time_t	start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first = fr_time_wrap(0);

		populate_values(values, count);

		start_alloc = fr_time();
		lst = fr_lst_alloc(NULL, lst_cmp, lst_thing, idx, 0);
		end_alloc = fr_time();
		TEST_CHECK(lst != NULL);

		start_insert = fr_time();
		for (i = 0; i < count; i++) TEST_CHECK(fr_lst_insert(lst, &values[i]) == 0);
		end_insert = fr_time();

		start_pop = fr_time();
		for (i = 0; i < count; i++) {
			TEST_CHECK(fr_lst_pop(lst) != NULL);
			if (i == 0) end_pop_first = fr_time();

			TEST_MSG("expected %u elements remaining in the lst", count - i);
			TEST_MSG("failed extracting %u", i);
		}
		end_pop = fr_time();

		TEST_MSG_ALWAYS("\nlst size: %u\n", count);
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_alloc, start_alloc)) / 1000);
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_insert, start_insert)) / 1000);
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop_first, start_pop)) / 1000);
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop, start_pop)) / 1000);

		talloc_free(lst);
	}

	/*
	 *	Check times for heap alloc, insert, pop
	 */
	{
		fr_time_t	start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first = fr_time_wrap(0);

		populate_values(values, count);

		start_alloc = fr_time();
		hp = fr_heap_alloc(NULL, lst_cmp, lst_thing, idx, count);
		end_alloc = fr_time();
		TEST_CHECK(hp != NULL);

		start_insert = fr_time();
		for (i = 0; i < count; i++) fr_heap_insert(&hp, &values[i]);
		end_insert = fr_time();

		start_pop = fr_time();
		for (i = 0; i < count; i++) {
			TEST_CHECK(fr_heap_pop(&hp) != NULL);
			if (i == 0) end_pop_first = fr_time();

			TEST_MSG("expected %u elements remaining in the heap", count - i);
			TEST_MSG("failed extracting %u", i);
		}
		end_pop = fr_time();

		TEST_MSG_ALWAYS("\nheap size: %u\n", count);
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_alloc, start_alloc)) / 1000);
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_insert, start_insert)) / 1000);
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop_first, start_pop)) / 1000);
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop, start_pop)) / 1000);

		talloc_free(hp);
	}

	/*
	 *	Array
	 */
	{
		lst_thing	**array;
		fr_time_t	start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first;

		populate_values(values, count);
		end_pop_first = fr_time_wrap(0);

		start_alloc = fr_time();
		array = talloc_array(NULL, lst_thing *, count);
		end_alloc = fr_time();

		start_insert = fr_time();
		for (i = 0; i < count; i++) array[i] = &values[i];
		end_insert = fr_time();

		start_pop = fr_time();
		for (i = 0; i < count; i++) {
			TEST_CHECK(array_pop(array, count) != NULL);
			if (i == 0) end_pop_first = fr_time();
		}
		end_pop = fr_time();

		TEST_MSG_ALWAYS("\narray size: %u\n", count);
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_alloc, start_alloc)) / 1000);
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_insert, start_insert)) / 1000);
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop_first, start_pop)) / 1000);
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_unwrap(fr_time_sub(end_pop, start_pop)) / 1000);

		talloc_free(array);
	}

	talloc_free(values);
}

static void queue_cmp_10(void)
{
	queue_cmp(10);
}

static void queue_cmp_50(void)
{
	queue_cmp(50);
}

static void queue_cmp_100(void)
{
	queue_cmp(100);
}

static void queue_cmp_1000(void)
{
	queue_cmp(1000);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "lst_test_basic",	lst_test_basic	},
	{ "lst_test_skip_1",	lst_test_skip_1	},
	{ "lst_test_skip_2",	lst_test_skip_2	},
	{ "lst_test_skip_10",	lst_test_skip_10	},
	{ "lst_stress_realloc",	lst_stress_realloc	},
	{ "lst_burn_in",	lst_burn_in		},
	{ "lst_cycle",		lst_cycle		},
	{ "lst_iter",		lst_iter },
	{ "queue_cmp_10",	queue_cmp_10 },
	{ "queue_cmp_50",	queue_cmp_50 },
	{ "queue_cmp_100",	queue_cmp_100 },
	{ "queue_cmp_1000",	queue_cmp_1000 },
	TEST_TERMINATOR
};
