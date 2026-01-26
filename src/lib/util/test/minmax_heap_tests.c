#include "acutest.h"
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/time.h>

#include "../minmax_heap.c"

typedef struct {
	unsigned int		data;
	fr_minmax_heap_index_t	idx;		/* for the heap */
	bool			visited;
} minmax_heap_thing;

static bool minmax_heap_contains(fr_minmax_heap_t *hp, void *data)
{
	minmax_heap_t	*h = *hp;

	for (unsigned int i = 1; i <= h->num_elements; i++) if (h->p[i] == data) return true;

	return false;
}

static int8_t minmax_heap_cmp(void const *one, void const *two)
{
	minmax_heap_thing const *a = one, *b = two;

	return CMP_PREFER_SMALLER(a->data, b->data);
}

#if 0
#define is_power_of_2(_n)	!((_n) & ((_n) - 1))
/*
 *	A simple minmax heap dump function, specific to minmax_heap_thing and
 *	intended for use only with small heaps. It only shows the data members
 *	in the order they appear in the array, ignoring the unused zeroeth
 *	entry and printing a vertical bar before the start of each successive level.
 */
static void minmax_heap_dump(fr_minmax_heap_t *hp)
{
	minmax_heap_t	*h = *hp;
	unsigned int	num_elements = h->num_elements;

	fprintf(stderr, "%3u: ", num_elements);

	for (fr_minmax_heap_index_t i = 1; i <= num_elements; i++) {
		if (is_power_of_2(i)) fprintf(stderr, "|");
		fprintf(stderr, "%6u", ((minmax_heap_thing *)(h->p[i]))->data);
	}
	fprintf(stderr, "\n");
}
#endif

static void populate_values(minmax_heap_thing values[], unsigned int len)
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
static void minmax_heap_test_basic(void)
{
	fr_minmax_heap_t	*hp;
	minmax_heap_thing	values[NVALUES];

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, NVALUES);
	TEST_CHECK(hp != NULL);

	populate_values(values, NVALUES);

	/*
	 * minmax heaps can get the minimum value...
	 */
	for (unsigned int i = 0; i < NVALUES; i++) {
		TEST_CHECK(fr_minmax_heap_insert(hp, &values[i]) >= 0);
		TEST_CHECK(fr_minmax_heap_entry_inserted(values[i].idx));
	}

	for (unsigned int i = 0; i < NVALUES; i++) {
		minmax_heap_thing	*value = fr_minmax_heap_min_pop(hp);

		TEST_CHECK(value != NULL);
		TEST_CHECK(!fr_minmax_heap_entry_inserted(value->idx));
		TEST_CHECK(value->data == i);
		TEST_MSG("iteration %u, popped %u", i, value->data);
	}

	/*
	 * ...or the maximum value.
	 */
	for (unsigned int i = 0; i < NVALUES; i++) {
		TEST_CHECK(fr_minmax_heap_insert(hp, &values[i]) >= 0);
		TEST_CHECK(fr_minmax_heap_entry_inserted(values[i].idx));
	}

	for (unsigned int i = NVALUES; --i > 0; ) {
		minmax_heap_thing	*value = fr_minmax_heap_max_pop(hp);

		TEST_CHECK(value != NULL);
		TEST_CHECK(!fr_minmax_heap_entry_inserted(value->idx));
		TEST_CHECK(value->data == i);
		TEST_MSG("iteration %u, popped %u", NVALUES - 1 - i, value->data);
	}

	talloc_free(hp);
}

#define MINMAX_HEAP_TEST_SIZE  (4096)

static void minmax_heap_test(int skip)
{
	fr_minmax_heap_t	*hp;
	int			i;
	minmax_heap_thing	*array;
	int			left;
	int			ret;
	fr_fast_rand_t		rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	array = talloc_zero_array(hp, minmax_heap_thing, MINMAX_HEAP_TEST_SIZE);

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	TEST_CASE("insertions");
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) {
		FR_MINMAX_HEAP_VERIFY(hp);
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(minmax_heap_contains(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("deletions");
	{
		int entry;

		for (i = 0; i < MINMAX_HEAP_TEST_SIZE / skip; i++) {
			entry = i * skip;

			FR_MINMAX_HEAP_VERIFY(hp);
			TEST_CHECK(array[entry].idx != 0);
			TEST_MSG("element %i removed out of order", entry);

			TEST_CHECK((ret = fr_minmax_heap_extract(hp, &array[entry])) >= 0);
			TEST_MSG("element %i removal failed, returned %i - %s", entry, ret, fr_strerror());

			TEST_CHECK(!minmax_heap_contains(hp, &array[entry]));
			TEST_MSG("element %i removed but still in heap", entry);

			TEST_CHECK(array[entry].idx == 0);
			TEST_MSG("element %i removed out of order", entry);
		}
	}

	left = fr_minmax_heap_num_elements(hp);
	for (i = 0; i < left; i++) {
		minmax_heap_thing	*t;

		FR_MINMAX_HEAP_VERIFY(hp);
		TEST_CHECK((t = fr_minmax_heap_min_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", left - i);

		TEST_CHECK(fr_minmax_heap_extract(hp, t) >= 0);
		TEST_MSG("failed extracting %i", i);
	}

	TEST_CHECK((ret = fr_minmax_heap_num_elements(hp)) == 0);
	TEST_MSG("%i elements remaining", ret);

	talloc_free(hp);
}

/*
 *	minmax heaps can do anything heaps can do, so let's make sure we have
 *	a (proper!) superset of the heap tests.
 */

static void minmax_heap_test_skip_0(void)
{
	minmax_heap_test(1);
}

static void minmax_heap_test_skip_2(void)
{
	minmax_heap_test(2);
}

static void minmax_heap_test_skip_10(void)
{
	minmax_heap_test(10);
}

#define BURN_IN_OPS	(10000000)

static void minmax_heap_burn_in(void)
{
	fr_minmax_heap_t	*hp = NULL;
	minmax_heap_thing	*array = NULL;
	fr_fast_rand_t		rand_ctx;
	int			insert_count = 0;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	array = calloc(BURN_IN_OPS, sizeof(minmax_heap_thing));
	for (unsigned int i = 0; i < BURN_IN_OPS; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	for (unsigned int i = 0; i < BURN_IN_OPS; i++) {
		minmax_heap_thing	*ret_thing = NULL;
		int			ret_insert = -1;

		if (fr_minmax_heap_num_elements(hp) == 0) {
		insert:
			TEST_CHECK((ret_insert = fr_minmax_heap_insert(hp, &array[insert_count])) >= 0);
			insert_count++;
		} else {
			switch (fr_fast_rand(&rand_ctx) % 5) {
			case 0: /* insert */
				goto insert;

			case 1: /* min pop */
				ret_thing = fr_minmax_heap_min_pop(hp);
				TEST_CHECK(ret_thing != NULL);
				break;
			case 2: /* min peek */
				ret_thing = fr_minmax_heap_min_peek(hp);
				TEST_CHECK(ret_thing != NULL);
				break;
			case 3: /* max pop */
				ret_thing = fr_minmax_heap_max_pop(hp);
				TEST_CHECK(ret_thing != NULL);
				break;
			case 4: /* max peek */
				ret_thing = fr_minmax_heap_max_peek(hp);
				TEST_CHECK(ret_thing != NULL);
				break;
			}
		}
	}

	talloc_free(hp);
	free(array);
}

#define MINMAX_HEAP_CYCLE_SIZE (1600000)

static void minmax_heap_test_order(void)
{
	fr_minmax_heap_t	*hp;
	int			i;
	minmax_heap_thing	*array;
	minmax_heap_thing	*thing, *prev = NULL;
	unsigned int		data;
	unsigned int		count;
	int			ret;
	fr_fast_rand_t		rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	array = talloc_zero_array(hp, minmax_heap_thing, MINMAX_HEAP_TEST_SIZE);

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	TEST_CASE("insertions for min");
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(minmax_heap_contains(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("min ordering");

	count = 0;
	data = 0;
	prev = NULL;
	while ((thing = fr_minmax_heap_min_pop(hp))) {
		TEST_CHECK(thing->data >= data);
		TEST_MSG("Expected data >= %u, got %u", data, thing->data);
		if (thing->data >= data) data = thing->data;
		TEST_CHECK(thing != prev);
		prev = thing;
		count++;
	}

	TEST_CHECK(count == MINMAX_HEAP_TEST_SIZE);

	TEST_CASE("insertions for max");
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(minmax_heap_contains(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("max ordering");

	count = 0;
	data = UINT_MAX;
	prev = NULL;
	while ((thing = fr_minmax_heap_max_pop(hp))) {
		TEST_CHECK(thing->data <= data);
		TEST_MSG("Expected data >= %u, got %u", data, thing->data);
		if (thing->data <= data) data = thing->data;
		TEST_CHECK(thing != prev);
		prev = thing;
		count++;
	}

	TEST_CHECK(count == MINMAX_HEAP_TEST_SIZE);

	talloc_free(hp);
}

static CC_HINT(noinline) minmax_heap_thing *array_pop(minmax_heap_thing **array, unsigned int count)
{
	minmax_heap_thing	*low = NULL;
	unsigned int		idx = 0;

	for (unsigned int j = 0; j < count; j++) {
		if (!array[j]) continue;

		if (!low || (minmax_heap_cmp(array[j], low) < 0)) {
			idx = j;
			low = array[j];
		}
	}
	if (low) array[idx] = NULL;

	return low;
}

/** Benchmarks for minmax heaps vs heaps when used as queues
 *
 */
static void queue_cmp(unsigned int count)
{
	fr_minmax_heap_t	*minmax;
	fr_heap_t		*hp;

	minmax_heap_thing	*values;

	unsigned int		i;

	values = talloc_array(NULL, minmax_heap_thing, count);

	/*
	 *	Check times for minmax heap alloc, insert, pop
	 */
	{
		fr_time_t	start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first = fr_time_wrap(0);

		populate_values(values, count);

		start_alloc = fr_time();
		minmax = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
		end_alloc = fr_time();
		TEST_CHECK(minmax != NULL);

		start_insert = fr_time();
		for (i = 0; i < count; i++) (void) fr_minmax_heap_insert(minmax, &values[i]);
		end_insert = fr_time();

		start_pop = fr_time();
		for (i = 0; i < count; i++) {
			TEST_CHECK(fr_minmax_heap_min_pop(minmax) != NULL);
			if (i == 0) end_pop_first = fr_time();

			TEST_MSG("expected %u elements remaining in the minmax heap", count - i);
			TEST_MSG("failed extracting %u", i);
		}
		end_pop = fr_time();

		TEST_MSG_ALWAYS("\nminmax heap size: %u\n", count);
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_alloc, start_alloc)));
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_insert, start_insert)));
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop_first, start_pop)));
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop, start_pop)));
		talloc_free(minmax);
	}

	/*
	 *	Check times for heap alloc, insert, pop
	 */
	{
		fr_time_t	start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first = fr_time_min();

		populate_values(values, count);

		start_alloc = fr_time();
		hp = fr_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, count);
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
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_alloc, start_alloc)));
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_insert, start_insert)));
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop_first, start_pop)));
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop, start_pop)));

		talloc_free(hp);
	}

	/*
	 *	Array
	 */
	{
		minmax_heap_thing	**array;
		fr_time_t		start_alloc, end_alloc, start_insert, end_insert, start_pop, end_pop, end_pop_first;

		populate_values(values, count);
		end_pop_first = fr_time_min();

		start_alloc = fr_time();
		array = talloc_array(NULL, minmax_heap_thing *, count);
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
		TEST_MSG_ALWAYS("alloc: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_alloc, start_alloc)));
		TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_insert, start_insert)));
		TEST_MSG_ALWAYS("pop-first: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop_first, start_pop)));
		TEST_MSG_ALWAYS("pop: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end_pop, start_pop)));

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

static void minmax_heap_cycle(void)
{
	fr_minmax_heap_t	*hp;
	int			i;
	minmax_heap_thing	*array;
	int			to_remove;
	int			inserted, removed;
	int			ret;
	fr_time_t		start_insert, start_remove, start_swap, end;
	fr_fast_rand_t		rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(MINMAX_HEAP_CYCLE_SIZE, sizeof(minmax_heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < MINMAX_HEAP_CYCLE_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	start_insert = fr_time();
	TEST_CASE("insertions");
	for (i = 0; i < MINMAX_HEAP_CYCLE_SIZE; i++) {
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
	}
	TEST_CHECK(fr_minmax_heap_num_elements(hp) == MINMAX_HEAP_CYCLE_SIZE);

	TEST_CASE("pop");

	/*
	 *	Remove a random number of elements from the heap
	 */
	to_remove = fr_minmax_heap_num_elements(hp) / 2;
	start_remove = fr_time();
	for (i = 0; i < to_remove; i++) {
		minmax_heap_thing *t;

		TEST_CHECK((t = fr_minmax_heap_min_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", to_remove - i);

		TEST_CHECK(fr_minmax_heap_extract(hp, t) >= 0);
		TEST_MSG("failed extracting %i - %s", i, fr_strerror());
	}

	/*
	 *	Now swap the inserted and removed set creating churn
	 */
	start_swap = fr_time();
	inserted = 0;
	removed = 0;

	for (i = 0; i < MINMAX_HEAP_CYCLE_SIZE; i++) {
		if (!fr_minmax_heap_entry_inserted(array[i].idx)) {
			TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
			TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
			inserted++;
		} else {
			TEST_CHECK((ret = fr_minmax_heap_extract(hp, &array[i])) >= 0);
			TEST_MSG("element %i removal failed, returned %i - %s", i, ret, fr_strerror());
			removed++;
		}
	}

	TEST_CHECK(removed == (MINMAX_HEAP_CYCLE_SIZE - to_remove));
	TEST_MSG("expected %i", MINMAX_HEAP_CYCLE_SIZE - to_remove);
	TEST_MSG("got %i", removed);

	TEST_CHECK(inserted == to_remove);
	TEST_MSG("expected %i", to_remove);
	TEST_MSG("got %i", inserted);

	end = fr_time();

	TEST_MSG_ALWAYS("\ncycle size: %d\n", MINMAX_HEAP_CYCLE_SIZE);
	TEST_MSG_ALWAYS("insert: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(start_remove, start_insert)));
	TEST_MSG_ALWAYS("extract: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(start_swap, start_remove)));
	TEST_MSG_ALWAYS("swap: %"PRId64" μs\n", fr_time_delta_to_usec(fr_time_sub(end, start_swap)));

	talloc_free(hp);
	free(array);
}

static void minmax_heap_iter(void)
{
	fr_minmax_heap_t	*hp;
	fr_minmax_heap_iter_t	iter;
	minmax_heap_thing	values[NVALUES], *data;
	unsigned int		total;

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	populate_values(values, NUM_ELEMENTS(values));

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++) (void) fr_minmax_heap_insert(hp, &values[i]);

	data = fr_minmax_heap_iter_init(hp, &iter);

	for (unsigned int i = 0; i < NUM_ELEMENTS(values); i++, data = fr_minmax_heap_iter_next(hp, &iter)) {
		TEST_CHECK(data != NULL);
		TEST_CHECK(!data->visited);
		TEST_CHECK(data->idx > 0);
		data->visited = true;
	}

	TEST_CHECK(data == NULL);

	total = 0;
	fr_minmax_heap_foreach(hp, minmax_heap_thing, item) {
		total += item->data;
	}}
	TEST_CHECK(total = 190);

	talloc_free(hp);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "minmax_heap_test_basic",	minmax_heap_test_basic	},
	{ "minmax_heap_test_skip_0",	minmax_heap_test_skip_0 },
	{ "minmax_heap_test_skip_2",	minmax_heap_test_skip_2 },
	{ "minmax_heap_test_skip_10",	minmax_heap_test_skip_10 },
	{ "minmax_heap_test_order",	minmax_heap_test_order },
	{ "minmax_heap_burn_in",	minmax_heap_burn_in },
	{ "minmax_heap_cycle",		minmax_heap_cycle },
	{ "minmax_heap_iter",		minmax_heap_iter },
	{ "queue_cmp_10",	queue_cmp_10 },
	{ "queue_cmp_50",	queue_cmp_50 },
	{ "queue_cmp_100",	queue_cmp_100 },
	{ "queue_cmp_1000",	queue_cmp_1000 },
	TEST_TERMINATOR
};

