#include "acutest.h"
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/rand.h>

#include "../heap.c"

static bool fr_heap_check(fr_heap_t *h, void *data)
{
	unsigned int i;

	if (!h || (h->num_elements == 0)) return false;

	for (i = 0; i < h->num_elements; i++) {
		if (h->p[i + 1] == data) {
			return true;
		}
	}

	return false;
}

typedef struct {
	int		data;
	unsigned int	heap;		/* for the heap */
} heap_thing;


/*
 *  cc -g -DTESTING -I .. heap.c -o heap
 *
 *  ./heap
 */
static int8_t heap_cmp(void const *one, void const *two)
{
	heap_thing const *a = one, *b = two;

	return CMP_PREFER_SMALLER(a->data, b->data);
}

#define HEAP_TEST_SIZE (4096)

static void heap_test(int skip)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	int		left;
	int		ret;
	fr_fast_rand_t	rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(HEAP_TEST_SIZE, sizeof(heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < HEAP_TEST_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

#if 0
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		printf("Array %d has value %d at offset %d\n",
		       i, array[i].data, array[i].heap);
	}
#endif

	TEST_CASE("insertions");
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		FR_HEAP_VERIFY(hp);
		TEST_CHECK((ret = fr_heap_insert(&hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(fr_heap_check(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("deletions");
	{
		int entry;

		for (i = 0; i < HEAP_TEST_SIZE / skip; i++) {
			entry = i * skip;

			FR_HEAP_VERIFY(hp);
			TEST_CHECK(array[entry].heap != 0);
			TEST_MSG("element %i removed out of order", entry);

			TEST_CHECK((ret = fr_heap_extract(&hp, &array[entry])) >= 0);
			TEST_MSG("element %i removal failed, returned %i - %s", entry, ret, fr_strerror());

			TEST_CHECK(!fr_heap_check(hp, &array[entry]));
			TEST_MSG("element %i removed but still in heap", entry);

			TEST_CHECK(array[entry].heap == 0);
			TEST_MSG("element %i removed out of order", entry);
		}
	}

	left = fr_heap_num_elements(hp);
	for (i = 0; i < left; i++) {
		heap_thing *t;

		FR_HEAP_VERIFY(hp);
		TEST_CHECK((t = fr_heap_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", left - i);

		TEST_CHECK(fr_heap_extract(&hp, t) >= 0);
		TEST_MSG("failed extracting %i", i);
	}

	TEST_CHECK((ret = fr_heap_num_elements(hp)) == 0);
	TEST_MSG("%i elements remaining", ret);

	talloc_free(hp);
	free(array);
}

static void heap_test_skip_0(void)
{
	heap_test(1);
}

static void heap_test_skip_2(void)
{
	heap_test(2);
}

static void heap_test_skip_10(void)
{
	heap_test(10);
}

#define HEAP_CYCLE_SIZE (1600000)

static void heap_test_order(void)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	heap_thing	*thing, *prev = NULL;
	int		data = 0;
	unsigned int	count = 0;
	int		ret;
	fr_fast_rand_t	rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(HEAP_TEST_SIZE, sizeof(heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < HEAP_TEST_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	TEST_CASE("insertions");
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_heap_insert(&hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(fr_heap_check(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("ordering");

	while ((thing = fr_heap_pop(&hp))) {
		TEST_CHECK(thing->data >= data);
		TEST_MSG("Expected data >= %i, got %i", data, thing->data);
		if (thing->data >= data) data = thing->data;
		TEST_CHECK(thing != prev);
		prev = thing;
		count++;
	}

	TEST_CHECK(count == HEAP_TEST_SIZE);

	talloc_free(hp);
	free(array);
}

#define	HEAP_ITER_SIZE	20

static void heap_iter(void)
{
	fr_heap_t	*hp;
	heap_thing	*array;
	unsigned int	data_set;

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(HEAP_ITER_SIZE, sizeof(heap_thing));

	for (size_t i = 0; i < HEAP_ITER_SIZE; i++) {
		array[i].data = i;
		TEST_CHECK(fr_heap_insert(&hp, &array[i])  >= 0);
	}

	data_set = 0;
	fr_heap_foreach(hp, heap_thing, item) {
		TEST_CHECK((data_set & (1U << item->data)) == 0);
		data_set |= (1U << item->data);
	}}
	TEST_CHECK(data_set == ((1U << HEAP_ITER_SIZE) - 1U));

	talloc_free(hp);
	free(array);
}

static void heap_cycle(void)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	int		to_remove;
	int		inserted, removed;
	int		ret;
	fr_time_t	start_insert, start_remove, start_swap, end;
	fr_fast_rand_t	rand_ctx;

	rand_ctx.a = fr_rand();
	rand_ctx.b = fr_rand();

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(HEAP_CYCLE_SIZE, sizeof(heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < HEAP_CYCLE_SIZE; i++) array[i].data = fr_fast_rand(&rand_ctx) % 65537;

	start_insert = fr_time();
	TEST_CASE("insertions");
	for (i = 0; i < HEAP_CYCLE_SIZE; i++) {
		TEST_CHECK((ret = fr_heap_insert(&hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
	}
	TEST_CHECK(fr_heap_num_elements(hp) == HEAP_CYCLE_SIZE);

	TEST_CASE("pop");

	/*
	 *	Remove a random number of elements from the heap
	 */
	to_remove = fr_heap_num_elements(hp) / 2;
	start_remove = fr_time();
	for (i = 0; i < to_remove; i++) {
		heap_thing *t;

		TEST_CHECK((t = fr_heap_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", to_remove - i);

		TEST_CHECK(fr_heap_extract(&hp, t) >= 0);
		TEST_MSG("failed extracting %i - %s", i, fr_strerror());
	}

	/*
	 *	Now swap the inserted and removed set creating churn
	 */
	start_swap = fr_time();
	inserted = 0;
	removed = 0;

	for (i = 0; i < HEAP_CYCLE_SIZE; i++) {
		if (!fr_heap_entry_inserted(array[i].heap)) {
			TEST_CHECK((ret = fr_heap_insert(&hp, &array[i])) >= 0);
			TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
			inserted++;
		} else {
			TEST_CHECK((ret = fr_heap_extract(&hp, &array[i])) >= 0);
			TEST_MSG("element %i removal failed, returned %i - %s", i, ret, fr_strerror());
			removed++;
		}
	}

	TEST_CHECK(removed == (HEAP_CYCLE_SIZE - to_remove));
	TEST_MSG("expected %i", HEAP_CYCLE_SIZE - to_remove);
	TEST_MSG("got %i", removed);

	TEST_CHECK(inserted == to_remove);
	TEST_MSG("expected %i", to_remove);
	TEST_MSG("got %i", inserted);

	end = fr_time();

	TEST_MSG_ALWAYS("\ncycle size: %d\n", HEAP_CYCLE_SIZE);
	TEST_MSG_ALWAYS("insert: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(start_remove, start_insert)) / (double)NSEC);
	TEST_MSG_ALWAYS("extract: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(start_swap, start_remove))/ (double)NSEC);
	TEST_MSG_ALWAYS("swap: %.2fs\n", fr_time_delta_unwrap(fr_time_sub(end, start_swap)) / (double)NSEC);

	talloc_free(hp);
	free(array);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "heap_test_skip_0",		heap_test_skip_0	},
	{ "heap_test_skip_2",		heap_test_skip_2	},
	{ "heap_test_skip_10",		heap_test_skip_10	},
	{ "heap_test_order",		heap_test_order		},
	{ "heap_iter",			heap_iter		},
	{ "heap_cycle",			heap_cycle		},
	TEST_TERMINATOR
};

