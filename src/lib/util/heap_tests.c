#include <freeradius-devel/util/acutest.h>

#include "heap.c"

static bool fr_heap_check(fr_heap_t *hp, void *data)
{
	int i;

	if (!hp || (hp->num_elements == 0)) return false;

	for (i = 0; i < hp->num_elements; i++) {
		if (hp->p[i] == data) {
			return true;
		}
	}

	return false;
}

typedef struct {
	int	data;
	int32_t	heap;		/* for the heap */
} heap_thing;


/*
 *  cc -g -DTESTING -I .. heap.c -o heap
 *
 *  ./heap
 */
static int8_t heap_cmp(void const *one, void const *two)
{
	heap_thing const *a = one, *b = two;

	return (a->data > b->data) - (a->data < b->data);
}

#define HEAP_TEST_SIZE (4096)

static void heap_test(int skip)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	int		left;
	int		ret;

	static bool	done_init = false;

	if (!done_init) {
		sranddev();
		done_init = true;
	}

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap);
	TEST_CHECK(hp != NULL);

	array = malloc(sizeof(heap_thing) * HEAP_TEST_SIZE);

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < HEAP_TEST_SIZE; i++) array[i].data = rand() % 65537;

#if 0
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		printf("Array %d has value %d at offset %d\n",
		       i, array[i].data, array[i].heap);
	}
#endif

	TEST_CASE("insertions");
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(fr_heap_check(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("deletions");
	{
		int32_t entry;

		for (i = 0; i < HEAP_TEST_SIZE / skip; i++) {
			entry = i * skip;

			TEST_CHECK(array[entry].heap != -1);
			TEST_MSG("element %i removed out of order", entry);

			TEST_CHECK((ret = fr_heap_extract(hp, &array[entry])) >= 0);
			TEST_MSG("element %i removal failed, returned %i", entry, ret);

			TEST_CHECK(!fr_heap_check(hp, &array[entry]));
			TEST_MSG("element %i removed but still in heap", entry);

			TEST_CHECK(array[entry].heap == -1);
			TEST_MSG("element %i removed out of order", entry);
		}
	}

	left = fr_heap_num_elements(hp);
	for (i = 0; i < left; i++) {
		heap_thing *t;

		TEST_CHECK((t = fr_heap_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", left - i);

		TEST_CHECK(fr_heap_extract(hp, NULL) >= 0);
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

#define HEAP_CYCLE_SIZE (16000000)

static void heap_cycle(void)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	heap_thing	*remaining;
	int		to_remove;
	int		ret;

	static bool	done_init = false;

	if (!done_init) {
		sranddev();
		done_init = true;
	}

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap);
	TEST_CHECK(hp != NULL);

	array = malloc(sizeof(heap_thing) * HEAP_CYCLE_SIZE);
	remaining = calloc(sizeof(heap_thing) * HEAP_CYCLE_SIZE, 1);

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < HEAP_CYCLE_SIZE; i++) array[i].data = rand() % 65537;

	TEST_CASE("insertions");
	for (i = 0; i < HEAP_CYCLE_SIZE; i++) {
		TEST_CHECK((ret = fr_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
	}
	TEST_CHECK(fr_heap_num_elements(hp) == HEAP_CYCLE_SIZE);

	TEST_CASE("pop");

	/*
	 *	Remove a random number of elements from the heap
	 */
	to_remove = fr_heap_num_elements(hp) / 2;
	for (i = 0; i < to_remove; i++) {
		heap_thing *t;

		TEST_CHECK((t = fr_heap_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", to_remove - i);

		TEST_CHECK(fr_heap_extract(hp, NULL) >= 0);
		TEST_MSG("failed extracting %i", i);
	}

	/*
	 *	Now swap the inserted and removed set creating churn
	 */
	{
		int inserted = 0, removed = 0;

		for (i = 0; i < HEAP_CYCLE_SIZE; i++) {
			if (array[i].heap == -1) {
				TEST_CHECK((ret = fr_heap_insert(hp, &array[i])) >= 0);
				TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());
				inserted++;
			} else {
				TEST_CHECK((ret = fr_heap_extract(hp, &array[i])) >= 0);
				TEST_MSG("element %i removal failed, returned %i", i, ret);
				removed++;
			}
		}

		TEST_CHECK(removed == (HEAP_CYCLE_SIZE - to_remove));
		TEST_MSG("expected %i", HEAP_CYCLE_SIZE - to_remove);
		TEST_MSG("got %i", removed);

		TEST_CHECK(inserted == to_remove);
		TEST_MSG("expected %i", to_remove);
		TEST_MSG("got %i", inserted);
	}

	talloc_free(hp);
	free(array);
	free(remaining);
}

static void heap_cycle(void)
{
	fr_heap_t	*hp;
	int		i;
	heap_thing	*array;
	heap_thing	*remaining;
	int		to_remove;
	int		ret;

	static bool	done_init = false;

	if (!done_init) {
		sranddev();
		done_init = true;
	}

	hp = fr_heap_alloc(NULL, heap_cmp, heap_thing, heap);
	TEST_CHECK(hp != NULL);

	array = malloc(sizeof(heap_thing) * HEAP_CYCLE_SIZE);

	for (i = 0; i < HEAP_CYCLE_SIZE; i++) array[i].data = rand() % 65537;
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "heap_test_skip_0",		heap_test_skip_0	},
	{ "heap_test_skip_2",		heap_test_skip_2	},
	{ "heap_test_skip_10",		heap_test_skip_10	},
	{ "heap_cycle",			heap_cycle		},
	{ NULL }
};

