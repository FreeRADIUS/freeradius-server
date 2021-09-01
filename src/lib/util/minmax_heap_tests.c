#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/time.h>

#include "minmax_heap.c"

typedef struct {
	unsigned int		data;
	fr_minmax_heap_index_t	idx;		/* for the heap */
	bool			visited;
} minmax_heap_thing;

#if 0
static void fr_minmax_heap_validate(fr_minmax_heap_t *hp);
#endif

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

#define MINMAX_HEAP_TEST_SIZE (4096)

static void minmax_heap_test(int skip)
{
	fr_minmax_heap_t	*hp;
	int			i;
	minmax_heap_thing	*array;
	int			left;
	int			ret;

	static bool		done_init = false;

	if (!done_init) {
		srand((unsigned int)time(NULL));
		done_init = true;
	}

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(MINMAX_HEAP_TEST_SIZE, sizeof(minmax_heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) array[i].data = rand() % 65537;

#if 0
	for (i = 0; i < HEAP_TEST_SIZE; i++) {
		printf("Array %d has value %d at offset %d\n",
		       i, array[i].data, array[i].heap);
	}
#endif

	TEST_CASE("insertions");
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(minmax_heap_contains(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("deletions");
	{
		unsigned int entry;

		for (i = 0; i < MINMAX_HEAP_TEST_SIZE / skip; i++) {
			entry = i * skip;

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

		TEST_CHECK((t = fr_minmax_heap_min_peek(hp)) != NULL);
		TEST_MSG("expected %i elements remaining in the heap", left - i);

		TEST_CHECK(fr_minmax_heap_extract(hp, t) >= 0);
		TEST_MSG("failed extracting %i", i);
	}

	TEST_CHECK((ret = fr_minmax_heap_num_elements(hp)) == 0);
	TEST_MSG("%i elements remaining", ret);

	talloc_free(hp);
	free(array);
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

#if 0
#define MINMAX_HEAP_CYCLE_SIZE (1600000)

static void heap_test_order(void)
{
	fr_minmax_heap_t	*hp;
	int			i;
	minmax_heap_thing	*array;
	minmax_heap_thing	*thing, *prev = NULL;
	unsigned int		data = 0;
	unsigned int		count = 0;
	int			ret;

	static bool	done_init = false;

	if (!done_init) {
		srand((unsigned int)time(NULL));
		done_init = true;
	}

	hp = fr_minmax_heap_alloc(NULL, minmax_heap_cmp, minmax_heap_thing, idx, 0);
	TEST_CHECK(hp != NULL);

	array = calloc(MINMAX_HEAP_TEST_SIZE, sizeof(minmax_heap_thing));

	/*
	 *	Initialise random values
	 */
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) array[i].data = rand() % 65537;

	TEST_CASE("insertions");
	for (i = 0; i < MINMAX_HEAP_TEST_SIZE; i++) {
		TEST_CHECK((ret = fr_minmax_heap_insert(hp, &array[i])) >= 0);
		TEST_MSG("insert failed, returned %i - %s", ret, fr_strerror());

		TEST_CHECK(minmax_heap_contains(hp, &array[i]));
		TEST_MSG("element %i inserted but not in heap", i);
	}

	TEST_CASE("ordering");

	while ((thing = fr_minmax_heap_min_pop(hp))) {
		TEST_CHECK(thing->data >= data);
		TEST_MSG("Expected data >= %i, got %i", data, thing->data);
		if (thing->data >= data) data = thing->data;
		TEST_CHECK(thing != prev);
		prev = thing;
		count++;
	}

	TEST_CHECK(count == MINMAX_HEAP_TEST_SIZE);

	talloc_free(hp);
	free(array);
}
#endif

#if 0
static void fr_minmax_heap_validate(fr_minmax_heap_t *hp)
{
	minmax_heap_t	*h = *hp;

	/*
	 *	Basic sanity checks...
	 */
	for (unsigned int idx = 1; idx <= h->num_elements; idx++) {
		fr_minmax_heap_index_t	element_idx;

		if (!(h->p[idx]))  {
			TEST_MSG_ALWAYS("null pointer at index %u", idx);
		}

		element_idx = index_get(h, h->p[idx]);
		if (element_idx != idx) {
			TEST_MSG_ALWAYS("element at index %u has index %u", idx, element_idx);
		}
	}

	/*
	 * 	Minmax heap property
	 */
}
#endif

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "minmax_heap_test_basic",	minmax_heap_test_basic	},
	{ "minmax_heap_test_skip_0",	minmax_heap_test_skip_0 },
	{ "minmax_heap_test_skip_2",	minmax_heap_test_skip_2 },
	{ "minmax_heap_test_skip_10",	minmax_heap_test_skip_10 },
	{ NULL }
};

