#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/time.h>

#include "minmax_heap.c"

typedef struct {
	unsigned int		data;
	fr_minmax_heap_index_t	idx;		/* for the heap */
	bool			visited;
} minmax_heap_thing;

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

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "minmax_heap_test_basic",	minmax_heap_test_basic	},
	{ NULL }
};

