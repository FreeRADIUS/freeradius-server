#include <freeradius-devel/util/acutest.h>

fr_time_t	test_time;

/** Allow us to arbitrarily manipulate time
 *
 */
#define fr_time()	test_time

#include <state_test.c>

/** Test functions that read from dbuffs.
 *
 */
static void state_entry_create(void)
{

}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "state_entry_create",				state_entry_create },
	{ "state_entry_too_many" }

	{ NULL }
};
