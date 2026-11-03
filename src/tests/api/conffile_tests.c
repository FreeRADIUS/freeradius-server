/*
 * Tests for configuration file APIs.
 */

#include <sys/wait.h>

#include <freeradius-devel/radiusd.h>

#include "acutest_common_init.h"

#ifdef HAVE_PTHREAD_H
pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

static void test_section_dup_alloc_failure(void)
{
	CONF_SECTION *src;
	CONF_SECTION *dup;

	src = cf_section_alloc(NULL, "source", NULL);
	TEST_ASSERT(src != NULL);
	if (!src) return;

	/*
	 * cf_section_alloc() rejects a NULL primary section name.
	 * cf_section_dup() should propagate that allocation failure.
	 */
	dup = cf_section_dup(NULL, src, NULL, NULL, false);
	TEST_CHECK(dup == NULL);

	talloc_free(src);
}

TEST_LIST = {
	{ "section_dup_alloc_failure", test_section_dup_alloc_failure },
	TEST_TERMINATOR
};
