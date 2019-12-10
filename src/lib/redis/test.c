/*
 *  cc  -g3 -Wall -DHAVE_DLFCN_H -I../../../src -include freeradius-devel/build.h -L../../../build/lib/local/.libs -ltalloc -lhiredis -lfreeradius-unlang -lfreeradius-util -lfreeradius-server -o test_redis test.c redis.c io.c crc16.c
 */
#include <freeradius-devel/util/acutest.h>
#include "base.h"
#include "io.h"

#define DEBUG_LVL_SET if (test_verbose_level__ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1

static void test_basic_connection(void)
{
	TALLOC_CTX		*ctx;
	fr_event_list_t		*el;
	fr_connection_t		*connection;
	int			events;

	DEBUG_LVL_SET;

	ctx = talloc_init("test_ctx");
	el = fr_event_list_alloc(ctx, NULL, NULL);

	DEBUG4("Spawning connection");
	connection = fr_redis_connection_alloc(ctx, el, &(fr_redis_io_conf_t){ .hostname = "127.0.0.1", .port = 30001 });
	fr_connection_signal_init(connection);

	do {
		events = fr_event_corral(el, fr_time(), true);
		fr_event_service(el);
	} while (events > 0);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "Basic - Connection", test_basic_connection},
	{ NULL }
};
