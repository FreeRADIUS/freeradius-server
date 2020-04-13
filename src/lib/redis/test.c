/*
 *  cc  -g3 -Wall -DHAVE_DLFCN_H -I../../../src -include freeradius-devel/build.h -L../../../build/lib/local/.libs -ltalloc -lhiredis -lfreeradius-unlang -lfreeradius-util -lfreeradius-server -o test_redis test.c redis.c io.c crc16.c
 */
#include <freeradius-devel/util/acutest.h>
#include "base.h"
#include "io.h"
#include "pipeline.h"

#define DEBUG_LVL_SET if (test_verbose_level__ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1


typedef struct {
	fr_time_t	start;
	uint64_t	enqueued;
} redis_pipeline_stats_t;

static void _command_complete(REQUEST *request, fr_dlist_head_t *completed, void *rctx)
{
	fr_time_t		io_stop;
	fr_time_delta_t		io_time;
	redis_pipeline_stats_t	*stats = rctx;
	fr_redis_command_t	*cmd = talloc_get_type_abort(fr_dlist_head(completed), fr_redis_command_t);
	redisReply		*reply = fr_redis_command_get_result(cmd);
	io_stop = fr_time();
	io_time = io_stop - stats->start;

	INFO("I/O time %pV (%u rps)",
	     fr_box_time_delta(io_time),
	     (uint32_t)(stats->enqueued / ((float)io_time / NSEC)));

	fr_assert(fr_dlist_num_elements(completed) == stats->enqueued);
}

static void _command_failed(REQUEST *request, fr_dlist_head_t *completed, void *rctx)
{
	TEST_CHECK(0);
}

static void test_basic_connection(void)
{
	TALLOC_CTX			*ctx;
	fr_event_list_t			*el;
	int				events;
	fr_redis_command_set_t		*cmds;
	fr_redis_cluster_thread_t	*cluster_thread;
	fr_redis_trunk_t		*rtrunk;
	fr_connection_conf_t		conn_conf;
	fr_trunk_conf_t			trunk_conf;
	size_t				i;
	redis_pipeline_stats_t		stats;

	DEBUG_LVL_SET;

	memset(&conn_conf, 0, sizeof(conn_conf));
	memset(&trunk_conf, 0, sizeof(trunk_conf));

	trunk_conf.conn_conf = &conn_conf;

	ctx = talloc_init("test_ctx");
	el = fr_event_list_alloc(ctx, NULL, NULL);

	cmds = fr_redis_command_set_alloc(ctx, NULL, _command_complete, _command_failed, &stats);
	/*
	 *	Enqueue 10 set commands
	 */
	for (i = 0; i < 1000000; i++) {
		TEST_CHECK(fr_redis_command_preformatted_add(cmds, "PING", sizeof("PING") - 1) == FR_REDIS_PIPELINE_OK);
	}

	cluster_thread = fr_redis_cluster_thread_alloc(ctx, el, &trunk_conf);
	rtrunk = fr_redis_trunk_alloc(cluster_thread,  &(fr_redis_io_conf_t){ .hostname = "127.0.0.1", .port = 30001 });

	stats.enqueued = 1000000;
	stats.start = fr_time();

	TEST_CHECK(redis_command_set_enqueue(rtrunk, cmds) == FR_REDIS_PIPELINE_OK);

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
