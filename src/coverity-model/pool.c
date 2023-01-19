#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/misc.h>

#include <time.h>

static fr_pool_connection_t *connection_spawn(fr_pool_t *pool, request_t *request, fr_time_t now, bool in_use, bool unlock)
{
	fr_pool_connection_t *result;
	
	if (result && !unlock)  __coverity_exclusive_lock_acquire__(pool->mutex);
	return result;
}

static fr_pool_connection_t *connection_find(fr_pool_t *pool, void *conn)
{
	fr_pool_connection_t *result;
	
	if (result)  __coverity_exclusive_lock_acquire__(pool->mutex); 
	return result;
}
