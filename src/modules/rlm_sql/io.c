#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/rad_assert.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

/** SQL query timer expired
 *
 * @param[in] now	The current time according to the event loop.
 * @param[in] ctx	The rlm_sql_thread_t specific to this thread.
 */
static void _sql_io_timer_expired(UNUSED struct timeval *now, void *ctx)
{
	rlm_sql_fd_map_t *fd_map_elt = talloc_get_type_abort(ctx, rlm_sql_fd_map_t);
	rlm_sql_handle_t *handle;

	DEBUG4("sql timer expired");

	unlang_resumable(fd_map_elt->request);

	handle = fd_map_elt->handle;
	/*
	 * Set cancelled flag so that connection gets closed on resume
	 */
	handle->cancelled = true;
}


/** Service an IO event on a file descriptor
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	the IO event occurred for.
 * @param[in] t		Thread the event ocurred in.
 */
static inline void _sql_io_service(fr_event_list_t *el, int fd, rlm_sql_thread_t *t)
{
	rlm_sql_fd_map_t *fd_map = NULL;
	sql_rcode_t ret;

	fd_map = sql_lookup_fd_map(t, fd);

	if (fd_map && fd_map->request) {
		/*
		 * Resume request so that sql driver can read data
		 */
		unlang_resumable(fd_map->request);
	} else {
		/*
		 * remove file descriptor from event list as it's of no use anymore.
		 */
		fr_event_fd_delete(el, fd);
	}
}

/** File descriptor experienced an error
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that errored.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _sql_io_service_errored(fr_event_list_t *el, int fd, void *ctx)
{
	rlm_sql_thread_t *t = talloc_get_type_abort(ctx, rlm_sql_thread_t);

	DEBUG4("sql fd %i errored", fd);

	_sql_io_service(el, fd, t);
}

/** File descriptor became writable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became writable.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _sql_io_service_writable(fr_event_list_t *el, int fd, void *ctx)
{
	rlm_sql_thread_t *t = talloc_get_type_abort(ctx, rlm_sql_thread_t);

	DEBUG4("sql fd %i now writable", fd);

	_sql_io_service(el, fd, t);
}

/** File descriptor became readable
 *
 * @param[in] el	fd was registered with.
 * @param[in] fd	that became readable.
 * @param[in] ctx	The rlm_rest_thread_t specific to this thread.
 */
static void _sql_io_service_readable(fr_event_list_t *el, int fd, void *ctx)
{
	rlm_sql_thread_t *t = talloc_get_type_abort(ctx, rlm_sql_thread_t);

	DEBUG4("sql fd %i now readable", fd);

	_sql_io_service(el, fd, t);
}

int sql_set_io_event_handlers(rlm_sql_t const *inst, sql_io_t io, rlm_sql_thread_t *thread, int fd, rlm_sql_fd_map_t *fd_map_elt)
{
	struct timeval now, to_add, when;
	uint64_t timeout_ms = inst->config->query_timeout * 1000;

	switch(io) {
	case SQL_READ:
	case SQL_WRITE:
	case SQL_READ_WRITE:
		if (fr_event_fd_insert(thread->el, fd,
					  _sql_io_service_readable, _sql_io_service_writable, _sql_io_service_errored,
					  thread) < 0) {
			ERROR("Registration failed for read+error events on FD %i: %s",
				 fd, fr_strerror());
			return -1;
		}
		DEBUG4("Registration for read+error events on FD %i", fd);

		if (timeout_ms > 0) {
			gettimeofday(&now, NULL);
			fr_timeval_from_ms(&to_add, timeout_ms);
			fr_timeval_add(&when, &now, &to_add);

			fr_event_timer_insert(thread->el, _sql_io_timer_expired, fd_map_elt, &when, &fd_map_elt->ev);
			DEBUG4("registered timeout for query");
		}
		break;

	case SQL_REMOVE:
		if (fr_event_fd_delete(thread->el, fd) < 0) {
			ERROR("De-registration failed for FD %i %s", fd, fr_strerror());
			return -1;
		}
		DEBUG4("Unregistered events for FD %i", fd);

		/*
		 * Delete timer for current request
		 */
		fr_event_timer_delete(thread->el, &fd_map_elt->ev);
		break;

	default:
		rad_assert(0);
		return -1;
	}

	return 0;
}
