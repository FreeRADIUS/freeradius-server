/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file lib/redis/pipeline.c
 * @brief Functions for pipelining commands.
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/trunk.h>

#include "pipeline.h"
#include "io.h"


/** Thread local state for a cluster
 *
 * MOVE ME TO NEW ASYNC CLUSTER CODE
 */
struct fr_redis_cluster_thread_s {
	fr_event_list_t			*el;
	fr_trunk_conf_t	const		*tconf;		//!< Configuration for all trunks in the cluster.
	char				*log_prefix;	//!< Common log prefix to use for all cluster related
							///< messages.
	bool				delay_start;	//!< Prevent connections from spawning immediately.
};

/** The thread local free list
 *
 * Any entries remaining in the list will be freed when the thread is joined
 */
static _Thread_local fr_dlist_head_t *command_set_free_list;

typedef enum {
	FR_REDIS_COMMAND_NORMAL = 0,			//!< A normal, non-transactional command.
	FR_REDIS_COMMAND_TRANSACTION_START,		//!< Start of a transaction block. Either WATCH or MULTI.
							///< if a transaction is started with WATCH, then multi
							///< is not marked up as a transaction start.
	FR_REDIS_COMMAND_TRANSACTION_END		//!< End of a transaction block. Either EXEC or DISCARD.
							///< If this command fails with
							///< MOVED or ASK, all commands back to the previous
							///< MULTI command must be requeued.
} fr_redis_command_type_t;

/** Represents a single command
 *
 */
struct fr_redis_command_s {
	fr_redis_command_set_t		*cmds;		//!< Command set this entry belongs to.
	fr_dlist_t			entry;		//!< Entry in the command buffer.

	fr_redis_command_type_t		type;		//!< Redis command type.

	char const			*str;		//!< The command string.
	size_t				len;		//!< Length of the command string.

	uint64_t			sqn;		//!< The sequence number of the command.  This is only
							///< valid for a specific handle, and is unique within
							///< the handle.

	redisReply			*result;	//!< The result from the REDIS server.
};

/** Represents a collection of pipelined commands
 *
 * Commands MUST map to the same cluster node if using clustering.
 */
struct fr_redis_command_set_s {
	fr_dlist_t			entry;

	/** @name Command state lists
	 * @{
 	 */
	fr_dlist_head_t			pending;	//!< Commands yet to be sent.
	fr_dlist_head_t			sent;		//!< Commands sent.
	fr_dlist_head_t			completed;	//!< Commands complete with replies.
	/** @} */

	uint8_t				redirected;	//!< How many times this command set was redirected.

	/** @name Request state
	 *
	 * treq and request are duplicated here with the trunk code.
	 * The reason for this, is because a fr_command_set_t, may need to be transferred
	 * between trunks when redirects are being followed, and so we need this information
	 * encapsulated within the command set, not just within the trunk.
	 * @{
 	 */
	fr_trunk_request_t		*treq;		//!< Trunk request this command set is associated with.
	REQUEST				*request;	//!< Request this commands set is associated with (if any).
	void				*rctx;		//!< Resume context to write results to.
	/** @} */

	/** @name Callback functions
	 * @{
 	 */
	fr_redis_command_set_complete_t complete;	//!< Notify the creator of the command set
							///< that the command set has executed to
							///< to completion.  We have results for
							///< all commands.

	fr_redis_command_set_fail_t	fail;		//!< Notify the creator of the command set
							///< that the command set failed to execute
							///< to completion.  Partial results will
							///< be available.
	/** @} */

	/** @name Command set transaction stats
	 *
	 * We do these checks as REDIS commands from a great number of requests may pipeline
	 * requests on the same connection and leaving a transaction open would be fairly
	 * catastrophic, potentially causing errors across all future command sets set to
	 * the connection.
	 * @{
 	 */
	bool				txn_watch;	//!< Transaction was started with a watch statement.
	uint16_t			txn_start;	//!< Number of times a transaction block was started
							///< in this command set.
	uint16_t			txn_end;	//!< The number of times a transaction block ended
							///< in this command set.

	/** @} */
};

struct fr_redis_trunk_s {
	fr_redis_io_conf_t const	*io_conf;	//!< Redis I/O configuration.  Specifies how to connect
							///< to the host this trunk is used to communicate with.
	fr_trunk_t			*trunk;		//!< Trunk containing all the connections to a specific
							///< host.
	fr_redis_cluster_thread_t	*cluster;	//!< Cluster this trunk belongs to.
};

/** Free any free requests when the thread is joined
 *
 */
static void _command_set_free_list_free_on_exit(void *arg)
{
	fr_dlist_head_t		*list = talloc_get_type_abort(arg, fr_dlist_head_t);
	fr_redis_command_set_t	*cmds;

	/*
	 *	See the destructor for why this works
	 */
	while ((cmds = fr_dlist_head(list))) talloc_free(cmds);
	talloc_free(list);
}

/** Free a command set
 *
 */
static int _redis_command_set_free(fr_redis_command_set_t *cmds)
{
	if (fr_dlist_num_elements(command_set_free_list) >= 1024) return 0;	/* Keep a buffer of 1024 */

	/*
	 *	Freed from the free list....
	 */
	if (unlikely(fr_dlist_entry_in_list(&cmds->entry))) {
		fr_dlist_entry_unlink(&cmds->entry);	/* Don't trust the list head to be available */
		return 0;
	}

	talloc_free_children(cmds);
	memset(&cmds, 0, sizeof(cmds));

	fr_dlist_insert_head(command_set_free_list, cmds);

	return -1;	/* Prevent the free */
}

/** Allocate a new command set
 *
 * This is a set of commands that the calling module wants to execute
 * on the redis server in sequence.
 *
 * Control will be returned to the caller via the registered complete
 * and fail functions.
 *
 * @param[in] ctx	to bind the command set's lifetime to.
 * @param[in] request	to pass to places that need it.
 * @param[in] complete	Function to call when all commands have been processed.
 * @param[in] fail	Function to call if the command set was not executed
 *			or was partially executed.
 * @param[in] rctx	Resume context to pass to complete and fail functions.
 * @return A new or refurbished command set.
 */
fr_redis_command_set_t *fr_redis_command_set_alloc(TALLOC_CTX *ctx,
						   REQUEST *request,
						   fr_redis_command_set_complete_t complete,
						   fr_redis_command_set_fail_t fail,
						   void *rctx)

{
	fr_redis_command_set_t	*cmds;
	fr_dlist_head_t		*free_list;

#define COMMAND_PRE_ALLOC_COUNT	8	//!< How much room we pre-allocate for commands.
#define COMMAND_PRE_ALLOC_LEN	64	//!< How much we allocate for each command string.

	/*
	 *	Initialise the free list
	 */
	if (unlikely(!command_set_free_list)) {
		MEM(free_list = talloc(NULL, fr_dlist_head_t));
		fr_dlist_init(free_list, fr_redis_command_set_t, entry);
		fr_thread_local_set_destructor(command_set_free_list, _command_set_free_list_free_on_exit, free_list);
	} else {
		free_list = command_set_free_list;
	}

	/*
	 *	Pull an element out of the free list
	 *	or allocate a new one.
	 */
	cmds = fr_dlist_head(free_list);
	if (!cmds) {
		MEM(cmds = talloc_zero_pooled_object(NULL, fr_redis_command_set_t,
						     COMMAND_PRE_ALLOC_COUNT,
						     COMMAND_PRE_ALLOC_COUNT * (sizeof(fr_redis_command_t) +
						     COMMAND_PRE_ALLOC_LEN)));
		talloc_set_destructor(cmds, _redis_command_set_free);
		fr_dlist_entry_init(&cmds->entry);
	} else {
		fr_dlist_remove(free_list, cmds);
	}

	fr_dlist_talloc_init(&cmds->pending, fr_redis_command_t, entry);
	fr_dlist_talloc_init(&cmds->sent, fr_redis_command_t, entry);
	fr_dlist_talloc_init(&cmds->completed, fr_redis_command_t, entry);
	cmds->request = request;
	cmds->complete = complete;
	cmds->fail = fail;
	cmds->rctx = rctx;

	if (ctx) talloc_link_ctx(ctx, cmds);

	return cmds;
}

/** Free any result associated with the command
 *
 * @param[in] cmd to free.  Frees any redis results associated with the command.
 */
static int _redis_command_free(fr_redis_command_t *cmd)
{
	//if (cmd->result) fr_redis_reply_free(&cmd->result);

	return 0;
}

redisReply *fr_redis_command_get_result(fr_redis_command_t *cmd)
{
	return cmd->result;
}

/** Add a preformatted/expanded command to the command set
 *
 * The command must either be entirely static, or parented by the command set.
 *
 * @note Caller should disallow "SUBSCRIBE" et al, if they're not appropriate.
 * 	 As subscribing to a stream where we're not expecting it would break
 * 	 things, badly.
 *
 * @param[in] cmds	Command set to add command to.
 * @param[in] cmd_str	A fully expanded/formatted command to send to redis.
 *			Must be static, or have the same lifetime as the
 *			command set (allocated with the command set as the parent).
 * @param[in] cmd_len	Length of the command.
 * @return
 *	- FR_REDIS_PIPELINE_BAD_CMDS if a bad command sequence is enqueued.
 *	- FR_REDIS_PIPELINE_OK if command was enqueued successfully.
 */
fr_redis_pipeline_status_t fr_redis_command_preformatted_add(fr_redis_command_set_t *cmds,
							     char const *cmd_str, size_t cmd_len)
{
	REQUEST			*request = cmds->request;
	fr_redis_command_t	*cmd;
	fr_redis_command_type_t	type = FR_REDIS_COMMAND_NORMAL;

	/*
	 *	Transaction sanity checks.
	 *
	 *	Because commands from many different requests share the same connection
	 *	we need to ensure that transaction blocks aren't left dangling and
	 *	that the commands are all in the right order.
	 *
	 *	We try very hard to do this without incurring a performance penalty
	 *      for non-transactional commands.
	 */
	switch (tolower(cmd_str[0])) {
	case 'm':
		if (tolower(cmd_str[1] != 'u')) break;
		if (strncasecmp(cmd_str, "multi", sizeof("multi") - 1) != 0) break;
		/*
		 *	There should only ever be a difference of
		 *	1 between txn starts and txn ends.
		 */
		if ((cmds->txn_end < cmds->txn_start) && ((cmds->txn_start - cmds->txn_end) > 1)) {
			ROPTIONAL(ERROR, REDEBUG, "Too many consecutive \"MULTI\" commands");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		/*
		 *	If we have a watch before the MULTI,
		 *	that's marked as the start of the transaction
		 *	block.
		 */
		type = cmds->txn_watch ? FR_REDIS_COMMAND_TRANSACTION_START : FR_REDIS_COMMAND_NORMAL;
		cmds->txn_start++;	/* Yes MULTI increments start, not WATCH */
		break;

	case 'e':
		if (tolower(cmd_str[1] != 'e')) break;
		if (strncasecmp(cmd_str, "exec", sizeof("exec") - 1) != 0) break;
		goto txn_end;

	/*
	 *	It's useful to allow discard as it allows command syntax checks
	 *	to be performed against the REDIS server without actually
	 *	executing the commands.
	 */
	case 'd':
		if (tolower(cmd_str[1] != 'i')) break;
		if (strncasecmp(cmd_str, "discard", sizeof("discard") - 1) != 0) break;
	txn_end:
		if (cmds->txn_start <= cmds->txn_end) {
			ROPTIONAL(ERROR, REDEBUG, "Transaction not started, missing \"MULTI\" command");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		type = FR_REDIS_COMMAND_TRANSACTION_END;
		cmds->txn_end++;
		break;

	case 'w':
		if (tolower(cmd_str[1] != 'a')) break;
		if (strncasecmp(cmd_str, "watch", sizeof("watch") - 1) != 0) break;
		if (cmds->txn_watch) {
			ROPTIONAL(ERROR, REDEBUG, "Too many consecutive \"WATCH\" commands");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		if (cmds->txn_start > cmds->txn_end) {
			ROPTIONAL(ERROR, REDEBUG, "\"WATCH\" can only be used before \"MULTI\"");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		/* FALL-THROUGH */

	default:
		break;
	}

	MEM(cmd = talloc_zero(cmds, fr_redis_command_t));
	talloc_set_destructor(cmd, _redis_command_free);
	cmd->cmds = cmds;
	cmd->type = type;
	cmd->str = cmd_str;
	cmd->len = cmd_len;
	fr_dlist_insert_tail(&cmds->pending, cmd);

	return FR_REDIS_PIPELINE_OK;
}

/** Enqueue a command set on a specific trunk
 *
 * The command set may be passed around several trunks before it is complete.
 * This is to allow it to follow MOVED and ASK responses.
 *
 * @param[in] rtrunk	to enqueue command set on.
 * @param[in] cmds	Command set to enqueue.
 * @return
 *	- FR_REDIS_PIPELINE_OK if commands were immediately enqueued or placed in the backlog.
 *	- FR_REDIS_PIPELINE_DST_UNAVAILABLE if the REDIS host is unreachable.
 *	- FR_REDIS_PIPELINE_FAIL any other general error.
 */
fr_redis_pipeline_status_t redis_command_set_enqueue(fr_redis_trunk_t *rtrunk, fr_redis_command_set_t *cmds)
{
	if (cmds->txn_start != cmds->txn_end) {
		ERROR("Refusing to enqueue - Unbalanced transaction start/stop commands");
		return FR_REDIS_PIPELINE_BAD_CMDS;
	}

	switch (fr_trunk_request_enqueue(&cmds->treq, rtrunk->trunk, cmds->request, cmds, cmds->rctx)) {
	case FR_TRUNK_ENQUEUE_OK:
	case FR_TRUNK_ENQUEUE_IN_BACKLOG:
		return FR_REDIS_PIPELINE_OK;

	case FR_TRUNK_ENQUEUE_DST_UNAVAILABLE:
		return FR_REDIS_PIPELINE_DST_UNAVAILABLE;

	default:
		return FR_REDIS_PIPELINE_FAIL;
	}
}

/** Callback for for receiving Redis replies
 *
 * This is called by hiredis for each response is receives.  privData is set to the
 * fr_command_set
 *
 * @note Called only from hiredis, not the trunk itself.
 *
 * @param[in] ac		The async context the command was enqueued on.
 * @param[in] vreply		redisReply containing the result of the command.
 * @param[in] privdata		fr_redis_command_t that was sent to the Redis server.
 *				The fr_redis_command_t contains a pointer to the
 *      			fr_redis_command_set_t which holds the treq which
 *				we use to signal that we have responses for all
 *				commands.
 */
static void _redis_pipeline_demux(struct redisAsyncContext *ac, void *vreply, void *privdata)
{
	fr_redis_command_t	*cmd;
	fr_redis_command_set_t	*cmds;
	fr_connection_t		*conn = talloc_get_type_abort(ac->ev.data, fr_connection_t);
	fr_redis_handle_t	*h = talloc_get_type_abort(conn->h, fr_redis_handle_t);
	redisReply		*reply = vreply;
	/*
	 *	First check if we should ignore the response
	 */
	if (!fr_redis_connection_process_response(h)) {
		DEBUG4("Ignoring response with SQN %"PRIu64, (h->rsp_sqn - 1));	/* Already incremented */
		fr_redis_reply_free((redisReply **)&reply);
		return;
	}

	/*
	 *	FIXME - Need to check TRYAGAIN, MOVED etc...
	 *	I guess we might want to wait for the end of
	 *	the command set to do that.
	 */
	cmd = talloc_get_type_abort(privdata, fr_redis_command_t);
	cmds = cmd->cmds;
	cmd->result = reply;

	fr_dlist_remove(&cmds->sent, cmd);
	fr_dlist_insert_tail(&cmds->completed, cmd);

	/*
	 *	Check is the command set is complete,
	 *	and if it is, tell the trunk the treq
	 *	is complete.
	 */
	if ((fr_dlist_num_elements(&cmds->pending) == 0) &&
	    (fr_dlist_num_elements(&cmds->sent) == 0)) fr_trunk_request_signal_complete(cmds->treq);
}

static fr_connection_t *_redis_pipeline_connection_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
							 fr_connection_conf_t const *conf,
							 char const *log_prefix, void *uctx)
{
	fr_redis_trunk_t *rtrunk = talloc_get_type_abort(uctx, fr_redis_trunk_t);

	return fr_redis_connection_alloc(tconn, el, conf, rtrunk->io_conf, log_prefix);
}

/** Enqueue one or more command sets onto a redis handle
 *
 * Because the trunk is in always writable mode, _redis_pipeline_mux
 * will be called any time fr_trunk_request_enqueue is called, so there'll only
 * ever be one command to dequeue.
 *
 * @param[in] tconn		Trunk connection holding the commands to enqueue.
 * @param[in] conn		Connection handle containing the fr_redis_handle_t.
 * @param[in] uctx		fr_redis_cluster_t.  Unused.
 */
static void _redis_pipeline_mux(fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	fr_trunk_request_t	*treq;
	fr_redis_command_set_t 	*cmds;
	fr_redis_command_t	*cmd;
	fr_redis_handle_t	*h = talloc_get_type_abort(conn->h, fr_redis_handle_t);
	REQUEST			*request;

	treq = fr_trunk_connection_pop_request(&request, (void *)&cmds, NULL, tconn);
	while ((cmd = fr_dlist_head(&cmds->pending))) {
		/*
		 *	If this fails it probably means the connection
		 *	is disconnecting, but if that's happening then
		 *	we shouldn't be enqueueing new requests?
		 */
		if (unlikely(redisAsyncCommand(h->ac, _redis_pipeline_demux, cmd, "%s", cmd->str) != REDIS_OK)) {
			ROPTIONAL(ERROR, REDEBUG, "Unexpected error queueing REDIS command");

			while ((cmd = fr_dlist_head(&cmds->sent))) {
				fr_redis_connection_ignore_response(h, cmd->sqn);
				fr_dlist_remove(&cmds->sent, cmd);
				fr_dlist_insert_tail(&cmds->pending, cmd);
			}
			fr_trunk_request_signal_fail(treq);
			return;
		}
		cmd->sqn = fr_redis_connection_sent_request(h);
		fr_dlist_remove(&cmds->pending, cmd);
		fr_dlist_insert_tail(&cmds->sent, cmd);
	}
	fr_trunk_request_signal_sent(treq);
}

/** Deal with cancellation of sent requests
 *
 * We can't actually signal redis to not process the request, so depending
 * on why the commands were cancelled, we either tell the handle to ignore
 * them, or move them back into the pending list.
 */
static void _redis_pipeline_command_set_cancel(fr_connection_t *conn, UNUSED fr_trunk_request_t *treq, void *preq,
					       fr_trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);
	fr_redis_handle_t	*h = conn->h;

	/*
	 *	How we cancel is very different depending
	 *	on _WHY_ we're cancelling.
	 */
	switch (reason) {
	/*
	 *	Cancel is only called for requests that
	 *	have been sent, and only when the connection
	 *	is about to be closed for some reason.
	 *
	 *	We don't need to tell the handle to ignore
	 *	the responses, we just need to get the
	 *	command set back into the correct state for
	 *	execution by another handle.
	 */
	case FR_TRUNK_CANCEL_REASON_MOVE:
		fr_dlist_move(&cmds->pending, &cmds->sent);
		return;

	/*
	 *	If the request was cancelled due to a signal
	 *	we'll have a response coming back for a
	 *	request, pctx and rctx that no longer exist.
	 *	Tell the handle to signal that the response
	 *	should be ignored when it's received.
	 *
	 *      Free will take care of cleaning up the
	 *	pending commands.
	 */
	case FR_TRUNK_CANCEL_REASON_SIGNAL:
	{
		fr_redis_command_t	*cmd;

		for (cmd = fr_dlist_head(&cmds->sent);
		     cmd;
		     cmd = fr_dlist_next(&cmds->sent, cmd)) {
			fr_redis_connection_ignore_response(h, cmd->sqn);
		}
	}

	case FR_TRUNK_CANCEL_REASON_NONE:
		fr_assert(0);
		return;
	}
}

/** Signal the API client that we got a complete set of responses to a command set
 *
 */
static void _redis_pipeline_command_set_complete(UNUSED REQUEST *request, void *preq,
						 UNUSED void *rctx, UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	if (cmds->complete) cmds->complete(cmds->request, &cmds->completed, cmds->rctx);
}

/** Signal the API client that we failed enqueuing the commands
 *
 */
static void _redis_pipeline_command_set_fail(UNUSED REQUEST *request, void *preq,
					     UNUSED void *rctx, UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	if (cmds->fail) cmds->fail(cmds->request, &cmds->completed, cmds->rctx);
}

/** Free the command set
 *
 */
static void _redis_pipeline_command_set_free(UNUSED REQUEST *request, void *preq,
					     UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	talloc_free(cmds);
}

/** Allocate a new trunk
 *
 * @param[in] cluster_thread	to allocate the trunk for.
 * @param[in] io_conf		Describing the connection to a single REDIS host.
 * @return
 *	- On success, a new fr_redis_trunk_t which can be used for pipelining commands.
 *	- NULL on failure.
 */
fr_redis_trunk_t *fr_redis_trunk_alloc(fr_redis_cluster_thread_t *cluster_thread, fr_redis_io_conf_t const *io_conf)
{
	fr_redis_trunk_t	*rtrunk;
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc	= _redis_pipeline_connection_alloc,
					.request_mux		= _redis_pipeline_mux,
					/* demux called directly by hiredis */
					.request_cancel		= _redis_pipeline_command_set_cancel,
					.request_complete	= _redis_pipeline_command_set_complete,
					.request_fail		= _redis_pipeline_command_set_fail,
					.request_free		= _redis_pipeline_command_set_free
				};

	MEM(rtrunk = talloc_zero(cluster_thread, fr_redis_trunk_t));
	rtrunk->io_conf = io_conf;
	rtrunk->trunk = fr_trunk_alloc(rtrunk, cluster_thread->el,
				       &io_funcs, cluster_thread->tconf, cluster_thread->log_prefix, rtrunk,
				       cluster_thread->delay_start);
	if (!rtrunk->trunk) {
		talloc_free(rtrunk);
		return NULL;
	}

	return rtrunk;
}

/** Allocate per-thread, per-cluster instance
 *
 * This structure represents all the connections for a given thread for a given cluster.
 * The structures holds the trunk connections to talk to each cluster member.
 *
 */
fr_redis_cluster_thread_t *fr_redis_cluster_thread_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, fr_trunk_conf_t const *tconf)
{
	fr_redis_cluster_thread_t *cluster_thread;
	fr_trunk_conf_t *our_tconf;

	MEM(cluster_thread = talloc_zero(ctx, fr_redis_cluster_thread_t));
	MEM(our_tconf = talloc_memdup(cluster_thread, tconf, sizeof(*tconf)));
	our_tconf->always_writable = true;

	cluster_thread->el = el;
	cluster_thread->tconf = our_tconf;

	return cluster_thread;
}


