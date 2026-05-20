/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @copyright 2019 Network RADIUS SAS (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/trunk.h>

#include "pipeline.h"
#include "cluster_async.h"
#include "io.h"


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

	size_t				argc;		//!< Number of argv arguments.
	char const			**argv;		//!< Arguments for the redis command.
	size_t				*argv_len;	//!< Lengths of the arguments.

	uint64_t			sqn;		//!< The sequence number of the command.  This is only
							///< valid for a specific handle, and is unique within
							///< the handle.

	fr_redis_command_complete_t	complete;	//!< Callback to process result from this command.

	void				*rctx;		//!< To be passed to the callback.
};

/** Represents a collection of pipelined commands
 *
 * Commands MUST map to the same cluster node if using clustering.
 */
struct fr_redis_command_set_s {
	fr_dlist_t			entry;

	fr_redis_async_rcode_t		rcode;		//!< Code from last error returned.
	bool				autofree;	//!< Should the command set be freed when it is complete

	fr_ipaddr_t			next_node_addr;	//!< IP address of node from MOVED / ASK reply
	uint16_t			next_node_port; //!< Port of node from MOVED / ASK reply

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
	trunk_request_t			*treq;		//!< Trunk request this command set is associated with.
	request_t			*request;	//!< Request this commands set is associated with (if any).
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
	trunk_t				*trunk;		//!< Trunk containing all the connections to a specific
							///< host.
	fr_redis_cluster_thread_t	*rtcluster;	//!< Cluster this trunk belongs to.
};

/** Free any free requests when the thread is joined
 *
 */
static int _command_set_free_list_free_on_exit(void *arg)
{
	fr_dlist_head_t		*list = talloc_get_type_abort(arg, fr_dlist_head_t);
	fr_redis_command_set_t	*cmds;

	/*
	 *	See the destructor for why this works
	 */
	while ((cmds = fr_dlist_head(list))) if (talloc_free(cmds) < 0) return -1;
	return talloc_free(list);
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
	memset(cmds, 0, sizeof(*cmds));

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
 * @param[in] autofree	Should the command set be freed when completed.
 * @return A new or refurbished command set.
 */
fr_redis_command_set_t *fr_redis_command_set_alloc(TALLOC_CTX *ctx,
						   request_t *request,
						   fr_redis_command_set_complete_t complete,
						   fr_redis_command_set_fail_t fail,
						   void *rctx, bool autofree)

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
		fr_atexit_thread_local(command_set_free_list, _command_set_free_list_free_on_exit, free_list);
	} else {
		free_list = command_set_free_list;
	}

	/*
	 *	Pull an element out of the free list
	 *	or allocate a new one.
	 */
	cmds = fr_dlist_pop_head(free_list);
	if (!cmds) {
		MEM(cmds = talloc_zero_pooled_object(NULL, fr_redis_command_set_t,
						     COMMAND_PRE_ALLOC_COUNT,
						     COMMAND_PRE_ALLOC_COUNT * (sizeof(fr_redis_command_t) +
						     COMMAND_PRE_ALLOC_LEN)));
		talloc_set_destructor(cmds, _redis_command_set_free);
		fr_dlist_entry_init(&cmds->entry);
	}

	fr_dlist_talloc_init(&cmds->pending, fr_redis_command_t, entry);
	fr_dlist_talloc_init(&cmds->sent, fr_redis_command_t, entry);
	fr_dlist_talloc_init(&cmds->completed, fr_redis_command_t, entry);
	cmds->request = request;
	cmds->complete = complete;
	cmds->fail = fail;
	cmds->rctx = rctx;
	cmds->autofree = autofree;

	if (ctx) talloc_link_ctx(ctx, cmds);

	return cmds;
}

static fr_redis_pipeline_status_t redis_command_transaction_check(request_t *request, fr_redis_command_type_t *type,
								  fr_redis_command_set_t *cmds, char const *cmd)
{
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
	switch (tolower(cmd[0])) {
	case 'm':
		if (tolower(cmd[1]) != 'u') break;
		if (strncasecmp(cmd, "multi", sizeof("multi") - 1) != 0) break;
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
		*type = cmds->txn_watch ? FR_REDIS_COMMAND_TRANSACTION_START : FR_REDIS_COMMAND_NORMAL;
		cmds->txn_start++;	/* Yes MULTI increments start, not WATCH */
		break;

	case 'e':
		if (tolower(cmd[1]) != 'e') break;
		if (strncasecmp(cmd, "exec", sizeof("exec") - 1) != 0) break;
		goto txn_end;

	/*
	 *	It's useful to allow discard as it allows command syntax checks
	 *	to be performed against the REDIS server without actually
	 *	executing the commands.
	 */
	case 'd':
		if (tolower(cmd[1]) != 'i') break;
		if (strncasecmp(cmd, "discard", sizeof("discard") - 1) != 0) break;
	txn_end:
		if (cmds->txn_start <= cmds->txn_end) {
			ROPTIONAL(ERROR, REDEBUG, "Transaction not started, missing \"MULTI\" command");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		*type = FR_REDIS_COMMAND_TRANSACTION_END;
		cmds->txn_end++;
		break;

	case 'w':
		if (tolower(cmd[1]) != 'a') break;
		if (strncasecmp(cmd, "watch", sizeof("watch") - 1) != 0) break;
		if (cmds->txn_watch) {
			ROPTIONAL(ERROR, REDEBUG, "Too many consecutive \"WATCH\" commands");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		if (cmds->txn_start > cmds->txn_end) {
			ROPTIONAL(ERROR, REDEBUG, "\"WATCH\" can only be used before \"MULTI\"");
			return FR_REDIS_PIPELINE_BAD_CMDS;
		}
		FALL_THROUGH;

	default:
		break;
	}

	return FR_REDIS_PIPELINE_OK;
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
 * @return
 *	- FR_REDIS_PIPELINE_BAD_CMDS if a bad command sequence is enqueued.
 *	- FR_REDIS_PIPELINE_OK if command was enqueued successfully.
 */
fr_redis_pipeline_status_t fr_redis_command_preformatted_add(fr_redis_command_set_t *cmds, char const *cmd_str,
							     fr_redis_command_complete_t complete, void *rctx)
{
	request_t		*request = cmds->request;
	fr_redis_command_t	*cmd;
	fr_redis_command_type_t	type = FR_REDIS_COMMAND_NORMAL;

	if (redis_command_transaction_check(request, &type, cmds, cmd_str) != FR_REDIS_PIPELINE_OK) return FR_REDIS_PIPELINE_BAD_CMDS;

	MEM(cmd = talloc_zero(cmds, fr_redis_command_t));
	cmd->cmds = cmds;
	cmd->type = type;
	cmd->str = cmd_str;
	cmd->complete = complete;
	cmd->rctx = rctx;
	fr_dlist_insert_tail(&cmds->pending, cmd);

	return FR_REDIS_PIPELINE_OK;
}

/** Add a command with arguments to the command set
 *
 * The command and arguments must either be entirely static, or parented by the command set.
 *
 * @param[in] cmds	Command set to add command to.
 * @param[in] argc	Number of arguments.
 * @param[in] argv	Redis command arguments.
 * @param[in] argv_len	Length of the command arguments.
 * @return
 *	- FR_REDIS_PIPELINE_BAD_CMDS if a bad command sequence is enqueued.
 *	- FR_REDIS_PIPELINE_OK if command was enqueued successfully.
 */
fr_redis_pipeline_status_t fr_redis_command_argv_add(fr_redis_command_set_t *cmds, size_t argc,
						     char const **argv, size_t *argv_len,
						     fr_redis_command_complete_t complete, void *rctx)
{
	request_t		*request = cmds->request;
	fr_redis_command_t	*cmd;
	fr_redis_command_type_t	type = FR_REDIS_COMMAND_NORMAL;

	if (redis_command_transaction_check(request, &type, cmds, argv[0]) != FR_REDIS_PIPELINE_OK) return FR_REDIS_PIPELINE_BAD_CMDS;

	MEM(cmd = talloc_zero(cmds, fr_redis_command_t));
	cmd->cmds = cmds;
	cmd->type = type;
	cmd->argc = argc;
	cmd->argv = argv;
	cmd->argv_len = argv_len;
	cmd->complete = complete;
	cmd->rctx = rctx;
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

	switch (trunk_request_enqueue(&cmds->treq, rtrunk->trunk, cmds->request, cmds, cmds->rctx)) {
	case TRUNK_ENQUEUE_OK:
	case TRUNK_ENQUEUE_IN_BACKLOG:
		return FR_REDIS_PIPELINE_OK;

	case TRUNK_ENQUEUE_DST_UNAVAILABLE:
		return FR_REDIS_PIPELINE_DST_UNAVAILABLE;

	default:
		return FR_REDIS_PIPELINE_FAIL;
	}
}

/** Convert a MOVED / ASK reply into an address and port
 *
 */
static int redis_addr_from_redirect(fr_ipaddr_t *addr, uint16_t *port, redisReply *redirect)
{
	unsigned long	key;
	fr_sbuff_t	sbuff;

	if (!redirect || (redirect->type != REDIS_REPLY_ERROR)) return -1;

	fr_sbuff_init_in(&sbuff, redirect->str, redirect->len);

	if (!((fr_sbuff_adv_past_str_literal(&sbuff, REDIS_ERROR_MOVED_STR " ")) ||
	    (fr_sbuff_adv_past_str_literal(&sbuff, REDIS_ERROR_MOVED_STR " ")))) {
		fr_strerror_const("No '-MOVED' or '-ASK' log_prefix");
		return -1;
	}

	if (fr_sbuff_out(NULL, &key, &sbuff) < 0) {
		fr_strerror_const("Failed to parse key slot from MOVED / ASK reply");
		return -1;
	};
	if (key >= KEY_SLOTS) {
		fr_strerror_printf("Key %lu outside of redis slot range", key);
		return -1;
	}

	if (!fr_sbuff_next_if_char(&sbuff, ' ')) {
		fr_strerror_const("Missing key/host separator");
		return -1;
	}

	if (fr_inet_pton_port(addr, port, fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff),
			      AF_UNSPEC, true, true) < 0) {
		return -1;
	}
	fr_assert(addr->af);

	return 0;
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
	connection_t		*conn = talloc_get_type_abort(ac->ev.data, connection_t);
	fr_redis_handle_t	*h = talloc_get_type_abort(conn->h, fr_redis_handle_t);
	redisReply		*reply = vreply;
	/*
	 *	First check if we should ignore the response
	 */
	if (!fr_redis_connection_process_response(h)) {
		DEBUG4("Ignoring response with SQN %"PRIu64, (h->rsp_sqn - 1));	/* Already incremented */
		return;
	}

	cmd = talloc_get_type_abort(privdata, fr_redis_command_t);
	cmds = cmd->cmds;

	fr_dlist_remove(&cmds->sent, cmd);
	fr_dlist_insert_tail(&cmds->completed, cmd);

	/*
	 *	If the reply was an error, look for known types.
	 */
	if (reply->type == REDIS_REPLY_ERROR) {
		request_t	*request = cmds->request;

		fr_assert_msg(reply->str, "Error response contained no error string");

		if (strncmp(REDIS_ERROR_MOVED_STR, reply->str, sizeof(REDIS_ERROR_MOVED_STR) - 1) == 0) {
			ROPTIONAL(RWARN, WARN, "Server returned %s", reply->str);
			cmds->rcode = REDIS_ASYNC_RCODE_MOVE;
			goto redirect;
		} else if (strncmp(REDIS_ERROR_ASK_STR, reply->str, sizeof(REDIS_ERROR_ASK_STR) - 1) == 0) {
			ROPTIONAL(RWARN, WARN, "Server returned %s", reply->str);
			cmds->rcode = REDIS_ASYNC_RCODE_ASK;
		redirect:
			if (redis_addr_from_redirect(&cmds->next_node_addr, &cmds->next_node_port, reply) < 0) {
				cmds->rcode = REDIS_ASYNC_RCODE_ERROR;
			}
			cmds->redirected++;
		} else if (strncmp(REDIS_ERROR_TRY_AGAIN_STR, reply->str, sizeof(REDIS_ERROR_TRY_AGAIN_STR) - 1) == 0) {
			ROPTIONAL(RWARN, WARN, "Server returned %s", reply->str);
			cmds->rcode = REDIS_ASYNC_RCODE_TRY_AGAIN;
		} else if (strncmp(REDIS_ERROR_NO_SCRIPT_STR, reply->str, sizeof(REDIS_ERROR_NO_SCRIPT_STR) - 1) == 0) {
			ROPTIONAL(RWARN, WARN, "Server returned %s", reply->str);
			cmds->rcode = REDIS_ASYNC_RCODE_NO_SCRIPT;
		} else {
			fr_strerror_printf("Server error: %s", reply->str);
			cmds->rcode = REDIS_ASYNC_RCODE_ERROR;
		}

		/*
		 *	Mark remaining sent commands to be ignored and fail the treq
		 */
		fr_dlist_foreach(&cmds->sent, fr_redis_command_t, sent_cmd) {
			fr_redis_connection_ignore_response(h, sent_cmd->sqn);
		}
		trunk_request_signal_fail(cmds->treq);
		return;
	}

	if (cmd->complete) cmd->complete(cmds->request, cmd, reply, cmd->rctx);
	cmds->rcode = REDIS_ASYNC_RCODE_SUCCESS;

	/*
	 *	Check is the command set is complete,
	 *	and if it is, tell the trunk the treq
	 *	is complete.
	 */
	if ((fr_dlist_num_elements(&cmds->pending) == 0) &&
	    (fr_dlist_num_elements(&cmds->sent) == 0)) trunk_request_signal_complete(cmds->treq);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_t *_redis_pipeline_connection_alloc(trunk_connection_t *tconn, fr_event_list_t *el,
							 connection_conf_t const *conf,
							 char const *log_prefix, void *uctx)
{
	fr_redis_trunk_t *rtrunk = talloc_get_type_abort(uctx, fr_redis_trunk_t);

	return fr_redis_connection_alloc(tconn, el, conf, rtrunk->io_conf, log_prefix);
}

/** Enqueue one or more command sets onto a redis handle
 *
 * Because the trunk is in always writable mode, _redis_pipeline_mux
 * will be called any time trunk_request_enqueue is called, so there'll only
 * ever be one command to dequeue.
 *
 * @param[in] tconn		Trunk connection holding the commands to enqueue.
 * @param[in] conn		Connection handle containing the fr_redis_handle_t.
 * @param[in] uctx		fr_redis_cluster_t.  Unused.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void _redis_pipeline_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t		*treq;
	fr_redis_command_set_t 	*cmds;
	fr_redis_command_t	*cmd;
	fr_redis_handle_t	*h = talloc_get_type_abort(conn->h, fr_redis_handle_t);
	request_t		*request;
	int			ret;

	while (trunk_connection_pop_request(&treq, tconn) == 0) {
		cmds = talloc_get_type_abort(treq->preq, fr_redis_command_set_t);
		request = treq->request;
		while ((cmd = fr_dlist_head(&cmds->pending))) {
			/*
			 *	If this fails it probably means the connection
			 *	is disconnecting, but if that's happening then
			 *	we shouldn't be enqueueing new requests?
			 */
			if (cmd->argv) {
				ret = redisAsyncCommandArgv(h->ac, _redis_pipeline_demux, cmd, cmd->argc,
							    cmd->argv, cmd->argv_len);
			} else {
				ret = redisAsyncCommand(h->ac, _redis_pipeline_demux, cmd, cmd->str);
			}

			if (unlikely(ret != REDIS_OK)) {
				ROPTIONAL(ERROR, REDEBUG, "Unexpected error queueing REDIS command");

				while ((cmd = fr_dlist_head(&cmds->sent))) {
					fr_redis_connection_ignore_response(h, cmd->sqn);
					fr_dlist_remove(&cmds->sent, cmd);
					fr_dlist_insert_tail(&cmds->pending, cmd);
				}
				trunk_request_signal_fail(treq);
				return;
			}
			cmd->sqn = fr_redis_connection_sent_request(h);
			fr_dlist_remove(&cmds->pending, cmd);
			fr_dlist_insert_tail(&cmds->sent, cmd);
		}
		trunk_request_signal_sent(treq);
	}
}

/** Deal with cancellation of sent requests
 *
 * We can't actually signal redis to not process the request, so depending
 * on why the commands were cancelled, we either tell the handle to ignore
 * them, or move them back into the pending list.
 */
static void _redis_pipeline_command_set_cancel(connection_t *conn, void *preq,
					       trunk_cancel_reason_t reason, UNUSED void *uctx)
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
	case TRUNK_CANCEL_REASON_REQUEUE:
	case TRUNK_CANCEL_REASON_MOVE:
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
	case TRUNK_CANCEL_REASON_SIGNAL:
	{
		fr_redis_command_t	*cmd;

		for (cmd = fr_dlist_head(&cmds->sent);
		     cmd;
		     cmd = fr_dlist_next(&cmds->sent, cmd)) {
			fr_redis_connection_ignore_response(h, cmd->sqn);
		}
	}
		return;

	case TRUNK_CANCEL_REASON_NONE:
		fr_assert(0);
		return;
	}
}

/** Signal the API client that we got a complete set of responses to a command set
 *
 */
static void _redis_pipeline_command_set_complete(UNUSED request_t *request, void *preq,
						 UNUSED void *rctx, UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	if (cmds->complete) cmds->complete(cmds->request, &cmds->completed, cmds->rctx);
	if (cmds->request) unlang_interpret_mark_runnable(cmds->request);
}

/** Signal the API client that we failed enqueuing the commands
 *
 */
static void _redis_pipeline_command_set_fail(UNUSED request_t *request, void *preq, UNUSED void *rctx,
					     UNUSED trunk_request_state_t state,  UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	if (cmds->fail) cmds->fail(cmds->request, &cmds->completed, cmds->rctx);
	if (cmds->request) unlang_interpret_mark_runnable(cmds->request);
}

/** Free the command set
 *
 */
static void _redis_pipeline_command_set_free(UNUSED request_t *request, void *preq,
					     UNUSED void *uctx)
{
	fr_redis_command_set_t	*cmds = talloc_get_type_abort(preq, fr_redis_command_set_t);

	if (cmds->autofree) talloc_free(cmds);
}

/** Allocate a new trunk
 *
 * @param[in] rtcluster		to allocate the trunk for.
 * @param[in] io_conf		Describing the connection to a single REDIS host.
 * @param[in] trigger_args	Pairs to pass to trigger requests, if triggers are enabled.
 * @return
 *	- On success, a new fr_redis_trunk_t which can be used for pipelining commands.
 *	- NULL on failure.
 */
fr_redis_trunk_t *fr_redis_trunk_alloc(fr_redis_cluster_thread_t *rtcluster, fr_redis_io_conf_t const *io_conf,
				       fr_pair_list_t *trigger_args)
{
	fr_redis_trunk_t	*rtrunk;
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc	= _redis_pipeline_connection_alloc,
					.request_mux		= _redis_pipeline_mux,
					/* demux called directly by hiredis */
					.request_cancel		= _redis_pipeline_command_set_cancel,
					.request_complete	= _redis_pipeline_command_set_complete,
					.request_fail		= _redis_pipeline_command_set_fail,
					.request_free		= _redis_pipeline_command_set_free
				};

	MEM(rtrunk = talloc_zero(rtcluster, fr_redis_trunk_t));
	rtrunk->io_conf = io_conf;
	rtrunk->trunk = trunk_alloc(rtrunk, fr_redis_cluster_thread_el(rtcluster),
				    &io_funcs, fr_redis_cluster_thread_trunk_conf(rtcluster),
				    io_conf->log_prefix, rtrunk, false, trigger_args);
	if (!rtrunk->trunk) {
		talloc_free(rtrunk);
		return NULL;
	}

	return rtrunk;
}

char const *fr_redis_command_get_cmd(fr_redis_command_t *cmd)
{
	if (cmd->argv) return cmd->argv[0];
	return cmd->str;
}

/** Extract the rcode from a command set
 */
fr_redis_async_rcode_t fr_redis_command_set_rcode(fr_redis_command_set_t *cmds)
{
	return cmds->rcode;
}

/** Extract the next node address and port from a command set
 */
void fr_redis_command_set_next_node(fr_redis_command_set_t *cmds, fr_socket_t *addr)
{
	addr->inet.dst_ipaddr = cmds->next_node_addr;
	addr->inet.dst_port = cmds->next_node_port;
}

/** Reset a command set to it's state before enqueuing
 *
 * For use when handling MOVED / ASK where the command set needs to be sent
 * to another node.
 */
int fr_redis_command_set_reset(fr_redis_command_set_t *cmds)
{
	fr_redis_command_t	*cmd;

	/*
	 *	Move sent and completed commands back to the pending list
	 *	Popping from the tail of sent, then completed and inserting
	 *	into the head of pending ensures pending is back in the
	 *	original sequence.
	 */
	while ((cmd = fr_dlist_pop_tail(&cmds->sent))) {
		fr_dlist_insert_head(&cmds->pending, cmd);
	}
	while ((cmd = fr_dlist_pop_tail(&cmds->completed))) {
		fr_dlist_insert_head(&cmds->pending, cmd);
	}

	cmds->next_node_addr = (fr_ipaddr_t){};
	cmds->next_node_port = 0;
	cmds->treq = NULL;

	return 0;
}
