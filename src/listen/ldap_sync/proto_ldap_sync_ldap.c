/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * @file proto_ldap_sync_ldap.c
 * @brief LDAP sync handler.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "proto_ldap_sync_ldap"

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/ldap/conf.h>

#include "proto_ldap_sync_ldap.h"
#include "rfc4533.h"
#include "persistent_search.h"
#include "active_directory.h"

static fr_internal_encode_ctx_t	encode_ctx = { .allow_name_only = true };

extern fr_app_io_t proto_ldap_sync_ldap;
extern fr_app_io_t proto_ldap_sync_child;

static conf_parser_t const proto_ldap_sync_ldap_config[] = {
	/*
	 *	LDAP server definition
	 */
	{ FR_CONF_OFFSET_FLAGS("server", CONF_FLAG_REQUIRED, proto_ldap_sync_ldap_t, server) },

	/*
	 *	Common LDAP conf parsers
	 */
	FR_LDAP_COMMON_CONF(proto_ldap_sync_ldap_t),

	/*
	 *	Network tunable parameters
	 */
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_ldap_sync_ldap_t, recv_buff) },
	{ FR_CONF_OFFSET("max_outstanding", proto_ldap_sync_ldap_t, max_outstanding), .dflt = "65536" },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_ldap_sync;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_ldap_sync_ldap_dict[];
fr_dict_autoload_t proto_ldap_sync_ldap_dict[] = {
	{ .out = &dict_ldap_sync, .proto = "ldap" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_ldap_sync_packet_id;
static fr_dict_attr_t const *attr_ldap_sync_cookie;
static fr_dict_attr_t const *attr_ldap_sync_entry_dn;
static fr_dict_attr_t const *attr_ldap_sync_entry_uuid;
static fr_dict_attr_t const *attr_ldap_sync_orig_dn;
static fr_dict_attr_t const *attr_ldap_sync_root_dn;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_ldap_sync_base_dn;

extern fr_dict_attr_autoload_t proto_ldap_sync_ldap_dict_attr[];
fr_dict_attr_autoload_t proto_ldap_sync_ldap_dict_attr[] = {
	{ .out = &attr_ldap_sync_packet_id, .name = "Sync-Packet-ID", .type = FR_TYPE_UINT32, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_cookie, .name = "LDAP-Sync.Cookie", .type = FR_TYPE_OCTETS, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_entry_dn, .name = "LDAP-Sync.Entry-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_entry_uuid, .name = "LDAP-Sync.Entry-UUID", .type = FR_TYPE_OCTETS, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_orig_dn, .name = "LDAP-Sync.Original-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_root_dn, .name = "LDAP-Sync.Directory-Root-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_base_dn, .name = "LDAP-Sync-Base-DN", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

extern global_lib_autoinst_t const *proto_ldap_sync_ldap_lib[];
global_lib_autoinst_t const *proto_ldap_sync_ldap_lib[] = {
	&fr_libldap_global_config,
	GLOBAL_LIB_TERMINATOR
};

/** Operations performed on entries
 */
fr_table_num_sorted_t const sync_op_table[] = {
	{ L("add"),			SYNC_OP_ADD			},
	{ L("delete"),			SYNC_OP_DELETE			},
	{ L("modify"),			SYNC_OP_MODIFY			},
	{ L("present"),			SYNC_OP_PRESENT			},
};
size_t sync_op_table_len = NUM_ELEMENTS(sync_op_table);

/** Context used when looking up Directory types
 */
typedef struct {
	fr_listen_t		*main_listen;
	fr_listen_t		*child_listen;
	connection_t		*conn;
	int			msgid;
} proto_ldap_dir_ctx;

/** Context for "load Cookie" retry timed event
 */
typedef struct {
	proto_ldap_sync_ldap_thread_t	*thread;
	proto_ldap_sync_ldap_t const	*inst;
	size_t				sync_no;
} proto_ldap_cookie_load_retry_ctx;

/** Compare two sync state structures on msgid
 *
 * @param[in] one first sync to compare.
 * @param[in] two second sync to compare.
 * @return CMP(one, two)
 */
int8_t sync_state_cmp(void const *one, void const *two)
{
	sync_state_t const *a = one, *b = two;

	return CMP(a->msgid, b->msgid);
}

/** Tell the remote server to stop the sync
 *
 * Terminates the search informing the remote server that we no longer want to receive results
 * for this sync.  A RFC 4511 abandon request is used to inform the server.
 *
 * This allows individual syncs to be stopped without destroying the underlying connection.
 *
 * Removes the sync's msgid from the tree of msgids associated with the connection.
 *
 * @param[in] sync to abandon.
 * @return 0
 */
static int sync_state_free(sync_state_t *sync)
{
	fr_ldap_connection_t	*conn = talloc_get_type_abort(sync->conn, fr_ldap_connection_t);
	fr_rb_tree_t		*tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);

	DEBUG3("Abandoning sync base dn \"%s\", filter \"%s\"", sync->config->base_dn, sync->config->filter);

	trigger(unlang_interpret_get_thread_default(), sync->config->cs, NULL, "modules.ldap_sync.stop", true, &sync->trigger_args);

	if (!sync->conn->handle) return 0;	/* Handled already closed? */

	/*
	 *	Tell the remote server to stop sending results
	 */
	if (sync->msgid >= 0) ldap_abandon_ext(sync->conn->handle, sync->msgid, NULL, NULL);
	fr_rb_delete(tree, &(sync_state_t){.msgid = sync->msgid});

	return 0;
}

/** Allocate a sync state
 *
 * @param[in] ctx	to allocate the sync state in.
 * @param[in] conn	which the sync will run on.
 * @param[in] inst	module instance for the sync.
 * @param[in] sync_no	number of the sync in the array of configs.
 * @param[in] config	for the sync.
 * @return new sync state.
 */
sync_state_t *sync_state_alloc(TALLOC_CTX *ctx, fr_ldap_connection_t *conn, proto_ldap_sync_t const *inst,
			       size_t sync_no, sync_config_t const *config)
{
	sync_state_t		*sync;
	fr_pair_t		*vp;

	MEM(sync = talloc_zero(ctx, sync_state_t));
	sync->conn = conn;
	sync->inst = inst;
	sync->config = config;
	sync->sync_no = sync_no;
	sync->phase = SYNC_PHASE_INIT;

	fr_dlist_talloc_init(&sync->pending, sync_packet_ctx_t, entry);

	/*
	 *	Create arguments to pass to triggers
	 */
	fr_pair_list_init(&sync->trigger_args);
	fr_pair_list_append_by_da_len(sync, vp, &sync->trigger_args, attr_ldap_sync_base_dn, config->base_dn,
				      talloc_array_length(config->base_dn) - 1, false);

	/*
	 *	If the connection is freed, all the sync state is also freed
	 */
	talloc_set_destructor(sync, sync_state_free);

	return sync;
}

/** Add a new cookie packet ctx to the pending list
 *
 * Does not actually send the packet.
 *
 * @param[in] sync	the cookie was received for.
 * @param[in] refresh	the sync after storing this cookie.
 * @return
 *	- 0 on success.
 *	- -1 on failure
 */
int ldap_sync_cookie_store(sync_state_t *sync, bool refresh)
{
	sync_packet_ctx_t		*sync_packet_ctx = NULL;
	uint8_t				*cookie = sync->cookie;

	MEM(sync_packet_ctx = talloc_zero(sync, sync_packet_ctx_t));
	sync_packet_ctx->sync = sync;

	sync_packet_ctx->type = SYNC_PACKET_TYPE_COOKIE;
	if (cookie) sync_packet_ctx->cookie = talloc_memdup(sync_packet_ctx, cookie, talloc_array_length(cookie));
	sync_packet_ctx->refresh = refresh;

	if (fr_dlist_insert_tail(&sync->pending, sync_packet_ctx) < 0) {
		talloc_free(sync_packet_ctx);
		return -1;
	}
	sync->pending_cookies++;

	return 0;
}

/** Event to handle storing of cookies on a timed basis
 *
 * Looks at the head of the list of pending sync packets for a cookie.
 * A cookie at the head says that all the previous changes have been
 * completed, so the cookie can be sent.
 */
void ldap_sync_cookie_event(fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	sync_state_t		*sync = talloc_get_type_abort(uctx, sync_state_t);
	sync_packet_ctx_t	*sync_packet_ctx;

	if (sync->pending_cookies == 0) goto finish;

	/*
	 *	Check the head entry in the list - is it a pending cookie
	 */
	sync_packet_ctx = fr_dlist_head(&sync->pending);
	if ((sync_packet_ctx->type != SYNC_PACKET_TYPE_COOKIE) ||
	    (sync_packet_ctx->status != SYNC_PACKET_PENDING)) goto finish;

	ldap_sync_cookie_send(sync_packet_ctx);

finish:
	(void) fr_timer_in(sync, tl, &sync->cookie_ev, sync->inst->cookie_interval,
			   false, ldap_sync_cookie_event, sync);
}

/** Enqueue a new cookie store packet
 *
 * Create a new internal packet containing the cookie we received from the LDAP server.
 * This allows the administrator to store the cookie and provide it on a future call to
 * load Cookie.
 *
 * @param[in] sync_packet_ctx	packet context containing the cookie to store.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
*/
int ldap_sync_cookie_send(sync_packet_ctx_t *sync_packet_ctx)
{
	sync_state_t			*sync = sync_packet_ctx->sync;
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(sync->config->user_ctx, proto_ldap_sync_ldap_thread_t);
	fr_dbuff_t			*dbuff;
	fr_pair_list_t			pairs;
	fr_pair_t			*vp;
	TALLOC_CTX			*local = NULL;
	uint8_t				*cookie = sync_packet_ctx->cookie;

	if (sync_packet_ctx->status != SYNC_PACKET_PENDING) return 0;
	sync_packet_ctx->status = SYNC_PACKET_PREPARING;

	FR_DBUFF_TALLOC_THREAD_LOCAL(&dbuff, 1024, 4096);

	local = talloc_new(NULL);
	fr_pair_list_init(&pairs);
	if (fr_pair_list_copy(local, &pairs, &sync->config->sync_pairs) < 0) {
	error:
		talloc_free(local);
		return -1;
	}

	fr_pair_list_append_by_da(local, vp, &pairs, attr_packet_type, (uint32_t)FR_LDAP_SYNC_CODE_COOKIE_STORE, true);
	if (!vp) goto error;

	fr_pair_list_append_by_da(local, vp, &pairs, attr_ldap_sync_packet_id, (uint32_t)sync->sync_no, true);
	if (!vp) goto error;

	/*
	 *	Add the cookie to the packet, if set.
	 *	If the server has indicated a refresh is required it can do so
	 *	with no cookie set - so we store a blank cookie to clear anything
	 *	which was previously stored.
	 */
	if (cookie) {
		fr_pair_list_append_by_da_parent_len(local, vp, &pairs, attr_ldap_sync_cookie,
			    			     cookie, talloc_array_length(cookie), true);
		if (!vp) goto error;
	}

	if (fr_internal_encode_list(dbuff, &pairs, &encode_ctx) < 0) goto error;
	talloc_free(local);

	if (fr_network_listen_send_packet(thread->nr, thread->li, thread->li, fr_dbuff_buff(dbuff),
					  fr_dbuff_used(dbuff), fr_time(), sync_packet_ctx) < 0) {
		sync_packet_ctx->status = SYNC_PACKET_PENDING;
		return -1;
	}

	sync_packet_ctx->status = SYNC_PACKET_PROCESSING;

	return 0;
}

/** Send a change packet to the workers
 *
 * Called each time a change packet is received and also from a
 * timer event retrying packets which previously failed to send.
 *
 * @param sync_packet_ctx Packet to send
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int ldap_sync_entry_send_network(sync_packet_ctx_t *sync_packet_ctx)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(sync_packet_ctx->sync->config->user_ctx,
									proto_ldap_sync_ldap_thread_t);
	fr_dbuff_t			*dbuff;

	FR_DBUFF_TALLOC_THREAD_LOCAL(&dbuff, 1024, 4096);

	if (fr_internal_encode_list(dbuff, &sync_packet_ctx->pairs, &encode_ctx) < 0) return -1;
	if (fr_network_listen_send_packet(thread->nr, thread->li, thread->li, fr_dbuff_buff(dbuff),
					  fr_dbuff_used(dbuff), fr_time(), sync_packet_ctx) < 0) return -1;

	sync_packet_ctx->status = SYNC_PACKET_PROCESSING;
	fr_pair_list_free(&sync_packet_ctx->pairs);

	return 0;
}

/** Event to handle sending of any change packets which failed to send.
 *
 * Looks at the head of the list of pending sync packets for unsent
 * change packets and sends any up to the first cookie.
 */
static void ldap_sync_retry_event(fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	sync_state_t		*sync = talloc_get_type_abort(uctx, sync_state_t);
	sync_packet_ctx_t	*sync_packet_ctx = NULL;

	while ((sync_packet_ctx = fr_dlist_next(&sync->pending, sync_packet_ctx))) {
		if (sync_packet_ctx->type != SYNC_PACKET_TYPE_CHANGE) break;
		if (sync_packet_ctx->status != SYNC_PACKET_PENDING) continue;

		/*
		 *	Retry sending packet.  Don't try any more if it fails.
		 */
		if (ldap_sync_entry_send_network(sync_packet_ctx) < 0) break;
	}

	/*
	 *	We didn't run through the whole list, so there may be other pending
	 *	packets - reschedule a retry event.
	 */
	if (sync_packet_ctx) {
		(void) fr_timer_in(sync, tl, &sync->retry_ev, sync->inst->retry_interval,
				   false, ldap_sync_retry_event, sync);
	}
}

static fr_ldap_sync_packet_code_t const sync_packet_code_table[4] = {
	FR_LDAP_SYNC_CODE_PRESENT,
	FR_LDAP_SYNC_CODE_ADD,
	FR_LDAP_SYNC_CODE_MODIFY,
	FR_LDAP_SYNC_CODE_DELETE
};

/** Enqueue a new entry change packet.
 *
 * @param[in] sync	notification has arrived for.
 * @param[in] uuid	of the entry (RFC 4533 only).
 * @param[in] orig_dn	original DN of the entry - provided by those directories
 * 			implementing persistent search, when an entry is renamed.
 * @param[in] msg	containing the entry.
 * @param[in] op	The type of modification we need to perform to our
 *			representation of the entry.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int ldap_sync_entry_send(sync_state_t *sync, uint8_t const uuid[SYNC_UUID_LENGTH], struct berval *orig_dn,
			LDAPMessage *msg, sync_op_t op)
{
	fr_ldap_sync_packet_code_t	pcode;
	fr_pair_list_t			*pairs;
	fr_pair_t			*vp;
	sync_packet_ctx_t		*sync_packet_ctx = NULL;

	MEM(sync_packet_ctx = talloc_zero(sync, sync_packet_ctx_t));
	sync_packet_ctx->sync = sync;

	fr_pair_list_init(&sync_packet_ctx->pairs);
	pairs = &sync_packet_ctx->pairs;

	if (fr_pair_list_copy(sync_packet_ctx, pairs, &sync->config->sync_pairs) < 0) {
	error:
		if (msg) ldap_msgfree(msg);
		talloc_free(sync_packet_ctx);
		return -1;
	}

	pcode = sync_packet_code_table[op];

	fr_pair_list_append_by_da(sync_packet_ctx, vp, pairs, attr_packet_type, (uint32_t)pcode, false);
	if (!vp) goto error;

	fr_pair_list_append_by_da(sync_packet_ctx, vp, pairs, attr_ldap_sync_packet_id, (uint32_t)sync->sync_no, false);
	if (!vp) goto error;

	/*
	 *	Add the UUID if provided
	 */
	if (uuid) {
		fr_pair_list_append_by_da_parent_len(sync_packet_ctx, vp, pairs, attr_ldap_sync_entry_uuid,
						     uuid, SYNC_UUID_LENGTH, true);
		if (!vp) goto error;
	}

	/*
	 *	Add the original DN if provided
	 */
	if (orig_dn && (orig_dn->bv_len > 0)) {
		fr_pair_list_append_by_da_parent_len(sync_packet_ctx, vp, pairs, attr_ldap_sync_orig_dn,
						     orig_dn->bv_val, orig_dn->bv_len, true);
		if (!vp) goto error;
	}

	/*
	 *	Add the entry DN if there is an LDAP message to read
	 */
	if (msg) {
		char			*entry_dn = ldap_get_dn(sync->conn->handle, msg);
		map_t const		*map = NULL;
		struct berval 		**values;
		int			count, i;

		fr_pair_list_append_by_da_parent_len(sync_packet_ctx, vp, pairs, attr_ldap_sync_entry_dn,
						     entry_dn, strlen(entry_dn), true);
		if (!vp) goto error;

		ldap_memfree(entry_dn);

		/*
		 *  Map LDAP returned attributes to pairs as per update map
		 */
		while ((map = map_list_next(&sync->config->entry_map, map))) {
			values = ldap_get_values_len(fr_ldap_handle_thread_local(), msg, map->rhs->name);
			if (!values) goto next;

			count = ldap_count_values_len(values);

			for (i = 0; i < count; i++) {
				if (values[i]->bv_len == 0) continue;

				if (pair_append_by_tmpl_parent(sync_packet_ctx, &vp, pairs, map->lhs, true) < 0) break;
				if (fr_value_box_from_str(vp, &vp->data, vp->vp_type, NULL, values[i]->bv_val,
							  values[i]->bv_len, NULL) < 0) {
					fr_pair_remove(pairs, vp);
					talloc_free(vp);
				}

				/*  Only += operator adds multiple values */
				if (map->op != T_OP_ADD_EQ) break;
			}
		next:
			ldap_value_free_len(values);
		}
	}

	if (fr_dlist_insert_tail(&sync->pending, sync_packet_ctx) < 0) goto error;

	ldap_msgfree(msg);

	/*
	 *	Send the packet and if it fails to send add a retry event
	 */
	if ((ldap_sync_entry_send_network(sync_packet_ctx) < 0) &&
	    (fr_timer_in(sync, sync->conn->conn->el->tl, &sync->retry_ev,
			 sync->inst->retry_interval, false, ldap_sync_retry_event, sync) < 0)) {
		PERROR("Inserting LDAP sync retry timer failed");
	}

	return 0;
}

static void _proto_ldap_socket_init(connection_t *conn, UNUSED connection_state_t prev,
				    UNUSED connection_state_t state, void *uctx);

static void _proto_ldap_socket_open_connected(connection_t *conn, UNUSED connection_state_t prev,
					      UNUSED connection_state_t state, void *uctx);

/** Attempt to (re)initialise a connection
 *
 * Performs complete re-initialization of a connection.  Called during socket_open
 * to create the initial connection and again any time we need to reopen the connection.
 *
 * @param[in] tl	the event list managing listen event.
 * @param[in] now	current time.
 * @param[in] user_ctx	Listener.
 */
static void proto_ldap_connection_init(fr_timer_list_t *tl, UNUSED fr_time_t now, void *user_ctx)
{
	fr_listen_t			*listen = talloc_get_type_abort(user_ctx, fr_listen_t);
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(listen->thread_instance, proto_ldap_sync_ldap_thread_t);
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(thread->inst, proto_ldap_sync_ldap_t);

	if (thread->conn) talloc_free(thread->conn);

	/*
	 *	Allocate an outbound LDAP connection
	 */
	thread->conn = fr_ldap_connection_state_alloc(thread, thread->el, &inst->handle_config, "ldap_sync");

	if (!thread->conn) {
		PERROR("Failed (re)initialising connection, will retry in %pV seconds",
		       fr_box_time_delta(inst->handle_config.reconnection_delay));

		if (fr_timer_in(thread, tl, &thread->conn_retry_ev,
				inst->handle_config.reconnection_delay,
				false, proto_ldap_connection_init, listen) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}
	}

	/*
	 *	Add watch functions on the LDAP connection
	 */
	connection_add_watch_post(thread->conn, CONNECTION_STATE_INIT,
				     _proto_ldap_socket_init, true, thread);

	connection_add_watch_post(thread->conn, CONNECTION_STATE_CONNECTED,
				     _proto_ldap_socket_open_connected, true, thread);

	/*
	 *	Signal the connection to start
	 */
	connection_signal_init(thread->conn);

	return;
}

/** Child listener mod_close
 *
 * Ensures the LDAP connection is signalled to close gracefully when
 * the listener is closed.
 */
static int proto_ldap_child_mod_close(fr_listen_t *li)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_ldap_sync_ldap_thread_t);

	connection_signal_shutdown(thread->conn);
	return 0;
}

/** LDAP sync mod_read for child listener
 *
 * Called when there is data to read on the LDAP connection
 *
 * Actual packets are created by the various callbacks since a single LDAP
 * message can result in multiple packets to process e.g.:
 *
 *   - Sync Info Message with syncInfoValue of syncIdSet can reference
 *     multiple directory entries.
 *   - Various sync related messages can include a new cookie in
 *     addition to their other data.
 */
static ssize_t proto_ldap_child_mod_read(fr_listen_t *li, UNUSED void **packet_ctx, UNUSED fr_time_t *recv_time_p, UNUSED uint8_t *buffer,
					 UNUSED size_t buffer_len, UNUSED size_t *leftover)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_ldap_sync_ldap_thread_t);
	fr_ldap_connection_t		*conn = talloc_get_type_abort(thread->conn->h, fr_ldap_connection_t);
	struct	timeval			poll = { 1, 0 };
	LDAPMessage			*msg = NULL;
	int				ret = 0;
	fr_ldap_rcode_t			rcode;
	sync_state_t			*sync = NULL;
	fr_rb_tree_t			*tree;
	int				type, msgid;
	LDAPControl			**ctrls = NULL;
	sync_msg_t			callback = NULL;

	fr_assert(conn);

	/*
	 *	If there are already too many outstanding requests just return.
	 *	This will (potentially) cause the TCP buffer to fill and push the
	 *	backpressure back to the LDAP server.
	 */
	if (fr_network_listen_outstanding(thread->nr, li) >= thread->inst->max_outstanding) return 0;

	tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);

	/*
	 *	Pull the next outstanding message from this connection.
	 *	We process one message at a time so that the message can be
	 *	passed to the worker, and freed once the request has been
	 *	handled.
	 */
	ret = ldap_result(conn->handle, LDAP_RES_ANY, LDAP_MSG_ONE, &poll, &msg);

	switch (ret) {
	case 0:	/*
		 *	Timeout - this has been observed if changes are being
		 *	processed slowly, the TCP receive buffer fills and
		 *	the LDAP directory pauses sending data for a period.
		 *	Then all pending changes are processed and the receive buffer
		 *	is emptied.
		 *	The situation resolves when the directory starts sending
		 *	data again.
		 */
		return 0;

	case -1:
		rcode = fr_ldap_error_check(NULL, conn, NULL, NULL);
		if (rcode == LDAP_PROC_BAD_CONN) return -2;
		return -1;

	default:
		break;
	}

	/*
	 *	De-multiplex based on msgid
	 */
	if (!msg) return 0;

	msgid = ldap_msgid(msg);
	type = ldap_msgtype(msg);

	ret = 0;
	if (msgid == 0) {
		WARN("Ignoring unsolicited %s message",
		     fr_table_str_by_value(sync_ldap_msg_table, type, "<invalid>"));
	free_msg:
		if (ctrls) ldap_controls_free(ctrls);
		ldap_msgfree(msg);
		return ret;
	}

	sync = fr_rb_find(tree, &(sync_state_t){.msgid = msgid});
	if (!sync) {
		WARN("Ignoring msgid %i, doesn't match any outstanding syncs", msgid);
		goto free_msg;
	}

	/*
	 *	Check for errors contained within the message.
	 *	This has to be per message, as multiple syncs
	 *	are multiplexed together on one connection.
	 */
	switch (fr_ldap_error_check(&ctrls, conn, msg, sync->config->base_dn)) {
	case LDAP_PROC_SUCCESS:
		break;

	/*
	 *	The e-syncRefresRequired result code is the server informing us that
	 *	the query needs to be restarted	for a new refresh phase to run.
	 *	It is sent as the result code for a SearchResultsDone message.
	 */
	case LDAP_PROC_REFRESH_REQUIRED:
		if (type != LDAP_RES_SEARCH_RESULT) {
			PERROR("e-syncRefreshRequired result code received on wrong message type");
			ret = -1;
			goto free_msg;
		}

		DEBUG2("LDAP Server returned e-syncRefreshRequired");
		if (sync->config->refresh) {
			return sync->config->refresh(sync, msg, ctrls);
		}
		goto free_msg;

	/*
	 *	Don't think this should happen... but libldap
	 *	is wonky sometimes...
	 */
	case LDAP_PROC_BAD_CONN:
		PERROR("Connection unusable");
		ret = -2;
		goto free_msg;

	default:
		PERROR("Sync error");
		ret = -1;
		goto free_msg;
	}

	DEBUG3("Got %s message for sync (msgid %i)",
	       fr_table_str_by_value(sync_ldap_msg_table, type, "<invalid>"), sync->msgid);

	switch (type) {
	case LDAP_RES_SEARCH_REFERENCE:
	case LDAP_RES_SEARCH_ENTRY:
		callback = sync->config->entry;
		break;

	case LDAP_RES_INTERMEDIATE:
		callback = sync->config->intermediate;
		break;

	default:
		WARN("Ignoring unexpected message type (%i)", type);
		ret = 0;
		goto free_msg;
	}

	if (callback) {
		ret = callback(sync, msg, ctrls);
		if (ret < 0) PERROR("Sync callback error");
	} else {
	/*
	 *	Callbacks are responsible for freeing the msg
	 *	so if there is no callback, free it.
	 */
		ldap_msgfree(msg);
	}

	ldap_controls_free(ctrls);

	return ret;
}

/** Send a fake packet to run the "load Cookie" section
 *
 * @param ctx		Context to allocate temporary pairs in.
 * @param inst		LDAP sync configuration.
 * @param sync_no	Id of the sync whose.
 * @param thread	Thread specific LDAP sync data.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int proto_ldap_cookie_load_send(TALLOC_CTX *ctx, proto_ldap_sync_ldap_t const *inst, size_t sync_no,
				       proto_ldap_sync_ldap_thread_t *thread) {
	size_t			j, len;
	sync_config_t		*config = inst->parent->sync_config[sync_no];
	fr_pair_list_t		pairs;
	fr_pair_t		*vp;
	fr_dbuff_t		*dbuff;
	fr_ldap_connection_t	*ldap_conn = thread->conn->h;

	fr_pair_list_init(&pairs);
	if (unlikely(fr_pair_list_copy(ctx, &pairs, &config->sync_pairs) < 0)) return -1;

	/*
	 *	Ensure we have access to the thread instance
	 *	in for the demux callbacks
	 */
	inst->parent->sync_config[sync_no]->user_ctx = thread;

	/*
	 *	Assess the namingContext which applies to this sync
	 */
	for (j = 0; j < talloc_array_length(ldap_conn->directory->naming_contexts); j++) {
		len = strlen(ldap_conn->directory->naming_contexts[j]);
		if (strlen(config->base_dn) < len) continue;

		if (strncasecmp(&config->base_dn[strlen(config->base_dn)-len],
				ldap_conn->directory->naming_contexts[j],
				strlen(ldap_conn->directory->naming_contexts[j])) == 0) {
			config->root_dn = ldap_conn->directory->naming_contexts[j];
			break;
		}
	}

	/*
	 *	Set up callbacks based on directory type.
	 */
	switch (ldap_conn->directory->sync_type) {
	case FR_LDAP_SYNC_RFC4533:
		config->init = rfc4533_sync_init;
		config->entry = rfc4533_sync_search_entry;
		config->intermediate = rfc4533_sync_intermediate;
		config->refresh = rfc4533_sync_refresh_required;
		break;

	case FR_LDAP_SYNC_PERSISTENT_SEARCH:
		config->init = persistent_sync_state_init;
		config->entry = persistent_sync_search_entry;
		break;

	case FR_LDAP_SYNC_ACTIVE_DIRECTORY:
		config->init = active_directory_sync_state_init;
		config->entry = active_directory_sync_search_entry;
		break;

	default:
		fr_assert(0);
	}

	fr_pair_list_append_by_da(ctx, vp, &pairs, attr_packet_type,
				  (uint32_t)FR_LDAP_SYNC_CODE_COOKIE_LOAD, false);
	if (!vp) return -1;
	fr_pair_list_append_by_da(ctx, vp, &pairs, attr_ldap_sync_packet_id, (uint32_t)sync_no, false);
	if (!vp) return -1;

	if (config->root_dn) {
		fr_pair_list_append_by_da_parent_len(ctx, vp, &pairs, attr_ldap_sync_root_dn,
						     config->root_dn, strlen(config->root_dn), false);
		if (!vp) return -1;
	}

	FR_DBUFF_TALLOC_THREAD_LOCAL(&dbuff, 1024, 4096);

	if (fr_internal_encode_list(dbuff, &pairs, &encode_ctx) < 0) return -1;

	if (fr_network_listen_send_packet(thread->nr, thread->li, thread->li,
					  fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff),
					  fr_time(), NULL) < 0) return -1;
	fr_pair_list_free(&pairs);
	return 0;
}

/** Timer event to retry running "load Cookie" on failures
 *
 */
static void proto_ldap_cookie_load_retry(fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	proto_ldap_cookie_load_retry_ctx  *retry_ctx = talloc_get_type_abort(uctx, proto_ldap_cookie_load_retry_ctx);

	DEBUG2("Retrying \"load Cookie\" for sync no %ld", retry_ctx->sync_no);
	if (proto_ldap_cookie_load_send(retry_ctx, retry_ctx->inst, retry_ctx->sync_no,
					retry_ctx->thread) < 0) {
		ERROR("Failed retrying \"load Cookie\".  Will try again in %pV seconds",
		      fr_box_time_delta(retry_ctx->inst->handle_config.reconnection_delay));
		(void) fr_timer_in(retry_ctx->thread->conn->h, tl,
				   &retry_ctx->inst->parent->sync_config[retry_ctx->sync_no]->ev,
				   retry_ctx->inst->handle_config.reconnection_delay,
				   false, proto_ldap_cookie_load_retry, retry_ctx);
		return;
	}
	talloc_free(retry_ctx);
}

/** LDAP sync mod_write for child listener
 *
 * Handle any returned data after the worker has processed the packet and,
 * for packets where tracking structures were used, ensure they are freed.
 */
static ssize_t proto_ldap_child_mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
					  uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_ldap_sync_ldap_thread_t);
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(thread->inst, proto_ldap_sync_ldap_t);
	fr_dbuff_t			dbuff;
	fr_ldap_sync_packet_code_t	pcode;
	uint32_t			packet_id;
	fr_pair_list_t			tmp;
	fr_pair_t			*vp = NULL;
	ssize_t				ret;
	TALLOC_CTX			*local;
	sync_packet_ctx_t		*sync_packet_ctx = NULL;

	local = talloc_new(NULL);
	fr_dbuff_init(&dbuff, buffer, buffer_len);

	if (packet_ctx) sync_packet_ctx = talloc_get_type_abort(packet_ctx, sync_packet_ctx_t);

	/*
	 *	Extract returned attributes into a temporary list
	 */
	fr_pair_list_init(&tmp);

	ret = fr_internal_decode_list_dbuff(local, &tmp, fr_dict_root(dict_ldap_sync), &dbuff, NULL);
	if (ret < 0) goto finish;

	/*
	 *	There should always be a packet ID and code
	 */
	vp = fr_pair_find_by_da(&tmp, NULL, attr_ldap_sync_packet_id);
	fr_assert(vp);
	packet_id = vp->vp_uint32;

	vp = fr_pair_find_by_da(&tmp, NULL, attr_packet_type);
	fr_assert(vp);
	pcode = vp->vp_uint32;

	switch (pcode) {
	case FR_LDAP_SYNC_CODE_COOKIE_LOAD_RESPONSE:
	{
		uint8_t	*cookie = NULL;

		/*
		 *	If the received packet ID is greater than the number of syncs
		 *	we have then something very bad has happened
		 */
		fr_assert (packet_id <= talloc_array_length(inst->parent->sync_config));

		/*
		 *	Look for the returned cookie.
		 */
		vp = fr_pair_find_by_da_nested(&tmp, NULL, attr_ldap_sync_cookie);
		if (vp) cookie = talloc_memdup(inst, vp->vp_octets, vp->vp_length);

		if (inst->parent->sync_config[packet_id]->init(thread->conn->h, packet_id, inst->parent, cookie) < 0) {
			ret = -1;
			goto finish;
		}
	}
		break;

	case FR_LDAP_SYNC_CODE_ENTRY_RESPONSE:
		break;

	case FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE:
	{
		sync_config_t const	*sync_config;

		if (!sync_packet_ctx || !sync_packet_ctx->refresh) break;

		/*
		 *	Abandon the old sync and start a new one with the relevant cookie.
		 */
		sync_config = sync_packet_ctx->sync->config;
		DEBUG3("Restarting sync with base %s", sync_config->base_dn);
		talloc_free(sync_packet_ctx->sync);
		if (inst->parent->sync_config[packet_id]->init(thread->conn->h, packet_id, inst->parent,
								  sync_packet_ctx->cookie) < 0) {
			ret = -1;
			goto finish;
		}
	}
		break;

	case FR_LDAP_SYNC_CODE_COOKIE_LOAD_FAIL:
	{
		proto_ldap_cookie_load_retry_ctx *retry_ctx;

		ERROR("Load Cookie failed for sync %d, retrying in %pV seconds", packet_id,
		      fr_box_time_delta(inst->handle_config.reconnection_delay));

		MEM(retry_ctx = talloc(thread, proto_ldap_cookie_load_retry_ctx));
		*retry_ctx = (proto_ldap_cookie_load_retry_ctx){
			.thread = thread,
			.inst = inst,
			.sync_no = packet_id,
		};

		(void) fr_timer_in(thread->conn->h, thread->el->tl, &inst->parent->sync_config[packet_id]->ev,
				   inst->handle_config.reconnection_delay,
				   false, proto_ldap_cookie_load_retry, retry_ctx);
	}
		break;

	default:
		ERROR("Invalid packet type returned %d", pcode);
		break;
	}

	if (sync_packet_ctx) {
		sync_state_t		*sync = sync_packet_ctx->sync;
		sync_packet_ctx_t	*pc;
		proto_ldap_sync_t	*ldap_sync = inst->parent;

		sync_packet_ctx->status = SYNC_PACKET_COMPLETE;

		/*
		 *	A cookie has been stored, reset the counter of changes
		 */
		if (sync_packet_ctx->type == SYNC_PACKET_TYPE_COOKIE) sync->changes_since_cookie = 0;

		/*
		 *	Pop any processed updates from the head of the list
		 */
		while ((pc = fr_dlist_head(&sync->pending))) {
			/*
			 *	If the head entry in the list is a pending cookie but we have
			 *	not processed enough entries and there are more pending
			 *	cookies, mark this one as processed.
			 */
			if ((pc->type == SYNC_PACKET_TYPE_COOKIE) && (pc->status == SYNC_PACKET_PENDING) &&
			    (sync->changes_since_cookie < ldap_sync->cookie_changes) &&
			     (sync->pending_cookies > 1)) pc->status = SYNC_PACKET_COMPLETE;

			if (pc->status != SYNC_PACKET_COMPLETE) break;

			/*
			 *	Update counters depending on entry type
			 */
			if (pc->type == SYNC_PACKET_TYPE_COOKIE) {
				sync->pending_cookies--;
			} else {
				sync->changes_since_cookie++;
			}
			pc = fr_dlist_pop_head(&sync->pending);
			talloc_free(pc);
		}

		/*
		 *	If the head of the list is a cookie which has not yet
		 *	been processed and sufficient changes have been recorded
		 *	send the cookie.
		 */
		if (pc && (pc->type == SYNC_PACKET_TYPE_COOKIE) && (pc->status == SYNC_PACKET_PENDING) &&
		    (sync->changes_since_cookie >= ldap_sync->cookie_changes)) ldap_sync_cookie_send(pc);
	}

finish:
	fr_pair_list_free(&tmp);
	talloc_free(local);

	return ret;
}

/** Callback for socket errors when running initial root query
 */
static void _proto_ldap_socket_open_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags,
					  UNUSED int fd_errno, void *uctx)
{
	proto_ldap_dir_ctx	*dir_ctx = talloc_get_type_abort(uctx, proto_ldap_dir_ctx);
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(dir_ctx->conn->h, fr_ldap_connection_t);

	talloc_free(dir_ctx);
	fr_ldap_state_error(ldap_conn);
}

/** Callback to process results of initial root query, identifying directory type
 */
static void _proto_ldap_socket_open_read(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	proto_ldap_dir_ctx		*dir_ctx = talloc_get_type_abort(uctx, proto_ldap_dir_ctx);
	fr_ldap_connection_t		*ldap_conn = talloc_get_type_abort(dir_ctx->conn->h, fr_ldap_connection_t);
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(dir_ctx->main_listen->app_io_instance,
									    proto_ldap_sync_ldap_t);
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(dir_ctx->main_listen->thread_instance,
									proto_ldap_sync_ldap_thread_t);
	fr_ldap_rcode_t			status;
	LDAPMessage			*result;

	size_t				i;
	TALLOC_CTX			*local = NULL;

	/*
	 *	Fetch the result.  Setting the timeout to 0 here means use
	 *	res_timeout from the configuration.
	 */
	status = fr_ldap_result(&result, NULL, ldap_conn, dir_ctx->msgid, LDAP_MSG_ALL, NULL, fr_time_delta_from_msec(0));
	if (status != LDAP_PROC_SUCCESS) {
		PERROR("Failed querying for directory type");
		if (result) ldap_msgfree(result);
	error:
		talloc_free(dir_ctx);
		if (local) talloc_free(local);
		connection_signal_reconnect(ldap_conn->conn, CONNECTION_FAILED);
		return;
	}

	fr_ldap_directory_result_parse(ldap_conn->directory, ldap_conn->handle, result, ldap_conn->config->name);
	ldap_msgfree(result);

	/*
	 *	If the server does not support any of the relevant controls, we just
	 *	tidy up - no point in signalling to reconnect.
	 */
	if (ldap_conn->directory->sync_type == FR_LDAP_SYNC_NONE) {
		ERROR("LDAP sync configured for directory which does not support any suitable control");
		talloc_free(dir_ctx);
		connection_signal_halt(ldap_conn->conn);
		return;
	}

	/*
	 *	We've done all the preparation work on the LDAP connection, now
	 *	use normal network event listeners.
	 */
	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);
	if (unlikely(fr_network_listen_add(thread->nr, thread->li) < 0)) {
		PERROR("Failed adding listener");
		goto error; /* retry? */
	}

	DEBUG2("Starting sync(s)");

	local = talloc_new(NULL);

	/*
	 *	Sync operations start by sending a fake packet to run
	 *	the load Cookie section in order to retrieve the cookie
	 */
	for (i = 0; i < talloc_array_length(inst->parent->sync_config); i++) {
		if (proto_ldap_cookie_load_send(local, inst, i, thread) < 0) goto error;
	}

	talloc_free(dir_ctx);
	talloc_free(local);
}

/** Allocate a child listener
 *
 * Called as a watch function when the LDAP connection enters the INIT state
 */
static void _proto_ldap_socket_init(connection_t *conn, UNUSED connection_state_t prev,
				    UNUSED connection_state_t state, void *uctx)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(uctx, proto_ldap_sync_ldap_thread_t);
	fr_listen_t			*li;

	MEM(li = talloc_zero(conn, fr_listen_t));

	thread->li = li;
	li->thread_instance = thread;

	li->cs = thread->parent->cs;
	li->app_io = &proto_ldap_sync_child;
	li->name = li->app_io->common.name;
	li->default_message_size = li->app_io->default_message_size;

	/*
	 *	Use the app from the parent listener to access
	 *	the encoder / decoder functions
	 */
	li->app = thread->parent->app;
	li->app_instance = thread->parent->app_instance;
	li->server_cs = thread->inst->parent->server_cs;
}

/** Callback for closure of LDAP connection
 *
 * Schedules re-start of the connection if appropriate
 */
static void _proto_ldap_socket_closed(UNUSED connection_t *conn, connection_state_t prev,
				      UNUSED connection_state_t state, void *uctx)
{
	fr_listen_t			*listen = talloc_get_type_abort(uctx, fr_listen_t);
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(listen->thread_instance, proto_ldap_sync_ldap_thread_t);
	proto_ldap_sync_ldap_t const	*inst = thread->inst;

	if (fr_event_loop_exiting(thread->el)) return;

	if (prev == CONNECTION_STATE_CONNECTED) {
		ERROR("LDAP connection closed.  Scheduling restart in %pVs",
		       fr_box_time_delta(inst->handle_config.reconnection_delay));
		if (fr_timer_in(thread, thread->el->tl, &thread->conn_retry_ev,
				inst->handle_config.reconnection_delay,
				false, proto_ldap_connection_init, listen) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}
	}
}

/** Query an LDAP server to establish its type
 *
 * Called as a watch function once the LDAP connection enters the CONNECTED state
 *
 * There are three different forms of LDAP sync/persistent search - so we need
 * to know what we're dealing with, and whether the relevant options have been enabled.
 */
static void _proto_ldap_socket_open_connected(connection_t *conn, UNUSED connection_state_t prev,
					      UNUSED connection_state_t state, void *uctx)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(uctx, proto_ldap_sync_ldap_thread_t);
	fr_listen_t			*listen = talloc_get_type_abort(thread->parent, fr_listen_t);
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(thread->inst,
									    proto_ldap_sync_ldap_t);
	fr_ldap_connection_t		*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);

	proto_ldap_dir_ctx		*dir_ctx;

	if (ldap_conn->fd < 0) {
	connection_failed:
		if (fr_timer_in(thread, thread->el->tl, &thread->conn_retry_ev,
				inst->handle_config.reconnection_delay,
				false, proto_ldap_connection_init, listen) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}
		return;
	}

	thread->li->fd = ldap_conn->fd;

	MEM(dir_ctx = talloc_zero(inst, proto_ldap_dir_ctx));
	if (!dir_ctx) goto connection_failed;

	dir_ctx->main_listen = listen;
	dir_ctx->conn = conn;
	dir_ctx->child_listen = thread->li;

#ifdef SO_RCVBUF
	if (inst->recv_buff_is_set) {
		int opt;

		opt = inst->recv_buff;
		if (setsockopt(ldap_conn->fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'recv_buff': %s", fr_syserror(errno));
		}
	}
#endif

	/*
	 *	Set the callback which will handle the results of this query
	 */
	if (fr_event_fd_insert(conn, NULL, conn->el, ldap_conn->fd,
			       _proto_ldap_socket_open_read,
			       NULL,
			       _proto_ldap_socket_open_error,
			       dir_ctx) < 0) {
					goto connection_failed;
	}

	/*
	 *	Allocate the directory structure and send the query
	 */
	dir_ctx->msgid = fr_ldap_conn_directory_alloc_async(ldap_conn);

	if (dir_ctx->msgid < 0) {
		talloc_free(dir_ctx);
		goto connection_failed;
	}

	/*
	 *	Add a watch to catch closed LDAP connections
	 */
	connection_add_watch_post(thread->conn, CONNECTION_STATE_CLOSED,
				     _proto_ldap_socket_closed, true, listen);
}

/** Callback triggered when parent listener app_io has its event list set
 *
 * Initiates the actual outbound LDAP connection
 *
 * @param[in] li	The parent listener.
 * @param[in] el	Event list for this listener.
 * @param[in] nr	Network handler.
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_ldap_sync_ldap_t);
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_ldap_sync_ldap_thread_t);

	/*
	 *	Set up thread data
	 */
	thread->name = inst->handle_config.name;
	thread->parent = li;
	thread->el = el;
	thread->nr = nr;
	thread->inst = inst;

	/*
	 *	Initialise the connection
	 */
	proto_ldap_connection_init(el->tl, fr_event_list_time(el), li);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_ldap_sync_ldap_t	*inst = talloc_get_type_abort(mctx->mi->data, proto_ldap_sync_ldap_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	char const		*server;

	/*
	 *	Verify that the LDAP server configuration is valid, either
	 *	distinct server and port or an LDAP url.
	 */
	fr_assert(inst->server);

	inst->parent = talloc_get_type_abort(mctx->mi->parent->data, proto_ldap_sync_t);
	inst->cs = conf;

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	server = inst->server;
	inst->handle_config.server = talloc_strdup(inst, "");

	if (ldap_is_ldap_url(server)) {
		if (fr_ldap_server_url_check(&inst->handle_config, server, conf) < 0) return -1;
	} else {
		if (fr_ldap_server_config_check(&inst->handle_config, server, conf) < 0) return -1;
	}

	inst->handle_config.server[talloc_array_length(inst->handle_config.server) - 1] = '\0';

	inst->handle_config.name = talloc_typed_asprintf(inst, "proto_ldap_conn (%s)",
							 cf_section_name(cf_item_to_section(cf_parent(cf_parent(conf)))));

	return 0;
}

fr_app_io_t proto_ldap_sync_child = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "ldap_sync_child"
	},
	.read			= proto_ldap_child_mod_read,
	.write			= proto_ldap_child_mod_write,
	.close			= proto_ldap_child_mod_close,

	.default_message_size	= 4096,
	.track_duplicates	= false,
};

fr_app_io_t proto_ldap_sync_ldap = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "ldap_sync_ldap",
		.config			= proto_ldap_sync_ldap_config,
		.inst_size		= sizeof(proto_ldap_sync_ldap_t),
		.thread_inst_size	= sizeof(proto_ldap_sync_ldap_thread_t),
		.instantiate		= mod_instantiate
	},

	.default_message_size	= 4096,
	.track_duplicates	= false,

	.event_list_set		= mod_event_list_set,
};
