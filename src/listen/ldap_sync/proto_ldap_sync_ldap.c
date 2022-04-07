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
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */
#define LOG_PREFIX "proto_ldap_sync_ldap"

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

extern fr_app_io_t proto_ldap_sync_ldap;
extern fr_app_io_t proto_ldap_sync_child;

static CONF_PARSER const proto_ldap_sync_ldap_config[] = {
	/*
	 *	LDAP server definition
	 */
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_ldap_sync_ldap_t, server) },

	/*
	 *	Common LDAP conf parsers
	 */
	FR_LDAP_COMMON_CONF(proto_ldap_sync_ldap_t),

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_ldap_sync;

extern fr_dict_autoload_t proto_ldap_sync_ldap_dict[];
fr_dict_autoload_t proto_ldap_sync_ldap_dict[] = {
	{ .out = &dict_ldap_sync, .proto = "ldap" },
	{ NULL }
};

static fr_dict_attr_t const *attr_ldap_sync_packet_id;
static fr_dict_attr_t const *attr_ldap_sync_cookie;
static fr_dict_attr_t const *attr_ldap_sync_entry_dn;
static fr_dict_attr_t const *attr_ldap_sync_entry_uuid;
static fr_dict_attr_t const *attr_ldap_sync_orig_dn;
static fr_dict_attr_t const *attr_ldap_sync_root_dn;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_ldap_sync_ldap_dict_attr[];
fr_dict_attr_autoload_t proto_ldap_sync_ldap_dict_attr[] = {
	{ .out = &attr_ldap_sync_packet_id, .name = "Sync-Packet-ID", .type = FR_TYPE_UINT32, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_cookie, .name = "LDAP-Sync.Cookie", .type = FR_TYPE_OCTETS, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_entry_dn, .name = "LDAP-Sync.Entry-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_entry_uuid, .name = "LDAP-Sync.Entry-UUID", .type = FR_TYPE_OCTETS, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_orig_dn, .name = "LDAP-Sync.Original-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_ldap_sync_root_dn, .name = "LDAP-Sync.Directory-Root-DN", .type = FR_TYPE_STRING, .dict = &dict_ldap_sync },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_ldap_sync },
	{ NULL }
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
	fr_connection_t		*conn;
	int			msgid;
} proto_ldap_dir_ctx;

static void _proto_ldap_socket_init(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
				    UNUSED fr_connection_state_t state, void *uctx);

static void _proto_ldap_socket_open_connected(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
					      UNUSED fr_connection_state_t state, void *uctx);

/** Attempt to (re)initialise a connection
 *
 * Performs complete re-initialization of a connection.  Called during socket_open
 * to create the initial connection and again any time we need to reopen the connection.
 *
 * @param[in] el	the event list managing listen event.
 * @param[in] now	current time.
 * @param[in] user_ctx	Listener.
 */
static void proto_ldap_connection_init(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *user_ctx)
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

		if (fr_event_timer_in(thread, thread->el, &thread->conn_retry_ev,
				      inst->handle_config.reconnection_delay,
				      proto_ldap_connection_init, listen) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}
	}

	/*
	 *	Add watch functions on the LDAP connection
	 */
	fr_connection_add_watch_post(thread->conn, FR_CONNECTION_STATE_INIT,
				     _proto_ldap_socket_init, true, thread);

	fr_connection_add_watch_post(thread->conn, FR_CONNECTION_STATE_CONNECTED,
				     _proto_ldap_socket_open_connected, true, thread);

	/*
	 *	Signal the connection to start
	 */
	fr_connection_signal_init(thread->conn);

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

	fr_connection_signal_shutdown(thread->conn);
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
 *   - Various sync related messages can inculde a new cookie in
 *     addition to their other data.
 */
static ssize_t proto_ldap_child_mod_read(fr_listen_t *li, UNUSED void **packet_ctx, UNUSED fr_time_t *recv_time_p, UNUSED uint8_t *buffer,
					 UNUSED size_t buffer_len, UNUSED size_t *leftover, UNUSED uint32_t *priority,
					 UNUSED bool *is_dup)
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

	tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);

	/*
	 *	Pull the next outstanding message from this connection.
	 *	We process one message at a time so that the message can be
	 *	passed to the worker, and freed once the request has been
	 *	handled.
	 */
	ret = ldap_result(conn->handle, LDAP_RES_ANY, LDAP_MSG_ONE, &poll, &msg);

	switch (ret) {
	case 0:	/* timeout - shouldn't happen */
		fr_assert(0);
		return -2;

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
	sync_error:
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
	} else {
	/*
	 *	Callbacks are responsible for freeing the msg
	 *	so if there is no callback, free it.
	 */
		ldap_msgfree(msg);
	}
	if (ret < 0) goto sync_error;

	ldap_controls_free(ctrls);

	return 0;
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

	local = talloc_new(NULL);
	fr_dbuff_init(&dbuff, buffer, buffer_len);

	/*
	 *	Extract returned attributes into a temporary list
	 */
	fr_pair_list_init(&tmp);

	ret = fr_internal_decode_list_dbuff(local, &tmp, fr_dict_root(dict_ldap_sync), &dbuff, NULL);
	if (ret < 0) {
		fr_pair_list_free(&tmp);
		talloc_free(local);
		return ret;
	}

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

		inst->parent->sync_config[packet_id]->init(thread->conn->h, packet_id, inst->parent->sync_config[packet_id], cookie);
	}
		break;

	case FR_LDAP_SYNC_CODE_ENTRY_RESPONSE:
		break;

	case FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE:
	{
		sync_refresh_packet_t	*refresh_packet;
		sync_config_t const	*sync_config;

		if (!packet_ctx) break;

		/*
		 *	If there is a packet_ctx, it will be the tracking structure
		 *	indicating that we need to refresh the sync.
		 */
		refresh_packet = talloc_get_type_abort(packet_ctx, sync_refresh_packet_t);

		/*
		 *	Abandon the old sync and start a new one with the relevant cookie.
		 */
		sync_config = refresh_packet->sync->config;
		DEBUG3("Restarting sync with base %s", sync_config->base_dn);
		talloc_free(refresh_packet->sync);
		inst->parent->sync_config[packet_id]->init(thread->conn->h, packet_id, sync_config, refresh_packet->refresh_cookie);

		talloc_free(refresh_packet);
	}
		break;

	default:
		ERROR("Invalid packet type returned %d", pcode);
		break;
	}

	fr_pair_list_free(&tmp);
	talloc_free(local);

	return buffer_len;
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
	fr_dbuff_t			*dbuff;
	fr_pair_list_t			pairs;
	fr_pair_t			*vp;
	TALLOC_CTX			*local = NULL;

	/*
	 *	Fetch the result.  Setting the timeout to 0 here means use
	 *	res_timeout from the configuration.
	 */
	status = fr_ldap_result(&result, NULL, ldap_conn, dir_ctx->msgid, LDAP_MSG_ALL, NULL, fr_time_delta_from_msec(0));

	if (status != LDAP_PROC_SUCCESS) {
		if (result) ldap_msgfree(result);
	error:
		talloc_free(dir_ctx);
		if (local) talloc_free(local);
		fr_connection_signal_reconnect(ldap_conn->conn, FR_CONNECTION_FAILED);
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
		fr_connection_signal_halt(ldap_conn->conn);
		return;
	}

	/*
	 *	We've done all the preparation work on the LDAP connection, now
	 *	use normal network event listeners.
	 */
	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);
	fr_network_listen_add(thread->nr, thread->li);

	DEBUG2("Starting sync(s)");

	fr_pair_list_init(&pairs);
	local = talloc_new(NULL);

	/*
	 *	Sync operations start by sending a fake packet to run
	 *	the load Cookie section in order to retrieve the cookie
	 */
	for (i = 0; i < talloc_array_length(inst->parent->sync_config); i++) {
		size_t		j, len;
		sync_config_t	*config = inst->parent->sync_config[i];

		fr_pair_list_copy(local, &pairs, &config->sync_pairs);
		/*
		 *	Ensure we have access to the thread instance
		 *	in for the demux callbacks
		 */
		inst->parent->sync_config[i]->user_ctx = thread;

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
			break;

		case FR_LDAP_SYNC_PERSISTENT_SEARCH:
			break;

		case FR_LDAP_SYNC_ACTIVE_DIRECTORY:
			break;

		default:
			fr_assert(0);
		}

		fr_pair_list_append_by_da(local, vp, &pairs, attr_packet_type,
					  (uint32_t)FR_LDAP_SYNC_CODE_COOKIE_LOAD, false);
		if (!vp) goto error;
		fr_pair_list_append_by_da(local, vp, &pairs, attr_ldap_sync_packet_id, (uint32_t)i, false);
		if (!vp) goto error;

		if (config->root_dn) {
			fr_pair_list_append_by_da_parent_len(local, vp, &pairs, attr_ldap_sync_root_dn,
							     config->root_dn, strlen(config->root_dn), false);
			if (!vp) goto error;
		}

		FR_DBUFF_TALLOC_THREAD_LOCAL(&dbuff, 1024, 4096);

		if (fr_internal_encode_list(dbuff, &pairs, NULL) < 0) goto error;

		if (fr_network_listen_send_packet(thread->nr, thread->li, thread->li,
						  fr_dbuff_buff(dbuff), fr_dbuff_used(dbuff),
						  fr_time(), NULL) < 0) goto error;
		fr_pair_list_free(&pairs);
	}

	talloc_free(dir_ctx);
	talloc_free(local);
}

/** Allocate a child listener
 *
 * Called as a watch function when the LDAP connection enters the INIT state
 */
static void _proto_ldap_socket_init(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
				    UNUSED fr_connection_state_t state, void *uctx)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(uctx, proto_ldap_sync_ldap_thread_t);
	fr_listen_t			*li;

	MEM(li = talloc_zero(conn, fr_listen_t));

	thread->li = li;
	li->thread_instance = thread;

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
static void _proto_ldap_socket_closed(UNUSED fr_connection_t *conn, fr_connection_state_t prev,
				      UNUSED fr_connection_state_t state, void *uctx)
{
	fr_listen_t			*listen = talloc_get_type_abort(uctx, fr_listen_t);
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(listen->thread_instance, proto_ldap_sync_ldap_thread_t);
	proto_ldap_sync_ldap_t const	*inst = thread->inst;

	if (fr_event_loop_exiting(thread->el)) return;

	if (prev == FR_CONNECTION_STATE_CONNECTED) {
		ERROR("LDAP connection closed.  Scheduling restart in %pVs",
		       fr_box_time_delta(inst->handle_config.reconnection_delay));
		if (fr_event_timer_in(thread, thread->el, &thread->conn_retry_ev,
				      inst->handle_config.reconnection_delay,
				      proto_ldap_connection_init, listen) < 0) {
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
static void _proto_ldap_socket_open_connected(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
					      UNUSED fr_connection_state_t state, void *uctx)
{
	proto_ldap_sync_ldap_thread_t	*thread = talloc_get_type_abort(uctx, proto_ldap_sync_ldap_thread_t);
	fr_listen_t			*listen = talloc_get_type_abort(thread->parent, fr_listen_t);
	proto_ldap_sync_ldap_t const	*inst = talloc_get_type_abort_const(thread->inst,
									    proto_ldap_sync_ldap_t);
	fr_ldap_connection_t		*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);

	proto_ldap_dir_ctx		*dir_ctx;

	if (ldap_conn->fd < 0) {
	connection_failed:
		if (fr_event_timer_in(thread, thread->el, &thread->conn_retry_ev,
				      inst->handle_config.reconnection_delay,
				      proto_ldap_connection_init, listen) < 0) {
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

	/*
	 *	Set the callback which will handle the results of this query
	 */
	if (fr_event_fd_insert(conn, conn->el, ldap_conn->fd,
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
	fr_connection_add_watch_post(thread->conn, FR_CONNECTION_STATE_CLOSED,
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
	proto_ldap_connection_init(el, fr_event_list_time(el), li);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_ldap_sync_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_ldap_sync_ldap_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	char const		*server;

	/*
	 *	Verify that the LDAP server configuration is valid, either
	 *	distinct server and port or an LDAP url.
	 */
	fr_assert(inst->server);

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

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_ldap_sync_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_ldap_sync_ldap_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	dl_module_inst_t const	*dl_inst;

	dl_inst = dl_module_instance_by_data(inst);
	fr_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_ldap_sync_t);
	inst->cs = conf;

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

		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},

	.default_message_size	= 4096,
	.track_duplicates	= false,

	.event_list_set		= mod_event_list_set,
};
