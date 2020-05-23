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
 * @file src/modules/proto_ldap_sync/proto_ldap_sync.c
 *
 * @brief Perform persistent searches against LDAP directories.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/util/debug.h>
#include <sys/socket.h>

#include "sync.h"

/** Configuration for listen instance of the proto_ldap_conn
 *
 */
typedef struct {
	fr_ldap_config_t		handle_config;		//!< Connection configuration instance.

	sync_config_t			**sync_config;		//!< DNs and filters to monitor.


	fr_event_list_t			*el;			//!< Network side event list.

	fr_event_timer_t const		*sync_retry_ev;		//!< When to retry re-establishing the sync.

	fr_event_timer_t const		*conn_retry_ev;		//!< When to retry re-establishing the conn.

	/*
	 *	Connection
	 */
	fr_ipaddr_t			dst_ipaddr;		//!< LDAP server IP address.
	uint16_t			dst_port;		//!< LDAP server port.

	fr_ipaddr_t			src_ipaddr;		//!< Our src interface.
	uint16_t			src_port;		//!< Our src port.

	fr_ldap_connection_t		*conn;			//!< Our connection to the LDAP directory.

	RADCLIENT			*client;		//!< Fake client representing the connection.

	/*
	 *	Per instance config
	 */
	fr_time_delta_t			sync_retry_interval;	//!< How long to wait before trying to re-start
								//!< a sync.

	fr_time_delta_t			conn_retry_interval;	//!< How long to wait before trying to re-establish
								//!< a connection.

	/*
	 *	Global config
	 */
	char const			*tls_random_file;	//!< Path to the random file if /dev/random
								//!< and /dev/urandom are unavailable.

	uint32_t			ldap_debug;		//!< Debug flag for the SDK.
} proto_ldap_inst_t;

typedef enum {
	LDAP_SYNC_CODE_PRESENT	= SYNC_STATE_PRESENT,
	LDAP_SYNC_CODE_ADD	= SYNC_STATE_ADD,
	LDAP_SYNC_CODE_MODIFY	= SYNC_STATE_MODIFY,
	LDAP_SYNC_CODE_DELETE	= SYNC_STATE_DELETE,
	LDAP_SYNC_CODE_COOKIE_LOAD,
	LDAP_SYNC_CODE_COOKIE_STORE
} ldap_sync_packet_code_t;

static fr_table_num_sorted_t const ldap_sync_code_table[] = {
	{ "cookie-load",	LDAP_SYNC_CODE_COOKIE_LOAD	},
	{ "cookie-store",	LDAP_SYNC_CODE_COOKIE_STORE	},
	{ "entry-add",		LDAP_SYNC_CODE_ADD		},
	{ "entry-delete",	LDAP_SYNC_CODE_DELETE		},
	{ "entry-modify",	LDAP_SYNC_CODE_MODIFY		},
	{ "entry-present",	LDAP_SYNC_CODE_PRESENT		}
};
static size_t ldap_sync_code_table_len = NUM_ELEMENTS(ldap_sync_code_table);

static CONF_PARSER sasl_mech_static[] = {
	{ FR_CONF_OFFSET("mech", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, fr_ldap_sasl_t, mech) },

	{ FR_CONF_OFFSET("proxy", FR_TYPE_STRING, fr_ldap_sasl_t, proxy) },

	{ FR_CONF_OFFSET("realm", FR_TYPE_STRING, fr_ldap_sasl_t, realm) },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER ldap_sync_search_config[] = {
	{ FR_CONF_OFFSET("base_dn", FR_TYPE_STRING, sync_config_t, base_dn), .dflt = "", .quote = T_SINGLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("filter", FR_TYPE_STRING, sync_config_t, filter) },

	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, sync_config_t, scope_str), .dflt = "sub" },

	{ FR_CONF_OFFSET("attrs", FR_TYPE_STRING | FR_TYPE_MULTI, sync_config_t, attrs) },

	{ FR_CONF_OFFSET("allow_refresh", FR_TYPE_BOOL, sync_config_t, allow_refresh), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER option_config[] = {
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{ FR_CONF_OFFSET("idle", FR_TYPE_TIME_DELTA, fr_ldap_config_t, keepalive_idle), .dflt = "60" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{ FR_CONF_OFFSET("probes", FR_TYPE_UINT32, fr_ldap_config_t, keepalive_probes), .dflt = "3" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	{ FR_CONF_OFFSET("interval", FR_TYPE_TIME_DELTA, fr_ldap_config_t, keepalive_interval), .dflt = "30" },
#endif
	{ FR_CONF_OFFSET("dereference", FR_TYPE_STRING, fr_ldap_config_t, dereference_str) },
	/* allow server unlimited time for search (server-side limit) */
	{ FR_CONF_OFFSET("srv_timelimit", FR_TYPE_TIME_DELTA, fr_ldap_config_t, srv_timelimit), .dflt = "20" },
	/* timeout for search results */
	{ FR_CONF_OFFSET("res_timeout", FR_TYPE_TIME_DELTA, fr_ldap_config_t, res_timeout), .dflt = "20" },
#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/* timeout on network activity */
	{ FR_CONF_DEPRECATED("net_timeout", FR_TYPE_TIME_DELTA, fr_ldap_config_t, net_timeout), .dflt = "10" },
#endif

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER global_config[] = {
	{ FR_CONF_OFFSET("random_file", FR_TYPE_FILE_EXISTS, proto_ldap_inst_t, tls_random_file) },
	{ FR_CONF_OFFSET("ldap_debug", FR_TYPE_UINT32, proto_ldap_inst_t, ldap_debug), .dflt = "0x0000" },		/* Debugging flags to the server */

	CONF_PARSER_TERMINATOR
};

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_file) },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_path) },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_certificate_file) },
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_private_key_file) },
	{ FR_CONF_OFFSET("start_tls", FR_TYPE_BOOL, fr_ldap_config_t, start_tls), .dflt = "no" },
	{ FR_CONF_OFFSET("require_cert", FR_TYPE_STRING, fr_ldap_config_t, tls_require_cert_str) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	/*
	 *	LDAP server definition
	 */
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_MULTI | FR_TYPE_REQUIRED, proto_ldap_inst_t, handle_config.server_str) },
	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_ldap_inst_t, handle_config.port) },
	{ FR_CONF_OFFSET("identity", FR_TYPE_STRING, proto_ldap_inst_t, handle_config.admin_identity) },
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING | FR_TYPE_SECRET, proto_ldap_inst_t, handle_config.admin_password) },
	{ FR_CONF_OFFSET("sasl", FR_TYPE_SUBSECTION, proto_ldap_inst_t, handle_config.admin_sasl), .subcs = (void const *) sasl_mech_static },

	{ FR_CONF_OFFSET("sync_retry_interval", FR_TYPE_TIME_DELTA, proto_ldap_inst_t, sync_retry_interval), .dflt = "5" },
	{ FR_CONF_OFFSET("conn_retry_interval", FR_TYPE_TIME_DELTA, proto_ldap_inst_t, conn_retry_interval), .dflt = "5" },

	/*
	 *	Areas of the DIT to listen on
	 */
	{ FR_CONF_SUBSECTION_ALLOC("sync", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_REQUIRED, proto_ldap_inst_t, sync_config, ldap_sync_search_config) },

	/*
	 *	Extra configuration items
	 */
	{ FR_CONF_POINTER("options", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) option_config },
	{ FR_CONF_POINTER("global", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) global_config },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, proto_ldap_inst_t, handle_config), .subcs = (void const *) tls_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_ldap_sync_dict[];
fr_dict_autoload_t proto_ldap_sync_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_ldap_sync_attr;
static fr_dict_attr_t const *attr_ldap_sync_cookie;
static fr_dict_attr_t const *attr_ldap_sync_dn;
static fr_dict_attr_t const *attr_ldap_sync_entry_dn;
static fr_dict_attr_t const *attr_ldap_sync_entry_state;
static fr_dict_attr_t const *attr_ldap_sync_entry_uuid;
static fr_dict_attr_t const *attr_ldap_sync_filter;
static fr_dict_attr_t const *attr_ldap_sync_scope;

extern fr_dict_attr_autoload_t proto_ldap_sync_dict_attr[];
fr_dict_attr_autoload_t proto_ldap_sync_dict_attr[] = {
	{ .out = &attr_ldap_sync_attr, .name = "LDAP-Sync-Attr", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_cookie, .name = "LDAP-Sync-Cookie", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_dn, .name = "LDAP-Sync-DN", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_entry_dn, .name = "LDAP-Sync-Entry-DN", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_entry_state, .name = "LDAP-Sync-Entry-State", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_entry_uuid, .name = "LDAP-Sync-Entry-UUID", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_filter, .name = "LDAP-Sync-Filter", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_sync_scope, .name = "LDAP-Sync-Scope", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

static REQUEST *request_setup(UNUSED TALLOC_CTX *ctx, UNUSED rad_listen_t *listener, UNUSED RADIUS_PACKET *packet,
		       UNUSED RADCLIENT *client, UNUSED RAD_REQUEST_FUNP fun)
{
	fr_assert(0 == 1);
	return NULL;
}

/** Add dict enumv from a fr_table_num_sorted_t table
 *
 * @param[in] da	to add enumv to.
 * @param[in] table	to add values from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_dict_enum_from_name_number(fr_dict_attr_t const *da, fr_table_num_sorted_t const *table)
{
	fr_table_num_sorted_t const	*p;
	fr_value_box_t		value = { .type = FR_TYPE_INT32 };

	for (p = table; p->name; p++) {
		value.vb_int32 = p->value;
		if (fr_dict_enum_add_name(fr_dict_attr_unconst(da), p->name, &value, true, false) < 0) return -1;
	}

	return 0;
}

/** Describe the socket we opened to the LDAP server
 *
 * @param[in] listen	abstracting the connection to the server.
 * @param[out] buffer	Where to write text describing the socket.
 * @param[in] bufsize	the length of data written to buffe.r
 * @return 1.
 */
static int proto_ldap_socket_print(rad_listen_t const *listen, char *buffer, size_t bufsize)
{
	size_t			len;
	proto_ldap_inst_t	*inst = listen->data;
	char const		*name = listen->proto->name;

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len
#define ADDSTRING(_x) strlcpy(buffer, _x, bufsize);FORWARD

	ADDSTRING(name);

	ADDSTRING(" server ");

	fr_inet_ntoh(&inst->dst_ipaddr, buffer, bufsize);
	FORWARD;

	ADDSTRING(" port ");
	snprintf(buffer, bufsize, "%d", inst->dst_port);
	FORWARD;

	if (listen->server) {
		ADDSTRING(" bound to virtual-server ");
		strlcpy(buffer, listen->server, bufsize);
	}

#undef ADDSTRING
#undef FORWARD

	return 1;
}

/** Describe the packet we received from the LDAP server
 *
 * @param[in] request	The current request.
 * @param[in] packet	containing attributes from the entry we received.
 * @param[in] received	Should always be true.
 */
static void proto_ldap_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received)
{
	char src_ipaddr[FR_IPADDR_STRLEN];
	char dst_ipaddr[FR_IPADDR_STRLEN];

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	RDEBUG("%s %s Sync Id %i from %s%s%s:%i to %s%s%s:%i",
	       received ? "Received" : "Sent",
	       fr_table_str_by_value(ldap_sync_code_table, packet->code, "<INVALID>"),
	       packet->id,
	       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
	       fr_inet_ntop(src_ipaddr, sizeof(src_ipaddr), &packet->src_ipaddr),
	       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
	       packet->src_port,
	       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
	       fr_inet_ntop(dst_ipaddr, sizeof(dst_ipaddr), &packet->dst_ipaddr),
	       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
	       packet->dst_port);

	return;
}

/** Very simple state machine to process requests
 *
 * Unlike normal protocol requests which may have multiple distinct states,
 * we really only have REQUEST_INIT and REQUEST_RECV phases.
 *
 * Conversion of LDAPMessage to VALUE_PAIR structs is done in the listener
 * because we cannot easily duplicate the LDAPMessage to send it across to
 * the worker for parsing.
 *
 * Most LDAP directories can only handle between 2000-5000 modifications a second
 * so we're unlikely to be I/O or CPU bound using this division of responsibilities.
 *
 * @param[in] request	to process.
 * @param[in] action	If something has signalled that the request should stop
 *			being processed.
 */
static void request_running(REQUEST *request, fr_state_signal_t action)
{
	CONF_SECTION	*unlang;
	char const	*verb;
	char const	*state;
	rlm_rcode_t	rcode = RLM_MODULE_FAIL;

	REQUEST_VERIFY(request);

	/*
	 *	Async (in the same thread, tho) signal to be done.
	 */
	if (action == FR_SIGNAL_CANCEL) goto done;

	/*
	 *	We ignore all other actions.
	 */
	if (action != FR_SIGNAL_RUN) return;

	switch (request->request_state) {
	case REQUEST_INIT:
		if (RDEBUG_ENABLED) proto_ldap_packet_debug(request, request->packet, true);
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->server_cs = request->listener->server_cs;
		request->component = "ldap";

		switch (request->packet->code) {
		case LDAP_SYNC_CODE_PRESENT:
			verb = "recv";
			state = "Present";
			break;

		case LDAP_SYNC_CODE_ADD:
			verb = "recv";
			state = "Add";
			break;

		case LDAP_SYNC_CODE_MODIFY:
			verb = "recv";
			state = "Modify";
			break;

		case LDAP_SYNC_CODE_DELETE:
			verb = "recv";
			state = "Delete";
			break;

		case LDAP_SYNC_CODE_COOKIE_LOAD:
			verb = "load";
			state = "Cookie";
			break;

		case LDAP_SYNC_CODE_COOKIE_STORE:
			verb = "store";
			state = "Cookie";
			break;

		default:
			fr_assert(0);
			return;
		}
		unlang = cf_section_find(request->server_cs, verb, state);
		if (!unlang) unlang = cf_section_find(request->server_cs, "recv", "*");
		if (!unlang) {
			RDEBUG2("Ignoring %s operation.  Add \"%s %s {}\" to virtual-server \"%s\""
				" to handle", fr_table_str_by_value(ldap_sync_code_table, request->packet->code, "<INVALID>"),
				verb, state, cf_section_name2(request->server_cs));
			rcode = RLM_MODULE_NOOP;
			goto done;
		}

		RDEBUG("Running '%s %s' from file %s", cf_section_name1(unlang),
		       cf_section_name2(unlang), cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

		if (rcode == RLM_MODULE_YIELD) return;
		FALL_THROUGH;

	default:
	done:
		switch (rcode) {
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_OK:
			break;

		default:
			break;
		}
		fr_assert(request->log.unlang_indent == 0);
		//request_delete(request);
		break;
	}
}

/** Process events while the request is queued.
 *
 *  \dot
 *	digraph request_queued {
 *		request_queued -> done [ label = "TIMER >= max_request_time" ];
 *		request_queued -> request_running [ label = "RUNNING" ];
 *	}
 *  \enddot
 *
 * @param[in] request	to process.
 * @param[in] action	If something has signalled that the request should stop
 *			being processed.
 */
static void request_queued(REQUEST *request, fr_state_signal_t action)
{
	REQUEST_VERIFY(request);

	switch (action) {
	case FR_SIGNAL_RUN:
		request->process = request_running;
		request->process(request, action);
		break;

	case FR_SIGNAL_CANCEL:
		(void) fr_heap_extract(request->backlog, request);
		//request_delete(request);
		break;

	default:
		break;
	}
}

/** Setup an LDAP sync request
 *
 * Allocates a request, with request/reply packets.
 *
 * Sets various fields in the request->packet with information from the file descriptor
 * we received from libldap.
 *
 * @param[in] listen	The common listener encapsulating the libldap fd.
 * @param[in] inst	of the proto_ldap_sync module.
 * @param[in] sync_id 	the unique identifier of the sync.
 * @return
 *	- A new request on success.
 *	- NULL on error.
 */
static REQUEST *proto_ldap_request_setup(rad_listen_t *listen, proto_ldap_inst_t *inst, int sync_id)
{
	TALLOC_CTX		*ctx;
	RADIUS_PACKET		*packet;
	REQUEST			*request;

	ctx = talloc_pool(NULL, main_config->talloc_pool_size);
	if (!ctx) return NULL;
	talloc_set_name_const(ctx, "ldap_inst_pool");

	packet = fr_radius_alloc(ctx, false);
	packet->sockfd = listen->fd;
	packet->id = sync_id;
	packet->src_ipaddr = inst->dst_ipaddr;
	packet->src_port = inst->dst_port;
	packet->dst_ipaddr = inst->src_ipaddr;
	packet->dst_port = inst->src_port;

	packet->timestamp = fr_time();

	request = request_setup(ctx, listen, packet, inst->client, NULL);
	if (!request) return NULL;

	request->process = request_queued;

	return request;
}

/** Add attributes describing the sync to the request
 *
 * Adds:
 * - LDAP-Sync-DN     - The DN we're searching on (not the DN of any received object).
 * - LDAP-Sync-Filter - The filter for the search.
 * - LDAP-Sync-Attr   - The attributes we retrieved.
 *
 * @param[in] request	The current request.
 * @param[in] config	Configuration of the sync.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int proto_ldap_attributes_add(REQUEST *request, sync_config_t const *config)
{
	VALUE_PAIR *vp;

	MEM(pair_add_request(&vp, attr_ldap_sync_dn) == 0);
	fr_pair_value_strcpy(vp, config->base_dn);

	if (config->filter) {
		MEM(pair_update_request(&vp, attr_ldap_sync_filter) >= 0);
		fr_pair_value_strcpy(vp, config->filter);
	}
	if (config->attrs) {
		char const *attrs_p;

		for (attrs_p = *config->attrs; *attrs_p; attrs_p++) {
			MEM(pair_add_request(&vp, attr_ldap_sync_attr) == 0);
			fr_pair_value_strcpy(vp, attrs_p);
		}
	}

	return 0;
}

/** Attempt to reinitialise a sync
 *
 * It's perfectly fine to re-initialise individual sync without tearing down the
 * connection completely.
 *
 * @param[in] el	the event list managing listen event.
 * @param[in] now	current time.
 * @param[in] user_ctx	Sync config.
 */
static void proto_ldap_sync_reinit(fr_event_list_t *el, fr_time_t now, void *user_ctx)
{
	sync_config_t		*config = talloc_get_type_abort(user_ctx, sync_config_t);
	proto_ldap_inst_t	*inst = talloc_get_type_abort(config->user_ctx, proto_ldap_inst_t);

	/*
	 *	Reinitialise the sync
	 */
	if (sync_state_init(inst->conn, config, NULL, true) == 0) return;

	PERROR("Failed reinitialising sync, will retry in %pV seconds", fr_box_time_delta(inst->sync_retry_interval));

	/*
	 *	We want the time from when we were called
	 */
	if (fr_event_timer_at(inst, el, &inst->sync_retry_ev,
			      now + inst->sync_retry_interval,
			      proto_ldap_sync_reinit, user_ctx) < 0) {
		FATAL("Failed inserting event: %s", fr_strerror());
	}
}

/** Attempt to (re)initialise a connection
 *
 * Performs complete re-initialization of a connection.  Called during socket_open
 * to create the initial connection and again any time we need to reopen the connection.
 *
 * @note Needs API rework to work correctly.  There's no way to inform the master that
 *	the listener's file descriptor has changed.
 *
 * @param[in] el	the event list managing listen event.
 * @param[in] now	current time.
 * @param[in] user_ctx	Listener.
 */
static void proto_ldap_connection_init(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, UNUSED void *user_ctx)
{
	return;
}

/** Reinitialise a sync with reload_hint=true
 *
 * The server returned an e-refreshRequired code, so we need to restart the sync
 * with reload_hint = true.
 *
 * @note This is a callback for the sync_demux function.
 *
 * @param[in] conn	the sync belongs to.
 * @param[in] config	of the sync that received the e-refreshRequired code.
 * @param[in] sync_id	of the sync that received the e-refreshRequired code.
 * @param[in] phase	Refresh phase the sync is currently in.
 * @param[in] user_ctx	The listener.
 * @return 0.
 */
static int _proto_ldap_refresh_required(fr_ldap_connection_t *conn, sync_config_t const *config,
				        int sync_id, UNUSED sync_phases_t phase, void *user_ctx)
{
	rad_listen_t		*listen = talloc_get_type_abort(user_ctx, rad_listen_t);
	proto_ldap_inst_t	*inst = talloc_get_type_abort(listen->data, proto_ldap_inst_t);;
	void 			*ctx;

	sync_state_destroy(conn, sync_id);	/* Destroy the old state */

	DEBUG2("Refresh required");

	memcpy(&ctx, &config, sizeof(ctx));
	proto_ldap_sync_reinit(inst->el, fr_time(), ctx);

	return 0;
}

/** Receive notification of present phase
 *
 * @note This is a callback for the sync_demux function.
 *
 * @param[in] conn	the sync belongs to.
 * @param[in] config	of the sync that entered the refresh present phase.
 * @param[in] sync_id	of the sync that entered the refresh present phase.
 * @param[in] phase	Refresh phase the sync was previously in.
 * @param[in] user_ctx	The listener.
 * @return 0.
 */
static int _proto_ldap_present(fr_ldap_connection_t *conn, sync_config_t const *config,
			       int sync_id, sync_phases_t phase, void *user_ctx)
{
	rad_listen_t		*listen = talloc_get_type_abort(user_ctx, rad_listen_t);

	if (!cf_section_find(listen->server_cs, "recv", "Present")) {
		DEBUG2("Present phase is not supported, reinitialising sync");

		return _proto_ldap_refresh_required(conn, config, sync_id, phase, user_ctx);
	}

	return 0;
}

/** Enque a new cookie store request
 *
 * Create a new request containing the cookie we received from the LDAP server. This allows
 * the administrator to store the cookie and provide it on a future call to
 * #proto_ldap_cookie_load.
 *
 * @note This is a callback for the sync_demux function.
 *
 * @param[in] conn	the cookie was received on.
 * @param[in] config	of the LDAP sync.
 * @param[in] sync_id	sync number (msgid) of the sync within the context of the connection.
 * @param[in] cookie	received from the LDAP server.
 * @param[in] user_ctx	listener.
 * @return
 *	- 0 on success.
 *	- -1 on failure
 */
static int _proto_ldap_cookie_store(UNUSED fr_ldap_connection_t *conn, sync_config_t const *config,
			      	    int sync_id, uint8_t const *cookie, void *user_ctx)
{
	rad_listen_t		*listen = talloc_get_type_abort(user_ctx, rad_listen_t);
	proto_ldap_inst_t	*inst = talloc_get_type_abort(listen->data, proto_ldap_inst_t);
	REQUEST			*request;
	VALUE_PAIR		*vp;

	request = proto_ldap_request_setup(listen, inst, sync_id);
	if (!request) return -1;

	proto_ldap_attributes_add(request, config);

	MEM(pair_update_request(&vp, attr_ldap_sync_cookie) >= 0);
	fr_pair_value_memdup(vp, cookie, talloc_array_length(cookie), true);

	request->packet->code = LDAP_SYNC_CODE_COOKIE_STORE;

//	request_enqueue(request);

	return 0;
}

/** Process an entry modification operation
 *
 * @note This is a callback for the sync_demux function.
 *
 * @param[in] conn	the sync belongs to.
 * @param[in] config	of the sync that received an entry.
 * @param[in] sync_id	of the sync that received an entry.
 * @param[in] phase	Refresh phase the sync is currently in.
 * @param[in] uuid	of the entry.
 * @param[in] msg	containing the entry.
 * @param[in] state	The type of modification we need to perform to our
 *			representation of the entry.
 * @param[in] user_ctx	The listener.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _proto_ldap_entry(fr_ldap_connection_t *conn, sync_config_t const *config,
			     int sync_id, UNUSED sync_phases_t phase,
			     uint8_t const uuid[SYNC_UUID_LENGTH], LDAPMessage *msg,
			     sync_states_t state, void *user_ctx)
{
	rad_listen_t		*listen = talloc_get_type_abort(user_ctx, rad_listen_t);
	proto_ldap_inst_t	*inst = talloc_get_type_abort(listen->data, proto_ldap_inst_t);
	fr_ldap_map_exp_t	expanded;
	REQUEST			*request;

	request = proto_ldap_request_setup(listen, inst, sync_id);
	if (!request) return -1;

	proto_ldap_attributes_add(request, config);
	request->packet->code = state;

	/*
	 *	Add the entry DN and attributes
	 */
	if (msg) {
		char *entry_dn;
		VALUE_PAIR *vp;

		entry_dn = ldap_get_dn(conn->handle, msg);

		MEM(pair_update_request(&vp, attr_ldap_sync_entry_dn) >= 0);
		ldap_memfree(entry_dn);

		MEM(pair_update_request(&vp, attr_ldap_sync_entry_uuid) >= 0);
		fr_pair_value_memdup(vp, uuid, SYNC_UUID_LENGTH, true);
	}

	/*
	 *	Apply the attribute map
	 */
	if (fr_ldap_map_expand(&expanded, request, config->entry_map) < 0) {
	error:
		talloc_free(request);
		return -1;
	}
	if (fr_ldap_map_do(request, conn, NULL, &expanded, msg) < 0) goto error;

//	request_enqueue(request);

	return 0;
}


/** Allocate a fake client representing the LDAP connection
 *
 * The server expects a client, and it's easier to fake one than check all
 * request->client dereferences.
 *
 * @param[in] inst	of proto_ldap to allocate a fake client for.
 * @return
 *	- A fake client.
 *	- NULL on error.
 */
static RADCLIENT *proto_ldap_fake_client_alloc(proto_ldap_inst_t *inst)
{
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	RADCLIENT	*client;
	char		buffer[FR_IPADDR_STRLEN];

	cs = cf_section_alloc(NULL, NULL, "client", "ldap");
	cp = cf_pair_alloc(cs, "ipaddr", fr_inet_ntop(buffer, sizeof(buffer), &inst->dst_ipaddr),
			   T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_add(cs, cp);
	cp = cf_pair_alloc(cs, "secret", "fake", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_add(cs, cp);

	client = client_afrom_cs(inst, cs, NULL);
	if (!client) {
		PERROR("Failed creating fake LDAP client");
		talloc_free(cs);
		return NULL;
	}
	talloc_steal(client, cs);

	return client;
}

/** Synchronously load cookie data
 *
 * FIXME: This should not be synchronous, but integrating it into the event loop
 *	before the server has started processing requests makes my head hurt.
 *
 * @param[in] ctx	to allocate cookie buffer in.
 * @param[out] cookie	Where to write the cookie we loaded.
 * @param[in] listen	structure encapsulating the LDAP
 * @param[in] config	of the sync we're loading the cookie for.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 *	- 1 no cookie returned.
 */
static int proto_ldap_cookie_load(TALLOC_CTX *ctx, uint8_t **cookie, rad_listen_t *listen, sync_config_t const *config)
{
	proto_ldap_inst_t	*inst = talloc_get_type_abort(listen->data, proto_ldap_inst_t);
	REQUEST			*request;
	CONF_SECTION		*unlang;
	int			ret = 0;

	rlm_rcode_t		rcode;

	request = proto_ldap_request_setup(listen, inst, 0);
	if (!request) return -1;

	proto_ldap_attributes_add(request, config);
	request->packet->code = LDAP_SYNC_CODE_COOKIE_STORE;

	unlang = cf_section_find(request->server_cs, "load", "Cookie");
	if (!unlang) {
		RDEBUG2("Ignoring %s operation.  Add \"load Cookie {}\" to virtual-server \"%s\""
			" to handle", fr_table_str_by_value(ldap_sync_code_table, request->packet->code, "<INVALID>"),
			cf_section_name2(request->server_cs));
	}

	*cookie = NULL;

	rcode = unlang_interpret_synchronous(request, unlang, RLM_MODULE_NOOP, true);
	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	{
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_da(request->reply->vps, attr_ldap_sync_cookie, TAG_ANY);
		if (!vp) {
			if (config->allow_refresh) RDEBUG2("No &reply:Cookie attribute found.  All entries matching "
							   "sync configuration will be returned");
			ret = 1;
			goto finish;
		}

		/*
		 *	So the request pool doesn't hang around indefinitely.
		 */
		MEM(*cookie = talloc_memdup(ctx, vp->vp_octets, vp->vp_length));
		ret = 0;
	}
		break;

	case RLM_MODULE_NOOP:
		if (config->allow_refresh) RDEBUG2("Section returned \"noop\".  All entries matching sync "
						   "configuration will be returned");
		ret = 1;
		break;

	default:
		RERROR("Section must return \"ok\", \"updated\", or \"noop\" for listener instantiation to succeed");
		ret = -1;
		break;
	}

finish:
	talloc_free(request);
	return ret;
}

/** De-multiplex incoming LDAP Messages
 *
 * This callback should be called when the LDAP socket is readable.  It drains
 * any outstanding LDAPMessages using sync_demux.  sync_demux in-turn calls one
 * of the following callbacks:
 *	- _proto_ldap_entry		We received a notification an entry
 *					was added, deleted, or modified.
 *	- _proto_ldap_cookie_store	We received a new cookie value.
 *	- _proto_ldap_present		The server wants to perform a refresh present
 *					phase (which we don't allow).
 *	- _proto_ldap_refresh_required	The server wants us to download all content
 *					specified by our sync/search.
 *
 * These callbacks may result in requests being enqueued or syncs restarted.
 *
 * @note We do not currently make enqueuing the cookie requests dependent on all
 *	previous LDAP entries being processed, so we may miss updates in some
 *	circumstances.  This needs to be fixed, but is waiting on v4.0.0
 *	re-architecture.
 *
 * @param[in] listen	encapsulating the libldap socket.
 * @return
 *	- 1 on success.
 *	- 0 on failure.
 */
static int proto_ldap_socket_recv(rad_listen_t *listen)
{
	proto_ldap_inst_t	*inst = talloc_get_type_abort(listen->data, proto_ldap_inst_t);
	int			sync_id;
 	void			*ctx;
 	sync_config_t const	*config;

	/*
	 *	Demultiplex drains any outstanding messages from the socket,
	 *	and calls the _proto_ldap_entry() callback above to create
	 *	the request..
	 *
	 *	Multiple requests may be created from one call to sync_demux.
	 */
 	switch (sync_demux(&sync_id, inst->conn)) {
 	default:
		return 1;

 	case -1:
		PERROR("Sync failed - will retry in %pV seconds", fr_box_time_delta(inst->sync_retry_interval));

 		config = sync_state_config_get(inst->conn, sync_id);
		sync_state_destroy(inst->conn, sync_id);	/* Destroy the old state */

		/*
		 *	Schedule sync reinit, but don't perform it immediately.
		 */
		memcpy(&ctx, &config, sizeof(ctx));
		if (fr_event_timer_in(inst, inst->el, &inst->sync_retry_ev,
				      inst->sync_retry_interval,
				      proto_ldap_sync_reinit, ctx) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}
 		return 1;

 	case -2:
 		PERROR("Connection failed - will retry in %pV seconds", fr_box_time_delta(inst->conn_retry_interval));

		/*
		 *	Schedule conn reinit, but don't perform it immediately
		 */
 		memcpy(&ctx, &config, sizeof(ctx));
		if (fr_event_timer_in(inst, inst->el, &inst->conn_retry_ev,
				      inst->conn_retry_interval,
				      proto_ldap_connection_init, listen) < 0) {
			FATAL("Failed inserting event: %s", fr_strerror());
		}

 		return 0;
 	}
}

/** Open a handle to the LDAP directory
 *
 * @note This is performed synchronously.
 *
 * @param[in] cs	specifying the listener configuration.
 * @param[in] listen	structure encapsulating the libldap socket.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
static int proto_ldap_socket_open(UNUSED CONF_SECTION *cs, rad_listen_t *listen)
{
	proto_ldap_inst_t		*inst = listen->data;
	fr_ldap_rcode_t			status;
	size_t				i;

	struct sockaddr_storage		addr;
	socklen_t			len = sizeof(addr);

	/*
	 *	Fixme - Should be the network thread's event loop?
	 */
	inst->el = main_loop_event_list();

	/*
	 *	Destroys any existing syncs and connections
	 */
	TALLOC_FREE(inst->conn);

	/*
	 *	Allocate a brand-new connection
	 */
	inst->conn = fr_ldap_connection_alloc(inst);
	if (!inst->conn) goto error;

	if (fr_ldap_connection_configure(inst->conn, &inst->handle_config) < 0) goto error;

	if (inst->conn->config->start_tls) {
		if (ldap_start_tls_s(inst->conn->handle, NULL, NULL) != LDAP_SUCCESS) {
			int		ldap_errno;

			ldap_get_option(inst->conn->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);

			ERROR("Failed starting TLS: %s", ldap_err2string(ldap_errno));

		error:
			TALLOC_FREE(inst->conn);

			PERROR("Failed (re)initialising connection, will retry in %pV seconds",
			       fr_box_time_delta(inst->conn_retry_interval));

			if (fr_event_timer_in(inst, inst->el, &inst->conn_retry_ev,
					      inst->conn_retry_interval,
					      proto_ldap_connection_init, listen) < 0) {
				FATAL("Failed inserting event: %s", fr_strerror());
			}

			return -1;
		}
	}

	status = fr_ldap_bind(NULL,
			      &inst->conn,
			      inst->conn->config->admin_identity, inst->conn->config->admin_password,
			      &(inst->conn->config->admin_sasl),
			      0,
			      NULL, NULL);
	if (status != LDAP_PROC_SUCCESS) goto error;

	/*
	 *	We need to know the directory type so we can synthesize cookies
	 */
	if (fr_ldap_directory_alloc(inst->conn, &inst->conn->directory, &inst->conn) < 0) goto error;

	if (ldap_get_option(inst->conn->handle, LDAP_OPT_DESC, &listen->fd) != LDAP_OPT_SUCCESS) {
		int ldap_errno;

		ldap_get_option(inst->conn->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);

		ERROR("Failed retrieving file descriptor from LDAP handle: %s", ldap_err2string(ldap_errno));
		goto error;
	}

	/*
	 *	Work back to get src/dst ip address and ports from the file descriptor
	 */
	if (getsockname(listen->fd, (struct sockaddr *)&addr, &len) < 0) {
		ERROR("Failed getting socket information: %s", fr_syserror(errno));
		goto error;
	}
	fr_ipaddr_from_sockaddr(&addr, len, &inst->src_ipaddr, &inst->src_port);

	if (getpeername(listen->fd, (struct sockaddr *)&addr, &len) < 0) {
		ERROR("Failed getting socket information: %s", fr_syserror(errno));
		goto error;
	}

	/*
	 *	Allocate a fake client to use in requests
	 */
	fr_ipaddr_from_sockaddr(&addr, len, &inst->dst_ipaddr, &inst->dst_port);
	inst->client = proto_ldap_fake_client_alloc(inst);

	DEBUG2("Starting sync(s)");
	for (i = 0; i < talloc_array_length(inst->sync_config); i++) {
		uint8_t *cookie;
		int	ret;

		/*
		 *	Synchronously load the cookie... ewww
		 */
		if (proto_ldap_cookie_load(inst, &cookie, listen, inst->sync_config[i]) < 0) goto error;
		ret = sync_state_init(inst->conn, inst->sync_config[i], cookie, false);
		talloc_free(cookie);
		if (ret < 0) goto error;
	}

	return 0;
}

/** Parse socket configuration
 *
 * @param[in] cs	specifying the listener configuration.
 * @param[in] listen	structure encapsulating the libldap socket.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
static int proto_ldap_socket_parse(CONF_SECTION *cs, rad_listen_t *listen)
{
	proto_ldap_inst_t 	*inst = listen->data;
	CONF_SECTION		*sync_cs;
	size_t		 	i;
	int			ret;

	/*
	 *	Always cache the CONF_SECTION of the server.
	 */
	listen->server_cs = virtual_server_find(listen->server);
	if (!listen->server_cs) {
		cf_log_err(cs, "Failed to find virtual server '%s'", listen->server);
		return -1;
	}

	if (cf_section_rules_push(cs, module_config) < 0) return -1;
	ret = cf_section_parse(inst, inst, cs);
	if (ret < 0) return ret;

	talloc_set_type(inst, proto_ldap_inst_t);

	fr_assert(inst->handle_config.server_str[0]);
	inst->handle_config.name = talloc_typed_asprintf(inst, "proto_ldap_conn (%s)", listen->server);

	memcpy(&inst->handle_config.server, &inst->handle_config.server_str[0], sizeof(inst->handle_config.server));

	/*
	 *	Convert scope strings to enumerated constants
	 */
	for (sync_cs = cf_section_find(cs, "sync", NULL), i = 0;
	     sync_cs;
	     sync_cs = cf_section_find_next(cs, sync_cs, "sync", NULL), i++) {
		int		scope;
		void		**tmp;
		CONF_SECTION	*map_cs;

		talloc_set_type(inst->sync_config[i], sync_config_t);

		scope = fr_table_value_by_str(fr_ldap_scope, inst->sync_config[i]->scope_str, -1);
		if (scope < 0) {
#ifdef LDAP_SCOPE_CHILDREN
			cf_log_err(cs, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one'"
				   ", 'base' or 'children'", inst->sync_config[i]->scope_str);
#else
			cf_log_err(cs, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one'"
				   " or 'base'", inst->sync_config[i]->scope_str)
#endif
			return -1;
		}
		inst->sync_config[i]->scope = scope;

		/*
		 *	Needs to be NULL terminated as that's what libldap needs
		 */
		if (inst->sync_config[i]->attrs) {
			memcpy(&tmp, &inst->sync_config[i]->attrs, sizeof(tmp));
			tmp = talloc_array_null_terminate(tmp);
			memcpy(&inst->sync_config[i]->attrs, tmp, sizeof(inst->sync_config[i]->attrs));
		}

		inst->sync_config[i]->persist = true;
		inst->sync_config[i]->user_ctx = listen;
		inst->sync_config[i]->cookie = _proto_ldap_cookie_store;
		inst->sync_config[i]->entry = _proto_ldap_entry;
		inst->sync_config[i]->refresh_required = _proto_ldap_refresh_required;
		inst->sync_config[i]->present = _proto_ldap_present;

		/*
		 *	Parse and validate any maps
		 */
		map_cs = cf_section_find(sync_cs, "update", NULL);
		if (map_cs && map_afrom_cs(inst, &inst->sync_config[i]->entry_map, map_cs,
					   NULL, NULL, fr_ldap_map_verify, NULL,
					   LDAP_MAX_ATTRMAP) < 0) {
			return -1;
		}
	}

	if (fr_ldap_global_config(inst->ldap_debug, inst->tls_random_file) < 0) return -1;

	return 0;
}

/** Compile an unlang section
 *
 * FIXME: Can probably be common code between all modules?
 *
 * @param[in] server_cs		The virtual server containing the section.
 * @param[in] name1		First name component e.g. recv.
 * @param[in] name2		Second name component e.g. sync-info.
 * @param[in] component		Method to execute in modules called from listen section.
 * @return
 *	- 0 if section couldn't be found.
 *	- 1 if section could be found and was compiled.
 *	- -1 on error.
 */
static int ldap_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2,
				rlm_components_t component)
{
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, name1, name2);
	if (!cs) return 0;

	cf_log_debug(cs, "Loading %s %s {...}", name1, name2);

	if (unlang_compile(cs, component, NULL, NULL) < 0) {
		cf_log_err(cs, "Failed compiling '%s %s { ... }' section", name1, name2);
		return -1;
	}

	return 1;
}

/** Compile the various recv/load/store sections
 *
 * @param[in] server_cs		The virtual server containing the sections to compile.
 * @param[in] listen_cs		The listen config section.
 */
static int proto_ldap_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;
	int found = 0;

	rcode = ldap_compile_section(server_cs, "load", "Cookie", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	rcode = ldap_compile_section(server_cs, "store", "Cookie", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	rcode = ldap_compile_section(server_cs, "recv", "Add", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	rcode = ldap_compile_section(server_cs, "recv", "Present", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	rcode = ldap_compile_section(server_cs, "recv", "Delete", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	rcode = ldap_compile_section(server_cs, "recv", "Modify", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode > 0) found++;

	if (found == 0) {
		cf_log_err(server_cs, "At least one of 'recv [Present|Add|Delete|Modify] { ... }' "
			      "sections must be present in virtual server %s", cf_section_name2(server_cs));

		return -1;
	}

	return 0;
}

static int proto_ldap_load(void)
{
	fr_ldap_init();

	/*
	 *	Setup dictionary attributes for the proto_ldap_sync module
	 *
	 *	Sets enumv values for various dictionary values,
	 *	from the name/number tables.
	 *	This ensures the dictionaries don't get out of
	 *	sync with the code.
	 */
	fr_dict_enum_from_name_number(attr_ldap_sync_scope, fr_ldap_scope);
	fr_dict_enum_from_name_number(attr_ldap_sync_entry_state, sync_state_table);

	return 0;
}

static void proto_ldap_unload(void)
{
	fr_ldap_free();
}

extern rad_protocol_t proto_ldap_sync;
rad_protocol_t proto_ldap_sync = {
	.magic		= RLM_MODULE_INIT,
	.name		= "ldap_sync",
	.inst_size	= sizeof(proto_ldap_inst_t),
	.transports	= TRANSPORT_NONE,
	.tls		= false,
	.onload		= proto_ldap_load,
	.unload		= proto_ldap_unload,
	.compile	= proto_ldap_listen_compile,
	.parse		= proto_ldap_socket_parse,
	.open		= proto_ldap_socket_open,
	.recv		= proto_ldap_socket_recv,
	.send		= NULL,
	.print		= proto_ldap_socket_print,
	.debug		= proto_ldap_packet_debug,
	.encode		= NULL,
	.decode		= NULL,
};
