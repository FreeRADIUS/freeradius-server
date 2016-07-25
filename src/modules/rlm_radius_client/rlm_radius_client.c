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
 * @file rlm_radius_client.c
 * @brief A RADIUS client library.
 *
 * @copyright 2016  The FreeRADIUS server project
 * @copyright 2016  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/rad_assert.h>

typedef struct radius_client_instance {
	char const		*name;			//!< Module instance name.

	char const		*virtual_server;       	//!< virtual server to run proxied packets through

	fr_ipaddr_t		src_ipaddr;		// Src IP for outgoing packets

	uint32_t		timeout; 		// Timeout to wait for home server replies (ms)
	home_server_t		*home_server;		// home servers to send packets to
	pthread_key_t		key;
} rlm_radius_client_instance_t;

static const CONF_PARSER listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", PW_TYPE_IPV4_ADDR, rlm_radius_client_instance_t, src_ipaddr) },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_POINTER("listen", PW_TYPE_SUBSECTION, NULL), .dflt = (void const *) listen_config },
	{ FR_CONF_OFFSET("timeout", PW_TYPE_INTEGER, rlm_radius_client_instance_t, timeout), .dflt = "100" },

	{ FR_CONF_OFFSET("virtual_server", PW_TYPE_STRING, rlm_radius_client_instance_t, virtual_server) },
	CONF_PARSER_TERMINATOR
};

typedef struct radius_client_conn {
	rlm_radius_client_instance_t *inst;
	int			num_fds;
	int			sockfd;
	fr_packet_list_t	*pl;
	fr_event_list_t		*el;
} rlm_radius_client_conn_t;

typedef struct rlm_radius_client_request {
	rlm_radius_client_instance_t	*inst;
	REQUEST				*request;
	rlm_rcode_t			rcode;

	rlm_radius_client_conn_t	*conn;

	RADIUS_PACKET			*packet;	/* the packet we sent */
	RADIUS_PACKET			*reply;		/* the reply from the home server */

	REQUEST				*child;		/* the child request */
} rlm_radius_client_request_t;

/** Clean up whatever intermediate state we're in.
 *
 */
static void mod_cleanup(REQUEST *request, rlm_radius_client_request_t *ccr)
{
	if (ccr->child->in_request_hash) {
		(void) fr_packet_list_yank(ccr->conn->pl, ccr->packet);
		ccr->child->in_request_hash = false;
	}

	/*
	 *	Set Failed-Home-Server-IP if we didn't get an answer.
	 */
	if (!ccr->reply) {
		VALUE_PAIR *vp;
		char buffer[INET6_ADDRSTRLEN];

		vp = pair_make_request("Failed-Home-Server-IP", NULL, T_OP_ADD);
		if (vp) {
			fr_pair_value_snprintf(vp, "%s", inet_ntop(ccr->packet->dst_ipaddr.af,
								   &ccr->packet->dst_ipaddr.ipaddr,
								   buffer, sizeof(buffer)));
		}
	}

	TALLOC_FREE(ccr->child);
}

static void mod_event_fd(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	rlm_radius_client_conn_t *conn = ctx;
	rlm_radius_client_request_t *ccr;
	RADIUS_PACKET *reply, **packet_p;
	REQUEST *request;
	char buffer[INET6_ADDRSTRLEN];

	/*
	 *	Look for the packet.
	 *
	 *	@fixme: if there's an error in the socket, remove the
	 *	socket from the packet list.
	 */
	reply = fr_radius_recv(conn, fd, 0, false);
	if (!reply) {
		return;
	}

	packet_p = fr_packet_list_find_byreply(conn->pl, reply);
	if (!packet_p) {
		DEBUG("Received unknown reply %s packet from home server %s port %d - ID %u - ignoring",
		       fr_packet_codes[reply->code],
		       inet_ntop(reply->src_ipaddr.af,
				 &reply->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       reply->src_port, reply->id);
		fr_radius_free(&reply);
		return;
	}

	/*
	 *	Walk back up the chain of structs.
	 */
	ccr = fr_packet2myptr(rlm_radius_client_request_t, packet, packet_p);
	request = ccr->request;

	RDEBUG("Received reply %s packet from home server %s port %d - ID %u",
	       fr_packet_codes[reply->code],
	       inet_ntop(reply->src_ipaddr.af,
			 &reply->src_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       reply->src_port, reply->id);

	/*
	 *	If the reply fails the signature validation, it's not a real reply.
	 */
	if (fr_radius_verify(reply, ccr->packet, ccr->inst->home_server->secret) < 0) {
		REDEBUG("Reply verification failed for home server %s", ccr->inst->home_server->name);
		fr_radius_free(&reply);
		return;
	}

	RDEBUG("Received response from home server");

	/*
	 *	Reply is valid, run the packet through the "recv FOO" stage.
	 */
	fr_packet_list_id_free(conn->pl, ccr->packet, true);
	ccr->child->in_request_hash = false;
	ccr->child->reply = talloc_steal(ccr->child, reply);
	ccr->reply = reply;

	/*
	 *	We've received the response.  Remove the timeout
	 *	handler, and resume.
	 */
	unlang_event_timeout_delete(ccr->request, ccr);

	RDEBUG("Resuming request");

	ccr->rcode = RLM_MODULE_OK;
	unlang_resumable(ccr->request);
}

static void mod_event_timeout(REQUEST *request, UNUSED void *instance, void *ctx, UNUSED struct timeval *now)
{
	rlm_radius_client_request_t *ccr = ctx;

	RDEBUG("Timeout on socket");

	mod_cleanup(request, ccr);

	unlang_resumable(request);
}


static rlm_rcode_t mod_resume(UNUSED REQUEST *request, void *instance, void *ctx)
{
	rlm_rcode_t rcode;
	rlm_radius_client_instance_t *inst = instance;
	rlm_radius_client_request_t *ccr = ctx;

	rad_assert(inst == ccr->inst);

	rcode = ccr->rcode;
	TALLOC_FREE(ccr);

	return rcode;
}


/** Cleanup socket when deleting connection
 *
 */
static void mod_conn_free(void *ctx)
{
	int i, max_fd;
	fd_set fds;
	rlm_radius_client_conn_t *conn = ctx;

	DEBUG("Cleaning up sockets for module %s", conn->inst->name);

	max_fd = fr_packet_list_fd_set(conn->pl, &fds);
	for (i = 0; i < max_fd; i++) {
		if (!FD_ISSET(i, &fds)) continue;

		if (close(i) < 0) DEBUG3("Closing socket failed: %s", fr_syserror(errno));
		fr_event_fd_delete(conn->el, 0, i);
	}
	fr_packet_list_free(conn->pl);

	talloc_free(conn);
}

/** Clean up an association between a child and parent request.
 *
 */
static int mod_ccr_free(rlm_radius_client_request_t *ccr)
{
	if (!ccr->child) return 0;

	if (ccr->child->in_request_hash) {
		(void) fr_packet_list_yank(ccr->conn->pl, ccr->packet);
		ccr->child->in_request_hash = false;
	}

	unlang_event_timeout_delete(ccr->request, ccr);

	return 0;
}

/** Create and add a new socket to the connecton handle.
 *
 */
static int mod_fd_add(fr_event_list_t *el, rlm_radius_client_conn_t *conn, rlm_radius_client_instance_t *inst)
{
	int sockfd;
	fr_ipaddr_t *server_ipaddr = &inst->src_ipaddr;
	uint16_t server_port = 0;
	fr_ipaddr_t ipaddr;

	/*
	 *	Too many outbound sockets is probably a bad idea.
	 */
	if (conn->num_fds > 16) {
		ERROR("Too many open sockets (%d)", conn->num_fds);
		return -1;
	}

	sockfd = fr_socket(server_ipaddr, server_port);
	if (sockfd < 0) {
		ERROR("Error opening socket");
		return 0;
	}

	/*
	 *	Always set the socket as non-blocking.
	 */
	fr_nonblock(sockfd);

	/*
	 *	The default destination is anywhere.
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.af = AF_INET;

	if (!fr_packet_list_socket_add(conn->pl, sockfd, IPPROTO_UDP, &ipaddr, 0, NULL)) {
		DEBUG("Failed adding socket: %s", fr_strerror());
		close(sockfd);
		return -1;
	}

	if (fr_event_fd_insert(el, 0, sockfd, mod_event_fd, conn) < 0) {
		DEBUG("Failed adding event for socket: %s", fr_strerror());
		close(sockfd);
		return -1;
	}

	conn->num_fds++;

	return sockfd;
}

/*
 *	Create a new connection handle.
 */
static void *mod_conn_create(fr_event_list_t *el, rlm_radius_client_instance_t *inst)
{
	rlm_radius_client_conn_t *conn;

	conn = talloc(NULL, rlm_radius_client_conn_t);
	conn->inst = inst;
	conn->pl = fr_packet_list_create(1);
	conn->num_fds = 0;
	conn->el = el;

	if (mod_fd_add(el, conn, inst) < 0) {
		fr_packet_list_free(conn->pl);
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

/** Send packets outbound.
 *
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, REQUEST *request)
{
	rlm_radius_client_instance_t *inst = instance;
	rlm_radius_client_conn_t *conn;
	rlm_radius_client_request_t *ccr;
	struct timeval now, timeout;
	RADIUS_PACKET *packet;
	VALUE_PAIR *vp;
	char buffer[INET6_ADDRSTRLEN];

	if (!request->el) {
		REDEBUG("%s requires the new virtual servers", inst->name);
		return RLM_MODULE_FAIL;
	}

	conn = pthread_getspecific(inst->key);
	if (!conn) {
		conn = mod_conn_create(request->el, inst);
		if (!conn) return RLM_MODULE_FAIL;

		if (pthread_setspecific(inst->key, conn) != 0) {
			rad_assert(0 == 1);
		}
	}

	/*
	 *	We need to tie the child to both the parent, to the
	 *	module instance, and to the connection it's using.
	 */
	MEM(ccr = talloc(request, rlm_radius_client_request_t));

	ccr->inst = inst;
	ccr->request = request;
	ccr->rcode = RLM_MODULE_FAIL;
	ccr->conn = conn;

	talloc_set_destructor(ccr, mod_ccr_free);

	/*
	 *	Create the child request and packet.
	 */
	MEM(ccr->child = request_alloc(request));

	MEM(ccr->packet = packet = fr_radius_alloc(ccr->child, false));

	ccr->child->parent = request;
	ccr->child->packet = ccr->packet;

	/*
	 *	FIXME: allow for changing of the packet code?
	 *	Also, check the home server compatibility against the packet code?
	 */
	packet->code = request->packet->code;
#ifdef WITH_TCP
	packet->proto = IPPROTO_UDP;
#endif
	packet->dst_ipaddr = inst->home_server->ipaddr;
	packet->dst_port = inst->home_server->port;

	packet->src_ipaddr = inst->home_server->src_ipaddr;
	packet->src_port = 0; /* we don't care what this is */

#ifndef NDEBUG
	/*
	 *	Copy the attributes (if any)
	 */
	if (request->packet->vps) {
		packet->vps = fr_pair_list_copy(packet, request->packet->vps);
		if (!packet->vps) {
			mod_cleanup(request, ccr);
			return RLM_MODULE_FAIL;
		}
	}

	vp = fr_pair_afrom_num(packet, 0, PW_PROXY_STATE);
	rad_assert(vp != NULL);
	fr_pair_value_snprintf(vp, "%08x", fr_rand());
	fr_pair_add(&packet->vps, vp);
#else
	/*
	 *	Avoid a memory allocation and copies in
	 *	production.  Since production code doesn't
	 *	check talloc parentage, this hack is OK.
	 */
	packet->vps = request->packet->vps;
#endif

	/*
	 *	Grab an ID.  If we can't, try to create
	 *	another socket, which will give us more IDs.
	 */
	if (!fr_packet_list_id_alloc(conn->pl, IPPROTO_UDP, &ccr->packet, NULL)) {
		if (mod_fd_add(request->el, conn, inst) < 0) {
			talloc_free(ccr);
			REDEBUG("Failed adding more sockets");
			return RLM_MODULE_FAIL;
		}

		if (!fr_packet_list_id_alloc(conn->pl, IPPROTO_UDP, &ccr->packet, NULL)) {
			talloc_free(ccr);
			REDEBUG("Failed allocating ID: %s", fr_strerror());
			return RLM_MODULE_FAIL;
		}
	}
	ccr->child->in_request_hash = true;

	RDEBUG("Sending %s packet to home server %s %s port %d - ID %u",
	       fr_packet_codes[packet->code],
	       ccr->inst->home_server->name,
	       inet_ntop(packet->dst_ipaddr.af,
			 &packet->dst_ipaddr.ipaddr,
			 buffer, sizeof(buffer)),
	       packet->dst_port, packet->id);

	fr_radius_send(packet, NULL, inst->home_server->secret);

#ifndef NDEBUG
	fr_pair_list_free(&packet->vps);
#else
	packet->vps = NULL;
#endif

	/*
	 *	Calculate the wall clock time of when we want to wake up.
	 */
	if (inst->timeout > 1000) {
		timeout.tv_sec = inst->timeout / 1000;
		timeout.tv_usec = (inst->timeout % 1000) * 1000;
	} else {
		timeout.tv_sec = 0;
		timeout.tv_usec = inst->timeout * 1000;
	}

	gettimeofday(&now, NULL);
	timeradd(&now, &timeout, &timeout);

	unlang_event_timeout_add(request, mod_event_timeout, inst, ccr, &timeout);

	return unlang_yield(request, mod_resume, inst, ccr);
}


static int mod_instantiate(CONF_SECTION *config, void *instance)
{
	CONF_SECTION *cs;
	int rcode;
	rlm_radius_client_instance_t *inst = instance;
	home_server_t *home;

	FR_INTEGER_BOUND_CHECK("timeout", inst->timeout, >=, 1);
	FR_INTEGER_BOUND_CHECK("timeout", inst->timeout, <, 500);

	inst->name = cf_section_name2(config);
	if (!inst->name) inst->name = cf_section_name1(config);

	cs = cf_subsection_find_next(config, NULL, "home_server");
	if (!cs) {
		cf_log_err_cs(config, "You must specify at least one home server");
		return -1;
	}

	if (cf_subsection_find_next(config, cs, "home_server") != NULL) {
		cf_log_err_cs(config, "Too many home servers were given.");
		return -1;
	}

	rcode = pthread_key_create(&inst->key, mod_conn_free);
	if (rcode != 0) {
		ERROR("Failed creating pthread key: %s", strerror(rcode));
		return -1;
	}

	home = home_server_afrom_cs(config, NULL, cs);
	if (!home) {
		cf_log_err_cs(config, "Failed parsing home server");
		return -1;
	}

#ifdef WITH_TCP
	if (home->proto != IPPROTO_UDP) {
		cf_log_err_cs(config, "Only home servers of 'proto = udp' are allowed.");
		return -1;
	}
#endif

	if (home->ping_check != HOME_PING_CHECK_NONE) {
		cf_log_err_cs(config, "Only home servers of 'status_check = none' is allowed.");
		return -1;
	}

	DEBUG("%s: Adding home server %s", inst->name, home->name);

	inst->home_server = home;

	return RLM_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_radius_client;
rad_module_t rlm_radius_client = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_client",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_radius_client_instance_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_PREACCT]		= mod_process,
		[MOD_AUTHENTICATE]     	= mod_process,
	},
};
