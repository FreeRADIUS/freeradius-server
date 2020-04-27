/*
 * @copyright (c) 2016, Network RADIUS SARL (license@networkradius.com)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Network RADIUS SARL nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * $Id$
 * @file rlm_sigtran/event.c
 * @brief separate eventing thread to run libosmocore's event loop
 *
 * libosmocore is not thread safe, none of the event loop access functions
 * support synchronised access by multiple threads.
 *
 * Writing a shim layer and overloading the libosmo functions would work
 * but is likely to be fragile.
 *
 * Instead, we run a special thread to handle all requests to SS7 entities.
 *
 * This thread runs the libosmocore event loop, and select()s over the SCTP
 * FDs libosmo* creates, and a pipe we create (to allow communication
 * with worker threads).
 *
 * You might except performance using this model to be terrible.  But the
 * fact that libosmo is entirely async, and there's no heavy crypto being
 * performed, I suspect that this thread is unlikely to become a bottleneck.
 *
 * In future when we have our own async event loop, we can look at submitting
 * patches to libosmocore to allow integration with external event loops.
 *
 * @note We rely on the fact that writes to a pipe of less than PIPE_BUF, are
 * 	atomic and not interleaved.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2016 Network RADIUS SARL (license@networkradius.com)
 */
#define LOG_PREFIX "rlm_sigtran - "

#include <osmocom/core/talloc.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/io/schedule.h>
#include <unistd.h>
#include <semaphore.h>

#include <osmocom/core/logging.h>
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/mtp/mtp_level3.h>

#include "libosmo-m3ua/include/bsc_data.h"
#include "libosmo-m3ua/include/sctp_m3ua.h"
#include "sigtran.h"

int			ctrl_pipe[2] = { -1, -1 };	/* Pipes are unidirectional */
static pthread_t	event_thread;
static sem_t		event_thread_running;
static bool		do_exit = false;

typedef int (*osmo_cb_func)(struct osmo_fd *fd, unsigned int what);

/** Unregister a osmocom_fd from the event loop, and close it
 *
 * @param ofd to unregister.
 * @return 0.
 */
static int _ofd_free(struct osmo_fd *ofd)
{
	osmo_fd_unregister(ofd);
	close(ofd->fd);
	return 0;
}

/** Register a new osmocom file descriptor callback
 *
 * @param ctx	to allocate osmocom_fd in.
 * @param fd	to associate with osmocom_fd .
 * @param func	to call when fd becomes readable.
 * @param data	private contextual data.
 * @return
 *	- NULL on error.
 * 	- New osmocom_fd on success.
 *	  Freeing unregisters osmocom_fd from event loop,
 *	  and closes file descriptor.
 */
static struct osmo_fd *ofd_create(TALLOC_CTX *ctx, int fd, osmo_cb_func func, void *data)
{
	struct osmo_fd *ofd;

	MEM(ofd = talloc_zero(ctx, struct osmo_fd));
	ofd->fd = fd;
	ofd->when = BSC_FD_READ;
	ofd->cb = func;
	ofd->data = data;
	if (osmo_fd_register(ofd) < 0) {
		ERROR("Failed registering pipe %i", fd);
		return NULL;
	}
	talloc_set_destructor(ofd, _ofd_free);

	return ofd;
}

/** Shutdown the MTP3 link gracefully if it's being freed
 *
 */
static int _mtp3_link_free(struct mtp_link *mtp3_link)
{
	mtp3_link->shutdown(mtp3_link);
	return 0;
}

/** Add a route to an m3ua_association
 *
 */
static int sigtran_m3ua_route_from_conf(UNUSED TALLOC_CTX *ctx,
					struct mtp_m3ua_client_link *client,
					sigtran_m3ua_route_t *conf)
{
	struct mtp_m3ua_reg_req *route;

	size_t i;

	route = mtp_m3ua_reg_req_add(client);
	if (!route) return -1;

	route->dpc = conf->dpc;

	if (conf->opc) {
		struct mtp_m3ua_opc *opc;

		for (i = 0; i < talloc_array_length(conf->opc); i++) {
			opc = talloc_zero(route, struct mtp_m3ua_opc);
			opc->opc = conf->opc[i];
			llist_add_tail(&opc->list, &route->opc);
		}
	}

	if (conf->si) {
		struct mtp_m3ua_si *si;

		for (i = 0; i < talloc_array_length(conf->si); i++) {
			si = talloc_zero(route, struct mtp_m3ua_si);
			si->si = conf->si[i];
			llist_add_tail(&si->list, &route->si);
		}
	}

	return 0;
}

/** Bring up SCTP/M3UA/MTP3/SCCP
 *
 * @note The final version needs to be much more complex.  We can only have one
 *	event loop per instance of rlm_sigtran, so we need to record link references
 *	and re-use existing SCTP/MTP3 connections where appropriate.
 *
 * @param[in] ctx	to allocate connection data in.
 * @param[out] out	where to write the new sigtran connection.
 * @param[in] conf	for the connection.  Specifies SCTP/M3UA/MTP3/SCCP parameters.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int event_link_up(TALLOC_CTX *ctx, sigtran_conn_t **out, sigtran_conn_conf_t *conf)
{
	struct mtp_link_set		*mtp3_link_set;
	struct mtp_link			*mtp3_link;
	struct mtp_m3ua_client_link 	*m3ua_client;
	socklen_t			salen;

	sigtran_conn_t			*conn;

	conn = talloc_zero(ctx, sigtran_conn_t);
	conn->conf = conf;

	/* Temporarily disable until we can fix the osmocom select loop */
#if 0
	conn->bsc_data = bsc_data_alloc(conn);
	talloc_set_destructor(conn, _conn_free);
#else
	conn->bsc_data = bsc_data_alloc(ctx);
#endif
	/*
	 *	Create a new link.  This will run over SCTP/M3UA
	 */
	MEM(mtp3_link_set = conn->mtp3_link_set = mtp_link_set_alloc(conn->bsc_data));

	mtp3_link_set->dpc = conf->mtp3_dpc;	/* Next hop Point Code */
	mtp3_link_set->opc = conf->mtp3_opc;

	/*
	 *	Patch in our SCCP receive function
	 */
	sigtran_sscp_init(conn);
	mtp_link_set_sccp_data_available_cb(mtp3_link_set, sigtran_sccp_incoming);

	MEM(mtp3_link = conn->mtp3_link = mtp_link_alloc(mtp3_link_set));
	talloc_set_destructor(mtp3_link, _mtp3_link_free);
	mtp3_link->name = talloc_strdup(mtp3_link, "default");
	mtp3_link->nr = 1;

	/*
	 *	Sets up the transport for the MTP3 link
	 */
	MEM(m3ua_client = mtp3_link->data = mtp_m3ua_client_link_init(mtp3_link));

	/*
	 *	Setup SCTP src/dst address
	 */
	fr_ipaddr_to_sockaddr(&conf->sctp_dst_ipaddr, conf->sctp_dst_port,
			      &m3ua_client->remote, &salen);
	if (conf->sctp_src_ipaddr.af != AF_UNSPEC) {
		fr_ipaddr_to_sockaddr(&conf->sctp_src_ipaddr, conf->sctp_src_port,
				      &m3ua_client->local, &salen);
	}

	/*
	 *	Setup M3UA link parameters
	 */
	m3ua_client->link_index = conf->m3ua_link_index;
	m3ua_client->routing_context = conf->m3ua_routing_context;
	m3ua_client->ack_timeout = conf->m3ua_ack_timeout;
	m3ua_client->use_beat = conf->m3ua_beat_interval;

	/*
	 *	Add the route.
	 */
	if (conf->m3ua_routes_is_set || conf->m3ua_routes.dpc_is_set) {
		if (sigtran_m3ua_route_from_conf(m3ua_client, m3ua_client, &conf->m3ua_routes) < 0) return -1;
	}

	/*
	 *	Bring up the MTP3 link
	 */
	mtp3_link->reset(mtp3_link);

	*out = conn;

	return 0;
}

/** Take down a sigtran link
 *
 * @note Probably need to do more than just freeing the memory
 */
static int event_link_down(sigtran_conn_t *conn)
{
	talloc_free(conn);
	return 0;
}

/** Send response
 *
 * @note Works for both blocking and non-blocking sockets
 *
 * @param[in] ofd to write response notification to.
 * @param[in] txn we're confirming.
 */
int sigtran_event_submit(struct osmo_fd *ofd, sigtran_transaction_t *txn)
{
	uint8_t buff[sizeof(void *)];
	uint8_t *p = buff, *end = buff + sizeof(buff);

	memcpy(buff, &txn, sizeof(buff));

	for (p = buff; p < end; p++) {
		ssize_t slen;

		slen = write(ofd->fd, p, end - p);
		if (slen > 0) {
			p += slen;
			continue;
		}

		if (errno == EAGAIN) {
			int	ret;
			fd_set	error_set;
			fd_set	write_set;

			DEBUG3("Server core - Got EAGAIN (no buffer space left), waiting for pipe to become writable");

			FD_ZERO(&error_set);
			FD_ZERO(&write_set);

			FD_SET(ofd->fd, &error_set);
			FD_SET(ofd->fd, &write_set);

			/*
			 *	Don't let signals mess up the select
			 */
			do {
				ret = select(ofd->fd + 1, NULL, &write_set, &error_set, NULL);
			} while ((ret == -1) && (errno == EINTR));

			/*
			 *	If there wasn't an error try again...
			 */
			if ((ret > 0) && !FD_ISSET(ofd->fd, &error_set)) continue;
		}

		ERROR("Server core - Failed writing to pipe (%i): %s", ofd->fd, fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Processes a request for a new pipe from a worker thread
 *
 * @param ofd	for the main ctrl_pipe.
 * @param what	happened.
 * @return
 *	- 0 on success, with pointer written to registration pipe for new osmo_fd.
 *	- -1 on error, with NULL pointer written to registration pipe.
 */
static int event_process_request(struct osmo_fd *ofd, unsigned int what)
{
	sigtran_transaction_t	*txn;

	void			*ptr;
	ssize_t			len;

	if (what & BSC_FD_EXCEPT) {
		ERROR("pipe (%i) closed by osmocom thread, event thread exiting", ofd->fd);
		do_exit = true;
		return -1;
	}

	if (!(what & BSC_FD_READ)) return 0;

	len = read(ofd->fd, &ptr, sizeof(ptr));
	if (len < 0) {
		ERROR("osmocom thread - Failed reading from pipe (%i): %s", ofd->fd, fr_syserror(errno));
		return -1;
	}
	if (len == 0) {
		DEBUG4("Ignoring zero length read");
		return 0;
	}
	if (len != sizeof(ptr)) {
		ERROR("osmocom thread - Failed reading data from pipe (%i): Too short, "
		      "expected %zu bytes, got %zu bytes", ofd->fd, sizeof(ptr), len);
		ptr = NULL;

		if (sigtran_event_submit(ofd, NULL) < 0) {
		fatal_error:
			DEBUG3("Event loop will exit");
			do_exit = true;
			return -1;
		}

		return -1;
	}

	DEBUG3("osmocom thread - Read %zu bytes from pipe %i (%p)", len, ofd->fd, ptr);

	txn = talloc_get_type_abort(ptr, sigtran_transaction_t);
	txn->ctx.ofd = ofd;
	switch (txn->request.type) {
	case SIGTRAN_REQUEST_THREAD_REGISTER:
	{
		struct osmo_fd	*req_ofd;
		int		fd;

		fd = *((int *)txn->request.data);	/* Not talloced */

		DEBUG3("osmocom thread - Registering req_pipe (%i)", fd);

		req_ofd = ofd_create(ofd->data, fd, event_process_request, NULL);
		if (!req_ofd) {
			txn->response.type = SIGTRAN_RESPONSE_FAIL;
		} else {
			txn->response.type = SIGTRAN_RESPONSE_OK;
		}
	}
		break;

	case SIGTRAN_REQUEST_THREAD_UNREGISTER:
		DEBUG3("osmocom thread - Deregistering req_pipe (%i).  Signalled by worker", ofd->fd);
		txn->response.type = SIGTRAN_RESPONSE_OK;

		if (sigtran_event_submit(ofd, txn) < 0) goto fatal_error;
		talloc_free(ofd);	/* Ordering is important */
		return 0;

	case SIGTRAN_REQUEST_LINK_UP:
		DEBUG3("osmocom thread - Bringing link up");
		if (event_link_up(ofd->data, (sigtran_conn_t **)&txn->response.data, txn->request.data) < 0) {	/* Struct not talloced */
			txn->response.type = SIGTRAN_RESPONSE_FAIL;
		} else {
			txn->response.type = SIGTRAN_RESPONSE_OK;
		}
		break;

	case SIGTRAN_REQUEST_LINK_DOWN:
		DEBUG3("osmocom thread - Taking link down");
		if (event_link_down(talloc_get_type_abort(txn->request.data, sigtran_conn_t)) < 0) {
			txn->response.type = SIGTRAN_RESPONSE_FAIL;
		} else {
			txn->response.type = SIGTRAN_RESPONSE_OK;
		}
		break;

	case SIGTRAN_REQUEST_MAP_SEND_AUTH_INFO:
	{
		sigtran_map_send_auth_info_req_t *req = talloc_get_type_abort(txn->request.data,
									      sigtran_map_send_auth_info_req_t);
		DEBUG3("osmocom thread - Processing map send auth info");
		if (sigtran_tcap_outgoing(NULL, req->conn, txn, ofd) < 0) {
			txn->response.type = SIGTRAN_RESPONSE_FAIL;
		} else {
			return 0;	/* Keep caller blocked until we get a response */
		}
	}
		break;

	case SIGTRAN_REQUEST_EXIT:
		DEBUG3("osmocom thread - Event loop will exit");
		do_exit = true;
		txn->response.type = SIGTRAN_RESPONSE_OK;

		if (sigtran_event_submit(ofd, txn) < 0) goto fatal_error;
		talloc_free(ofd);	/* Ordering is important */
		return 0;

#ifndef NDEBUG
	case SIGTRAN_REQUEST_TEST:
		txn->response.type = SIGTRAN_RESPONSE_OK;
		break;
#endif

	default:
		fr_assert(0);
		goto fatal_error;
	}

	if (sigtran_event_submit(ofd, txn) < 0) goto fatal_error;

	return 0;
}

/** Enter the libosmo event loop
 *
 * Will run until the thread is killed, or signalled to exit on the ctrl_pipe.
 */
static void *sigtran_event_loop(UNUSED void *instance)
{
	TALLOC_CTX	*ctx = talloc_init_const("sigtran_event_ctx");

	fr_assert((ctrl_pipe[0] < 0) && (ctrl_pipe[1] < 0));	/* Ensure only one instance exists */

	/*
	 *	Patch in libosmo's logging system to ours
	 */
	sigtran_log_init(ctx);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ctrl_pipe) < 0) {
		ERROR("osmocom thread - Failed creating ctrl_pipe: %s", fr_syserror(errno));
		return NULL;
	}
	if (!ofd_create(ctx, ctrl_pipe[1], event_process_request, ctx)) return NULL;

	DEBUG2("osmocom thread - Entering event loop, listening on fd %i (client fd %i)", ctrl_pipe[1], ctrl_pipe[0]);

	sem_post(&event_thread_running);		/* Up enough to be ok! */

	/*
	 *	The main event loop.
	 */
	while (true) {
		osmo_select_main(0);
		if (do_exit) {
#if 0
			fd_set	readset, writeset, exceptset;
			int	high_fd;

			FD_ZERO(&readset);
			FD_ZERO(&writeset);
			FD_ZERO(&exceptset);

			high_fd = osmo_fd_fill_fds(&readset, &writeset, &exceptset);
			if (high_fd == 0) break;

			DEBUG3("osmocom thread - Deferring exit, waiting for fd %i", high_fd);
#else
			break;
#endif
		}
	}

	talloc_free(ctx);	/* Also frees ctrl pipe ofd (which closes ctrl_pipe[1]) */

	DEBUG2("osmocom thread - Event loop exiting");

	return NULL;
}

/** Start the libosmo event loop
 *
 */
int sigtran_event_start(void)
{
	sem_init(&event_thread_running, 0, 0);

	if (sigtran_sccp_global_init() < 0) {
		ERROR("main thread - Failed initialising SCCP layer");
		return -1;
	}

	if (fr_schedule_pthread_create(&event_thread, sigtran_event_loop, NULL) < 0) {
		ERROR("main thread - Failed spawning thread for multiplexer event loop: %s", fr_syserror(errno));
		return -1;
	}

	sem_wait(&event_thread_running);

#ifndef NDEBUG
	{
		sigtran_transaction_t *txn;

		txn = talloc_zero(NULL, sigtran_transaction_t);
		txn->request.type = SIGTRAN_REQUEST_TEST;

		if ((sigtran_client_do_transaction(ctrl_pipe[0], txn) < 0) ||
		    (txn->response.type != SIGTRAN_RESPONSE_OK)) {
			ERROR("main thread - libosmo thread died");
			talloc_free(txn);
			return -1;
		}
		talloc_free(txn);

		DEBUG2("main thread - libosmo thread responding");
	}
#endif

	return 0;
}

/** Signal that libosmo should exit
 *
 */
int sigtran_event_exit(void)
{
	sigtran_transaction_t *txn;

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_EXIT;

	if ((sigtran_client_do_transaction(ctrl_pipe[0], txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("worker - Failed signalling osmocom thread to exit");
		talloc_free(txn);
		return -1;
	}
	talloc_free(txn);

	close(ctrl_pipe[0]);
	ctrl_pipe[0] = -1;
	ctrl_pipe[1] = -1;

	pthread_join(event_thread, NULL);

	sigtran_sccp_global_free();

	return 0;
}
