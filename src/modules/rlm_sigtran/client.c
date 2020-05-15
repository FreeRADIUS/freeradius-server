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
#define LOG_PREFIX "rlm_sigtran - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>
#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/module.h>

#include "attrs.h"
#include "sigtran.h"

static pthread_mutex_t ctrl_pipe_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * $Id$
 * @file rlm_sigtran/client.c
 * @brief Talk to the event loop.
 */
int sigtran_client_do_transaction(int fd, sigtran_transaction_t *txn)
{
	ssize_t		len;
	void		*ptr;

	if (write(fd, &txn, sizeof(txn)) < 0) {
		ERROR("worker - ctrl_pipe (%i) write failed: %s", fd, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Block until libosmo responds
	 */
	len = read(fd, &ptr, sizeof(ptr));
	if (len < 0) {
		ERROR("worker - ctrl_pipe (%i) read failed : %s", fd, fr_syserror(errno));
		return -1;
	}

	if (len != sizeof(ptr)) {
		ERROR("worker - ctrl_pipe (%i) data too short, expected %zu bytes, got %zi bytes",
		      fd, sizeof(ptr), len);
		return -1;
	}

	if (ptr != txn) {
		ERROR("worker - ctrl_pipe (%i) response ptr (%p) does not match request (%p)", fd, ptr, txn);
		return -1;
	}

	/*
	 *	Check talloc header is still OK
	 */
	talloc_get_type_abort(ptr, sigtran_transaction_t);

	return 0;
}

static int sigtran_client_do_ctrl_transaction(sigtran_transaction_t *txn)
{
	int ret;

	fr_assert(ctrl_pipe[0] >= 0);

	pthread_mutex_lock(&ctrl_pipe_mutex);
	ret = sigtran_client_do_transaction(ctrl_pipe[0], txn);
	pthread_mutex_unlock(&ctrl_pipe_mutex);

	return ret;
}

/** This should never happen
 *
 */
static void _sigtran_pipe_error(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, int fd_errno, UNUSED void *uctx)
{
	ERROR("worker - ctrl_pipe (%i) read failed : %s", fd, fr_syserror(fd_errno));
	fr_assert(0);
}

/** Drain any data we received
 *
 * We don't care about this data, we just don't want the kernel to
 * signal the other side that our read buffer's full.
 */
static void _sigtran_pipe_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, UNUSED void *uctx)
{
	ssize_t			len;
	void			*ptr;
	sigtran_transaction_t	*txn;

	len = read(fd, &ptr, sizeof(ptr));
	if (len < 0) {
		ERROR("worker - ctrl_pipe (%i) read failed : %s", fd, fr_syserror(errno));
		return;
	}

	if (len != sizeof(ptr)) {
		ERROR("worker - ctrl_pipe (%i) data too short, expected %zu bytes, got %zi bytes",
		      fd, sizeof(ptr), len);
		return;
	}

	/*
	 *	Check talloc header is still OK
	 */
	txn = talloc_get_type_abort(ptr, sigtran_transaction_t);
	if (txn->ctx.defunct) return;		/* Request was stopped */

	fr_assert(txn->ctx.request);
	unlang_interpret_resumable(txn->ctx.request);	/* Continue processing */
}

/** Called by a new thread to register a new req_pipe
 *
 * @return
 *	- The client side of the req_pipe on success.
 *	- -1 on error.
 */
int sigtran_client_thread_register(fr_event_list_t *el)
{
	int			req_pipe[2] = { -1, -1 };
	sigtran_transaction_t	*txn;

	/*
	 *	Create the pipe on our side, and pass over
	 *	the remote end to be registered.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, req_pipe) < 0) {
		ERROR("worker - Failed creating req_pipe: %s", fr_syserror(errno));
		return -1;
	}

	fr_assert((req_pipe[0] >= 0) && (req_pipe[1] >= 0));

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_THREAD_REGISTER;
	txn->request.data = &req_pipe[1];

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("worker - Failed registering thread");
	error:
		close(req_pipe[0]);
		close(req_pipe[1]);
		talloc_free(txn);
		return -1;
	}
	DEBUG3("worker - Thread register acked by osmocom thread");
	talloc_free(txn);

	/*
	 *	Read data coming back on the pipe,
	 *	and resume requests which are
	 *	waiting.
	 */
	if (fr_event_fd_insert(NULL, el, req_pipe[0], _sigtran_pipe_read, NULL, _sigtran_pipe_error, NULL) < 0) {
		ERROR("worker - Failed listening on osmocom pipe");
		goto error;
	}

	return req_pipe[0];
}

/** Signal that libosmo should unregister the other side of the pipe
 *
 * @param[in] el		the request pipe was registered to.
 * @param[in] req_pipe_fd	The rlm_sigtran side of the req_pipe.
 */
int sigtran_client_thread_unregister(fr_event_list_t *el, int req_pipe_fd)
{
	sigtran_transaction_t	*txn;

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_THREAD_UNREGISTER;

	/*
	 *	The signal to unregister *MUST* be sent on the
	 *	request pipe itself, so that the osmocom thread
	 *	knows *WHICH* pipe to close on its side.
	 */
	if ((sigtran_client_do_transaction(req_pipe_fd, txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("worker - Failed unregistering thread");
		talloc_free(txn);
		return -1;
	}
	DEBUG3("worker - Thread unregister acked by osmocom thread");
	talloc_free(txn);

	fr_event_fd_delete(el, req_pipe_fd, FR_EVENT_FILTER_IO);
	close(req_pipe_fd);

	return 0;
}

/** Create a new connection
 *
 * Register the required links for a connection.
 *
 * @todo Return struct representing the connection
 */
int sigtran_client_link_up(sigtran_conn_t const **out, sigtran_conn_conf_t const *conn_conf)
{
	sigtran_transaction_t	*txn;

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_LINK_UP;
	memcpy(&txn->request.data, &conn_conf, sizeof(txn->request.data));

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("worker - Failed bringing up link");
		talloc_free(txn);
		return -1;
	}
	DEBUG3("worker - Link up acked by osmocom thread");
	*out = talloc_get_type_abort(txn->response.data, sigtran_conn_t);
	talloc_free(txn);

	return 0;
}

/** Destroy a connection
 *
 * Gracefully shutdown the links for a connection and free it.
 *
 */
int sigtran_client_link_down(sigtran_conn_t const **conn)
{
	sigtran_transaction_t	*txn;

	if (!*conn || !(*conn)->mtp3_link) return 0;	/* Ignore if there is no link */

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_LINK_DOWN;
	memcpy(&txn->request.data, conn, sizeof(txn->request.data));

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("worker - Failed taking down the link");
		talloc_free(txn);
		return -1;
	}
	DEBUG3("worker - Link down acked by osmocom thread");
	talloc_free(txn);
	*conn = NULL;

	return 0;
}

static void sigtran_client_signal(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request,
				  void *rctx, fr_state_signal_t action)
{
	sigtran_transaction_t	*txn = talloc_get_type_abort(rctx, sigtran_transaction_t);

	/*
	 *	Ignore DUP signals, along with all others.
	 */
	if (action != FR_SIGNAL_CANCEL) return;

	txn->ctx.defunct = true;	/* Mark the transaction up as needing to be freed */
	txn->ctx.request = NULL;	/* remove the link to the (now dead) request */
}

static rlm_rcode_t sigtran_client_map_resume(UNUSED void *instance, UNUSED void *thread, REQUEST *request, void *rctx)
{
	sigtran_transaction_t			*txn = talloc_get_type_abort(rctx, sigtran_transaction_t);
	rlm_rcode_t				rcode;
	fr_assert(request == txn->ctx.request);

	/*
	 *	Process response
	 */
	switch (txn->response.type) {
	case SIGTRAN_RESPONSE_OK:
	{
		unsigned int		i = 0;
		fr_cursor_t		cursor;
		VALUE_PAIR		*vp;
		sigtran_vector_t	*vec;
		sigtran_map_send_auth_info_res_t *res = talloc_get_type_abort(txn->response.data,
									      sigtran_map_send_auth_info_res_t);
		fr_cursor_init(&cursor, &request->control);

		for (vec = res->vector; vec; vec = vec->next) {
			switch (vec->type) {
			case SIGTRAN_VECTOR_TYPE_SIM_TRIPLETS:
				fr_assert(vec->sim.rand);
				fr_assert(vec->sim.sres);
				fr_assert(vec->sim.kc);

				RDEBUG2("SIM auth vector %i", i);
				RINDENT();
				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_rand));
				fr_pair_value_memsteal(vp, vec->sim.rand, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_sres));
				fr_pair_value_memsteal(vp, vec->sim.sres, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_kc));
				fr_pair_value_memsteal(vp, vec->sim.kc, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);
				REXDENT();

				i++;
				break;

			case SIGTRAN_VECTOR_TYPE_UMTS_QUINTUPLETS:
				fr_assert(vec->umts.rand);
				fr_assert(vec->umts.xres);
				fr_assert(vec->umts.ck);
				fr_assert(vec->umts.ik);
				fr_assert(vec->umts.authn);

				RDEBUG2("UMTS auth vector %i", i);
				RINDENT();
				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_rand));
				fr_pair_value_memsteal(vp, vec->umts.rand, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_xres));
				fr_pair_value_memsteal(vp, vec->umts.xres, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_ck));
				fr_pair_value_memsteal(vp, vec->umts.ck, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_ik));
				fr_pair_value_memsteal(vp, vec->umts.ik, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);

				MEM(vp = fr_pair_afrom_da(request, attr_eap_aka_sim_autn));
				fr_pair_value_memsteal(vp, vec->umts.authn, true);
				RDEBUG2("&control:%pP", vp);
				fr_cursor_append(&cursor, vp);
				REXDENT();

				i++;
				break;
			}
		}
		rcode = RLM_MODULE_OK;
	}
		break;

	case SIGTRAN_RESPONSE_NOOP:
		rcode = RLM_MODULE_NOOP;
		break;

	case SIGTRAN_RESPONSE_NOTFOUND:
		rcode = RLM_MODULE_NOTFOUND;
		break;

	default:
		fr_assert(0);
		FALL_THROUGH;

	case SIGTRAN_RESPONSE_FAIL:
		rcode = RLM_MODULE_FAIL;
		break;
	}
	talloc_free(txn);

	return rcode;
}

/** Create a MAP_SEND_AUTH_INFO request
 *
 * @param inst		of rlm_sigtran.
 * @param request	The current request.
 * @param conn		current connection.
 * @param fd		file descriptor on which the transaction is done
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
rlm_rcode_t sigtran_client_map_send_auth_info(rlm_sigtran_t const *inst, REQUEST *request,
					      sigtran_conn_t const *conn, int fd)
{
	sigtran_transaction_t			*txn;
	sigtran_map_send_auth_info_req_t	*req;
	char					*imsi;
	size_t					len;

	fr_assert((fd != ctrl_pipe[0]) && (fd != ctrl_pipe[1]));

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_MAP_SEND_AUTH_INFO;

	req = talloc(txn, sigtran_map_send_auth_info_req_t);
	req->conn = conn;

	if (tmpl_aexpand(request, &req->version, request, inst->conn_conf.map_version, NULL, NULL) < 0) {
		ERROR("Failed retrieving version");
	error:
		talloc_free(txn);
		return RLM_MODULE_FAIL;
	}

	switch (req->version) {
	case 2:
	case 3:
		break;

	default:
		REDEBUG("%i is not a valid version", req->version);
		goto error;
	}

	txn->request.data = req;
	txn->ctx.request = request;

	if (tmpl_aexpand(req, &imsi, request, inst->imsi, NULL, NULL) < 0) {
		REDEBUG("Failed retrieving IMSI");
		goto error;
	}

	len = talloc_array_length(imsi) - 1;
	if ((len != 16) && (len != 15)) {
		REDEBUG("IMSI must be 15 or 16 digits got %zu digits", len);
		goto error;
	}

	if (sigtran_ascii_to_tbcd(req, &req->imsi, imsi) < 0) {
		REDEBUG("Failed converting ASCII to BCD");
		goto error;
	}

	if (RDEBUG_ENABLED2) {
		RDEBUG2("Sending MAPv%u request with IMSI \"%pV\"", req->version, fr_box_strvalue_buffer(imsi));
	} else if (RDEBUG_ENABLED3){
		RDEBUG3("Sending MAPv%u request with IMSI \"%pV\" (TBCD %pV)",
			req->version, fr_box_strvalue_buffer(imsi), fr_box_octets_buffer(req->imsi));
	}

	/*
	 *	FIXME - We shouldn't assume the pipe is always writable
	 */
	if (write(fd, &txn, sizeof(txn)) < 0) {
		REDEBUG("worker - ctrl_pipe (%i) write failed: %s", fd, fr_syserror(errno));
		goto error;
	}

	return unlang_module_yield(request, sigtran_client_map_resume, sigtran_client_signal, txn);
}
