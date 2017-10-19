/*
 * Copyright (c) 2016, Network RADIUS SARL <license@networkradius.com>
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
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/eap.aka.h>
#include <freeradius-devel/eap.sim.h>
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
		ERROR("ctrl_pipe (%i) write failed: %s", fd, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Block until libosmo responds
	 */
	len = read(fd, &ptr, sizeof(ptr));
	if (len < 0) {
		ERROR("ctrl_pipe (%i) read failed : %s", fd, fr_syserror(errno));
		return -1;
	}

	if (len != sizeof(ptr)) {
		ERROR("ctrl_pipe (%i) data too short, expected %zu bytes, got %zi bytes",
		      fd, sizeof(ptr), len);
		return -1;
	}

	if (ptr != txn) {
		ERROR("ctrl_pipe (%i) response ptr (%p) does not match request (%p)", fd, ptr, txn);
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

	rad_assert(ctrl_pipe[0] >= 0);

	pthread_mutex_lock(&ctrl_pipe_mutex);
	ret = sigtran_client_do_transaction(ctrl_pipe[0], txn);
	pthread_mutex_unlock(&ctrl_pipe_mutex);

	return ret;
}

/** Called by a new thread to register a new req_pipe
 *
 * @return
 *	- The client side of the req_pipe on success.
 *	- -1 on error.
 */
int sigtran_client_thread_register(void)
{
	int			req_pipe[2] = { -1, -1 };
	sigtran_transaction_t	*txn;

	/*
	 *	Create the pipe on our side, and pass over
	 *	the remote end to be registered.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, req_pipe) < 0) {
		ERROR("Failed creating req_pipe: %s", fr_syserror(errno));
		return -1;
	}

	rad_assert((req_pipe[0] >= 0) && (req_pipe[1] >= 0));

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_THREAD_REGISTER;
	txn->request.data = &req_pipe[1];

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("Failed registering thread");

		close(req_pipe[0]);
		close(req_pipe[1]);
		talloc_free(txn);
		return -1;
	}
	talloc_free(txn);

	return req_pipe[0];
}

/** Signal that libosmo should unregister the other side of the pipe
 *
 * @param req_pipe_fd The rlm_sigtran side of the req_pipe.
 */
int sigtran_client_thread_unregister(int req_pipe_fd)
{
	sigtran_transaction_t	*txn;

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_THREAD_UNREGISTER;

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("Failed unregistering thread");
		talloc_free(txn);
		return -1;
	}
	talloc_free(txn);
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
		ERROR("Failed bringing up link");
		talloc_free(txn);
		return -1;
	}
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

	txn = talloc_zero(NULL, sigtran_transaction_t);
	txn->request.type = SIGTRAN_REQUEST_LINK_DOWN;
	memcpy(&txn->request.data, conn, sizeof(txn->request.data));

	if ((sigtran_client_do_ctrl_transaction(txn) < 0) || (txn->response.type != SIGTRAN_RESPONSE_OK)) {
		ERROR("Failed bringing up link");
		talloc_free(txn);
		return -1;
	}
	talloc_free(txn);
	*conn = NULL;

	return 0;
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
rlm_rcode_t sigtran_client_map_send_auth_info(rlm_sigtran_t *inst, REQUEST *request,
					      sigtran_conn_t const *conn, int fd)
{
	rlm_rcode_t				rcode;
	sigtran_transaction_t			*txn;
	sigtran_map_send_auth_info_req_t	*req;
	char					*imsi;
	size_t					len;

	rad_assert((fd != ctrl_pipe[0]) && (fd != ctrl_pipe[1]));

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
		ERROR("%i is not a valid version", req->version);
		goto error;
	}

	txn->request.data = req;
	txn->ctx.request = request;

	if (tmpl_aexpand(req, &imsi, request, inst->imsi, NULL, NULL) < 0) {
		ERROR("Failed retrieving IMSI");
		goto error;
	}

	len = talloc_array_length(imsi) - 1;
	if ((len != 16) && (len != 15)) {
		ERROR("IMSI must be 15 or 16 digits got %zu digits", len);
		goto error;
	}

	if (sigtran_ascii_to_tbcd(req, &req->imsi, imsi) < 0) {
		ERROR("Failed converting ASCII to BCD");
		goto error;
	}

	if (sigtran_client_do_transaction(fd, txn) < 0) {
		ERROR("Failed sending MAP_SEND_AUTH_INFO request");
		goto error;
	}

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
			{
				fr_dict_attr_t const *root;

				rad_assert(vec->sim.rand);
				rad_assert(vec->sim.sres);
				rad_assert(vec->sim.kc);

				root = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_EAP_SIM_ROOT);
				if (!root) {
					REDEBUG("Can't find dict root for EAP-SIM");
					goto error;
				}

				RDEBUG2("SIM auth vector %i", i);
				RINDENT();
				vp = fr_pair_afrom_child_num(request, root, FR_EAP_SIM_RAND);
				fr_pair_value_memsteal(vp, vec->sim.rand);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_SIM_SRES);
				fr_pair_value_memsteal(vp, vec->sim.sres);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_SIM_KC);
				fr_pair_value_memsteal(vp, vec->sim.kc);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);
				REXDENT();

				i++;
			}
				break;

			case SIGTRAN_VECTOR_TYPE_UMTS_QUINTUPLETS:
			{
				fr_dict_attr_t const *root;

				rad_assert(vec->umts.rand);
				rad_assert(vec->umts.xres);
				rad_assert(vec->umts.ck);
				rad_assert(vec->umts.ik);
				rad_assert(vec->umts.authn);

				root = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_EAP_AKA_ROOT);
				if (!root) {
					REDEBUG("Can't find dict root for EAP-AKA");
					goto error;
				}

				RDEBUG2("UMTS auth vector %i", i);
				RINDENT();
				vp = fr_pair_afrom_child_num(request, root, FR_EAP_AKA_RAND);
				fr_pair_value_memsteal(vp, vec->umts.rand);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_AKA_XRES);
				fr_pair_value_memsteal(vp, vec->umts.xres);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_AKA_CK);
				fr_pair_value_memsteal(vp, vec->umts.ck);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_AKA_IK);
				fr_pair_value_memsteal(vp, vec->umts.ik);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);

				vp = fr_pair_afrom_child_num(request, root, FR_EAP_AKA_AUTN);
				fr_pair_value_memsteal(vp, vec->umts.authn);
				rdebug_pair(L_DBG_LVL_2, request, vp, "&control:");
				fr_cursor_append(&cursor, vp);
				REXDENT();

				i++;
			}
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
		rad_assert(0);
		/* FALL-THROUGH */

	case SIGTRAN_RESPONSE_FAIL:
		rcode = RLM_MODULE_FAIL;
		break;
	}
	talloc_free(txn);

	return rcode;
}
