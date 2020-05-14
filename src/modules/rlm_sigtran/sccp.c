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
 * @file rlm_sigtran/sccp.c
 * @brief Implement SCCP/TCAP glue layer
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2016 Network RADIUS SARL (license@networkradius.com)
 */
#define LOG_PREFIX "rlm_sigtran - osmocom thread - "

#include <osmocom/core/talloc.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include "sigtran.h"

#undef DEBUG

#include "libosmo-m3ua/include/cellmgr_debug.h"
#include "libosmo-m3ua/include/mtp_data.h"

static uint32_t	last_txn_id = 0;	//!< Global transaction ID
static rbtree_t *txn_tree = NULL;	//!< Global transaction tree... Should really be per module.
static uint32_t	txn_tree_inst = 0;

/** Compare rounds of a transaction
 *
 */
static int sigtran_txn_cmp(void const *a, void const *b)
{
	sigtran_transaction_t const *a_tx = a;	/* May be stack allocated */
	sigtran_transaction_t const *b_tx = b;	/* May be stack allocated */

	if (a_tx->ctx.otid > b_tx->ctx.otid) return +1;
	if (a_tx->ctx.otid < b_tx->ctx.otid) return -1;

	if (a_tx->ctx.invoke_id > b_tx->ctx.invoke_id) return +1;
	if (a_tx->ctx.invoke_id < b_tx->ctx.invoke_id) return -1;

	return 0;
}

static void sigtran_tcap_timeout(void *data)
{
	sigtran_transaction_t *txn = talloc_get_type_abort(data, sigtran_transaction_t);

	ERROR("OTID %u Invoke ID %u timeout", txn->ctx.otid, txn->ctx.invoke_id);

	/*
	 *	Remove the outstanding transaction
	 */
	if (!rbtree_deletebydata(txn_tree, txn)) ERROR("Transaction removed before timeout");

	txn->response.type = SIGTRAN_RESPONSE_FAIL;

	if (sigtran_event_submit(txn->ctx.ofd, txn) < 0) {
		ERROR("Failed informing event client of result: %s", fr_syserror(errno));
		return;
	}
}

/** Send a request with static MAP data in it
 *
 * SCCP will add its headers and call sigtran_sccp_outgoing
 *
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
int sigtran_tcap_outgoing(UNUSED struct msgb *msg_in, void *ctx, sigtran_transaction_t *txn, UNUSED struct osmo_fd *ofd)
{
	static uint8_t tcap_map_raw_v2[] = {
		0x62, 0x43, 0x48, 0x01, 0x01, 0x6b, 0x80, 0x28, /* 0x00 */
		0x80, 0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, /* 0x08 */
		0x01, 0x01, 0xa0, 0x80, 0x60, 0x80, 0x80, 0x02, /* 0x10 */
		0x07, 0x80, 0xa1, 0x80, 0x06, 0x07, 0x04, 0x00, /* 0x18 */
		0x00, 0x01, 0x00, 0x0e, 0x02, 0x00, 0x00, 0x00, /* 0x20 (0x24 is version)*/
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, /* 0x30 (0x35 is invoke ID) */
		0x14, 0xa1, 0x80, 0x02, 0x01, 0x03, 0x02, 0x01, /* 0x38 (0x3c is IMSI len, 0x3d-0x44 IMSI) */
		0x38, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 0x40 */
		0xff, 0xff, 0xff, 0x00, 0x00 };			/* 0x48 */

	static uint8_t tcap_map_raw_v3[] = {
		0x62, 0x48, 0x48, 0x01, 0x01, 0x6b, 0x80, 0x28,	/* 0x00 */
		0x80, 0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, /* 0x08 */
		0x01, 0x01, 0xa0, 0x80, 0x60, 0x80, 0x80, 0x02, /* 0x10 */
		0x07, 0x80, 0xa1, 0x80, 0x06, 0x07, 0x04, 0x00, /* 0x18 */
		0x00, 0x01, 0x00, 0x0e, 0x03, 0x00, 0x00, 0x00, /* 0x20 (0x24 is version)*/
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, /* 0x28 */
		0x19, 0xa1, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, /* 0x30 (0x35 is invoke ID) */
		0x38, 0x30, 0x0d, 0x80, 0x00, 0x00, 0x00, 0x00, /* 0x38 (0x3c is IMSI len, 0x3d-0x44 IMSI) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, /* 0x40 */
		0x00, 0x00 };					/* 0x48 */

	sigtran_map_send_auth_info_req_t *req =
		talloc_get_type_abort(txn->request.data, sigtran_map_send_auth_info_req_t);

	struct msgb			*msg;

	sigtran_conn_t			*conn = talloc_get_type_abort(ctx, sigtran_conn_t);
	struct mtp_m3ua_client_link 	*m3ua_client = talloc_get_type_abort(conn->mtp3_link->data,
									     struct mtp_m3ua_client_link);

	fr_assert(req->imsi);

	if (!mtp_m3ua_link_is_up(m3ua_client)) {
		ERROR("Link not yet active, dropping the request");

		return -1;
	}

	if (rbtree_num_elements(txn_tree) > UINT8_MAX) {
		ERROR("Too many outstanding requests, dropping the request");

		return -1;
	}

	switch (req->version) {
	case 2:
		DEBUG4("Allocating buffer for MAP v2, %zu bytes", sizeof(tcap_map_raw_v2));
		msg = msgb_alloc(sizeof(tcap_map_raw_v2), "sccp: tcap_map");
		msg->l3h = msgb_put(msg, sizeof(tcap_map_raw_v2));
		memcpy(msg->l3h, tcap_map_raw_v2, sizeof(tcap_map_raw_v2));

		*(msg->l3h + 0x3a) = talloc_array_length(req->imsi);
		memcpy(msg->l3h + 0x3b, req->imsi, talloc_array_length(req->imsi));
//		RHEXDUMP(0, msg->l3h, sizeof(tcap_map_raw_v2), "MAPv2 Request");

		break;

	case 3:
		DEBUG4("Allocating buffer for MAP v3, %zu bytes", sizeof(tcap_map_raw_v3));
		msg = msgb_alloc(sizeof(tcap_map_raw_v3), "sccp: tcap_map");
		msg->l3h = msgb_put(msg, sizeof(tcap_map_raw_v3));
		memcpy(msg->l3h, tcap_map_raw_v3, sizeof(tcap_map_raw_v3));

		*(msg->l3h + 0x3c) = talloc_array_length(req->imsi);
		memcpy(msg->l3h + 0x3d, req->imsi, talloc_array_length(req->imsi));
//		RHEXDUMP(0, msg->l3h, sizeof(tcap_map_raw_v3), "MAPv3 Request");

		break;

	default:
		fr_assert_fail(NULL);
		return -1;
	}

	/*
	 *	Set the transaction ID
	 */
	txn->ctx.otid = (last_txn_id++) & UINT8_MAX;			/* 8 bit for now */

	txn->ctx.invoke_id++;						/* Needs to be two operations */
	txn->ctx.invoke_id &= 0x7f;					/* Invoke ID is 7bits */
	DEBUG2("Sending request with OTID %u Invoke ID %u", txn->ctx.otid, txn->ctx.invoke_id);

	if (!rbtree_insert(txn_tree, txn)) {
		ERROR("Failed inserting transaction, maybe at txn limit?");

		msgb_free(msg);
		return -1;
	}

	/*
	 *	Set OTID and Invoke ID in the packet
	 */
	*(msg->l3h + 0x04) = txn->ctx.otid;
	*(msg->l3h + 0x35) = txn->ctx.invoke_id;

	sccp_write(msg, &conn->conf->sccp_calling_sockaddr, &conn->conf->sccp_called_sockaddr,
		   SCCP_PROTOCOL_RETURN_MESSAGE << 4 | SCCP_PROTOCOL_CLASS_0, ctx);	/* Class is connectionless (ish) */

	msgb_free(msg);

	txn->ctx.timer.data = txn;
	txn->ctx.timer.cb = sigtran_tcap_timeout;

	osmo_timer_schedule(&txn->ctx.timer, 1, 0);

	return 0;
}

/** Incoming data
 *
 * This should be called by the SCCP functions to give us result data
 */
static int sigtran_tcap_incoming(struct msgb *msg, UNUSED unsigned int length, UNUSED void *ctx)
{
	sigtran_vector_t	*vec;
	uint8_t			*tcap = msg->l3h;
	uint8_t			*p, *end;
	size_t			len = (size_t)msgb_l3len(msg);

	sigtran_transaction_t	find, *found;
	sigtran_transaction_t	*txn;

	sigtran_map_send_auth_info_req_t *req;
	sigtran_map_send_auth_info_res_t *res;

	struct osmo_fd		*ofd;
	sigtran_vector_t	**last;

	memset(&find, 0, sizeof(find));

//	sigtran_conn_t *conn = talloc_get_type_abort(ctx, sigtran_conn_t);

	DEBUG3("Got %zu bytes of L4 data", (size_t)msgb_l3len(msg));
//	log_request_hex(L_DBG, L_DBG_LVL_3, request, msg->l3h, (size_t)msgb_l3len(msg));

	find.ctx.otid = *(msg->l3h + 0x5);

	// find.ctx.invoke_id = *(msg->l3h + 0x34);
	find.ctx.invoke_id = 1;				/* Always 1 for now... */
	DEBUG2("Received response with DTID %u Invoke ID %u", find.ctx.otid, find.ctx.invoke_id);

	/*
	 *	Lookup the transaction in our tree of outstanding transactions
	 */
	found = rbtree_finddata(txn_tree, &find);
	if (!found) {
		/*
		 *	Not an error, could be a retransmission
		 */
		ERROR("No outstanding transaction with DTID %u Invoke ID %u", find.ctx.otid, find.ctx.invoke_id);
		return 0;
	}
	if (!rbtree_deletebydata(txn_tree, found)) {		/* Remove the outstanding transaction */
		ERROR("Failed removing transaction");
		fr_assert(0);
	}

	txn = talloc_get_type_abort(found, sigtran_transaction_t);
	req = talloc_get_type_abort(txn->request.data, sigtran_map_send_auth_info_req_t);
	ofd = txn->ctx.ofd;
	osmo_timer_del(&txn->ctx.timer);			/* Remove the timeout timer */

	MEM(res = talloc_zero(txn, sigtran_map_send_auth_info_res_t));
	txn->response.type = SIGTRAN_RESPONSE_OK;
	txn->response.data = res;
	last = &res->vector;	/* Head of vector list */

#define sigtran_memdup(_x) \
	do { \
		p++; \
		DEBUG4("Start 0x%02x len %u", (unsigned int)(tcap - p), p[0]); \
		if (p[0] >= (len - (p - tcap))) { \
			ERROR("Invalid length %u specified for vector component", p[0]); \
			return -1; \
		} \
		vec->_x = talloc_memdup(vec, p + 1, p[0]); \
		talloc_set_type(vec->_x, uint8_t); \
		p += p[0] + 1; \
	} while (0)

	end = tcap + msgb_l3len(msg);

	/*
	 *	And now pretend to parse the response by looking at
	 *	fixed offsets in the response data...
	 *
	 *	Umm.. fixme?
	 */
	if (req->version == 2) {
		p = tcap + 0x40;
		while (p < end) {
			if ((p[0] != 0x30) || (p[1] != 0x22)) {
				DEBUG4("Breaking out of parsing loop at %x", (uint32_t)(p - tcap));
				break;
			}
			p += 2;

			MEM(vec = talloc_zero(res, sigtran_vector_t));
			vec->type = SIGTRAN_VECTOR_TYPE_SIM_TRIPLETS;

			sigtran_memdup(sim.rand);
			sigtran_memdup(sim.sres);
			sigtran_memdup(sim.kc);

			*last = vec;
			last = &(vec->next);
		}
	} else if (req->version == 3) {
		p = tcap + 0x40; /* fixed offset for now */

		MEM(vec = talloc_zero(res, sigtran_vector_t));
		vec->type = SIGTRAN_VECTOR_TYPE_UMTS_QUINTUPLETS;
		sigtran_memdup(umts.rand);
		sigtran_memdup(umts.xres);
		sigtran_memdup(umts.ck);
		sigtran_memdup(umts.ik);
		sigtran_memdup(umts.authn);

		*last = vec;
	}

	if (sigtran_event_submit(ofd, txn) < 0) {
		ERROR("Failed informing event client of result: %s", fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Wrapper to pass data down to MTP3 layer for processing
 *
 * This is the write callback for the SCCP Code.
 */
static void sigtran_sccp_outgoing(UNUSED struct sccp_connection *sscp_conn,
				  struct msgb *msg, UNUSED void *write_ctx, void *ctx)
{
	sigtran_conn_t *conn = talloc_get_type_abort(ctx, sigtran_conn_t);

	mtp_link_set_submit_sccp_data(conn->mtp3_link_set, -1, msg->l2h, msgb_l2len(msg));

	msgb_free(msg);	/* Apparently our responsibility to free this message */
}

/** Wrapper to pass data off to libsccp for processing
 *
 * @param set	Link set data was received on.
 * @param msg 	Data from the lower layer.
 * @param sls	Link number the data was received on.
 */
void sigtran_sccp_incoming(UNUSED struct mtp_link_set *set, struct msgb *msg, UNUSED int sls)
{
	sccp_system_incoming(msg);
}

/** Initialise libscctp
 *
 */
int sigtran_sscp_init(sigtran_conn_t *conn)
{
	sccp_set_log_area(DSCCP);

	sccp_system_init(sigtran_sccp_outgoing, NULL);					/* Set write callback */
	sccp_set_variant(SCCP_VARIANT_ANSI);
	sccp_set_read(&conn->conf->sccp_calling_sockaddr, sigtran_tcap_incoming, conn);	/* Set data_available callback */

	return 0;
}

int sigtran_sccp_global_init(void)
{
	if (txn_tree) {
		txn_tree_inst++;
		return 0;
	}

	txn_tree = rbtree_talloc_alloc(NULL, sigtran_txn_cmp, sigtran_transaction_t, false, 0);
	if (!txn_tree) return -1;

	txn_tree_inst++;
	return 0;
}

void sigtran_sccp_global_free(void)
{
	if (--txn_tree_inst > 0) return;

	talloc_free(txn_tree);
	txn_tree = NULL;
}
