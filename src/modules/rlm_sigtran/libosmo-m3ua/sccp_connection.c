/* Interaction with the SCCP subsystem */
/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <openbsc/ipaccess.h>
#include <openbsc/signal.h>

#include <osmocom/core/talloc.h>
#include <osmocom/sccp/sccp.h>

/* SCCP helper */
#define SCCP_IT_TIMER 60

static void free_queued(sigtran_conn_t *conn)
{
	struct msgb *msg;

	while (!llist_empty(&conn->ssccp->ccp_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&conn->sccp->sccp_queue);
		msgb_free(msg);
	}

	conn->sccp_queue_size = 0;
}

static void send_queued(sigtran_conn_t *conn)
{
	struct msgb *msg;

	while (!llist_empty(&conn->sccp->sccp_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&conn->sccp->sccp_queue);
		sccp_connection_write(conn->sccp->sccp, msg);
		msgb_free(msg);
		conn->sccp->sccp_queue_size -= 1;
	}
}

/** Forward data down to the MTP3 layer
 *
 */
static void sccp_outgoing_data(struct sccp_connection *sccp,
			       struct msgb *msg, unsigned int len)
{
	sigtran_conn_t *conn = talloc_get_type_abort(sccp->ctx_data, sigtran_conn_t);

	mtp_link_set_send(conn->mtp3_link_set, msg);
}

static void sccp_outgoing_state(struct sccp_connection *sccp, int old_state)
{
	sigtran_conn_t *conn = talloc_get_type_abort(sccp->ctx_data, sigtran_conn_t);

	if (sccp->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		if (conn->sccp) {
			LOGP(DMSC, LOGL_ERROR, "ERROR: The lchan is still associated\n.");
		}
		free_queued(conn);
		sccp_connection_free(sccp);
		conn->sccp = NULL;
	} else if (sccp->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_DEBUG, "Connection established: %p\n", sccp);

		osmo_timer_del(&conn->sccp->sccp_cc_timeout);
		osmo_timer_schedule(&conn->sccp->sccp_it_timeout, SCCP_IT_TIMER, 0);

		send_queued(conn);
	}
}

static void sccp_it_timeout(void *_data)
{
	sigtran_conn_t *conn = talloc_get_type_abort(_data, sigtran_conn_t);

	sccp_connection_send_it(conn->sccp);
	osmo_timer_schedule(&conn->sccp_it_timeout, SCCP_IT_TIMER, 0);
}

static void sccp_cc_timeout(void *_data)
{
	sigtran_conn_t *conn = talloc_get_type_abort(_data, sigtran_conn_t);

	if (data->sccp->connection_state >= SCCP_CONNECTION_STATE_ESTABLISHED) return;

	LOGP(DMSC, LOGL_ERROR, "The connection was never established.\n");
	bsc_sccp_force_free(data);
}

static void msc_sccp_write_ipa(struct sccp_connection *conn, struct msgb *msg,
			      void *global_ctx, void *ctx)
{
	struct gsm_network *net = (struct gsm_network *) global_ctx;
	msc_queue_write(net->msc_data->msc_con, msg, IPAC_PROTO_SCCP);
}

static int msc_sccp_accept(struct sccp_connection *connection, void *data)
{
	LOGP(DMSC, LOGL_DEBUG, "Rejecting incoming SCCP connection.\n");
	return -1;
}

static int msc_sccp_read(struct msgb *msgb, unsigned int length, void *data)
{
	struct gsm_network *net = (struct gsm_network *) data;
	return bsc_handle_udt(net, net->msc_data->msc_con, msgb, length);
}

int sigtran_sccp_enque(struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	struct sccp_connection *sccp = conn->sccp;

	if (sccp->connection_state > SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_ERROR, "Connection closing, dropping packet on: %p\n", sccp);
		msgb_free(msg);
	} else if (sccp->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED
		   && conn->sccp_queue_size == 0) {
		sccp_connection_write(sccp, msg);
		msgb_free(msg);
	} else if (conn->sccp_queue_size > 10) {
		LOGP(DMSC, LOGL_ERROR, "Connection closing, dropping packet on: %p\n", sccp);
		msgb_free(msg);
	} else {
		LOGP(DMSC, LOGL_DEBUG, "Queueing packet on %p. Queue size: %d\n", sccp, conn->sccp_queue_size);
		conn->sccp_queue_size += 1;
		msgb_enqueue(&conn->sccp_queue, msg);
	}

	return 0;
}

static int _sigtran_sccp_conn_free(sigtran_sccp_conn_t *sccp)
{
	osmo_timer_del(&sccp->sccp_it_timeout);
	osmo_timer_del(&sccp->sccp_cc_timeout);
	free_queued(sccp);
	sccp_connection_force_free(sccp);
	llist_del(&sccp->sccp_queue);

	return 0;
}

int sigtran_sccp_conn_patch(sigtran_conn_t *conn)
{
	struct sccp_connection *sccp;

	sccp = sccp_connection_socket();
	if (!sccp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate memory.\n");
		return -1;
	}

	conn->sccp = talloc_zero(conn, sigtran_sccp_conn_t);
	talloc_set_destructor(conn->sccp, _sigtran_sccp_conn_free);

	/* callbacks */
	sccp->state_cb = sccp_outgoing_state;
	sccp->data_cb = sccp_outgoing_data;
	sccp->data_ctx = conn;

	/* prepare the timers */
	conn->sccp->sccp_it_timeout.cb = sccp_it_timeout;
	conn->sccp->sccp_it_timeout.data = bsc_con;
	conn->scpp->sccp_cc_timeout.cb = sccp_cc_timeout;
	conn->sccp->sccp_cc_timeout.data = bsc_con;

	INIT_LLIST_HEAD(&conn->sccp->sccp_queue);

	conn->sccp->sccp = sccp;

	return 0;
}

int sigtran_sccp_open_connection(sigtran_conn_t *conn, struct msgb *msg)
{
	osmo_timer_schedule(&conn->sccp->sccp_cc_timeout, 10, 0);
	sccp_connection_connect(conn->sccp->sccp, &sccp_ssn_bssap, msg);
	msgb_free(msg);

	return 0;
}

int sigtran_sscp_init(struct gsm_network *gsmnet)
{
	sccp_set_log_area(DSCCP);
	sccp_system_init(msc_sccp_write_ipa, gsmnet);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, gsmnet);

	osmo_signal_register_handler(SS_MSC, handle_msc_signal, gsmnet);

	return 0;
}
