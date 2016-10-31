/* Run M2UA over SCTP here */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 */

#include <sctp_m2ua.h>
#include <bsc_data.h>
#include <cellmgr_debug.h>
#include <counter.h>
#include <mtp_data.h>
#include <mtp_pcap.h>

#include <osmocom/core/talloc.h>

#include <osmocom/sigtran/m2ua_types.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>

#define SCTP_PPID_M2UA 2


int sctp_m2ua_conn_count(struct sctp_m2ua_transport *trans)
{
	int count = 0;
	struct sctp_m2ua_conn *conn;

	llist_for_each_entry(conn, &trans->conns, entry)
		count += 1;

	return count;
}

static struct mtp_m2ua_link *find_m2ua_link(struct sctp_m2ua_transport *trans, int link_index)
{
	struct mtp_m2ua_link *link;

	llist_for_each_entry(link, &trans->links, entry) {
		if (link->link_index == link_index)
			return link;
	}

	return NULL;
}

static void link_down(struct mtp_link *link)
{
	rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_ERROR]);
	mtp_link_down(link);
}

static void m2ua_conn_destroy(struct sctp_m2ua_conn *conn)
{
	struct mtp_m2ua_link *link;

	close(conn->queue.bfd.fd);
	osmo_fd_unregister(&conn->queue.bfd);
	osmo_wqueue_clear(&conn->queue);
	llist_del(&conn->entry);

	llist_for_each_entry(link, &conn->trans->links, entry) {
		if (link->conn != conn)
			continue;

		if (link->established)
			link_down(link->base);
		link->established = 0;
		link->asp_active = 0;
		link->active = 0;
		link->conn = NULL;
	}

	talloc_free(conn);

	#warning "Notify any other AS(P) for failover scenario"
}

static int m2ua_conn_send(struct sctp_m2ua_conn *conn,
			  struct xua_msg *m2ua,
			  struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	msg = xua_to_msg(M2UA_VERSION, m2ua);
	if (!msg)
		return -1;

	/* save the OOB data in front of the message */
	msg->l2h = msg->data;
	msgb_push(msg, sizeof(*info));
	memcpy(msg->data, info, sizeof(*info));

	if (osmo_wqueue_enqueue(&conn->queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int m2ua_conn_send_ntfy(struct mtp_m2ua_link *link,
			       struct sctp_m2ua_conn *conn,
			       struct sctp_sndrcvinfo *info)
{
	struct xua_msg *msg;
	uint16_t state[2];
	uint32_t ident;
	int rc;

	msg = xua_msg_alloc();
	if (!msg)
		return -1;
	msg->hdr.msg_class = M2UA_CLS_MGMT;
	msg->hdr.msg_type = M2UA_MGMT_NTFY;

	/* state change */
	state[0] = ntohs(M2UA_STP_AS_STATE_CHG);

	if (link->asp_active)
		state[1] = ntohs(M2UA_STP_AS_ACTIVE);
	else
		state[1] = ntohs(M2UA_STP_AS_INACTIVE);

	xua_msg_add_data(msg, MUA_TAG_STATUS, 4, (uint8_t *) state);
	xua_msg_add_data(msg, MUA_TAG_ASP_IDENT, 4, conn->asp_ident);

	ident = htonl(link->link_index);
	xua_msg_add_data(msg, MUA_TAG_IDENT_INT, 4, (uint8_t *) &ident);

	rc = m2ua_conn_send(conn, msg, info);
	xua_msg_free(msg);

	return rc;
}

static int m2ua_handle_asp_ack(struct sctp_m2ua_conn *conn,
			       struct xua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	struct sctp_m2ua_transport *trans = conn->trans;
	struct sctp_m2ua_conn *tmp;
	struct xua_msg_part *asp_ident;
	struct xua_msg *ack;

	asp_ident = xua_msg_find_tag(m2ua, MUA_TAG_ASP_IDENT);
	if (!asp_ident) {
		LOGP(DINP, LOGL_ERROR, "ASP UP lacks ASP IDENT\n");
		return -1;
	}
	if (asp_ident->len != 4) {
		LOGP(DINP, LOGL_ERROR, "ASP Ident needs to be four byte.\n");
		return -1;
	}

	/* TODO: Better handling for fail over is needed here */
	ack = xua_msg_alloc();
	if (!ack) {
		LOGP(DINP, LOGL_ERROR, "Failed to create response\n");
		return -1;
	}

	ack->hdr.msg_class = M2UA_CLS_ASPSM;
	ack->hdr.msg_type = M2UA_ASPSM_UP_ACK;
	if (m2ua_conn_send(conn, ack, info) != 0) {
		xua_msg_free(ack);
		return -1;
	}

	memcpy(conn->asp_ident, asp_ident->dat, 4);
	conn->asp_up = 1;

	/* some verification about the ASPs */
	llist_for_each_entry(tmp, &trans->conns, entry) {
		if (tmp == conn)
			continue;
		if (memcmp(tmp->asp_ident, conn->asp_ident, 4) != 0)
			continue;
		LOGP(DINP, LOGL_ERROR,
		     "Two active SCTP conns with %d.%d.%d.%d on %p, %p\n",
		     conn->asp_ident[0], conn->asp_ident[1],
		     conn->asp_ident[2], conn->asp_ident[3],
		     tmp, conn);
	}

	xua_msg_free(ack);
	return 0;
}

static int m2ua_handle_asp(struct sctp_m2ua_conn *conn,
			   struct xua_msg *m2ua, struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_ASPSM_UP:
		m2ua_handle_asp_ack(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_asptm_act(struct sctp_m2ua_conn *conn,
				 struct xua_msg *m2ua,
				 struct sctp_sndrcvinfo *info)
{
	struct xua_msg_part *part;
	struct xua_msg *ack;

	ack = xua_msg_alloc();
	if (!ack)
		return -1;

	ack->hdr.msg_class = M2UA_CLS_ASPTM;
	ack->hdr.msg_type = M2UA_ASPTM_ACTIV_ACK;

	/*
	 * Move things over to this connection now.
	 */
	llist_for_each_entry(part, &m2ua->headers, entry) {
		struct mtp_m2ua_link *link;
		uint32_t interf;


		if (part->tag != MUA_TAG_IDENT_INT)
			continue;
		if (part->len != 4)
			continue;

		memcpy(&interf, part->dat, 4);
		link = find_m2ua_link(conn->trans, ntohl(interf));
		if (!link) {
			LOGP(DINP, LOGL_ERROR,
			     "M2UA Link index %d is not configured.\n", ntohl(interf));
			continue;
		}

		link->conn = conn;
		link->asp_active = 1;
		xua_msg_add_data(ack, MUA_TAG_IDENT_INT, 4, (uint8_t *) &interf);
	}


	if (m2ua_conn_send(conn, ack, info) != 0) {
		xua_msg_free(ack);
		return -1;
	}

	/* now again send NTFY on all these links */
	llist_for_each_entry(part, &m2ua->headers, entry) {
		struct mtp_m2ua_link *link;
		uint32_t interf;


		if (part->tag != MUA_TAG_IDENT_INT)
			continue;
		if (part->len != 4)
			continue;

		memcpy(&interf, part->dat, 4);
		link = find_m2ua_link(conn->trans, ntohl(interf));
		if (!link)
			continue;
		m2ua_conn_send_ntfy(link, conn,	info);
	}

	xua_msg_free(ack);
	return 0;
}

static int m2ua_handle_asptm(struct sctp_m2ua_conn *conn,
			     struct xua_msg *m2ua,
			     struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_ASPTM_ACTIV:
		m2ua_handle_asptm_act(conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_state_req(struct mtp_m2ua_link *link,
				 struct sctp_m2ua_conn *conn,
				 struct xua_msg *m2ua,
				 struct sctp_sndrcvinfo *info)
{
	struct xua_msg_part *state;
	struct xua_msg *conf;
	uint32_t index;
	int req;

	state = xua_msg_find_tag(m2ua, M2UA_TAG_STATE_REQ);
	if (!state || state->len != 4) {
		LOGP(DINP, LOGL_ERROR, "Mandantory state request not present.\n");
		return -1;
	}

	memcpy(&req, state->dat, 4);
	req = ntohl(req);

	switch (req) {
	case M2UA_STATUS_EMER_SET:
		conf = xua_msg_alloc();
		if (!conf)
			return -1;

		index = htonl(link->link_index);
		req = htonl(req);
		conf->hdr.msg_class = M2UA_CLS_MAUP;
		conf->hdr.msg_type = M2UA_MAUP_STATE_CON;
		xua_msg_add_data(conf, MUA_TAG_IDENT_INT, 4, (uint8_t *) &index);
		xua_msg_add_data(conf, M2UA_TAG_STATE_REQ, 4, (uint8_t *) &req);
		if (m2ua_conn_send(conn, conf, info) != 0) {
			xua_msg_free(conf);
			return -1;
		}
		xua_msg_free(conf);

		LOGP(DINP, LOGL_NOTICE, "M2UA link-index %d is running.\n", link->link_index);
		link->active = 1;
		mtp_link_up(link->base);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unknown STATE Request: %d\n", req);
		break;
	}

	return 0;
}

static int m2ua_handle_est_req(struct mtp_m2ua_link *link,
			       struct sctp_m2ua_conn *conn,
			       struct xua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	uint32_t index;
	struct xua_msg *conf;

	conf = xua_msg_alloc();
	if (!conf)
		return -1;

	conf->hdr.msg_class = M2UA_CLS_MAUP;
	conf->hdr.msg_type = M2UA_MAUP_EST_CON;

	index = htonl(link->link_index);
	xua_msg_add_data(conf, MUA_TAG_IDENT_INT, 4, (uint8_t *) &index);

	if (m2ua_conn_send(conn, conf, info) != 0) {
		link->established = 0;
		xua_msg_free(conf);
		return -1;
	}

	link->established = 1;
	xua_msg_free(conf);
	return 0;
}

static int m2ua_handle_rel_req(struct mtp_m2ua_link *link,
			       struct sctp_m2ua_conn *conn,
			       struct xua_msg *m2ua,
			       struct sctp_sndrcvinfo *info)
{
	uint32_t index;
	struct xua_msg *conf;

	conf = xua_msg_alloc();
	if (!conf)
		return -1;

	conf->hdr.msg_class = M2UA_CLS_MAUP;
	conf->hdr.msg_type = M2UA_MAUP_REL_CON;

	index = htonl(link->link_index);
	xua_msg_add_data(conf, MUA_TAG_IDENT_INT, 4, (uint8_t *) &index);

	if (m2ua_conn_send(conn, conf, info) != 0) {
		xua_msg_free(conf);
		return -1;
	}

	link->established = 0;
	link->active = 0;
	LOGP(DINP, LOGL_NOTICE, "M2UA/Link link-index %d is released.\n", link->link_index);
	link_down(link->base);
	xua_msg_free(conf);
	return 0;
}

static int m2ua_handle_data(struct mtp_m2ua_link *_link,
			    struct sctp_m2ua_conn *conn,
			    struct xua_msg *m2ua,
			    struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	struct xua_msg_part *data;
	struct mtp_link *link;

	data = xua_msg_find_tag(m2ua, M2UA_TAG_DATA);
	if (!data) {
		LOGP(DINP, LOGL_ERROR, "No DATA in DATA message.\n");
		return -1;
	}

	if (data->len > 2048) {
		LOGP(DINP, LOGL_ERROR, "TOO much data for us to handle.\n");
		return -1;
	}

	msg = msgb_alloc(2048, "m2ua-data");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
		return -1;
	}

	msg->l2h = msgb_put(msg, data->len);
	memcpy(msg->l2h, data->dat, data->len);

	link = _link->base;
	if (!link->blocked) {
		mtp_handle_pcap(link, NET_IN, msg->l2h, msgb_l2len(msg));
		mtp_link_set_data(link, msg);
	}
	msgb_free(msg);

	return 0;
}

static int m2ua_handle_maup(struct mtp_m2ua_link *link,
			    struct sctp_m2ua_conn *conn,
			    struct xua_msg *m2ua,
			    struct sctp_sndrcvinfo *info)
{
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "Link is required.\n");
		return -1;
	}

	/* fixup for a broken MSC */
	if (!link->conn && m2ua->hdr.msg_type == M2UA_MAUP_STATE_REQ) {
		LOGP(DINP, LOGL_NOTICE,
		     "No ASP Activate but no connection is on link-index %d.\n",
		     link->link_index);
		link->conn = conn;
		link->asp_active = 1;
	}

	if (link->conn != conn) {
		LOGP(DINP, LOGL_ERROR,
		     "Someone forgot the ASP Activate on link-index %d\n",
		     link->link_index);
		return -1;
	}

	switch (m2ua->hdr.msg_type) {
	case M2UA_MAUP_STATE_REQ:
		m2ua_handle_state_req(link, conn, m2ua, info);
		break;
	case M2UA_MAUP_EST_REQ:
		m2ua_handle_est_req(link, conn, m2ua, info);
		break;
	case M2UA_MAUP_REL_REQ:
		m2ua_handle_rel_req(link, conn, m2ua, info);
		break;
	case M2UA_MAUP_DATA:
		m2ua_handle_data(link, conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m2ua->hdr.msg_type);
		break;
	}

	return 0;
}

static int m2ua_handle_mgmt(struct sctp_m2ua_conn *conn,
			    struct xua_msg *m2ua, struct sctp_sndrcvinfo *info)
{
	switch (m2ua->hdr.msg_type) {
	case M2UA_MGMT_ERROR:
		LOGP(DINP, LOGL_ERROR, "We did something wrong. Error...\n");
		break;
	case M2UA_MGMT_NTFY:
		LOGP(DINP, LOGL_NOTICE, "There was a notiy.. but we should only send it.\n");
		break;
	}

	return 0;
}

static int m2ua_find_interface(struct xua_msg *m2ua, int def)
{
	struct xua_msg_part *ident;

	ident = xua_msg_find_tag(m2ua, MUA_TAG_IDENT_INT);
	if (ident && ident->len == 4) {
		memcpy(&def, ident->dat, 4);
		def = ntohl(def);
	}

	return def;
}

static int m2ua_conn_handle(struct sctp_m2ua_conn *conn,
			    struct msgb *msg, struct sctp_sndrcvinfo *info)
{
	struct mtp_m2ua_link *link;
	struct xua_msg *m2ua;
	m2ua = xua_from_msg(M2UA_VERSION, msg->len, msg->data);
	if (!m2ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse the message.\n");
		return -1;
	}

	link = find_m2ua_link(conn->trans, m2ua_find_interface(m2ua, 0));

	switch (m2ua->hdr.msg_class) {
	case M2UA_CLS_MGMT:
		m2ua_handle_mgmt(conn, m2ua, info);
		break;
	case M2UA_CLS_ASPSM:
		m2ua_handle_asp(conn, m2ua, info);
		break;
	case M2UA_CLS_ASPTM:
		m2ua_handle_asptm(conn, m2ua, info);
		break;
	case M2UA_CLS_MAUP:
		m2ua_handle_maup(link, conn, m2ua, info);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_class %d\n",
			m2ua->hdr.msg_class);
		break;
	}

	xua_msg_free(m2ua);
	return 0;
}

static int m2ua_conn_read(struct osmo_fd *fd)
{
	struct sockaddr_in addr;
	struct sctp_sndrcvinfo info;
	socklen_t len = sizeof(addr);
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(2048, "m2ua buffer");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate buffer.\n");
		m2ua_conn_destroy(fd->data);
		return -1;
	}

	memset(&info, 0, sizeof(info));
	memset(&addr, 0, sizeof(addr));
	rc = sctp_recvmsg(fd->fd, msg->data, msg->data_len,
			  (struct sockaddr *) &addr, &len, &info, NULL);
	if (rc <= 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to read: %d errno: %d\n",
			rc, errno);
		msgb_free(msg);
		m2ua_conn_destroy(fd->data);
		return -1;
	}

	if (ntohl(info.sinfo_ppid) != SCTP_PPID_M2UA) {
		LOGP(DINP, LOGL_ERROR, "Only M2UA is allowed on this socket.\n");
		msgb_free(msg);
		return -1;
	}

	msgb_put(msg, rc);
	LOGP(DINP, LOGL_DEBUG, "Read %d on stream: %d ssn: %d assoc: %d\n",
		rc, info.sinfo_stream, info.sinfo_ssn, info.sinfo_assoc_id);
	m2ua_conn_handle(fd->data, msg, &info);
	msgb_free(msg);
	return 0;
}

static int sctp_m2ua_write(struct mtp_link *link, struct msgb *msg)
{
	struct mtp_m2ua_link *mlink;
	struct sctp_sndrcvinfo info;
	struct xua_msg *m2ua;
	uint32_t interface;

	mlink = (struct mtp_m2ua_link *) link->data;


	if (!mlink->conn) {
		LOGP(DINP, LOGL_ERROR, "M2UA write with no ASP for %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		goto clean;
	}

	if (!mlink->asp_active || !mlink->established || !mlink->active) {
		LOGP(DINP, LOGL_ERROR, "ASP not ready  for %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		goto clean;
	}

	m2ua = xua_msg_alloc();
	if (!m2ua)
		goto clean;

	mtp_handle_pcap(link, NET_OUT, msg->data, msg->len);

	m2ua->hdr.msg_class = M2UA_CLS_MAUP;
	m2ua->hdr.msg_type = M2UA_MAUP_DATA;

	interface = htonl(mlink->link_index);
	xua_msg_add_data(m2ua, MUA_TAG_IDENT_INT, 4, (uint8_t *) &interface);
	xua_msg_add_data(m2ua, M2UA_TAG_DATA, msg->len, msg->data);

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 1;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M2UA);

	m2ua_conn_send(mlink->conn, m2ua, &info);
	xua_msg_free(m2ua);

clean:
	msgb_free(msg);
	return 0;
}

static int m2ua_conn_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;
	struct sctp_sndrcvinfo info;
	memcpy(&info, msg->data, sizeof(info));

	ret = sctp_send(fd->fd, msg->l2h, msgb_l2len(msg),
			&info, 0);

	if (ret != msgb_l2len(msg))
		LOGP(DINP, LOGL_ERROR, "Failed to send %d.\n", ret);

	return 0;
}

static int sctp_trans_accept(struct osmo_fd *fd, unsigned int what)
{
	struct sctp_event_subscribe events;
	struct sctp_m2ua_transport *trans;
	struct sctp_m2ua_conn *conn;
	struct sockaddr_in addr;
	socklen_t len;
	int s, ret, count;

	len = sizeof(addr);
	s = accept(fd->fd, (struct sockaddr *) &addr, &len);
	if (s < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to accept.\n");
		return -1;
	}

	trans = fd->data;
	if (!trans->started) {
		LOGP(DINP, LOGL_NOTICE, "The link is not started.\n");
		close(s);
		return -1;
	}

	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	ret = setsockopt(s, SOL_SCTP, SCTP_EVENTS, &events, sizeof(events));
	if (ret != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enable SCTP Events. Closing socket.\n");
		close(s);
		return -1;
	}

	LOGP(DINP, LOGL_NOTICE, "Got a new SCTP connection.\n");
	conn = talloc_zero(fd->data, struct sctp_m2ua_conn);
	if (!conn) {
		LOGP(DINP, LOGL_ERROR, "Failed to create.\n");
		close(s);
		return -1;
	}

	conn->trans = trans;

	osmo_wqueue_init(&conn->queue, 10);
	conn->queue.bfd.fd = s;
	conn->queue.bfd.data = conn;
	conn->queue.bfd.when = BSC_FD_READ;
	conn->queue.read_cb = m2ua_conn_read;
	conn->queue.write_cb = m2ua_conn_write;

	if (osmo_fd_register(&conn->queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register.\n");
		close(s);
		talloc_free(conn);
		return -1;
	}

	llist_add_tail(&conn->entry, &trans->conns);


	count = sctp_m2ua_conn_count(trans);
	LOGP(DINP, LOGL_NOTICE, "Now having %d SCTP connection(s).\n", count);
	return 0;
}

static int sctp_m2ua_dummy(struct mtp_link *link)
{
	return 0;
}

static int sctp_m2ua_reset(struct mtp_link *_link)
{
	struct mtp_m2ua_link *link = (struct mtp_m2ua_link *) _link->data;

	/*
	 * TODO: Send a Release Indication? Send NTFY to other ASPs to
	 * ask them to activate the link? What should we do here? Right
	 * now do exactly nothing.
	 */
	LOGP(DINP, LOGL_ERROR,
	     "M2UA link-index %d not doing the reset.\n", link->link_index);

	if (link->conn && link->asp_active && link->established)
		mtp_link_start_link_test(_link);

	return 0;
}

struct sctp_m2ua_transport *sctp_m2ua_transp_create(struct bsc_data *bsc)
{
	struct sctp_m2ua_transport *trans;

	trans = talloc_zero(bsc, struct sctp_m2ua_transport);
	if (!trans) {
		LOGP(DINP, LOGL_ERROR, "Remove the talloc.\n");
		return NULL;
	}

	INIT_LLIST_HEAD(&trans->conns);
	INIT_LLIST_HEAD(&trans->links);


	return trans;
}

int sctp_m2ua_transport_bind(struct sctp_m2ua_transport *trans,
			     const char *ip, int port)
{
	int sctp;
	struct sockaddr_in addr;

	sctp = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (!sctp) {
		LOGP(DINP, LOGL_ERROR, "Failed to create socket.\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (bind(sctp, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind.\n");
		close(sctp);
		return -2;
	}

	if (listen(sctp, 1) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to listen.\n");
		close(sctp);
		return -3;
	}

	trans->bsc.fd = sctp;
	trans->bsc.data = trans;
	trans->bsc.cb = sctp_trans_accept;
	trans->bsc.when = BSC_FD_READ;

	if (osmo_fd_register(&trans->bsc) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register the fd.\n");
		close(sctp);
		return -4;
	}

	return 0;
}

struct mtp_m2ua_link *mtp_m2ua_link_init(struct mtp_link *blnk)
{
	struct sctp_m2ua_transport *trans;
	struct mtp_m2ua_link *lnk;

	lnk = talloc_zero(blnk, struct mtp_m2ua_link);
	if (!lnk) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	/* make sure we can resolve it both ways */
	lnk->base = blnk;
	blnk->data = lnk;
	blnk->type = SS7_LTYPE_M2UA;

	/* remember we have a link here */
	trans = blnk->set->bsc->m2ua_trans;
	llist_add_tail(&lnk->entry, &trans->links);

	lnk->base->shutdown = sctp_m2ua_reset;
	lnk->base->clear_queue = sctp_m2ua_dummy;
	lnk->base->reset = sctp_m2ua_reset;
	lnk->base->write = sctp_m2ua_write;

	lnk->transport = trans;
	return lnk;
}
