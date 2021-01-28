/* Run M3UA over SCTP here */
/* (C) 2015 by Holger Hans Peter Freyther
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

#include <sctp_m3ua.h>
#include <cellmgr_debug.h>
#include <string.h>
#include <bsc_data.h>
#include <counter.h>

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/m3ua_types.h>
#include <osmocom/sigtran/xua_types.h>
#include <osmocom/mtp/mtp_level3.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include <netinet/sctp.h>

#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define SCTP_PPID_M3UA 3

#define notImplemented()	\
		LOGP(DINP, LOGL_NOTICE, "%s not implemented.\n", __func__)

extern unsigned int __hack_opc, __hack_dpc;

static struct xua_msg *xua_from_part(struct xua_msg_part *part)
{
	size_t len = part->len;
	uint8_t *data = part->dat;
	struct xua_parameter_hdr *par;

	struct xua_msg *msg;
	uint16_t pos, par_len, padding;
	int rc;

	msg = xua_msg_alloc();
	if (!msg)
		return NULL;
	pos = 0;

	while (pos + sizeof(*par) < len) {
		par = (struct xua_parameter_hdr *) &data[pos];
		par_len = ntohs(par->len);

		if (pos + par_len > len || par_len < 4)
			goto fail;

		rc = xua_msg_add_data(msg, ntohs(par->tag), par_len - 4, par->data);
		if (rc != 0)
			goto fail;

		pos += par_len;

		/* move over the padding */
		padding = (4 - (par_len % 4)) & 0x3;
		pos += padding;
	}

	/* TODO: parse */
	return msg;

fail:
	LOGP(DINP, LOGL_ERROR, "Failed to parse.\n");
	xua_msg_free(msg);
	return NULL;
}

/*
 * State machine code
 */
static void m3ua_handle_mgmt(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_aspsm(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_asptm(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_trans(struct mtp_m3ua_client_link *link, struct xua_msg *msg);
static void m3ua_handle_reg_rsp(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua);
static void m3ua_send_daud(struct mtp_m3ua_client_link *link, uint32_t pc);
static void m3ua_send_aspup(struct mtp_m3ua_client_link *link);
static void m3ua_send_aspac(struct mtp_m3ua_client_link *link);
static void m3ua_send_aspdn(struct mtp_m3ua_client_link *link);
static void m3ua_send_reg_req(struct mtp_m3ua_client_link *link, struct mtp_m3ua_reg_req *route);
static void m3ua_send_beat(void *data);

/*
 * boilerplate
 */
static int clear_link(struct mtp_m3ua_client_link *link);
static int m3ua_shutdown(struct mtp_link *mtp_link);
static void m3ua_start(void *data);
static void aspac_ack_timeout(void *data);
static void aspup_ack_timeout(void *data);
static void aspdn_ack_timeout(void *data);

static int m3ua_setnonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)  {
		LOGP(DINP, LOGL_ERROR, "Failed getting socket flags whilst setting O_NONBLOCK.\n");
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed setting O_NONBLOCK\n");
		return -1;
	}

	return flags;
}

static int m3ua_setblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)  {
		LOGP(DINP, LOGL_ERROR, "Failed getting socket flags whilst clearing O_NONBLOCK.\n");
		return -1;
	}

	if (!(flags & O_NONBLOCK)) return flags;

	flags ^= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed clearing O_NONBLOCK\n");
		return -1;
	}

	return flags;
}

static void schedule_restart(struct mtp_m3ua_client_link *link)
{
	link->connect_timer.data = link;
	link->connect_timer.cb = m3ua_start;
	osmo_timer_schedule(&link->connect_timer, 1, 0);
}

static void schedule_t_beat(struct mtp_m3ua_client_link *link)
{
	link->t_beat.data = link;
	link->t_beat.cb = m3ua_send_beat;
	osmo_timer_schedule(&link->t_beat, link->use_beat, 0);
}

static void schedule_aspup_t_ack(struct mtp_m3ua_client_link *link)
{
	link->t_ack.data = link;
	link->t_ack.cb = aspup_ack_timeout;
	osmo_timer_schedule(&link->t_ack, link->ack_timeout, 0);
}

static void schedule_aspac_t_ack(struct mtp_m3ua_client_link *link)
{
	link->t_ack.data = link;
	link->t_ack.cb = aspac_ack_timeout;
	osmo_timer_schedule(&link->t_ack, link->ack_timeout, 0);
}

static void schedule_aspdn_t_ack(struct mtp_m3ua_client_link *link)
{
	link->t_ack.data = link;
	link->t_ack.cb = aspdn_ack_timeout;
	osmo_timer_schedule(&link->t_ack, link->ack_timeout, 0);
}

static int clear_link(struct mtp_m3ua_client_link *link)
{
	if (link->queue.bfd.fd >= 0) {
		osmo_fd_unregister(&link->queue.bfd);
		close(link->queue.bfd.fd);
		link->queue.bfd.fd = -1;
	}
	osmo_wqueue_clear(&link->queue);
	link->aspsm_active = 0;
	link->asptm_active = 0;
	osmo_timer_del(&link->connect_timer);
	osmo_timer_del(&link->t_beat);
	osmo_timer_del(&link->t_ack);
	return 0;
}

static void fail_link(struct mtp_m3ua_client_link *link)
{
	/* We need to fail the link */
	m3ua_shutdown(link->base);
	mtp_link_down(link->base);
	schedule_restart(link);
}

static void aspac_ack_timeout(void *data)
{
	struct mtp_m3ua_client_link *link = data;

	LOGP(DINP, LOGL_ERROR, "ASPAC ACK not received. Closing it down.\n");
	fail_link(link);
}

static void aspup_ack_timeout(void *data)
{
	struct mtp_m3ua_client_link *link = data;

	LOGP(DINP, LOGL_ERROR, "ASPUP ACK not received. Closing it down.\n");
	fail_link(link);
}

static void aspdn_ack_timeout(void *data)
{
	struct mtp_m3ua_client_link *link = data;

	LOGP(DINP, LOGL_ERROR, "ASPDN ACK not received.  Cleaning up link\n");
	clear_link(link);
}

static void reg_rsp_timeout(void *data)
{
	struct mtp_m3ua_reg_req *route = data;

	LOGP(DINP, LOGL_ERROR, "REG_RSP %u not received. Closing it down.\n", route->local_rk_identifier);
	fail_link(route->link);
}

static int m3ua_conn_handle(struct mtp_m3ua_client_link *link,
				struct msgb *msg, struct sctp_sndrcvinfo *info)
{
	struct xua_msg *m3ua;
	m3ua = xua_from_msg(M3UA_VERSION, msg->len, msg->data);
	if (!m3ua) {
		LOGP(DINP, LOGL_ERROR, "Failed to parse the message.\n");
		return -1;
	}

	switch (m3ua->hdr.msg_class) {
	case M3UA_CLS_MGMT:
		m3ua_handle_mgmt(link, m3ua);
		break;
	case M3UA_CLS_ASPSM:
		m3ua_handle_aspsm(link, m3ua);
		break;
	case M3UA_CLS_ASPTM:
		m3ua_handle_asptm(link, m3ua);
		break;
	case M3UA_CLS_TRANS:
		m3ua_handle_trans(link, m3ua);
		break;
	case M3UA_CLS_RKM:
		m3ua_handle_reg_rsp(link, m3ua);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_class %d\n",
			m3ua->hdr.msg_class);
		break;
	}

	xua_msg_free(m3ua);
	return 0;
}

static int m3ua_conn_write(struct osmo_fd *ofd, struct msgb *msg)
{
	size_t ret;
	char strerrbuf[256];
	struct sctp_sndrcvinfo info;
	memcpy(&info, msg->data, sizeof(info));

	LOGP(DINP, LOGL_DEBUG, "Writing %u bytes to fd %i\n", msgb_l2len(msg), ofd->fd);
	ret = sctp_send(ofd->fd, msg->l2h, msgb_l2len(msg), &info, 0);

	if (ret != msgb_l2len(msg)) {
		/* Needs to be thread safe for library use in threaded programs */
		strerrbuf[0] = '\0';

		LOGP(DINP, LOGL_ERROR, "Failed writing to fd %i (only wrote %zu bytes): %s.\n",
		     ofd->fd, ret, strerror_r(errno, strerrbuf, sizeof(strerrbuf)));
	} else {
		LOGP(DINP, LOGL_DEBUG, "Wrote %u bytes to fd %i\n", msgb_l2len(msg), ofd->fd);
	}

	return 0;
}

static int m3ua_conn_send(struct mtp_m3ua_client_link *link,
			  struct xua_msg *m3ua,
			  struct sctp_sndrcvinfo *info)
{
	struct msgb *msg;
	msg = xua_to_msg(M3UA_VERSION, m3ua);
	if (!msg)
		return -1;

	/* save the OOB data in front of the message */
	msg->l2h = msg->data;
	msgb_push(msg, sizeof(*info));
	memcpy(msg->data, info, sizeof(*info));

	if (osmo_wqueue_enqueue(&link->queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue.\n");
		rate_ctr_inc(&link->base->ctrg->ctr[MTP_LNK_DRP]);
		rate_ctr_inc(&link->base->set->ctrg->ctr[MTP_LSET_TOTA_DRP_MSG]);
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int m3ua_conn_read(struct osmo_fd *fd)
{
	struct sockaddr_in addr;
	struct sctp_sndrcvinfo info;
	socklen_t len = sizeof(addr);
	struct mtp_m3ua_client_link *link = fd->data;
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(2048, "m3ua buffer");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate buffer.\n");
		fail_link(link);
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
		fail_link(link);
		return -1;
	}

	if (ntohl(info.sinfo_ppid) != SCTP_PPID_M3UA) {
		LOGP(DINP, LOGL_ERROR, "Only M3UA is allowed on this socket: %d\n",
			ntohl(info.sinfo_ppid));
		msgb_free(msg);
		return -1;
	}

	msgb_put(msg, rc);
	LOGP(DINP, LOGL_DEBUG, "Read %d on stream: %d ssn: %d assoc: %d\n",
		rc, info.sinfo_stream, info.sinfo_ssn, info.sinfo_assoc_id);
	m3ua_conn_handle(link, msg, &info);
	msgb_free(msg);
	return 0;
}

static int m3ua_sctp_assoc_complete(struct osmo_fd *ofd, unsigned int what)
{
	struct mtp_m3ua_client_link *link = ofd->data;
	int ret, err;
	socklen_t len = sizeof(err);

	osmo_fd_unregister(ofd);	/* Remove our connect callback */

	ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed getting socket error: %s (%i).\n", strerror(errno), errno);
	error:
		close(ofd->fd);
		ofd->fd = -1;
		fail_link(link);
		return -1;
	}

	if (err != 0) {
		LOGP(DINP, LOGL_ERROR, "SCTP association failed: %s (%i).\n", strerror(err), errno);
		goto error;
	}

	LOGP(DINP, LOGL_NOTICE, "SCTP association established\n");

//	if (m3ua_setblocking(ofd->fd) < 0) goto error;

	link->queue.bfd.fd = ofd->fd;
	link->queue.bfd.data = link;
	link->queue.bfd.when = BSC_FD_READ;
	link->queue.read_cb = m3ua_conn_read;
	link->queue.write_cb = m3ua_conn_write;

	if (osmo_fd_register(&link->queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register fd\n");
		goto error;
	}

	/* reset route state */
	llist_splice_init(&link->routes_active, &link->routes);
	llist_splice_init(&link->routes_failed, &link->routes);

	LOGP(DINP, LOGL_NOTICE, "Sending ASPUP\n");
	m3ua_send_aspup(link);
	schedule_aspup_t_ack(link);

	return 0;
}

static void m3ua_start(void *data)
{
	int sctp, ret, on = 1;
	struct mtp_m3ua_client_link *link = data;
	struct sctp_event_subscribe events;

	sctp = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (!sctp) {
		LOGP(DINP, LOGL_ERROR, "Failed to create socket.\n");
		return fail_link(link);
	}

	if (setsockopt(sctp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed setting reuseaddr: %s (%i).\n", strerror(errno), errno);
	error:
		close(sctp);
		return fail_link(link);
	}

	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	ret = setsockopt(sctp, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events));
	if (ret != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enable SCTP Events. Closing socket.\n");
		goto error;
	}

	if (bind(sctp, (struct sockaddr *) &link->local, sizeof(link->local)) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed binding local side of SCTP association: %s (%i).\n", strerror(errno), errno);
		goto error;
	}

	if (m3ua_setnonblocking(sctp) < 0) goto error;

	LOGP(DINP, LOGL_NOTICE, "Initialising SCTP association\n");

	ret = connect(sctp, (struct sockaddr *) &link->remote, sizeof(link->remote));
	if ((ret != 0) && (errno != EINPROGRESS)) {
		LOGP(DINP, LOGL_ERROR, "Failed creating SCTP association: %s (%i).\n", strerror(errno), errno);
		goto error;
	}

	link->connect.fd = sctp;
	link->connect.data = link;
	link->connect.when = BSC_FD_WRITE | BSC_FD_READ | BSC_FD_EXCEPT;
	link->connect.cb = m3ua_sctp_assoc_complete;

	if (osmo_fd_register(&link->connect) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register fd\n");
		goto error;
	}
}

static int m3ua_write(struct mtp_link *mtp_link, struct msgb *msg)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;
	struct sctp_sndrcvinfo info;
	struct xua_msg *m3ua;
	struct mtp_level_3_hdr *mtp_hdr;
	struct m3ua_protocol_data proto_data;
	uint8_t *proto_start;
	uint32_t netappear;

	if (!link->asptm_active) {
		LOGP(DINP, LOGL_ERROR, "ASP not ready for %d/%s of %d/%s.\n",
			mtp_link->nr, mtp_link->name, mtp_link->set->nr,
			mtp_link->set->name);
		goto clean;
	}

	/*
	 * TODO.. we could enhance the structure of mtp_link to
	 * have function pointers for operations like SLTM instead
	 * of doing what we do here.
	 * The entire m3ua episode (code + reading the spec) had a
	 * budget of < 2 man days so the amount of architecture changes
	 * we can do.
	 */

	/* TODO.. need to terminate MTPL3 locally... */

	/* TODO.. extract MTP information.. */
	mtp_hdr = (struct mtp_level_3_hdr *) msg->l2h;
	switch (mtp_hdr->ser_ind) {
	case MTP_SI_MNT_SNM_MSG:
	case MTP_SI_MNT_REG_MSG:
		LOGP(DINP, LOGL_ERROR,
			"Dropping SNM/REG message %d\n", mtp_hdr->ser_ind);
		goto clean;
		break;
	case MTP_SI_MNT_ISUP:
	case MTP_SI_MNT_SCCP:
	default:
		memset(&proto_data, 0, sizeof(proto_data));
		proto_data.opc = htonl(__hack_opc);
		proto_data.dpc = htonl(__hack_dpc);
		proto_data.sls = MTP_LINK_SLS(mtp_hdr->addr);
		proto_data.si = mtp_hdr->ser_ind;
		proto_data.ni = mtp_link->set->ni;

		msg->l3h = mtp_hdr->data;
		msgb_pull_to_l3(msg);

		netappear = htonl(1);

		proto_start = msgb_push(msg, sizeof(proto_data));
		memcpy(proto_start, &proto_data, sizeof(proto_data));
		break;
	};

	m3ua = xua_msg_alloc();
	if (!m3ua)
		goto clean;

	mtp_handle_pcap(mtp_link, NET_OUT, msg->data, msg->len);

	m3ua->hdr.msg_class = M3UA_CLS_TRANS;
	m3ua->hdr.msg_type = M3UA_TRANS_DATA;

	/*
	 * Modify the data...to create a true protocol data..
	 */
	xua_msg_add_data(m3ua, M3UA_TAG_NET_APPEAR, sizeof(netappear), (uint8_t *)&netappear);
	xua_msg_add_data(m3ua, M3UA_TAG_PROTO_DATA, msg->len, msg->data);

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 1;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	m3ua_conn_send(link, m3ua, &info);
	xua_msg_free(m3ua);

clean:
	msgb_free(msg);
	return 0;
}

static int m3ua_shutdown(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;

	if (link->asptm_active) {
		/* need to allow the event loop to actually send the message */
		m3ua_send_aspdn(link);
		schedule_aspdn_t_ack(link);
	} else
		clear_link(link);

	return 0;
}

static int m3ua_reset(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;

	/* stop things in case they run.. */
	m3ua_shutdown(mtp_link);
	schedule_restart(link);
	return 0;
}

static int clear_link_queue(struct mtp_link *mtp_link)
{
	struct mtp_m3ua_client_link *link = mtp_link->data;
	osmo_wqueue_clear(&link->queue);
	return 0;
}

struct mtp_m3ua_client_link *mtp_m3ua_client_link_init(struct mtp_link *blnk)
{
	struct mtp_m3ua_client_link *lnk;

	lnk = talloc_zero(blnk, struct mtp_m3ua_client_link);
	if (!lnk) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	/* make sure we can resolve it both ways */
	lnk->base = blnk;
	blnk->data = lnk;
	blnk->type = SS7_LTYPE_M3UA_CLIENT;

	/* do some checks for lower layer handling */
	blnk->skip_link_test = 1;

	lnk->base->write = m3ua_write;
	lnk->base->shutdown = m3ua_shutdown;
	lnk->base->reset = m3ua_reset;
	lnk->base->clear_queue = clear_link_queue;

	osmo_wqueue_init(&lnk->queue, 10);
	lnk->queue.bfd.fd = -1;

	INIT_LLIST_HEAD(&lnk->routes);
	INIT_LLIST_HEAD(&lnk->routes_active);
	INIT_LLIST_HEAD(&lnk->routes_failed);

	lnk->traffic_mode = 2;
	lnk->ack_timeout = 10;
	return lnk;
}

int mtp_m3ua_link_is_up(struct mtp_m3ua_client_link *link)
{
	return link->asptm_active;
}

struct mtp_m3ua_reg_req *mtp_m3ua_reg_req_add(struct mtp_m3ua_client_link *link)
{
	struct mtp_m3ua_reg_req *route;

	route = talloc_zero(link, struct mtp_m3ua_reg_req);
	if (!route) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate reg req.\n");
		return NULL;
	}

	/* make sure we can resolve it both ways */
	route->link = link;

	route->traffic_mode = link->traffic_mode;
	route->reg_rsp_timeout = 10;

	INIT_LLIST_HEAD(&route->opc);
	INIT_LLIST_HEAD(&route->si);

	llist_add_tail(&route->list, &link->routes);

	return route;
}

/*
 * asp handling
 */
static void m3ua_send_aspup(struct mtp_m3ua_client_link *link)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *aspup;
	uint32_t asp_ident;

	aspup = xua_msg_alloc();
	if (!aspup) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	aspup->hdr.msg_class = M3UA_CLS_ASPSM;
	aspup->hdr.msg_type = M3UA_ASPSM_UP;

	if (link->use_asp_ident) {
		asp_ident = htonl(link->link_index);
		xua_msg_add_data(aspup, MUA_TAG_ASP_IDENT, 4, (uint8_t *) &asp_ident);
	}

	m3ua_conn_send(link, aspup, &info);
	xua_msg_free(aspup);
}

static void m3ua_send_aspac(struct mtp_m3ua_client_link *link)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *aspac;
	uint32_t routing_ctx;
	uint32_t traffic_mode;

	aspac = xua_msg_alloc();
	if (!aspac) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	aspac->hdr.msg_class = M3UA_CLS_ASPTM;
	aspac->hdr.msg_type = M3UA_ASPTM_ACTIV;

	traffic_mode = htonl(link->traffic_mode);
	xua_msg_add_data(aspac, MUA_TAG_TRA_MODE, 4, (uint8_t *) &traffic_mode);

	if (link->use_routing_context) {
		routing_ctx = htonl(link->routing_context);
		xua_msg_add_data(aspac, MUA_TAG_ROUTING_CTX, 4, (uint8_t *) &routing_ctx);
	}

	m3ua_conn_send(link, aspac, &info);
	xua_msg_free(aspac);
}

static void m3ua_send_aspdn(struct mtp_m3ua_client_link *link)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *aspdn;

	aspdn = xua_msg_alloc();
	if (!aspdn) return;

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	aspdn->hdr.msg_class = M3UA_CLS_ASPSM;
	aspdn->hdr.msg_type = M3UA_ASPSM_DOWN;

	m3ua_conn_send(link, aspdn, &info);
	xua_msg_free(aspdn);
}

static void m3ua_send_daud(struct mtp_m3ua_client_link *link, uint32_t dpc)
{
	struct sctp_sndrcvinfo info;
	struct xua_msg *daud;
	uint32_t routing_ctx;

	daud = xua_msg_alloc();
	if (!daud) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	daud->hdr.msg_class = M3UA_CLS_SSNM;
	daud->hdr.msg_type = M3UA_SSNM_DAUD;

	if (link->use_routing_context) {
		routing_ctx = htonl(link->routing_context);
		xua_msg_add_data(daud, MUA_TAG_ROUTING_CTX, 4, (uint8_t *) &routing_ctx);
	}

	dpc = htonl(dpc);
	xua_msg_add_data(daud, MUA_TAG_AFF_PC, 4, (uint8_t *) &dpc);

	m3ua_conn_send(link, daud, &info);
	xua_msg_free(daud);
}

/* Shouldn't be required but may help work around some broken STPs */
static void m3ua_send_beat(void *arg)
{
	struct mtp_m3ua_client_link *link = talloc_get_type_abort(arg, struct mtp_m3ua_client_link);
	struct sctp_sndrcvinfo info;
	struct xua_msg *beat;
	uint64_t beat_seq;

	beat = xua_msg_alloc();
	if (!beat) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	beat->hdr.msg_class = M3UA_CLS_ASPSM;
	beat->hdr.msg_type = M3UA_ASPSM_BEAT;

	LOGP(DINP, LOGL_DEBUG, "Sending BEAT %" PRIu64 "\n", link->beat_seq);

	beat_seq = htonl(link->beat_seq);
	xua_msg_add_data(beat, MUA_TAG_ASP_IDENT, sizeof(beat_seq), (uint8_t *) &beat_seq);
	link->beat_seq++;

	m3ua_conn_send(link, beat, &info);
	xua_msg_free(beat);

	schedule_t_beat(link);		/* reschedule */
}

static void m3ua_send_reg_req(struct mtp_m3ua_client_link *link, struct mtp_m3ua_reg_req *route)
{
	static uint32_t rk_next;	/* Must be unique */

	struct sctp_sndrcvinfo info;
	struct xua_msg *regreq;

	uint32_t local_rk_identifier, routing_ctx, traffic_mode;
	uint32_t dpc;
	uint32_t network_appearance;
	struct mtp_m3ua_si *si_ptr;
	struct mtp_m3ua_opc *opc_ptr;

	struct llist_head *entry;
	size_t len;

	route->local_rk_identifier = ++rk_next;

	regreq = xua_msg_alloc();
	if (!regreq) {
		fail_link(link);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.sinfo_stream = 0;
	info.sinfo_assoc_id = 1;
	info.sinfo_ppid = htonl(SCTP_PPID_M3UA);

	regreq->hdr.msg_class = M3UA_CLS_RKM;
	regreq->hdr.msg_type = M3UA_RKM_REG_REQ;

	local_rk_identifier = htonl(route->local_rk_identifier);
	xua_msg_add_data(regreq, M3UA_TAG_LOCAL_ROUT_KEY_IDENT, 4, (uint8_t *)&local_rk_identifier);

	if (route->use_routing_context) {
		routing_ctx = htonl(route->routing_context);
		xua_msg_add_data(regreq, MUA_TAG_ROUTING_CTX, 4, (uint8_t *)&routing_ctx);
	}

	if (route->use_traffic_mode) {
		traffic_mode = htonl(route->traffic_mode);
		xua_msg_add_data(regreq, MUA_TAG_TRA_MODE, 4, (uint8_t *)&traffic_mode);
	}

	dpc = htonl(route->dpc);
	xua_msg_add_data(regreq, M3UA_TAG_DEST_PC, 4, (uint8_t *)&dpc);

	if (route->use_network_appearance) {
		network_appearance = htonl(route->network_appearance);
		xua_msg_add_data(regreq, M3UA_TAG_NET_APPEAR, 4, (uint8_t *)&network_appearance);
	}

	if (!llist_empty(&route->si)) {
		uint8_t	*val, *p;
		entry = NULL;

		len = 0;
		llist_for_each(entry, &route->si) len++;
		len = ((len / 4) + 1) * 4;

		p = val = talloc_zero_array(regreq, uint8_t, len);
		if (!p) {
			fail_link(link);
			talloc_free(regreq);
			return;
		}

		llist_for_each_entry(si_ptr, &route->si, list) *p++ = htonl(si_ptr->si);

		xua_msg_add_data(regreq, M3UA_TAG_SERV_IND, len, val);			/* Packed as an array */
		talloc_free(val);
	}

	if (!llist_empty(&route->opc)) {
		uint32_t *val, *p;
		entry = NULL;

		len = 0;
		llist_for_each(entry, &route->si) len++;

		p = val = talloc_zero_array(regreq, uint32_t, len);
		if (!p) {
			fail_link(link);
			talloc_free(regreq);
			return;
		}

		llist_for_each_entry(opc_ptr, &route->opc, list) *p++ = htonl(opc_ptr->opc);

		xua_msg_add_data(regreq, M3UA_TAG_ORIG_PC_LIST, 4, (uint8_t *) val);	/* Packed as an array */
		talloc_free(val);
	}

	route->reg_rsp_timer.data = route;
	route->reg_rsp_timer.cb = reg_rsp_timeout;
	osmo_timer_schedule(&route->reg_rsp_timer, route->reg_rsp_timeout, 0);

	m3ua_conn_send(link, regreq, &info);
	xua_msg_free(regreq);
}

static void m3ua_handle_reg_rsp(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	struct xua_msg_part *param;

	switch (m3ua->hdr.msg_type) {
	case M3UA_RKM_REG_RSP:
		llist_for_each_entry(param, &m3ua->headers, entry) {
			struct mtp_m3ua_reg_req *route = NULL;
			struct xua_msg *result;

			uint32_t local_rk_identifier;
			uint32_t registration_status;
			uint32_t routing_ctx;

			struct llist_head *entry;

			if (param->tag != M3UA_TAG_REG_RESULT) {
				LOGP(DINP, LOGL_NOTICE, "Invalid param %i in REG_RSP, skipping...\n", param->tag);
				continue;
			}

			result = xua_from_part(param);
			if (!result) {
				LOGP(DINP, LOGL_ERROR, "Decoding REG_RESULT failed.\n");
				continue;
			}

			param = xua_msg_find_tag(result, M3UA_TAG_LOCAL_ROUT_KEY_IDENT);
			if (!param) {
				LOGP(DINP, LOGL_ERROR, "No LOCAL_ROUT_KEY_IDENT in REG_RSP result\n");
				goto next;
			}
			if (param->len != 4) {
				LOGP(DINP, LOGL_ERROR, "Bad length for LOCAL_ROUT_KEY_IDENT in REG_RSP result\n");
				goto next;
			}
			memcpy(&local_rk_identifier, &param->dat[0], 4);

			llist_for_each(entry, &link->routes) {
				route = llist_entry(entry, struct mtp_m3ua_reg_req, list);
				if (route->local_rk_identifier == local_rk_identifier) break;
			}

			/* Check if it's in our outstanding list */
			if (!route) {
				LOGP(DINP, LOGL_NOTICE, "No outstanding REG_REQ matching REG_RSP %u",
				     local_rk_identifier);
				continue;
			}

			param = xua_msg_find_tag(result, MUA_TAG_STATUS);
			if (!param) {
				LOGP(DINP, LOGL_ERROR, "No REG_STATUS in REG_RSP result.\n");
				goto next;
			}
			if (param->len != 4) {
				LOGP(DINP, LOGL_ERROR, "Bad length for REG_STATUS in REG_RSP result.\n");
				goto next;
			}
			memcpy(&registration_status, &param->dat[0], 4);

			param = xua_msg_find_tag(result, MUA_TAG_ROUTING_CTX);
			if (!param) {
				LOGP(DINP, LOGL_ERROR, "No ROUTING_CTX in REG_RSP result.\n");
				goto next;
			}
			if (param->len != 4) {
				LOGP(DINP, LOGL_ERROR, "Bad length for ROUTING_CTX in REG_RSP result.\n");
				goto next;
			}
			memcpy(&routing_ctx, &param->dat[0], 4);

			osmo_timer_del(&route->reg_rsp_timer);	/* disarm timer */

			if (registration_status != 0) {
				LOGP(DINP, LOGL_NOTICE, "REG_REQ RK ID %u failed.  Registration status %i.\n",
				     local_rk_identifier, registration_status);

				llist_move_tail(entry, &link->routes_failed);
				goto next;
			}

			LOGP(DINP, LOGL_INFO, "REG_REQ RK ID %u succeeded.\n",
			     local_rk_identifier);

			route->reg_routing_context = routing_ctx;
			llist_move_tail(entry, &link->routes_active);

		next:
			xua_msg_free(result);
		}

		/* No outstanding routes to process */
		if (llist_empty(&link->routes)) {
			LOGP(DINP, LOGL_NOTICE, "All REG_REQ complete.. sending ASPAC\n");

			m3ua_send_aspac(link);
			schedule_aspac_t_ack(link);
		}
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n", m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_mgmt(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	switch (m3ua->hdr.msg_type) {
	case M3UA_MGMT_ERROR:
	{
		struct xua_msg_part	*param;
		uint32_t		error_code;

		LOGP(DINP, LOGL_ERROR, "Received MGMT_ERROR\n");

		param = xua_msg_find_tag(m3ua, MUA_TAG_ERR_CODE);
		if (!param) {
			LOGP(DINP, LOGL_ERROR, "No ERR_CODE in M3UA_MGMT_ERROR result.\n");
			break;
		}
		if (param->len != 4) {
			LOGP(DINP, LOGL_ERROR, "Bad length for ERR_CODE in M3UA_MGMT_ERROR result.\n");
			break;
		}
		memcpy(&error_code, &param->dat[0], 4);
		error_code = ntohl(error_code);

		LOGP(DINP, LOGL_ERROR, "Received MGMT_ERROR with ERR_CODE %u.\n", error_code);

		switch (error_code) {
		case M3UA_ERR_CODE_REFUSED_MANAGEMENT_BLOCKING:
			fail_link(link);
			break;

		default:
			break;
		}
	}
		break;

	case M3UA_MGMT_NTFY:
		LOGP(DINP, LOGL_NOTICE, "Received MGMT_NTFY\n");
		break;

	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n", m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_aspsm(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	struct mtp_m3ua_reg_req *route = NULL;

	switch (m3ua->hdr.msg_type) {
	case M3UA_ASPSM_UP_ACK:
		link->aspsm_active = 1;
		osmo_timer_del(&link->t_ack);

		/* Send REG_REQ *before* activating ASP, else we might lose data */
		if (!llist_empty(&link->routes)) {
			LOGP(DINP, LOGL_NOTICE, "Received ASP_UP_ACK.. sending REG_REQs\n");
			llist_for_each_entry(route, &link->routes, list) {
				m3ua_send_reg_req(link, route);
				LOGP(DINP, LOGL_NOTICE, "Sent REG_REQ RK ID %u\n", route->local_rk_identifier);
			}
			return;
		}

		/* No routes to register */
		LOGP(DINP, LOGL_NOTICE, "Received ASP_UP_ACK.. sending ASPAC\n");

		m3ua_send_aspac(link);
		schedule_aspac_t_ack(link);
		break;

	case M3UA_ASPSM_DOWN_ACK:
		LOGP(DINP, LOGL_NOTICE, "Received ASP_DOWN_ACK.. Cleaning up link\n");
		link->aspsm_active = 0;
		osmo_timer_del(&link->t_ack);
		clear_link(link);
		break;

	case M3UA_ASPSM_BEAT_ACK:
		LOGP(DINP, LOGL_DEBUG, "Received BEAT_ACK\n");
		break;

	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n", m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_asptm(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	switch (m3ua->hdr.msg_type) {
	case M3UA_ASPTM_ACTIV_ACK:
		LOGP(DINP, LOGL_NOTICE, "Received ASPAC_ACK.. taking link up\n");
		osmo_timer_del(&link->t_ack);
		link->asptm_active = 1;
		mtp_link_up(link->base);

		m3ua_send_daud(link, link->base->set->dpc);
		if (link->base->set->sccp_dpc != -1) m3ua_send_daud(link, link->base->set->sccp_dpc);
		if (link->use_beat) schedule_t_beat(link);

		break;

	default:
		LOGP(DINP, LOGL_ERROR, "Unhandled msg_type %d\n",
			m3ua->hdr.msg_type);
		break;
	}
}

static void m3ua_handle_trans(struct mtp_m3ua_client_link *link, struct xua_msg *m3ua)
{
	struct msgb *msg;
	struct xua_msg_part *data;
	struct mtp_link *mtp_link;
	struct m3ua_protocol_data *proto;
	struct mtp_level_3_hdr *mtp_hdr;
	uint32_t opc, dpc;
	uint8_t sls, si;

	mtp_link = link->base;

	/* ignore everything if the link is blocked */
	if (mtp_link->blocked)
		return;

	if (m3ua->hdr.msg_type != M3UA_TRANS_DATA) {
		LOGP(DINP, LOGL_ERROR, "msg_type(%d) is not known. Ignoring\n",
			m3ua->hdr.msg_type);
		return;
	}

	data = xua_msg_find_tag(m3ua, M3UA_TAG_PROTO_DATA);
	if (!data) {
		LOGP(DINP, LOGL_ERROR, "No PROTO_DATA in DATA message.\n");
		return;
	}

	if (data->len > 2048) {
		LOGP(DINP, LOGL_ERROR, "TOO much data for us to handle.\n");
		return;
	}

	if (data->len < sizeof(struct m3ua_protocol_data)) {
		LOGP(DINP, LOGL_ERROR, "Too little data..\n");
		return;
	}

	msg = msgb_alloc(2048, "m3ua-data");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate storage.\n");
		return;
	}

	msg->l2h = msgb_put(msg, data->len);
	memcpy(msg->l2h, data->dat, data->len);

	proto = (struct m3ua_protocol_data *) msg->l2h;
	opc = ntohl(proto->opc);
	dpc = ntohl(proto->dpc);
	sls = proto->sls;
	si = proto->si;
	LOGP(DINP, LOGL_DEBUG, "Got data for OPC(%d)/DPC(%d)/SLS(%d) len(%zu)\n",
		opc, dpc, sls, msgb_l2len(msg) - sizeof(*proto));


	/* put a MTP3 header in front */
	msg->l3h = proto->data;
	msgb_pull_to_l3(msg);
	msg->l2h = msgb_push(msg, sizeof(*mtp_hdr));
	mtp_hdr = (struct mtp_level_3_hdr *) msg->l2h;
	mtp_hdr->ser_ind = si;
	mtp_hdr->addr = MTP_ADDR(sls % 16, dpc, opc);

	mtp_handle_pcap(mtp_link, NET_IN, msg->l2h, msgb_l2len(msg));
	mtp_link_set_data(mtp_link, msg);
	msgb_free(msg);
}
