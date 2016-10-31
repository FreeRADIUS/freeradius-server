/* MSC related stuff... */
/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

#include <msc_connection.h>
#include <bsc_data.h>
#include <bsc_sccp.h>
#include <bssap_sccp.h>
#include <ipaccess.h>
#include <mtp_data.h>
#include <cellmgr_debug.h>
#include <ss7_application.h>
#include <mgcp_patch.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/gsm/tlv.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define RECONNECT_TIME		10, 0
#define NAT_MUX 0xfc

static void msc_send_id_response(struct msc_connection *bsc);
static void msc_send(struct msc_connection *bsc, struct msgb *msg, int proto);
static void msc_schedule_reconnect(struct msc_connection *bsc);
static int msc_conn_bind(struct msc_connection *bsc);
static void msc_handle_id_response(struct msc_connection *bsc, struct msgb *msg);

void msc_close_connection(struct msc_connection *fw)
{
	struct osmo_fd *bfd = &fw->msc_connection.bfd;

	if (bfd->fd >= 0) {
		close(bfd->fd);
		osmo_fd_unregister(bfd);
		bfd->fd = -1;
	}

	fw->msc_link_down = 1;
	release_bsc_resources(fw);
	osmo_timer_del(&fw->ping_timeout);
	osmo_timer_del(&fw->pong_timeout);
	osmo_timer_del(&fw->msc_timeout);
	osmo_wqueue_clear(&fw->msc_connection);
	ss7_application_msc_down(fw->app);
	msc_schedule_reconnect(fw);
}

static void msc_connect_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;

	LOGP(DMSC, LOGL_ERROR, "Timeout on the MSC connection.\n");
	msc_close_connection(fw);
}

static void msc_pong_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;
	LOGP(DMSC, LOGL_ERROR, "MSC didn't respond to ping. Closing.\n");
	msc_close_connection(fw);
}

static void send_ping(struct msc_connection *fw)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ping");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create PING.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;

	msc_send(fw, msg, IPAC_PROTO_IPACCESS);
}

static void msc_ping_timeout(void *_fw_data)
{
	struct msc_connection *fw = _fw_data;

	if (fw->ping_time < 0)
		return;

	send_ping(fw);

	/* send another ping in 20 seconds */
	osmo_timer_schedule(&fw->ping_timeout, fw->ping_time, 0);

	/* also start a pong timer */
	osmo_timer_schedule(&fw->pong_timeout, fw->pong_time, 0);
}

/*
 * callback with IP access data
 */
static int ipaccess_a_fd_cb(struct osmo_fd *bfd)
{
	int error;
	struct ipaccess_head *hh;
	struct msc_connection *fw;
	struct msgb *msg;

	fw = bfd->data;
	msg = ipaccess_read_msg(bfd, &error);

	if (!msg) {
		if (error == 0)
			fprintf(stderr, "The connection to the MSC was lost, exiting\n");
		else
			fprintf(stderr, "Error in the IPA stream.\n");

		msc_close_connection(fw);
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "From MSC: %s proto: %d\n", osmo_hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (fw->first_contact) {
			LOGP(DMSC, LOGL_NOTICE, "Connected to MSC. Sending reset.\n");
			osmo_timer_del(&fw->msc_timeout);
			fw->first_contact = 0;
			fw->msc_link_down = 0;
			ss7_application_msc_up(fw->app);
			msc_send_reset(fw);
		}
		if (msg->l2h[0] == IPAC_MSGT_ID_GET && fw->token) {
			msc_send_id_response(fw);
		} else if (msg->l2h[0] == IPAC_MSGT_PONG) {
			osmo_timer_del(&fw->pong_timeout);
		} else if (msg->l2h[0] == IPAC_MSGT_ID_RESP) {
			msc_handle_id_response(fw, msg);
		}

		msgb_free(msg);
		return 0;
	}

	if (fw->mode == MSC_MODE_SERVER && !fw->auth) {
		LOGP(DMSC, LOGL_ERROR,
			"Ignoring non ipa message for unauth user.\n");
		msgb_free(msg);
		return -1;
	}

	if (hh->proto == IPAC_PROTO_SCCP) {
		msc_dispatch_sccp(fw, msg);
	} else if (hh->proto == NAT_MUX) {
		abort();
	/*
		msg = mgcp_patch(fw->app, msg);
		mgcp_forward(&fw->mgcp_agent, msg->l2h, msgb_l2len(msg));
	*/
	} else {
		LOGP(DMSC, LOGL_ERROR, "Unknown IPA proto 0x%x\n", hh->proto);
	}

	msgb_free(msg);
	return 0;
}

static int ipaccess_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	LOGP(DMSC, LOGL_DEBUG, "Sending to MSC: %s\n", osmo_hexdump(msg->data, msg->len));
	rc = write(fd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DMSC, LOGL_ERROR, "Could not write to MSC.\n");

	return rc;
}

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct osmo_fd *fd, unsigned int what)
{
	int rc;
	int val;
	socklen_t len = sizeof(val);
	struct msc_connection *fw;

	fw = fd->data;

	if (fd != &fw->msc_connection.bfd) {
		LOGP(DMSC, LOGL_ERROR, "This is only working with the MSC connection.\n");
		return -1;
	}

	if ((what & BSC_FD_WRITE) == 0)
		return -1;

	/* check the socket state */
	rc = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &val, &len);
	if (rc != 0) {
		LOGP(DMSC, LOGL_ERROR, "getsockopt for the MSC socket failed.\n");
		goto error;
	}
	if (val != 0) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to the MSC.\n");
		goto error;
	}


	/* go to full operation */
	fd->cb = osmo_wqueue_bfd_cb;
	fd->when = BSC_FD_READ;
	if (!llist_empty(&fw->msc_connection.msg_queue))
		fd->when |= BSC_FD_WRITE;
	return 0;

error:
	msc_close_connection(fw);
	return -1;
}

static int setnonblocking(struct osmo_fd *fd)
{
	int flags;

	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return -1;
	}

	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return -1;
	}

	return 0;
}

static int connect_to_msc(struct osmo_fd *fd, const char *ip, int port, int tos)
{
	struct sockaddr_in sin;
	int on = 1, ret;

	LOGP(DMSC, LOGL_NOTICE, "Attempting to connect MSC at %s:%d\n", ip, port);

	fd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd->fd < 0) {
		perror("Creating TCP socket failed");
		return fd->fd;
	}

	/* make it non blocking */
	if (setnonblocking(fd) != 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	inet_aton(ip, &sin.sin_addr);

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = setsockopt(fd->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
	ret = setsockopt(fd->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR, "Failed to set IP_TOS: %s\n", strerror(errno));

	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret == -1 && errno == EINPROGRESS) {
		LOGP(DMSC, LOGL_ERROR, "MSC Connection in progress\n");
		fd->when = BSC_FD_WRITE;
		fd->cb = msc_connection_connect;
	} else if (ret < 0) {
		perror("Connection failed");
		close(fd->fd);
		fd->fd = -1;
		return ret;
	} else {
		fd->when = BSC_FD_READ;
		fd->cb = osmo_wqueue_bfd_cb;
	}

	ret = osmo_fd_register(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		fd->fd = -1;
		return ret;
	}

	return ret;
}

static void msc_reconnect(void *_data)
{
	int rc;
	struct msc_connection *fw = _data;

	osmo_timer_del(&fw->reconnect_timer);
	fw->first_contact = 1;

	rc = connect_to_msc(&fw->msc_connection.bfd, fw->ip, fw->port, fw->dscp);
	if (rc < 0) {
		fprintf(stderr, "Opening the MSC connection failed. Trying again\n");
		osmo_timer_schedule(&fw->reconnect_timer, RECONNECT_TIME);
		return;
	}

	fw->msc_timeout.cb = msc_connect_timeout;
	fw->msc_timeout.data = fw;
	osmo_timer_schedule(&fw->msc_timeout, fw->msc_time, 0);
}

static void msc_schedule_reconnect(struct msc_connection *fw)
{
	if (fw->mode == MSC_MODE_SERVER)
		return;
	osmo_timer_schedule(&fw->reconnect_timer, RECONNECT_TIME);
}

/*
 * mgcp forwarding is below
 */
/* send a RSIP to the MGCP GW */
void msc_mgcp_reset(struct msc_connection *msc)
{
	char buf[512];
	char *dest = "mgw";

	if (msc->app->mgcp_domain_name)
		dest = msc->app->mgcp_domain_name;

	snprintf(buf, sizeof(buf) - 1, "RSIP 1 13@%s MGCP 1.0\r\n", dest);
	buf[sizeof(buf) - 1] = '\0';

	abort();
	//mgcp_forward(&msc->mgcp_agent, (const uint8_t *) buf, strlen(buf));
}

static void msc_mgcp_read_cb(struct mgcp_callagent *agent, struct msgb *msg)
{
	struct msc_connection *fw = container_of(agent, struct msc_connection, mgcp_agent);
	msc_send(fw, msg, NAT_MUX);
}

static void msc_send(struct msc_connection *fw, struct msgb *msg, int proto)
{
	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Dropping data due lack of MSC connection.\n");
		msgb_free(msg);
		return;
	}

	ipaccess_prepend_header(msg, proto);

	if (osmo_wqueue_enqueue(&fw->msc_connection, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue MSG for the MSC.\n");
		msgb_free(msg);
		return;
	}
}

void msc_send_rlc(struct msc_connection *fw,
		  struct sccp_source_reference *src, struct sccp_source_reference *dst)
{
	struct msgb *msg;

	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Not releasing connection due lack of connection.\n");
		return;
	}

	msg = create_sccp_rlc(src, dst);
	if (!msg)
		return;

	msc_send(fw, msg, IPAC_PROTO_SCCP);
}

void msc_send_reset(struct msc_connection *fw)
{
	struct msgb *msg;

	if (fw->msc_link_down) {
		LOGP(DMSC, LOGL_NOTICE, "Not sending reset due lack of connection.\n");
		return;
	}

	/* start the ping/pong but nothing else */
	if (fw->mode == MSC_MODE_SERVER) {
		LOGP(DMSC, LOGL_DEBUG, "Not sending BSSMAP resets in server mode.\n");
		msc_ping_timeout(fw);
		return;
	}


	msg = create_reset();
	if (!msg)
		return;

	msc_send(fw, msg, IPAC_PROTO_SCCP);
	msc_ping_timeout(fw);
}

static void msc_send_id_response(struct msc_connection *fw)
{
	struct msgb *msg;

	if (fw->mode == MSC_MODE_SERVER) {
		LOGP(DMSC, LOGL_DEBUG,
			"Not sending our token in server mode.\n");
		return;
	}

	msg = msgb_alloc_headroom(4096, 128, "id resp");
	msg->l2h = msgb_v_put(msg, IPAC_MSGT_ID_RESP);
	msgb_l16tv_put(msg, strlen(fw->token) + 1,
		       IPAC_IDTAG_UNITNAME, (uint8_t *) fw->token);

	msc_send(fw, msg, IPAC_PROTO_IPACCESS);
}

void msc_send_direct(struct msc_connection *fw, struct msgb *msg)
{
	return msc_send(fw, msg, IPAC_PROTO_SCCP);
}

struct msc_connection *msc_connection_create(struct bsc_data *bsc, int mgcp)
{
	struct msc_connection *msc;

	msc = talloc_zero(NULL, struct msc_connection);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate the MSC Connection.\n");
		return NULL;
	}

	msc->mode = MSC_MODE_CLIENT;
	msc->port = 5000;

	osmo_wqueue_init(&msc->msc_connection, 100);
	msc->reconnect_timer.cb = msc_reconnect;
	msc->reconnect_timer.data = msc;
	msc->msc_connection.read_cb = ipaccess_a_fd_cb;
	msc->msc_connection.write_cb = ipaccess_write_cb;
	msc->msc_connection.bfd.data = msc;
	msc->msc_connection.bfd.fd = -1;
	msc->msc_link_down = 1;

	/* handle the timeout */
	msc->ping_time = -1;
	msc->ping_timeout.cb = msc_ping_timeout;
	msc->ping_timeout.data = msc;
	msc->pong_timeout.cb = msc_pong_timeout;
	msc->pong_timeout.data = msc;
/*
	if (mgcp && mgcp_create_port(&msc->mgcp_agent) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to bind for the MGCP port.\n");
		talloc_free(msc);
		return NULL;
	}
*/
	llist_add_tail(&msc->entry, &bsc->mscs);
	msc->nr = bsc->num_mscs++;
	msc->mgcp_agent.read_cb = msc_mgcp_read_cb;

	return msc;
}

struct msc_connection *msc_connection_num(struct bsc_data *bsc, int num)
{
	struct msc_connection *msc;

	llist_for_each_entry(msc, &bsc->mscs, entry)
		if (msc->nr == num)
			return msc;
	return NULL;
}

int msc_connection_start(struct msc_connection *msc)
{
	if (msc->msc_connection.bfd.fd > 0) {
		LOGP(DMSC, LOGL_ERROR,
		     "Function should not be called with active connection.\n");
		return -1;
	}

	/* bind and wait if we are a server */
	if (msc->mode == MSC_MODE_SERVER)
		return msc_conn_bind(msc);

	msc_schedule_reconnect(msc);
	return 0;
}

const char *msc_mode(struct msc_connection *msc)
{
	switch (msc->mode) {
	case MSC_MODE_CLIENT:
		return "client";
	case MSC_MODE_SERVER:
		return "server";
	}

	return "invalid";
}

/* Non-clean MSC server socket abstraction.. bind and accept */
static int msc_send_auth_req(struct msc_connection *msc)
{
	struct msgb *msg;

	static const uint8_t id_req[] = {
		IPAC_MSGT_ID_GET,
		0x01, IPAC_IDTAG_UNIT,
		0x01, IPAC_IDTAG_MACADDR,
		0x01, IPAC_IDTAG_LOCATION1,
		0x01, IPAC_IDTAG_LOCATION2,
		0x01, IPAC_IDTAG_EQUIPVERS,
		0x01, IPAC_IDTAG_SWVERSION,
		0x01, IPAC_IDTAG_UNITNAME,
		0x01, IPAC_IDTAG_SERNR,
	};

	msg = msgb_alloc_headroom(4096, 128, "auth");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate auth.\n");
		msc_close_connection(msc);
		return -1;
	}

	msg->l2h = msgb_put(msg, ARRAY_SIZE(id_req));
	memcpy(msg->l2h, id_req, ARRAY_SIZE(id_req));

	msc_send(msc, msg, IPAC_PROTO_IPACCESS);
	return 0;
}

static void msc_handle_id_response(struct msc_connection *msc, struct msgb *msg)
{
	unsigned int len;
	const char *token;

	/* only for the server */
	if (msc->mode != MSC_MODE_SERVER) {
		LOGP(DMSC, LOGL_ERROR, "Unexpected ID response for client.\n");
		return;
	}

	if (!msc->token) {
		LOGP(DMSC, LOGL_ERROR, "No token defined. Giving up.\n");
		goto clean;
	}

	if (msgb_l2len(msg) < 4) {
		LOGP(DMSC, LOGL_ERROR, "Too short message...%u\n",
				msgb_l2len(msg));
		goto clean;
	}

	/* in lack of ipaccess_idtag_parse we have a very basic method */
	if (msg->l2h[3] != IPAC_IDTAG_UNITNAME) {
		LOGP(DMSC, LOGL_ERROR, "Expected unitname tag got %d\n",
			msg->l2h[3]);
		goto clean;
	}

	token = (const char *) &msg->l2h[4];
	len = msgb_l2len(msg) - 4;

	if (len != strlen(msc->token)) {
		LOGP(DMSC, LOGL_ERROR, "Wrong length %u vs. %zu\n", len, strlen(msc->token));
		goto clean;
	}

	if (memcmp(msc->token, token, len) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Token has the wrong size.\n");
		goto clean;
	}

	LOGP(DMSC, LOGL_NOTICE, "Authenticated the connection.\n");
	msc->auth = 1;
	ss7_application_msc_up(msc->app);
	return;
clean:
	msc_close_connection(msc);
}

static int msc_conn_accept(struct osmo_fd *bsc_fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	struct msc_connection *msc = bsc_fd->data;
	int ret;

	LOGP(DMSC, LOGL_NOTICE, "Going to accept a connection.\n");

	ret = accept(bsc_fd->fd, (struct sockaddr *) &addr, &len);
	if (ret < 0) {
		LOGP(DMSC, LOGL_ERROR, "Accept failed with fd(%d) errno(%d)\n",
			ret, errno);
		return -1;
	}

	/*
	 * Close the previous/current connection.
	 * TODO: switch only once we know it is a valid connection
	 */
	msc_close_connection(msc);

	/* re-set the internal state */
	msc->auth = 0;

	/* adopt the connection */
	msc->msc_connection.bfd.fd = ret;
	msc->msc_connection.bfd.when = BSC_FD_READ;
	ret = osmo_fd_register(&msc->msc_connection.bfd);
	if (ret < 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to register fd.\n");
		close(msc->msc_connection.bfd.fd);
		msc->msc_connection.bfd.fd = -1;
		return -1;
	}

	/* consider it up and running */
	msc->msc_link_down = 0;

	/* msc send auth request */
	msc_send_auth_req(msc);
	LOGP(DMSC, LOGL_ERROR, "Registered fd %d and waiting for data.\n",
		msc->msc_connection.bfd.fd);

	return 0;
}

static int msc_conn_bind(struct msc_connection *msc)
{
	int rc;

	LOGP(DMSC, LOGL_NOTICE, "Going to bind and wait for connections.\n");

	rc = osmo_sock_init_ofd(&msc->listen_fd, AF_UNSPEC, SOCK_STREAM,
			IPPROTO_TCP, "127.0.0.1", msc->port, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		LOGP(DMSC, LOGL_NOTICE, "Failed to bind the socket.\n");
		return rc;
	}

	msc->listen_fd.data = msc;
	msc->listen_fd.cb = msc_conn_accept;

	return 0;
}
