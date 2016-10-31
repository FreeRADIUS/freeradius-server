/* Implementation of the C7 UDP link */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <bsc_data.h>
#include <udp_input.h>
#include <mtp_data.h>
#include <mtp_pcap.h>
#include <snmp_mtp.h>
#include <cellmgr_debug.h>
#include <counter.h>

#include <osmocom/core/talloc.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>

static struct mtp_udp_link *find_link(struct mtp_udp_data *data, uint16_t link_index)
{
	struct mtp_udp_link *lnk;

	llist_for_each_entry(lnk, &data->links, entry)
		if (lnk->link_index == link_index)
			return lnk;

	return NULL;
}


static int udp_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	struct mtp_udp_data *data;
	struct mtp_udp_link *link;
	int rc;

	data = fd->data;
	link = find_link(data, msg->cb[0]);
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "Failed to find link with %lu\n", msg->cb[0]);
		return -1;
	}

	LOGP(DINP, LOGL_DEBUG, "Sending MSU: %s\n", osmo_hexdump(msg->data, msg->len));
	mtp_handle_pcap(link->base, NET_OUT, msg->l2h, msgb_l2len(msg));

	/* the assumption is we have connected the socket to the remote */
	rc = sendto(fd->fd, msg->data, msg->len, 0,
		     (struct sockaddr *) &link->remote, sizeof(link->remote));
	if (rc != msg->len) {
		LOGP(DINP, LOGL_ERROR, "Failed to write msg to socket: %d\n", rc);
		return -1;
	}

	return 0;
}

static int udp_read_cb(struct osmo_fd *fd)
{
	struct mtp_udp_data *data;
	struct mtp_udp_link *ulnk;
	struct mtp_link *link;
	struct udp_data_hdr *hdr;
	struct msgb *msg;
	int rc;
	unsigned int length;

	msg = msgb_alloc_headroom(4096, 128, "UDP datagram");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate memory.\n");
		return -1;
	}


	data = (struct mtp_udp_data *) fd->data;
	rc = read(fd->fd, msg->data, 2096);
	if (rc < sizeof(*hdr)) {
		LOGP(DINP, LOGL_ERROR, "Failed to read at least size of the header: %d\n", rc);
		rc = -1;
		goto exit;
	}

	hdr = (struct udp_data_hdr *) msgb_put(msg, sizeof(*hdr));
	ulnk = find_link(data, ntohs(hdr->data_link_index));

	if (!ulnk) {
		LOGP(DINP, LOGL_ERROR, "No link registered for %d\n",
		     ntohs(hdr->data_link_index));
		goto exit;
	}

	link = ulnk->base;
	if (link->blocked) {
		LOGP(DINP, LOGL_ERROR, "The link is blocked.\n");
		rc = 0;
		goto exit;
	}

	if (hdr->data_type == UDP_DATA_RETR_COMPL || hdr->data_type == UDP_DATA_RETR_IMPOS) {
		LOGP(DINP, LOGL_ERROR, "Link retrieval done on %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		mtp_link_failure(link);
		goto exit;
	} else if (hdr->data_type == UDP_DATA_LINK_UP) {
		LOGP(DINP, LOGL_NOTICE, "Link of %d/%s of %d/%s is up.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		mtp_link_up(link);
		goto exit;
	} else if (hdr->data_type == UDP_DATA_LINK_DOWN) {
		LOGP(DINP, LOGL_NOTICE, "Link of %d/%s of %d/%s is down.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		mtp_link_failure(link);
		goto exit;
	} else if (hdr->data_type > UDP_DATA_MSU_PRIO_3) {
		LOGP(DINP, LOGL_ERROR, "Link failue on %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		mtp_link_failure(link);
		goto exit;
	}

	/* throw away data as the link is down */
	if (link->set->available == 0) {
		LOGP(DINP, LOGL_ERROR, "Link %d/%s of %d/%s is down. Not forwarding.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		rc = 0;
		goto exit;
	}

	length = ntohl(hdr->data_length);
	if (length + sizeof(*hdr) > (unsigned int) rc) {
		LOGP(DINP, LOGL_ERROR,
		     "The MSU payload does not fit: %u + %zu > %d on link %d/%s of %d/%s.\n",
		     length, sizeof(*hdr), rc,
		     link->nr, link->name, link->set->nr, link->set->name);
		rc = 0;
		rc = -1;
		goto exit;
	}

	msg->l2h = msgb_put(msg, length);

	LOGP(DINP, LOGL_DEBUG, "MSU data on link %d/%s of %d/%s data %s.\n",
	     link->nr, link->name, link->set->nr, link->set->name,
	     osmo_hexdump(msg->data, msg->len));
	mtp_handle_pcap(link, NET_IN, msg->l2h, msgb_l2len(msg));
	mtp_link_set_data(link, msg);

exit:
	msgb_free(msg);
	return rc;
}

static int udp_link_dummy(struct mtp_link *link)
{
	/* nothing todo */
	return 0;
}

static void do_start(void *_data)
{
	struct mtp_udp_link *link = (struct mtp_udp_link *) _data;

	snmp_mtp_activate(link->session, link->link_index);
}

static int udp_link_reset(struct mtp_link *link)
{
	struct mtp_udp_link *ulnk;

	ulnk = (struct mtp_udp_link *) link->data;

	snmp_mtp_deactivate(ulnk->session, ulnk->link_index);
	return 0;
}

static int udp_link_shutdown(struct mtp_link *link)
{
	return udp_link_reset(link);
}

static int udp_link_write(struct mtp_link *link, struct msgb *msg)
{
	struct mtp_udp_link *ulnk;
	struct udp_data_hdr *hdr;

	ulnk = (struct mtp_udp_link *) link->data;

	hdr = (struct udp_data_hdr *) msgb_push(msg, sizeof(*hdr));
	hdr->format_type = UDP_FORMAT_SIMPLE_UDP;
	hdr->data_type = UDP_DATA_MSU_PRIO_0;
	hdr->data_link_index = htons(ulnk->link_index);
	hdr->user_context = 0;
	hdr->data_length = htonl(msgb_l2len(msg));

	msg->cb[0] = ulnk->link_index;

	if (osmo_wqueue_enqueue(&ulnk->data->write_queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue msg on link %d/%s of %d/%s.\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		rate_ctr_inc(&link->ctrg->ctr[MTP_LNK_DRP]);
		rate_ctr_inc(&link->set->ctrg->ctr[MTP_LSET_TOTA_DRP_MSG]);
		msgb_free(msg);
		return -1;
	}

	return 0;
}

int link_udp_init(struct mtp_udp_link *link, char *remote, int port)
{
	/* prepare the remote */
	memset(&link->remote, 0, sizeof(link->remote));
	link->remote.sin_family = AF_INET;
	link->remote.sin_port = htons(port);
	inet_aton(remote, &link->remote.sin_addr);

	return 0;
}

static void snmp_poll(void *_data)
{
	struct mtp_udp_data *data = _data;
	snmp_mtp_poll();
	osmo_timer_schedule(&data->snmp_poll, 0, 5000);
}

int link_global_init(struct mtp_udp_data *data)
{
	INIT_LLIST_HEAD(&data->links);
	osmo_wqueue_init(&data->write_queue, 100);

	/* socket creation */
	data->write_queue.bfd.data = data;
	data->write_queue.bfd.when = BSC_FD_READ;
	data->write_queue.read_cb = udp_read_cb;
	data->write_queue.write_cb = udp_write_cb;

	return 0;
}

int link_global_bind(struct mtp_udp_data *data, int src_port)
{
	struct sockaddr_in addr;
	int fd;
	int on;

	data->write_queue.bfd.fd = fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to create UDP socket.\n");
		return -1;
	}

	on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(src_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind UDP socket");
		close(fd);
		return -1;
	}

	/* now connect the socket to the remote */
	if (osmo_fd_register(&data->write_queue.bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register BFD.\n");
		close(fd);
		return -1;
	}

	data->snmp_poll.data = data;
	data->snmp_poll.cb = snmp_poll;
	snmp_poll(data);

	return 0;
}

void snmp_mtp_callback(struct snmp_mtp_session *session,
		      int area, int res, int link_id)
{
	struct mtp_udp_link *ulink;
	struct mtp_link *link;

	ulink = session->data;
	if (!ulink) {
		LOGP(DINP, LOGL_ERROR, "Failed to find link_id %d\n", link_id);
		return;
	}

	link = ulink->base;

	if (res == SNMP_STATUS_TIMEOUT && !link->blocked) {
		LOGP(DINP, LOGL_ERROR,
		     "Failed to restart link %d/%s of linkset %d/%s\n",
		     link->nr, link->name, link->set->nr, link->set->name);
		udp_link_reset(link);
		return;
	}

	switch (area) {
	case SNMP_LINK_UP:
		break;
	case SNMP_LINK_DOWN:
		mtp_link_down(link);

		/*
		 * restart the link in 90 seconds...
		 * to force a timeout on the BSC
		 */
		if (!link->blocked) {
			link->link_activate.cb = do_start;
			link->link_activate.data = ulink;
			osmo_timer_schedule(&link->link_activate, ulink->reset_timeout, 0);
			LOGP(DINP, LOGL_NOTICE,
			     "Will bring up link %d/%s of linkset %d/%s in %d seconds.\n",
			     link->nr, link->name,
			     link->set->nr, link->set->name,
			     ulink->reset_timeout);
		}
		break;
	default:
		LOGP(DINP, LOGL_ERROR,
		     "Unknown event %d on %d/%s of linkset %d/%s.\n",
		      area, link->nr, link->name, link->set->nr, link->set->name);
	}
}

struct mtp_udp_link *mtp_udp_link_init(struct mtp_link *blnk)
{
	struct bsc_data *bsc;
	struct mtp_udp_link *lnk;

	lnk = talloc_zero(blnk, struct mtp_udp_link);
	if (!lnk) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	/* setup SNMP first, it is blocking */
	lnk->session = snmp_mtp_session_create();
	if (!lnk->session) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate snmp session.\n");
		talloc_free(lnk);
		return NULL;
	}
	lnk->session->data = lnk;

	bsc = blnk->set->bsc;
	lnk->data = &bsc->udp_data;
	lnk->reset_timeout = bsc->udp_reset_timeout;

	lnk->base = blnk;
	lnk->base->data = lnk;
	lnk->base->type = SS7_LTYPE_UDP;
	lnk->bsc = bsc;

	/* function table */
	lnk->base->shutdown = udp_link_shutdown;
	lnk->base->clear_queue = udp_link_dummy;

	lnk->base->reset = udp_link_reset;
	lnk->base->write = udp_link_write;

	/* prepare the remote */
	memset(&lnk->remote, 0, sizeof(lnk->remote));
	lnk->remote.sin_family = AF_INET;

	/* add it to the list of udp connections */
	llist_add_tail(&lnk->entry, &lnk->data->links);

	return lnk;
}
