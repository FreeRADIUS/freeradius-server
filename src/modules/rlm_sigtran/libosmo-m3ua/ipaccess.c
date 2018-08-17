/* OpenBSC Abis input driver for ip.access */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <ipaccess.h>


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

#define TS1_ALLOC_SIZE	4096

static const uint8_t pong[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG };
static const uint8_t id_ack[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK };
static const uint8_t id_req[] = { 0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
					0x01, IPAC_IDTAG_UNIT,
					0x01, IPAC_IDTAG_MACADDR,
					0x01, IPAC_IDTAG_LOCATION1,
					0x01, IPAC_IDTAG_LOCATION2,
					0x01, IPAC_IDTAG_EQUIPVERS,
					0x01, IPAC_IDTAG_SWVERSION,
					0x01, IPAC_IDTAG_UNITNAME,
					0x01, IPAC_IDTAG_SERNR,
				};

/* send the id ack */
int ipaccess_send_id_ack(int fd)
{
	return write(fd, id_ack, sizeof(id_ack));
}

int ipaccess_send_id_req(int fd)
{
	return write(fd, id_req, sizeof(id_req));
}

/* base handling of the ip.access protocol */
int ipaccess_rcvmsg_base(struct msgb *msg,
			 struct osmo_fd *bfd)
{
	uint8_t msg_type = *(msg->l2h);
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = write(bfd->fd, pong, sizeof(pong));
		break;
	case IPAC_MSGT_PONG:
		break;
	case IPAC_MSGT_ID_ACK:
		ret = ipaccess_send_id_ack(bfd->fd);
		break;
	}
	return ret;
}

/*
 * read one ipa message from the socket
 * return NULL in case of error
 */
struct msgb *ipaccess_read_msg(struct osmo_fd *bfd, int *error)
{
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "Abis/IP");
	struct ipaccess_head *hh;
	int len, ret = 0;

	if (!msg) {
		*error = -ENOMEM;
		return NULL;
	}

	/* first read our 3-byte header */
	hh = (struct ipaccess_head *) msg->data;
	ret = recv(bfd->fd, msg->data, 3, 0);
	if (ret < 0) {
		msgb_free(msg);
		*error = ret;
		return NULL;
	} else if (ret == 0) {
		msgb_free(msg);
		*error = ret;
		return NULL;
	}

	msgb_put(msg, ret);

	/* then read te length as specified in header */
	msg->l2h = msg->data + sizeof(*hh);
	len = ntohs(hh->len);
	ret = recv(bfd->fd, msg->l2h, len, 0);
	if (ret < len) {
		msgb_free(msg);
		*error = -EIO;
		return NULL;
	}
	msgb_put(msg, ret);

	return msg;
}

void ipaccess_prepend_header(struct msgb *msg, int proto)
{
	struct ipaccess_head *hh;

	/* prepend the ip.access header */
	hh = (struct ipaccess_head *) msgb_push(msg, sizeof(*hh));
	hh->len = htons(msg->len - sizeof(*hh));
	hh->proto = proto;
}

