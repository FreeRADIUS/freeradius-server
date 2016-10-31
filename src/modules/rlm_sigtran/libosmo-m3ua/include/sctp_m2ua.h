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

#ifndef sctp_m2ua_h
#define sctp_m2ua_h

#include "mtp_data.h"

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/core/write_queue.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

struct sctp_m2ua_conn;
struct mtp_link;

/**
 * Drive M2UA over a SCTP link. Right now we have no
 * real concept for failover and such for the link.
 */
struct sctp_m2ua_transport {
	int started;
	struct llist_head conns;
	struct osmo_fd bsc;

	struct llist_head links;
};

struct mtp_m2ua_link {
	struct mtp_link *base;

	/*
	 * The state of the link, who is using it and
	 * what will happen to it. For load-sharing we
	 * will need to turn this into a list.
	 */
	int active;
	int asp_active;
	int established;
	struct sctp_m2ua_conn *conn;

	int link_index;
	struct llist_head entry;
	struct sctp_m2ua_transport *transport;

	char *as;
};

/*
 * One ASP that can be active or such.
 */
struct sctp_m2ua_conn {
	struct llist_head entry;
	uint8_t asp_ident[4];
	int asp_up;

	struct osmo_wqueue queue;
	struct sctp_m2ua_transport *trans;
};

struct sctp_m2ua_transport *sctp_m2ua_transp_create(struct bsc_data *bsc);
int sctp_m2ua_transport_bind(struct sctp_m2ua_transport *, const char *ip, int port);
struct mtp_m2ua_link *mtp_m2ua_link_create(struct sctp_m2ua_transport *transport,
					   struct mtp_link_set *);

struct mtp_m2ua_link *mtp_m2ua_link_init(struct mtp_link *link);

int sctp_m2ua_conn_count(struct sctp_m2ua_transport *tran);

#endif
