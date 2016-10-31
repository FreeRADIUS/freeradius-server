/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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
 */

#ifndef MSC_CONNECTION_H
#define MSC_CONNECTION_H

#include "mgcp_callagent.h"

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/sccp/sccp.h>

struct bsc_data;
struct ss7_application;

enum msc_mode {
	MSC_MODE_CLIENT,
	MSC_MODE_SERVER,
};

struct msc_connection {
	/* management */
	struct llist_head entry;
	int nr;
	char *name;
	enum msc_mode mode;
	int auth;

	/* ip management */
	int dscp;
	int port;
	char *ip;
	char *token;

	/* connection management */
	int msc_link_down;
	struct osmo_wqueue msc_connection;
	struct osmo_timer_list reconnect_timer;
	int first_contact;

	/* time to wait for first message from MSC */
	struct osmo_timer_list msc_timeout;
	int msc_time;

	/* timeouts for the msc connection */
	int ping_time;
	int pong_time;
	struct osmo_timer_list ping_timeout;
	struct osmo_timer_list pong_timeout;

	/* mgcp messgaes */
	struct mgcp_callagent mgcp_agent;

	/* application pointer */
	struct ss7_application *app;

	/* server functions */
	struct osmo_fd listen_fd;
};

/* msc related functions */
void msc_send_rlc(struct msc_connection *bsc, struct sccp_source_reference *src, struct sccp_source_reference *dest);
void msc_send_reset(struct msc_connection *bsc);
void msc_send_direct(struct msc_connection *bsc, struct msgb *msg);
void msc_close_connection(struct msc_connection *data);

struct msc_connection *msc_connection_create(struct bsc_data *bsc, int mgcp);
struct msc_connection *msc_connection_num(struct bsc_data *bsc, int num);
int msc_connection_start(struct msc_connection *msc);

/* MGCP */
void msc_mgcp_reset(struct msc_connection *msc);

/* Called by the MSC Connection */
void msc_dispatch_sccp(struct msc_connection *msc, struct msgb *msg);

const char *msc_mode(struct msc_connection *msc);

#endif
