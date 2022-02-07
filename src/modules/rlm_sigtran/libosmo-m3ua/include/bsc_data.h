/* Everything related to the BSC connection */
/*
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2012 by On-Waves
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

#ifndef BSC_DATA_H
#define BSC_DATA_H

#include "mtp_data.h"
#include "mgcp_callagent.h"

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/write_queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

struct bsc_data;
struct snmp_mtp_session;
struct msc_connection;
struct mtp_m2ua_transport;

struct mtp_udp_data {
	struct osmo_wqueue write_queue;
	struct osmo_timer_list snmp_poll;

	struct llist_head links;
};

struct mtp_udp_link {
	/* subclass */
	struct mtp_link *base;

	/* UDP specific stuff */
	struct bsc_data *bsc;
	int link_index;
	int reset_timeout;

	char *dest;
	struct sockaddr_in remote;

	struct mtp_udp_data *data;
	struct llist_head entry;

	/* snmp for controlling the link */
	struct snmp_mtp_session *session;
};

struct bsc_data {
	int pcap_fd;
	int udp_reset_timeout;

	/* udp code */
	struct mtp_udp_data udp_data;

	int udp_src_port;
	int udp_port;
	char *udp_ip;
	int udp_nr_links;

	int m2ua_src_port;

	/* MTP Links */
	struct llist_head linksets;
	int num_linksets;

	/* inject */
	int allow_inject;
	struct osmo_fd inject_fd;

	/* m2ua code */
	struct sctp_m2ua_transport *m2ua_trans;

	/* MSCs */
	struct llist_head mscs;
	int num_mscs;

	/* Simple send only mgcp agent */
	struct mgcp_callagent mgcp_agent;

	/* application */
	struct llist_head apps;
	int num_apps;
};

/* bsc related functions */
void release_bsc_resources(struct msc_connection *fw);

void mtp_linkset_down(struct mtp_link_set *);
void mtp_linkset_up(struct mtp_link_set *);

/* connection tracking and action */

/* udp init */
struct mtp_link_set *link_set_create(struct bsc_data *bsc);
int link_global_init(struct mtp_udp_data *data);
int link_global_bind(struct mtp_udp_data *data, int src_port);
int link_udp_init(struct mtp_udp_link *data, char *dest_ip, int port);
int link_init(struct bsc_data *bsc, struct mtp_link_set *set);
int link_shutdown_all(struct mtp_link_set *);
int link_reset_all(struct mtp_link_set *);
int link_clear_all(struct mtp_link_set *);

/* pcap */
enum {
	NET_IN,
	NET_OUT,
};
int mtp_handle_pcap(struct mtp_link *, int dir, const uint8_t *data, int length);

struct bsc_data *bsc_data_alloc(TALLOC_CTX *ctx);
struct bsc_data *bsc_data_create(void);

struct mtp_udp_link *mtp_udp_link_init(struct mtp_link *link);

#endif
