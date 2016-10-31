/* Stuff to handle the SS7 application */
/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef SS7_APPLICATION_H
#define SS7_APPLICATION_H

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

struct bsc_data;
struct msc_connection;
struct mtp_link_set;
struct mtp_link;

enum ss7_set_type {
	SS7_SET_LINKSET,
	SS7_SET_MSC,
};

enum ss7_app_type {
	APP_NONE,
	APP_CELLMGR,
	APP_RELAY,
	APP_STP,
};

struct ss7_application_route {
	int type;
	int nr;

	int up;

	/* maybe they were resolved */
	struct mtp_link_set *set;
	struct msc_connection *msc;
};

struct ss7_application {
	/* handling */
	struct llist_head entry;
	int nr;
	char *name;

	/* app type */
	int type;

	/* for the routing */
	int route_is_set;
	struct ss7_application_route route_src;
	struct ss7_application_route route_dst;

	struct bsc_data *bsc;

	/* isup handling */
	int isup_pass;

	/* handling for the NAT/State handling */
	struct llist_head sccp_connections;
	struct osmo_timer_list reset_timeout;
	struct mtp_link_set *target_link;
	int forward_only;
	int reset_count;

	/* mgcp handling for the cellmgr and stp */
	char *mgcp_domain_name;
	char *trunk_name;

	/* various hacks/quirks to deal with broken equipment */
	/*
	 * Some equipments do not look into the codec list but only the
	 * size of it.
	 */
	unsigned fixed_ass_cmpl_reply : 1;

	/**
	 * force link down
	 */
	int force_down;
};


struct ss7_application *ss7_application_alloc(struct bsc_data *);
struct ss7_application *ss7_application_num(struct bsc_data *, int nr);
int ss7_application_setup(struct ss7_application *, int type,
			  int src_type, int src_num,
			  int dst_type, int dst_num);

int ss7_application_start(struct ss7_application *);

/* config changes */
void ss7_application_pass_isup(struct ss7_application *, int pass);

int ss7_application_mgcp_domain_name(struct ss7_application *,
				     const char *domain_name);
int ss7_application_trunk_name(struct ss7_application *,
				const char *trunk_name);

int ss7_application_msc_down(struct ss7_application *app);
int ss7_application_msc_up(struct ss7_application *app);

#endif
