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

#ifndef bsc_sccp_h
#define bsc_sccp_h

#include <inttypes.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

struct ss7_application;

/*
 * One SCCP connection.
 * Use for connection tracking and fixups...
 */
struct active_sccp_con {
	struct llist_head entry;

	struct sccp_source_reference src_ref;
	struct sccp_source_reference dst_ref;

	int has_dst_ref;

	/* fixup stuff */

	/* We get a RLSD from the MSC and need to send a RLC */
	int released_from_msc;

	/* timeout for waiting for the RLC */
	struct osmo_timer_list rlc_timeout;

	/* how often did we send a RLSD this */
	unsigned int rls_tries;

	/* Link to the SS7 Application */
	struct ss7_application *app;

	/* sls id */
	int sls;
};

void free_con(struct active_sccp_con *con);
struct active_sccp_con *find_con_by_dest_ref(struct ss7_application *, struct sccp_source_reference *ref);
struct active_sccp_con *find_con_by_src_ref(struct ss7_application *,struct sccp_source_reference *src_ref);
struct active_sccp_con *find_con_by_src_dest_ref(struct ss7_application *, struct sccp_source_reference *src_ref,
						 struct sccp_source_reference *dst_ref);
unsigned int sls_for_src_ref(struct ss7_application *, struct sccp_source_reference *ref);

void app_resources_released(struct ss7_application *ss7);
void app_clear_connections(struct ss7_application *ss7);
void app_forward_sccp(struct ss7_application *ss7, struct msgb *_msg, int sls);

#endif
